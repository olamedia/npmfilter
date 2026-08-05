//! The daemon side of the control socket.
//!
//! Binds `socket_path`, hands every accepted connection to [`ControlService`] and answers one
//! framed request per connection.
//!
//! # Why a socket at all
//!
//! Because file permissions are not a policy engine. The previous arrangement had the MCP
//! shim and the CLI open `rules.db` directly, which forced `/var/lib/npmfilter` to ship
//! group-writable: membership of group `npmfilter` was then the ability to write allow rules
//! **into the database**, bypassing the daemon's validation and its audit log entirely. A
//! socket makes the same group membership mean "may ask the daemon to approve something",
//! which is a request the daemon gets to validate, attribute and record.
//!
//! What the socket is *not* is an authentication boundary: anything that can open it can
//! approve packages, exactly as before. What changed is that every approval now exists on one
//! code path, with one validator and one audit trail.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use super::protocol::{
    CONNECTION_TIMEOUT, MAX_CONCURRENT_CONNECTIONS, MAX_REQUEST_BYTES, REFUSAL_TIMEOUT,
    REQUEST_TIMEOUT, RequestEnvelope, ResponseEnvelope,
};
use super::service::ControlService;
use super::{Actor, SOCKET_MODE};

/// A bound control socket that unlinks itself when it is dropped.
#[derive(Debug)]
pub struct ControlListener {
    listener: UnixListener,
    path: PathBuf,
}

impl ControlListener {
    /// The path this listener is bound to.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ControlListener {
    fn drop(&mut self) {
        // Leaving the node behind makes the next start look like "another daemon is already
        // running" until someone removes it by hand.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Bind the control socket at `path`.
///
/// A leftover socket from a killed daemon is removed, but only after a connect attempt proves
/// nothing is listening on it — stealing the path from a live daemon would silently split the
/// approval surface in two.
pub fn bind(path: &Path) -> io::Result<ControlListener> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.is_dir()
    {
        create_socket_dir(parent)?;
    }

    if path.exists() {
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "another npmfilter is already listening on {}",
                        path.display()
                    ),
                ));
            }
            Err(_) => {
                tracing::warn!(
                    socket = %path.display(),
                    "removing a stale control socket left by an earlier run"
                );
                std::fs::remove_file(path)?;
            }
        }
    }

    let listener = UnixListener::bind(path)?;
    // The socket is created under the process umask, which the packaged unit sets to 0077, so
    // it starts owner-only and is widened here deliberately rather than the other way round.
    restrict(path)?;
    Ok(ControlListener {
        listener,
        path: path.to_path_buf(),
    })
}

/// Create the socket's parent directory, group-traversable and nothing more.
fn create_socket_dir(dir: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o750);
    }
    builder.create(dir)
}

/// Set the socket to [`SOCKET_MODE`].
fn restrict(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))
}

/// Serve control requests until the listener dies.
///
/// The ceiling is enforced **before** a connection becomes a task. Acquiring the permit inside
/// the spawned task instead meant every accepted connection became a queued task holding a
/// file descriptor, waiting behind whatever was holding the eight slots — and what was holding
/// them could be eight peers that had said nothing at all, for [`CONNECTION_TIMEOUT`] each.
pub async fn serve(listener: ControlListener, service: Arc<ControlService>) -> io::Result<()> {
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    loop {
        let (stream, _) = listener.listener.accept().await?;
        // Over the ceiling: refuse, rather than queue a task that holds a descriptor for as
        // long as someone else cares to hold a slot.
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            tracing::warn!(
                limit = MAX_CONCURRENT_CONNECTIONS,
                "refusing a control connection: every slot is in use"
            );
            tokio::spawn(refuse_busy(stream));
            continue;
        };
        let service = Arc::clone(&service);
        tokio::spawn(async move {
            let _permit = permit;
            // A client that connects and then says nothing is dropped by REQUEST_TIMEOUT
            // inside `handle`; this bounds the work that follows a request that did arrive.
            match tokio::time::timeout(CONNECTION_TIMEOUT, handle(stream, service)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!(%error, "a control connection failed");
                }
                Err(_) => {
                    tracing::warn!(
                        timeout_secs = CONNECTION_TIMEOUT.as_secs(),
                        "a control connection timed out and was dropped"
                    );
                }
            }
        });
    }
}

/// Tell a connection the daemon is at its ceiling, and close.
///
/// Bounded by [`REFUSAL_TIMEOUT`] and holding no permit: the refusal must not itself become a
/// way to occupy the daemon.
async fn refuse_busy(mut stream: UnixStream) {
    let response = ResponseEnvelope::failed(
        "busy",
        format!(
            "npmfilter is already serving {MAX_CONCURRENT_CONNECTIONS} control connections and \
             will not queue another. Retry in a moment; a connection that sends no request is \
             dropped within {}s.",
            REQUEST_TIMEOUT.as_secs()
        ),
    );
    let _ = tokio::time::timeout(REFUSAL_TIMEOUT, write_frame(&mut stream, &response)).await;
}

/// Read one request, answer it, close.
async fn handle(mut stream: UnixStream, service: Arc<ControlService>) -> io::Result<()> {
    // The kernel says who this is. The request may carry a label; it may not carry an
    // identity.
    let actor = match stream.peer_cred() {
        Ok(cred) => Actor::from_cred(&cred),
        Err(error) => {
            tracing::error!(%error, "refusing a control connection with no peer credentials");
            return write_frame(
                &mut stream,
                &ResponseEnvelope::failed(
                    "internal",
                    "the peer credentials of this connection could not be read, so no request \
                     from it can be attributed to anyone",
                ),
            )
            .await;
        }
    };

    // The frame is read under its own short deadline. This is the fix for the wedge: a peer
    // that connects and never speaks now costs a slot for REQUEST_TIMEOUT, not for the whole
    // CONNECTION_TIMEOUT that `inspect` and `seed` legitimately need for their work.
    let frame = match tokio::time::timeout(REQUEST_TIMEOUT, read_frame(&mut stream)).await {
        Ok(Ok(frame)) => frame,
        Ok(Err(error)) => {
            return write_frame(
                &mut stream,
                &ResponseEnvelope::failed("invalid_request", error),
            )
            .await;
        }
        Err(_) => {
            tracing::warn!(
                uid = actor.uid,
                timeout_secs = REQUEST_TIMEOUT.as_secs(),
                "dropping a control connection that sent no request"
            );
            return write_frame(
                &mut stream,
                &ResponseEnvelope::failed(
                    "timeout",
                    format!(
                        "no request arrived within {}s; the connection was dropped so the slot \
                         could be used",
                        REQUEST_TIMEOUT.as_secs()
                    ),
                ),
            )
            .await;
        }
    };

    let envelope: RequestEnvelope = match serde_json::from_slice(&frame) {
        Ok(envelope) => envelope,
        Err(error) => {
            // The parse error names the offending key or type, which is what makes a
            // mis-shaped request debuggable; it quotes nothing back that was not sent.
            return write_frame(
                &mut stream,
                &ResponseEnvelope::failed(
                    "invalid_request",
                    format!("the request frame is not a valid npmfilter control request: {error}"),
                ),
            )
            .await;
        }
    };

    if let Err(error) = envelope.validate() {
        tracing::warn!(
            uid = actor.uid,
            operation = envelope.request.name(),
            %error,
            "rejected an invalid control request"
        );
        return write_frame(
            &mut stream,
            &ResponseEnvelope::failed("invalid_request", error.to_string()),
        )
        .await;
    }

    let actor = actor.with_label(&envelope.client);
    let operation = envelope.request.name();
    if envelope.request.is_mutation() {
        tracing::info!(
            operation,
            actor = %actor.render(),
            "control socket: recording a mutation"
        );
    } else {
        tracing::debug!(operation, actor = %actor.render(), "control socket: request");
    }

    let response = match service.dispatch(envelope.request, &actor).await {
        Ok(answer) => ResponseEnvelope::ok(answer),
        Err(error) => {
            tracing::warn!(operation, %error, "a control request failed");
            ResponseEnvelope::failed(error.code(), error.to_string())
        }
    };
    write_frame(&mut stream, &response).await
}

/// Read one `\n`-terminated frame, refusing anything over [`MAX_REQUEST_BYTES`].
///
/// Read byte-budgeted rather than to EOF: a client that never sends a newline cannot make the
/// daemon buffer without limit, and a client that sends two requests down one connection has
/// the second ignored because the connection is closed after the answer.
async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, String> {
    let mut frame = Vec::with_capacity(1024);
    let mut chunk = [0u8; 8192];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("the request could not be read: {error}"))?;
        if read == 0 {
            return Err("the connection closed before a complete request arrived".to_owned());
        }
        if let Some(newline) = chunk[..read].iter().position(|byte| *byte == b'\n') {
            if frame.len() + newline > MAX_REQUEST_BYTES {
                return Err(over_limit());
            }
            frame.extend_from_slice(&chunk[..newline]);
            return Ok(frame);
        }
        if frame.len() + read > MAX_REQUEST_BYTES {
            return Err(over_limit());
        }
        frame.extend_from_slice(&chunk[..read]);
    }
}

fn over_limit() -> String {
    format!(
        "the request frame exceeds the {MAX_REQUEST_BYTES}-byte limit; a seed of more than \
         {} packages has to be split",
        super::protocol::MAX_SEED_ENTRIES
    )
}

/// Write one frame and flush it.
async fn write_frame(stream: &mut UnixStream, response: &ResponseEnvelope) -> io::Result<()> {
    let mut body = serde_json::to_vec(response).map_err(io::Error::other)?;
    body.push(b'\n');
    stream.write_all(&body).await?;
    stream.flush().await
}
