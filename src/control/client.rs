//! The client side of the control socket: `npmfilter mcp` and every CLI subcommand.
//!
//! There is no fallback path. If the daemon is not running, these commands fail and say so —
//! they do **not** quietly open `rules.db` instead. A tool that sometimes writes the policy
//! database directly is a tool whose writes sometimes miss the validator and the audit log,
//! and "sometimes" is the whole problem.

use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::protocol::{
    Answer, CLIENT_TIMEOUT, Failure, MAX_RESPONSE_BYTES, Request, RequestEnvelope,
    ResponseEnvelope,
};

/// Anything that can go wrong talking to the daemon.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Nothing is listening. The actionable case, and the common one.
    #[error(
        "npmfilter is not running: nothing is listening on the control socket {path}.\n\
         \n\
         Start it, then try again:\n\
         \n    sudo systemctl start npmfilter\n    systemctl status npmfilter\n\
         \n\
         This command will not fall back to writing the state database directly. The daemon \
         is the only writer of npmfilter's state, which is what makes every approval \
         validated and audited on one code path."
    )]
    NotRunning {
        /// The socket that was tried.
        path: PathBuf,
    },
    /// The socket is there but this user may not open it.
    #[error(
        "not permitted to open the npmfilter control socket {path}.\n\
         \n\
         Approving a package is a privileged operation; the socket is owned by the daemon's \
         user and group. To grant it:\n\
         \n    sudo adduser $USER npmfilter        # then start a new login session\n\
         \n\
         That membership is the right to approve any package for this machine. Grant it as \
         deliberately as you would `docker`. The alternative is to run the command as the \
         daemon's own user: sudo -u npmfilter npmfilter …"
    )]
    Denied {
        /// The socket that was tried.
        path: PathBuf,
    },
    /// The connection failed for some other reason.
    #[error("could not talk to the npmfilter daemon on {path}")]
    Io {
        /// The socket that was tried.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
    /// The daemon did not answer within [`CLIENT_TIMEOUT`].
    #[error("the npmfilter daemon did not answer within {}s", CLIENT_TIMEOUT.as_secs())]
    Timeout,
    /// The answer was not a control response.
    #[error("the npmfilter daemon sent an answer this client cannot read")]
    BadResponse(#[source] serde_json::Error),
    /// The answer was a well-formed frame of the wrong shape.
    #[error("{0}")]
    Protocol(String),
    /// The daemon refused the request.
    #[error("npmfilter: {}", .0.message)]
    Refused(Failure),
}

/// A client for one control socket.
#[derive(Debug, Clone)]
pub struct ControlClient {
    path: PathBuf,
    label: String,
}

impl ControlClient {
    /// A client for the socket at `path`, labelling itself `label` in the audit trail.
    ///
    /// The label is a hint, not an identity: the daemon attributes every write to the peer
    /// credentials of the connection.
    pub fn new(path: impl Into<PathBuf>, label: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            label: label.into(),
        }
    }

    /// The socket this client talks to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Send one request and read the answer.
    pub async fn send(&self, request: Request) -> Result<Answer, ClientError> {
        let envelope = RequestEnvelope::new(&self.label, request);
        let mut frame = serde_json::to_vec(&envelope).map_err(ClientError::BadResponse)?;
        frame.push(b'\n');

        let response = tokio::time::timeout(CLIENT_TIMEOUT, self.exchange(frame))
            .await
            .map_err(|_| ClientError::Timeout)??;

        let response: ResponseEnvelope =
            serde_json::from_slice(&response).map_err(ClientError::BadResponse)?;
        match (response.answer, response.error) {
            (Some(answer), _) => Ok(answer),
            (None, Some(failure)) => Err(ClientError::Refused(failure)),
            (None, None) => Err(ClientError::Protocol(
                "the daemon answered with neither a result nor an error".to_owned(),
            )),
        }
    }

    /// Connect, write the frame, read the answer.
    async fn exchange(&self, frame: Vec<u8>) -> Result<Vec<u8>, ClientError> {
        let mut stream = UnixStream::connect(&self.path).await.map_err(|source| {
            match source.kind() {
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
                    ClientError::NotRunning {
                        path: self.path.clone(),
                    }
                }
                io::ErrorKind::PermissionDenied => ClientError::Denied {
                    path: self.path.clone(),
                },
                _ => ClientError::Io {
                    path: self.path.clone(),
                    source,
                },
            }
        })?;

        stream.write_all(&frame).await.map_err(|source| ClientError::Io {
            path: self.path.clone(),
            source,
        })?;
        stream.flush().await.map_err(|source| ClientError::Io {
            path: self.path.clone(),
            source,
        })?;

        let mut answer = Vec::with_capacity(4096);
        let mut chunk = [0u8; 16 * 1024];
        loop {
            let read = stream.read(&mut chunk).await.map_err(|source| ClientError::Io {
                path: self.path.clone(),
                source,
            })?;
            if read == 0 {
                break;
            }
            if answer.len() + read > MAX_RESPONSE_BYTES {
                return Err(ClientError::Protocol(format!(
                    "the daemon's answer exceeds the {MAX_RESPONSE_BYTES}-byte limit"
                )));
            }
            if let Some(newline) = chunk[..read].iter().position(|byte| *byte == b'\n') {
                answer.extend_from_slice(&chunk[..newline]);
                break;
            }
            answer.extend_from_slice(&chunk[..read]);
        }
        if answer.is_empty() {
            return Err(ClientError::Protocol(
                "the daemon closed the connection without answering".to_owned(),
            ));
        }
        Ok(answer)
    }
}

/// Send one request on a fresh runtime — what the synchronous CLI entry points use.
///
/// The runtime is built here rather than in `main` so a command that never talks to the
/// daemon never pays for one.
pub fn send_blocking(client: &ControlClient, request: Request) -> anyhow::Result<Answer> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let answer = runtime.block_on(client.send(request))?;
    Ok(answer)
}
