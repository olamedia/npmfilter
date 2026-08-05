//! Tests for the control plane.
//!
//! The socket tests bind a real `AF_UNIX` socket under the temp directory and drive it with
//! the real client; nothing here reaches the network, and the store is always in memory.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::protocol::*;
use super::*;
use crate::config::Config;
use crate::store::Store;

/// A unique socket path per test, so a whole run can go in parallel.
fn socket_path(tag: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "npmfilter-test-{}-{unique}-{tag}.sock",
        std::process::id()
    ))
}

/// A daemon on a temporary socket, with an in-memory store.
struct Daemon {
    path: PathBuf,
    store: Arc<Store>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Daemon {
    fn client(&self) -> ControlClient {
        ControlClient::new(self.path.clone(), LABEL_CLI)
    }
}

/// Start a daemon whose upstream is `upstream` (which may be unreachable when unused).
fn start(tag: &str, upstream: &str) -> Daemon {
    let path = socket_path(tag);
    let config = Config {
        upstream: upstream.to_owned(),
        socket_path: path.clone(),
        ..Config::default()
    };
    let store = Arc::new(Store::open_in_memory().expect("in-memory store"));
    let service = Arc::new(
        ControlService::new(Arc::new(config), Arc::clone(&store)).expect("service builds"),
    );
    let listener = server::bind(&path).expect("bind the control socket");
    let task = tokio::spawn(async move {
        let _ = server::serve(listener, service).await;
    });
    Daemon { path, store, task }
}

/// Write one raw frame and read the raw answer, bypassing the typed client.
async fn raw(path: &std::path::Path, frame: &[u8]) -> Value {
    let mut stream = UnixStream::connect(path).await.expect("connect");
    stream.write_all(frame).await.expect("write");
    stream.flush().await.expect("flush");
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.expect("read");
    serde_json::from_slice(&answer).expect("the answer is JSON")
}

// -- the socket ------------------------------------------------------------------------------

#[tokio::test]
async fn a_rule_recorded_over_the_socket_is_written_by_the_daemon_and_attributed_to_the_peer() {
    let daemon = start("deny", "http://127.0.0.1:1");
    let answer = daemon
        .client()
        .send(Request::Deny(DenyArgs {
            package: "keyv".to_owned(),
            version: "6.0.0".to_owned(),
            reason: Some("Shai-Hulud".to_owned()),
        }))
        .await
        .expect("the daemon answers");

    let Answer::Rule(written) = answer else {
        panic!("expected a rule answer");
    };
    assert_eq!(written.rule.verdict, "deny");

    // The row exists in the daemon's own store, and its actor is the uid the kernel reported
    // for the connection — not anything the client said about itself.
    let stored = daemon
        .store
        .try_lookup_rule("keyv", "6.0.0")
        .expect("lookup")
        .expect("the daemon wrote the rule");
    let actor = stored.rule.actor.as_deref().unwrap_or_default();
    assert!(
        actor.starts_with(&format!("uid={}", peer_uid().await)),
        "actor was {actor:?}"
    );
    assert!(actor.contains("via=cli"), "actor was {actor:?}");

    // And the mutation is in the audit log, because it went through the one code path.
    let audit = daemon.store.recent_audit(Some("keyv"), 10).expect("audit");
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].entry.event, crate::store::EVENT_DENY);
}

#[tokio::test]
async fn the_socket_is_readable_by_its_group_and_by_nobody_else() {
    use std::os::unix::fs::PermissionsExt;
    let daemon = start("mode", "http://127.0.0.1:1");
    let mode = std::fs::metadata(&daemon.path)
        .expect("the socket exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, SOCKET_MODE, "socket mode was {mode:04o}");
    assert_eq!(mode & 0o007, 0, "the world may not approve packages");
}

#[tokio::test]
async fn a_second_daemon_will_not_steal_a_live_socket() {
    let daemon = start("contended", "http://127.0.0.1:1");
    let error = server::bind(&daemon.path).expect_err("the path is taken");
    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    // The live daemon is still answering on it.
    assert!(
        daemon
            .client()
            .send(Request::Status(StatusArgs {}))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_stale_socket_from_a_killed_daemon_is_reclaimed() {
    let path = socket_path("stale");
    // A node where the socket should be, with nothing listening on it.
    std::fs::write(&path, b"").expect("leave a stale node");
    let listener = server::bind(&path).expect("a stale node is reclaimed");
    assert_eq!(listener.path(), path);
}

#[tokio::test]
async fn an_unknown_field_in_a_request_is_refused() {
    let daemon = start("unknown-field", "http://127.0.0.1:1");
    let frame = json!({
        "version": PROTOCOL_VERSION,
        "client": "cli",
        "request": { "deny": { "package": "keyv", "version": "6.0.0", "verdict": "allow" } }
    })
    .to_string()
        + "\n";
    let answer = raw(&daemon.path, frame.as_bytes()).await;
    assert_eq!(answer["error"]["code"], json!("invalid_request"));
    assert!(
        answer["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("verdict"),
        "{answer}"
    );
    assert!(
        daemon
            .store
            .try_lookup_rule("keyv", "6.0.0")
            .expect("lookup")
            .is_none(),
        "a request that failed to parse must write nothing"
    );
}

#[tokio::test]
async fn an_unknown_operation_is_refused() {
    let daemon = start("unknown-op", "http://127.0.0.1:1");
    let frame = json!({
        "version": PROTOCOL_VERSION,
        "client": "cli",
        "request": { "drop_all_rules": {} }
    })
    .to_string()
        + "\n";
    let answer = raw(&daemon.path, frame.as_bytes()).await;
    assert_eq!(answer["error"]["code"], json!("invalid_request"));
}

#[tokio::test]
async fn a_request_from_a_future_protocol_is_refused_rather_than_guessed_at() {
    let daemon = start("protocol", "http://127.0.0.1:1");
    let frame = json!({
        "version": PROTOCOL_VERSION + 1,
        "client": "cli",
        "request": { "status": {} }
    })
    .to_string()
        + "\n";
    let answer = raw(&daemon.path, frame.as_bytes()).await;
    assert_eq!(answer["error"]["code"], json!("invalid_request"));
    assert!(
        answer["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("control protocol"),
        "{answer}"
    );
}

#[tokio::test]
async fn a_frame_over_the_limit_is_refused_without_buffering_it_all() {
    let daemon = start("oversize", "http://127.0.0.1:1");
    // No newline anywhere: the daemon must stop on the byte budget, not wait for a terminator.
    let mut frame = vec![b'x'; MAX_REQUEST_BYTES + 4096];
    frame.push(b'\n');
    let answer = raw(&daemon.path, &frame).await;
    assert_eq!(answer["error"]["code"], json!("invalid_request"));
    assert!(
        answer["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("exceeds"),
        "{answer}"
    );
}

#[tokio::test]
async fn a_request_that_never_terminates_its_frame_gets_an_error_not_a_hang() {
    let daemon = start("unterminated", "http://127.0.0.1:1");
    let mut stream = UnixStream::connect(&daemon.path).await.expect("connect");
    stream.write_all(b"{\"version\":1").await.expect("write");
    stream.flush().await.expect("flush");
    stream.shutdown().await.expect("half-close");
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.expect("read");
    let answer: Value = serde_json::from_slice(&answer).expect("JSON");
    assert_eq!(answer["error"]["code"], json!("invalid_request"));
}

/// Eight connections that say nothing used to hold every slot for `CONNECTION_TIMEOUT` —
/// five minutes, renewable — while every real `status`, `allow` or `deny` queued behind them
/// with no deadline of its own. npmfilter withholds by default, so a wedged control socket is
/// a machine where nothing can be approved and therefore nothing can be installed.
#[tokio::test]
async fn idle_connections_cannot_wedge_the_control_socket() {
    let daemon = start("wedge", "http://127.0.0.1:1");

    // Occupy every slot, and say nothing on any of them.
    let mut idle = Vec::new();
    for _ in 0..MAX_CONCURRENT_CONNECTIONS {
        idle.push(
            UnixStream::connect(&daemon.path)
                .await
                .expect("connect an idle peer"),
        );
    }

    // A real request must be *answered*, promptly, one way or the other. Before the fix it
    // waited out CLIENT_TIMEOUT.
    let answered = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        daemon.client().send(Request::Status(StatusArgs {})),
    )
    .await
    .expect("the daemon must answer inside two seconds, not queue for five minutes");

    match answered {
        Ok(_) => {}
        Err(ClientError::Refused(failure)) => assert_eq!(
            failure.code, "busy",
            "over the ceiling is a refusal, not a silent queue: {failure:?}"
        ),
        Err(other) => panic!("unexpected control failure: {other}"),
    }

    // And the idle peers are dropped by the read deadline, so the slots come back on their
    // own without anyone reconnecting.
    tokio::time::sleep(REQUEST_TIMEOUT + std::time::Duration::from_secs(2)).await;
    let answer = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        daemon.client().send(Request::Status(StatusArgs {})),
    )
    .await
    .expect("no timeout")
    .expect("the slots freed themselves");
    assert!(matches!(answer, Answer::Status(_)), "{answer:?}");
    drop(idle);
}

#[tokio::test]
async fn a_connection_that_sends_no_request_is_dropped_by_the_read_deadline() {
    let daemon = start("silent", "http://127.0.0.1:1");
    let mut stream = UnixStream::connect(&daemon.path).await.expect("connect");

    let mut answer = Vec::new();
    let read = tokio::time::timeout(
        REQUEST_TIMEOUT + std::time::Duration::from_secs(3),
        stream.read_to_end(&mut answer),
    )
    .await
    .expect("the daemon must not hold a silent connection for CONNECTION_TIMEOUT");
    read.expect("read");

    let answer: Value = serde_json::from_slice(&answer).expect("the answer is JSON");
    assert_eq!(answer["error"]["code"], json!("timeout"), "{answer}");
}

#[tokio::test]
async fn a_client_with_no_daemon_is_told_exactly_what_to_do() {
    let client = ControlClient::new(socket_path("absent"), LABEL_CLI);
    let error = client
        .send(Request::Status(StatusArgs {}))
        .await
        .expect_err("nothing is listening");
    let message = error.to_string();
    assert!(matches!(error, ClientError::NotRunning { .. }), "{message}");
    assert!(message.contains("systemctl start npmfilter"), "{message}");
    assert!(
        message.contains("will not fall back to writing the state database"),
        "the absence of a fallback is the point: {message}"
    );
}

#[tokio::test]
async fn a_validation_failure_crosses_the_socket_as_a_refusal_and_writes_nothing() {
    let daemon = start("validated", "http://127.0.0.1:1");
    let error = daemon
        .client()
        .send(Request::Allow(AllowArgs {
            package: "../../etc/passwd".to_owned(),
            version: "1.0.0".to_owned(),
            reason: None,
            pins: Vec::new(),
        }))
        .await
        .expect_err("a traversal-shaped name is refused");
    assert!(matches!(error, ClientError::Refused(_)), "{error}");
    assert_eq!(
        daemon.store.rule_counts().expect("counts"),
        (0, 0),
        "nothing reached the store"
    );
}

// -- validation ------------------------------------------------------------------------------

#[test]
fn a_package_name_that_could_escape_its_path_segment_is_refused() {
    for name in [
        "../../etc/passwd",
        "..",
        ".",
        ".hidden",
        "_private",
        "a/b",
        "@scope/../x",
        "widget?query",
        "widget#frag",
        "widget%2f..",
        "wid get",
        "@scope",
        "@/name",
        "@scope/",
        "",
    ] {
        assert!(
            package_name("package", name).is_err(),
            "{name:?} must not be accepted as a package name"
        );
    }
    for name in [
        "lodash",
        "@babel/core",
        "@olamedia/thing",
        "is-odd",
        "left.pad",
        "node_modules_bad~ok",
    ] {
        assert!(
            package_name("package", name).is_ok(),
            "{name:?} is a real npm name"
        );
    }
    // npm's own ceiling.
    assert!(package_name("package", &"a".repeat(MAX_NAME_BYTES)).is_ok());
    assert!(package_name("package", &"a".repeat(MAX_NAME_BYTES + 1)).is_err());
}

#[test]
fn an_exact_version_must_be_semver_and_a_reason_must_be_printable() {
    assert!(exact_version("version", "1.0.0").is_ok());
    assert!(exact_version("version", "1.0.0-beta.1+build").is_ok());
    for bad in ["latest", "1.0", "", "1.0.0; rm -rf /", "^1.0.0"] {
        assert!(exact_version("version", bad).is_err(), "{bad:?}");
    }

    let control = Request::Allow(AllowArgs {
        package: "lodash".to_owned(),
        version: "4.17.21".to_owned(),
        // A terminal escape in an operator note would be re-rendered by every tool that shows
        // the rule.
        reason: Some("fine\u{1b}[2J".to_owned()),
        pins: Vec::new(),
    });
    assert!(matches!(
        control.validate(),
        Err(ValidationError::ControlCharacter { .. })
    ));

    let long = Request::Allow(AllowArgs {
        package: "lodash".to_owned(),
        version: "4.17.21".to_owned(),
        reason: Some("x".repeat(MAX_REASON_BYTES + 1)),
        pins: Vec::new(),
    });
    assert!(matches!(
        long.validate(),
        Err(ValidationError::TooLong { .. })
    ));
}

#[test]
fn a_seed_request_is_bounded_field_by_field() {
    let entry = |name: &str, integrity: &str, hook: &str| SeedEntry {
        name: name.to_owned(),
        version: "1.0.0".to_owned(),
        integrity: integrity.to_owned(),
        integrity_source: "package-lock.json".to_owned(),
        key: "node_modules/x".to_owned(),
        tree_sha256: "sha256:abc".to_owned(),
        hooks: [(hook.to_owned(), "node install.js".to_owned())]
            .into_iter()
            .collect(),
    };
    let args = |entries: Vec<SeedEntry>| {
        Request::Seed(SeedArgs {
            root: "/srv/app/node_modules".to_owned(),
            dry_run: false,
            offline: false,
            entries,
        })
    };

    assert!(
        args(vec![entry("esbuild", "sha512-AAA==", "postinstall")])
            .validate()
            .is_ok()
    );
    // A hook name outside the three npm actually runs would be recorded as if it were one.
    assert!(matches!(
        args(vec![entry("esbuild", "sha512-AAA==", "prepare")]).validate(),
        Err(ValidationError::BadHook { .. })
    ));
    // An "integrity" that is not one.
    assert!(matches!(
        args(vec![entry("esbuild", "not an sri value", "install")]).validate(),
        Err(ValidationError::BadIntegrity { .. })
    ));
    // And the entry ceiling.
    let many = (0..MAX_SEED_ENTRIES + 1)
        .map(|_| entry("esbuild", "sha512-AAA==", "install"))
        .collect();
    assert!(matches!(
        args(many).validate(),
        Err(ValidationError::TooManySeedEntries { .. })
    ));
}

#[test]
fn the_actor_is_built_from_the_peer_and_the_label_is_only_decoration() {
    let actor = Actor {
        uid: 1000,
        gid: 1000,
        pid: Some(77),
        label: String::new(),
    }
    // A label that tried to write its own audit line.
    .with_label("cli uid=0 root\nallow");
    let rendered = actor.render();
    assert!(rendered.starts_with("uid=1000 pid=77 via="), "{rendered}");
    assert!(
        !rendered.contains('\n') && !rendered.contains(' ') || rendered.matches(' ').count() == 2,
        "the label cannot forge extra fields: {rendered}"
    );
    assert_eq!(rendered, "uid=1000 pid=77 via=cliuid0rootallow");
    assert!(
        Actor {
            uid: 0,
            gid: 0,
            pid: None,
            label: String::new(),
        }
        .with_label("x".repeat(200).as_str())
        .render()
        .len()
            < 64,
        "a long label cannot bloat the actor column"
    );
}

/// This process's uid as the peer-credential API reports it.
///
/// Read through the same API the daemon uses, so the test needs no libc dependency.
async fn peer_uid() -> u32 {
    let path = socket_path("uid");
    let listener = tokio::net::UnixListener::bind(&path).expect("bind");
    let client = UnixStream::connect(&path).await.expect("connect");
    let uid = client.peer_cred().expect("peer cred").uid();
    drop(listener);
    let _ = std::fs::remove_file(&path);
    uid
}

// -- seed verification -------------------------------------------------------------------------
//
// The daemon does not take a lockfile's word for anything: it asks the registry. These drive
// that against a stub bound to port 0; registry.npmjs.org is never contacted.

/// A stub registry serving one packument for `esbuild`.
async fn stub_registry() -> (String, tokio::task::JoinHandle<()>) {
    use axum::routing::get;

    let packument = json!({
        "name": "esbuild",
        "dist-tags": { "latest": "0.21.5" },
        "time": { "0.21.5": "2024-01-01T00:00:00.000Z" },
        "versions": {
            "0.21.5": {
                "name": "esbuild",
                "version": "0.21.5",
                "scripts": { "postinstall": "node install.js" },
                "dist": { "integrity": "sha512-REAL==" }
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub");
    let address = listener.local_addr().expect("stub address");
    let app = axum::Router::new()
        .route(
            "/{package}",
            get(move || {
                let packument = packument.clone();
                async move { axum::Json(packument) }
            }),
        )
        .fallback(|| async { (axum::http::StatusCode::NOT_FOUND, "no such package") });
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}"), handle)
}

/// One seed entry for `esbuild@0.21.5`, with whatever the caller's "lockfile" claims.
fn seed_entry(integrity: &str, hook_command: &str) -> SeedEntry {
    SeedEntry {
        name: "esbuild".to_owned(),
        version: "0.21.5".to_owned(),
        integrity: integrity.to_owned(),
        integrity_source: "node_modules/.package-lock.json".to_owned(),
        key: "node_modules/esbuild".to_owned(),
        tree_sha256: "sha256:abcdef".to_owned(),
        hooks: [("postinstall".to_owned(), hook_command.to_owned())]
            .into_iter()
            .collect(),
    }
}

async fn seed(daemon: &Daemon, args: SeedArgs) -> SeedResult {
    match daemon
        .client()
        .send(Request::Seed(args))
        .await
        .expect("the daemon answers")
    {
        Answer::Seed(result) => *result,
        other => panic!("expected a seed answer, got {other:?}"),
    }
}

#[tokio::test]
async fn a_verified_seed_entry_is_approved_and_says_what_confirmed_it() {
    let (upstream, stub) = stub_registry().await;
    let daemon = start("seed-ok", &upstream);
    let result = seed(
        &daemon,
        SeedArgs {
            root: "/srv/app/node_modules".to_owned(),
            dry_run: false,
            offline: false,
            entries: vec![seed_entry("sha512-REAL==", "node install.js")],
        },
    )
    .await;
    stub.abort();

    assert_eq!(result.verified, 1);
    assert_eq!(result.written, 1);
    assert_eq!(result.refused, 0);
    assert_eq!(result.outcomes[0].status, "written");

    let stored = daemon
        .store
        .try_lookup_rule("esbuild", "0.21.5")
        .expect("lookup")
        .expect("the rule exists");
    let reason = stored.rule.reason.as_deref().unwrap_or_default();
    assert!(reason.contains("VERIFIED against"), "{reason}");
    assert!(reason.contains("sha256:abcdef"), "{reason}");
}

#[tokio::test]
async fn a_seed_entry_whose_lockfile_hash_is_not_what_upstream_serves_is_refused() {
    let (upstream, stub) = stub_registry().await;
    let daemon = start("seed-bad-hash", &upstream);
    let result = seed(
        &daemon,
        SeedArgs {
            root: "/srv/app/node_modules".to_owned(),
            dry_run: false,
            offline: false,
            entries: vec![seed_entry("sha512-TAMPERED==", "node install.js")],
        },
    )
    .await;
    stub.abort();

    assert_eq!(result.written, 0);
    assert_eq!(result.refused, 1);
    assert_eq!(result.outcomes[0].status, "refused");
    let detail = &result.outcomes[0].detail;
    assert!(detail.contains("is NOT the one"), "{detail}");
    // Neither hash is reproduced — one is upstream's and one came off a disk being vetted.
    assert!(!detail.contains("sha512-REAL"), "{detail}");
    assert!(!detail.contains("sha512-TAMPERED"), "{detail}");
    assert!(detail.contains("fingerprint sha256:"), "{detail}");

    assert!(
        daemon
            .store
            .try_lookup_rule("esbuild", "0.21.5")
            .expect("lookup")
            .is_none(),
        "a refused entry gets no rule"
    );
    // And the refusal is on the record.
    let audit = daemon
        .store
        .recent_audit(Some("esbuild"), 10)
        .expect("audit");
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].entry.event, crate::store::EVENT_SEED_REFUSED);
}

#[tokio::test]
async fn a_seed_entry_whose_hooks_are_not_the_published_ones_is_refused() {
    let (upstream, stub) = stub_registry().await;
    let daemon = start("seed-bad-hooks", &upstream);
    let result = seed(
        &daemon,
        SeedArgs {
            root: "/srv/app/node_modules".to_owned(),
            dry_run: false,
            offline: false,
            entries: vec![seed_entry("sha512-REAL==", "node evil.js")],
        },
    )
    .await;
    stub.abort();

    assert_eq!(result.refused, 1);
    let detail = &result.outcomes[0].detail;
    assert!(detail.contains("install-hook commands"), "{detail}");
    assert!(
        !detail.contains("node evil.js") && !detail.contains("node install.js"),
        "the commands themselves are not echoed back: {detail}"
    );
}

#[tokio::test]
async fn a_seed_entry_for_a_version_upstream_does_not_publish_is_refused() {
    let (upstream, stub) = stub_registry().await;
    let daemon = start("seed-unknown", &upstream);
    let mut entry = seed_entry("sha512-REAL==", "node install.js");
    entry.version = "9.9.9".to_owned();
    let result = seed(
        &daemon,
        SeedArgs {
            root: "/srv/app/node_modules".to_owned(),
            dry_run: false,
            offline: false,
            entries: vec![entry],
        },
    )
    .await;
    stub.abort();

    assert_eq!(result.refused, 1);
    assert!(
        result.outcomes[0]
            .detail
            .contains("publishes no such version"),
        "{:?}",
        result.outcomes[0]
    );
}

#[tokio::test]
async fn a_dry_run_seed_verifies_and_writes_nothing() {
    let (upstream, stub) = stub_registry().await;
    let daemon = start("seed-dry", &upstream);
    let result = seed(
        &daemon,
        SeedArgs {
            root: "/srv/app/node_modules".to_owned(),
            dry_run: true,
            offline: false,
            entries: vec![seed_entry("sha512-REAL==", "node install.js")],
        },
    )
    .await;
    stub.abort();

    assert_eq!(result.verified, 1);
    assert_eq!(result.written, 0);
    assert_eq!(result.outcomes[0].status, "verified");
    assert_eq!(daemon.store.rule_counts().expect("counts"), (0, 0));
}

#[tokio::test]
async fn an_offline_seed_writes_the_rule_and_records_the_reduced_assurance() {
    // The upstream is a port nothing is listening on: --offline must not reach for it.
    let daemon = start("seed-offline", "http://127.0.0.1:1");
    let result = seed(
        &daemon,
        SeedArgs {
            root: "/srv/app/node_modules".to_owned(),
            dry_run: false,
            offline: true,
            entries: vec![seed_entry("sha512-WHATEVER==", "node install.js")],
        },
    )
    .await;

    assert_eq!(result.verified, 0, "nothing was verified");
    assert_eq!(result.written, 1);
    assert!(result.note.contains("OFFLINE SEED"), "{}", result.note);

    let stored = daemon
        .store
        .try_lookup_rule("esbuild", "0.21.5")
        .expect("lookup")
        .expect("the rule exists");
    let reason = stored.rule.reason.as_deref().unwrap_or_default();
    assert!(reason.contains("NOT VERIFIED (--offline)"), "{reason}");
    assert!(reason.contains("Reduced assurance"), "{reason}");
}

// -- pin validation -------------------------------------------------------------------------

#[test]
fn a_pin_path_that_could_never_name_a_real_entry_is_refused() {
    for bad in [
        "/etc/shadow",
        "../escape.js",
        "./install.js",
        "a//b.js",
        "back\\slash.js",
        "",
    ] {
        let request = Request::Allow(AllowArgs {
            package: "widget".to_owned(),
            version: "1.0.0".to_owned(),
            reason: None,
            pins: vec![PinRequest {
                path: bad.to_owned(),
                sha256: None,
            }],
        });
        assert!(
            request.validate().is_err(),
            "{bad:?} must be refused as a pin path"
        );
    }
}

#[test]
fn an_asserted_digest_must_look_like_a_sha256() {
    let request = Request::Allow(AllowArgs {
        package: "widget".to_owned(),
        version: "1.0.0".to_owned(),
        reason: None,
        pins: vec![PinRequest {
            path: "install.js".to_owned(),
            sha256: Some("NOTAHASH".to_owned()),
        }],
    });
    assert!(matches!(
        request.validate(),
        Err(ValidationError::BadSha256 { .. })
    ));
}

#[test]
fn an_approval_may_not_pin_an_unbounded_number_of_files() {
    let request = Request::Allow(AllowArgs {
        package: "widget".to_owned(),
        version: "1.0.0".to_owned(),
        reason: None,
        pins: (0..crate::control::protocol::MAX_PINS + 1)
            .map(|i| PinRequest {
                path: format!("file{i}.js"),
                sha256: None,
            })
            .collect(),
    });
    assert!(matches!(
        request.validate(),
        Err(ValidationError::TooManyPins { .. })
    ));
}
