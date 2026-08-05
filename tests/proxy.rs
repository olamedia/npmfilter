//! Integration tests for `npmfilter serve` — DESIGN.md "Verification".
//!
//! Everything here runs against a **local stub upstream** bound to port 0, never against
//! registry.npmjs.org, and against an in-memory store. Two servers are spun up per test: the
//! stub registry, and the daemon itself through the same `npmfilter::proxy::run` entry point
//! that `npmfilter serve` uses.

// The shipped caps must stay generous enough for the largest real packuments — the largest
// found on registry.npmjs.org was @types/node at 11.1 MB. Checked at compile time: asserting
// a constant at runtime proves nothing the compiler could not prove for free.
const _: () = assert!(npmfilter::proxy::MAX_PACKUMENT_VERSIONS >= 20_000);
const _: () = assert!(npmfilter::proxy::MAX_PACKUMENT_BYTES >= 64 * 1024 * 1024);

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::{Json, Router};
use chrono::{Duration, SecondsFormat, Utc};
use npmfilter::config::Config;
use npmfilter::proxy::{ABBREVIATED_MEDIA_TYPE, ABBREVIATED_VERSION_KEYS, AppState, run};
use npmfilter::store::{NewRule, ScriptSet, Severity, Store};
use serde_json::{Value, json};
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------

/// An RFC 3339 timestamp `days` in the past, in the exact shape npm's `time` field uses.
fn days_ago(days: i64) -> String {
    (Utc::now() - Duration::days(days)).to_rfc3339_opts(SecondsFormat::Millis, true)
}

const HASH_A: &str = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
const HASH_B: &str = "sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==";
const HASH_HOOKED: &str = "sha512-HOOKHOOKHOOKHOOKHOOKHOOKHOOKHOOKHOOKHOOKHOOKHOOKHOOKHOOK==";

/// `widget` — one aged clean version, one aged install-script version, one published today.
///
/// `dist-tags.latest` points at the too-new version, so the repointing gate has work to do;
/// `legacy` points at a version that survives, so it must be left exactly as it is.
fn widget(integrity_1_0_0: &str) -> Value {
    json!({
        "_id": "widget",
        "_rev": "7-cafe",
        "name": "widget",
        "description": "a test widget",
        "readme": "# widget\n",
        "maintainers": [{ "name": "someone", "email": "someone@example.test" }],
        "dist-tags": { "latest": "2.0.0", "legacy": "1.0.0" },
        "time": {
            "created": days_ago(400),
            "modified": days_ago(1),
            "1.0.0": days_ago(300),
            "1.1.0": days_ago(200),
            "2.0.0": days_ago(1)
        },
        "versions": {
            "1.0.0": {
                "_id": "widget@1.0.0",
                "_npmUser": { "name": "someone" },
                "name": "widget",
                "version": "1.0.0",
                "description": "a test widget",
                "readme": "# widget\n",
                "gitHead": "deadbeef",
                "scripts": { "test": "mocha" },
                "dependencies": { "left-pad": "^1.0.0" },
                "devDependencies": { "mocha": "^10.0.0" },
                "engines": { "node": ">=18" },
                "dist": {
                    "integrity": integrity_1_0_0,
                    "shasum": "1111111111111111111111111111111111111111",
                    "tarball": "https://registry.npmjs.org/widget/-/widget-1.0.0.tgz"
                }
            },
            "1.1.0": {
                "name": "widget",
                "version": "1.1.0",
                "scripts": { "preinstall": "node setup.mjs", "test": "mocha" },
                "dependencies": {},
                "dist": {
                    "integrity": HASH_HOOKED,
                    "tarball": "https://registry.npmjs.org/widget/-/widget-1.1.0.tgz"
                }
            },
            "2.0.0": {
                "name": "widget",
                "version": "2.0.0",
                "scripts": { "test": "mocha" },
                "dist": {
                    "integrity": "sha512-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC==",
                    "tarball": "https://registry.npmjs.org/widget/-/widget-2.0.0.tgz"
                }
            }
        }
    })
}

/// A first-party scoped package carrying an install hook, exempt via `bypass_scopes`.
fn bypass_tool() -> Value {
    json!({
        "name": "@bypass/tool",
        "dist-tags": { "latest": "3.2.1" },
        "time": {
            "created": days_ago(500),
            "modified": days_ago(120),
            "3.2.1": days_ago(120)
        },
        "versions": {
            "3.2.1": {
                "_id": "@bypass/tool@3.2.1",
                "name": "@bypass/tool",
                "version": "3.2.1",
                "description": "builds things",
                "readme": "# tool\n",
                "maintainers": [{ "name": "someone" }],
                "scripts": { "install": "node-gyp rebuild", "test": "mocha" },
                "dependencies": { "node-addon-api": "^8.0.0" },
                "devDependencies": { "mocha": "^10.0.0" },
                "peerDependencies": { "node-gyp": "12.x" },
                "peerDependenciesMeta": { "node-gyp": { "optional": true } },
                "engines": { "node": ">=20" },
                "os": ["linux"],
                "cpu": ["x64"],
                "bin": { "tool": "cli.js" },
                "funding": { "url": "https://example.test/fund" },
                "dist": {
                    "integrity": "sha512-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD==",
                    "shasum": "2222222222222222222222222222222222222222",
                    "tarball": "https://registry.npmjs.org/@bypass/tool/-/tool-3.2.1.tgz",
                    "fileCount": 12,
                    "unpackedSize": 98765
                }
            }
        }
    })
}

// ---------------------------------------------------------------------------------------
// The stub upstream registry
// ---------------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct StubState {
    packuments: HashMap<String, Value>,
    hits: HashMap<String, usize>,
    accepts: Vec<String>,
    authorizations: Vec<Option<String>>,
    search_queries: Vec<String>,
    bulk_bodies: Vec<String>,
    /// Paths that reached the verbatim proxy — what a refused write must never appear in.
    fallback_paths: Vec<String>,
}

type Stub = Arc<Mutex<StubState>>;

fn lock(stub: &Stub) -> MutexGuard<'_, StubState> {
    stub.lock().unwrap_or_else(PoisonError::into_inner)
}

async fn stub_packument(
    State(stub): State<Stub>,
    Path(package): Path<String>,
    headers: HeaderMap,
) -> Response {
    let document = {
        let mut state = lock(&stub);
        *state.hits.entry(package.clone()).or_default() += 1;
        state.accepts.push(
            headers
                .get(header::ACCEPT)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned(),
        );
        state.authorizations.push(
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        );
        state.packuments.get(&package).cloned()
    };
    match document {
        Some(document) => (StatusCode::OK, Json(document)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Not found", "stub": true })),
        )
            .into_response(),
    }
}

async fn stub_search(State(stub): State<Stub>, uri: Uri) -> Response {
    lock(&stub)
        .search_queries
        .push(uri.query().unwrap_or_default().to_owned());
    Json(json!({ "objects": [], "total": 0, "stub": "search" })).into_response()
}

async fn stub_bulk(State(stub): State<Stub>, body: String) -> Response {
    lock(&stub).bulk_bodies.push(body);
    Json(json!({ "lodash": [], "stub": "bulk" })).into_response()
}

async fn stub_fallback(State(stub): State<Stub>, uri: Uri) -> Response {
    lock(&stub).fallback_paths.push(uri.path().to_owned());
    (
        StatusCode::OK,
        [("x-stub", "fallback")],
        Json(json!({ "stub": "fallback", "path": uri.path() })),
    )
        .into_response()
}

async fn start_stub(packuments: Vec<(&str, Value)>) -> (SocketAddr, Stub) {
    let stub: Stub = Arc::new(Mutex::new(StubState {
        packuments: packuments
            .into_iter()
            .map(|(name, document)| (name.to_owned(), document))
            .collect(),
        ..StubState::default()
    }));
    let app = Router::new()
        .route("/-/v1/search", get(stub_search))
        .route("/-/npm/v1/security/advisories/bulk", post(stub_bulk))
        .route("/{package}", any(stub_packument))
        .fallback(stub_fallback)
        .with_state(Arc::clone(&stub));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the stub upstream");
    let address = listener.local_addr().expect("stub address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (address, stub)
}

// ---------------------------------------------------------------------------------------
// The daemon under test
// ---------------------------------------------------------------------------------------

struct Harness {
    address: SocketAddr,
    stub_address: SocketAddr,
    store: Arc<Store>,
    stub: Stub,
    client: reqwest::Client,
}

impl Harness {
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    async fn get(&self, path: &str) -> reqwest::Response {
        self.request(path, None, None).await
    }

    async fn get_abbreviated(&self, path: &str) -> reqwest::Response {
        self.request(
            path,
            Some("application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"),
            None,
        )
        .await
    }

    async fn request(
        &self,
        path: &str,
        accept: Option<&str>,
        authorization: Option<&str>,
    ) -> reqwest::Response {
        let mut request = self.client.get(self.url(path));
        if let Some(accept) = accept {
            request = request.header(header::ACCEPT, accept);
        }
        if let Some(authorization) = authorization {
            request = request.header(header::AUTHORIZATION, authorization);
        }
        request.send().await.expect("the daemon answers")
    }

    async fn packument(&self, path: &str) -> Value {
        let response = self.get(path).await;
        assert_eq!(response.status(), StatusCode::OK, "GET {path}");
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        response.json().await.expect("a JSON packument")
    }

    fn upstream_hits(&self, package: &str) -> usize {
        lock(&self.stub).hits.get(package).copied().unwrap_or(0)
    }

    /// Send a request over a raw socket, with the request target written out byte for byte.
    ///
    /// Every URL parser — `reqwest`'s included — collapses `.` and `..` before a request
    /// leaves, which is the whole reason the bypass existed: npmfilter read the path as sent
    /// and its upstream client read it normalised, and the two disagreed about which package
    /// was being asked for. Reproducing that needs a client that does not help.
    async fn raw(&self, method: &str, target: &str, headers: &[(&str, &str)]) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut request = format!("{method} {target} HTTP/1.1\r\nHost: {}\r\n", self.address);
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("Connection: close\r\nContent-Length: 0\r\n\r\n");

        let mut stream = tokio::net::TcpStream::connect(self.address)
            .await
            .expect("connect to the daemon");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write the raw request");
        stream.flush().await.expect("flush");
        let mut answer = Vec::new();
        stream
            .read_to_end(&mut answer)
            .await
            .expect("read the raw answer");

        let text = String::from_utf8_lossy(&answer).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .unwrap_or_else(|| panic!("no status line in {text:?}"));
        let body = text
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.to_owned())
            .unwrap_or_default();
        (status, body)
    }
}

/// Start a stub upstream and a daemon pointed at it. The store is in memory: DESIGN.md's
/// packument cache is metadata only and these tests never touch the disk.
async fn start(packuments: Vec<(&str, Value)>, tweak: impl FnOnce(&mut Config)) -> Harness {
    let store = Arc::new(Store::open_in_memory().expect("in-memory store"));
    start_with_store(packuments, tweak, store).await
}

/// [`start`] against a store the caller owns — used by the test that breaks the database.
async fn start_with_store(
    packuments: Vec<(&str, Value)>,
    tweak: impl FnOnce(&mut Config),
    store: Arc<Store>,
) -> Harness {
    let (stub_address, stub) = start_stub(packuments).await;

    let mut config = Config {
        upstream: format!("http://{stub_address}"),
        ..Config::default()
    };
    tweak(&mut config);

    let state = AppState::new(Arc::new(config), Arc::clone(&store)).expect("proxy state");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the daemon");
    let address = listener.local_addr().expect("daemon address");
    tokio::spawn(async move {
        let _ = run(state, listener).await;
    });

    Harness {
        address,
        stub_address,
        store,
        stub,
        client: reqwest::Client::new(),
    }
}

/// Audit rows of one event, for a package.
fn audit_events(harness: &Harness, package: &str, event: &str) -> usize {
    harness
        .store
        .recent_audit(Some(package), 200)
        .expect("audit readable")
        .iter()
        .filter(|record| record.entry.event == event)
        .count()
}

fn version_keys(packument: &Value) -> Vec<String> {
    packument["versions"]
        .as_object()
        .expect("versions is an object")
        .keys()
        .cloned()
        .collect()
}

fn withheld(packument: &Value) -> HashMap<String, String> {
    packument["_npmfilter"]["withheld"]
        .as_array()
        .expect("withheld is an array")
        .iter()
        .map(|record| {
            (
                record["version"].as_str().unwrap_or_default().to_owned(),
                record["reason"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------------------
// DESIGN.md "Request path"
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn too_new_and_install_script_versions_are_withheld() {
    let harness = start(vec![("widget", widget(HASH_A))], |_| {}).await;
    let packument = harness.packument("/widget").await;

    assert_eq!(version_keys(&packument), vec!["1.0.0"]);
    let withheld = withheld(&packument);
    assert_eq!(
        withheld.get("1.1.0").map(String::as_str),
        Some("install_script")
    );
    assert_eq!(withheld.get("2.0.0").map(String::as_str), Some("too_new"));
    assert_eq!(packument["_npmfilter"]["withheld_count"], json!(2));
    assert_eq!(packument["_npmfilter"]["policy"]["min_age_days"], json!(30));

    // Withheld versions leave `time` as well, but `created`/`modified` stay.
    let time = packument["time"].as_object().expect("time survives");
    assert!(time.contains_key("1.0.0"));
    assert!(!time.contains_key("1.1.0"));
    assert!(!time.contains_key("2.0.0"));
    assert!(time.contains_key("created") && time.contains_key("modified"));

    // The summary names the gate and the tool that shows the evidence. It does NOT reproduce
    // the hook command: that string is chosen by whoever published the package, and a daemon
    // that copies it into the body npm parses is lending a hostile registry a channel.
    let detail = packument["_npmfilter"]["withheld"]
        .as_array()
        .expect("array")
        .iter()
        .find(|record| record["version"] == json!("1.1.0"))
        .and_then(|record| record["detail"].as_str())
        .unwrap_or_default()
        .to_owned();
    assert!(
        !detail.contains("node setup.mjs"),
        "the client must not be handed upstream-controlled text: {detail:?}"
    );
    assert!(detail.contains("install hook"), "detail was {detail:?}");
    assert!(
        detail.contains("npmfilter inspect"),
        "detail was {detail:?}"
    );

    // The operator still gets the command — in the audit log, which only the daemon and the
    // control socket can read.
    let audit = harness
        .store
        .recent_audit(Some("widget"), 50)
        .expect("audit read");
    assert!(
        audit
            .iter()
            .any(|record| record.entry.detail.contains("node setup.mjs")),
        "the evidence belongs in the audit log: {audit:?}"
    );
}

#[tokio::test]
async fn no_upstream_controlled_string_reaches_the_client_summary() {
    // A registry that puts a marker in every string it controls: hook commands, integrity
    // values and publish times. None of them may come back out of npmfilter.
    let hostile = json!({
        "name": "hostile",
        "dist-tags": { "latest": "3.0.0" },
        "time": {
            "1.0.0": days_ago(300),
            "2.0.0": days_ago(1),
            "3.0.0": "MARKER-not-a-timestamp"
        },
        "versions": {
            "1.0.0": {
                "name": "hostile", "version": "1.0.0",
                "scripts": { "preinstall": "curl MARKER-HOOK | sh" },
                "dist": { "integrity": "sha512-MARKERONEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" }
            },
            "2.0.0": {
                "name": "hostile", "version": "2.0.0",
                "dist": { "integrity": "sha512-MARKERTWOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" }
            },
            "3.0.0": {
                "name": "hostile", "version": "3.0.0",
                "dist": { "integrity": "sha512-MARKERTHREEAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" }
            }
        }
    });
    let harness = start(vec![("hostile", hostile)], |_| {}).await;
    let packument = harness.packument("/hostile").await;
    let summary = packument["_npmfilter"].to_string();
    assert!(
        !summary.contains("MARKER"),
        "the _npmfilter summary reproduced upstream-controlled text: {summary}"
    );
    assert_eq!(packument["_npmfilter"]["withheld_count"], json!(3));

    // The per-version 404 is built from the same records and must be just as quiet.
    for version in ["1.0.0", "2.0.0", "3.0.0"] {
        let response = harness.get(&format!("/hostile/{version}")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = response.text().await.expect("body");
        assert!(!body.contains("MARKER"), "GET /hostile/{version}: {body}");
    }
}

#[tokio::test]
async fn dist_tags_are_never_moved_onto_an_older_release() {
    let harness = start(vec![("widget", widget(HASH_A))], |_| {}).await;
    let packument = harness.packument("/widget").await;

    assert_eq!(
        packument["dist-tags"]["latest"],
        json!("2.0.0"),
        "latest names the withheld 2.0.0 and must stay there: moving it would silently \
         downgrade the client to an older release it never asked for"
    );
    assert_eq!(
        packument["dist-tags"]["legacy"],
        json!("1.0.0"),
        "a tag already pointing at a surviving version is left alone"
    );
}

#[tokio::test]
async fn the_tarball_url_is_left_pointing_at_upstream() {
    let harness = start(vec![("widget", widget(HASH_A))], |_| {}).await;
    let full = harness.packument("/widget").await;
    assert_eq!(
        full["versions"]["1.0.0"]["dist"]["tarball"],
        json!("https://registry.npmjs.org/widget/-/widget-1.0.0.tgz")
    );
    assert_eq!(
        full["versions"]["1.0.0"]["dist"]["integrity"],
        json!(HASH_A)
    );

    let response = harness.get_abbreviated("/widget").await;
    let abbreviated: Value = response.json().await.expect("JSON");
    assert_eq!(
        abbreviated["versions"]["1.0.0"]["dist"], full["versions"]["1.0.0"]["dist"],
        "dist is copied verbatim into the abbreviated form too"
    );
}

#[tokio::test]
async fn the_full_packument_upstream_is_fetched_even_for_an_abbreviated_request() {
    let harness = start(vec![("widget", widget(HASH_A))], |config| {
        config.packument_ttl_secs = 0;
    })
    .await;
    let _ = harness.get_abbreviated("/widget").await;
    let accepts = lock(&harness.stub).accepts.clone();
    assert_eq!(
        accepts,
        vec!["application/json".to_owned()],
        "abbreviated packuments carry no `time`, so upstream is always asked for the full one"
    );
}

// ---------------------------------------------------------------------------------------
// Abbreviated re-serialization
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn the_abbreviated_shape_matches_npm_and_preserves_has_install_script() {
    let harness = start(vec![("@bypass/tool", bypass_tool())], |config| {
        config.bypass_scopes = vec!["@bypass".to_owned()];
    })
    .await;

    let response = harness.get_abbreviated("/@bypass%2Ftool").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(ABBREVIATED_MEDIA_TYPE)
    );
    let abbreviated: Value = response.json().await.expect("JSON");

    let mut root: Vec<&str> = abbreviated
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    root.sort_unstable();
    assert_eq!(root, vec!["dist-tags", "modified", "name", "versions"]);
    assert_eq!(abbreviated["name"], json!("@bypass/tool"));
    assert_eq!(abbreviated["dist-tags"]["latest"], json!("3.2.1"));

    let meta = &abbreviated["versions"]["3.2.1"];
    assert_eq!(
        meta["hasInstallScript"],
        json!(true),
        "a surviving install-script version must still be flagged for npm"
    );
    let object = meta.as_object().expect("object");
    for key in object.keys() {
        assert!(
            ABBREVIATED_VERSION_KEYS.contains(&key.as_str()),
            "{key} is not part of npm's abbreviated format"
        );
    }
    for kept in [
        "name",
        "version",
        "dependencies",
        "devDependencies",
        "dist",
        "engines",
        "peerDependencies",
        "peerDependenciesMeta",
        "os",
        "cpu",
        "bin",
        "funding",
    ] {
        assert!(object.contains_key(kept), "{kept} must be preserved");
    }
    for dropped in ["scripts", "_id", "readme", "maintainers", "description"] {
        assert!(!object.contains_key(dropped), "{dropped} must be dropped");
    }
}

#[tokio::test]
async fn a_scoped_package_resolves_in_both_url_forms() {
    let harness = start(vec![("@bypass/tool", bypass_tool())], |config| {
        config.bypass_scopes = vec!["@bypass".to_owned()];
        config.packument_ttl_secs = 0;
    })
    .await;

    for path in ["/@bypass%2Ftool", "/@bypass/tool"] {
        let packument = harness.packument(path).await;
        assert_eq!(packument["name"], json!("@bypass/tool"), "GET {path}");
        assert_eq!(version_keys(&packument), vec!["3.2.1"], "GET {path}");
    }
    assert_eq!(
        harness.upstream_hits("@bypass/tool"),
        2,
        "both forms address the same upstream package"
    );
}

// ---------------------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn an_approved_version_reappears_once_a_rule_exists() {
    let harness = start(vec![("widget", widget(HASH_A))], |_| {}).await;

    let before = harness.packument("/widget").await;
    assert_eq!(version_keys(&before), vec!["1.0.0"]);

    let rule = NewRule::allow("widget", "1.1.0", HASH_HOOKED)
        .with_scripts(ScriptSet::from_hooks([("preinstall", "node setup.mjs")]))
        .with_reason("reviewed the setup script")
        .with_actor("test");
    harness
        .store
        .record_rule(&rule, Utc::now())
        .expect("record the allow rule");

    let after = harness.packument("/widget").await;
    assert_eq!(
        version_keys(&after),
        vec!["1.0.0", "1.1.0"],
        "an approval pinned to the current integrity brings the version back"
    );
    assert_eq!(withheld(&after).get("1.1.0"), None);
    assert_eq!(
        after["dist-tags"]["latest"],
        json!("2.0.0"),
        "tags are never moved — latest still names what upstream published"
    );

    // The approved version is flagged so npm knows it will run a hook.
    let response = harness.get_abbreviated("/widget").await;
    let abbreviated: Value = response.json().await.expect("JSON");
    assert_eq!(
        abbreviated["versions"]["1.1.0"]["hasInstallScript"],
        json!(true)
    );
}

#[tokio::test]
async fn a_replaced_version_is_blocked_and_no_allow_rule_rescues_it() {
    // DESIGN.md "Verification", the replacement path. A live cache would hide the swap, so
    // this runs with the TTL disabled — exactly how an operator would reproduce it.
    let harness = start(vec![("widget", widget(HASH_A))], |config| {
        config.packument_ttl_secs = 0;
    })
    .await;

    let first = harness.packument("/widget").await;
    assert_eq!(version_keys(&first), vec!["1.0.0"]);
    assert_eq!(
        first["versions"]["1.0.0"]["dist"]["integrity"],
        json!(HASH_A)
    );

    // Upstream now serves the same version with different bytes.
    lock(&harness.stub)
        .packuments
        .insert("widget".to_owned(), widget(HASH_B));

    let second = harness.packument("/widget").await;
    assert!(
        version_keys(&second).is_empty(),
        "every version is now withheld, so `versions` is empty rather than wrong"
    );
    assert_eq!(
        withheld(&second).get("1.0.0").map(String::as_str),
        Some("integrity_changed")
    );
    assert_eq!(
        second["dist-tags"].as_object().map(|tags| tags.len()),
        Some(2),
        "tags are preserved as upstream published them; each now fails to resolve, which is \
         the honest answer when nothing is installable"
    );

    // An approval pinned to the *new* hash must not rescue it — the ledger comes first.
    harness
        .store
        .record_rule(&NewRule::allow("widget", "1.0.0", HASH_B), Utc::now())
        .expect("record the allow rule");

    let third = harness.packument("/widget").await;
    assert!(version_keys(&third).is_empty());
    assert_eq!(
        withheld(&third).get("1.0.0").map(String::as_str),
        Some("integrity_changed"),
        "an approval cannot override the integrity ledger"
    );

    // The replacement is a critical audit event.
    let audit = harness
        .store
        .recent_audit(Some("widget"), 50)
        .expect("read the audit log");
    let tampers: Vec<_> = audit
        .iter()
        .filter(|record| record.entry.event == "tamper")
        .collect();
    assert!(!tampers.is_empty(), "the replacement must be audited");
    assert_eq!(tampers[0].entry.severity, Severity::Critical);
    assert_eq!(tampers[0].entry.version.as_deref(), Some("1.0.0"));

    // And the ledger still holds the hash it saw first — the evidence is never overwritten.
    let entry = harness
        .store
        .ledger_entry("widget", "1.0.0")
        .expect("read the ledger")
        .expect("the version was observed");
    assert_eq!(entry.integrity.as_deref(), Some(HASH_A));
}

// ---------------------------------------------------------------------------------------
// Cache, credentials
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn packuments_are_cached_for_the_configured_ttl() {
    let harness = start(vec![("widget", widget(HASH_A))], |config| {
        config.packument_ttl_secs = 60;
    })
    .await;
    for _ in 0..3 {
        let _ = harness.packument("/widget").await;
    }
    assert_eq!(harness.upstream_hits("widget"), 1, "one upstream fetch");
}

#[tokio::test]
async fn a_zero_ttl_fetches_upstream_every_time() {
    let harness = start(vec![("widget", widget(HASH_A))], |config| {
        config.packument_ttl_secs = 0;
    })
    .await;
    for _ in 0..3 {
        let _ = harness.packument("/widget").await;
    }
    assert_eq!(harness.upstream_hits("widget"), 3);
}

#[tokio::test]
async fn the_authorization_header_is_forwarded_upstream() {
    let harness = start(vec![("widget", widget(HASH_A))], |_| {}).await;
    let response = harness
        .request("/widget", None, Some("Bearer npm_supersecret"))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        lock(&harness.stub).authorizations,
        vec![Some("Bearer npm_supersecret".to_owned())]
    );
}

#[tokio::test]
async fn a_cached_packument_is_not_served_to_a_different_credential() {
    let harness = start(vec![("widget", widget(HASH_A))], |config| {
        config.packument_ttl_secs = 60;
    })
    .await;
    let _ = harness.request("/widget", None, Some("Bearer mine")).await;
    let _ = harness.request("/widget", None, Some("Bearer yours")).await;
    let _ = harness.request("/widget", None, None).await;
    assert_eq!(
        harness.upstream_hits("widget"),
        3,
        "each credential resolves against upstream on its own"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_for_the_same_package_are_safe() {
    let harness = start(vec![("widget", widget(HASH_A))], |config| {
        config.packument_ttl_secs = 60;
    })
    .await;
    let harness = Arc::new(harness);

    let mut tasks = Vec::new();
    for _ in 0..16 {
        let harness = Arc::clone(&harness);
        tasks.push(tokio::spawn(
            async move { harness.packument("/widget").await },
        ));
    }
    for task in tasks {
        let packument = task.await.expect("no handler panicked");
        assert_eq!(version_keys(&packument), vec!["1.0.0"]);
        assert_eq!(packument["dist-tags"]["latest"], json!("2.0.0"));
    }

    let entry = harness
        .store
        .ledger_entry("widget", "1.0.0")
        .expect("read the ledger")
        .expect("observed");
    assert_eq!(entry.integrity.as_deref(), Some(HASH_A));
    assert!(entry.times_seen >= 1);
}

// ---------------------------------------------------------------------------------------
// DESIGN.md "Other endpoints"
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn search_is_proxied_transparently() {
    let harness = start(vec![], |_| {}).await;
    let response = harness.get("/-/v1/search?text=lodash&size=1").await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("JSON");
    assert_eq!(body["stub"], json!("search"));
    assert_eq!(
        lock(&harness.stub).search_queries,
        vec!["text=lodash&size=1".to_owned()],
        "the query string reaches upstream untouched"
    );
}

#[tokio::test]
async fn the_audit_bulk_endpoint_is_proxied_transparently() {
    let harness = start(vec![], |_| {}).await;
    let response = harness
        .client
        .post(harness.url("/-/npm/v1/security/advisories/bulk"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"lodash":["4.17.21"]}"#)
        .send()
        .await
        .expect("the daemon answers");
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("JSON");
    assert_eq!(body["stub"], json!("bulk"));
    assert_eq!(
        lock(&harness.stub).bulk_bodies,
        vec![r#"{"lodash":["4.17.21"]}"#.to_owned()],
        "the request body reaches upstream untouched"
    );
}

#[tokio::test]
async fn an_unmatched_path_is_proxied_transparently() {
    let harness = start(vec![], |_| {}).await;
    // `/widget/1.0.0` is deliberately absent: the single-version manifest is a resolution
    // endpoint and is answered from the filtered document, not proxied.
    for path in ["/-/ping", "/-/whoami", "/widget/-/widget-1.0.0.tgz"] {
        let response = harness.get(path).await;
        assert_eq!(response.status(), StatusCode::OK, "GET {path}");
        assert_eq!(
            response
                .headers()
                .get("x-stub")
                .and_then(|value| value.to_str().ok()),
            Some("fallback"),
            "GET {path} must reach the upstream fallback"
        );
        let body: Value = response.json().await.expect("JSON");
        assert_eq!(body["path"], json!(path));
    }
}

/// Every write is refused the same way, whichever verb it arrives as.
///
/// This is the regression that mattered: `PUT` answered 405 while `DELETE` and `PATCH` fell
/// through to the verbatim proxy **with the client's Authorization header**, so
/// `npm unpublish` went straight through a daemon whose own error text said writes were
/// refused.
#[tokio::test]
async fn every_mutating_method_is_refused_with_the_same_actionable_error() {
    let harness = start(vec![("widget", widget(HASH_A))], |_| {}).await;
    let cases = [
        (reqwest::Method::PUT, "/widget"),
        (reqwest::Method::PUT, "/@bypass%2Ftool"),
        (reqwest::Method::PUT, "/@bypass/tool"),
        (reqwest::Method::PUT, "/-/user/x"),
        // `npm unpublish`.
        (reqwest::Method::DELETE, "/widget/-rev/7-cafe"),
        (reqwest::Method::DELETE, "/widget"),
        (reqwest::Method::PATCH, "/widget"),
        // `npm dist-tag add` posts to a package path.
        (reqwest::Method::POST, "/widget"),
        (reqwest::Method::POST, "/@bypass/tool"),
    ];
    for (method, path) in cases {
        let response = harness
            .client
            .request(method.clone(), harness.url(path))
            .header(header::AUTHORIZATION, "Bearer npm_secret")
            .body(r#"{"name":"widget"}"#)
            .send()
            .await
            .expect("the daemon answers");
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path}"
        );
        assert_eq!(
            response
                .headers()
                .get(header::ALLOW)
                .and_then(|value| value.to_str().ok()),
            Some("GET, HEAD, POST"),
            "{method} {path}"
        );
        let body: Value = response.json().await.expect("JSON");
        assert_eq!(body["code"], json!("publish_refused"), "{method} {path}");
        assert_eq!(body["method"], json!(method.as_str()), "{method} {path}");
        let detail = body["detail"].as_str().unwrap_or_default();
        assert!(
            detail.contains("@yourscope:registry="),
            "the error says how to publish instead: {detail:?}"
        );
        assert!(detail.contains("--registry"), "detail was {detail:?}");
        assert!(
            detail.contains("holds no credentials"),
            "detail was {detail:?}"
        );
    }
    assert_eq!(
        harness.upstream_hits("widget"),
        0,
        "a refused write never touches upstream, and never forwards the token it carried"
    );
    assert!(
        lock(&harness.stub).fallback_paths.is_empty(),
        "no refused write reached the verbatim proxy: {:?}",
        lock(&harness.stub).fallback_paths
    );
}

/// The read-only endpoints npm needs must keep working, `POST` and all.
#[tokio::test]
async fn the_read_only_post_endpoints_are_not_treated_as_writes() {
    let harness = start(vec![], |_| {}).await;

    let response = harness
        .client
        .post(harness.url("/-/npm/v1/security/advisories/bulk"))
        .body(r#"{"lodash":["4.17.21"]}"#)
        .send()
        .await
        .expect("the daemon answers");
    assert_eq!(response.status(), StatusCode::OK, "npm audit must survive");

    let response = harness.get("/-/v1/search?text=lodash").await;
    assert_eq!(response.status(), StatusCode::OK, "npm search must survive");
}

/// With the opt-in on, a write is relayed — and every one of them is on the record.
#[tokio::test]
async fn an_allowed_passthrough_write_is_relayed_and_audited() {
    let harness = start(vec![("widget", widget(HASH_A))], |config| {
        config.allow_publish_passthrough = true;
    })
    .await;

    let response = harness
        .client
        .put(harness.url("/widget"))
        .header(header::AUTHORIZATION, "Bearer npm_secret_value")
        .body(r#"{"name":"widget"}"#)
        .send()
        .await
        .expect("the daemon answers");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        harness.upstream_hits("widget"),
        1,
        "the write reached upstream"
    );

    let audit = harness.store.recent_audit(None, 10).expect("audit read");
    let entry = audit
        .iter()
        .find(|record| record.entry.event == "publish_passthrough")
        .expect("the relayed write is on the record");
    assert_eq!(entry.entry.severity, Severity::Warning);
    assert_eq!(entry.entry.name, "widget");
    assert!(entry.entry.detail.contains("PUT /widget"), "{entry:?}");
    assert!(
        entry.entry.detail.contains("authorization present"),
        "that a credential was used is worth recording: {entry:?}"
    );
    assert!(
        !entry.entry.detail.contains("npm_secret_value"),
        "the credential itself is never recorded: {entry:?}"
    );
    assert!(entry.entry.detail.contains("127.0.0.1"), "{entry:?}");
}

// ---------------------------------------------------------------------------------------
// Failure paths — a bad upstream must never panic the daemon
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn an_unreachable_upstream_answers_502_with_a_json_error() {
    // A port nothing is listening on: bind it, take the address, drop the listener.
    let dead = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind")
        .local_addr()
        .expect("address");
    let harness = start(vec![], |config| {
        config.upstream = format!("http://{dead}");
    })
    .await;

    let response = harness.get("/widget").await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body: Value = response.json().await.expect("JSON");
    assert_eq!(body["code"], json!("upstream_unavailable"));
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .starts_with("npmfilter:"),
        "error was {:?}",
        body["error"]
    );

    // The daemon is still alive and still refusing publishes.
    let again = harness.get("/widget").await;
    assert_eq!(again.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn a_malformed_upstream_packument_answers_502() {
    let harness = start(
        vec![("broken", json!({ "gibberish": true, "versions": {} }))],
        |_| {},
    )
    .await;
    let response = harness.get("/broken").await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body: Value = response.json().await.expect("JSON");
    assert_eq!(body["code"], json!("malformed_packument"));
}

#[tokio::test]
async fn an_upstream_404_is_forwarded_verbatim() {
    let harness = start(vec![], |_| {}).await;
    let response = harness.get("/does-not-exist").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: Value = response.json().await.expect("JSON");
    assert_eq!(body["error"], json!("Not found"));
    assert_eq!(body["stub"], json!(true));
}

// ---------------------------------------------------------------------------------------
// Path normalization — every resolution endpoint reaches the policy engine
// ---------------------------------------------------------------------------------------

/// A trailing or duplicated slash used to miss both package routes and be answered by the
/// verbatim proxy: every withheld version served, with no ledger observation and no audit row.
#[tokio::test]
async fn a_trailing_or_duplicated_slash_filters_exactly_like_the_canonical_path() {
    let harness = start(
        vec![("widget", widget(HASH_A)), ("@bypass/tool", bypass_tool())],
        |_| {},
    )
    .await;

    for path in ["/widget", "/widget/", "//widget", "/widget//"] {
        let response = harness.get(path).await;
        assert_eq!(response.status(), StatusCode::OK, "GET {path}");
        assert_eq!(
            response
                .headers()
                .get("x-npmfilter-withheld")
                .and_then(|value| value.to_str().ok()),
            Some("2"),
            "GET {path} must be filtered, not proxied"
        );
        let packument: Value = response.json().await.expect("JSON");
        assert_eq!(version_keys(&packument), vec!["1.0.0"], "GET {path}");
        assert_eq!(
            packument["dist-tags"]["latest"],
            json!("2.0.0"),
            "GET {path}"
        );
    }

    // The scoped form too, in every spelling.
    for path in ["/@bypass/tool", "/@bypass/tool/", "/@bypass%2Ftool/"] {
        let response = harness.get(path).await;
        assert_eq!(response.status(), StatusCode::OK, "GET {path}");
        let packument: Value = response.json().await.expect("JSON");
        assert_eq!(packument["name"], json!("@bypass/tool"), "GET {path}");
    }
}

// ---------------------------------------------------------------------------------------
// The single-version endpoint and dist-tags — DESIGN.md "Request path"
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn the_single_version_endpoint_answers_from_the_filtered_document() {
    let harness = start(vec![("widget", widget(HASH_A))], |_| {}).await;

    // A surviving version is served, tarball untouched.
    let response = harness.get("/widget/1.0.0").await;
    assert_eq!(response.status(), StatusCode::OK);
    let meta: Value = response.json().await.expect("JSON");
    assert_eq!(meta["version"], json!("1.0.0"));
    assert_eq!(meta["dist"]["integrity"], json!(HASH_A));
    assert_eq!(
        meta["dist"]["tarball"],
        json!("https://registry.npmjs.org/widget/-/widget-1.0.0.tgz")
    );

    // The install-script version is withheld here as well, and the 404 names the gate.
    let response = harness.get("/widget/1.1.0").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: Value = response.json().await.expect("JSON");
    assert_eq!(body["code"], json!("version_withheld"));
    assert_eq!(body["reason"], json!("install_script"));
    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(
        !detail.contains("node setup.mjs"),
        "the 404 must not reproduce the published command: {body}"
    );
    assert!(detail.contains("npmfilter inspect"), "{body}");

    // So is the too-new one.
    let response = harness.get("/widget/2.0.0").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: Value = response.json().await.expect("JSON");
    assert_eq!(body["reason"], json!("too_new"));

    // `latest` names the withheld 2.0.0, and the tag was NOT moved. Resolving it therefore
    // fails, naming the gate — instead of quietly handing back an older release.
    let response = harness.get("/widget/latest").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: Value = response.json().await.expect("JSON");
    assert_eq!(body["code"], json!("version_withheld"));
    assert_eq!(body["reason"], json!("too_new"));

    // A tag naming a surviving version still resolves normally.
    let response = harness.get("/widget/legacy").await;
    assert_eq!(response.status(), StatusCode::OK);
    let meta: Value = response.json().await.expect("JSON");
    assert_eq!(meta["version"], json!("1.0.0"));

    // A version that was never published is an ordinary 404.
    let response = harness.get("/widget/9.9.9").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: Value = response.json().await.expect("JSON");
    assert_eq!(body["code"], json!("version_not_found"));
}

#[tokio::test]
async fn a_denied_version_is_withheld_from_the_single_version_endpoint() {
    let harness = start(vec![("widget", widget(HASH_A))], |_| {}).await;
    harness
        .store
        .record_rule_audited(
            &NewRule::deny("widget", "1.0.0").with_reason("known bad"),
            Utc::now(),
        )
        .expect("deny rule recorded");

    let response = harness.get("/widget/1.0.0").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: Value = response.json().await.expect("JSON");
    assert_eq!(body["reason"], json!("deny_rule"));
    // The operator's own note stays with the operator: it is in the rule and in the audit
    // log, not in a body handed to every client that asks.
    assert!(
        !body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("known bad"),
        "{body}"
    );
    let audit = harness
        .store
        .recent_audit(Some("widget"), 50)
        .expect("audit read");
    assert!(
        audit
            .iter()
            .any(|record| record.entry.detail.contains("known bad")),
        "{audit:?}"
    );
}

#[tokio::test]
async fn a_scoped_single_version_request_is_filtered_too() {
    let harness = start(vec![("widget", widget(HASH_A))], |_| {}).await;
    // `/@scope/name/version` is three segments and used to fall straight through.
    let response = harness.get("/@bypass/tool/3.2.1").await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "the stub has no @bypass/tool, so upstream's own 404 comes back"
    );
    let body: Value = response.json().await.expect("JSON");
    assert_eq!(body["stub"], json!(true), "the answer came from upstream");
}

#[tokio::test]
async fn the_dist_tags_endpoint_reports_the_unmoved_tags() {
    let harness = start(vec![("widget", widget(HASH_A))], |_| {}).await;
    let response = harness.get("/-/package/widget/dist-tags").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-npmfilter-withheld")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    let tags: Value = response.json().await.expect("JSON");
    assert_eq!(
        tags,
        json!({ "latest": "2.0.0", "legacy": "1.0.0" }),
        "latest must not report the withheld 2.0.0"
    );
}

// ---------------------------------------------------------------------------------------
// Making the filtering visible — DESIGN.md "the daemon fails with a clear message"
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn every_filtered_response_states_how_many_versions_were_withheld() {
    let harness = start(vec![("widget", widget(HASH_A))], |_| {}).await;

    // `npm install` asks for the abbreviated shape, which carries no `_npmfilter` summary.
    let response = harness.get_abbreviated("/widget").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-npmfilter-withheld")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );
    assert_eq!(
        response
            .headers()
            .get("x-npmfilter-reasons")
            .and_then(|value| value.to_str().ok()),
        Some("install_script=1 too_new=1")
    );

    // And the full shape says so too, alongside the summary object.
    let response = harness.get("/widget").await;
    assert_eq!(
        response
            .headers()
            .get("x-npmfilter-withheld")
            .and_then(|value| value.to_str().ok()),
        Some("2")
    );

    // An unfiltered package still states that npmfilter looked at it.
    let harness = start(vec![("widget", widget(HASH_A))], |config| {
        config.min_age_days = 0;
        config.bypass_scopes = vec!["@bypass".to_owned()];
    })
    .await;
    let response = harness.get("/widget").await;
    assert_eq!(
        response
            .headers()
            .get("x-npmfilter-withheld")
            .and_then(|value| value.to_str().ok()),
        Some("1"),
        "only the install-script version is withheld once the age gate is off"
    );
}

/// A broken state database withholds every version by failing closed, which is
/// indistinguishable from "policy withheld everything" and from "that version was never
/// published". It has to be reported as what it is.
#[tokio::test]
async fn a_broken_state_database_answers_502_rather_than_an_empty_packument() {
    let path = std::env::temp_dir().join(format!(
        "npmfilter-proxy-broken-{}-{:?}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let _ = std::fs::remove_file(&path);
    let store = Arc::new(Store::open(&path).expect("file-backed store"));
    let harness = start_with_store(vec![("widget", widget(HASH_A))], |_| {}, store).await;

    // It works before the damage.
    assert_eq!(harness.get("/widget").await.status(), StatusCode::OK);

    {
        let conn = rusqlite::Connection::open(&path).expect("second connection");
        conn.execute_batch("DROP TABLE rules")
            .expect("drop the rules table");
    }

    let response = harness.get("/widget").await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body: Value = response.json().await.expect("JSON");
    assert_eq!(body["code"], json!("store_unavailable"));
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("database"),
        "{body}"
    );

    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------------------
// Bounded work per request — the state database and the upstream body
// ---------------------------------------------------------------------------------------

/// Re-serving a cached document must not re-write the ledger's bookkeeping or repeat the same
/// audit rows: the policy runs per request, but the verdicts and the observation do not change.
#[tokio::test]
async fn repeated_requests_do_not_multiply_audit_rows_or_ledger_writes() {
    let harness = start(vec![("widget", widget(HASH_A))], |config| {
        config.packument_ttl_secs = 60;
    })
    .await;

    for _ in 0..3 {
        assert_eq!(harness.get("/widget").await.status(), StatusCode::OK);
    }
    assert_eq!(harness.upstream_hits("widget"), 1, "one upstream fetch");

    let audit = harness
        .store
        .recent_audit(Some("widget"), 100)
        .expect("audit readable");
    assert_eq!(
        audit.len(),
        3,
        "one row per withheld version plus the one-off tarball-host note, not one per \
         request: {audit:?}"
    );
    assert_eq!(audit_events(&harness, "widget", "foreign_tarball"), 1);

    let entry = harness
        .store
        .ledger_entry("widget", "1.0.0")
        .expect("read")
        .expect("observed");
    assert_eq!(
        entry.times_seen, 1,
        "a cache hit compares the ledger without re-writing it"
    );
}

// ---------------------------------------------------------------------------------------
// Path normalization, part two: dot segments
// ---------------------------------------------------------------------------------------

/// The bypass that mattered most. `GET /./is-odd` matched no package route, fell through to
/// the verbatim proxy, and `reqwest`'s URL parser then normalised the dot segment away — so
/// upstream answered the packument for the real package and the client received it
/// **unfiltered**: every withheld version, no ledger observation, no audit row. The tamper
/// evidence the whole ledger exists to produce could be routed around by spelling the path
/// differently.
#[tokio::test]
async fn a_dot_segment_path_is_refused_and_never_reaches_upstream() {
    let harness = start(vec![("widget", widget(HASH_A))], |config| {
        config.packument_ttl_secs = 0;
    })
    .await;

    for path in [
        "/./widget",
        "/foo/../widget",
        "/_x/../widget",
        "/%2e/widget",
        "/%2E%2E/widget",
        "/-/../widget",
        "/@bypass/../widget",
        "/widget/..",
    ] {
        let (status, body) = harness.raw("GET", path, &[]).await;
        assert_eq!(status, 400, "GET {path} answered {status}: {body}");
        assert!(body.contains("invalid_path"), "GET {path}: {body}");
        assert!(
            !body.contains("1.0.0"),
            "no packument leaked for {path}: {body}"
        );
    }

    assert_eq!(
        harness.upstream_hits("widget"),
        0,
        "a path npmfilter refuses is a path upstream never sees"
    );
    assert!(
        lock(&harness.stub).fallback_paths.is_empty(),
        "no dot-segment path reached the verbatim proxy: {:?}",
        lock(&harness.stub).fallback_paths
    );

    // The canonical spelling still works, and is still filtered.
    let packument = harness.packument("/widget").await;
    assert_eq!(version_keys(&packument), vec!["1.0.0"]);
}

/// The same bypass turned a refused `POST` into an upstream-relayed one carrying the client's
/// publish token, with `allow_publish_passthrough` still false and no audit row written.
#[tokio::test]
async fn a_dot_segment_write_is_refused_with_or_without_the_passthrough_opt_in() {
    for passthrough in [false, true] {
        let harness = start(vec![("widget", widget(HASH_A))], |config| {
            config.allow_publish_passthrough = passthrough;
            config.packument_ttl_secs = 0;
        })
        .await;

        for method in ["POST", "PUT", "DELETE", "COPY"] {
            let (status, body) = harness
                .raw(
                    method,
                    "/./widget",
                    &[("Authorization", "Bearer npm_secret_value")],
                )
                .await;
            assert_eq!(
                status, 400,
                "{method} /./widget with allow_publish_passthrough = {passthrough}: {body}"
            );
            assert!(body.contains("invalid_path"), "{method}: {body}");
        }

        assert_eq!(
            harness.upstream_hits("widget"),
            0,
            "the credential was never relayed"
        );
        assert!(lock(&harness.stub).fallback_paths.is_empty());
        assert_eq!(
            harness
                .store
                .recent_audit(None, 50)
                .expect("audit readable")
                .iter()
                .filter(|record| record.entry.event == "publish_passthrough")
                .count(),
            0,
            "nothing was relayed, so nothing claims to have been"
        );
    }
}

/// Every method outside `GET`/`HEAD` — including verbs the method table never listed — is a
/// write. They used to be classified as `Passthrough` by default and relayed verbatim to a
/// package path, with the client's `Authorization` header, unaudited and unrefused.
#[tokio::test]
async fn an_unrecognised_method_to_a_package_path_is_refused_like_a_write() {
    let harness = start(vec![("widget", widget(HASH_A))], |_| {}).await;

    for verb in ["COPY", "PROPFIND", "OPTIONS", "FROB", "MKCOL", "TRACE"] {
        for path in [
            "/widget",
            "/widget/1.0.0",
            "/@bypass/tool",
            "/-/package/widget/dist-tags",
        ] {
            let method = reqwest::Method::from_bytes(verb.as_bytes()).expect("a method token");
            let response = harness
                .client
                .request(method, harness.url(path))
                .header(header::AUTHORIZATION, "Bearer npm_secret_value")
                .send()
                .await
                .expect("the daemon answers");
            assert_eq!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{verb} {path}"
            );
            let body: Value = response.json().await.expect("JSON");
            assert_eq!(body["code"], json!("publish_refused"), "{verb} {path}");
            assert_eq!(body["method"], json!(verb), "{verb} {path}");
        }
    }

    assert_eq!(
        harness.upstream_hits("widget"),
        0,
        "an unrecognised verb never reaches upstream, and never forwards the token it carried"
    );
    assert!(
        lock(&harness.stub).fallback_paths.is_empty(),
        "nothing reached the verbatim proxy: {:?}",
        lock(&harness.stub).fallback_paths
    );
}

// ---------------------------------------------------------------------------------------
// The integrity ledger has to have something to pin
// ---------------------------------------------------------------------------------------

/// A version publishing no `dist.integrity` was recorded in the ledger as `NULL`, and
/// `NULL == NULL` is a permanent `Match`: upstream could repoint `dist.tarball` at another
/// artefact for ever and every fetch still reported the version unchanged, withheld nothing
/// and raised no tamper event.
#[tokio::test]
async fn a_version_with_no_content_hash_is_withheld_and_a_repointed_tarball_cannot_hide() {
    let hashless = json!({
        "name": "hashless",
        "dist-tags": { "latest": "1.0.0" },
        "time": { "1.0.0": days_ago(300) },
        "versions": {
            "1.0.0": {
                "name": "hashless",
                "version": "1.0.0",
                "dist": { "tarball": "http://first.test/a.tgz" }
            }
        }
    });
    let harness = start(vec![("hashless", hashless)], |config| {
        config.packument_ttl_secs = 0;
    })
    .await;

    let packument = harness.packument("/hashless").await;
    assert!(
        version_keys(&packument).is_empty(),
        "nothing to pin means nothing to serve: {packument}"
    );
    assert_eq!(
        withheld(&packument).get("1.0.0").map(String::as_str),
        Some("no_integrity")
    );
    let summary = packument["_npmfilter"].to_string();
    assert!(
        !summary.contains("first.test"),
        "the client is never handed upstream-controlled text: {summary}"
    );

    // Repointing the artefact does not make it servable either.
    lock(&harness.stub).packuments.insert(
        "hashless".to_owned(),
        json!({
            "name": "hashless",
            "dist-tags": { "latest": "1.0.0" },
            "time": { "1.0.0": days_ago(300) },
            "versions": {
                "1.0.0": {
                    "name": "hashless",
                    "version": "1.0.0",
                    "dist": { "tarball": "http://evil.test/b.tgz" }
                }
            }
        }),
    );
    let packument = harness.packument("/hashless").await;
    assert!(version_keys(&packument).is_empty());
    assert_eq!(
        withheld(&packument).get("1.0.0").map(String::as_str),
        Some("no_integrity")
    );
}

/// `dist.tarball` is relayed untouched by design, so an upstream serving it from somewhere
/// else is a fact the operator gets told once — not per request, and not per version.
#[tokio::test]
async fn tarballs_hosted_away_from_the_upstream_are_recorded_once_per_package() {
    let harness = start(vec![("widget", widget(HASH_A))], |config| {
        config.packument_ttl_secs = 0;
    })
    .await;

    for _ in 0..3 {
        assert_eq!(harness.get("/widget").await.status(), StatusCode::OK);
    }
    assert_eq!(
        harness.upstream_hits("widget"),
        3,
        "each request re-fetched"
    );
    assert_eq!(
        audit_events(&harness, "widget", "foreign_tarball"),
        1,
        "recorded once per package, however many times it is resolved"
    );
    let note = harness
        .store
        .recent_audit(Some("widget"), 50)
        .expect("audit readable")
        .into_iter()
        .find(|record| record.entry.event == "foreign_tarball")
        .expect("the note exists");
    assert_eq!(note.entry.severity, Severity::Warning);
    assert!(
        note.entry.detail.contains("registry.npmjs.org"),
        "the operator is told where the bytes come from: {note:?}"
    );

    // A packument whose tarballs live on the configured upstream raises nothing.
    let local = json!({
        "name": "local",
        "dist-tags": { "latest": "1.0.0" },
        "time": { "1.0.0": days_ago(300) },
        "versions": {
            "1.0.0": {
                "name": "local",
                "version": "1.0.0",
                "dist": {
                    "integrity": HASH_A,
                    "tarball": format!("http://{}/local/-/local-1.0.0.tgz", harness.stub_address)
                }
            }
        }
    });
    lock(&harness.stub)
        .packuments
        .insert("local".to_owned(), local);
    assert_eq!(harness.get("/local").await.status(), StatusCode::OK);
    assert_eq!(audit_events(&harness, "local", "foreign_tarball"), 0);
}

#[tokio::test]
async fn an_upstream_packument_with_more_versions_than_the_cap_is_refused() {
    let (stub_address, _stub) = start_stub(vec![("widget", widget(HASH_A))]).await;
    let upstream = npmfilter::proxy::Upstream::new(format!("http://{stub_address}"))
        .expect("client")
        .with_max_packument_versions(2);

    let error = upstream
        .fetch_packument("widget", None)
        .await
        .expect_err("the fixture declares three versions");
    assert_eq!(error.code(), "packument_too_many_versions");
    assert_eq!(error.status(), StatusCode::BAD_GATEWAY);

    // Under the cap it is served as usual: over the limit is a refusal, never a truncated
    // answer that looks like a smaller packument.
    let upstream = npmfilter::proxy::Upstream::new(format!("http://{stub_address}"))
        .expect("client")
        .with_max_packument_versions(3);
    assert!(matches!(
        upstream
            .fetch_packument("widget", None)
            .await
            .expect("under the cap"),
        npmfilter::proxy::PackumentFetch::Document(_)
    ));
}

#[tokio::test]
async fn an_upstream_packument_larger_than_the_cap_is_refused() {
    let (stub_address, _stub) = start_stub(vec![("widget", widget(HASH_A))]).await;
    let upstream = npmfilter::proxy::Upstream::new(format!("http://{stub_address}"))
        .expect("client")
        .with_max_packument_bytes(64);

    let error = upstream
        .fetch_packument("widget", None)
        .await
        .expect_err("the body is far larger than 64 bytes");
    assert_eq!(error.code(), "packument_too_large");
    assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
}
