//! The filtering registry proxy — DESIGN.md "Request path" and "Other endpoints".
//!
//! `npmfilter serve` binds the configured address and answers as an npm registry:
//!
//! * `GET /{package}` and `GET /@scope%2Fname` (and the literal `/@scope/name` form) fetch
//!   the **full** packument upstream, run every version through the policy engine, and
//!   re-serialize into whichever shape the client asked for. `dist.tarball` is never
//!   touched, so lockfiles stay portable and no package bytes transit this daemon.
//! * `GET /-/v1/search`, `POST /-/npm/v1/security/advisories/bulk` and every unmatched path
//!   are proxied verbatim, so `npm search` and `npm audit` keep working.
//! * **Only `GET` and `HEAD` ever read**, and `POST` only to the two registry endpoints that
//!   are reads. Every other method — `PUT`, `DELETE`, `PATCH`, `POST` to a package path, and
//!   any verb outside the standard set, `COPY` and `PROPFIND` included — is a write and is
//!   refused with one actionable JSON error. They used to disagree twice over: `PUT` answered
//!   405 while `DELETE` was relayed upstream with the client's `Authorization` header, and an
//!   unrecognised verb was relayed verbatim without even being classified.
//!   `allow_publish_passthrough = true` relays writes instead, and then every one of them is
//!   written to the audit log with its method, path and actor.
//! * **A path that cannot be canonicalised is refused, not proxied.** `GET /./is-odd` and
//!   `GET /foo/../is-odd` are the packument for `is-odd` by the time a URL parser has seen
//!   them, but they matched no package route, fell through to the verbatim proxy, and came
//!   back unfiltered, unobserved by the integrity ledger and unaudited — every withheld
//!   version retrievable by spelling the path differently. A `.` or `..` segment now answers
//!   400 for every method.
//!
//! The daemon also listens on a Unix control socket (`socket_path`) — see [`crate::control`].
//! That socket is the only way a rule is ever written: the MCP shim and the CLI are clients of
//! it and never open the state database.
//!
//! Upstream packuments are held in a short in-memory TTL cache (`packument_ttl_secs`,
//! default 60). The cache holds the *unfiltered* upstream document, so a rule recorded while
//! an entry is warm takes effect on the next request instead of waiting out the TTL.

mod cache;
mod error;
mod shape;
mod upstream;

#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::Json;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::{Router, body};
use chrono::Utc;
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::config::Config;
use crate::control::{self, ControlService};
use crate::policy::{self, PolicyOutcome};
use crate::store::{AuditEntry, EVENT_PUBLISH, Severity, Store};

pub use cache::{CacheKey, DEFAULT_MAX_BYTES, DEFAULT_MAX_ENTRIES, PackumentCache};
pub use error::ProxyError;
pub use shape::{
    ABBREVIATED_MEDIA_TYPE, ABBREVIATED_ROOT_KEYS, ABBREVIATED_VERSION_KEYS, FULL_MEDIA_TYPE,
    FilterSummary, SUMMARY_KEY, SummaryPolicy, WithheldVersion, abbreviate, abbreviate_version,
    encode_package_path, has_install_script, wants_abbreviated, with_summary,
};
pub use upstream::{
    MAX_PACKUMENT_BYTES, MAX_PACKUMENT_VERSIONS, PackumentFetch, Upstream, UpstreamStatus,
};

/// DESIGN.md "Other endpoints" — npm search.
pub const SEARCH_PATH: &str = "/-/v1/search";
/// DESIGN.md "Other endpoints" — `npm audit`.
pub const ADVISORY_BULK_PATH: &str = "/-/npm/v1/security/advisories/bulk";

/// How many versions this response withheld. Present on every filtered resolution answer, in
/// both packument shapes, so the filtering is visible to a client that never reads the body's
/// `_npmfilter` summary.
pub const WITHHELD_HEADER: &str = "x-npmfilter-withheld";
/// `reason=count` pairs for the versions this response withheld.
pub const REASONS_HEADER: &str = "x-npmfilter-reasons";
/// `tag=version` pairs for `dist-tags` entries naming a withheld version, e.g. `latest=6.0.1`.
///
/// Tags are never moved onto an older release, so resolving one of these fails. That failure is
/// correct — a silent downgrade would be worse — but the client's own error says only that no
/// version matched, so the tag is named here.
pub const WITHHELD_TAGS_HEADER: &str = "x-npmfilter-withheld-tags";
/// What to do when a withheld tag made resolution fail: the tools that resolve it.
pub const ACTION_HEADER: &str = "x-npmfilter-action";

/// The largest request body this daemon will relay upstream. Only metadata endpoints are
/// proxied, so the limit exists to bound memory, not to constrain any real client.
///
/// A compile-time constant on purpose (DESIGN.md "Hard limits"): a config field for it would
/// be a way to weaken the daemon.
pub const MAX_PROXY_BODY: usize = 8 * 1024 * 1024;

/// How many packuments this daemon will fetch, parse and evaluate at the same time.
///
/// Each in-flight resolution holds the upstream document plus the copy `policy::evaluate`
/// rebuilds, so without a ceiling the daemon's peak memory is set by however many requests a
/// local client cares to make at once — the cache byte budget bounds what is *kept*, not what
/// is *in flight*. `npm` opens 15 sockets to a registry by default, so this queues briefly
/// under a large install and refuses nothing.
pub const MAX_CONCURRENT_PACKUMENTS: usize = 8;

/// How often the daemon prunes the audit log and the integrity ledger.
///
/// Retention used to run once, at startup, which is no retention at all for a daemon that is
/// meant to stay up: `Restart=always` and a machine that is never rebooted meant the tables
/// only ever grew.
pub const MAINTENANCE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(6 * 3600);

/// Everything a request handler needs. Cheap to clone — all shared state is behind `Arc`.
#[derive(Clone)]
pub struct AppState {
    config: Arc<Config>,
    store: Arc<Store>,
    upstream: Arc<Upstream>,
    cache: PackumentCache,
    /// Bounds how many packuments are held in memory at once — see
    /// [`MAX_CONCURRENT_PACKUMENTS`].
    slots: Arc<tokio::sync::Semaphore>,
}

impl AppState {
    /// Build the shared state from a loaded config and an open store.
    pub fn new(config: Arc<Config>, store: Arc<Store>) -> Result<Self, ProxyError> {
        let upstream = Arc::new(Upstream::new(config.upstream_base())?);
        let cache = PackumentCache::from_secs(config.packument_ttl_secs);
        Ok(Self {
            config,
            store,
            upstream,
            cache,
            slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PACKUMENTS)),
        })
    }

    /// The loaded configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The rules store, integrity ledger and audit log.
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The upstream registry client.
    pub fn upstream(&self) -> &Upstream {
        &self.upstream
    }

    /// The in-memory packument cache.
    pub fn cache(&self) -> &PackumentCache {
        &self.cache
    }
}

/// The router — DESIGN.md "Request path" and "Other endpoints".
///
/// Every request lands in the same handler and is classified by [`classify`], not by the route
/// table. axum's matcher never sees `/widget/`, `//widget` or `/@babel/core/` as package paths,
/// and a resolution request that misses the table must never fall through to the verbatim
/// proxy — that would serve every withheld version unfiltered, unobserved by the integrity
/// ledger and unaudited. The routes below are still registered so the contract stays legible.
pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route(SEARCH_PATH, any(handle))
        .route(ADVISORY_BULK_PATH, any(handle))
        .route("/{package}", any(handle))
        .route("/{scope}/{package}", any(handle))
        .fallback(handle)
        .with_state(state)
}

/// Serve until the listener dies.
///
/// The peer address is threaded through as a connection extension so an audited passthrough
/// can name the actor that sent it.
pub async fn run(state: AppState, listener: TcpListener) -> std::io::Result<()> {
    axum::serve(
        listener,
        build_app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

/// `npmfilter serve` — open the store, build the runtime, bind and serve.
///
/// The store is opened before the runtime exists, so no blocking file I/O ever runs on an
/// async worker.
pub fn serve_blocking(config: Config) -> anyhow::Result<()> {
    let store = Arc::new(config.open_store().with_context(|| {
        format!(
            "opening the npmfilter state database at {}",
            config.state_path.display()
        )
    })?);
    prune_state(&store, config.audit_retention_days);
    let retention_days = config.audit_retention_days;
    let listen = config.listen;
    let socket_path = config.socket_path.clone();
    let config = Arc::new(config);
    let state =
        AppState::new(Arc::clone(&config), Arc::clone(&store)).context("building the proxy state")?;
    let service = Arc::new(
        ControlService::new(Arc::clone(&config), Arc::clone(&store))
            .context("building the control service")?,
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?;

    runtime.block_on(async move {
        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("binding {listen}"))?;
        // The control socket is the only path by which a rule is ever written. If it cannot be
        // bound, the daemon does not come up half-usable: approvals would be impossible and
        // every blocked install would be unfixable.
        let control = control::server::bind(&socket_path)
            .with_context(|| format!("binding the control socket at {}", socket_path.display()))?;
        tracing::info!(
            %listen,
            socket = %socket_path.display(),
            upstream = state.upstream().base(),
            min_age_days = state.config().min_age_days,
            packument_ttl_secs = state.cache().ttl().as_secs(),
            allow_publish_passthrough = state.config().allow_publish_passthrough,
            state_path = %state.config().state_path.display(),
            "npmfilter is serving"
        );
        tokio::select! {
            result = run(state, listener) => result.context("the npmfilter proxy stopped"),
            result = control::server::serve(control, service) => {
                result.context("the npmfilter control socket stopped")
            }
            () = maintain(Arc::clone(&store), retention_days) => {
                Err(anyhow::anyhow!("the npmfilter maintenance task stopped"))
            }
        }
    })
}

/// Prune the audit log and the integrity ledger to their retentions.
///
/// A failure here is logged and ignored — retention is housekeeping, not a reason to refuse to
/// serve — but it is not optional work: nothing else prunes these tables, and a state database
/// that only ever grows ends as a full disk, which fails every store write, which fails closed
/// into a machine where no `npm install` resolves.
fn prune_state(store: &Store, retention_days: u32) {
    if retention_days > 0
        && let Some(cutoff) =
            Utc::now().checked_sub_signed(chrono::Duration::days(i64::from(retention_days)))
    {
        match store.prune_audit(cutoff) {
            Ok(0) => {}
            Ok(removed) => tracing::info!(
                removed,
                retention_days,
                "pruned audit rows older than the configured retention"
            ),
            Err(error) => tracing::warn!(
                %error,
                retention_days,
                "could not prune the audit log; carrying on"
            ),
        }
    }

    // The ledger keeps every row that ever recorded a mismatch and every row a rule refers to,
    // whatever its age — see `Store::prune_seen`.
    let Some(cutoff) =
        Utc::now().checked_sub_signed(chrono::Duration::days(crate::store::SEEN_RETENTION_DAYS))
    else {
        return;
    };
    match store.prune_seen(cutoff) {
        Ok(0) => {}
        Ok(removed) => tracing::info!(
            removed,
            retention_days = crate::store::SEEN_RETENTION_DAYS,
            "pruned integrity-ledger rows not observed within the retention window"
        ),
        Err(error) => tracing::warn!(
            %error,
            "could not prune the integrity ledger; carrying on"
        ),
    }
}

/// Re-run [`prune_state`] every [`MAINTENANCE_INTERVAL`], for ever.
///
/// The pruning itself is blocking SQLite work, so it runs on the blocking pool rather than on
/// an async worker.
async fn maintain(store: Arc<Store>, retention_days: u32) {
    let mut ticker = tokio::time::interval(MAINTENANCE_INTERVAL);
    // The first tick completes immediately, and startup has just pruned.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let store = Arc::clone(&store);
        if let Err(error) =
            tokio::task::spawn_blocking(move || prune_state(&store, retention_days)).await
        {
            tracing::warn!(%error, "the scheduled state pruning did not run");
        }
    }
}

/// What a request path resolves to once it has been normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// `GET /{package}` — the packument, in whichever shape the client asked for.
    Packument(String),
    /// `GET /{package}/{version}` — one version manifest. `version` may be a dist-tag.
    Version {
        /// The package.
        package: String,
        /// The version or dist-tag that was asked for.
        spec: String,
    },
    /// `GET /-/package/{package}/dist-tags` — the tag map on its own.
    DistTags(String),
    /// Anything else: proxied verbatim.
    Passthrough,
    /// A path that cannot be canonicalised: it carries a `.` or `..` segment.
    ///
    /// Never proxied and never resolved — answered 400. `reqwest`'s URL parser normalises dot
    /// segments away, so relaying `/./is-odd` verbatim asked upstream for `/is-odd` and handed
    /// the client the unfiltered packument: every withheld version, no ledger observation, no
    /// audit row. Fail closed instead: a path npmfilter cannot agree on with its own upstream
    /// is a path it must not forward.
    Invalid,
}

/// Classify a raw request path.
///
/// The path is split into percent-decoded, **non-empty** segments, which is what collapses
/// `//widget`, `/widget/` and `/@babel/core/` onto their canonical forms. Dropping empty
/// segments deliberately errs towards filtering: a path that is ambiguous must reach the
/// policy engine, never the verbatim proxy.
///
/// `/@scope%2Fname` (one segment) and `/@scope/name` (two) are the same package. The registry's
/// own `/-/…` namespace is never a package: npm names cannot start with `-`, `.` or `_`.
///
/// A `.` or `..` segment — in any spelling, `%2e` included — is [`Route::Invalid`]. Such a path
/// has two readings, npmfilter's and the URL parser's inside the upstream client, and the
/// difference between them was a complete bypass of every gate.
pub fn classify(path: &str) -> Route {
    let segments: Vec<String> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(percent_decode)
        .collect();

    if segments.iter().any(|segment| is_dot_segment(segment)) {
        return Route::Invalid;
    }

    if let [dash, package_word, name, tags] = segments.as_slice()
        && dash == "-"
        && package_word == "package"
        && tags == "dist-tags"
        && is_package_segment(name)
    {
        return Route::DistTags(name.clone());
    }

    match take_package(&segments) {
        Some((package, [])) => Route::Packument(package),
        Some((package, [spec])) => Route::Version {
            package,
            spec: spec.clone(),
        },
        _ => Route::Passthrough,
    }
}

/// Consume the package name from the head of `segments`, returning it and what is left.
///
/// A scope arriving as its own segment (`/@babel/core`) takes two segments; every other form
/// takes one, including the percent-encoded `@babel%2Fcore` the registry documents.
fn take_package(segments: &[String]) -> Option<(String, &[String])> {
    let first = segments.first()?;
    if !is_package_segment(first) {
        return None;
    }
    if first.starts_with('@') && !first.contains('/') {
        let name = segments.get(1)?;
        Some((format!("{first}/{name}"), &segments[2..]))
    } else {
        Some((first.clone(), &segments[1..]))
    }
}

/// Is this a relative path segment a URL parser would collapse?
///
/// `.` and `..`, decoded — `%2e`, `%2E`, `%2e%2e` and the rest all arrive here as plain text
/// because [`percent_decode`] has already run.
fn is_dot_segment(segment: &str) -> bool {
    segment == "." || segment == ".."
}

/// Could this segment be an npm package name?
///
/// `-` on its own is the registry's reserved namespace (`/-/v1/search`, `/-/whoami`, and the
/// `/{package}/-/{file}.tgz` tarball path), and npm forbids a name starting with `.` or `_` —
/// which also keeps `.` and `..` out. Anything else is treated as a package and therefore
/// filtered: for a resolution path, guessing wrong towards the policy engine is the safe
/// direction, and upstream answers 404 for a name that does not exist.
fn is_package_segment(segment: &str) -> bool {
    !segment.is_empty() && segment != "-" && !segment.starts_with(['.', '_'])
}

/// Percent-decode one path segment.
///
/// Decoding happens **after** splitting, so an encoded `%2F` becomes part of a name rather than
/// a separator. Invalid escapes are left as they are and invalid UTF-8 is replaced, so a
/// hostile path can never fail this. The decoded name is re-encoded by
/// [`encode_package_path`] before it goes upstream.
fn percent_decode(segment: &str) -> String {
    if !segment.contains('%') {
        return segment.to_owned();
    }
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(high), Some(low)) = (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
        {
            out.push((high << 4) | low);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Route one request: refuse every mutation, filter every resolution endpoint, proxy the rest.
async fn handle(State(state): State<AppState>, request: Request) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    // Every method is classified, whatever it is. Deciding the route from the method table
    // first is what let `COPY /lodash` and `PROPFIND /lodash` past both the mutation gate and
    // the package filter: neither was classified, so both were relayed verbatim, with the
    // client's `Authorization` header, to a path that resolves packages.
    let route = classify(&path);

    if matches!(route, Route::Invalid) {
        return refuse_path(&method, &path);
    }

    if is_mutating(&method, &route) {
        if !state.config.allow_publish_passthrough {
            return refuse_mutation(&state, &method, &path);
        }
        // Opted in: relay it, but only once the audit row is on disk. A relayed write that
        // was not recorded is a write this daemon cannot account for.
        //
        // The audit entry is built here, synchronously, so nothing borrows the request across
        // the await that writes it.
        let entry = mutation_audit_entry(&method, &path, &route, &request);
        if let Err(error) = record_mutation(&state, entry).await {
            return error.into_response();
        }
        return match proxy_through(&state, request).await {
            Ok(response) => response,
            Err(error) => error.into_response(),
        };
    }

    let result = match route {
        Route::Packument(package) => serve_packument(&state, &package, request.headers()).await,
        Route::Version { package, spec } => {
            serve_version(&state, &package, &spec, request.headers()).await
        }
        Route::DistTags(package) => serve_dist_tags(&state, &package, request.headers()).await,
        Route::Passthrough => proxy_through(&state, request).await,
        // Refused above, before anything could be forwarded.
        Route::Invalid => Ok(refuse_path(&method, &path)),
    };
    match result {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

/// What resolving a package produced.
enum Resolved {
    /// The filtered document, plus the policy that produced it.
    Filtered {
        outcome: PolicyOutcome,
        policy: policy::PolicyConfig,
    },
    /// Upstream declined — 404 for an unknown package, 401 for a private one.
    Upstream(UpstreamStatus),
}

/// DESIGN.md "Request path" steps 1-3: fetch the full packument, evaluate every version,
/// rebuild the document.
///
/// Every endpoint that answers a resolution question goes through here, so no client can ask
/// the same question by another URL and get an unfiltered answer.
async fn resolve(
    state: &AppState,
    package: &str,
    headers: &HeaderMap,
) -> Result<Resolved, ProxyError> {
    let authorization = headers.get(header::AUTHORIZATION);
    let key = CacheKey::new(package, authorization.map(|value| value.as_bytes()));

    // One permit per in-flight packument. Held across the fetch *and* the evaluation, because
    // both hold the document: the ceiling is on documents in memory, not on sockets.
    let _slot = state
        .slots
        .acquire()
        .await
        .map_err(|_| ProxyError::Unavailable {
            detail: "the packument concurrency gate is closed".to_owned(),
        })?;

    let (document, cached) = match state.cache.get(&key) {
        Some(cached) => {
            tracing::debug!(package, "serving a cached upstream packument");
            (cached, true)
        }
        None => match state
            .upstream
            .fetch_packument(package, authorization)
            .await?
        {
            PackumentFetch::Document(document) => {
                let document = Arc::new(document);
                state.cache.insert(key, Arc::clone(&document));
                (document, false)
            }
            PackumentFetch::Status(status) => {
                tracing::debug!(
                    package,
                    status = status.status.as_u16(),
                    "upstream declined the packument; forwarding its answer verbatim"
                );
                return Ok(Resolved::Upstream(status));
            }
        },
    };

    let policy = state.config.policy();
    let outcome = evaluate(
        Arc::clone(&state.store),
        document,
        package.to_owned(),
        policy.clone(),
        cached,
        url_host(state.config.upstream_base()).map(str::to_owned),
    )
    .await?;

    if outcome.blocked.is_empty() {
        tracing::debug!(package, "packument served unfiltered");
    } else {
        tracing::info!(
            package,
            withheld = outcome.blocked.len(),
            reasons = %summarize(&outcome.blocked),
            "packument filtered"
        );
    }

    Ok(Resolved::Filtered { outcome, policy })
}

/// DESIGN.md "Request path": fetch full, evaluate, rebuild, re-serialize.
async fn serve_packument(
    state: &AppState,
    package: &str,
    headers: &HeaderMap,
) -> Result<Response, ProxyError> {
    let (outcome, policy) = match resolve(state, package, headers).await? {
        Resolved::Filtered { outcome, policy } => (outcome, policy),
        Resolved::Upstream(status) => return Ok(status.into_response()),
    };
    let PolicyOutcome { packument, blocked } = outcome;

    let abbreviated = wants_abbreviated(
        headers
            .get(header::ACCEPT)
            .and_then(|accept| accept.to_str().ok()),
    );
    let withheld_tags = shape::withheld_dist_tags(&packument, &blocked);
    if !withheld_tags.is_empty() {
        // Worth a log line of its own: this is the case where the client's install fails and
        // its own error names neither npmfilter nor a next step.
        tracing::warn!(
            package = %package,
            tags = %withheld_tags
                .iter()
                .map(|entry| format!("{}={}", entry.tag, entry.version))
                .collect::<Vec<_>>()
                .join(","),
            "a dist-tag names a withheld version — resolution of that tag will fail; the tag was \
             NOT moved to an older release. Review with `npmfilter recent-blocks` / \
             `npmfilter inspect` and approve, or request an older version explicitly"
        );
    }
    let (document, media_type) = if abbreviated {
        (abbreviate(&packument), ABBREVIATED_MEDIA_TYPE)
    } else {
        (
            with_summary(packument, &blocked, &policy, Utc::now()),
            FULL_MEDIA_TYPE,
        )
    };

    let body = serde_json::to_vec(&document).map_err(ProxyError::Serialize)?;
    let mut response =
        ([(header::CONTENT_TYPE, media_type)], body::Body::from(body)).into_response();
    attach_filter_headers(&mut response, &blocked, &withheld_tags);
    Ok(response)
}

/// `GET /{package}/{version}` — the single-version manifest, answered from the **filtered**
/// document.
///
/// This endpoint asks the same question the packument does, so it gets the same answer: a
/// version any gate withheld is not here either, and the 404 says which gate withheld it.
/// `{version}` may be a dist-tag, which resolves through the repointed tags.
async fn serve_version(
    state: &AppState,
    package: &str,
    spec: &str,
    headers: &HeaderMap,
) -> Result<Response, ProxyError> {
    let outcome = match resolve(state, package, headers).await? {
        Resolved::Filtered { outcome, .. } => outcome,
        Resolved::Upstream(status) => return Ok(status.into_response()),
    };

    let target = resolve_spec(&outcome.packument, spec);
    let meta = target.as_deref().and_then(|version| {
        outcome
            .packument
            .get("versions")
            .and_then(Value::as_object)
            .and_then(|versions| versions.get(version))
    });

    let mut response = match meta {
        Some(meta) => {
            let body = serde_json::to_vec(meta).map_err(ProxyError::Serialize)?;
            (
                [(header::CONTENT_TYPE, FULL_MEDIA_TYPE)],
                body::Body::from(body),
            )
                .into_response()
        }
        None => version_not_found(package, spec, target.as_deref(), &outcome.blocked),
    };
    attach_filter_headers(&mut response, &outcome.blocked, &[]);
    Ok(response)
}

/// `GET /-/package/{package}/dist-tags` — the tag map exactly as the packument carries it.
async fn serve_dist_tags(
    state: &AppState,
    package: &str,
    headers: &HeaderMap,
) -> Result<Response, ProxyError> {
    let outcome = match resolve(state, package, headers).await? {
        Resolved::Filtered { outcome, .. } => outcome,
        Resolved::Upstream(status) => return Ok(status.into_response()),
    };
    let tags = outcome
        .packument
        .get("dist-tags")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let body = serde_json::to_vec(&tags).map_err(ProxyError::Serialize)?;
    let mut response = (
        [(header::CONTENT_TYPE, FULL_MEDIA_TYPE)],
        body::Body::from(body),
    )
        .into_response();
    attach_filter_headers(&mut response, &outcome.blocked, &[]);
    Ok(response)
}

/// Resolve `{version}` against a filtered packument: an exact version, or a dist-tag.
fn resolve_spec(packument: &Value, spec: &str) -> Option<String> {
    let versions = packument.get("versions").and_then(Value::as_object);
    if versions.is_some_and(|versions| versions.contains_key(spec)) {
        return Some(spec.to_owned());
    }
    packument
        .get("dist-tags")
        .and_then(Value::as_object)
        .and_then(|tags| tags.get(spec))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The 404 for a version that is not in the filtered document, naming the gate when one of
/// ours withheld it.
///
/// `spec` is what the client asked for and may be a dist-tag; `resolved` is the version that
/// tag names. Block records are keyed by version, so the lookup MUST use `resolved` — matching
/// on `spec` reported `version_not_found` for `GET /pkg/latest`, which is a lie: the version
/// exists upstream and this daemon is the reason it is not being served. Since tags are never
/// moved onto an older release, a withheld `latest` is the ordinary case, not a corner one.
fn version_not_found(
    package: &str,
    spec: &str,
    resolved: Option<&str>,
    blocked: &[policy::BlockRecord],
) -> Response {
    let target = resolved.unwrap_or(spec);
    match blocked.iter().find(|record| record.version == target) {
        Some(record) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": if target == spec {
                    format!("npmfilter withheld {package}@{spec}")
                } else {
                    format!("npmfilter withheld {package}@{target}, which `{spec}` names")
                },
                "code": "version_withheld",
                "reason": record.reason.as_str(),
                "detail": record.public_detail,
                "resolved_version": target,
                "action": "review it with npmfilter_recent_blocks then npmfilter_inspect, and \
                           approve with npmfilter_allow if the hook is legitimate — or request \
                           an older version explicitly. npmfilter does not move dist-tags onto \
                           older releases, so nothing was silently downgraded.",
                "npmfilter": true,
            })),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": format!("version not found: {spec}"),
                "code": "version_not_found",
                "package": package,
                "npmfilter": true,
            })),
        )
            .into_response(),
    }
}

/// State the filtering on the response itself, in both packument shapes.
///
/// `npm install` asks for the abbreviated form, which carries no `_npmfilter` summary, so
/// without these headers an all-blocked package is a bare 200 with an empty `versions` map and
/// npm reports `notarget` with nothing to point at. These show up under `npm --loglevel=http`.
fn attach_filter_headers(
    response: &mut Response,
    blocked: &[policy::BlockRecord],
    withheld_tags: &[shape::WithheldDistTag],
) {
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&blocked.len().to_string()) {
        headers.insert(HeaderName::from_static(WITHHELD_HEADER), value);
    }
    if !blocked.is_empty()
        && let Ok(value) = HeaderValue::from_str(&summarize(blocked))
    {
        headers.insert(HeaderName::from_static(REASONS_HEADER), value);
    }
    // A withheld dist-tag is the case a client cannot diagnose on its own: it asked for
    // `latest`, resolution failed, and its error says only that no version matched. Name the
    // tag and the tool that resolves it, in the one place the abbreviated shape can carry it.
    if !withheld_tags.is_empty() {
        let tags = withheld_tags
            .iter()
            .map(|entry| format!("{}={}", entry.tag, entry.version))
            .collect::<Vec<_>>()
            .join(",");
        if let Ok(value) = HeaderValue::from_str(&tags) {
            headers.insert(HeaderName::from_static(WITHHELD_TAGS_HEADER), value);
        }
        if let Ok(value) = HeaderValue::from_str(
            "resolution will fail: the version this tag names is withheld and npmfilter does \
             not downgrade tags; review it with npmfilter_recent_blocks / npmfilter_inspect / \
             npmfilter_allow, or request an older version explicitly",
        ) {
            headers.insert(HeaderName::from_static(ACTION_HEADER), value);
        }
    }
}

/// Run the policy engine and append its audit rows.
///
/// The engine reads SQLite, so it runs on the blocking pool rather than an async worker. An
/// audit-log failure is logged and swallowed: the filtering verdict already stands, and
/// failing the response would turn a logging problem into a broken install. A *storage* failure
/// is not swallowed: the store's fail-closed lookups would withhold every version, which is
/// indistinguishable from a policy verdict, so it becomes a 502 carrying the error.
///
/// `cached` says the document came from the TTL cache, in which case the ledger compares
/// without re-writing its bookkeeping — see [`Store::try_observe_with`].
async fn evaluate(
    store: Arc<Store>,
    document: Arc<Value>,
    package: String,
    config: policy::PolicyConfig,
    cached: bool,
    upstream_host: Option<String>,
) -> Result<PolicyOutcome, ProxyError> {
    let outcome = tokio::task::spawn_blocking(move || {
        let now = Utc::now();
        store.clear_failure();
        // Every version of this packument is observed in **one** transaction. One `IMMEDIATE`
        // transaction per version turned a packument with a hundred thousand versions into
        // minutes of disk-bound work behind the connection mutex.
        let observations = observations(document.as_ref());
        let checks = store.observe_batch(&package, &observations, now, !cached);
        let ledger = RequestLedger {
            store: store.as_ref(),
            bump: !cached,
            checks: observations
                .into_iter()
                .map(|(version, _)| version)
                .zip(checks)
                .collect(),
        };
        let outcome = policy::evaluate(document.as_ref(), store.as_ref(), &ledger, &config, now)?;
        if let Some(detail) = store.take_failure() {
            return Err(ProxyError::StoreUnavailable { detail });
        }
        if let Err(error) = store.record_blocks(&package, &outcome.blocked, now) {
            tracing::error!(
                package,
                %error,
                "failed to append the audit rows for a filtered packument"
            );
        }
        if !cached && let Some(upstream_host) = upstream_host.as_deref() {
            note_foreign_tarballs(store.as_ref(), &package, document.as_ref(), upstream_host, now);
        }
        Ok::<PolicyOutcome, ProxyError>(outcome)
    })
    .await??;
    Ok(outcome)
}

/// `(version, ledger identity)` for every version of a packument, in document order.
fn observations(document: &Value) -> Vec<(String, Option<String>)> {
    document
        .get("versions")
        .and_then(Value::as_object)
        .map(|versions| {
            versions
                .iter()
                .map(|(version, meta)| (version.clone(), policy::version_identity(meta)))
                .collect()
        })
        .unwrap_or_default()
}

/// Record — once per package — that upstream serves its tarballs somewhere else.
///
/// `dist.tarball` is relayed untouched by design (DESIGN.md "Tarballs — pass-through"), so a
/// URL on a host that is not the configured upstream is a fact about this registry the
/// operator has to be able to see. It is not a block: a mirror that serves npmjs.org tarball
/// URLs, or a registry fronted by a CDN, is an ordinary and legitimate arrangement, and
/// withholding every version of every package on that upstream would be a broken daemon
/// rather than a strict one. What is not acceptable is that it happen silently.
fn note_foreign_tarballs(
    store: &Store,
    package: &str,
    document: &Value,
    upstream_host: &str,
    now: chrono::DateTime<Utc>,
) {
    let Some(versions) = document.get("versions").and_then(Value::as_object) else {
        return;
    };
    let mut hosts: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut count = 0usize;
    for meta in versions.values() {
        let Some(tarball) = policy::version_tarball(meta) else {
            continue;
        };
        let host = url_host(tarball);
        if host.is_some_and(|host| host.eq_ignore_ascii_case(upstream_host)) {
            continue;
        }
        count += 1;
        if hosts.len() < 4 {
            hosts.insert(printable(host.unwrap_or("<no host>"), 128));
        }
    }
    if count == 0 {
        return;
    }
    let hosts = hosts.into_iter().collect::<Vec<_>>().join(", ");
    tracing::warn!(
        package,
        versions = count,
        hosts = %hosts,
        upstream_host,
        "upstream serves dist.tarball URLs on another host; npmfilter relays them untouched"
    );
    let entry = AuditEntry {
        ts: now,
        event: crate::store::EVENT_FOREIGN_TARBALL.to_owned(),
        severity: Severity::Warning,
        name: printable(package, 214),
        version: None,
        detail: format!(
            "{count} version(s) point dist.tarball at {hosts}, which is not the configured \
             upstream host {upstream_host}. npmfilter relays the URL untouched, so those bytes \
             are fetched from there; the version's dist.integrity is what verifies them"
        ),
    };
    if let Err(error) = store.append_audit_once(&entry) {
        tracing::warn!(package, %error, "could not record the foreign-tarball observation");
    }
}

/// The `host[:port]` of an absolute URL, if it has one.
fn url_host(url: &str) -> Option<&str> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    // `user:password@host` — the host is what comes after the last `@`.
    let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    if host.is_empty() { None } else { Some(host) }
}

/// The integrity ledger as the request path hands it to the engine.
///
/// Every version of the packument was observed in one transaction before the engine ran, so
/// `observe` is a lookup. A version the batch did not cover — impossible for a document the
/// batch was built from, but the trait cannot say so — falls back to observing it on its own,
/// which fails closed exactly as before.
///
/// `bump` is false for a document served from the packument cache: the observation was already
/// recorded when it was fetched, and repeating it would cost one write transaction per version
/// per request.
struct RequestLedger<'a> {
    store: &'a Store,
    bump: bool,
    checks: std::collections::HashMap<String, policy::LedgerCheck>,
}

impl policy::IntegrityLedger for RequestLedger<'_> {
    fn observe(
        &self,
        name: &str,
        version: &str,
        integrity: Option<&str>,
        now: chrono::DateTime<Utc>,
    ) -> policy::LedgerCheck {
        match self.checks.get(version) {
            Some(check) => check.clone(),
            None => self
                .store
                .observe_with(name, version, integrity, now, self.bump),
        }
    }
}

/// `reason=count` pairs, for one log line instead of one per withheld version.
fn summarize(blocked: &[policy::BlockRecord]) -> String {
    let mut counts: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    for record in blocked {
        *counts.entry(record.reason.as_str()).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(reason, count)| format!("{reason}={count}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Is this request a write?
///
/// The policy is an allow-list, not a deny-list: **only** `GET` and `HEAD` are reads, plus
/// `POST` to the registry's own read-only endpoints (`/-/v1/search`,
/// `/-/npm/v1/security/advisories/bulk` — `npm audit`), which live under `/-/` and never
/// classify as a package. Everything else is a write.
///
/// A deny-list is what the two bypasses were made of. `PUT` answered 405 while `DELETE` and
/// `PATCH` fell through to the verbatim proxy **with the client's `Authorization` header**,
/// letting `npm unpublish` straight through a daemon whose own error text claimed writes were
/// refused. Then any verb outside the standard set — `COPY`, `PROPFIND`, `FROB` — was neither
/// classified nor refused, so it reached upstream verbatim, credential included, at a path
/// that resolves packages. Naming the safe methods cannot fail that way: a verb nobody has
/// thought about is refused by default.
pub fn is_mutating(method: &Method, route: &Route) -> bool {
    match *method {
        Method::GET | Method::HEAD => false,
        Method::POST => !matches!(route, Route::Passthrough),
        _ => true,
    }
}

/// Refuse a path npmfilter cannot canonicalise, before anything is forwarded anywhere.
fn refuse_path(method: &Method, path: &str) -> Response {
    tracing::warn!(
        %method,
        path = %printable(path, 512),
        "refused a request whose path carries a `.` or `..` segment"
    );
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "npmfilter refuses a path containing a `.` or `..` segment",
            "detail": "npmfilter resolves a package from the path exactly as written; a URL \
                       parser between here and the registry would collapse the dot segments \
                       first, so the two would not agree on which package was asked for. That \
                       disagreement is a way to fetch a packument past every gate, so such a \
                       path is refused rather than guessed at. Ask for the package by name.",
            "code": "invalid_path",
            "npmfilter": true,
        })),
    )
        .into_response()
}

/// Refuse a mutating request with an error that says what to do instead.
fn refuse_mutation(state: &AppState, method: &Method, path: &str) -> Response {
    let upstream = state.config.upstream_base();
    tracing::warn!(
        %method,
        path,
        "refused a mutating request — npmfilter is a read-through filter"
    );
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, "GET, HEAD, POST")],
        Json(json!({
            "error": format!(
                "npmfilter refuses {method}: it is a read-through filter for {upstream}, not a \
                 registry you can write to"
            ),
            "detail": format!(
                "npmfilter gates resolution and never relays package bytes, so a write sent \
                 through it could not be trusted to arrive intact — and it holds no \
                 credentials of its own, so it is not the place your publish token belongs. \
                 Point the write at the registry that should receive it: put \
                 `@yourscope:registry=https://your.registry/` in .npmrc so publishes for that \
                 scope never come here, or pass `--registry` explicitly, e.g. \
                 `npm publish --registry {upstream}`. PUT, POST to a package path, DELETE and \
                 PATCH are all refused the same way; `allow_publish_passthrough = true` in \
                 /etc/npmfilter/config.toml relays them and audits every one."
            ),
            "code": "publish_refused",
            "method": method.as_str(),
            "upstream": upstream,
        })),
    )
        .into_response()
}

/// Build the audit entry for a mutating request that `allow_publish_passthrough` let through.
///
/// Method, path and actor — never the `Authorization` value. Whether the request carried one
/// at all is recorded, because "a write went out under someone's credential" is the fact worth
/// having; the credential itself is not this daemon's to store.
fn mutation_audit_entry(
    method: &Method,
    path: &str,
    route: &Route,
    request: &Request,
) -> AuditEntry {
    let actor = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| peer.to_string())
        .unwrap_or_else(|| "<unknown peer>".to_owned());
    let authorization = if request.headers().contains_key(header::AUTHORIZATION) {
        "present"
    } else {
        "absent"
    };
    // `PUT` and `DELETE` are never classified on the request path — they are refused before
    // routing matters — so the package name for the record is derived here. A path that names
    // no package is recorded as `-`.
    let package = match route {
        Route::Packument(package) | Route::DistTags(package) => package.clone(),
        Route::Version { package, .. } => package.clone(),
        Route::Passthrough | Route::Invalid => match classify(path) {
            Route::Packument(package) | Route::DistTags(package) => package,
            Route::Version { package, .. } => package,
            Route::Passthrough | Route::Invalid => "-".to_owned(),
        },
    };
    tracing::warn!(
        %method,
        path,
        actor,
        authorization,
        "relaying a mutating request upstream because allow_publish_passthrough is on"
    );
    AuditEntry {
        ts: Utc::now(),
        event: EVENT_PUBLISH.to_owned(),
        severity: Severity::Warning,
        name: printable(&package, 214),
        version: None,
        detail: format!(
            "relayed {method} {} for actor {actor} (allow_publish_passthrough = true; \
             authorization {authorization}, never recorded)",
            printable(path, 512)
        ),
    }
}

/// Write the passthrough audit row, refusing the request if it cannot be written.
///
/// Fail-closed on purpose: a relayed write that was not recorded is a write this daemon
/// cannot account for, and the whole point of the opt-in is the record.
async fn record_mutation(state: &AppState, entry: AuditEntry) -> Result<(), ProxyError> {
    let store = Arc::clone(&state.store);
    match tokio::task::spawn_blocking(move || store.append_audit(&entry)).await? {
        Ok(_) => Ok(()),
        Err(error) => Err(ProxyError::StoreUnavailable {
            detail: format!(
                "the mutating request was not relayed because it could not be audited: {error}"
            ),
        }),
    }
}

/// Cap and de-fang a client-supplied string before it is stored or logged.
///
/// Control characters are replaced rather than dropped, so a log line or an audit row cannot
/// be split or re-coloured by whatever a client put in a URL.
fn printable(raw: &str, limit: usize) -> String {
    raw.chars()
        .take(limit)
        .map(|character| {
            if character.is_control() {
                '.'
            } else {
                character
            }
        })
        .collect()
}

/// DESIGN.md "Other endpoints": search, audit bulk and everything else, proxied verbatim.
async fn proxy_through(state: &AppState, request: Request) -> Result<Response, ProxyError> {
    let (parts, body) = request.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|target| target.as_str().to_owned())
        .unwrap_or_else(|| parts.uri.path().to_owned());
    let body = body::to_bytes(body, MAX_PROXY_BODY)
        .await
        .map_err(ProxyError::RequestBody)?;

    tracing::debug!(method = %parts.method, path = %path_and_query, "proxying transparently");
    let response = state
        .upstream
        .forward(parts.method, &path_and_query, &parts.headers, body)
        .await?;
    upstream::into_response(response)
}
