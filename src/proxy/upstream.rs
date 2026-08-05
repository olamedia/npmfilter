//! The upstream registry client — DESIGN.md "Request path" step 1 and "Other endpoints".
//!
//! Two jobs:
//!
//! * [`Upstream::fetch_packument`] — always asks for the **full** packument, because the
//!   abbreviated form carries no `time` and the age gate cannot be evaluated without it. The
//!   client's `Authorization` header is forwarded when present, so private packages resolve.
//! * [`Upstream::forward`] — verbatim proxying for `/-/v1/search`, the audit bulk endpoint
//!   and everything else, with the response body streamed rather than buffered.

use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use serde_json::Value;

use super::error::ProxyError;
use super::shape::{FULL_MEDIA_TYPE, encode_package_path};

/// How long a single upstream request may take, end to end. Packuments are metadata; a
/// fetch that has not finished in a minute is a failure the client should hear about.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// How long the TCP + TLS handshake may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest packument body this daemon will buffer, parse and evaluate.
///
/// Measured against the live registry on 2026-08-05: lodash 248 KB, react 6.9 MB,
/// `aws-sdk` 10.6 MB, `@types/node` 11.1 MB — the largest packuments npm actually publishes.
/// 64 MiB is several times the worst real case and still bounds the parse-and-clone cost that
/// follows, so a hostile or broken `upstream` cannot exhaust memory here.
pub const MAX_PACKUMENT_BYTES: usize = 64 * 1024 * 1024;

/// The most versions a packument may declare before this daemon refuses to evaluate it.
///
/// The byte cap alone does not bound the *work*: every version is a policy evaluation, a
/// ledger observation and a row in the rebuilt document, and 64 MiB of well-formed JSON is
/// several hundred thousand of them. Measured against a hostile upstream, one such request
/// held the daemon busy for minutes and appended tens of megabytes of permanent ledger state.
///
/// 20 000 is far above anything npm publishes — the busiest real packages are in the low
/// thousands — and an over-limit document is **refused**, not truncated: serving the first
/// N versions of a document would be a filtered answer that silently withheld the rest.
pub const MAX_PACKUMENT_VERSIONS: usize = 20_000;

/// Headers that describe one hop and must not be copied to the next one (RFC 9110 §7.6.1).
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// What an upstream packument fetch produced.
#[derive(Debug)]
pub enum PackumentFetch {
    /// A parsed full packument, ready for the policy engine.
    Document(Value),
    /// Upstream declined — 404 for an unknown package, 401 for a private one. Forwarded
    /// verbatim so npm sees the registry's own answer instead of an invented one.
    Status(UpstreamStatus),
}

/// A non-success upstream answer, captured for verbatim forwarding.
#[derive(Debug, Clone)]
pub struct UpstreamStatus {
    /// The status upstream returned.
    pub status: StatusCode,
    /// Upstream's `Content-Type`, if it sent one.
    pub content_type: Option<HeaderValue>,
    /// The body bytes, as received.
    pub body: Bytes,
}

impl IntoResponse for UpstreamStatus {
    fn into_response(self) -> Response {
        let mut response = (self.status, Body::from(self.body)).into_response();
        if let Some(content_type) = self.content_type {
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, content_type);
        }
        response
    }
}

/// The HTTP client for the configured upstream registry.
#[derive(Debug, Clone)]
pub struct Upstream {
    client: reqwest::Client,
    base: String,
    max_packument_bytes: usize,
    max_packument_versions: usize,
}

impl Upstream {
    /// Build a client for `base` (trailing slashes are trimmed).
    pub fn new(base: impl Into<String>) -> Result<Self, ProxyError> {
        let base = base.into().trim_end_matches('/').to_owned();
        let client = reqwest::Client::builder()
            .user_agent(concat!("npmfilter/", env!("CARGO_PKG_VERSION")))
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|source| ProxyError::Client {
                base: base.clone(),
                source,
            })?;
        Ok(Self {
            client,
            base,
            max_packument_bytes: MAX_PACKUMENT_BYTES,
            max_packument_versions: MAX_PACKUMENT_VERSIONS,
        })
    }

    /// Build a client around an existing `reqwest::Client`.
    pub fn with_client(client: reqwest::Client, base: impl Into<String>) -> Self {
        Self {
            client,
            base: base.into().trim_end_matches('/').to_owned(),
            max_packument_bytes: MAX_PACKUMENT_BYTES,
            max_packument_versions: MAX_PACKUMENT_VERSIONS,
        }
    }

    /// Override the packument body cap. Used by tests, which cannot afford to stream 64 MiB.
    pub fn with_max_packument_bytes(mut self, limit: usize) -> Self {
        self.max_packument_bytes = limit;
        self
    }

    /// The packument body cap in force.
    pub fn max_packument_bytes(&self) -> usize {
        self.max_packument_bytes
    }

    /// Override the version-count cap. Used by tests, which cannot afford 20 000 versions.
    pub fn with_max_packument_versions(mut self, limit: usize) -> Self {
        self.max_packument_versions = limit;
        self
    }

    /// The version-count cap in force.
    pub fn max_packument_versions(&self) -> usize {
        self.max_packument_versions
    }

    /// The upstream base URL, without a trailing slash.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// The underlying client, for callers that need to issue their own requests.
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// The URL this daemon would fetch for `package`.
    pub fn packument_url(&self, package: &str) -> String {
        format!("{}/{}", self.base, encode_package_path(package))
    }

    /// Fetch the **full** packument for `package`, forwarding `authorization` if present.
    pub async fn fetch_packument(
        &self,
        package: &str,
        authorization: Option<&HeaderValue>,
    ) -> Result<PackumentFetch, ProxyError> {
        let url = self.packument_url(package);
        let mut request = self
            .client
            .get(&url)
            .header(header::ACCEPT, FULL_MEDIA_TYPE);
        if let Some(authorization) = authorization {
            request = request.header(header::AUTHORIZATION, authorization);
        }

        let mut response = request
            .send()
            .await
            .map_err(|source| ProxyError::Upstream {
                url: url.clone(),
                source,
            })?;
        let status = response.status();
        let content_type = response.headers().get(header::CONTENT_TYPE).cloned();

        // `upstream` is a config field — a mirror, a private registry, or a middlebox — so the
        // body is read under a hard cap rather than buffered whole. The policy engine then
        // clones the parsed document, so an unbounded body here is an unbounded multiple of it
        // in memory.
        let limit = self.max_packument_bytes;
        if let Some(declared) = response.content_length()
            && declared > limit as u64
        {
            return Err(ProxyError::PackumentTooLarge {
                package: package.to_owned(),
                limit,
            });
        }
        let mut buffer: Vec<u8> = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|source| ProxyError::Upstream {
            url: url.clone(),
            source,
        })? {
            if buffer.len().saturating_add(chunk.len()) > limit {
                return Err(ProxyError::PackumentTooLarge {
                    package: package.to_owned(),
                    limit,
                });
            }
            buffer.extend_from_slice(&chunk);
        }
        let body = Bytes::from(buffer);

        if !status.is_success() {
            return Ok(PackumentFetch::Status(UpstreamStatus {
                status,
                content_type,
                body,
            }));
        }

        let document: Value =
            serde_json::from_slice(&body).map_err(|source| ProxyError::BadPackument {
                package: package.to_owned(),
                source,
            })?;

        // Bounded work, not just a bounded body: every version below costs an evaluation and a
        // ledger row. Over the limit is a refusal — a partial answer would be a filtered
        // packument that withheld versions no gate ever looked at.
        let versions = document
            .get("versions")
            .and_then(Value::as_object)
            .map(serde_json::Map::len)
            .unwrap_or(0);
        if versions > self.max_packument_versions {
            return Err(ProxyError::PackumentTooManyVersions {
                package: package.to_owned(),
                limit: self.max_packument_versions,
            });
        }
        Ok(PackumentFetch::Document(document))
    }

    /// Proxy a request through verbatim, returning the upstream response unread.
    ///
    /// `path_and_query` is the client's own already-encoded path, so nothing is rewritten.
    pub async fn forward(
        &self,
        method: Method,
        path_and_query: &str,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<reqwest::Response, ProxyError> {
        let url = format!("{}{}", self.base, path_and_query);
        let mut request = self.client.request(method, &url);
        for (name, value) in headers {
            if is_stripped_request_header(name) {
                continue;
            }
            request = request.header(name, value);
        }
        if !body.is_empty() {
            request = request.body(body);
        }
        request.send().await.map_err(|source| ProxyError::Upstream {
            url: url.clone(),
            source,
        })
    }
}

/// Turn an upstream response into ours, streaming the body straight through.
pub fn into_response(response: reqwest::Response) -> Result<Response, ProxyError> {
    let status = response.status();
    let headers = response.headers().clone();
    let mut builder = Response::builder().status(status);
    for (name, value) in headers.iter() {
        if is_stripped_response_header(name) {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from_stream(response.bytes_stream()))
        .map_err(ProxyError::Response)
}

/// Headers not to copy from the client's request to the upstream one.
///
/// `accept-encoding` is dropped because the client decides its own transfer encoding with
/// upstream; reqwest negotiates and transparently decodes gzip for us, and forwarding the
/// client's preference would leave the body decoded but the header claiming otherwise.
fn is_stripped_request_header(name: &HeaderName) -> bool {
    let name = name.as_str();
    HOP_BY_HOP.contains(&name) || matches!(name, "host" | "content-length" | "accept-encoding")
}

/// Headers not to copy from the upstream response to ours.
///
/// `content-encoding` and `content-length` describe the body reqwest already decoded; hyper
/// frames the body it is actually handed.
fn is_stripped_response_header(name: &HeaderName) -> bool {
    let name = name.as_str();
    HOP_BY_HOP.contains(&name) || matches!(name, "content-length" | "content-encoding")
}
