//! Request-path errors.
//!
//! Every failure in the request path becomes an HTTP response with a JSON body — DESIGN.md's
//! daemon is a hard dependency of installs, so a bad upstream response must never take the
//! process down. There is no `unwrap` and no panic on this path; a panic inside the blocking
//! policy task surfaces as [`ProxyError::Join`] and answers 500.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;

use crate::policy::PolicyError;

/// Anything that can go wrong serving a request.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// The upstream HTTP client could not be built (bad TLS setup, bad base URL).
    #[error("failed to build the upstream HTTP client for {base}")]
    Client {
        /// The configured upstream base URL.
        base: String,
        /// The reqwest failure.
        #[source]
        source: reqwest::Error,
    },

    /// The upstream registry could not be reached, or the response body could not be read.
    #[error("upstream request to {url} failed")]
    Upstream {
        /// The URL that was attempted.
        url: String,
        /// The reqwest failure.
        #[source]
        source: reqwest::Error,
    },

    /// Upstream answered 2xx with something that is not a JSON packument.
    #[error("upstream returned a body for {package} that is not a JSON packument")]
    BadPackument {
        /// The package that was requested.
        package: String,
        /// The parse failure.
        #[source]
        source: serde_json::Error,
    },

    /// Upstream's packument body is larger than this daemon will buffer.
    #[error("upstream packument for {package} exceeds the {limit}-byte limit")]
    PackumentTooLarge {
        /// The package that was requested.
        package: String,
        /// The cap that was exceeded — [`super::MAX_PACKUMENT_BYTES`].
        limit: usize,
    },

    /// Upstream's packument declares more versions than this daemon will evaluate.
    #[error("upstream packument for {package} declares more than {limit} versions")]
    PackumentTooManyVersions {
        /// The package that was requested.
        package: String,
        /// The cap that was exceeded — [`super::MAX_PACKUMENT_VERSIONS`].
        limit: usize,
    },

    /// The daemon is already evaluating as many packuments at once as it will hold in memory.
    ///
    /// Only reachable if the concurrency gate is closed, which nothing does while the daemon
    /// is running; it exists so the gate can never be a silent no-op.
    #[error("npmfilter cannot take another packument evaluation right now: {detail}")]
    Unavailable {
        /// What was refused.
        detail: String,
    },

    /// The packument parsed, but the policy engine could not make sense of it.
    #[error("upstream packument is malformed")]
    Policy(#[from] PolicyError),

    /// The rules store or the integrity ledger could not be read while evaluating.
    ///
    /// The store's own trait impls fail closed, so a broken database withholds every version.
    /// Answering an empty packument would make "policy withheld everything", "the state
    /// database is broken" and "that version was never published" indistinguishable, so this
    /// surfaces as a gateway error carrying the storage failure instead.
    #[error("the npmfilter state database is unavailable: {detail}")]
    StoreUnavailable {
        /// The storage failure, as the store reported it.
        detail: String,
    },

    /// The blocking policy task failed — cancelled, or it panicked.
    #[error("the policy evaluation task failed")]
    Join(#[from] tokio::task::JoinError),

    /// The filtered packument could not be serialized.
    #[error("failed to serialize the filtered packument")]
    Serialize(#[source] serde_json::Error),

    /// The proxied request body could not be read, or exceeded the limit.
    #[error("failed to read the proxied request body")]
    RequestBody(#[source] axum::Error),

    /// The proxied response could not be assembled.
    #[error("failed to build the proxied response")]
    Response(#[source] axum::http::Error),
}

impl ProxyError {
    /// The status this failure answers with.
    ///
    /// Anything upstream's fault is a 502, so npm reports a gateway failure rather than
    /// silently treating a broken fetch as "no such package".
    pub fn status(&self) -> StatusCode {
        match self {
            ProxyError::Client { .. }
            | ProxyError::Upstream { .. }
            | ProxyError::BadPackument { .. }
            | ProxyError::PackumentTooLarge { .. }
            | ProxyError::PackumentTooManyVersions { .. }
            | ProxyError::StoreUnavailable { .. }
            | ProxyError::Policy(_) => StatusCode::BAD_GATEWAY,
            ProxyError::Unavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            ProxyError::RequestBody(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ProxyError::Join(_) | ProxyError::Serialize(_) | ProxyError::Response(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    /// A stable machine-readable code for the JSON body.
    pub fn code(&self) -> &'static str {
        match self {
            ProxyError::Client { .. } => "upstream_client",
            ProxyError::Upstream { .. } => "upstream_unavailable",
            ProxyError::BadPackument { .. } => "bad_packument",
            ProxyError::PackumentTooLarge { .. } => "packument_too_large",
            ProxyError::PackumentTooManyVersions { .. } => "packument_too_many_versions",
            ProxyError::Unavailable { .. } => "unavailable",
            ProxyError::StoreUnavailable { .. } => "store_unavailable",
            ProxyError::Policy(_) => "malformed_packument",
            ProxyError::Join(_) => "policy_task_failed",
            ProxyError::Serialize(_) => "serialization_failed",
            ProxyError::RequestBody(_) => "request_body",
            ProxyError::Response(_) => "response_build",
        }
    }

    /// The full `error: caused by: …` chain, flattened for the response body.
    pub fn chain(&self) -> String {
        let mut out = self.to_string();
        let mut source: Option<&(dyn std::error::Error + 'static)> =
            std::error::Error::source(self);
        while let Some(error) = source {
            out.push_str(": ");
            out.push_str(&error.to_string());
            source = error.source();
        }
        out
    }
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let status = self.status();
        let chain = self.chain();
        tracing::error!(
            status = status.as_u16(),
            code = self.code(),
            error = %chain,
            "npmfilter could not serve a request"
        );
        (
            status,
            Json(json!({
                "error": format!("npmfilter: {self}"),
                "detail": chain,
                "code": self.code(),
            })),
        )
            .into_response()
    }
}
