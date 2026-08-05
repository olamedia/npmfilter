//! `npmfilter mcp` — DESIGN.md "MCP surface", an rmcp 3.1 stdio server.
//!
//! Seven tools: `npmfilter_status`, `npmfilter_recent_blocks`, `npmfilter_inspect`,
//! `npmfilter_allow`, `npmfilter_deny`, `npmfilter_rules`, `npmfilter_ledger`.
//!
//! # How the shim reaches daemon state
//!
//! Over the Unix socket of DESIGN.md "MCP transport" — see [`crate::control`]. This process is
//! a **client**: it opens no database, holds no policy and decides nothing. It turns a tool
//! call into one framed request, and renders what comes back.
//!
//! An earlier implementation had the shim open `rules.db` directly. That is what forced the
//! state directory to be group-writable, and it made membership of group `npmfilter` the
//! ability to write allow rules straight into the policy store — around the daemon's
//! validation, and around its audit log. Everything now goes through one validated, audited
//! code path in the daemon.
//!
//! If the daemon is not running, every tool fails with an actionable error. There is no
//! fallback to direct database access, deliberately: a shim that sometimes writes the database
//! itself is a shim whose writes sometimes miss the validator.
//!
//! `npmfilter allow` takes effect on the daemon's next request, because the request path
//! re-runs the policy per request against the same database (it caches the unfiltered upstream
//! document, not the verdict). No reload is needed.
//!
//! Everything the tools return is written to stdout by the MCP transport, so tracing goes to
//! stderr — `main` already configures it that way.
//!
//! The submodules here — [`inspect`] and [`blocks`] — are the *daemon-side* implementations of
//! two of these tools. They live under this module because that is where their output types
//! are defined; they are called by [`crate::control::service`], never by this shim.

pub mod blocks;
pub mod inspect;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use anyhow::Context;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{Implementation, InitializeResult, ServerCapabilities, ServerInfo};
use rmcp::transport::stdio;
use rmcp::{ErrorData, Json, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::Config;
use crate::control::client::ControlClient;
use crate::control::protocol::{
    AllowArgs, Answer, DenyArgs, InspectArgs, LedgerArgs, PinRequest, RecentBlocksArgs, Request,
    RulesArgs, StatusArgs,
};
use crate::control::{ClientError, LABEL_MCP};
use crate::policy::Verdict;
use crate::store::StoredRule;

use blocks::RecentBlock;
use inspect::{HookCommand, InspectReport};

/// Default number of audit rows `npmfilter_recent_blocks` returns.
pub const DEFAULT_RECENT_LIMIT: u32 = 20;
/// Ceiling on that number, so one call cannot drag the whole audit log through the transport.
pub const MAX_RECENT_LIMIT: u32 = 500;

/// Instructions handed to the MCP client at initialize time.
const INSTRUCTIONS: &str = "\
npmfilter is a local npm registry filtering proxy. It withholds package versions that are too \
new or that run install scripts, until they are approved.

When an npm install fails, start with npmfilter_recent_blocks: it names the package, the version, \
the gate that stopped it and the exact install-hook commands. Then npmfilter_inspect(package, \
version) streams the published tarball, reads only its package.json and reports the publish age, \
the dist.integrity an approval would pin to, the install-hook commands with their hashes, and the \
script delta against the previous published version. A version that NEWLY ACQUIRES an install \
hook is the shape of a supply-chain compromise — read that field before approving anything. \
npmfilter_allow records the approval pinned to the current integrity and script hashes; \
npmfilter_deny blocks a version outright; npmfilter_rules lists what is recorded; \
npmfilter_ledger shows every integrity npmfilter has ever observed for a package.";

// -- tool inputs -----------------------------------------------------------------------------

/// `npmfilter_recent_blocks` arguments.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct RecentBlocksRequest {
    /// Only show blocks for this package.
    pub package: Option<String>,
    /// How many to return (default 20, max 500).
    pub limit: Option<u32>,
}

/// `npmfilter_inspect` arguments.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct InspectRequest {
    /// Package name, e.g. `sqlite3` or `@scope/name`.
    pub package: String,
    /// Version to inspect. Defaults to `dist-tags.latest`.
    #[serde(default)]
    pub version: Option<String>,
}

/// `npmfilter_allow` arguments.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AllowRequest {
    /// Package name.
    pub package: String,
    /// Exact version to approve.
    pub version: String,
    /// Why this approval is being granted. Recorded on the rule and in the audit log.
    #[serde(default)]
    pub reason: Option<String>,
    /// The files you reviewed, package-relative. The daemon hashes each from the tarball it
    /// fetches itself, so a pin always describes bytes that were really published.
    #[serde(default)]
    pub pins: Vec<PinInput>,
}

/// One file an approval names.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PinInput {
    /// Package-relative path inside the tarball, e.g. `install.js`.
    pub path: String,
    /// The sha256 you expect this file to have, if you want it checked. A disagreement fails
    /// the whole approval — it means the published bytes moved between inspection and
    /// approval, which is exactly when an approval should not be recorded.
    #[serde(default)]
    pub sha256: Option<String>,
}

/// `npmfilter_deny` arguments.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DenyRequest {
    /// Package name.
    pub package: String,
    /// Exact version to block.
    pub version: String,
    /// Why this version is being denied.
    #[serde(default)]
    pub reason: Option<String>,
}

/// `npmfilter_rules` arguments.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct RulesRequest {
    /// Only show rules for this package.
    pub package: Option<String>,
    /// Only show rules with this verdict — `allow` or `deny`.
    pub verdict: Option<String>,
}

/// `npmfilter_ledger` arguments.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LedgerRequest {
    /// Package whose integrity history to read.
    pub package: String,
}

// -- tool outputs ----------------------------------------------------------------------------

/// Whether the filtering daemon is up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DaemonStatus {
    /// The address the daemon is configured to bind.
    pub listen: String,
    /// Whether a TCP connection to it succeeded just now.
    pub reachable: bool,
    /// The upstream registry it proxies.
    pub upstream: String,
    /// When the probe ran, RFC 3339.
    pub checked_at: String,
    /// What the answer means in practice.
    pub detail: String,
}

/// The policy in force, as the daemon reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyStatus {
    /// Versions younger than this are withheld; 0 disables the age gate.
    pub min_age_days: u32,
    /// Days a version carrying an install hook must be published before ANY approval admits
    /// it. The one gate an approval cannot override, so it belongs in any statement of the
    /// policy in force.
    pub install_script_quarantine_days: u32,
    /// Scopes exempt from the automatic gates.
    pub bypass_scopes: Vec<String>,
    /// In-memory packument TTL, in seconds.
    pub packument_ttl_secs: u64,
}

/// How many rules are recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuleCounts {
    /// Approvals.
    pub allow: u64,
    /// Denials.
    pub deny: u64,
}

/// `npmfilter_status` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StatusReport {
    /// This binary's version.
    pub version: String,
    /// Daemon health.
    pub daemon: DaemonStatus,
    /// Active policy.
    pub policy: PolicyStatus,
    /// Rule counts.
    pub rules: RuleCounts,
    /// The state database both the daemon and this shim use.
    pub state_path: String,
    /// How this shim reaches daemon state.
    pub transport: String,
}

/// `npmfilter_recent_blocks` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecentBlocksReport {
    /// The package filter that was applied, if any.
    pub package: Option<String>,
    /// How many rows were returned.
    pub count: usize,
    /// The withheld versions, newest first.
    pub blocks: Vec<RecentBlock>,
    /// What to do when the list is empty.
    pub note: String,
}

/// One recorded rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuleView {
    /// Row id.
    pub id: i64,
    /// Package name.
    pub package: String,
    /// Version the rule covers.
    pub version: String,
    /// `allow` or `deny`.
    pub verdict: String,
    /// The sha512 an allow rule is pinned to.
    pub integrity: Option<String>,
    /// The install-hook commands the approval covers, with their hashes.
    pub scripts: Vec<HookCommand>,
    /// sha256 over the sorted install-hook map.
    pub scripts_sha256: Option<String>,
    /// The files the approval named, each with the sha256 the daemon computed from the
    /// published tarball. `None` means the approval named no files — which is not the same
    /// claim as "the reviewer checked and pinned nothing".
    pub pins: Option<Vec<PinnedFile>>,
    /// Why the rule exists.
    pub reason: Option<String>,
    /// Who recorded it.
    pub actor: Option<String>,
    /// When, RFC 3339.
    pub created: String,
}

impl RuleView {
    /// The wire view of one stored rule.
    pub fn from_stored(stored: &StoredRule) -> Self {
        Self {
            id: stored.id,
            package: stored.rule.name.clone(),
            version: stored.rule.version.clone(),
            verdict: match stored.rule.verdict {
                Verdict::Allow => "allow".to_owned(),
                Verdict::Deny => "deny".to_owned(),
            },
            integrity: stored.rule.integrity.clone(),
            scripts: hooks_from_json(stored.scripts_json.as_deref()),
            scripts_sha256: stored.rule.scripts_sha256.clone(),
            pins: stored.pins.as_ref().map(|pins| {
                pins.files()
                    .iter()
                    .map(|(path, sha256)| PinnedFile {
                        path: path.clone(),
                        sha256: sha256.clone(),
                    })
                    .collect()
            }),
            reason: stored.rule.reason.clone(),
            actor: stored.rule.actor.clone(),
            created: stored.created.to_rfc3339(),
        }
    }
}

/// One file an approval pinned, with the digest the daemon computed itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PinnedFile {
    /// Path inside the package, with the tarball's `package/` root stripped.
    pub path: String,
    /// sha256 of that file's bytes as published.
    pub sha256: String,
}

/// `npmfilter_rules` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RulesReport {
    /// How many rules matched.
    pub count: usize,
    /// The rules, ordered by package then version.
    pub rules: Vec<RuleView>,
}

/// `npmfilter_allow` / `npmfilter_deny` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuleWritten {
    /// The rule as recorded.
    pub rule: RuleView,
    /// What changes as a result.
    pub effect: String,
}

/// One version in the integrity ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LedgerVersion {
    /// The version observed.
    pub version: String,
    /// The `dist.integrity` recorded the first time it was seen. Never overwritten.
    pub integrity: Option<String>,
    /// When it was first observed, RFC 3339.
    pub first_seen: String,
    /// When it was last confirmed unchanged, RFC 3339.
    pub last_seen: String,
    /// How many confirmed observations of those exact bytes.
    pub times_seen: u64,
    /// How many times a DIFFERENT hash was served for this version. The recorded hash above
    /// never moves — it is the evidence — so this is what makes repeated replacement attempts
    /// visible.
    pub mismatch_count: u64,
    /// When the most recent mismatch was observed, RFC 3339.
    pub last_mismatch: Option<String>,
}

/// `npmfilter_ledger` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LedgerReport {
    /// The package.
    pub package: String,
    /// How many versions have ever been observed.
    pub count: usize,
    /// Every observed version, newest observation first.
    pub versions: Vec<LedgerVersion>,
    /// Every `IntegrityChanged` event recorded for this package — version replacement.
    pub integrity_changed: Vec<RecentBlock>,
    /// What the ledger means.
    pub note: String,
}

// -- the server ------------------------------------------------------------------------------

/// The MCP server: the seven DESIGN.md tools, each one a control-socket request.
///
/// It holds a socket path and nothing else. No store, no upstream client, no policy — those
/// live in the daemon, which is the only thing allowed to have them.
#[derive(Clone)]
pub struct McpServer {
    client: Arc<ControlClient>,
    tool_router: ToolRouter<Self>,
}

impl McpServer {
    /// Build the shim from a loaded config.
    pub fn new(config: &Config) -> Self {
        Self::with_client(ControlClient::new(config.socket_path.clone(), LABEL_MCP))
    }

    /// Build the shim around an existing client — used by tests against a temporary socket.
    pub fn with_client(client: ControlClient) -> Self {
        Self {
            client: Arc::new(client),
            tool_router: Self::tool_router(),
        }
    }

    /// The control-socket client this shim talks through.
    pub fn client(&self) -> &ControlClient {
        &self.client
    }

    /// Send one request and insist on the answer shape the tool expects.
    async fn send(&self, request: Request) -> Result<Answer, ErrorData> {
        self.client.send(request).await.map_err(client_error)
    }
}

#[tool_router(router = tool_router)]
impl McpServer {
    /// DESIGN.md "MCP surface" — daemon health, active policy, rule counts.
    #[tool(
        name = "npmfilter_status",
        description = "Daemon health, the policy in force and how many allow/deny rules are recorded. Start here to confirm npmfilter is actually running and what it is enforcing."
    )]
    pub async fn status(&self) -> Result<Json<StatusReport>, ErrorData> {
        match self.send(Request::Status(StatusArgs {})).await? {
            Answer::Status(report) => Ok(Json(*report)),
            other => Err(unexpected("status", &other)),
        }
    }

    /// DESIGN.md "MCP surface" — the entry point when an install fails.
    #[tool(
        name = "npmfilter_recent_blocks",
        description = "What npmfilter recently withheld and why: package, version, the gate that stopped it, and the exact install-hook commands it would have run. This is the first tool to call when an npm install fails."
    )]
    pub async fn recent_blocks(
        &self,
        params: Parameters<RecentBlocksRequest>,
    ) -> Result<Json<RecentBlocksReport>, ErrorData> {
        let RecentBlocksRequest { package, limit } = params.0;
        match self
            .send(Request::RecentBlocks(RecentBlocksArgs { package, limit }))
            .await?
        {
            Answer::RecentBlocks(report) => Ok(Json(*report)),
            other => Err(unexpected("recent_blocks", &other)),
        }
    }

    /// DESIGN.md "MCP surface" — stream the tarball, keep `package.json` and a digest per
    /// entry, discard the bytes.
    #[tool(
        name = "npmfilter_inspect",
        description = "Inspect one published version before approving it. The daemon streams the tarball from the registry, keeping only its package.json and a sha256 per file — no package bytes are written to disk. Reports publish time and age, dist.integrity, the install-hook commands with their hashes, the SCRIPT DELTA against the previous published version (a version that newly acquires an install hook is the compromise shape), a digest for every published file, maintainers and _npmUser, whether a provenance attestation exists, and the file count and unpacked size. IMPORTANT: the script delta compares COMMAND STRINGS only — an unchanged `postinstall: node install.js` says nothing about what install.js contains. If an earlier approval for this package pinned files, pin_audit reports each one as unchanged, changed or absent here; read every changed entry before approving. Use the files list to pick paths for npmfilter_allow's pins."
    )]
    pub async fn inspect(
        &self,
        params: Parameters<InspectRequest>,
    ) -> Result<Json<InspectReport>, ErrorData> {
        let InspectRequest { package, version } = params.0;
        match self
            .send(Request::Inspect(InspectArgs { package, version }))
            .await?
        {
            Answer::Inspect(report) => Ok(Json(*report)),
            other => Err(unexpected("inspect", &other)),
        }
    }

    /// DESIGN.md "MCP surface" — approval pinned to the current integrity and script hashes.
    #[tool(
        name = "npmfilter_allow",
        description = "Approve one package version. The daemon pins the rule to that version's current dist.integrity (sha512) and to the sha256 of its exact install-hook commands, so the approval lapses the moment either changes. Optionally pass `pins`: the files you actually reviewed, package-relative (e.g. install.js). The daemon fetches the tarball and hashes each itself — if you also state a sha256 and it disagrees, the whole approval is refused, which means the bytes moved between your inspection and your approval. Inspect the version first."
    )]
    pub async fn allow(
        &self,
        params: Parameters<AllowRequest>,
    ) -> Result<Json<RuleWritten>, ErrorData> {
        let AllowRequest {
            package,
            version,
            reason,
            pins,
        } = params.0;
        match self
            .send(Request::Allow(AllowArgs {
                package,
                version,
                reason,
                pins: pins
                    .into_iter()
                    .map(|pin| PinRequest {
                        path: pin.path,
                        sha256: pin.sha256,
                    })
                    .collect(),
            }))
            .await?
        {
            Answer::Rule(written) => Ok(Json(*written)),
            other => Err(unexpected("allow", &other)),
        }
    }

    /// DESIGN.md "MCP surface" — block a version outright.
    #[tool(
        name = "npmfilter_deny",
        description = "Block one package version outright. A deny rule beats every other gate except the integrity ledger, and needs no network round trip."
    )]
    pub async fn deny(
        &self,
        params: Parameters<DenyRequest>,
    ) -> Result<Json<RuleWritten>, ErrorData> {
        let DenyRequest {
            package,
            version,
            reason,
        } = params.0;
        match self
            .send(Request::Deny(DenyArgs {
                package,
                version,
                reason,
            }))
            .await?
        {
            Answer::Rule(written) => Ok(Json(*written)),
            other => Err(unexpected("deny", &other)),
        }
    }

    /// DESIGN.md "MCP surface" — list existing rules.
    #[tool(
        name = "npmfilter_rules",
        description = "List the recorded allow/deny rules, optionally filtered by package or verdict. Each rule shows what it is pinned to, who recorded it and why."
    )]
    pub async fn rules(
        &self,
        params: Parameters<RulesRequest>,
    ) -> Result<Json<RulesReport>, ErrorData> {
        let RulesRequest { package, verdict } = params.0;
        match self
            .send(Request::Rules(RulesArgs { package, verdict }))
            .await?
        {
            Answer::Rules(report) => Ok(Json(*report)),
            other => Err(unexpected("rules", &other)),
        }
    }

    /// DESIGN.md "MCP surface" — integrity history and any replacement events.
    #[tool(
        name = "npmfilter_ledger",
        description = "Every dist.integrity npmfilter has ever observed for a package, plus any IntegrityChanged events and how many times a replaced version has been served since. Published npm versions are immutable, so a version whose hash moved has been replaced — the strongest signal this daemon can produce."
    )]
    pub async fn ledger(
        &self,
        params: Parameters<LedgerRequest>,
    ) -> Result<Json<LedgerReport>, ErrorData> {
        match self
            .send(Request::Ledger(LedgerArgs {
                package: params.0.package,
            }))
            .await?
        {
            Answer::Ledger(report) => Ok(Json(*report)),
            other => Err(unexpected("ledger", &other)),
        }
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerInfo {
        InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("npmfilter", env!("CARGO_PKG_VERSION"))
                    .with_title("npmfilter")
                    .with_description(
                        "Local npm registry filtering daemon: release-age and install-script \
                         gates with content-pinned manual approval.",
                    ),
            )
            .with_instructions(INSTRUCTIONS)
    }
}

/// `npmfilter mcp` — serve MCP over stdio, talking to the daemon over its control socket.
///
/// No database is opened here. If the daemon is down, every tool call answers with the error
/// that says how to start it.
pub fn serve_blocking(config: Config) -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?;

    runtime.block_on(async move {
        let server = McpServer::new(&config);
        tracing::info!(
            socket = %config.socket_path.display(),
            "npmfilter MCP stdio server ready — daemon state is reached over the control socket"
        );
        let service = server
            .serve(stdio())
            .await
            .context("starting the npmfilter MCP stdio server")?;
        let reason = service
            .waiting()
            .await
            .context("the npmfilter MCP server task failed")?;
        tracing::info!(?reason, "npmfilter MCP server stopped");
        Ok(())
    })
}

// -- helpers ---------------------------------------------------------------------------------

/// Turn a control-socket failure into the error an MCP client sees.
///
/// A refusal the daemon issued keeps its own class, so a bad package name reads as a
/// parameter error rather than as an internal one; everything else — including "the daemon is
/// not running" — is internal, with the whole actionable message intact.
fn client_error(error: ClientError) -> ErrorData {
    match &error {
        ClientError::Refused(failure) => match failure.code.as_str() {
            "invalid_request" | "not_found" => {
                ErrorData::invalid_params(failure.message.clone(), None)
            }
            _ => ErrorData::internal_error(failure.message.clone(), None),
        },
        _ => {
            let mut message = error.to_string();
            let mut source = std::error::Error::source(&error);
            while let Some(cause) = source {
                message.push_str(&format!(": {cause}"));
                source = cause.source();
            }
            ErrorData::internal_error(message, None)
        }
    }
}

/// The daemon answered a different operation than the one that was asked.
fn unexpected(operation: &str, answer: &Answer) -> ErrorData {
    ErrorData::internal_error(
        format!(
            "the npmfilter daemon answered {operation} with a {} result",
            answer_name(answer)
        ),
        None,
    )
}

/// The name of an answer variant, for the mismatch message.
fn answer_name(answer: &Answer) -> &'static str {
    match answer {
        Answer::Status(_) => "status",
        Answer::RecentBlocks(_) => "recent_blocks",
        Answer::Inspect(_) => "inspect",
        Answer::Rule(_) => "rule",
        Answer::Rules(_) => "rules",
        Answer::Ledger(_) => "ledger",
        Answer::Seed(_) => "seed",
    }
}

/// The install hooks a stored rule's `scripts_json` records, with their hashes.
fn hooks_from_json(scripts_json: Option<&str>) -> Vec<HookCommand> {
    let Some(text) = scripts_json else {
        return Vec::new();
    };
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    crate::policy::INSTALL_HOOKS
        .iter()
        .filter_map(|hook| {
            map.get(*hook)
                .and_then(Value::as_str)
                .map(|command| HookCommand::new(*hook, command))
        })
        .collect()
}
