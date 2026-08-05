//! The control-socket wire protocol.
//!
//! One request per connection, one response, then close. A frame is a single line of JSON
//! terminated by `\n`; there is no continuation, no streaming and no second request, so a
//! client cannot hold a connection open feeding partial frames.
//!
//! # This is untrusted input
//!
//! Reaching the socket means being in the `npmfilter` group, which is the right to approve a
//! package. It is **not** a reason to skip validation: the daemon is the one component that
//! must not be talked into writing a rule nobody meant. Every field is length-bounded and
//! charset-checked before it reaches the store, unknown keys are rejected, and the frame
//! itself is capped so a client cannot make the daemon buffer without limit.
//!
//! The `actor` recorded on a rule is **never** taken from the request. It is derived from the
//! peer credentials of the connection (`SO_PEERCRED`), which a client cannot forge; the
//! request may only carry a `client` label saying which entry point it was.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::policy::INSTALL_HOOKS;

/// The protocol version this binary speaks. A mismatch is refused rather than guessed at.
pub const PROTOCOL_VERSION: u32 = 1;

/// The largest request frame the daemon will read, in bytes.
///
/// A `seed` of a large monorepo is the only request that is not tiny, and
/// [`MAX_SEED_ENTRIES`] bounds that independently. Compile-time on purpose (DESIGN.md
/// "Hard limits").
pub const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;

/// The largest response frame a client will read, in bytes.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// How many packages one `seed` request may carry.
pub const MAX_SEED_ENTRIES: usize = 4096;

/// npm's own limit on a package name.
pub const MAX_NAME_BYTES: usize = 214;
/// Longest version string accepted.
pub const MAX_VERSION_BYTES: usize = 256;
/// Longest `reason` accepted on a rule.
pub const MAX_REASON_BYTES: usize = 1024;
/// Longest `dist.integrity` (SRI) value accepted.
pub const MAX_INTEGRITY_BYTES: usize = 512;
/// Longest filesystem path accepted in a seed request.
pub const MAX_PATH_BYTES: usize = 4096;
/// Longest install-hook command accepted in a seed request.
pub const MAX_COMMAND_BYTES: usize = 8 * 1024;
/// Longest label a client may attach to itself.
pub const MAX_LABEL_BYTES: usize = 32;

/// How long one connection may live, end to end.
///
/// `inspect` streams a published tarball, which is the slow case; everything else is a
/// database read.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(300);

/// How long a client waits for the daemon to answer.
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(300);

/// How long a connection has to send its one request frame.
///
/// [`CONNECTION_TIMEOUT`] covers the *work*, which for `inspect` and `seed` is legitimately
/// slow. Reading a single line of JSON from a peer that has already connected is not: it is
/// one write on a local socket. Without a deadline of its own, eight peers that connect and
/// say nothing held every slot for five minutes each, renewably — and since npmfilter
/// withholds by default, a wedged control socket is a machine where nothing can be approved
/// and therefore nothing can be installed.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the daemon will spend telling a connection it is over the ceiling.
///
/// The refusal is a couple of hundred bytes; a peer that will not take them within this is not
/// waiting for an answer.
pub const REFUSAL_TIMEOUT: Duration = Duration::from_secs(1);

/// How many control connections are served at once.
///
/// Beyond this, a connection is **refused**, not queued: SECURITY.md's hard limits all fail
/// closed, and a limit that silently queues is one an attacker can hold shut. With
/// [`REQUEST_TIMEOUT`] bounding how long a slot can be held without a request, a client that
/// is refused can retry into a slot that frees within seconds.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 8;

/// What a request failed validation on.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("an approval may pin at most {limit} files")]
    TooManyPins { limit: usize },
    #[error(
        "{field} must be a package-relative path: no leading `/`, no `.` or `..` segment, no \
         backslash and no NUL"
    )]
    BadPinPath { field: &'static str },
    #[error("{field} must be 64 lowercase hex characters")]
    BadSha256 { field: &'static str },
    #[error("{field} is longer than the {limit}-byte limit")]
    TooLong { field: &'static str, limit: usize },
    #[error(
        "{field} is not a usable npm package name: it must not start with `.` or `_`, and may \
         only contain letters, digits and `-._~`, with at most one `@scope/` prefix"
    )]
    BadPackageName { field: &'static str },
    #[error("{field} is not a valid semver version, which every published npm version is")]
    BadVersion { field: &'static str },
    #[error("{field} contains a control character")]
    ControlCharacter { field: &'static str },
    #[error(
        "{field} is not a subresource-integrity value: expected `<algorithm>-<base64>`, e.g. \
         `sha512-…`"
    )]
    BadIntegrity { field: &'static str },
    #[error("{field} is not one of the install hooks npm runs for a registry tarball")]
    BadHook { field: &'static str },
    #[error(
        "a seed request may carry at most {MAX_SEED_ENTRIES} packages, this one carries {count}"
    )]
    TooManySeedEntries { count: usize },
    #[error("verdict must be \"allow\" or \"deny\"")]
    BadVerdict,
    #[error(
        "this npmfilter speaks control protocol {PROTOCOL_VERSION}, the request declared {found}"
    )]
    ProtocolVersion { found: u32 },
}

/// What a client is asking the daemon to do.
///
/// Externally tagged, so an unknown operation is a parse failure rather than a silently
/// half-understood request, and every variant's payload denies unknown fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    /// Daemon health, the policy in force and the rule counts.
    Status(StatusArgs),
    /// What was recently withheld and why.
    RecentBlocks(RecentBlocksArgs),
    /// Inspect one published version before approving it.
    Inspect(InspectArgs),
    /// Approve one version, pinned to what upstream serves right now.
    Allow(AllowArgs),
    /// Block one version outright.
    Deny(DenyArgs),
    /// List the recorded rules.
    Rules(RulesArgs),
    /// The integrity history of a package.
    Ledger(LedgerArgs),
    /// Pre-approve the install-script packages of an already-installed tree.
    Seed(SeedArgs),
}

/// `status` takes no arguments; the empty object keeps every frame the same shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusArgs {}

/// `recent_blocks` arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecentBlocksArgs {
    /// Only blocks for this package.
    pub package: Option<String>,
    /// How many to return.
    pub limit: Option<u32>,
}

/// `inspect` arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectArgs {
    /// Package to inspect.
    pub package: String,
    /// Version or dist-tag. Defaults to `dist-tags.latest`.
    #[serde(default)]
    pub version: Option<String>,
}

/// `allow` arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowArgs {
    /// Package to approve.
    pub package: String,
    /// Exact version to approve.
    pub version: String,
    /// Why.
    #[serde(default)]
    pub reason: Option<String>,
    /// Files this approval is pinned to, package-relative.
    ///
    /// The daemon fetches the tarball and hashes each one itself; a caller may state the
    /// digest it expects, and a mismatch fails the whole approval rather than being recorded.
    #[serde(default)]
    pub pins: Vec<PinRequest>,
}

/// One file an approval names, with an optional expected digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinRequest {
    /// Package-relative path, e.g. `install.js`.
    pub path: String,
    /// The sha256 the caller believes this file has. Checked against the daemon's own
    /// computation; never stored in place of it.
    #[serde(default)]
    pub sha256: Option<String>,
}

/// Most files a single approval may pin. Generous for review, bounded against a caller that
/// would otherwise name every path in a large archive.
pub const MAX_PINS: usize = 64;

/// `deny` arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyArgs {
    /// Package to block.
    pub package: String,
    /// Exact version to block.
    pub version: String,
    /// Why.
    #[serde(default)]
    pub reason: Option<String>,
}

/// `rules` arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RulesArgs {
    /// Only rules for this package.
    pub package: Option<String>,
    /// Only rules with this verdict.
    pub verdict: Option<String>,
}

/// `ledger` arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerArgs {
    /// Package whose integrity history to read.
    pub package: String,
}

/// `seed` arguments.
///
/// The client walks the tree — the daemon runs as its own user with `ProtectHome=yes` and
/// cannot read the operator's `node_modules` — and sends what it found. The daemon then
/// verifies every entry against upstream before it will write a rule for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedArgs {
    /// The tree that was walked, recorded in each rule's reason.
    pub root: String,
    /// Verify and report, write nothing.
    pub dry_run: bool,
    /// Skip the upstream verification. Reduced assurance, recorded as such on every rule.
    pub offline: bool,
    /// The install-hook packages that were found.
    pub entries: Vec<SeedEntry>,
}

/// One installed package a `seed` request offers for approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedEntry {
    /// Package name, as the directory it is installed in says.
    pub name: String,
    /// Installed version.
    pub version: String,
    /// The `dist.integrity` the client read out of a lockfile on disk.
    pub integrity: String,
    /// Which file that came from.
    pub integrity_source: String,
    /// Where in the tree it is installed.
    pub key: String,
    /// The reproducible hash of the unpacked directory.
    pub tree_sha256: String,
    /// The install hooks the installed `package.json` declares.
    pub hooks: BTreeMap<String, String>,
}

/// The envelope every request travels in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    /// Must equal [`PROTOCOL_VERSION`].
    pub version: u32,
    /// Which entry point sent this — `mcp`, `cli` or `seed`.
    ///
    /// A label for the audit trail only. The identity a rule is recorded against comes from
    /// the connection's peer credentials, which a client cannot choose.
    pub client: String,
    /// What is being asked.
    pub request: Request,
}

impl RequestEnvelope {
    /// Wrap a request from `client`.
    pub fn new(client: impl Into<String>, request: Request) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            client: client.into(),
            request,
        }
    }

    /// Reject anything malformed, over-long or out of charset before it reaches the store.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ValidationError::ProtocolVersion {
                found: self.version,
            });
        }
        text("client", &self.client, MAX_LABEL_BYTES)?;
        self.request.validate()
    }
}

impl Request {
    /// Reject anything malformed, over-long or out of charset.
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Request::Status(StatusArgs {}) => Ok(()),
            Request::RecentBlocks(args) => match &args.package {
                Some(package) => package_name("package", package),
                None => Ok(()),
            },
            Request::Inspect(args) => {
                package_name("package", &args.package)?;
                match &args.version {
                    // `inspect` accepts a dist-tag as well as a version, so this is the one
                    // place a non-semver spec is legitimate. It is still charset-bounded.
                    Some(version) => version_or_tag("version", version),
                    None => Ok(()),
                }
            }
            Request::Allow(args) => {
                package_name("package", &args.package)?;
                exact_version("version", &args.version)?;
                optional_text("reason", args.reason.as_deref(), MAX_REASON_BYTES)?;
                if args.pins.len() > MAX_PINS {
                    return Err(ValidationError::TooManyPins { limit: MAX_PINS });
                }
                for pin in &args.pins {
                    pin_path("pins.path", &pin.path)?;
                    if let Some(sha256) = &pin.sha256 {
                        sha256_hex("pins.sha256", sha256)?;
                    }
                }
                Ok(())
            }
            Request::Deny(args) => {
                package_name("package", &args.package)?;
                exact_version("version", &args.version)?;
                optional_text("reason", args.reason.as_deref(), MAX_REASON_BYTES)
            }
            Request::Rules(args) => {
                if let Some(package) = &args.package {
                    package_name("package", package)?;
                }
                match args.verdict.as_deref() {
                    None | Some("allow") | Some("deny") => Ok(()),
                    Some(_) => Err(ValidationError::BadVerdict),
                }
            }
            Request::Ledger(args) => package_name("package", &args.package),
            Request::Seed(args) => args.validate(),
        }
    }

    /// The operation name, for logs and audit rows.
    pub fn name(&self) -> &'static str {
        match self {
            Request::Status(_) => "status",
            Request::RecentBlocks(_) => "recent_blocks",
            Request::Inspect(_) => "inspect",
            Request::Allow(_) => "allow",
            Request::Deny(_) => "deny",
            Request::Rules(_) => "rules",
            Request::Ledger(_) => "ledger",
            Request::Seed(_) => "seed",
        }
    }

    /// Whether serving this request writes to the state database.
    pub fn is_mutation(&self) -> bool {
        matches!(
            self,
            Request::Allow(_) | Request::Deny(_) | Request::Seed(_)
        )
    }
}

impl SeedArgs {
    fn validate(&self) -> Result<(), ValidationError> {
        text("root", &self.root, MAX_PATH_BYTES)?;
        if self.entries.len() > MAX_SEED_ENTRIES {
            return Err(ValidationError::TooManySeedEntries {
                count: self.entries.len(),
            });
        }
        for entry in &self.entries {
            entry.validate()?;
        }
        Ok(())
    }
}

impl SeedEntry {
    fn validate(&self) -> Result<(), ValidationError> {
        package_name("name", &self.name)?;
        exact_version("version", &self.version)?;
        integrity("integrity", &self.integrity)?;
        text("integrity_source", &self.integrity_source, MAX_REASON_BYTES)?;
        text("key", &self.key, MAX_PATH_BYTES)?;
        text("tree_sha256", &self.tree_sha256, MAX_INTEGRITY_BYTES)?;
        for (hook, command) in &self.hooks {
            if !INSTALL_HOOKS.contains(&hook.as_str()) {
                return Err(ValidationError::BadHook { field: "hooks" });
            }
            text("hooks", command, MAX_COMMAND_BYTES)?;
        }
        Ok(())
    }
}

/// What the daemon answers with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Answer {
    Status(Box<crate::mcp::StatusReport>),
    RecentBlocks(Box<crate::mcp::RecentBlocksReport>),
    Inspect(Box<crate::mcp::inspect::InspectReport>),
    Rule(Box<crate::mcp::RuleWritten>),
    Rules(Box<crate::mcp::RulesReport>),
    Ledger(Box<crate::mcp::LedgerReport>),
    Seed(Box<SeedResult>),
}

/// What one `seed` request did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedResult {
    /// Whether the daemon was asked to write anything.
    pub dry_run: bool,
    /// Whether upstream verification was skipped.
    pub offline: bool,
    /// How many entries were verified against upstream.
    pub verified: usize,
    /// How many rules were written.
    pub written: usize,
    /// How many entries the daemon refused to trust.
    pub refused: usize,
    /// One line per entry.
    pub outcomes: Vec<SeedOutcome>,
    /// What the run means.
    pub note: String,
}

/// What became of one seed entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedOutcome {
    /// The package.
    pub name: String,
    /// The version.
    pub version: String,
    /// `written`, `verified`, `refused` or `unverified`.
    pub status: String,
    /// Why.
    pub detail: String,
}

/// A failure, rendered for the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    /// A stable machine-readable class: `invalid_request`, `not_found`, `upstream`, `internal`.
    pub code: String,
    /// The whole error chain, flattened.
    pub message: String,
}

/// The envelope every response travels in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEnvelope {
    /// Always [`PROTOCOL_VERSION`].
    pub version: u32,
    /// The answer, when the request succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<Answer>,
    /// The failure, when it did not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Failure>,
}

impl ResponseEnvelope {
    /// A successful answer.
    pub fn ok(answer: Answer) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            answer: Some(answer),
            error: None,
        }
    }

    /// A failure.
    pub fn failed(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            answer: None,
            error: Some(Failure {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

// -- field validators ------------------------------------------------------------------------

/// A bounded, control-character-free string.
fn text(field: &'static str, value: &str, limit: usize) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::Empty { field });
    }
    if value.len() > limit {
        return Err(ValidationError::TooLong { field, limit });
    }
    if value.chars().any(char::is_control) {
        return Err(ValidationError::ControlCharacter { field });
    }
    Ok(())
}

/// [`text`], but the field may be absent.
fn optional_text(
    field: &'static str,
    value: Option<&str>,
    limit: usize,
) -> Result<(), ValidationError> {
    match value {
        Some(value) => text(field, value, limit),
        None => Ok(()),
    }
}

/// An npm package name, scoped or not.
///
/// The charset is what keeps a name from becoming a path or a URL of its own once it is
/// appended to the upstream base — `..`, `/`, `?`, `#` and `%` are all out. The leading-dot
/// and leading-underscore rules are npm's own and also exclude `.` and `..` outright.
/// A package-relative file path inside a tarball.
///
/// Rejected outright: absolute paths, `.`/`..` segments, backslashes and NUL. A pin is only
/// ever compared against a manifest the daemon built itself, so a traversing path could not
/// escape anything — but a path that cannot name a real entry is a mistake worth reporting at
/// the point it is made rather than silently storing a pin that can never match.
pub fn pin_path(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::Empty { field });
    }
    if value.len() > MAX_NAME_BYTES {
        return Err(ValidationError::TooLong {
            field,
            limit: MAX_NAME_BYTES,
        });
    }
    let bad = value.starts_with('/')
        || value.contains('\\')
        || value.contains('\0')
        || value
            .split('/')
            .any(|segment| segment == "." || segment == ".." || segment.is_empty());
    if bad {
        return Err(ValidationError::BadPinPath { field });
    }
    Ok(())
}

/// Lowercase-hex sha256, exactly 64 characters.
pub fn sha256_hex(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ValidationError::BadSha256 { field });
    }
    Ok(())
}

pub fn package_name(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::Empty { field });
    }
    if value.len() > MAX_NAME_BYTES {
        return Err(ValidationError::TooLong {
            field,
            limit: MAX_NAME_BYTES,
        });
    }
    let bare = match value.strip_prefix('@') {
        Some(scoped) => {
            let Some((scope, name)) = scoped.split_once('/') else {
                return Err(ValidationError::BadPackageName { field });
            };
            if !is_name_part(scope) || !is_name_part(name) {
                return Err(ValidationError::BadPackageName { field });
            }
            return Ok(());
        }
        None => value,
    };
    if is_name_part(bare) {
        Ok(())
    } else {
        Err(ValidationError::BadPackageName { field })
    }
}

/// One `@scope` or `name` component.
fn is_name_part(part: &str) -> bool {
    !part.is_empty()
        && !part.starts_with(['.', '_', '-'])
        && part.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_' | '~')
        })
}

/// An exact published version. Every version npm serves is valid semver.
pub fn exact_version(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::Empty { field });
    }
    if value.len() > MAX_VERSION_BYTES {
        return Err(ValidationError::TooLong {
            field,
            limit: MAX_VERSION_BYTES,
        });
    }
    if semver::Version::parse(value).is_err() {
        return Err(ValidationError::BadVersion { field });
    }
    Ok(())
}

/// A version or a dist-tag — what `inspect` accepts.
fn version_or_tag(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::Empty { field });
    }
    if value.len() > MAX_VERSION_BYTES {
        return Err(ValidationError::TooLong {
            field,
            limit: MAX_VERSION_BYTES,
        });
    }
    let usable = value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '+' | '_')
    });
    if usable {
        Ok(())
    } else {
        Err(ValidationError::BadVersion { field })
    }
}

/// A subresource-integrity value, e.g. `sha512-<base64>`.
fn integrity(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::Empty { field });
    }
    if value.len() > MAX_INTEGRITY_BYTES {
        return Err(ValidationError::TooLong {
            field,
            limit: MAX_INTEGRITY_BYTES,
        });
    }
    let Some((algorithm, digest)) = value.split_once('-') else {
        return Err(ValidationError::BadIntegrity { field });
    };
    let algorithm_ok = !algorithm.is_empty()
        && algorithm
            .chars()
            .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit());
    let digest_ok = !digest.is_empty()
        && digest.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '/' | '=')
        });
    if algorithm_ok && digest_ok {
        Ok(())
    } else {
        Err(ValidationError::BadIntegrity { field })
    }
}
