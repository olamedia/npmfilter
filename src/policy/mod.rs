//! The policy engine — DESIGN.md "Policy engine".
//!
//! [`evaluate`] is a pure function over `serde_json` values:
//! `(packument, rules, ledger, config, now) -> FilteredPackument + Vec<BlockRecord>`.
//! It performs no I/O of its own; the rules store and the integrity ledger are traits, so
//! step 4 can back them with SQLite without touching a line of this module.
//!
//! Per version, the gates run in exactly this order (DESIGN.md steps 0-6):
//!
//! 0. integrity-ledger check — a changed identity blocks, and nothing below can rescue it
//! 1. explicit deny rule
//! 2. allow rule pinned to `dist.integrity` **and** to the sha256 of the approved commands
//!    (either mismatch blocks)
//! 3. scope in `bypass_scopes`
//! 4. no usable content hash at all — neither `dist.integrity` nor `dist.shasum`
//! 5. release age below `min_age_days`
//! 6. `preinstall` / `install` / `postinstall` present, or upstream's `hasInstallScript` flag
//! 7. otherwise allowed
//!
//! Gate 4 is what keeps the ledger from being a no-op. The recorded identity is
//! [`version_identity`]: `dist.integrity` when the version publishes one, and the `sha1`
//! `dist.shasum` under a `shasum-sha1:` prefix when it does not. A version publishing
//! neither has nothing to pin at all — the ledger would record `NULL`, and `NULL == NULL`
//! would report *unchanged* for ever while the bytes behind the version were replaced at
//! will — so it is withheld rather than served under a comparison that cannot fail.
//!
//! The document is then rebuilt: blocked versions are dropped from `versions` **and** `time`,
//! and every `dist-tags` entry is checked so no tag is left pointing at a withheld version.

mod memory;
#[cfg(test)]
mod tests;

use std::cmp::Ordering;
use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use memory::{InMemoryLedger, InMemoryRules, LedgerEntry};

/// The three lifecycle scripts npm runs for a registry tarball install.
///
/// `prepare` is deliberately absent: it does not run for registry installs (DESIGN.md
/// "Verified facts"), only for git dependencies, which are out of scope.
pub const INSTALL_HOOKS: [&str; 3] = ["preinstall", "install", "postinstall"];

/// Seconds in a day, for the age gate.
const SECONDS_PER_DAY: i64 = 86_400;

/// The slice of [`crate::config::Config`] the engine consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyConfig {
    /// Versions younger than this are withheld. `0` disables the age gate entirely.
    pub min_age_days: u32,
    /// Scopes exempt from the automatic gates, with or without the leading `@`.
    pub bypass_scopes: Vec<String>,
    /// Whether a `dist-tags` entry whose target was withheld may be moved to an older
    /// surviving version.
    ///
    /// `false` — the default, and the only safe value — leaves every tag exactly as upstream
    /// published it. A client asking for `latest` then fails to resolve, which is the honest
    /// answer: the version it wanted is withheld pending review. Moving the tag instead
    /// **silently installs an older release**, and older releases are the ones carrying known
    /// vulnerabilities — a security gate that quietly downgrades you is doing harm. Observed
    /// live: `sqlite3` had 102 of 104 versions withheld, `latest` was moved from 6.0.1 to
    /// 2.1.3 (2014), and the install died in `node-gyp` with nothing naming npmfilter.
    pub allow_dist_tag_downgrade: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            min_age_days: crate::config::DEFAULT_MIN_AGE_DAYS,
            bypass_scopes: Vec::new(),
            allow_dist_tag_downgrade: false,
        }
    }
}

/// Why a version was withheld.
///
/// The wire form is snake_case; the Rust variants carry the DESIGN.md names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    /// `dist.integrity` no longer matches what the ledger recorded, or what an allow rule
    /// pinned. Always a critical audit event; no rule can override it.
    IntegrityChanged,
    /// An explicit deny rule.
    DenyRule,
    /// Published less than `min_age_days` ago — or with no usable publish time at all.
    TooNew,
    /// Carries `preinstall`, `install` or `postinstall` — or upstream flags `hasInstallScript`
    /// without publishing the commands.
    InstallScript,
    /// An allow rule's approved install-hook commands are not the commands this version now
    /// declares. DESIGN.md "Rules store": "a changed command never inherits approval".
    ScriptsChanged,
    /// The version publishes neither `dist.integrity` nor `dist.shasum`, so there is nothing
    /// for the integrity ledger to pin and nothing an approval could be bound to.
    NoIntegrity,
}

impl BlockReason {
    /// Stable string form, used for JSON, logs and the audit log.
    pub fn as_str(self) -> &'static str {
        match self {
            BlockReason::IntegrityChanged => "integrity_changed",
            BlockReason::DenyRule => "deny_rule",
            BlockReason::TooNew => "too_new",
            BlockReason::InstallScript => "install_script",
            BlockReason::ScriptsChanged => "scripts_changed",
            BlockReason::NoIntegrity => "no_integrity",
        }
    }

    /// What a registry client is told when this gate fires.
    ///
    /// Deliberately value-free: naming the gate and the tool that shows the evidence, without
    /// reproducing a hash, a timestamp or a command line that upstream chose.
    pub fn public_detail(self) -> &'static str {
        match self {
            BlockReason::IntegrityChanged => {
                "this version no longer serves the dist.integrity npmfilter recorded when it \
                 first observed it. Published npm versions are immutable, so this is version \
                 replacement; run `npmfilter ledger <package>` for the recorded value. No \
                 approval can override it"
            }
            BlockReason::DenyRule => "an explicit deny rule withholds this version",
            BlockReason::TooNew => {
                "this version is younger than the configured quarantine window, or publishes \
                 no usable publish time; run `npmfilter inspect <package> <version>`"
            }
            BlockReason::InstallScript => {
                "this version runs an install hook (preinstall/install/postinstall). Run \
                 `npmfilter inspect <package> <version>` to read the commands, then \
                 `npmfilter allow` if they are legitimate"
            }
            BlockReason::ScriptsChanged => {
                "the install-hook commands this version declares are not the ones its approval \
                 covered. Run `npmfilter inspect <package> <version>` and re-approve only once \
                 you know why the command changed"
            }
            BlockReason::NoIntegrity => {
                "this version publishes no content hash — neither dist.integrity nor \
                 dist.shasum — so npmfilter cannot pin it, the integrity ledger cannot tell \
                 whether its bytes were replaced, and npm has nothing to verify a download \
                 against. Run `npmfilter inspect <package> <version>`"
            }
        }
    }

    /// Whether this block is a critical audit event (DESIGN.md steps 0 and 2).
    ///
    /// A changed script command under an unchanged `dist.integrity` is the same class of event
    /// as a changed hash: the approved artefact and the served artefact no longer agree.
    pub fn is_critical(self) -> bool {
        matches!(
            self,
            BlockReason::IntegrityChanged | BlockReason::ScriptsChanged
        )
    }
}

impl std::fmt::Display for BlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One withheld version.
///
/// Two details, deliberately.
///
/// * [`BlockRecord::detail`] is **operator-facing**: the whole evidence, including values that
///   came from upstream. It goes to the audit log and to the control socket, both of which are
///   reachable only by someone already trusted to approve packages.
/// * [`BlockRecord::public_detail`] is **client-facing**: it states that a gate fired without
///   reproducing anything upstream controls. It is what the `_npmfilter` summary and the
///   version 404 carry. A daemon that echoed a hostile registry's strings back into the body
///   npm parses would be lending it a channel it did not have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRecord {
    /// The version that was withheld.
    pub version: String,
    /// Which gate stopped it.
    pub reason: BlockReason,
    /// Operator-facing specifics — hashes, publish time, script commands. Never sent to a
    /// registry client.
    pub detail: String,
    /// Client-facing specifics, carrying no upstream-controlled text.
    pub public_detail: String,
}

impl BlockRecord {
    /// A record whose client-facing detail is the generic wording for its gate.
    pub fn new(
        version: impl Into<String>,
        reason: BlockReason,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            version: version.into(),
            reason,
            detail: detail.into(),
            public_detail: reason.public_detail().to_owned(),
        }
    }

    /// A record with an explicit client-facing detail.
    pub fn with_public_detail(mut self, public_detail: impl Into<String>) -> Self {
        self.public_detail = public_detail.into();
        self
    }
}

/// What [`evaluate`] returns: the rebuilt packument plus the withheld versions.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyOutcome {
    /// The packument with blocked versions removed and `dist-tags` repointed.
    pub packument: Value,
    /// Every version that was withheld, with its reason.
    pub blocked: Vec<BlockRecord>,
}

impl PolicyOutcome {
    /// The versions that survived, in the packument's own key order.
    pub fn surviving_versions(&self) -> Vec<String> {
        self.packument
            .get("versions")
            .and_then(Value::as_object)
            .map(|versions| versions.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// A malformed packument. The request path turns this into an error response — never a panic.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    #[error("packument is not a JSON object")]
    NotAnObject,
    #[error("packument has no string `name` field")]
    MissingName,
    #[error("packument has no `versions` object")]
    MissingVersions,
}

/// An allow or deny verdict recorded by an operator or by the MCP tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny,
}

/// A row of the `rules` table (DESIGN.md "Rules store").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub version: String,
    pub verdict: Verdict,
    /// The `dist.integrity` (sha512) this rule is pinned to. An allow rule only applies while
    /// the version still carries this exact hash.
    pub integrity: Option<String>,
    /// sha256 over the sorted install-hook map the approval was granted for.
    pub scripts_sha256: Option<String>,
    /// Why the rule exists.
    pub reason: Option<String>,
    /// Who recorded it.
    pub actor: Option<String>,
}

impl Rule {
    /// An allow rule pinned to `integrity`.
    pub fn allow(
        name: impl Into<String>,
        version: impl Into<String>,
        integrity: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            verdict: Verdict::Allow,
            integrity: Some(integrity.into()),
            scripts_sha256: None,
            reason: None,
            actor: None,
        }
    }

    /// A deny rule.
    pub fn deny(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            verdict: Verdict::Deny,
            integrity: None,
            scripts_sha256: None,
            reason: None,
            actor: None,
        }
    }

    /// Attach a reason.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
}

/// Lookup of allow/deny rules. Step 4 backs this with SQLite.
pub trait RuleStore: Send + Sync {
    /// The rule for this exact `(name, version)`, if any.
    fn lookup(&self, name: &str, version: &str) -> Option<Rule>;
}

/// The result of comparing an observed integrity against the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerCheck {
    /// First time this `(name, version)` has ever been observed; it has now been recorded.
    Unseen,
    /// Observed before with the same integrity.
    Match,
    /// Observed before with a *different* integrity — version replacement.
    Changed {
        /// What was recorded the first time round.
        recorded: Option<String>,
    },
}

/// The trust-on-first-use integrity ledger — the `seen` table of DESIGN.md "Rules store".
///
/// `observe` both compares and records: every version the daemon sees is written, including
/// blocked ones, so the quarantine window doubles as an observation window. Implementations
/// take `&self` and handle their own interior mutability, so the engine can hold a shared
/// reference from an async request handler.
pub trait IntegrityLedger: Send + Sync {
    /// Compare `integrity` against the recorded hash for `(name, version)`, recording the
    /// observation. A version with no `dist.integrity` is recorded as `None`, and a later
    /// transition in either direction counts as [`LedgerCheck::Changed`].
    fn observe(
        &self,
        name: &str,
        version: &str,
        integrity: Option<&str>,
        now: DateTime<Utc>,
    ) -> LedgerCheck;
}

/// The internal per-version outcome.
enum Decision {
    Allow,
    Block { reason: BlockReason, detail: String },
}

/// Evaluate a full packument and rebuild it with the blocked versions withheld.
///
/// `now` is passed in rather than read from the clock, so the whole engine is deterministic
/// and testable without network or wall-clock dependence.
pub fn evaluate(
    packument: &Value,
    rules: &dyn RuleStore,
    ledger: &dyn IntegrityLedger,
    config: &PolicyConfig,
    now: DateTime<Utc>,
) -> Result<PolicyOutcome, PolicyError> {
    let root = packument.as_object().ok_or(PolicyError::NotAnObject)?;
    let name = root
        .get("name")
        .and_then(Value::as_str)
        .ok_or(PolicyError::MissingName)?;
    let versions = root
        .get("versions")
        .and_then(Value::as_object)
        .ok_or(PolicyError::MissingVersions)?;
    let time = root.get("time").and_then(Value::as_object);

    let mut blocked = Vec::new();
    let mut surviving = BTreeSet::new();

    for (version, meta) in versions {
        let published = time
            .and_then(|time| time.get(version.as_str()))
            .and_then(Value::as_str);
        match evaluate_version(name, version, meta, published, rules, ledger, config, now) {
            Decision::Allow => {
                surviving.insert(version.clone());
            }
            Decision::Block { reason, detail } => {
                blocked.push(BlockRecord::new(version.clone(), reason, detail));
            }
        }
    }

    let mut out = root.clone();

    let mut kept_versions = Map::new();
    for (version, meta) in versions {
        if surviving.contains(version) {
            kept_versions.insert(version.clone(), meta.clone());
        }
    }
    out.insert("versions".to_owned(), Value::Object(kept_versions));

    if let Some(time) = time {
        let mut kept_time = Map::new();
        for (key, value) in time {
            // `created` / `modified` and entries for versions we never saw are left alone;
            // only the versions we withheld are dropped.
            if versions.contains_key(key) && !surviving.contains(key) {
                continue;
            }
            kept_time.insert(key.clone(), value.clone());
        }
        out.insert("time".to_owned(), Value::Object(kept_time));
    }

    if let Some(tags) = root.get("dist-tags").and_then(Value::as_object) {
        // Tags are left exactly as upstream published them unless the operator explicitly
        // opted into downgrading. `latest` must keep meaning latest: a tag pointing at a
        // withheld version makes the client fail to resolve, which is the truth, instead of
        // quietly handing it an older release it never asked for.
        let rebuilt = if config.allow_dist_tag_downgrade {
            Value::Object(repoint_dist_tags(tags, &surviving))
        } else {
            Value::Object(tags.clone())
        };
        out.insert("dist-tags".to_owned(), rebuilt);
    }

    Ok(PolicyOutcome {
        packument: Value::Object(out),
        blocked,
    })
}

/// The gates of DESIGN.md "Policy engine", in order, for a single version.
#[allow(clippy::too_many_arguments)]
fn evaluate_version(
    name: &str,
    version: &str,
    meta: &Value,
    published: Option<&str>,
    rules: &dyn RuleStore,
    ledger: &dyn IntegrityLedger,
    config: &PolicyConfig,
    now: DateTime<Utc>,
) -> Decision {
    let integrity = version_integrity(meta);
    let identity = version_identity(meta);

    // 0. Integrity ledger. Nothing below can override a changed hash.
    if let LedgerCheck::Changed { recorded } =
        ledger.observe(name, version, identity.as_deref(), now)
    {
        return Decision::Block {
            reason: BlockReason::IntegrityChanged,
            detail: format!(
                "integrity ledger: {name}@{version} was first recorded as {} but upstream now \
                 serves a different value (fingerprint {})",
                show_integrity(recorded.as_deref()),
                fingerprint(identity.as_deref())
            ),
        };
    }

    if let Some(rule) = rules.lookup(name, version) {
        match rule.verdict {
            // 1. Explicit deny.
            Verdict::Deny => {
                let detail = match rule.reason {
                    Some(reason) => format!("denied by rule: {reason}"),
                    None => "denied by rule".to_owned(),
                };
                return Decision::Block {
                    reason: BlockReason::DenyRule,
                    detail,
                };
            }
            // 2. Allow, only while the pinned hash **and** the approved commands still match.
            Verdict::Allow => {
                if rule.integrity.as_deref() != integrity {
                    return Decision::Block {
                        reason: BlockReason::IntegrityChanged,
                        detail: format!(
                            "allow rule for {name}@{version} is pinned to {} but this version \
                             now carries a different value (fingerprint {})",
                            show_integrity(rule.integrity.as_deref()),
                            fingerprint(integrity)
                        ),
                    };
                }
                // DESIGN.md "Rules store": the approval is bound to the exact commands, so a
                // changed command never inherits it. Packument metadata is served independently
                // of the tarball bytes, so the hash matching is not on its own enough.
                if let Some(approved) = rule.scripts_sha256.as_deref() {
                    let current = scripts_sha256(meta);
                    if approved != current {
                        return Decision::Block {
                            reason: BlockReason::ScriptsChanged,
                            detail: format!(
                                "allow rule for {name}@{version} approved install hooks with \
                                 sha256 {approved} but this version now declares {current} ({})",
                                describe_hooks(meta)
                            ),
                        };
                    }
                }
                return Decision::Allow;
            }
        }
    }

    // 3. First-party scopes bypass the automatic gates.
    if let Some(scope) = package_scope(name)
        && config
            .bypass_scopes
            .iter()
            .any(|allowed| allowed.trim_start_matches('@') == scope)
    {
        return Decision::Allow;
    }

    // 4. No content hash at all. Fail closed: a version the ledger cannot pin is a version
    // whose bytes can be swapped for ever without the daemon being able to notice, and npm
    // has nothing to verify its download against either. An operator who has inspected it
    // can still approve it deliberately — gate 2 runs first.
    if identity.is_none() {
        return Decision::Block {
            reason: BlockReason::NoIntegrity,
            detail: format!(
                "{name}@{version} publishes no dist.integrity and no dist.shasum, so the \
                 integrity ledger has nothing to pin: every later observation would compare \
                 absent against absent and report the version unchanged whatever upstream \
                 served (tarball fingerprint {})",
                fingerprint(version_tarball(meta))
            ),
        };
    }

    // 5. Release age. `min_age_days == 0` disables the gate outright.
    if config.min_age_days > 0 {
        let min_age_secs = i64::from(config.min_age_days) * SECONDS_PER_DAY;
        match published.map(parse_timestamp) {
            Some(Some(published_at)) => {
                let age_secs = now.signed_duration_since(published_at).num_seconds();
                if age_secs < min_age_secs {
                    return Decision::Block {
                        reason: BlockReason::TooNew,
                        detail: format!(
                            "published {} ({}), under the {}-day minimum",
                            published_at.to_rfc3339(),
                            describe_age(age_secs),
                            config.min_age_days
                        ),
                    };
                }
            }
            // Fail closed: without a usable publish time the age gate cannot clear a version.
            Some(None) => {
                return Decision::Block {
                    reason: BlockReason::TooNew,
                    detail: format!(
                        "the packument's publish time for {version} is not a valid RFC 3339 \
                         timestamp (fingerprint {}), so the {}-day age gate cannot clear it",
                        fingerprint(published),
                        config.min_age_days
                    ),
                };
            }
            None => {
                return Decision::Block {
                    reason: BlockReason::TooNew,
                    detail: format!(
                        "packument has no `time` entry for {version}, so the {}-day age gate cannot clear this version",
                        config.min_age_days
                    ),
                };
            }
        }
    }

    // 6. Install hooks.
    let hooks = install_hooks(meta);
    if !hooks.is_empty() {
        let commands = hooks
            .iter()
            .map(|(hook, command)| format!("{hook}: {command}"))
            .collect::<Vec<_>>()
            .join("; ");
        return Decision::Block {
            reason: BlockReason::InstallScript,
            detail: format!("install hooks present — {commands}"),
        };
    }
    // The same gate honours upstream's own `hasInstallScript` flag. It is publisher-supplied
    // (libnpmpublish writes it) and some mirrors serve it without a `scripts` map at all, and
    // it is exactly what this daemon re-serializes to npm — a version cannot be admitted on
    // the grounds that it has no install script and then be handed to npm labelled as having
    // one.
    if flags_install_script(meta) {
        return Decision::Block {
            reason: BlockReason::InstallScript,
            detail: "upstream flags install scripts (hasInstallScript: true) but published no \
                     `scripts` map, so the commands cannot be reviewed from the packument"
                .to_owned(),
        };
    }

    // 7. Allowed.
    Decision::Allow
}

/// `dist.tarball` for a version, if present.
///
/// npmfilter never rewrites it (DESIGN.md "Tarballs — pass-through"), but the request path
/// checks which host it points at, so an upstream serving package bytes from somewhere other
/// than itself is recorded rather than relayed silently.
pub fn version_tarball(meta: &Value) -> Option<&str> {
    meta.get("dist")
        .and_then(Value::as_object)
        .and_then(|dist| dist.get("tarball"))
        .and_then(Value::as_str)
}

/// `dist.integrity` for a version, if present.
///
/// This is what an **approval** pins: a rule is only ever bound to a hash the publisher
/// actually published. The *ledger* pins [`version_identity`] instead, which falls back to
/// `dist.shasum`.
pub fn version_integrity(meta: &Value) -> Option<&str> {
    meta.get("dist")
        .and_then(Value::as_object)
        .and_then(|dist| dist.get("integrity"))
        .and_then(Value::as_str)
}

/// `dist.shasum` for a version, if present and non-empty.
pub fn version_shasum(meta: &Value) -> Option<&str> {
    meta.get("dist")
        .and_then(Value::as_object)
        .and_then(|dist| dist.get("shasum"))
        .and_then(Value::as_str)
        .filter(|shasum| !shasum.is_empty())
}

/// What the integrity ledger records for a version — DESIGN.md "Integrity ledger".
///
/// `dist.integrity` (sha512) when the version publishes one. When it does not — every
/// package published before npm 5 is in this shape — the `sha1` `dist.shasum` is used
/// instead, under a `shasum-sha1:` prefix so it can never be confused with, or collide with,
/// a real `integrity` string.
///
/// `None` means the version publishes **no** content hash at all. Recording that as `NULL`
/// and comparing it against the next `NULL` is a comparison that can never fail, which is
/// exactly why gate 4 withholds such a version instead of pretending the ledger covers it.
pub fn version_identity(meta: &Value) -> Option<String> {
    if let Some(integrity) = version_integrity(meta) {
        return Some(integrity.to_owned());
    }
    version_shasum(meta).map(|shasum| format!("shasum-sha1:{shasum}"))
}

/// The install hooks a version declares, in `preinstall`, `install`, `postinstall` order.
///
/// A hook present with a non-string value is reported as its JSON text: presence is what the
/// gate cares about, so anything but `null`/absent counts.
pub fn install_hooks(meta: &Value) -> Vec<(&'static str, String)> {
    let Some(scripts) = meta.get("scripts").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut hooks = Vec::new();
    for hook in INSTALL_HOOKS {
        match scripts.get(hook) {
            None | Some(Value::Null) => {}
            Some(Value::String(command)) => hooks.push((hook, command.clone())),
            Some(other) => hooks.push((hook, other.to_string())),
        }
    }
    hooks
}

/// Whether upstream flags this version as running install scripts.
///
/// The flag is publisher-supplied and is what an abbreviated packument carries in place of the
/// `scripts` map, so it is a signal in its own right: some mirrors emit it with no `scripts`
/// key at all.
pub fn flags_install_script(meta: &Value) -> bool {
    meta.get("hasInstallScript")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// sha256 over the sorted install-hook map, lowercase hex — what an approval pins the exact
/// commands to (DESIGN.md "Rules store").
///
/// Identical by construction to [`crate::store::ScriptSet::sha256`] for the same version
/// object: both hash the canonical JSON of the sorted `hook -> command` map. `store::tests`
/// pins the two against each other so they cannot drift.
pub fn scripts_sha256(meta: &Value) -> String {
    let mut object = Map::new();
    for (hook, command) in install_hooks(meta) {
        object.insert(hook.to_owned(), Value::String(command));
    }
    // `serde_json::Map` is a `BTreeMap` here (no `preserve_order`), so the rendered keys are
    // sorted and the text is stable for a given set of hooks.
    let json = Value::Object(object).to_string();
    crate::store::hex_encode(Sha256::digest(json.as_bytes()).as_slice())
}

/// The install hooks a version declares, rendered for a message.
fn describe_hooks(meta: &Value) -> String {
    let hooks = install_hooks(meta);
    if hooks.is_empty() {
        return "this version declares no install hooks".to_owned();
    }
    format!(
        "now: {}",
        hooks
            .iter()
            .map(|(hook, command)| format!("{hook}: {command}"))
            .collect::<Vec<_>>()
            .join("; ")
    )
}

/// The scope of a package name — `@olamedia/foo` yields `olamedia`.
pub fn package_scope(name: &str) -> Option<&str> {
    let (scope, package) = name.strip_prefix('@')?.split_once('/')?;
    if scope.is_empty() || package.is_empty() {
        None
    } else {
        Some(scope)
    }
}

/// Parse an npm `time` value (RFC 3339, e.g. `2011-12-16T00:00:00.000Z`).
fn parse_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|parsed| parsed.with_timezone(&Utc))
}

/// Ensure no `dist-tags` entry points at a version that was withheld.
///
/// A tag whose target survived is left exactly as it was — repointing `legacy` or `next` at
/// the newest version would corrupt what those tags mean. A tag whose target was withheld is
/// moved to the newest surviving version; if the original target was a stable release, only
/// stable versions are considered first, so `latest` can never be dragged onto a prerelease.
/// A tag with no candidate at all (everything blocked) is dropped.
fn repoint_dist_tags(
    tags: &Map<String, Value>,
    surviving: &BTreeSet<String>,
) -> Map<String, Value> {
    let mut out = Map::new();
    for (tag, target) in tags {
        let target = target.as_str();
        match target {
            Some(target) if surviving.contains(target) => {
                out.insert(tag.clone(), Value::String(target.to_owned()));
            }
            _ => {
                let target_is_stable = target.is_none_or(is_stable);
                if let Some(replacement) = newest_surviving(surviving, target_is_stable) {
                    out.insert(tag.clone(), Value::String(replacement));
                }
            }
        }
    }
    out
}

/// The newest surviving version, preferring stable releases when asked.
fn newest_surviving(surviving: &BTreeSet<String>, prefer_stable: bool) -> Option<String> {
    if prefer_stable {
        let newest_stable = pick_newest(surviving.iter().filter(|version| is_stable(version)));
        if newest_stable.is_some() {
            return newest_stable;
        }
    }
    pick_newest(surviving.iter())
}

/// The maximum of an iterator of versions under semver ordering.
fn pick_newest<'a, I: Iterator<Item = &'a String>>(versions: I) -> Option<String> {
    versions
        .max_by(|left, right| compare_versions(left, right))
        .cloned()
}

/// Semver ordering, with unparseable versions ranked below every parseable one.
fn compare_versions(left: &str, right: &str) -> Ordering {
    match (Version::parse(left).ok(), Version::parse(right).ok()) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => left.cmp(right),
    }
}

/// Whether a version string is a parseable, non-prerelease semver.
fn is_stable(version: &str) -> bool {
    Version::parse(version).is_ok_and(|parsed| parsed.pre.is_empty())
}

/// A short, fixed-alphabet fingerprint of an upstream-supplied string.
///
/// Used wherever a message would otherwise reproduce a value that a hostile registry chose:
/// the operator still gets something to correlate two observations by, and nothing the
/// registry wrote is repeated. `None` renders as a marker, not as an empty quotation.
pub fn fingerprint(value: Option<&str>) -> String {
    match value {
        Some(value) => {
            let digest = crate::store::hex_encode(Sha256::digest(value.as_bytes()).as_slice());
            format!("sha256:{}", &digest[..16.min(digest.len())])
        }
        None => "<absent>".to_owned(),
    }
}

/// Render an optional integrity for a message.
fn show_integrity(integrity: Option<&str>) -> String {
    match integrity {
        Some(integrity) => integrity.to_owned(),
        None => "<no dist.integrity>".to_owned(),
    }
}

/// Render an age for a message.
fn describe_age(age_secs: i64) -> String {
    if age_secs < 0 {
        return "publish time is in the future".to_owned();
    }
    let days = age_secs / SECONDS_PER_DAY;
    let hours = (age_secs % SECONDS_PER_DAY) / 3_600;
    if days == 0 {
        format!("{hours}h old")
    } else {
        format!("{days}d {hours}h old")
    }
}
