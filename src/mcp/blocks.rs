//! `npmfilter_recent_blocks` — DESIGN.md's "entry point when an install fails".
//!
//! The daemon records one audit row per withheld version. A row's `detail` is written by
//! [`crate::store::AuditEntry::block`] as `"<reason>: <BlockRecord.detail>"`, and the install-hook
//! gate's own detail is `"install hooks present — <hook>: <command>; <hook>: <command>"`. This
//! module turns those rows back into structured answers: package, version, reason, the offending
//! script commands, and what to do next.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::policy::{BlockReason, INSTALL_HOOKS};
use crate::store::{AuditRecord, EVENT_BLOCK, EVENT_TAMPER};

use super::inspect::HookCommand;

/// The marker the install-script gate puts before its command list.
const HOOK_MARKER: &str = "install hooks present — ";

/// One withheld version, ready to act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecentBlock {
    /// The audit row's id, so a caller can correlate.
    pub id: i64,
    /// The package that was withheld.
    pub package: String,
    /// The version that was withheld.
    pub version: Option<String>,
    /// `integrity_changed` | `deny_rule` | `too_new` | `install_script`, when recognisable.
    pub reason: Option<String>,
    /// The audit event: `block` or `tamper`.
    pub event: String,
    /// `info` | `warning` | `critical`.
    pub severity: String,
    /// When it happened, RFC 3339.
    pub at: String,
    /// The gate's own explanation, with the reason prefix stripped.
    pub detail: String,
    /// The install-hook commands that caused the block, when that was the reason.
    pub scripts: Vec<HookCommand>,
    /// What to do about it.
    pub next_step: String,
}

/// Whether an audit row describes a withheld version.
pub fn is_block(record: &AuditRecord) -> bool {
    record.entry.event == EVENT_BLOCK || record.entry.event == EVENT_TAMPER
}

/// Turn one audit row into a [`RecentBlock`].
pub fn from_audit(record: &AuditRecord) -> RecentBlock {
    let (reason, detail) = split_reason(&record.entry.detail);
    let scripts = parse_hooks(&detail);
    let next_step = next_step(
        reason,
        &record.entry.name,
        record.entry.version.as_deref().unwrap_or("<version>"),
    );
    RecentBlock {
        id: record.id,
        package: record.entry.name.clone(),
        version: record.entry.version.clone(),
        reason: reason.map(|reason| reason.as_str().to_owned()),
        event: record.entry.event.clone(),
        severity: record.entry.severity.as_str().to_owned(),
        at: record.entry.ts.to_rfc3339(),
        detail,
        scripts,
        next_step,
    }
}

/// Split `"<reason>: <detail>"` into the recognised reason and the rest.
///
/// A row whose prefix is not one of the four reasons is returned whole, so a hand-written or
/// future audit row is never mangled.
pub fn split_reason(detail: &str) -> (Option<BlockReason>, String) {
    let Some((head, tail)) = detail.split_once(": ") else {
        return (None, detail.to_owned());
    };
    match parse_reason(head) {
        Some(reason) => (Some(reason), tail.to_owned()),
        None => (None, detail.to_owned()),
    }
}

/// The `BlockReason` wire strings, parsed back.
pub fn parse_reason(raw: &str) -> Option<BlockReason> {
    match raw {
        "integrity_changed" => Some(BlockReason::IntegrityChanged),
        "deny_rule" => Some(BlockReason::DenyRule),
        "too_new" => Some(BlockReason::TooNew),
        "install_script" => Some(BlockReason::InstallScript),
        "scripts_changed" => Some(BlockReason::ScriptsChanged),
        _ => None,
    }
}

/// Pull the offending commands out of an install-script block's detail.
///
/// The list is `hook: command` pairs joined by `"; "`, and a command may itself contain `"; "`
/// (`postinstall: node a.js; node b.js`). A new pair therefore only starts where a known hook
/// name is followed by `": "`, at the start of the list or immediately after a `"; "`.
pub fn parse_hooks(detail: &str) -> Vec<HookCommand> {
    let Some(list) = detail.split_once(HOOK_MARKER).map(|(_, tail)| tail) else {
        return Vec::new();
    };

    let mut starts: Vec<(usize, &'static str)> = Vec::new();
    for hook in INSTALL_HOOKS {
        let needle = format!("{hook}: ");
        let mut from = 0usize;
        while let Some(found) = list[from..].find(&needle) {
            let at = from + found;
            if at == 0 || list[..at].ends_with("; ") {
                starts.push((at, hook));
            }
            from = at + needle.len();
        }
    }
    starts.sort_by_key(|(at, _)| *at);

    let mut hooks = Vec::new();
    for (index, (at, hook)) in starts.iter().enumerate() {
        let value_from = at + hook.len() + 2;
        let end = match starts.get(index + 1) {
            // Drop the `"; "` that separates this command from the next pair.
            Some((next, _)) => next.saturating_sub(2),
            None => list.len(),
        };
        if value_from > end || end > list.len() {
            continue;
        }
        hooks.push(HookCommand::new(*hook, &list[value_from..end]));
    }
    hooks
}

/// What the caller should do about a block.
fn next_step(reason: Option<BlockReason>, package: &str, version: &str) -> String {
    match reason {
        Some(BlockReason::InstallScriptQuarantine) => format!(
            "{package}@{version} runs an install hook and is inside the quarantine floor. \
             NO approval overrides it — that is the point: a malicious release is normally \
             pulled within a day or two, and reviewing it early cannot shorten that. Run \
             npmfilter_inspect({package}, {version}) and npmfilter_allow now if it is \
             legitimate — the rule is recorded and takes effect when the window clears — or \
             install a version already past it"
        ),
        Some(BlockReason::InstallScript) => format!(
            "run npmfilter_inspect({package}, {version}) — read the script delta against the \
             previous published version — then npmfilter_allow({package}, {version}, reason) if \
             the hook is legitimate"
        ),
        Some(BlockReason::TooNew) => format!(
            "this version is inside the quarantine window; wait it out, or run \
             npmfilter_inspect({package}, {version}) and npmfilter_allow({package}, {version}, reason) \
             to admit it early"
        ),
        Some(BlockReason::DenyRule) => format!(
            "an explicit deny rule withholds {package}@{version}; check npmfilter_rules({package}) \
             before changing it"
        ),
        Some(BlockReason::IntegrityChanged) => format!(
            "CRITICAL — {package}@{version} no longer serves the bytes npmfilter first recorded. \
             Published npm versions are immutable, so this is version replacement. Run \
             npmfilter_ledger({package}) for the recorded hash; do NOT approve it without \
             establishing why the hash moved"
        ),
        Some(BlockReason::ScriptsChanged) => format!(
            "CRITICAL — the approval for {package}@{version} covered different install-hook \
             commands than the ones it now declares. Run npmfilter_inspect({package}, {version}) \
             and read the script delta; re-approve with npmfilter_allow only once you know why \
             the command changed"
        ),
        Some(BlockReason::NoIntegrity) => format!(
            "{package}@{version} publishes no content hash at all — neither dist.integrity nor \
             dist.shasum — so nothing pins its bytes and the integrity ledger cannot tell \
             whether they were replaced. Run npmfilter_inspect({package}, {version}); approve it \
             only if you accept that no later replacement of this version can be detected"
        ),
        None => format!("inspect {package}@{version} before acting on this event"),
    }
}
