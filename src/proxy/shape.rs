//! Packument re-serialization — DESIGN.md "Request path" steps 3-5.
//!
//! Everything here is a pure function over `serde_json` values: no clock, no network, no
//! store. The daemon always fetches the *full* packument upstream (abbreviated packuments
//! carry no `time`, so the age gate cannot be evaluated from one) and re-serializes into
//! whichever shape the client asked for.
//!
//! The abbreviated key sets below were taken from the live registry rather than assumed:
//! `Accept: application/vnd.npm.install-v1+json` was fetched for `sqlite3`, `esbuild`,
//! `lodash`, `bcrypt`, `@babel/core`, `fsevents`, `@esbuild/linux-x64`,
//! `@parcel/watcher-linux-x64-glibc` and `@next/swc-linux-x64-gnu` — 3,836 version objects.
//! Top-level keys were exactly `dist-tags, modified, name, versions` in all nine, and the
//! union of per-version keys was `name, version, dist, dependencies, devDependencies,
//! optionalDependencies, peerDependencies, peerDependenciesMeta, bundleDependencies, bin,
//! directories, engines, os, cpu, funding, deprecated, hasInstallScript`. `_hasShrinkwrap`,
//! `libc` and `acceptDependencies` are part of npm's documented abbreviated filter but did
//! not occur in the sample; they are carried through when upstream has them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::policy::{BlockReason, BlockRecord, PolicyConfig, install_hooks};

/// The media type npm sends in `Accept` when it wants an abbreviated packument.
pub const ABBREVIATED_MEDIA_TYPE: &str = "application/vnd.npm.install-v1+json";
/// The media type of a full packument.
pub const FULL_MEDIA_TYPE: &str = "application/json";
/// Where the "what was withheld and why" summary is attached, on the full form only.
pub const SUMMARY_KEY: &str = "_npmfilter";

/// The top-level keys of an abbreviated packument — verified against the live registry.
pub const ABBREVIATED_ROOT_KEYS: [&str; 4] = ["dist-tags", "modified", "name", "versions"];

/// The per-version keys an abbreviated packument carries — verified against the live
/// registry, plus npm's documented `_hasShrinkwrap`, `libc` and `acceptDependencies`.
///
/// Anything else — `scripts`, `_id`, `_npmUser`, `maintainers`, `readme`, `gitHead`, … — is
/// dropped, exactly as the registry's own abbreviated filter drops it.
pub const ABBREVIATED_VERSION_KEYS: [&str; 20] = [
    "_hasShrinkwrap",
    "acceptDependencies",
    "bin",
    "bundleDependencies",
    "cpu",
    "dependencies",
    "deprecated",
    "devDependencies",
    "directories",
    "dist",
    "engines",
    "funding",
    "hasInstallScript",
    "libc",
    "name",
    "optionalDependencies",
    "os",
    "peerDependencies",
    "peerDependenciesMeta",
    "version",
];

/// The `_npmfilter` object attached to a full packument: what was withheld and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterSummary {
    /// Always `npmfilter`, so a human reading a packument knows what touched it.
    pub daemon: &'static str,
    /// The daemon version that filtered this document.
    pub version: &'static str,
    /// When the filtering ran.
    pub generated: DateTime<Utc>,
    /// The policy in force at the time.
    pub policy: SummaryPolicy,
    /// How many versions were withheld.
    pub withheld_count: usize,
    /// Each withheld version, with its gate and a client-safe explanation.
    pub withheld: Vec<WithheldVersion>,
    /// `dist-tags` entries whose target was withheld, e.g. `latest -> 6.0.1`.
    ///
    /// Tags are never moved onto an older release, so these tags still name the version
    /// upstream published. Resolving one fails, which is the point: the client is not handed
    /// a downgrade it did not ask for.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub withheld_dist_tags: Vec<WithheldDistTag>,
    /// What to do about it, naming the tools that resolve it. Present whenever anything was
    /// withheld, because the client's own error says only that no version matched.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub action_required: Option<String>,
}

/// A `dist-tags` entry pointing at a version this daemon withheld.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithheldDistTag {
    /// The tag, e.g. `latest`.
    pub tag: String,
    /// The version it names, which upstream published and this daemon withheld.
    pub version: String,
    /// Which gate stopped that version.
    pub reason: BlockReason,
}

/// One withheld version, as a **registry client** is told about it.
///
/// This is deliberately not [`BlockRecord`]: that carries the operator-facing evidence, which
/// includes values a hostile upstream chose. What goes into a response body names the gate and
/// points at the tool that shows the evidence, and reproduces nothing upstream wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithheldVersion {
    /// The version that was withheld.
    pub version: String,
    /// Which gate stopped it.
    pub reason: BlockReason,
    /// What that means, without reproducing any upstream-controlled value.
    pub detail: String,
}

impl WithheldVersion {
    /// The client-safe view of one block record.
    pub fn new(record: &BlockRecord) -> Self {
        Self {
            version: record.version.clone(),
            reason: record.reason,
            detail: record.public_detail.clone(),
        }
    }
}

/// The policy fields worth restating to a client whose install just lost a version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryPolicy {
    /// Versions younger than this are withheld; `0` disables the age gate.
    pub min_age_days: u32,
    /// Scopes exempt from the automatic gates.
    pub bypass_scopes: Vec<String>,
}

impl FilterSummary {
    /// Build the summary for one filtered packument.
    pub fn new(blocked: &[BlockRecord], policy: &PolicyConfig, generated: DateTime<Utc>) -> Self {
        Self::with_tags(blocked, &[], policy, generated)
    }

    /// Build the summary, naming any `dist-tags` entry whose target was withheld.
    ///
    /// A withheld tag is the case worth shouting about: the client asked for `latest`, the
    /// version upstream calls latest is not installable, and the tag was deliberately NOT
    /// moved onto an older release. Without this, all the client sees is its own generic "no
    /// matching version", with nothing naming npmfilter or saying what to do next.
    pub fn with_tags(
        blocked: &[BlockRecord],
        withheld_dist_tags: &[WithheldDistTag],
        policy: &PolicyConfig,
        generated: DateTime<Utc>,
    ) -> Self {
        let action_required = if blocked.is_empty() {
            None
        } else if withheld_dist_tags.is_empty() {
            Some(
                "Some versions were withheld pending review. To see why and resolve it: \
                 npmfilter_recent_blocks, then npmfilter_inspect(package, version), then \
                 npmfilter_allow(package, version, reason) — or the same subcommands of the \
                 npmfilter CLI."
                    .to_owned(),
            )
        } else {
            let tags = withheld_dist_tags
                .iter()
                .map(|entry| format!("{} -> {}", entry.tag, entry.version))
                .collect::<Vec<_>>()
                .join(", ");
            Some(format!(
                "RESOLUTION WILL FAIL: {tags}. The version this tag names is withheld pending \
                 review, and npmfilter does NOT move a tag onto an older release — that would \
                 silently downgrade you. Either approve the named version after reviewing it \
                 (npmfilter_recent_blocks -> npmfilter_inspect -> npmfilter_allow, or the \
                 npmfilter CLI), or request an older version explicitly."
            ))
        };
        Self {
            daemon: "npmfilter",
            version: env!("CARGO_PKG_VERSION"),
            generated,
            policy: SummaryPolicy {
                min_age_days: policy.min_age_days,
                bypass_scopes: policy.bypass_scopes.clone(),
            },
            withheld_count: blocked.len(),
            withheld: blocked.iter().map(WithheldVersion::new).collect(),
            withheld_dist_tags: withheld_dist_tags.to_vec(),
            action_required,
        }
    }
}

/// Which `dist-tags` entries name a version that was withheld.
///
/// Returns nothing when the tags were moved (`allow_dist_tag_downgrade`), because then no tag
/// names a withheld version by construction.
pub fn withheld_dist_tags(filtered: &Value, blocked: &[BlockRecord]) -> Vec<WithheldDistTag> {
    let Some(tags) = filtered.get("dist-tags").and_then(Value::as_object) else {
        return Vec::new();
    };
    let surviving = filtered.get("versions").and_then(Value::as_object);
    let mut out = Vec::new();
    for (tag, target) in tags {
        let Some(target) = target.as_str() else {
            continue;
        };
        if surviving.is_some_and(|versions| versions.contains_key(target)) {
            continue;
        }
        if let Some(record) = blocked.iter().find(|record| record.version == target) {
            out.push(WithheldDistTag {
                tag: tag.clone(),
                version: target.to_owned(),
                reason: record.reason,
            });
        }
    }
    out
}

/// Does this `Accept` header ask for the abbreviated shape?
///
/// npm sends `application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*`, so a
/// substring test is what the registry itself effectively does.
pub fn wants_abbreviated(accept: Option<&str>) -> bool {
    accept.is_some_and(|accept| accept.to_ascii_lowercase().contains(ABBREVIATED_MEDIA_TYPE))
}

/// Re-serialize a (already filtered) full packument into npm's abbreviated shape.
///
/// `modified` is taken from `time.modified`, which is where the full form keeps it. A
/// packument that is not a JSON object is returned untouched — the caller has already had a
/// chance to reject it, and mangling it further helps nobody.
pub fn abbreviate(full: &Value) -> Value {
    let Some(root) = full.as_object() else {
        return full.clone();
    };
    let mut out = Map::new();

    if let Some(name) = root.get("name") {
        out.insert("name".to_owned(), name.clone());
    }
    if let Some(tags) = root.get("dist-tags") {
        out.insert("dist-tags".to_owned(), tags.clone());
    }
    if let Some(modified) = root
        .get("time")
        .and_then(Value::as_object)
        .and_then(|time| time.get("modified"))
        .or_else(|| root.get("modified"))
    {
        out.insert("modified".to_owned(), modified.clone());
    }

    let mut versions = Map::new();
    if let Some(source) = root.get("versions").and_then(Value::as_object) {
        for (version, meta) in source {
            versions.insert(version.clone(), abbreviate_version(meta));
        }
    }
    out.insert("versions".to_owned(), Value::Object(versions));

    Value::Object(out)
}

/// Re-serialize one version object into npm's abbreviated shape.
///
/// `dist` is copied verbatim, so `dist.tarball` keeps pointing at upstream — DESIGN.md
/// "Decisions taken", tarballs are pass-through.
///
/// Empty values are dropped, because the registry drops them: across the 3,836 abbreviated
/// version objects sampled above, not one carried `{}`, `[]`, `""`, `null` or
/// `_hasShrinkwrap: false`. Emitting `"dependencies": {}` where npm emits nothing would make
/// this daemon's output distinguishable from the registry's for no gain.
pub fn abbreviate_version(meta: &Value) -> Value {
    let Some(source) = meta.as_object() else {
        return meta.clone();
    };
    let mut out = Map::new();
    for key in ABBREVIATED_VERSION_KEYS {
        match source.get(key) {
            Some(value) if !is_empty_value(value) => {
                out.insert(key.to_owned(), value.clone());
            }
            _ => {}
        }
    }
    if has_install_script(meta) {
        out.insert("hasInstallScript".to_owned(), Value::Bool(true));
    }
    Value::Object(out)
}

/// Is this a value npm's abbreviated packument would simply omit?
fn is_empty_value(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(flag) => !flag,
        Value::String(text) => text.is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Object(fields) => fields.is_empty(),
        Value::Number(_) => false,
    }
}

/// Does this version declare `preinstall`, `install` or `postinstall`?
///
/// An upstream document that already states `hasInstallScript` is believed as well, so the
/// flag survives even if `scripts` was stripped before it reached us. This is exactly the
/// predicate policy gate 5 blocks on, so the two layers can never disagree about whether a
/// version runs install scripts.
pub fn has_install_script(meta: &Value) -> bool {
    !install_hooks(meta).is_empty() || crate::policy::flags_install_script(meta)
}

/// Attach the `_npmfilter` summary to a full packument (DESIGN.md "Request path" step 3).
///
/// A packument that is not a JSON object is returned untouched, and a summary that somehow
/// fails to serialize is logged and skipped — the packument still goes out.
pub fn with_summary(
    full: Value,
    blocked: &[BlockRecord],
    policy: &PolicyConfig,
    generated: DateTime<Utc>,
) -> Value {
    let tags = withheld_dist_tags(&full, blocked);
    let Value::Object(mut root) = full else {
        return full;
    };
    let summary = FilterSummary::with_tags(blocked, &tags, policy, generated);
    match serde_json::to_value(&summary) {
        Ok(value) => {
            root.insert(SUMMARY_KEY.to_owned(), value);
        }
        Err(error) => {
            tracing::error!(%error, "failed to serialize the _npmfilter summary; omitting it");
        }
    }
    Value::Object(root)
}

/// Percent-encode a package name for use as a single upstream path segment.
///
/// `@scope/name` becomes `@scope%2Fname`, which is the form the registry documents for
/// scoped packages. Everything outside the unreserved set is encoded, so a name arriving
/// from a request path can never climb out of the segment it was given.
pub fn encode_package_path(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 8);
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'@') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(hex_digit(byte >> 4));
            out.push(hex_digit(byte & 0x0f));
        }
    }
    out
}

fn hex_digit(nibble: u8) -> char {
    const DIGITS: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
    ];
    DIGITS[usize::from(nibble & 0x0f)]
}
