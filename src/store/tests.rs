//! Store tests — schema, rules, the TOFU ledger, the audit log, and the policy engine running
//! against real SQLite storage. Nothing here touches the network; every database is either
//! in-memory or a temp file removed on drop.

use std::fs;

use serde_json::json;

use super::*;
use crate::policy::{self, BlockReason, PolicyConfig};

/// A sha512 integrity, as npm publishes them (shortened — only equality matters here).
const HASH_A: &str = "sha512-AAAAaaaaBBBBbbbbCCCCccccDDDDddddEEEEeeeeFFFFffff==";
const HASH_B: &str = "sha512-ZZZZzzzzYYYYyyyyXXXXxxxxWWWWwwwwVVVVvvvvUUUUuuuu==";

fn ts(raw: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(raw)
        .expect("fixture timestamp is valid RFC 3339")
        .with_timezone(&Utc)
}

fn now() -> DateTime<Utc> {
    ts("2026-08-04T12:00:00Z")
}

fn store() -> Store {
    Store::open_in_memory().expect("in-memory store opens")
}

/// A temp directory that removes itself, so `open` can be tested on a path that does not exist.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("npmfilter-store-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        Self { path }
    }

    /// A database path two levels below a directory that does not exist yet.
    fn db(&self) -> PathBuf {
        self.path.join("state").join("rules.db")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// -- schema ------------------------------------------------------------------------------

#[test]
fn opening_creates_the_schema_and_the_state_directory() {
    let dir = TempDir::new("schema");
    let path = dir.db();
    assert!(!path.exists(), "fixture must start from nothing");

    let store = Store::open(&path).expect("store opens on a fresh path");
    assert!(path.is_file(), "database file was created at {path:?}");
    assert_eq!(store.path(), Some(path.as_path()));

    let conn = store.lock();
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user_version readable");
    assert_eq!(version, SCHEMA_VERSION);

    let mut tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get::<_, String>(0))
                .and_then(|rows| rows.collect())
        })
        .expect("table list readable");
    tables.retain(|name| !name.starts_with("sqlite_"));
    assert_eq!(tables, vec!["audit", "rules", "seen"]);
}

#[test]
fn reopening_keeps_the_data_and_does_not_re_migrate() {
    let dir = TempDir::new("reopen");
    let path = dir.db();

    {
        let store = Store::open(&path).expect("first open");
        store
            .record_rule(&NewRule::allow("sqlite3", "5.1.7", HASH_A), now())
            .expect("rule recorded");
        store
            .try_observe("sqlite3", "5.1.7", Some(HASH_A), now())
            .expect("observation recorded");
    }

    let store = Store::open(&path).expect("second open");
    let rule = store
        .try_lookup_rule("sqlite3", "5.1.7")
        .expect("lookup succeeds")
        .expect("rule survived the reopen");
    assert_eq!(rule.rule.integrity.as_deref(), Some(HASH_A));
    let entry = store
        .ledger_entry("sqlite3", "5.1.7")
        .expect("ledger readable")
        .expect("observation survived the reopen");
    assert_eq!(entry.times_seen, 1);
}

// -- TOFU ledger -------------------------------------------------------------------------

#[test]
fn first_sight_records_the_version_and_reports_unseen() {
    let store = store();
    let check = store
        .try_observe("keyv", "5.0.0", Some(HASH_A), now())
        .expect("observe succeeds");
    assert_eq!(check, LedgerCheck::Unseen);

    let entry = store
        .ledger_entry("keyv", "5.0.0")
        .expect("ledger readable")
        .expect("first sight was recorded");
    assert_eq!(entry.integrity.as_deref(), Some(HASH_A));
    assert_eq!(entry.first_seen, now());
    assert_eq!(entry.last_seen, now());
    assert_eq!(entry.times_seen, 1);
}

#[test]
fn a_matching_reobservation_bumps_last_seen_and_times_seen() {
    let store = store();
    let later = ts("2026-08-06T09:30:00Z");
    assert_eq!(
        store
            .try_observe("keyv", "5.0.0", Some(HASH_A), now())
            .expect("first observe"),
        LedgerCheck::Unseen
    );
    assert_eq!(
        store
            .try_observe("keyv", "5.0.0", Some(HASH_A), later)
            .expect("second observe"),
        LedgerCheck::Match
    );

    let entry = store
        .ledger_entry("keyv", "5.0.0")
        .expect("ledger readable")
        .expect("entry present");
    assert_eq!(entry.integrity.as_deref(), Some(HASH_A));
    assert_eq!(entry.first_seen, now(), "first_seen is never moved");
    assert_eq!(entry.last_seen, later);
    assert_eq!(entry.times_seen, 2);
}

#[test]
fn a_changed_integrity_reports_changed_and_never_overwrites_the_recorded_hash() {
    let store = store();
    let later = ts("2026-08-06T09:30:00Z");
    store
        .try_observe("keyv", "5.0.0", Some(HASH_A), now())
        .expect("first observe");

    let check = store
        .try_observe("keyv", "5.0.0", Some(HASH_B), later)
        .expect("second observe");
    assert_eq!(
        check,
        LedgerCheck::Changed {
            recorded: Some(HASH_A.to_owned())
        }
    );

    let entry = store
        .ledger_entry("keyv", "5.0.0")
        .expect("ledger readable")
        .expect("entry present");
    assert_eq!(
        entry.integrity.as_deref(),
        Some(HASH_A),
        "the first hash is the evidence and must survive"
    );
    assert_eq!(entry.last_seen, now(), "a mismatch does not bump last_seen");
    assert_eq!(entry.times_seen, 1, "a mismatch does not bump times_seen");

    // The mismatch is still reported on every later fetch — it is not a one-shot alarm.
    assert_eq!(
        store
            .try_observe("keyv", "5.0.0", Some(HASH_B), later)
            .expect("third observe"),
        LedgerCheck::Changed {
            recorded: Some(HASH_A.to_owned())
        }
    );
}

#[test]
fn a_version_without_integrity_is_recorded_as_null_and_gaining_one_counts_as_changed() {
    let store = store();
    assert_eq!(
        store
            .try_observe("ancient", "0.0.1", None, now())
            .expect("first observe"),
        LedgerCheck::Unseen
    );
    let entry = store
        .ledger_entry("ancient", "0.0.1")
        .expect("ledger readable")
        .expect("entry present");
    assert_eq!(entry.integrity, None);

    assert_eq!(
        store
            .try_observe("ancient", "0.0.1", None, now())
            .expect("second observe"),
        LedgerCheck::Match
    );
    assert_eq!(
        store
            .try_observe("ancient", "0.0.1", Some(HASH_A), now())
            .expect("third observe"),
        LedgerCheck::Changed { recorded: None }
    );
}

/// One packument is one transaction. It used to be one `IMMEDIATE` transaction *per version*,
/// which is what let a hostile upstream turn a single `GET` into minutes of disk-bound work
/// and tens of megabytes of permanent state.
#[test]
fn a_whole_packument_is_observed_in_one_batch() {
    let store = store();
    let first: Vec<(String, Option<String>)> = vec![
        ("1.0.0".to_owned(), Some(HASH_A.to_owned())),
        ("1.1.0".to_owned(), Some(HASH_B.to_owned())),
        ("1.2.0".to_owned(), None),
    ];

    let checks = store
        .try_observe_batch("widget", &first, now(), true)
        .expect("batch observed");
    assert_eq!(
        checks,
        vec![
            LedgerCheck::Unseen,
            LedgerCheck::Unseen,
            LedgerCheck::Unseen
        ]
    );

    // Every row landed, in the same order, with the same semantics as one-at-a-time.
    let checks = store
        .try_observe_batch("widget", &first, now(), true)
        .expect("batch re-observed");
    assert_eq!(
        checks,
        vec![LedgerCheck::Match, LedgerCheck::Match, LedgerCheck::Match]
    );
    assert_eq!(
        store
            .ledger_entry("widget", "1.0.0")
            .expect("readable")
            .expect("present")
            .times_seen,
        2
    );

    // A replacement inside a batch is reported per version, and the recorded hash stays frozen.
    let replaced: Vec<(String, Option<String>)> = vec![
        ("1.0.0".to_owned(), Some(HASH_B.to_owned())),
        ("1.1.0".to_owned(), Some(HASH_B.to_owned())),
    ];
    let checks = store
        .try_observe_batch("widget", &replaced, now(), true)
        .expect("batch observed");
    assert_eq!(
        checks,
        vec![
            LedgerCheck::Changed {
                recorded: Some(HASH_A.to_owned())
            },
            LedgerCheck::Match
        ]
    );
    let entry = store
        .ledger_entry("widget", "1.0.0")
        .expect("readable")
        .expect("present");
    assert_eq!(entry.integrity.as_deref(), Some(HASH_A));
    assert_eq!(entry.mismatch_count, 1);

    // An empty document is not a transaction at all.
    assert!(
        store
            .try_observe_batch("widget", &[], now(), true)
            .expect("no work")
            .is_empty()
    );
}

/// The ledger is evidence, so retention is deliberately narrow — but it does exist. Without
/// it the table grows for ever and a full disk fails every store write, which fails closed
/// into a machine where nothing resolves.
#[test]
fn pruning_the_ledger_keeps_mismatches_rules_and_recent_observations() {
    let store = store();
    let old = ts("2024-01-01T00:00:00Z");
    let cutoff = ts("2025-01-01T00:00:00Z");

    store
        .try_observe("stale", "1.0.0", Some(HASH_A), old)
        .expect("observed");
    store
        .try_observe("recent", "1.0.0", Some(HASH_A), now())
        .expect("observed");
    // A version that recorded a replacement attempt is evidence for ever.
    store
        .try_observe("tampered", "1.0.0", Some(HASH_A), old)
        .expect("observed");
    store
        .try_observe("tampered", "1.0.0", Some(HASH_B), old)
        .expect("mismatch recorded");
    // A version an operator ruled on keeps the observation the verdict was formed against.
    store
        .try_observe("ruled", "1.0.0", Some(HASH_A), old)
        .expect("observed");
    store
        .record_rule(&NewRule::allow("ruled", "1.0.0", HASH_A), old)
        .expect("rule recorded");

    let removed = store.prune_seen(cutoff).expect("prune runs");
    assert_eq!(removed, 1, "only the stale, unremarkable row goes");
    assert!(
        store
            .ledger_entry("stale", "1.0.0")
            .expect("readable")
            .is_none()
    );
    for kept in ["recent", "tampered", "ruled"] {
        assert!(
            store
                .ledger_entry(kept, "1.0.0")
                .expect("readable")
                .is_some(),
            "{kept} must survive pruning"
        );
    }
}

#[test]
fn a_package_wide_note_is_recorded_once_and_only_once() {
    let store = store();
    let entry = AuditEntry {
        ts: now(),
        event: EVENT_FOREIGN_TARBALL.to_owned(),
        severity: Severity::Warning,
        name: "widget".to_owned(),
        version: None,
        detail: "tarballs live on cdn.example.test".to_owned(),
    };

    assert!(store.append_audit_once(&entry).expect("first write"));
    assert!(!store.append_audit_once(&entry).expect("second write"));
    assert!(!store.append_audit_once(&entry).expect("third write"));

    let rows = store.recent_audit(Some("widget"), 50).expect("audit read");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].entry.event, EVENT_FOREIGN_TARBALL);
    assert_eq!(rows[0].entry.severity, Severity::Warning);

    // Another package gets its own row.
    let other = AuditEntry {
        name: "other".to_owned(),
        ..entry
    };
    assert!(store.append_audit_once(&other).expect("first write"));
}

/// v3 drops `seen` rows recorded with a `NULL` integrity. They were evidence of nothing: every
/// later observation compared absent against absent and reported the version unchanged, so a
/// hash-less version was exempt from the ledger entirely.
#[test]
fn upgrading_from_v2_drops_the_null_integrity_ledger_rows() {
    let dir = TempDir::new("migrate-v3");
    let path = dir.db();
    fs::create_dir_all(path.parent().expect("a parent")).expect("state dir");

    {
        let conn = Connection::open(&path).expect("raw connection");
        conn.execute_batch(SCHEMA_SQL).expect("v2 schema");
        conn.pragma_update(None, "user_version", 2i64)
            .expect("pretend to be v2");
        conn.execute(
            "INSERT INTO seen (name, version, integrity, first_seen_ts, last_seen_ts, times_seen,
                               mismatch_count, last_mismatch_ts)
             VALUES ('hashless', '1.0.0', NULL, 1, 1, 9, 0, NULL)",
            [],
        )
        .expect("null row");
        conn.execute(
            "INSERT INTO seen (name, version, integrity, first_seen_ts, last_seen_ts, times_seen,
                               mismatch_count, last_mismatch_ts)
             VALUES ('pinned', '1.0.0', 'sha512-AAA', 1, 1, 9, 0, NULL)",
            [],
        )
        .expect("real row");
    }

    let store = Store::open(&path).expect("upgrade to v3");
    assert!(
        store
            .ledger_entry("hashless", "1.0.0")
            .expect("readable")
            .is_none(),
        "a NULL identity was never evidence and must not survive as one"
    );
    assert_eq!(
        store
            .ledger_entry("pinned", "1.0.0")
            .expect("readable")
            .expect("kept")
            .integrity
            .as_deref(),
        Some("sha512-AAA")
    );
    let version: i64 = store
        .lock()
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("user_version");
    assert_eq!(version, SCHEMA_VERSION);
}

#[test]
fn the_ledger_is_keyed_per_version_and_per_package() {
    let store = store();
    store
        .try_observe("keyv", "5.0.0", Some(HASH_A), now())
        .expect("observe 5.0.0");
    store
        .try_observe("keyv", "5.1.0", Some(HASH_B), now())
        .expect("observe 5.1.0");
    store
        .try_observe("flat-cache", "5.0.0", Some(HASH_B), now())
        .expect("observe another package");

    assert_eq!(
        store
            .ledger_entry("keyv", "5.1.0")
            .expect("readable")
            .and_then(|entry| entry.integrity)
            .as_deref(),
        Some(HASH_B)
    );
    let history = store.ledger_history("keyv").expect("history readable");
    assert_eq!(history.len(), 2, "only keyv rows: {history:?}");
}

// -- rules -------------------------------------------------------------------------------

#[test]
fn an_allow_rule_round_trips_with_its_script_pins() {
    let store = store();
    let scripts =
        ScriptSet::from_hooks([("install", "prebuild-install -r napi || node-gyp rebuild")]);
    let stored = store
        .record_rule(
            &NewRule::allow("sqlite3", "5.1.7", HASH_A)
                .with_scripts(scripts.clone())
                .with_reason("native build tool, reviewed")
                .with_actor("olamedia"),
            now(),
        )
        .expect("rule recorded");

    assert!(stored.id > 0);
    assert_eq!(stored.created, now());
    assert_eq!(
        stored.scripts_json.as_deref(),
        Some(scripts.json().as_str())
    );

    let found = store
        .try_lookup_rule("sqlite3", "5.1.7")
        .expect("lookup succeeds")
        .expect("rule present");
    assert_eq!(found, stored);
    assert_eq!(found.rule.verdict, Verdict::Allow);
    assert_eq!(found.rule.integrity.as_deref(), Some(HASH_A));
    assert_eq!(found.rule.scripts_sha256, Some(scripts.sha256()));
    assert_eq!(
        found.rule.reason.as_deref(),
        Some("native build tool, reviewed")
    );
    assert_eq!(found.rule.actor.as_deref(), Some("olamedia"));

    assert_eq!(
        store.try_lookup_rule("sqlite3", "5.1.6").expect("lookup"),
        None,
        "rules are pinned to one exact version"
    );
}

#[test]
fn recording_a_rule_again_replaces_the_previous_verdict() {
    let store = store();
    store
        .record_rule(&NewRule::allow("keyv", "5.0.0", HASH_A), now())
        .expect("allow recorded");
    let later = ts("2026-08-05T08:00:00Z");
    store
        .record_rule(&NewRule::deny("keyv", "5.0.0").with_reason("worm"), later)
        .expect("deny recorded");

    let rules = store
        .list_rules(&RuleFilter::for_package("keyv"))
        .expect("list succeeds");
    assert_eq!(rules.len(), 1, "one rule per (name, version): {rules:?}");
    assert_eq!(rules[0].rule.verdict, Verdict::Deny);
    assert_eq!(rules[0].rule.integrity, None);
    assert_eq!(rules[0].created, later);
    assert_eq!(store.rule_counts().expect("counts"), (0, 1));
}

#[test]
fn rules_are_listed_and_filtered() {
    let store = store();
    for rule in [
        NewRule::allow("sqlite3", "5.1.7", HASH_A),
        NewRule::allow("esbuild", "0.25.0", HASH_B),
        NewRule::deny("keyv", "5.0.0"),
        NewRule::deny("keyv", "5.1.0"),
    ] {
        store.record_rule(&rule, now()).expect("rule recorded");
    }

    let all = store.list_rules(&RuleFilter::all()).expect("list all");
    let listed: Vec<(&str, &str)> = all
        .iter()
        .map(|stored| (stored.rule.name.as_str(), stored.rule.version.as_str()))
        .collect();
    assert_eq!(
        listed,
        vec![
            ("esbuild", "0.25.0"),
            ("keyv", "5.0.0"),
            ("keyv", "5.1.0"),
            ("sqlite3", "5.1.7"),
        ],
        "ordered by name then version"
    );

    let keyv = store
        .list_rules(&RuleFilter::for_package("keyv"))
        .expect("list by name");
    assert_eq!(keyv.len(), 2);

    let allows = store
        .list_rules(&RuleFilter::all().with_verdict(Verdict::Allow))
        .expect("list by verdict");
    assert_eq!(allows.len(), 2);

    let keyv_allows = store
        .list_rules(&RuleFilter::for_package("keyv").with_verdict(Verdict::Allow))
        .expect("list by name and verdict");
    assert!(keyv_allows.is_empty());

    assert_eq!(store.rule_counts().expect("counts"), (2, 2));
}

// -- script hashing ----------------------------------------------------------------------

#[test]
fn scripts_sha256_is_stable_under_key_reordering() {
    let forwards = ScriptSet::from_hooks([
        ("preinstall", "node setup.mjs"),
        ("install", "node-gyp rebuild"),
        ("postinstall", "node fix.js"),
    ]);
    let backwards = ScriptSet::from_hooks([
        ("postinstall", "node fix.js"),
        ("install", "node-gyp rebuild"),
        ("preinstall", "node setup.mjs"),
    ]);

    assert_eq!(forwards.json(), backwards.json());
    assert_eq!(forwards.sha256(), backwards.sha256());
    assert_eq!(
        forwards.json(),
        r#"{"install":"node-gyp rebuild","postinstall":"node fix.js","preinstall":"node setup.mjs"}"#,
        "canonical form is the sorted map"
    );
    assert_eq!(forwards.sha256().len(), 64, "hex sha256");
    assert!(forwards.sha256().chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn a_changed_command_changes_the_script_hash() {
    let approved = ScriptSet::from_hooks([("install", "node-gyp rebuild")]);
    let tampered = ScriptSet::from_hooks([("install", "node-gyp rebuild && node setup.mjs")]);
    assert_ne!(approved.sha256(), tampered.sha256());

    let renamed = ScriptSet::from_hooks([("preinstall", "node-gyp rebuild")]);
    assert_ne!(
        approved.sha256(),
        renamed.sha256(),
        "the same command under a different hook is a different approval"
    );

    let empty = ScriptSet::new();
    assert!(empty.is_empty());
    assert_eq!(empty.json(), "{}");
    assert_ne!(empty.sha256(), approved.sha256());
}

#[test]
fn the_script_hash_matches_sha256_of_the_canonical_json() {
    // Reference values from `printf '%s' '<json>' | sha256sum` — this pins both the canonical
    // form and the hex encoding, so a later refactor cannot silently change what an approval
    // is bound to.
    let pair = ScriptSet::from_hooks([
        ("install", "node-gyp rebuild"),
        ("preinstall", "node setup.mjs"),
    ]);
    assert_eq!(
        pair.json(),
        r#"{"install":"node-gyp rebuild","preinstall":"node setup.mjs"}"#
    );
    assert_eq!(
        pair.sha256(),
        "26dd45fbb1536716e414acd942a01e3a0652925ab977c90e0117697e6b4329f5"
    );
    assert_eq!(
        ScriptSet::new().sha256(),
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        "sha256 of {{}}"
    );
}

#[test]
fn a_script_set_is_read_straight_off_a_packument_version() {
    let meta = json!({
        "name": "sqlite3",
        "version": "5.1.7",
        "scripts": {
            "postinstall": "node fix.js",
            "test": "mocha",
            "install": "node-gyp rebuild",
            "prepare": "tsc"
        },
        "dist": { "integrity": HASH_A }
    });
    let scripts = ScriptSet::from_version(&meta);
    assert_eq!(
        scripts.len(),
        2,
        "only install hooks: {:?}",
        scripts.hooks()
    );
    assert_eq!(
        scripts.hooks().keys().cloned().collect::<Vec<_>>(),
        vec!["install".to_owned(), "postinstall".to_owned()]
    );
    assert_eq!(
        ScriptSet::from_version(&json!({ "version": "1.0.0" })),
        ScriptSet::new(),
        "a version with no scripts hashes as the empty set"
    );
}

// -- audit -------------------------------------------------------------------------------

#[test]
fn audit_rows_are_appended_and_read_back_newest_first() {
    let store = store();
    store
        .append_audit(&AuditEntry::tamper(
            "keyv",
            "5.0.0",
            "integrity moved from A to B",
            now(),
        ))
        .expect("tamper appended");
    let later = ts("2026-08-04T13:00:00Z");
    store
        .append_audit(
            &NewRule::allow("sqlite3", "5.1.7", HASH_A)
                .with_reason("reviewed")
                .audit_entry(later),
        )
        .expect("allow appended");

    let recent = store.recent_audit(None, 10).expect("audit readable");
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].entry.event, EVENT_ALLOW);
    assert_eq!(recent[0].entry.severity, Severity::Info);
    assert_eq!(recent[0].entry.ts, later);
    assert!(
        recent[0].entry.detail.contains(HASH_A) && recent[0].entry.detail.contains("reviewed"),
        "allow detail records the pin and the reason: {}",
        recent[0].entry.detail
    );
    assert_eq!(recent[1].entry.event, EVENT_TAMPER);
    assert_eq!(recent[1].entry.severity, Severity::Critical);

    let filtered = store.recent_audit(Some("keyv"), 10).expect("filtered");
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].entry.name, "keyv");
    assert_eq!(store.recent_audit(None, 1).expect("limited").len(), 1);

    let denial = NewRule::deny("flat-cache", "6.0.0")
        .with_reason("worm")
        .audit_entry(now());
    assert_eq!(denial.event, EVENT_DENY);
    assert_eq!(denial.severity, Severity::Warning);
}

#[test]
fn every_withheld_version_lands_in_the_audit_log_with_its_severity() {
    let store = store();
    let blocked = vec![
        BlockRecord::new(
            "5.0.0",
            BlockReason::IntegrityChanged,
            "integrity ledger: recorded A, upstream now serves a different value",
        ),
        BlockRecord::new(
            "5.1.0",
            BlockReason::InstallScript,
            "install hooks present — preinstall: node setup.mjs",
        ),
        BlockRecord::new("5.2.0", BlockReason::TooNew, "published today"),
    ];
    assert_eq!(
        store
            .record_blocks("keyv", &blocked, now())
            .expect("appended"),
        3
    );
    assert_eq!(store.record_blocks("keyv", &[], now()).expect("no-op"), 0);

    let rows = store
        .recent_audit(Some("keyv"), 10)
        .expect("audit readable");
    assert_eq!(rows.len(), 3);
    let by_version: BTreeMap<String, (String, Severity, String)> = rows
        .into_iter()
        .filter_map(|row| {
            row.entry.version.clone().map(|version| {
                (
                    version,
                    (row.entry.event, row.entry.severity, row.entry.detail),
                )
            })
        })
        .collect();

    let (event, severity, detail) = &by_version["5.0.0"];
    assert_eq!(
        event, EVENT_TAMPER,
        "an integrity mismatch is a tamper event"
    );
    assert_eq!(*severity, Severity::Critical);
    assert!(detail.starts_with("integrity_changed: "), "{detail}");

    let (event, severity, detail) = &by_version["5.1.0"];
    assert_eq!(event, EVENT_BLOCK);
    assert_eq!(*severity, Severity::Warning);
    assert!(detail.starts_with("install_script: "), "{detail}");

    let (event, severity, _) = &by_version["5.2.0"];
    assert_eq!(event, EVENT_BLOCK);
    assert_eq!(*severity, Severity::Warning);
}

#[test]
fn recording_a_rule_audited_writes_both_the_rule_and_the_event() {
    let store = store();
    store
        .record_rule_audited(
            &NewRule::allow("sqlite3", "5.1.7", HASH_A).with_actor("mcp"),
            now(),
        )
        .expect("rule recorded");

    assert!(
        store
            .try_lookup_rule("sqlite3", "5.1.7")
            .expect("lookup")
            .is_some()
    );
    let audit = store.recent_audit(Some("sqlite3"), 10).expect("audit");
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].entry.event, EVENT_ALLOW);
    assert_eq!(audit[0].entry.version.as_deref(), Some("5.1.7"));
}

// -- the engine on real storage ----------------------------------------------------------

/// A one-version packument, published long ago, with no install hooks.
fn packument(name: &str, version: &str, integrity: &str) -> Value {
    json!({
        "name": name,
        "dist-tags": { "latest": version },
        "versions": {
            version: {
                "name": name,
                "version": version,
                "dist": { "integrity": integrity, "tarball": "https://registry.npmjs.org/x.tgz" }
            }
        },
        "time": { version: "2020-01-01T00:00:00.000Z" }
    })
}

#[test]
fn the_engine_runs_against_the_sqlite_store_and_records_what_it_sees() {
    let store = store();
    let doc = packument("lodash", "4.17.21", HASH_A);

    let outcome = policy::evaluate(&doc, &store, &store, &PolicyConfig::default(), now())
        .expect("packument evaluates");
    assert_eq!(outcome.surviving_versions(), vec!["4.17.21".to_owned()]);
    assert!(outcome.blocked.is_empty(), "{:?}", outcome.blocked);

    let entry = store
        .ledger_entry("lodash", "4.17.21")
        .expect("ledger readable")
        .expect("the engine recorded the version it served");
    assert_eq!(entry.integrity.as_deref(), Some(HASH_A));
    assert_eq!(entry.times_seen, 1);

    // A second fetch of the same bytes is a match, not an alarm.
    let outcome = policy::evaluate(&doc, &store, &store, &PolicyConfig::default(), now())
        .expect("second evaluation");
    assert!(outcome.blocked.is_empty());
    assert_eq!(
        store
            .ledger_entry("lodash", "4.17.21")
            .expect("readable")
            .map(|entry| entry.times_seen),
        Some(2)
    );
}

#[test]
fn a_deny_rule_in_the_store_withholds_the_version() {
    let store = store();
    store
        .record_rule(
            &NewRule::deny("keyv", "5.0.0").with_reason("Shai-Hulud"),
            now(),
        )
        .expect("deny recorded");

    let outcome = policy::evaluate(
        &packument("keyv", "5.0.0", HASH_A),
        &store,
        &store,
        &PolicyConfig::default(),
        now(),
    )
    .expect("packument evaluates");
    assert!(outcome.surviving_versions().is_empty());
    assert_eq!(outcome.blocked.len(), 1);
    assert_eq!(outcome.blocked[0].reason, BlockReason::DenyRule);
    assert!(outcome.blocked[0].detail.contains("Shai-Hulud"));
}

#[test]
fn an_allow_rule_does_not_rescue_a_version_whose_integrity_changed() {
    let store = store();
    let first_seen = ts("2026-07-01T00:00:00Z");
    // The daemon saw 5.0.0 carrying hash A while it was quarantined.
    assert_eq!(
        store
            .try_observe("keyv", "5.0.0", Some(HASH_A), first_seen)
            .expect("first sight"),
        LedgerCheck::Unseen
    );
    // The operator approves the version — pinned to the hash upstream serves *now*, B.
    store
        .record_rule(
            &NewRule::allow("keyv", "5.0.0", HASH_B).with_reason("looks fine to me"),
            now(),
        )
        .expect("allow recorded");

    // Upstream now serves B for the same version number.
    let outcome = policy::evaluate(
        &packument("keyv", "5.0.0", HASH_B),
        &store,
        &store,
        &PolicyConfig::default(),
        now(),
    )
    .expect("packument evaluates");

    assert!(
        outcome.surviving_versions().is_empty(),
        "the ledger is step 0 — an allow rule cannot override it"
    );
    assert_eq!(outcome.blocked.len(), 1);
    assert_eq!(outcome.blocked[0].reason, BlockReason::IntegrityChanged);
    assert!(
        outcome.blocked[0].detail.contains("integrity ledger"),
        "the ledger, not the rule, made this call: {}",
        outcome.blocked[0].detail
    );

    // The rule really is in the store, and really does pin the hash upstream serves.
    let rule = store
        .try_lookup_rule("keyv", "5.0.0")
        .expect("lookup")
        .expect("rule present");
    assert_eq!(rule.rule.verdict, Verdict::Allow);
    assert_eq!(rule.rule.integrity.as_deref(), Some(HASH_B));

    // And the evidence is untouched.
    let entry = store
        .ledger_entry("keyv", "5.0.0")
        .expect("readable")
        .expect("entry present");
    assert_eq!(entry.integrity.as_deref(), Some(HASH_A));
    assert_eq!(entry.first_seen, first_seen);
    assert_eq!(entry.times_seen, 1);

    // The withheld version is auditable as a critical tamper event.
    store
        .record_blocks("keyv", &outcome.blocked, now())
        .expect("audit appended");
    let audit = store
        .recent_audit(Some("keyv"), 10)
        .expect("audit readable");
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].entry.event, EVENT_TAMPER);
    assert_eq!(audit[0].entry.severity, Severity::Critical);
}

#[test]
fn an_allow_rule_pinned_to_the_recorded_hash_still_serves_a_hooked_version() {
    let store = store();
    let doc = json!({
        "name": "sqlite3",
        "dist-tags": { "latest": "5.1.7" },
        "versions": {
            "5.1.7": {
                "name": "sqlite3",
                "version": "5.1.7",
                "scripts": { "install": "node-gyp rebuild" },
                "dist": { "integrity": HASH_A }
            }
        },
        "time": { "5.1.7": "2020-01-01T00:00:00.000Z" }
    });

    // Without a rule the install hook withholds it.
    let outcome =
        policy::evaluate(&doc, &store, &store, &PolicyConfig::default(), now()).expect("evaluates");
    assert_eq!(outcome.blocked.len(), 1);
    assert_eq!(outcome.blocked[0].reason, BlockReason::InstallScript);

    // Approve it, pinned to the integrity and the exact command.
    let meta = &doc["versions"]["5.1.7"];
    let scripts = ScriptSet::from_version(meta);
    store
        .record_rule_audited(
            &NewRule::allow("sqlite3", "5.1.7", HASH_A)
                .with_scripts(scripts.clone())
                .with_reason("native build"),
            now(),
        )
        .expect("rule recorded");

    let outcome =
        policy::evaluate(&doc, &store, &store, &PolicyConfig::default(), now()).expect("evaluates");
    assert_eq!(outcome.surviving_versions(), vec!["5.1.7".to_owned()]);
    assert!(outcome.blocked.is_empty());
    assert_eq!(
        store
            .try_lookup_rule("sqlite3", "5.1.7")
            .expect("lookup")
            .and_then(|stored| stored.rule.scripts_sha256),
        Some(scripts.sha256()),
        "the approval is bound to the exact command"
    );
}

// -- write amplification, retention and fail-closed reporting ----------------------------

/// The policy runs per request against the cached document, so the same verdict is produced
/// again on every retry. Only a *new* verdict is worth a row.
#[test]
fn a_repeated_verdict_is_not_appended_twice() {
    let store = store();
    let blocked = vec![BlockRecord::new(
        "0.21.5",
        BlockReason::InstallScript,
        "install hooks present — postinstall: node install.js",
    )];

    assert_eq!(
        store
            .record_blocks("esbuild", &blocked, now())
            .expect("appended"),
        1
    );
    for _ in 0..3 {
        assert_eq!(
            store
                .record_blocks("esbuild", &blocked, now())
                .expect("appended"),
            0,
            "the same verdict must not be appended again"
        );
    }
    assert_eq!(
        store.recent_audit(Some("esbuild"), 10).expect("read").len(),
        1
    );

    // The age gate rewrites its detail every hour; the reason is what identifies the verdict.
    let same_reason_new_detail = vec![BlockRecord::new(
        "0.21.5",
        BlockReason::InstallScript,
        "install hooks present — postinstall: node install.js (again)",
    )];
    assert_eq!(
        store
            .record_blocks("esbuild", &same_reason_new_detail, now())
            .expect("appended"),
        0
    );

    // A different gate is a different event and is recorded.
    let denied = vec![BlockRecord::new(
        "0.21.5",
        BlockReason::DenyRule,
        "denied by rule",
    )];
    assert_eq!(
        store
            .record_blocks("esbuild", &denied, now())
            .expect("appended"),
        1
    );
    assert_eq!(
        store.recent_audit(Some("esbuild"), 10).expect("read").len(),
        2
    );
}

#[test]
fn pruning_drops_audit_rows_older_than_the_cutoff() {
    let store = store();
    let old = ts("2026-01-01T00:00:00Z");
    let recent = ts("2026-08-01T00:00:00Z");
    store
        .append_audit(&AuditEntry::tamper("keyv", "6.0.0", "old event", old))
        .expect("appended");
    store
        .append_audit(&AuditEntry::tamper("keyv", "6.0.1", "recent event", recent))
        .expect("appended");

    let cutoff = ts("2026-07-01T00:00:00Z");
    assert_eq!(store.prune_audit(cutoff).expect("pruned"), 1);
    let rows = store.recent_audit(None, 10).expect("read");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].entry.detail, "recent event");
    assert_eq!(
        store.prune_audit(cutoff).expect("pruned"),
        0,
        "pruning again removes nothing"
    );
}

/// A cache hit re-runs the policy but must not re-write the ledger's bookkeeping.
#[test]
fn observing_without_the_bump_compares_but_does_not_write() {
    let store = store();
    let first = ts("2026-08-01T00:00:00Z");
    assert_eq!(
        store
            .try_observe("keyv", "5.0.0", Some(HASH_A), first)
            .expect("observed"),
        LedgerCheck::Unseen
    );

    let later = ts("2026-08-04T00:00:00Z");
    assert_eq!(
        store
            .try_observe_with("keyv", "5.0.0", Some(HASH_A), later, false)
            .expect("observed"),
        LedgerCheck::Match
    );
    let entry = store
        .ledger_entry("keyv", "5.0.0")
        .expect("read")
        .expect("recorded");
    assert_eq!(entry.times_seen, 1, "no bookkeeping write on a cache hit");
    assert_eq!(entry.last_seen, first);

    // A replacement is still caught without the bump.
    assert_eq!(
        store
            .try_observe_with("keyv", "5.0.0", Some(HASH_B), later, false)
            .expect("observed"),
        LedgerCheck::Changed {
            recorded: Some(HASH_A.to_owned())
        }
    );

    // A version never seen before is recorded even without the bump — DESIGN.md records every
    // version observed.
    assert_eq!(
        store
            .try_observe_with("keyv", "5.1.0", Some(HASH_B), later, false)
            .expect("observed"),
        LedgerCheck::Unseen
    );
    assert!(store.ledger_entry("keyv", "5.1.0").expect("read").is_some());
}

/// The trait methods are infallible by signature, so a broken database has to be reported some
/// other way: it fails closed **and** records the failure for the request path to surface.
#[test]
fn a_broken_rules_table_fails_closed_and_reports_the_failure() {
    let store = store();
    {
        let conn = store.lock();
        conn.execute_batch("DROP TABLE rules")
            .expect("drop the table");
    }
    store.clear_failure();

    let rule = RuleStore::lookup(&store, "esbuild", "0.21.5").expect("fails closed to a deny");
    assert_eq!(rule.verdict, Verdict::Deny);
    let failure = store.take_failure().expect("the failure was recorded");
    assert!(failure.contains("query failed"), "{failure}");
    assert!(
        store.take_failure().is_none(),
        "taking the failure clears it"
    );
}

#[test]
fn a_broken_seen_table_fails_closed_and_reports_the_failure() {
    let store = store();
    {
        let conn = store.lock();
        conn.execute_batch("DROP TABLE seen").expect("drop");
    }
    store.clear_failure();

    assert_eq!(
        IntegrityLedger::observe(&store, "esbuild", "0.21.5", Some(HASH_A), now()),
        LedgerCheck::Changed { recorded: None }
    );
    assert!(store.take_failure().is_some());
}

/// The policy engine hashes install-hook commands without depending on the store, so the two
/// implementations are pinned against each other here.
#[test]
fn the_policy_script_hash_matches_the_stores_script_set() {
    for meta in [
        json!({ "scripts": { "postinstall": "node install.js" } }),
        json!({ "scripts": { "install": "node-gyp rebuild", "preinstall": "echo hi", "test": "mocha" } }),
        json!({ "scripts": {} }),
        json!({}),
    ] {
        assert_eq!(
            ScriptSet::from_version(&meta).sha256(),
            policy::scripts_sha256(&meta),
            "hashes must agree for {meta}"
        );
    }
}

// -- the mismatch counter, the frozen evidence and the on-disk permissions ----------------

#[test]
fn a_mismatched_observation_freezes_the_hash_and_counts_the_attempt() {
    let store = store();
    assert_eq!(
        store
            .try_observe("keyv", "6.0.0", Some(HASH_A), now())
            .expect("observed"),
        LedgerCheck::Unseen
    );

    for expected in 1..=3u64 {
        let check = store
            .try_observe("keyv", "6.0.0", Some(HASH_B), now())
            .expect("observed");
        assert!(matches!(check, LedgerCheck::Changed { .. }));
        let entry = store
            .ledger_entry("keyv", "6.0.0")
            .expect("read")
            .expect("the version is on record");
        assert_eq!(
            entry.integrity.as_deref(),
            Some(HASH_A),
            "the first hash is the evidence and never moves"
        );
        assert_eq!(
            entry.mismatch_count, expected,
            "a repeated replacement attempt has to be visible"
        );
        assert_eq!(entry.last_mismatch, Some(now()));
        assert_eq!(entry.times_seen, 1, "a mismatch is not a confirmation");
    }

    // A cache-hit re-check takes the read-only path and must still count.
    let check = store
        .try_observe_with("keyv", "6.0.0", Some(HASH_B), now(), false)
        .expect("observed");
    assert!(matches!(check, LedgerCheck::Changed { .. }));
    assert_eq!(
        store
            .ledger_entry("keyv", "6.0.0")
            .expect("read")
            .expect("on record")
            .mismatch_count,
        4
    );

    // And a genuine re-confirmation of the recorded hash is still just a confirmation.
    store
        .try_observe("keyv", "6.0.0", Some(HASH_A), now())
        .expect("observed");
    let entry = store
        .ledger_entry("keyv", "6.0.0")
        .expect("read")
        .expect("on record");
    assert_eq!(entry.times_seen, 2);
    assert_eq!(entry.mismatch_count, 4);
}

#[test]
fn a_v1_database_gains_the_mismatch_columns_when_it_is_opened() {
    let temp = TempDir::new("migrate-v1");
    let path = temp.path.join("rules.db");
    fs::create_dir_all(&temp.path).expect("mkdir");

    // Exactly the v1 `seen` table, with a row in it.
    {
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE seen (
                 name          TEXT    NOT NULL,
                 version       TEXT    NOT NULL,
                 integrity     TEXT,
                 first_seen_ts INTEGER NOT NULL,
                 last_seen_ts  INTEGER NOT NULL,
                 times_seen    INTEGER NOT NULL,
                 PRIMARY KEY (name, version)
             );",
        )
        .expect("v1 schema");
        conn.execute(
            "INSERT INTO seen VALUES ('keyv', '6.0.0', 'sha512-OLD', 1, 1, 1)",
            [],
        )
        .expect("v1 row");
        conn.pragma_update(None, "user_version", 1_i64)
            .expect("v1 version");
    }

    let store = Store::open(&path).expect("a v1 database still opens");
    let entry = store
        .ledger_entry("keyv", "6.0.0")
        .expect("read")
        .expect("the v1 row survived");
    assert_eq!(entry.integrity.as_deref(), Some("sha512-OLD"));
    assert_eq!(entry.mismatch_count, 0);
    assert_eq!(entry.last_mismatch, None);

    // And the new bookkeeping works on the migrated row.
    let check = store
        .try_observe("keyv", "6.0.0", Some(HASH_B), now())
        .expect("observed");
    assert!(matches!(check, LedgerCheck::Changed { .. }));
    assert_eq!(
        store
            .ledger_entry("keyv", "6.0.0")
            .expect("read")
            .expect("on record")
            .mismatch_count,
        1
    );
}

#[test]
fn the_state_database_is_created_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let temp = TempDir::new("permissions");
    let path = temp.path.join("nested").join("rules.db");
    let store = Store::open(&path).expect("store opens");
    store
        .record_rule(&NewRule::deny("keyv", "6.0.0"), now())
        .expect("write something so the WAL exists");

    let mode = fs::metadata(&path)
        .expect("the database exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "database mode was {mode:04o}");

    let dir = path.parent().expect("parent");
    let dir_mode = fs::metadata(dir)
        .expect("the directory exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700, "directory mode was {dir_mode:04o}");

    // Anything that can read the WAL can read the rules it holds.
    let mut wal = path.clone().into_os_string();
    wal.push("-wal");
    let wal = PathBuf::from(wal);
    if wal.exists() {
        let wal_mode = fs::metadata(&wal).expect("wal").permissions().mode() & 0o777;
        assert_eq!(wal_mode & 0o077, 0, "wal mode was {wal_mode:04o}");
    }
}
