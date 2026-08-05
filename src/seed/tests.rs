//! Tests for `npmfilter seed` — DESIGN.md "Build order" step 5.
//!
//! Every test builds a real `node_modules` tree on disk and walks it. Nothing touches the
//! network, and every store used here is in-memory.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, TimeZone, Utc};
use serde_json::{Value, json};

use super::*;
use crate::policy::{self, BlockReason, PolicyConfig};
use crate::store::Store;

/// What the daemon does with a scan result: turn each pinnable candidate into a socket entry,
/// build its rule and record it. The real path runs the same [`seed_rule`] on the far side of
/// the control socket, with the verification verdict the daemon reached.
fn record(
    report: &mut SeedReport,
    store: &Store,
    verification: &SeedVerification,
    now: DateTime<Utc>,
) {
    let root = report.root.display().to_string();
    let mut written = 0usize;
    for candidate in &report.approved {
        let Some(entry) = candidate.entry() else {
            continue;
        };
        let rule = seed_rule(&entry, &root, verification, "uid=1000 via=seed", now);
        store
            .record_rule_audited(&rule, now)
            .expect("rule recorded");
        written += 1;
    }
    report.written = written;
}

/// The verdict the daemon reaches for a tree whose hashes it confirmed upstream.
fn verified() -> SeedVerification {
    SeedVerification::Verified {
        upstream: "https://registry.example.test".to_owned(),
    }
}

/// A temporary directory that removes itself.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("npmfilter-seed-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 4, 12, 0, 0)
        .single()
        .expect("valid timestamp")
}

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent");
    }
    fs::write(path, contents).expect("write file");
}

fn write_json(path: &Path, value: &Value) {
    write(
        path,
        &serde_json::to_string_pretty(value).expect("render json"),
    );
}

/// Install a package into `<root>/node_modules/<name>`.
fn install(root: &Path, name: &str, manifest: Value) -> PathBuf {
    let dir = root.join("node_modules").join(name);
    write_json(&dir.join("package.json"), &manifest);
    write(&dir.join("index.js"), "module.exports = 1;\n");
    dir
}

fn manifest(name: &str, version: &str, scripts: Value) -> Value {
    json!({ "name": name, "version": version, "scripts": scripts })
}

/// A project with two install-hook packages and one hookless one, plus npm's hidden lockfile.
fn sample_project(tag: &str) -> TempDir {
    let temp = TempDir::new(tag);
    let root = temp.path();

    install(
        root,
        "esbuild",
        manifest(
            "esbuild",
            "0.21.5",
            json!({ "postinstall": "node install.js" }),
        ),
    );
    install(
        root,
        "lodash",
        manifest("lodash", "4.17.21", json!({ "test": "echo ok" })),
    );
    let scoped = root.join("node_modules/@parcel/watcher");
    write_json(
        &scoped.join("package.json"),
        &manifest(
            "@parcel/watcher",
            "2.4.1",
            json!({ "install": "node-gyp-build" }),
        ),
    );
    write(&scoped.join("index.js"), "module.exports = 2;\n");

    write_json(
        &root.join("node_modules/.package-lock.json"),
        &json!({
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "node_modules/esbuild": {
                    "version": "0.21.5",
                    "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.21.5.tgz",
                    "integrity": "sha512-ESBUILD",
                    "hasInstallScript": true
                },
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "integrity": "sha512-LODASH"
                },
                "node_modules/@parcel/watcher": {
                    "version": "2.4.1",
                    "integrity": "sha512-WATCHER",
                    "hasInstallScript": true
                }
            }
        }),
    );
    temp
}

#[test]
fn seed_finds_only_the_install_hook_packages_and_pins_each_to_its_lockfile_integrity() {
    let temp = sample_project("hooks");
    let root = resolve_node_modules(temp.path()).expect("node_modules resolves");
    let report = scan(&root, now()).expect("scan succeeds");

    assert_eq!(report.packages_scanned, 3, "all three manifests were read");
    assert_eq!(report.unpinnable, Vec::new(), "everything is pinnable here");

    let names: Vec<&str> = report
        .approved
        .iter()
        .map(|candidate| candidate.name.as_str())
        .collect();
    assert_eq!(
        names,
        vec!["@parcel/watcher", "esbuild"],
        "lodash has no install hook"
    );

    let esbuild = report
        .approved
        .iter()
        .find(|candidate| candidate.name == "esbuild")
        .expect("esbuild is a candidate");
    assert_eq!(esbuild.version, "0.21.5");
    assert_eq!(esbuild.integrity.as_deref(), Some("sha512-ESBUILD"));
    assert_eq!(
        esbuild.integrity_source,
        Some(IntegritySource::HiddenLockfile)
    );
    assert_eq!(esbuild.key, "node_modules/esbuild");
    assert_eq!(
        esbuild.hook_lines(),
        vec!["postinstall: node install.js".to_owned()]
    );
    assert!(
        esbuild.tree_sha256.starts_with(TREE_HASH_PREFIX),
        "{}",
        esbuild.tree_sha256
    );

    let watcher = report
        .approved
        .iter()
        .find(|candidate| candidate.name == "@parcel/watcher")
        .expect("scoped packages are walked");
    assert_eq!(watcher.integrity.as_deref(), Some("sha512-WATCHER"));
    assert_eq!(watcher.key, "node_modules/@parcel/watcher");
}

#[test]
fn a_seeded_rule_admits_the_version_the_daemon_would_otherwise_withhold() {
    let temp = sample_project("admits");
    let root = resolve_node_modules(temp.path()).expect("node_modules resolves");
    let mut report = scan(&root, now()).expect("scan succeeds");

    let store = Store::open_in_memory().expect("in-memory store");
    record(&mut report, &store, &verified(), now());
    assert_eq!(report.written, 2);

    // The upstream packument the daemon would fetch: aged, but it runs a postinstall.
    let packument = json!({
        "name": "esbuild",
        "dist-tags": { "latest": "0.21.5" },
        "time": { "0.21.5": "2024-01-01T00:00:00.000Z" },
        "versions": {
            "0.21.5": {
                "name": "esbuild",
                "version": "0.21.5",
                "scripts": { "postinstall": "node install.js" },
                "dist": { "integrity": "sha512-ESBUILD" }
            }
        }
    });

    let outcome = policy::evaluate(&packument, &store, &store, &PolicyConfig::default(), now())
        .expect("policy runs");
    assert_eq!(
        outcome.surviving_versions(),
        vec!["0.21.5".to_owned()],
        "the seeded approval admits the install-script version: {:?}",
        outcome.blocked
    );
}

#[test]
fn a_rule_pinned_to_the_on_disk_tree_hash_would_block_the_version_instead() {
    // Why seeding pins to dist.integrity and not to the tree hash: gate 2 compares the rule's
    // pin against the version's upstream dist.integrity, and anything else withholds it.
    let temp = sample_project("wrong-pin");
    let root = resolve_node_modules(temp.path()).expect("node_modules resolves");
    let report = scan(&root, now()).expect("scan succeeds");
    let esbuild = report
        .approved
        .iter()
        .find(|candidate| candidate.name == "esbuild")
        .expect("esbuild is a candidate");

    let store = Store::open_in_memory().expect("in-memory store");
    let wrong = NewRule::allow("esbuild", "0.21.5", esbuild.tree_sha256.clone());
    store.record_rule(&wrong, now()).expect("rule recorded");

    let packument = json!({
        "name": "esbuild",
        "dist-tags": { "latest": "0.21.5" },
        "time": { "0.21.5": "2024-01-01T00:00:00.000Z" },
        "versions": {
            "0.21.5": {
                "name": "esbuild",
                "version": "0.21.5",
                "scripts": { "postinstall": "node install.js" },
                "dist": { "integrity": "sha512-ESBUILD" }
            }
        }
    });
    let outcome = policy::evaluate(&packument, &store, &store, &PolicyConfig::default(), now())
        .expect("policy runs");
    assert!(outcome.surviving_versions().is_empty());
    assert_eq!(outcome.blocked.len(), 1);
    assert_eq!(outcome.blocked[0].reason, BlockReason::IntegrityChanged);
}

#[test]
fn a_dry_run_writes_nothing() {
    let temp = sample_project("dry");
    let root = resolve_node_modules(temp.path()).expect("node_modules resolves");
    let mut report = scan(&root, now()).expect("scan succeeds");
    report.dry_run = true;

    let store = Store::open_in_memory().expect("in-memory store");
    assert_eq!(store.rule_counts().expect("counts"), (0, 0));
    assert_eq!(report.written, 0);

    let rendered = render(&report);
    assert!(
        rendered.contains("DRY RUN — nothing was written"),
        "{rendered}"
    );
    assert!(rendered.contains("esbuild@0.21.5"), "{rendered}");
    assert!(
        rendered.contains("postinstall: node install.js"),
        "the dry run lists the exact command it would approve: {rendered}"
    );
    assert!(rendered.contains("sha512-ESBUILD"), "{rendered}");
    assert_eq!(
        store.rule_counts().expect("counts"),
        (0, 0),
        "a dry run must not have written a rule"
    );
}

#[test]
fn the_report_always_warns_that_seeding_trusts_the_working_state() {
    let temp = sample_project("warn");
    let root = resolve_node_modules(temp.path()).expect("node_modules resolves");
    let report = scan(&root, now()).expect("scan succeeds");
    let rendered = render(&report);

    assert!(
        rendered.contains("WARNING — seeding trusts the CURRENT WORKING STATE"),
        "{rendered}"
    );
    assert!(
        rendered.contains("seeding trusts the current state"),
        "{rendered}"
    );
    assert!(
        rendered.contains("On-disk tree hash"),
        "the report states precisely what is hashed: {rendered}"
    );
    assert!(
        !rendered.contains("OFFLINE"),
        "an online seed does not print the offline warning: {rendered}"
    );
}

#[test]
fn an_offline_seed_says_loudly_that_nothing_was_checked() {
    let temp = sample_project("offline-warning");
    let root = resolve_node_modules(temp.path()).expect("node_modules resolves");
    let mut report = scan(&root, now()).expect("scan succeeds");
    report.offline = true;
    let rendered = render(&report);

    assert!(
        rendered.contains("!! OFFLINE — NOTHING BELOW WAS CHECKED AGAINST THE REGISTRY !!"),
        "{rendered}"
    );
    assert!(rendered.contains("--offline skips"), "{rendered}");
}

#[test]
fn an_unverified_rule_records_the_reduced_assurance_in_its_reason() {
    let temp = sample_project("offline-reason");
    let root = resolve_node_modules(temp.path()).expect("node_modules resolves");
    let mut report = scan(&root, now()).expect("scan succeeds");

    let store = Store::open_in_memory().expect("in-memory store");
    record(
        &mut report,
        &store,
        &SeedVerification::Unverified {
            upstream: "https://registry.example.test".to_owned(),
        },
        now(),
    );

    let stored = store
        .try_lookup_rule("esbuild", "0.21.5")
        .expect("lookup")
        .expect("rule exists");
    let reason = stored.rule.reason.as_deref().unwrap_or_default();
    assert!(reason.contains("NOT VERIFIED (--offline)"), "{reason}");
    assert!(reason.contains("Reduced assurance"), "{reason}");
}

#[test]
fn the_help_text_states_exactly_what_is_hashed() {
    let help = seed_long_about();
    assert!(help.contains("On-disk tree hash"), "{help}");
    assert!(help.contains("sha256-hex"), "{help}");
    assert!(help.contains("node_modules/"), "{help}");
    assert!(help.contains("sorted by the raw bytes"), "{help}");
    assert!(help.contains("--dry-run"), "{help}");
    assert!(help.contains("dist.integrity"), "{help}");
}

#[test]
fn a_package_with_no_integrity_on_disk_is_reported_and_never_written() {
    let temp = TempDir::new("unpinnable");
    let root = temp.path();
    install(
        root,
        "local-tool",
        manifest(
            "local-tool",
            "0.0.0",
            json!({ "preinstall": "node build.js" }),
        ),
    );

    let node_modules = resolve_node_modules(root).expect("node_modules resolves");
    let mut report = scan(&node_modules, now()).expect("scan succeeds");
    assert!(report.approved.is_empty());
    assert_eq!(report.unpinnable.len(), 1);
    assert_eq!(report.unpinnable[0].name, "local-tool");
    assert!(report.unpinnable[0].integrity.is_none());

    let store = Store::open_in_memory().expect("in-memory store");
    record(&mut report, &store, &verified(), now());
    assert_eq!(report.written, 0);
    assert_eq!(store.rule_counts().expect("counts"), (0, 0));

    let rendered = render(&report);
    assert!(rendered.contains("CANNOT PIN (1)"), "{rendered}");
    assert!(rendered.contains("npmfilter_inspect"), "{rendered}");
}

#[test]
fn the_integrity_field_npm6_left_in_package_json_is_used_as_a_fallback() {
    let temp = TempDir::new("underscore-integrity");
    let root = temp.path();
    install(
        root,
        "node-sass",
        json!({
            "name": "node-sass",
            "version": "4.14.1",
            "scripts": { "install": "node scripts/install.js" },
            "_integrity": "sha512-NODESASS",
            "_resolved": "https://registry.npmjs.org/node-sass/-/node-sass-4.14.1.tgz"
        }),
    );

    let node_modules = resolve_node_modules(root).expect("node_modules resolves");
    let report = scan(&node_modules, now()).expect("scan succeeds");
    assert_eq!(report.approved.len(), 1);
    assert_eq!(
        report.approved[0].integrity.as_deref(),
        Some("sha512-NODESASS")
    );
    assert_eq!(
        report.approved[0].integrity_source,
        Some(IntegritySource::PackageJsonField)
    );
    assert_eq!(
        report.approved[0].resolved.as_deref(),
        Some("https://registry.npmjs.org/node-sass/-/node-sass-4.14.1.tgz")
    );
}

/// A `package.json` is untrusted input. npm materialises a git dependency as a real directory
/// whose manifest can declare any name and version it likes, and whose lockfile entry carries a
/// `resolved` but no `integrity`. Without the path check that directory mints an allow rule for
/// a package it is not, pinned to the real package's hash.
#[test]
fn a_directory_that_claims_another_packages_name_is_refused() {
    let temp = TempDir::new("spoof");
    let root = temp.path();

    // A git dependency installed at node_modules/handy, claiming to be esbuild@0.25.9.
    install(
        root,
        "handy",
        json!({
            "name": "esbuild",
            "version": "0.25.9",
            "scripts": { "postinstall": "node steal.js" }
        }),
    );
    // The real esbuild is in the same lockfile, with its real hash.
    write_json(
        &root.join("node_modules/.package-lock.json"),
        &json!({
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "node_modules/handy": {
                    "version": "1.0.0",
                    "resolved": "git+ssh://git@example.test/handy.git#deadbeef"
                },
                "node_modules/esbuild": {
                    "version": "0.25.9",
                    "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.25.9.tgz",
                    "integrity": "sha512-REAL-ESBUILD"
                }
            }
        }),
    );

    let node_modules = resolve_node_modules(root).expect("node_modules resolves");
    let report = scan(&node_modules, now()).expect("scan succeeds");

    assert!(
        report.approved.is_empty(),
        "no rule may be minted from a spoofed manifest: {:?}",
        report.approved
    );
    assert!(report.unpinnable.is_empty());
    assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
    assert!(
        report.warnings[0].contains("node_modules/handy")
            && report.warnings[0].contains("esbuild"),
        "{}",
        report.warnings[0]
    );
}

/// The mirror of the same defect: the directory really is the package, but the lockfile entry
/// for it has no integrity (a git or `file:` install), so the `(name, version)` index must not
/// be consulted — pinning to some other entry's hash would withhold the legitimate version and
/// raise a critical tamper event on it forever.
#[test]
fn a_directory_the_lockfile_records_without_an_integrity_is_never_pinned_from_elsewhere() {
    let temp = TempDir::new("no-integrity-at-path");
    let root = temp.path();
    install(
        root,
        "esbuild",
        manifest(
            "esbuild",
            "0.25.9",
            json!({ "postinstall": "node install.js" }),
        ),
    );
    write_json(
        &root.join("node_modules/.package-lock.json"),
        &json!({
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "node_modules/esbuild": {
                    "version": "0.25.9",
                    "resolved": "git+ssh://git@example.test/esbuild.git#deadbeef"
                }
            }
        }),
    );
    // A second lockfile knows the registry hash for that (name, version).
    write_json(
        &root.join("package-lock.json"),
        &json!({
            "name": "app",
            "lockfileVersion": 1,
            "dependencies": {
                "esbuild": {
                    "version": "0.25.9",
                    "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.25.9.tgz",
                    "integrity": "sha512-REAL-ESBUILD"
                }
            }
        }),
    );

    let node_modules = resolve_node_modules(root).expect("node_modules resolves");
    let report = scan(&node_modules, now()).expect("scan succeeds");
    assert!(report.approved.is_empty(), "{:?}", report.approved);
    assert_eq!(report.unpinnable.len(), 1);
    assert_eq!(report.unpinnable[0].name, "esbuild");
    assert!(report.unpinnable[0].integrity.is_none());
}

/// A manifest whose version disagrees with what the lockfile recorded for that exact directory
/// cannot be pinned either: the rule would name a version these bytes are not.
#[test]
fn a_manifest_version_that_contradicts_the_lockfile_is_refused() {
    let temp = TempDir::new("version-mismatch");
    let root = temp.path();
    install(
        root,
        "esbuild",
        manifest(
            "esbuild",
            "0.25.9",
            json!({ "postinstall": "node install.js" }),
        ),
    );
    write_json(
        &root.join("node_modules/.package-lock.json"),
        &json!({
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "node_modules/esbuild": {
                    "version": "0.21.5",
                    "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.21.5.tgz",
                    "integrity": "sha512-ESBUILD-0215"
                }
            }
        }),
    );

    let node_modules = resolve_node_modules(root).expect("node_modules resolves");
    let report = scan(&node_modules, now()).expect("scan succeeds");
    assert!(report.approved.is_empty(), "{:?}", report.approved);
    assert_eq!(report.warnings.len(), 1, "{:?}", report.warnings);
    assert!(report.warnings[0].contains("0.21.5"), "{}", report.warnings[0]);
}

#[test]
fn a_v1_lockfile_dependencies_tree_is_indexed_by_name_and_version() {
    let temp = TempDir::new("v1-lock");
    let root = temp.path();
    install(
        root,
        "sqlite3",
        manifest("sqlite3", "5.1.7", json!({ "install": "node-gyp rebuild" })),
    );
    write_json(
        &root.join("package-lock.json"),
        &json!({
            "name": "app",
            "lockfileVersion": 1,
            "dependencies": {
                "sqlite3": {
                    "version": "5.1.7",
                    "resolved": "https://registry.npmjs.org/sqlite3/-/sqlite3-5.1.7.tgz",
                    "integrity": "sha512-SQLITE3"
                }
            }
        }),
    );

    let node_modules = resolve_node_modules(root).expect("node_modules resolves");
    let report = scan(&node_modules, now()).expect("scan succeeds");
    assert_eq!(report.approved.len(), 1);
    assert_eq!(
        report.approved[0].integrity.as_deref(),
        Some("sha512-SQLITE3")
    );
    assert_eq!(
        report.approved[0].integrity_source,
        Some(IntegritySource::Lockfile)
    );
    assert_eq!(report.integrity_sources.len(), 1);
}

#[test]
fn nested_node_modules_are_walked_and_deduplicated() {
    let temp = TempDir::new("nested");
    let root = temp.path();
    install(
        root,
        "outer",
        manifest("outer", "1.0.0", json!({ "postinstall": "node a.js" })),
    );
    let nested = root.join("node_modules/outer/node_modules/inner");
    write_json(
        &nested.join("package.json"),
        &manifest("inner", "2.0.0", json!({ "preinstall": "node b.js" })),
    );
    write(&nested.join("index.js"), "1\n");
    // A second, identical copy of `inner` elsewhere in the tree.
    let second = root.join("node_modules/other/node_modules/inner");
    write_json(
        &second.join("package.json"),
        &manifest("inner", "2.0.0", json!({ "preinstall": "node b.js" })),
    );
    write(&second.join("index.js"), "1\n");
    write_json(
        &root.join("node_modules/other/package.json"),
        &manifest("other", "1.0.0", json!({})),
    );

    let node_modules = resolve_node_modules(root).expect("node_modules resolves");
    let report = scan(&node_modules, now()).expect("scan succeeds");
    let inner = report
        .unpinnable
        .iter()
        .find(|candidate| candidate.name == "inner")
        .expect("inner was found");
    assert_eq!(inner.copies, 2, "both copies were counted once");
    assert_eq!(
        report.unpinnable.len(),
        2,
        "outer and inner, both unpinnable"
    );
}

#[test]
fn a_symlinked_dependency_is_not_walked_twice() {
    let temp = TempDir::new("symlink");
    let root = temp.path();
    let real = install(
        root,
        "real",
        manifest("real", "1.0.0", json!({ "install": "node x.js" })),
    );
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real, root.join("node_modules/link")).expect("symlink");
    #[cfg(not(unix))]
    let _ = &real;

    let node_modules = resolve_node_modules(root).expect("node_modules resolves");
    let report = scan(&node_modules, now()).expect("scan succeeds");
    assert_eq!(report.packages_scanned, 1);
    assert_eq!(report.unpinnable.len(), 1);
    assert_eq!(report.unpinnable[0].copies, 1);
}

#[test]
fn resolve_node_modules_accepts_a_project_root_or_the_directory_itself() {
    let temp = sample_project("resolve");
    let direct = temp.path().join("node_modules");
    assert_eq!(
        resolve_node_modules(temp.path()).expect("project root"),
        direct
    );
    assert_eq!(
        resolve_node_modules(&direct).expect("directory itself"),
        direct
    );

    let missing = temp.path().join("nowhere");
    let error = resolve_node_modules(&missing).expect_err("missing tree is an error");
    assert!(
        matches!(error, SeedError::NoNodeModules { .. }),
        "{error:?}"
    );
}

// -- the on-disk tree hash ------------------------------------------------------------------

#[test]
fn the_tree_hash_is_stable_and_covers_contents_paths_and_the_exec_bit() {
    let temp = TempDir::new("tree-hash");
    let package = temp.path().join("pkg");
    write(&package.join("package.json"), "{\"name\":\"p\"}");
    write(&package.join("lib/index.js"), "module.exports = 1;\n");

    let first = tree_sha256(&package).expect("hash");
    let second = tree_sha256(&package).expect("hash again");
    assert_eq!(first, second, "the hash is stable across runs");
    assert!(first.starts_with(TREE_HASH_PREFIX), "{first}");
    assert_eq!(first.len(), TREE_HASH_PREFIX.len() + 64, "{first}");

    // A changed byte changes the hash.
    write(&package.join("lib/index.js"), "module.exports = 2;\n");
    assert_ne!(tree_sha256(&package).expect("hash"), first);

    // A renamed file changes the hash even with identical contents.
    write(&package.join("lib/index.js"), "module.exports = 1;\n");
    assert_eq!(tree_sha256(&package).expect("hash"), first);
    fs::rename(package.join("lib/index.js"), package.join("lib/main.js")).expect("rename");
    assert_ne!(tree_sha256(&package).expect("hash"), first);
}

#[cfg(unix)]
#[test]
fn the_tree_hash_notices_the_execute_bit() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new("exec-bit");
    let package = temp.path().join("pkg");
    let script = package.join("bin/run.sh");
    write(&script, "#!/bin/sh\necho hi\n");

    let plain = tree_sha256(&package).expect("hash");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
    let executable = tree_sha256(&package).expect("hash");
    assert_ne!(plain, executable, "the exec bit is part of the manifest");
}

#[test]
fn the_tree_hash_ignores_nested_node_modules_and_empty_directories() {
    let temp = TempDir::new("tree-excludes");
    let package = temp.path().join("pkg");
    write(&package.join("index.js"), "1\n");
    let base = tree_sha256(&package).expect("hash");

    // A nested dependency does not change the package's own hash.
    write(
        &package.join("node_modules/dep/package.json"),
        "{\"name\":\"dep\"}",
    );
    assert_eq!(tree_sha256(&package).expect("hash"), base);

    // Neither does an empty directory.
    fs::create_dir_all(package.join("empty")).expect("mkdir");
    assert_eq!(tree_sha256(&package).expect("hash"), base);
}

#[test]
fn the_recorded_reason_carries_the_whole_provenance_of_the_approval() {
    let temp = sample_project("reason");
    let root = resolve_node_modules(temp.path()).expect("node_modules resolves");
    let mut report = scan(&root, now()).expect("scan succeeds");

    let store = Store::open_in_memory().expect("in-memory store");
    record(&mut report, &store, &verified(), now());

    let stored = store
        .try_lookup_rule("esbuild", "0.21.5")
        .expect("lookup")
        .expect("rule exists");
    let reason = stored.rule.reason.as_deref().unwrap_or_default();
    assert!(reason.contains("seeded from"), "{reason}");
    assert!(
        reason.contains("node_modules/.package-lock.json"),
        "{reason}"
    );
    assert!(reason.contains(TREE_HASH_PREFIX), "{reason}");
    assert!(reason.contains("node_modules/esbuild"), "{reason}");
    assert_eq!(stored.rule.actor.as_deref(), Some("uid=1000 via=seed"));
    assert!(
        reason.contains("VERIFIED against https://registry.example.test"),
        "a seeded rule records whether the registry confirmed its pin: {reason}"
    );
    assert_eq!(
        stored.scripts_json.as_deref(),
        Some("{\"postinstall\":\"node install.js\"}"),
        "the approval is bound to the exact command"
    );
    assert!(stored.rule.scripts_sha256.is_some());
}

#[test]
fn seeding_writes_one_audit_row_per_approval() {
    let temp = sample_project("audit");
    let root = resolve_node_modules(temp.path()).expect("node_modules resolves");
    let mut report = scan(&root, now()).expect("scan succeeds");

    let store = Store::open_in_memory().expect("in-memory store");
    record(&mut report, &store, &verified(), now());

    let audit = store.recent_audit(None, 100).expect("audit read");
    assert_eq!(audit.len(), 2);
    assert!(audit.iter().all(|record| record.entry.event == "allow"));
}

#[test]
fn an_unreadable_lockfile_is_reported_rather_than_stopping_the_seed() {
    let temp = TempDir::new("bad-lock");
    let root = temp.path();
    install(
        root,
        "tool",
        manifest("tool", "1.0.0", json!({ "install": "node x.js" })),
    );
    write(&root.join("node_modules/.package-lock.json"), "{ not json");

    let node_modules = resolve_node_modules(root).expect("node_modules resolves");
    let report = scan(&node_modules, now()).expect("scan still succeeds");
    assert_eq!(report.unpinnable.len(), 1);
    assert_eq!(report.warnings.len(), 1);
    assert!(
        report.warnings[0].contains("not valid JSON"),
        "{:?}",
        report.warnings
    );
    assert!(render(&report).contains("SKIPPED (1)"));
}
