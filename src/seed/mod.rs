//! `npmfilter seed` — DESIGN.md "Build order" step 5.
//!
//! Walks an installed `node_modules` tree, finds every package whose `package.json` declares
//! `preinstall` / `install` / `postinstall`, and records an allow rule for each one. Without
//! this the first install after adoption blocks on `esbuild`, `sqlite3`, `better-sqlite3`,
//! `lightningcss`, `@parcel/watcher` and every other install-hook package already in use.
//!
//! # Who does what
//!
//! `seed` is split across the socket. The **client** walks the tree, because the daemon runs
//! as its own user under `ProtectHome=yes` and cannot read anybody's `node_modules`. The
//! **daemon** verifies and writes, because it is the only process that opens the state
//! database. The client never records a rule.
//!
//! # What an allow rule is pinned to
//!
//! DESIGN.md "Policy engine" gate 2 admits a version only while the rule's pinned sha512 still
//! equals the version's upstream `dist.integrity`; a rule pinned to any other value **withholds
//! the version and raises a critical tamper event**. A seeded rule must therefore carry the real
//! `dist.integrity`, and this module reads it from disk:
//!
//! 1. `node_modules/.package-lock.json` — npm's hidden lockfile, written on every install and
//!    describing exactly the tree that is on disk;
//! 2. the project's `package-lock.json`, then `npm-shrinkwrap.json`;
//! 3. the `_integrity` field npm 6 wrote into the installed `package.json`.
//!
//! A package for which none of those yields a hash is **reported and skipped** — writing a rule
//! pinned to anything else would block the package instead of approving it.
//!
//! A lockfile is exactly as trustworthy as the tree it describes, which is the thing being
//! vetted, so the daemon does not take its word for anything: before it writes a rule it
//! fetches the packument for that `(name, version)` and confirms the hash **and** the
//! install-hook commands are the ones the registry actually serves. An entry that disagrees is
//! refused and reported, and the refusal is audited. `--offline` skips that check; it prints a
//! prominent warning and the reduced assurance is recorded in every rule's reason.
//!
//! # The on-disk tree hash
//!
//! Independently of the pin, every candidate gets a reproducible hash of what is actually on
//! disk, recorded in the rule's `reason` and printed in the report. Its definition is
//! [`TREE_HASH_SPEC`] and it is quoted verbatim in `npmfilter seed --help`.

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::Config;
use crate::control::client::{ControlClient, send_blocking};
use crate::control::protocol::{
    Answer, MAX_SEED_ENTRIES, Request, SeedArgs, SeedEntry, SeedResult,
};
use crate::control::{ClientError, LABEL_SEED};
use crate::store::{NewRule, ScriptSet, StoreError, hex_encode};

/// Prefix of the on-disk tree hash, so it can never be mistaken for an SRI `sha512-…` value.
pub const TREE_HASH_PREFIX: &str = "sha256:";

/// How deep the walker will descend before giving up. Nested `node_modules` chains are
/// normally two or three deep; this only exists so a pathological tree cannot spin forever.
const MAX_DEPTH: usize = 32;

/// Read buffer used when hashing package files.
const HASH_CHUNK: usize = 64 * 1024;

/// Exactly what the on-disk tree hash covers. Quoted verbatim by `npmfilter seed --help`.
pub const TREE_HASH_SPEC: &str = "\
On-disk tree hash — `sha256:<hex>` over a canonical manifest of the unpacked package
directory. The manifest is built as follows, and nothing else enters it:

  * every regular file and symlink under the package directory is an entry, EXCEPT
    anything under a nested `node_modules/` directory at any depth (those are separate
    packages and are hashed on their own);
  * directories are not entries, so empty directories do not affect the hash;
  * entry paths are relative to the package directory, `/`-separated, and the entries are
    sorted by the raw bytes of that path;
  * each entry is one line:  <sha256-hex> <SP> <kind> <SP> <length> <SP> <path> <LF>
      - kind `f` = regular file, `x` = regular file with the owner-execute bit set,
        `l` = symlink;
      - for `f`/`x` the sha256 and the length are those of the file contents;
      - for `l` they are those of the link target string, which is never followed;
  * the manifest is hashed with sha256 and rendered as lowercase hex.

Timestamps, ownership, inode order and directory entries are deliberately excluded, so the
same package contents always hash to the same value on any machine.";

/// The warning `seed` always prints. Seeding trusts this tree's CHOICE of versions.
pub const SEED_WARNING: &str = "\
WARNING — seeding trusts the CURRENT WORKING STATE of this tree.
The daemon confirms that each hash below is the one the registry serves for that exact
version, so a tampered lockfile cannot mint an approval. What it cannot tell you is whether
those versions were the right ones to install: if this tree was resolved from a compromised
lockfile, the packages are genuine registry artefacts of genuinely compromised versions, and
seeding approves them. Read the list before seeding, and only seed a tree you installed from
a lockfile you trust. (DESIGN.md \"Known limitations\": seeding trusts the current state.)";

/// The extra warning `--offline` prints. Skipping verification is a deliberate downgrade.
pub const SEED_OFFLINE_WARNING: &str = "\
!! OFFLINE — NOTHING BELOW WAS CHECKED AGAINST THE REGISTRY !!
--offline skips the upstream verification entirely. Every rule is pinned to a hash read out
of a lockfile on disk, and a lockfile is exactly as trustworthy as the tree it describes —
which is the thing being vetted. Anything that could edit that file before this ran chose
what gets approved. Every rule written this way records the reduced assurance in its reason.
Re-run without --offline as soon as the machine is online.";

/// Head of `npmfilter seed --help`; [`seed_long_about`] splices [`TREE_HASH_SPEC`] into it.
pub const SEED_LONG_ABOUT_HEAD: &str = "\
Pre-approve the install-script packages already present in a node_modules tree.

Every installed package whose package.json declares preinstall/install/postinstall gets an
allow rule pinned to its upstream dist.integrity (sha512) and to the sha256 of its exact
install-hook commands. The integrity is read from disk — from node_modules/.package-lock.json,
then package-lock.json, then npm-shrinkwrap.json, then the _integrity field of the installed
package.json. A package for which no dist.integrity can be found on disk is listed and SKIPPED:
an allow rule pinned to anything else would withhold the version rather than approve it
(DESIGN.md \"Policy engine\" gate 2).

The rules themselves are written by the daemon, not by this command: the candidates are sent
over the control socket, and before it records anything the daemon fetches the packument for
each (name, version) and confirms that the hash AND the install-hook commands are the ones the
registry actually serves. Entries that disagree are refused and reported. --offline skips that
verification; it is a deliberate downgrade and is recorded in every rule it writes.

Independently of that pin, each package also gets a reproducible hash of what is on disk,
recorded in the rule's reason and printed in the report:
";

/// Tail of `npmfilter seed --help`.
pub const SEED_LONG_ABOUT_TAIL: &str = "\
Seeding approves the current working state — see the warning the command prints on every run.
Use --dry-run first: it lists exactly what would be approved and has the daemon verify every
entry, but writes nothing at all.

The daemon must be running; this command never writes the state database itself.";

/// The full `--help` text for `seed`, hashing contract included.
pub fn seed_long_about() -> String {
    format!("{SEED_LONG_ABOUT_HEAD}\n{TREE_HASH_SPEC}\n\n{SEED_LONG_ABOUT_TAIL}")
}

/// Anything that can stop a seed run.
#[derive(Debug, Error)]
pub enum SeedError {
    #[error(
        "no node_modules directory at {path} — expected {path}/node_modules, or {path} itself to be one"
    )]
    NoNodeModules { path: PathBuf },
    #[error("failed to read {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to record a seeded rule")]
    Store(#[from] StoreError),
    #[error(
        "this tree holds {count} install-hook packages, more than the {MAX_SEED_ENTRIES} one \
         seed request may carry; seed its workspaces one at a time"
    )]
    TooManyEntries { count: usize },
    #[error("could not reach the npmfilter daemon to record the seeded rules")]
    Control(#[from] ClientError),
}

/// Where a package's `dist.integrity` was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegritySource {
    /// `node_modules/.package-lock.json` — npm's hidden lockfile.
    HiddenLockfile,
    /// The project's `package-lock.json`.
    Lockfile,
    /// The project's `npm-shrinkwrap.json`.
    Shrinkwrap,
    /// The `_integrity` field npm 6 wrote into the installed `package.json`.
    PackageJsonField,
}

impl IntegritySource {
    /// A short label for the report.
    pub fn as_str(self) -> &'static str {
        match self {
            IntegritySource::HiddenLockfile => "node_modules/.package-lock.json",
            IntegritySource::Lockfile => "package-lock.json",
            IntegritySource::Shrinkwrap => "npm-shrinkwrap.json",
            IntegritySource::PackageJsonField => "package.json _integrity",
        }
    }
}

impl std::fmt::Display for IntegritySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One installed package that declares install hooks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedCandidate {
    /// Package name as declared by the installed `package.json`.
    pub name: String,
    /// Installed version.
    pub version: String,
    /// The directory the package was read from.
    pub directory: PathBuf,
    /// That directory relative to the project root, `/`-separated — the lockfile's own key.
    pub key: String,
    /// The `preinstall` / `install` / `postinstall` commands, exactly as declared.
    pub scripts: ScriptSet,
    /// The upstream `dist.integrity`, when it could be found on disk.
    pub integrity: Option<String>,
    /// Where that hash came from.
    pub integrity_source: Option<IntegritySource>,
    /// The tarball URL recorded on disk, when known.
    pub resolved: Option<String>,
    /// The on-disk tree hash — see [`TREE_HASH_SPEC`].
    pub tree_sha256: String,
    /// How many copies of this exact `(name, version)` the tree holds.
    pub copies: usize,
}

impl SeedCandidate {
    /// Whether an allow rule can be pinned for this package.
    pub fn is_pinnable(&self) -> bool {
        self.integrity.is_some()
    }

    /// The install hooks rendered as `hook: command` pairs, in lifecycle order.
    pub fn hook_lines(&self) -> Vec<String> {
        crate::policy::INSTALL_HOOKS
            .iter()
            .filter_map(|hook| {
                self.scripts
                    .hooks()
                    .get(*hook)
                    .map(|command| format!("{hook}: {command}"))
            })
            .collect()
    }

    /// The `reason` recorded on the rule — the whole provenance of the approval, in one string.
    pub fn reason(&self, root: &Path, now: DateTime<Utc>) -> String {
        format!(
            "seeded from {} at {}; dist.integrity read from {}; on-disk tree {} ({})",
            root.display(),
            now.to_rfc3339(),
            self.integrity_source
                .map(IntegritySource::as_str)
                .unwrap_or("<unknown>"),
            self.tree_sha256,
            self.key,
        )
    }

    /// What this candidate looks like on the control socket, or `None` when it cannot be
    /// pinned.
    pub fn entry(&self) -> Option<SeedEntry> {
        let integrity = self.integrity.as_ref()?;
        Some(SeedEntry {
            name: self.name.clone(),
            version: self.version.clone(),
            integrity: integrity.clone(),
            integrity_source: self
                .integrity_source
                .map(IntegritySource::as_str)
                .unwrap_or("<unknown>")
                .to_owned(),
            key: self.key.clone(),
            tree_sha256: self.tree_sha256.clone(),
            hooks: self.scripts.hooks().clone(),
        })
    }
}

/// Whether the daemon confirmed a seed entry against the registry before approving it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedVerification {
    /// The hash and the install-hook commands match what upstream serves.
    Verified {
        /// The registry that was asked.
        upstream: String,
    },
    /// `--offline`: nothing was checked.
    Unverified {
        /// The registry that was *not* asked.
        upstream: String,
    },
}

impl SeedVerification {
    /// The phrase recorded in a rule's reason and shown in the report.
    pub fn detail(&self) -> String {
        match self {
            SeedVerification::Verified { upstream } => {
                format!(
                    "VERIFIED against {upstream}: the registry serves this exact hash and these exact install hooks for this version"
                )
            }
            SeedVerification::Unverified { upstream } => format!(
                "NOT VERIFIED (--offline): the pinned dist.integrity was read from a lockfile on \
                 disk and was never checked against {upstream}. Reduced assurance — re-seed \
                 online to confirm it"
            ),
        }
    }
}

/// The rule the daemon records for one verified (or deliberately unverified) seed entry.
///
/// Pure, so the exact provenance a seeded approval carries is a unit-testable fact rather
/// than something buried in the socket handler.
pub fn seed_rule(
    entry: &SeedEntry,
    root: &str,
    verification: &SeedVerification,
    actor: &str,
    now: DateTime<Utc>,
) -> NewRule {
    let reason = format!(
        "seeded from {root} at {}; dist.integrity read from {}; {}; on-disk tree {} ({})",
        now.to_rfc3339(),
        entry.integrity_source,
        verification.detail(),
        entry.tree_sha256,
        entry.key,
    );
    NewRule::allow(&entry.name, &entry.version, &entry.integrity)
        .with_scripts(ScriptSet::from_hooks(entry.hooks.clone()))
        .with_reason(reason)
        .with_actor(actor)
}

/// What one seed run found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedReport {
    /// The `node_modules` directory that was walked.
    pub root: PathBuf,
    /// The project root — `root`'s parent, where the lockfiles live.
    pub project: PathBuf,
    /// When the scan ran.
    pub scanned_at: DateTime<Utc>,
    /// How many installed packages carried a readable `package.json`.
    pub packages_scanned: usize,
    /// Install-hook packages that can be pinned, sorted by name then version.
    pub approved: Vec<SeedCandidate>,
    /// Install-hook packages with no `dist.integrity` on disk. No rule is written for these.
    pub unpinnable: Vec<SeedCandidate>,
    /// Which lockfiles were actually read.
    pub integrity_sources: Vec<PathBuf>,
    /// Anything skipped or unreadable, in the order it was hit.
    pub warnings: Vec<String>,
    /// Whether this run wrote anything.
    pub dry_run: bool,
    /// Whether upstream verification was skipped.
    pub offline: bool,
    /// How many rules were recorded (always 0 for a dry run).
    pub written: usize,
}

impl SeedReport {
    /// Every install-hook package found, pinnable or not.
    pub fn candidates(&self) -> usize {
        self.approved.len() + self.unpinnable.len()
    }
}

/// Resolve the `node_modules` directory to walk.
///
/// Accepts either the directory itself or a project root that contains one.
pub fn resolve_node_modules(path: &Path) -> Result<PathBuf, SeedError> {
    if path.file_name() == Some(OsStr::new("node_modules")) && path.is_dir() {
        return Ok(path.to_path_buf());
    }
    let nested = path.join("node_modules");
    if nested.is_dir() {
        return Ok(nested);
    }
    Err(SeedError::NoNodeModules {
        path: path.to_path_buf(),
    })
}

/// Walk `root` and describe every install-hook package in it. Reads the filesystem only.
pub fn scan(root: &Path, now: DateTime<Utc>) -> Result<SeedReport, SeedError> {
    let project = root
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let mut warnings = Vec::new();
    let index = IntegrityIndex::load(root, &project, &mut warnings);

    let mut found: BTreeMap<(String, String), SeedCandidate> = BTreeMap::new();
    let mut scanned = 0usize;
    walk_node_modules(
        root,
        &project,
        &index,
        &mut found,
        &mut scanned,
        &mut warnings,
        0,
    )?;

    let mut approved = Vec::new();
    let mut unpinnable = Vec::new();
    for candidate in found.into_values() {
        if candidate.is_pinnable() {
            approved.push(candidate);
        } else {
            unpinnable.push(candidate);
        }
    }

    Ok(SeedReport {
        root: root.to_path_buf(),
        project,
        scanned_at: now,
        packages_scanned: scanned,
        approved,
        unpinnable,
        integrity_sources: index.sources,
        warnings,
        dry_run: false,
        offline: false,
        written: 0,
    })
}

/// The human-readable report. Pure — takes no clock and touches no filesystem.
pub fn render(report: &SeedReport) -> String {
    let mut out = String::new();
    out.push_str("npmfilter seed — DESIGN.md \"Build order\" step 5\n\n");
    out.push_str(SEED_WARNING);
    out.push_str("\n\n");
    if report.offline {
        out.push_str(SEED_OFFLINE_WARNING);
        out.push_str("\n\n");
    }

    out.push_str(&format!("tree                 {}\n", report.root.display()));
    out.push_str(&format!(
        "scanned              {} installed packages\n",
        report.packages_scanned
    ));
    out.push_str(&format!("install-hook packages {}\n", report.candidates()));
    if report.integrity_sources.is_empty() {
        out.push_str("integrity read from  (nothing — no lockfile found)\n");
    } else {
        for (index, source) in report.integrity_sources.iter().enumerate() {
            let label = if index == 0 {
                "integrity read from "
            } else {
                "                    "
            };
            out.push_str(&format!("{label} {}\n", source.display()));
        }
    }
    out.push('\n');

    out.push_str(TREE_HASH_SPEC);
    out.push_str("\n\n");

    if report.approved.is_empty() {
        out.push_str("APPROVE (0) — nothing in this tree declares an install hook.\n");
    } else {
        out.push_str(&format!(
            "APPROVE ({}) — one allow rule each, pinned to dist.integrity and to the script hash:\n",
            report.approved.len()
        ));
        for candidate in &report.approved {
            out.push_str(&format!("\n  {}@{}\n", candidate.name, candidate.version));
            for line in candidate.hook_lines() {
                out.push_str(&format!("    hook            {line}\n"));
            }
            out.push_str(&format!(
                "    scripts sha256  {}\n",
                candidate.scripts.sha256()
            ));
            out.push_str(&format!(
                "    dist.integrity  {}  (from {})\n",
                candidate.integrity.as_deref().unwrap_or("<none>"),
                candidate
                    .integrity_source
                    .map(IntegritySource::as_str)
                    .unwrap_or("<unknown>"),
            ));
            out.push_str(&format!("    on-disk tree    {}\n", candidate.tree_sha256));
            out.push_str(&format!("    directory       {}\n", candidate.key));
            if candidate.copies > 1 {
                out.push_str(&format!(
                    "    copies          {} identical (name, version) directories in this tree\n",
                    candidate.copies
                ));
            }
        }
        out.push('\n');
    }

    if !report.unpinnable.is_empty() {
        out.push_str(&format!(
            "\nCANNOT PIN ({}) — no dist.integrity on disk, so NO rule is written. An allow rule\n\
             pinned to anything but the upstream sha512 would withhold the version and raise a\n\
             critical tamper event (DESIGN.md \"Policy engine\" gate 2). Approve these deliberately\n\
             with `npmfilter inspect` + `npmfilter allow`, or the MCP tools npmfilter_inspect /\n\
             npmfilter_allow:\n",
            report.unpinnable.len()
        ));
        for candidate in &report.unpinnable {
            out.push_str(&format!("\n  {}@{}\n", candidate.name, candidate.version));
            for line in candidate.hook_lines() {
                out.push_str(&format!("    hook            {line}\n"));
            }
            out.push_str(&format!("    on-disk tree    {}\n", candidate.tree_sha256));
            out.push_str(&format!("    directory       {}\n", candidate.key));
        }
        out.push('\n');
    }

    if !report.warnings.is_empty() {
        out.push_str(&format!("\nSKIPPED ({}):\n", report.warnings.len()));
        for warning in &report.warnings {
            out.push_str(&format!("  {warning}\n"));
        }
        out.push('\n');
    }

    if report.dry_run {
        out.push_str(
            "\nDRY RUN — nothing was written. Re-run without --dry-run to record these rules.\n",
        );
    } else {
        out.push_str(&format!(
            "\nWROTE {} allow rule(s). Seeding approved the state of this tree as of {}.\n",
            report.written,
            report.scanned_at.to_rfc3339(),
        ));
    }
    out
}

/// The daemon's side of the report: what it verified, wrote and refused.
pub fn render_result(result: &SeedResult) -> String {
    let mut out = String::from("\nDAEMON VERIFICATION\n");
    out.push_str(&format!(
        "  verified {}   written {}   refused {}\n",
        result.verified, result.written, result.refused
    ));
    let refused: Vec<_> = result
        .outcomes
        .iter()
        .filter(|outcome| outcome.status == "refused")
        .collect();
    if !refused.is_empty() {
        out.push_str(&format!(
            "\nREFUSED ({}) — no rule was written for these. A lockfile hash that disagrees with\n\
             the registry means the tree on disk is not the artefact the registry published:\n",
            refused.len()
        ));
        for outcome in refused {
            out.push_str(&format!("\n  {}@{}\n", outcome.name, outcome.version));
            out.push_str(&format!("    {}\n", outcome.detail));
        }
    }
    out.push_str(&format!("\n{}\n", result.note));
    out
}

/// `npmfilter seed <path> [--dry-run] [--offline]`.
///
/// Walks the tree here, then hands the candidates to the daemon: it verifies each one against
/// the registry and it, not this command, writes the rules.
pub fn run(path: &Path, dry_run: bool, offline: bool, config: &Config) -> anyhow::Result<()> {
    let root = resolve_node_modules(path)?;
    let now = Utc::now();
    let mut report = scan(&root, now)?;
    report.dry_run = dry_run;
    report.offline = offline;

    let entries: Vec<SeedEntry> = report
        .approved
        .iter()
        .filter_map(SeedCandidate::entry)
        .collect();
    if entries.len() > MAX_SEED_ENTRIES {
        return Err(SeedError::TooManyEntries {
            count: entries.len(),
        }
        .into());
    }

    let client = ControlClient::new(config.socket_path.clone(), LABEL_SEED);
    let answer = send_blocking(
        &client,
        Request::Seed(SeedArgs {
            root: report.root.display().to_string(),
            dry_run,
            offline,
            entries,
        }),
    )?;
    let Answer::Seed(result) = answer else {
        anyhow::bail!("the npmfilter daemon answered a seed request with something else");
    };
    report.written = result.written;

    tracing::info!(
        tree = %report.root.display(),
        written = result.written,
        verified = result.verified,
        refused = result.refused,
        offline,
        dry_run,
        "seeded install-script packages"
    );

    print!("{}", render(&report));
    print!("{}", render_result(&result));
    Ok(())
}

// -- the on-disk tree hash ------------------------------------------------------------------

/// One manifest line, before rendering.
#[derive(Debug)]
struct TreeEntry {
    path: Vec<u8>,
    kind: u8,
    len: u64,
    digest: String,
}

/// The reproducible hash of an unpacked package directory — see [`TREE_HASH_SPEC`].
pub fn tree_sha256(dir: &Path) -> Result<String, SeedError> {
    let mut entries = Vec::new();
    collect_tree(dir, &[], &mut entries, 0)?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));

    let mut manifest = Vec::new();
    for entry in &entries {
        manifest.extend_from_slice(entry.digest.as_bytes());
        manifest.push(b' ');
        manifest.push(entry.kind);
        manifest.push(b' ');
        manifest.extend_from_slice(entry.len.to_string().as_bytes());
        manifest.push(b' ');
        manifest.extend_from_slice(&entry.path);
        manifest.push(b'\n');
    }
    Ok(format!(
        "{TREE_HASH_PREFIX}{}",
        hex_encode(Sha256::digest(&manifest).as_slice())
    ))
}

fn collect_tree(
    dir: &Path,
    prefix: &[u8],
    out: &mut Vec<TreeEntry>,
    depth: usize,
) -> Result<(), SeedError> {
    if depth > MAX_DEPTH {
        return Ok(());
    }
    for name in read_dir_sorted(dir)? {
        if name == OsStr::new("node_modules") {
            // Nested dependencies are separate packages and are hashed on their own.
            continue;
        }
        let child = dir.join(&name);
        let metadata = fs::symlink_metadata(&child).map_err(|source| SeedError::Io {
            path: child.clone(),
            source,
        })?;

        let mut relative = prefix.to_vec();
        if !relative.is_empty() {
            relative.push(b'/');
        }
        relative.extend_from_slice(&os_bytes(&name));

        if metadata.is_symlink() {
            let target = fs::read_link(&child).map_err(|source| SeedError::Io {
                path: child.clone(),
                source,
            })?;
            let bytes = os_bytes(target.as_os_str());
            out.push(TreeEntry {
                path: relative,
                kind: b'l',
                len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                digest: hex_encode(Sha256::digest(&bytes).as_slice()),
            });
        } else if metadata.is_dir() {
            collect_tree(&child, &relative, out, depth + 1)?;
        } else if metadata.is_file() {
            let (digest, len) = hash_file(&child)?;
            out.push(TreeEntry {
                path: relative,
                kind: if is_executable(&metadata) { b'x' } else { b'f' },
                len,
                digest,
            });
        }
        // Anything else (fifo, socket, device) is not package content and is not hashed.
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<(String, u64), SeedError> {
    let mut file = File::open(path).map_err(|source| SeedError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; HASH_CHUNK];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buffer).map_err(|source| SeedError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total = total.saturating_add(u64::try_from(read).unwrap_or(0));
    }
    Ok((hex_encode(hasher.finalize().as_slice()), total))
}

// -- the walk -------------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn walk_node_modules(
    node_modules: &Path,
    project: &Path,
    index: &IntegrityIndex,
    found: &mut BTreeMap<(String, String), SeedCandidate>,
    scanned: &mut usize,
    warnings: &mut Vec<String>,
    depth: usize,
) -> Result<(), SeedError> {
    if depth > MAX_DEPTH {
        warnings.push(format!(
            "{}: nesting deeper than {MAX_DEPTH} levels was not walked",
            node_modules.display()
        ));
        return Ok(());
    }
    for name in read_dir_sorted(node_modules)? {
        let entry = node_modules.join(&name);
        let Some(metadata) = symlink_metadata_opt(&entry, warnings) else {
            continue;
        };
        if metadata.is_symlink() {
            // pnpm and workspace links point at a directory that is walked at its real
            // location; following them would double-count and can loop.
            continue;
        }
        if !metadata.is_dir() {
            continue;
        }

        let raw = name.to_string_lossy().into_owned();
        if raw.starts_with('.') {
            if raw == ".pnpm" {
                walk_pnpm_store(&entry, project, index, found, scanned, warnings, depth + 1)?;
            }
            continue;
        }
        if raw.starts_with('@') {
            for scoped in read_dir_sorted(&entry)? {
                let package_dir = entry.join(&scoped);
                let Some(scoped_meta) = symlink_metadata_opt(&package_dir, warnings) else {
                    continue;
                };
                if scoped_meta.is_symlink() || !scoped_meta.is_dir() {
                    continue;
                }
                visit_package(
                    &package_dir,
                    project,
                    index,
                    found,
                    scanned,
                    warnings,
                    depth + 1,
                )?;
            }
            continue;
        }
        visit_package(&entry, project, index, found, scanned, warnings, depth + 1)?;
    }
    Ok(())
}

/// pnpm keeps the real packages under `node_modules/.pnpm/<name>@<version>/node_modules/<name>`.
#[allow(clippy::too_many_arguments)]
fn walk_pnpm_store(
    store_dir: &Path,
    project: &Path,
    index: &IntegrityIndex,
    found: &mut BTreeMap<(String, String), SeedCandidate>,
    scanned: &mut usize,
    warnings: &mut Vec<String>,
    depth: usize,
) -> Result<(), SeedError> {
    for name in read_dir_sorted(store_dir)? {
        let nested = store_dir.join(&name).join("node_modules");
        if nested.is_dir() {
            walk_node_modules(&nested, project, index, found, scanned, warnings, depth + 1)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn visit_package(
    dir: &Path,
    project: &Path,
    index: &IntegrityIndex,
    found: &mut BTreeMap<(String, String), SeedCandidate>,
    scanned: &mut usize,
    warnings: &mut Vec<String>,
    depth: usize,
) -> Result<(), SeedError> {
    let manifest_path = dir.join("package.json");
    if manifest_path.is_file() {
        match read_json(&manifest_path) {
            Ok(manifest) => {
                *scanned += 1;
                record_candidate(dir, project, index, &manifest, found, warnings);
            }
            Err(message) => warnings.push(message),
        }
    }

    let nested = dir.join("node_modules");
    if nested.is_dir() {
        walk_node_modules(&nested, project, index, found, scanned, warnings, depth + 1)?;
    }
    Ok(())
}

fn record_candidate(
    dir: &Path,
    project: &Path,
    index: &IntegrityIndex,
    manifest: &Value,
    found: &mut BTreeMap<(String, String), SeedCandidate>,
    warnings: &mut Vec<String>,
) {
    let scripts = ScriptSet::from_version(manifest);
    if scripts.is_empty() {
        return;
    }
    let Some(name) = manifest.get("name").and_then(Value::as_str) else {
        warnings.push(format!(
            "{}: declares install hooks but has no `name` — cannot be pinned to a package",
            dir.display()
        ));
        return;
    };
    let Some(version) = manifest.get("version").and_then(Value::as_str) else {
        warnings.push(format!(
            "{}: {name} declares install hooks but has no `version` — cannot be pinned",
            dir.display()
        ));
        return;
    };

    let key = relative_key(project, dir);

    // The manifest is untrusted input: a git dependency, a `file:` link or any hand-made
    // directory can declare whatever name and version it likes, and a rule is written for
    // whatever it says. The directory it is installed in is the lockfile's own key, so that is
    // what decides which package this is. A manifest that disagrees is not seeded at all —
    // otherwise one such directory mints an allow rule for a package nobody vetted, or pins a
    // legitimate one to the wrong hash and turns it into a permanent `integrity_changed` block.
    let installed_as = name_from_key(&key);
    if installed_as != name {
        warnings.push(format!(
            "{}: installed at {key} but its package.json declares `{name}` — refusing to seed a \
             rule for a package this directory is not; approve it deliberately with \
             `npmfilter inspect` + `npmfilter allow` if it is genuine",
            dir.display()
        ));
        return;
    }
    if let Some(recorded) = index.path_version(&key)
        && recorded != version
    {
        warnings.push(format!(
            "{}: the lockfile records {name}@{recorded} at {key} but its package.json declares \
             version {version} — refusing to seed a rule whose version cannot be trusted",
            dir.display()
        ));
        return;
    }

    if let Some(existing) = found.get_mut(&(name.to_owned(), version.to_owned())) {
        existing.copies += 1;
        return;
    }

    let located = index.lookup(&key, name, version, manifest);
    let tree_sha256 = match tree_sha256(dir) {
        Ok(hash) => hash,
        Err(error) => {
            warnings.push(format!(
                "{}: {name}@{version} could not be hashed ({error}) — skipped",
                dir.display()
            ));
            return;
        }
    };

    found.insert(
        (name.to_owned(), version.to_owned()),
        SeedCandidate {
            name: name.to_owned(),
            version: version.to_owned(),
            directory: dir.to_path_buf(),
            key,
            scripts,
            integrity: located.integrity,
            integrity_source: located.source,
            resolved: located.resolved,
            tree_sha256,
            copies: 1,
        },
    );
}

// -- integrity discovery --------------------------------------------------------------------

/// One package's pin, as found on disk.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Located {
    integrity: Option<String>,
    resolved: Option<String>,
    source: Option<IntegritySource>,
}

/// A lockfile entry: the `dist.integrity` and `dist.tarball` npm recorded for a package.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LockEntry {
    integrity: Option<String>,
    resolved: Option<String>,
    /// The version the lockfile recorded, when it stated one.
    version: Option<String>,
    source: IntegritySource,
}

/// Every `dist.integrity` npm wrote to disk for this tree, indexed two ways.
#[derive(Debug, Default)]
struct IntegrityIndex {
    by_path: HashMap<String, LockEntry>,
    by_name_version: HashMap<(String, String), LockEntry>,
    sources: Vec<PathBuf>,
}

impl IntegrityIndex {
    /// Read npm's hidden lockfile, then `package-lock.json`, then `npm-shrinkwrap.json`.
    /// Earlier sources win: the hidden lockfile describes the tree that is actually installed.
    fn load(node_modules: &Path, project: &Path, warnings: &mut Vec<String>) -> Self {
        let mut index = Self::default();
        let candidates = [
            (
                node_modules.join(".package-lock.json"),
                IntegritySource::HiddenLockfile,
            ),
            (project.join("package-lock.json"), IntegritySource::Lockfile),
            (
                project.join("npm-shrinkwrap.json"),
                IntegritySource::Shrinkwrap,
            ),
        ];
        for (path, source) in candidates {
            if !path.is_file() {
                continue;
            }
            match read_json(&path) {
                Ok(document) => {
                    index.absorb(&document, source);
                    index.sources.push(path);
                }
                Err(message) => warnings.push(format!("{message} — that lockfile was not used")),
            }
        }
        index
    }

    /// Index one lockfile document — both the v2/v3 `packages` map and the v1 `dependencies` tree.
    fn absorb(&mut self, document: &Value, source: IntegritySource) {
        if let Some(packages) = document.get("packages").and_then(Value::as_object) {
            for (key, entry) in packages {
                if key.is_empty() {
                    continue;
                }
                let integrity = entry.get("integrity").and_then(Value::as_str);
                let resolved = entry.get("resolved").and_then(Value::as_str);
                if integrity.is_none() && resolved.is_none() {
                    continue;
                }
                let lock = LockEntry {
                    integrity: integrity.map(str::to_owned),
                    resolved: resolved.map(str::to_owned),
                    version: entry
                        .get("version")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    source,
                };
                self.by_path.entry(key.clone()).or_insert(lock.clone());
                if let Some(version) = entry.get("version").and_then(Value::as_str) {
                    let name = entry
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .unwrap_or_else(|| name_from_key(key));
                    self.by_name_version
                        .entry((name, version.to_owned()))
                        .or_insert(lock);
                }
            }
        }
        if let Some(dependencies) = document.get("dependencies").and_then(Value::as_object) {
            self.absorb_v1(dependencies, source, 0);
        }
    }

    fn absorb_v1(
        &mut self,
        dependencies: &serde_json::Map<String, Value>,
        source: IntegritySource,
        depth: usize,
    ) {
        if depth > MAX_DEPTH {
            return;
        }
        for (name, entry) in dependencies {
            let Some(version) = entry.get("version").and_then(Value::as_str) else {
                continue;
            };
            let integrity = entry.get("integrity").and_then(Value::as_str);
            let resolved = entry.get("resolved").and_then(Value::as_str);
            if integrity.is_some() || resolved.is_some() {
                self.by_name_version
                    .entry((name.clone(), version.to_owned()))
                    .or_insert(LockEntry {
                        integrity: integrity.map(str::to_owned),
                        resolved: resolved.map(str::to_owned),
                        version: Some(version.to_owned()),
                        source,
                    });
            }
            if let Some(nested) = entry.get("dependencies").and_then(Value::as_object) {
                self.absorb_v1(nested, source, depth + 1);
            }
        }
    }

    /// The version the lockfile recorded for the directory at `key`, if it has an entry.
    fn path_version(&self, key: &str) -> Option<&str> {
        self.by_path.get(key)?.version.as_deref()
    }

    /// Path key first (it names the exact directory), then `(name, version)`, then the
    /// `_integrity` field npm 6 left in the installed `package.json`.
    ///
    /// The `(name, version)` fallback only applies when the lockfile has **no** entry for this
    /// directory at all — a v1 `dependencies` tree, which is indexed no other way. A directory
    /// that the lockfile does describe but without an integrity is a git, `file:` or `link:`
    /// dependency: it is not the registry artefact of that `(name, version)`, and pinning it to
    /// some other entry's hash would approve bytes nobody looked at.
    fn lookup(&self, key: &str, name: &str, version: &str, manifest: &Value) -> Located {
        let path_entry = self.by_path.get(key);
        if let Some(entry) = path_entry
            && entry.integrity.is_some()
        {
            return Located {
                integrity: entry.integrity.clone(),
                resolved: entry.resolved.clone(),
                source: Some(entry.source),
            };
        }
        if let Some(entry) = self
            .by_name_version
            .get(&(name.to_owned(), version.to_owned()))
            && path_entry.is_none()
            && entry.integrity.is_some()
        {
            return Located {
                integrity: entry.integrity.clone(),
                resolved: entry.resolved.clone(),
                source: Some(entry.source),
            };
        }
        if let Some(integrity) = manifest.get("_integrity").and_then(Value::as_str) {
            return Located {
                integrity: Some(integrity.to_owned()),
                resolved: manifest
                    .get("_resolved")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                source: Some(IntegritySource::PackageJsonField),
            };
        }
        Located {
            integrity: None,
            resolved: self
                .by_path
                .get(key)
                .and_then(|entry| entry.resolved.clone()),
            source: None,
        }
    }
}

/// `node_modules/foo/node_modules/@scope/bar` → `@scope/bar`.
fn name_from_key(key: &str) -> String {
    match key.rsplit_once("node_modules/") {
        Some((_, tail)) => tail.to_owned(),
        None => key.to_owned(),
    }
}

// -- small filesystem helpers ---------------------------------------------------------------

/// `dir` relative to `project`, `/`-separated — the shape a lockfile uses as its key.
fn relative_key(project: &Path, dir: &Path) -> String {
    let relative = dir.strip_prefix(project).unwrap_or(dir);
    relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn read_dir_sorted(dir: &Path) -> Result<Vec<OsString>, SeedError> {
    let mut names = Vec::new();
    let entries = fs::read_dir(dir).map_err(|source| SeedError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| SeedError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        names.push(entry.file_name());
    }
    names.sort_by_key(|name| os_bytes(name));
    Ok(names)
}

fn symlink_metadata_opt(path: &Path, warnings: &mut Vec<String>) -> Option<Metadata> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) => {
            warnings.push(format!("{}: {error}", path.display()));
            None
        }
    }
}

fn read_json(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_str(&text)
        .map_err(|error| format!("{}: not valid JSON ({error})", path.display()))
}

#[cfg(unix)]
fn os_bytes(name: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    name.as_bytes().to_vec()
}

#[cfg(not(unix))]
fn os_bytes(name: &OsStr) -> Vec<u8> {
    name.to_string_lossy().into_owned().into_bytes()
}

#[cfg(unix)]
fn is_executable(metadata: &Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o100 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &Metadata) -> bool {
    false
}
