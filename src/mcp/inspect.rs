//! `npmfilter_inspect` — DESIGN.md "MCP surface".
//!
//! Fetches the tarball for one published version, **streams** it, and keeps only
//! `package.json` and a sha256 per entry — every other byte is discarded as it passes.
//! Nothing is ever written to disk: the download
//! is piped chunk-by-chunk into a blocking decoder and each entry's body is skipped as the tar
//! reader walks past it. Three hard limits — compressed bytes, decompressed bytes and entry
//! count — mean a hostile tarball cannot exhaust memory or spin the reader forever.
//!
//! The highest-signal field it returns is the **script delta** against the previous published
//! version: a version that newly acquires an install hook is exactly the compromise shape
//! (`keyv@6.0.0` gaining a `preinstall` when 5.x had none).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use axum::body::Bytes;
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tar::Archive;
use thiserror::Error;
use tokio::sync::mpsc;

use crate::policy::{INSTALL_HOOKS, install_hooks, version_integrity};
use crate::store::{ScriptSet, hex_encode};

/// Largest compressed tarball this will read. Real npm tarballs are kilobytes to a few MiB.
pub const DEFAULT_MAX_COMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
/// Largest decompressed stream this will read — the gzip-bomb guard.
pub const DEFAULT_MAX_UNPACKED_BYTES: u64 = 256 * 1024 * 1024;
/// Largest `package.json` this will parse. These are the only bytes ever retained.
pub const DEFAULT_MAX_PACKAGE_JSON_BYTES: u64 = 4 * 1024 * 1024;
/// Largest number of tar entries this will walk.
pub const DEFAULT_MAX_ENTRIES: u64 = 200_000;

/// The bounds enforced while streaming a tarball.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TarballLimits {
    /// Bytes read off the wire before the download is abandoned.
    pub max_compressed_bytes: u64,
    /// Bytes produced by the gzip decoder before the scan is abandoned.
    pub max_unpacked_bytes: u64,
    /// Bytes of `package.json` retained.
    pub max_package_json_bytes: u64,
    /// Tar entries walked.
    pub max_entries: u64,
}

impl Default for TarballLimits {
    fn default() -> Self {
        Self {
            max_compressed_bytes: DEFAULT_MAX_COMPRESSED_BYTES,
            max_unpacked_bytes: DEFAULT_MAX_UNPACKED_BYTES,
            max_package_json_bytes: DEFAULT_MAX_PACKAGE_JSON_BYTES,
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }
}

/// What one streamed tarball yielded. The tarball bytes themselves are gone by now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarballScan {
    /// The parsed `<root>/package.json`, if the archive carried one.
    pub package_json: Option<Value>,
    /// The path that `package.json` was read from, e.g. `package/package.json`.
    pub package_json_path: Option<String>,
    /// Every regular file in the archive with its sha256, package-relative and sorted.
    ///
    /// Digests, never contents: each entry is hashed as it streams past and its bytes are
    /// dropped. This is what an approval can be pinned to, and it is the only way to answer
    /// "which files changed between these two versions" at all — a packument publishes
    /// `fileCount` and `unpackedSize` and no per-file digest whatsoever.
    pub files: Vec<FileDigest>,
    /// How many regular files the archive holds.
    pub file_count: u64,
    /// The sum of those files' sizes — the same quantity npm publishes as `unpackedSize`.
    pub unpacked_bytes: u64,
    /// How many compressed bytes were read to learn all of the above.
    pub compressed_bytes: u64,
}

/// Anything that can stop a tarball scan.
#[derive(Debug, Error)]
pub enum TarballError {
    #[error("tarball exceeds the {limit}-byte compressed limit and was abandoned")]
    CompressedLimit { limit: u64 },
    #[error("tarball expands past the {limit}-byte unpacked limit and was abandoned")]
    UnpackedLimit { limit: u64 },
    #[error("tarball holds more than {limit} entries and was abandoned")]
    EntryLimit { limit: u64 },
    #[error("package.json is larger than the {limit}-byte limit")]
    PackageJsonLimit { limit: u64 },
    #[error("failed to read the tarball")]
    Read(#[source] std::io::Error),
    #[error("package.json in the tarball is not valid JSON")]
    PackageJson(#[source] serde_json::Error),
}

/// Anything that can stop an inspection.
#[derive(Debug, Error)]
pub enum InspectError {
    #[error("upstream request for {url} failed")]
    Http {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("upstream answered {status} for {url}")]
    Status { url: String, status: u16 },
    #[error("packument for {package} is malformed: {detail}")]
    BadPackument { package: String, detail: String },
    #[error("{package} has no published version {version}")]
    UnknownVersion { package: String, version: String },
    #[error("{package}@{version} has no dist.tarball, so there is nothing to inspect")]
    NoTarball { package: String, version: String },
    #[error(transparent)]
    Tarball(#[from] TarballError),
    #[error("the tarball reader task failed")]
    Join(#[source] tokio::task::JoinError),
}

/// One file in a published tarball, by path and content digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileDigest {
    /// Package-relative path, e.g. `install.js`. The archive's root directory is stripped so
    /// a pin means the same file whatever that root happens to be called.
    pub path: String,
    /// Lowercase-hex sha256 of the file's contents.
    pub sha256: String,
    /// Size in bytes, as the archive header declares it.
    pub size: u64,
}

/// One install-hook command and the sha256 of that exact command string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HookCommand {
    /// `preinstall`, `install` or `postinstall`.
    pub hook: String,
    /// The command as declared.
    pub command: String,
    /// Lowercase-hex sha256 of the command's UTF-8 bytes.
    pub sha256: String,
}

impl HookCommand {
    /// Build one, hashing the command.
    pub fn new(hook: impl Into<String>, command: impl Into<String>) -> Self {
        let command = command.into();
        let sha256 = hex_encode(Sha256::digest(command.as_bytes()).as_slice());
        Self {
            hook: hook.into(),
            command,
            sha256,
        }
    }

    /// Every install hook a [`ScriptSet`] holds, in lifecycle order.
    pub fn from_scripts(scripts: &ScriptSet) -> Vec<Self> {
        INSTALL_HOOKS
            .iter()
            .filter_map(|hook| {
                scripts
                    .hooks()
                    .get(*hook)
                    .map(|command| Self::new(*hook, command))
            })
            .collect()
    }
}

/// One hook whose command changed between two versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HookChange {
    /// Which hook.
    pub hook: String,
    /// What the previous version ran.
    pub previous: String,
    /// What this version runs.
    pub current: String,
    /// sha256 of `previous`.
    pub previous_sha256: String,
    /// sha256 of `current`.
    pub current_sha256: String,
}

/// The install-hook difference against the previous published version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ScriptDelta {
    /// Which version this was compared against, if any.
    pub previous_version: Option<String>,
    /// Whether a comparison happened at all.
    pub compared: bool,
    /// **The compromise shape**: the previous version ran no install hook and this one does.
    pub newly_acquires_install_hooks: bool,
    /// Hooks this version has and the previous one did not.
    pub added: Vec<HookCommand>,
    /// Hooks the previous version had and this one does not.
    pub removed: Vec<HookCommand>,
    /// Hooks present in both, with a different command.
    pub changed: Vec<HookChange>,
    /// Hooks present in both with the same command string. The *files* those commands run
    /// are NOT compared here — a `postinstall: node install.js` that is "unchanged" says
    /// nothing about install.js. Pin the file to cover that.
    pub unchanged: Vec<HookCommand>,
    /// One sentence naming what the delta means.
    pub summary: String,
}

/// What an earlier approval's pinned files look like in the version being inspected.
///
/// The script delta above compares command strings. This compares the bytes those commands
/// run: an approval that pinned `install.js` in 0.25.12 makes 0.25.13's `install.js` either
/// provably the same file or provably a different one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PinAudit {
    /// The version whose approval recorded these pins.
    pub pinned_version: String,
    /// Pinned files this version publishes with identical bytes.
    pub unchanged: Vec<String>,
    /// Pinned files this version publishes with different bytes. **Read every one of these
    /// before approving**: a changed install script under an unchanged command is the shape
    /// the command-level delta cannot see.
    pub changed: Vec<PinChange>,
    /// Pinned paths this version does not publish at all.
    pub missing: Vec<String>,
    /// One sentence naming what the comparison found.
    pub summary: String,
}

/// One pinned file whose bytes moved between the approved version and this one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PinChange {
    /// Path inside the package.
    pub path: String,
    /// The digest the earlier approval pinned.
    pub pinned_sha256: String,
    /// The digest this version publishes.
    pub observed_sha256: String,
}

/// Compare an earlier approval's pins against the files this version actually publishes.
///
/// `pinned` is `(version, path -> sha256)` as recorded by the approval; `files` is what the
/// daemon just hashed out of the tarball.
pub fn pin_audit(
    pinned_version: &str,
    pinned: &BTreeMap<String, String>,
    files: &[FileDigest],
) -> PinAudit {
    let observed: BTreeMap<&str, &str> = files
        .iter()
        .map(|file| (file.path.as_str(), file.sha256.as_str()))
        .collect();

    let mut unchanged = Vec::new();
    let mut changed = Vec::new();
    let mut missing = Vec::new();
    for (path, pinned_sha256) in pinned {
        match observed.get(path.as_str()) {
            Some(observed_sha256) if *observed_sha256 == pinned_sha256.as_str() => {
                unchanged.push(path.clone());
            }
            Some(observed_sha256) => changed.push(PinChange {
                path: path.clone(),
                pinned_sha256: pinned_sha256.clone(),
                observed_sha256: (*observed_sha256).to_owned(),
            }),
            None => missing.push(path.clone()),
        }
    }

    let summary = if !changed.is_empty() {
        format!(
            "{} of {} file(s) pinned by {pinned_version} changed: {}",
            changed.len(),
            pinned.len(),
            changed
                .iter()
                .map(|change| change.path.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else if !missing.is_empty() {
        format!(
            "{} file(s) pinned by {pinned_version} are not published here: {}",
            missing.len(),
            missing.join(", ")
        )
    } else {
        format!("every file pinned by {pinned_version} is byte-identical in this version",)
    };

    PinAudit {
        pinned_version: pinned_version.to_owned(),
        unchanged,
        changed,
        missing,
        summary,
    }
}

/// Whether a provenance attestation was published alongside the version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Provenance {
    /// Whether `dist.attestations` is present at all.
    pub attested: bool,
    /// The attestation bundle URL, when published.
    pub url: Option<String>,
    /// The predicate types the bundle declares, e.g. `https://slsa.dev/provenance/v1`.
    pub predicate_types: Vec<String>,
    /// How many registry signatures the version carries (`dist.signatures`).
    pub signatures: usize,
}

/// Registry-declared versus observed counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Measured {
    /// What the packument claims.
    pub registry: Option<u64>,
    /// What streaming the tarball actually found.
    pub observed: u64,
}

/// Everything `npmfilter_inspect` reports for one version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InspectReport {
    /// The package inspected.
    pub package: String,
    /// The version inspected.
    pub version: String,
    /// Whether the version was chosen by the caller or defaulted to `dist-tags.latest`.
    pub version_source: String,
    /// Publish time, RFC 3339, from the packument's `time` map.
    pub published: Option<String>,
    /// Age in whole days at inspection time.
    pub age_days: Option<i64>,
    /// The same age in words.
    pub age: Option<String>,
    /// `dist.integrity` — the sha512 an approval pins to.
    pub dist_integrity: Option<String>,
    /// `dist.tarball` — where the bytes came from. They were streamed, not stored.
    pub dist_tarball: Option<String>,
    /// The install hooks the **tarball's** `package.json` declares, with their hashes.
    pub install_hooks: Vec<HookCommand>,
    /// sha256 over the sorted install-hook map — what an approval pins the commands to.
    pub scripts_sha256: String,
    /// The install hooks the **packument** declares — what the request path gates on.
    pub packument_install_hooks: Vec<HookCommand>,
    /// The packument's script hash.
    pub packument_scripts_sha256: String,
    /// Whether the tarball and the packument agree about the install hooks.
    pub scripts_match_packument: bool,
    /// The install-hook delta against the previous published version.
    pub script_delta: ScriptDelta,
    /// How this version's files compare to the ones an earlier approval pinned, when the
    /// package has such an approval. `None` means no earlier approval named any file.
    pub pin_audit: Option<PinAudit>,
    /// `maintainers`, rendered `name <email>`.
    pub maintainers: Vec<String>,
    /// `_npmUser` — the account that published this exact version.
    pub npm_user: Option<String>,
    /// Provenance attestation presence.
    pub provenance: Provenance,
    /// File count: what the registry claims versus what the stream held.
    pub file_count: Measured,
    /// Unpacked size in bytes: registry versus observed.
    pub unpacked_size: Measured,
    /// How many compressed bytes were read.
    pub compressed_bytes: u64,
    /// Every file in the tarball with its sha256 — the manifest an approval pins against.
    ///
    /// Capped at [`MAX_REPORTED_FILES`] entries so a package with thousands of files does not
    /// make the report unreadable; `files_truncated` says when that happened, and the count is
    /// always exact in `file_count`.
    pub files: Vec<FileDigest>,
    /// Whether `files` was cut short by the cap.
    pub files_truncated: bool,
    /// The limits that were in force.
    pub limits: TarballLimits,
    /// Anything worth the caller's attention before approving.
    pub notes: Vec<String>,
}

/// Pick the version to inspect: the caller's, or `dist-tags.latest`, or the newest by semver.
pub fn resolve_version(
    packument: &Value,
    package: &str,
    requested: Option<&str>,
) -> Result<(String, String), InspectError> {
    let versions = packument
        .get("versions")
        .and_then(Value::as_object)
        .ok_or_else(|| InspectError::BadPackument {
            package: package.to_owned(),
            detail: "no `versions` object".to_owned(),
        })?;

    if let Some(version) = requested {
        if versions.contains_key(version) {
            return Ok((version.to_owned(), "requested".to_owned()));
        }
        return Err(InspectError::UnknownVersion {
            package: package.to_owned(),
            version: version.to_owned(),
        });
    }

    if let Some(latest) = packument
        .get("dist-tags")
        .and_then(Value::as_object)
        .and_then(|tags| tags.get("latest"))
        .and_then(Value::as_str)
        && versions.contains_key(latest)
    {
        return Ok((latest.to_owned(), "dist-tags.latest".to_owned()));
    }

    let newest = versions
        .keys()
        .filter_map(|version| {
            semver::Version::parse(version)
                .ok()
                .map(|parsed| (parsed, version.clone()))
        })
        .max_by(|left, right| left.0.cmp(&right.0))
        .map(|(_, version)| version)
        .or_else(|| versions.keys().next_back().cloned())
        .ok_or_else(|| InspectError::BadPackument {
            package: package.to_owned(),
            detail: "`versions` is empty".to_owned(),
        })?;
    Ok((newest, "newest published".to_owned()))
}

/// The version published immediately before `version`.
///
/// Publish order decides, because that is what "previous published version" means; the
/// packument's `time` map is the source. When `time` cannot answer — a missing entry, an
/// unparseable stamp — the highest semver strictly below `version` is used instead.
pub fn previous_version(packument: &Value, version: &str) -> Option<String> {
    let versions = packument.get("versions").and_then(Value::as_object)?;
    let time = packument.get("time").and_then(Value::as_object);

    let published = |candidate: &str| -> Option<DateTime<Utc>> {
        time.and_then(|time| time.get(candidate))
            .and_then(Value::as_str)
            .and_then(|raw| {
                DateTime::parse_from_rfc3339(raw)
                    .ok()
                    .map(|parsed| parsed.with_timezone(&Utc))
            })
    };

    let target_time = published(version);
    let target_semver = semver::Version::parse(version).ok();

    let mut best: Option<(Option<DateTime<Utc>>, Option<semver::Version>, String)> = None;
    for candidate in versions.keys() {
        if candidate == version {
            continue;
        }
        let candidate_time = published(candidate);
        let candidate_semver = semver::Version::parse(candidate).ok();

        let earlier = match (target_time, candidate_time) {
            (Some(target), Some(found)) => found < target,
            _ => match (&target_semver, &candidate_semver) {
                (Some(target), Some(found)) => found < target,
                _ => candidate.as_str() < version,
            },
        };
        if !earlier {
            continue;
        }

        let better = match &best {
            None => true,
            Some((best_time, best_semver, best_version)) => match (best_time, candidate_time) {
                (Some(current), Some(found)) if current != &found => found > *current,
                _ => match (best_semver, &candidate_semver) {
                    (Some(current), Some(found)) if current != found => found > current,
                    _ => candidate.as_str() > best_version.as_str(),
                },
            },
        };
        if better {
            best = Some((candidate_time, candidate_semver, candidate.clone()));
        }
    }
    best.map(|(_, _, version)| version)
}

/// The install-hook difference between two versions — DESIGN.md's highest-signal detector.
pub fn script_delta(previous: Option<(&str, &ScriptSet)>, current: &ScriptSet) -> ScriptDelta {
    let Some((previous_version, previous_scripts)) = previous else {
        let summary = if current.is_empty() {
            "no previous published version to compare against; this version declares no install hooks".to_owned()
        } else {
            "no previous published version to compare against; this version declares install hooks"
                .to_owned()
        };
        return ScriptDelta {
            previous_version: None,
            compared: false,
            newly_acquires_install_hooks: false,
            added: Vec::new(),
            removed: Vec::new(),
            changed: Vec::new(),
            unchanged: Vec::new(),
            summary,
        };
    };

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();
    let mut unchanged = Vec::new();

    for hook in INSTALL_HOOKS {
        let before = previous_scripts.hooks().get(hook);
        let after = current.hooks().get(hook);
        match (before, after) {
            (None, Some(command)) => added.push(HookCommand::new(hook, command)),
            (Some(command), None) => removed.push(HookCommand::new(hook, command)),
            (Some(before), Some(after)) if before != after => changed.push(HookChange {
                hook: hook.to_owned(),
                previous: before.clone(),
                current: after.clone(),
                previous_sha256: hex_encode(Sha256::digest(before.as_bytes()).as_slice()),
                current_sha256: hex_encode(Sha256::digest(after.as_bytes()).as_slice()),
            }),
            (Some(_), Some(command)) => unchanged.push(HookCommand::new(hook, command)),
            (None, None) => {}
        }
    }

    let newly_acquires_install_hooks = previous_scripts.is_empty() && !current.is_empty();
    let summary = if newly_acquires_install_hooks {
        format!(
            "NEWLY ACQUIRED INSTALL HOOKS — {previous_version} ran none, this version runs {}. \
             This is the shape of a supply-chain compromise; inspect the command before approving.",
            added
                .iter()
                .map(|hook| hook.hook.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else if !added.is_empty() || !changed.is_empty() {
        format!(
            "install hooks differ from {previous_version}: {} added, {} changed, {} removed",
            added.len(),
            changed.len(),
            removed.len()
        )
    } else if !removed.is_empty() {
        format!(
            "install hooks were removed since {previous_version}: {}",
            removed
                .iter()
                .map(|hook| hook.hook.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else if current.is_empty() {
        format!("neither {previous_version} nor this version declares an install hook")
    } else {
        format!(
            "the install-hook COMMANDS are identical to {previous_version}; the files those \
             commands run were not compared — pin them to cover that"
        )
    };

    ScriptDelta {
        previous_version: Some(previous_version.to_owned()),
        compared: true,
        newly_acquires_install_hooks,
        added,
        removed,
        changed,
        unchanged,
        summary,
    }
}

/// Stream a gzipped npm tarball, pulling `package.json` out of it and hashing every entry.
///
/// Every other entry's bytes are walked past and discarded — nothing but `package.json` is
/// ever held. The three limits in [`TarballLimits`] are enforced as the stream is consumed,
/// so a hostile archive is abandoned rather than buffered.
pub fn scan_tarball<R: Read>(
    reader: R,
    limits: &TarballLimits,
) -> Result<TarballScan, TarballError> {
    let compressed = Arc::new(Meter::default());
    let unpacked = Arc::new(Meter::default());

    let outer = MeteredReader {
        inner: reader,
        meter: Arc::clone(&compressed),
        limit: limits.max_compressed_bytes,
    };
    let decoder = GzDecoder::new(outer);
    let inner = MeteredReader {
        inner: decoder,
        meter: Arc::clone(&unpacked),
        limit: limits.max_unpacked_bytes,
    };

    let scanned = scan_entries(Archive::new(inner), limits);
    match scanned {
        Ok(mut scan) => {
            scan.compressed_bytes = compressed.bytes.load(Ordering::Relaxed);
            Ok(scan)
        }
        Err(TarballError::Read(error)) => {
            if compressed.tripped.load(Ordering::Relaxed) {
                Err(TarballError::CompressedLimit {
                    limit: limits.max_compressed_bytes,
                })
            } else if unpacked.tripped.load(Ordering::Relaxed) {
                Err(TarballError::UnpackedLimit {
                    limit: limits.max_unpacked_bytes,
                })
            } else {
                Err(TarballError::Read(error))
            }
        }
        Err(other) => Err(other),
    }
}

fn scan_entries<R: Read>(
    mut archive: Archive<R>,
    limits: &TarballLimits,
) -> Result<TarballScan, TarballError> {
    let mut scan = TarballScan {
        package_json: None,
        package_json_path: None,
        files: Vec::new(),
        file_count: 0,
        unpacked_bytes: 0,
        compressed_bytes: 0,
    };
    let mut seen = 0u64;

    for entry in archive.entries().map_err(TarballError::Read)? {
        let mut entry = entry.map_err(TarballError::Read)?;
        seen += 1;
        if seen > limits.max_entries {
            return Err(TarballError::EntryLimit {
                limit: limits.max_entries,
            });
        }

        let is_file = entry.header().entry_type().is_file();
        let size = entry.header().size().map_err(TarballError::Read)?;
        let path = entry
            .path()
            .map_err(TarballError::Read)?
            .to_string_lossy()
            .into_owned();

        if is_file {
            scan.file_count += 1;
            scan.unpacked_bytes = scan.unpacked_bytes.saturating_add(size);
        }

        if scan.package_json.is_none() && is_file && is_root_package_json(&path) {
            if size > limits.max_package_json_bytes {
                return Err(TarballError::PackageJsonLimit {
                    limit: limits.max_package_json_bytes,
                });
            }
            let mut buffer = Vec::new();
            entry
                .by_ref()
                .take(limits.max_package_json_bytes.saturating_add(1))
                .read_to_end(&mut buffer)
                .map_err(TarballError::Read)?;
            if u64::try_from(buffer.len()).unwrap_or(u64::MAX) > limits.max_package_json_bytes {
                return Err(TarballError::PackageJsonLimit {
                    limit: limits.max_package_json_bytes,
                });
            }
            scan.package_json =
                Some(serde_json::from_slice(&buffer).map_err(TarballError::PackageJson)?);
            scan.package_json_path = Some(path.clone());
            scan.files.push(FileDigest {
                path: package_relative(&path),
                sha256: hex_encode(Sha256::digest(&buffer).as_slice()),
                size: u64::try_from(buffer.len()).unwrap_or(u64::MAX),
            });
        } else if is_file {
            // Hashed as it streams, then dropped. A 256 MiB archive costs one hasher, not an
            // archive's worth of memory — the same discipline as reading only package.json.
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let read = entry.read(&mut buffer).map_err(TarballError::Read)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
            scan.files.push(FileDigest {
                path: package_relative(&path),
                sha256: hex_encode(hasher.finalize().as_slice()),
                size,
            });
        }
    }
    scan.files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(scan)
}

/// Strip the archive's root directory, so a pin reads `install.js` rather than
/// `package/install.js` and still names the same file if that root is ever called something
/// else. npm publishes `package/`, but nothing in the format requires it.
fn package_relative(path: &str) -> String {
    let trimmed = path.trim_start_matches("./");
    match trimmed.split_once('/') {
        Some((_root, rest)) if !rest.is_empty() => rest.to_owned(),
        _ => trimmed.to_owned(),
    }
}

/// `package/package.json` — the manifest at the archive root, whatever the root is called.
fn is_root_package_json(path: &str) -> bool {
    let components: Vec<&str> = path
        .trim_start_matches("./")
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect();
    components.len() == 2 && components[1] == "package.json"
}

/// Download a tarball and scan it without ever holding the whole thing.
///
/// The response is pumped chunk-by-chunk through a bounded channel into a blocking decoder.
/// When the scan stops early — a limit tripped, `package.json` unparseable — the receiver is
/// dropped, the pump's next send fails, and the download is abandoned.
pub async fn fetch_and_scan(
    client: &reqwest::Client,
    url: &str,
    limits: TarballLimits,
) -> Result<TarballScan, InspectError> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|source| InspectError::Http {
            url: url.to_owned(),
            source,
        })?;
    if !response.status().is_success() {
        return Err(InspectError::Status {
            url: url.to_owned(),
            status: response.status().as_u16(),
        });
    }

    let (sender, receiver) = mpsc::channel::<Result<Bytes, String>>(8);
    let pump = tokio::spawn(async move {
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if sender.send(Ok(chunk)).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    let _ = sender.send(Err(error.to_string())).await;
                    break;
                }
            }
        }
    });

    let scanned =
        tokio::task::spawn_blocking(move || scan_tarball(ChannelReader::new(receiver), &limits))
            .await;
    // The scan owns the receiver and has dropped it by now; stop the pump rather than let it
    // drain a tarball nobody is reading.
    pump.abort();

    match scanned {
        Ok(result) => Ok(result?),
        Err(error) => Err(InspectError::Join(error)),
    }
}

/// Build the report for one version. `scan` is what streaming the tarball produced.
/// How many per-file digests one report will carry.
pub const MAX_REPORTED_FILES: usize = 500;

pub fn build_report(
    package: &str,
    version: &str,
    version_source: &str,
    packument: &Value,
    scan: &TarballScan,
    limits: TarballLimits,
    now: DateTime<Utc>,
) -> InspectReport {
    let meta = packument
        .get("versions")
        .and_then(Value::as_object)
        .and_then(|versions| versions.get(version))
        .cloned()
        .unwrap_or(Value::Null);

    let published_raw = packument
        .get("time")
        .and_then(Value::as_object)
        .and_then(|time| time.get(version))
        .and_then(Value::as_str);
    let published_at = published_raw.and_then(|raw| {
        DateTime::parse_from_rfc3339(raw)
            .ok()
            .map(|parsed| parsed.with_timezone(&Utc))
    });
    let age_days = published_at.map(|at| now.signed_duration_since(at).num_days());

    let packument_scripts = ScriptSet::from_version(&meta);
    let tarball_scripts = scan
        .package_json
        .as_ref()
        .map(ScriptSet::from_version)
        .unwrap_or_default();

    let previous = previous_version(packument, version);
    let previous_scripts = previous.as_ref().and_then(|previous| {
        packument
            .get("versions")
            .and_then(Value::as_object)
            .and_then(|versions| versions.get(previous))
            .map(ScriptSet::from_version)
    });
    let delta = script_delta(
        previous.as_deref().zip(previous_scripts.as_ref()),
        &tarball_scripts,
    );

    let dist = meta.get("dist").cloned().unwrap_or(Value::Null);
    let mut notes = Vec::new();
    if scan.package_json.is_none() {
        notes.push(
            "the tarball carries no root package.json; install hooks below come from the packument alone"
                .to_owned(),
        );
    }
    let scripts_match_packument = if scan.package_json.is_some() {
        let matches = tarball_scripts == packument_scripts;
        if !matches {
            notes.push(
                "the tarball's install hooks DIFFER from the packument's — the registry metadata \
                 npmfilter gates on does not describe what the tarball would actually run"
                    .to_owned(),
            );
        }
        matches
    } else {
        false
    };
    if version_integrity(&meta).is_none() {
        notes.push(
            "this version publishes no dist.integrity, so no approval can be pinned to it"
                .to_owned(),
        );
    }
    if delta.newly_acquires_install_hooks {
        notes.push(delta.summary.clone());
    }

    InspectReport {
        package: package.to_owned(),
        version: version.to_owned(),
        version_source: version_source.to_owned(),
        published: published_raw.map(str::to_owned),
        age_days,
        age: age_days.map(describe_age),
        dist_integrity: version_integrity(&meta).map(str::to_owned),
        dist_tarball: dist
            .get("tarball")
            .and_then(Value::as_str)
            .map(str::to_owned),
        install_hooks: HookCommand::from_scripts(&tarball_scripts),
        scripts_sha256: tarball_scripts.sha256(),
        packument_install_hooks: HookCommand::from_scripts(&packument_scripts),
        packument_scripts_sha256: packument_scripts.sha256(),
        scripts_match_packument,
        script_delta: delta,
        pin_audit: None,
        maintainers: maintainers(&meta, packument),
        npm_user: meta
            .get("_npmUser")
            .and_then(Value::as_object)
            .and_then(|user| user.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        provenance: provenance(&dist),
        file_count: Measured {
            registry: dist.get("fileCount").and_then(Value::as_u64),
            observed: scan.file_count,
        },
        unpacked_size: Measured {
            registry: dist.get("unpackedSize").and_then(Value::as_u64),
            observed: scan.unpacked_bytes,
        },
        compressed_bytes: scan.compressed_bytes,
        files: scan
            .files
            .iter()
            .take(MAX_REPORTED_FILES)
            .cloned()
            .collect(),
        files_truncated: scan.files.len() > MAX_REPORTED_FILES,
        limits,
        notes,
    }
}

/// The install hooks a packument version declares, with hashes — used by `npmfilter_allow`.
pub fn packument_hooks(meta: &Value) -> Vec<HookCommand> {
    install_hooks(meta)
        .into_iter()
        .map(|(hook, command)| HookCommand::new(hook, command))
        .collect()
}

fn maintainers(meta: &Value, packument: &Value) -> Vec<String> {
    let list = meta
        .get("maintainers")
        .and_then(Value::as_array)
        .or_else(|| packument.get("maintainers").and_then(Value::as_array));
    let Some(list) = list else {
        return Vec::new();
    };
    list.iter()
        .map(|entry| match entry {
            Value::String(text) => text.clone(),
            Value::Object(fields) => {
                let name = fields.get("name").and_then(Value::as_str).unwrap_or("?");
                match fields.get("email").and_then(Value::as_str) {
                    Some(email) => format!("{name} <{email}>"),
                    None => name.to_owned(),
                }
            }
            other => other.to_string(),
        })
        .collect()
}

fn provenance(dist: &Value) -> Provenance {
    let attestations = dist.get("attestations");
    let predicate_types = attestations
        .and_then(|value| value.get("provenance"))
        .and_then(Value::as_object)
        .and_then(|provenance| provenance.get("predicateType"))
        .and_then(Value::as_str)
        .map(|predicate| vec![predicate.to_owned()])
        .unwrap_or_default();
    Provenance {
        attested: attestations.is_some_and(|value| !value.is_null()),
        url: attestations
            .and_then(|value| value.get("url"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        predicate_types,
        signatures: dist
            .get("signatures")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0),
    }
}

fn describe_age(days: i64) -> String {
    if days < 0 {
        return format!("published {} day(s) in the future", -days);
    }
    match days {
        0 => "today".to_owned(),
        1 => "1 day old".to_owned(),
        other => format!("{other} days old"),
    }
}

// -- streaming plumbing ---------------------------------------------------------------------

/// A byte counter shared with the reader that feeds it.
#[derive(Debug, Default)]
struct Meter {
    bytes: AtomicU64,
    tripped: AtomicBool,
}

/// A reader that fails once it has produced more than `limit` bytes.
struct MeteredReader<R> {
    inner: R,
    meter: Arc<Meter>,
    limit: u64,
}

impl<R: Read> Read for MeteredReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        let total = self
            .meter
            .bytes
            .fetch_add(u64::try_from(read).unwrap_or(0), Ordering::Relaxed)
            .saturating_add(u64::try_from(read).unwrap_or(0));
        if total > self.limit {
            self.meter.tripped.store(true, Ordering::Relaxed);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "npmfilter: tarball size limit exceeded",
            ));
        }
        Ok(read)
    }
}

/// A blocking [`Read`] over an async byte stream, so the tar reader never touches the runtime.
struct ChannelReader {
    receiver: mpsc::Receiver<Result<Bytes, String>>,
    current: Bytes,
    offset: usize,
}

impl ChannelReader {
    fn new(receiver: mpsc::Receiver<Result<Bytes, String>>) -> Self {
        Self {
            receiver,
            current: Bytes::new(),
            offset: 0,
        }
    }
}

impl Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.offset < self.current.len() {
                let take = buf.len().min(self.current.len() - self.offset);
                if take == 0 {
                    return Ok(0);
                }
                let mut target = &mut buf[..take];
                target.write_all(&self.current[self.offset..self.offset + take])?;
                self.offset += take;
                return Ok(take);
            }
            match self.receiver.blocking_recv() {
                Some(Ok(chunk)) => {
                    self.current = chunk;
                    self.offset = 0;
                }
                Some(Err(message)) => return Err(std::io::Error::other(message)),
                None => return Ok(0),
            }
        }
    }
}
