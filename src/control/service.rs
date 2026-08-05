//! The daemon-side implementation behind every control-socket operation.
//!
//! This is the **one** place a rule is written. `npmfilter allow` at a terminal, an agent
//! calling `npmfilter_allow` over MCP and `npmfilter seed` all arrive here, having crossed the
//! socket, been validated by [`super::protocol`] and been attributed to a peer the kernel
//! vouched for. Nothing else in the binary opens the state database.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use serde_json::Value;
use thiserror::Error;

use crate::config::Config;
use crate::mcp::blocks::{self, RecentBlock};
use crate::mcp::inspect::{self, InspectError, InspectReport, TarballLimits};
use crate::mcp::{
    DaemonStatus, LedgerReport, LedgerVersion, PolicyStatus, RecentBlocksReport, RuleCounts,
    RuleView, RuleWritten, RulesReport, StatusReport,
};
use crate::policy::Verdict;
use crate::proxy::{PackumentFetch, Upstream};
use crate::seed::{SeedVerification, seed_rule};
use crate::store::{
    AuditEntry, EVENT_SEED_REFUSED, NewRule, RuleFilter, ScriptSet, Severity, Store, StoreError,
};

use super::Actor;
use super::protocol::{Answer, Request, SeedArgs, SeedEntry, SeedOutcome, SeedResult};

/// Anything a control operation can fail with.
#[derive(Debug, Error)]
pub enum ControlError {
    /// The request was well-formed but asks for something that cannot be done.
    #[error("{0}")]
    Invalid(String),
    /// The package or version does not exist.
    #[error("{0}")]
    NotFound(String),
    /// The upstream registry could not be reached, or answered something unusable.
    #[error("{0}")]
    Upstream(String),
    /// The daemon itself failed.
    #[error("{0}")]
    Internal(String),
}

impl ControlError {
    /// A stable machine-readable class, carried on the wire.
    pub fn code(&self) -> &'static str {
        match self {
            ControlError::Invalid(_) => "invalid_request",
            ControlError::NotFound(_) => "not_found",
            ControlError::Upstream(_) => "upstream",
            ControlError::Internal(_) => "internal",
        }
    }
}

/// Flatten an error and its whole source chain into one line.
fn chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

/// Cap a string and neutralise control characters before it is shown or stored.
///
/// Upstream chooses the text in an error body, and an operator reads the answer in a
/// terminal. Escape sequences do not get a free ride there.
pub fn printable(raw: &str, limit: usize) -> String {
    raw.chars()
        .take(limit)
        .map(|character| {
            if character.is_control() {
                '.'
            } else {
                character
            }
        })
        .collect()
}

/// The operations the control socket exposes.
pub struct ControlService {
    config: Arc<Config>,
    store: Arc<Store>,
    upstream: Arc<Upstream>,
    limits: TarballLimits,
}

impl ControlService {
    /// Build the service from a loaded config and the daemon's open store.
    pub fn new(config: Arc<Config>, store: Arc<Store>) -> Result<Self, ControlError> {
        let upstream = Upstream::new(config.upstream_base()).map_err(|error| {
            ControlError::Internal(format!(
                "building the upstream registry client: {}",
                chain(&error)
            ))
        })?;
        Ok(Self {
            config,
            store,
            upstream: Arc::new(upstream),
            limits: TarballLimits::default(),
        })
    }

    /// Override the tarball limits — used by tests.
    pub fn with_limits(mut self, limits: TarballLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The tarball limits in force.
    pub fn limits(&self) -> TarballLimits {
        self.limits
    }

    /// The state database this service writes.
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The loaded configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Dispatch one validated request.
    pub async fn dispatch(&self, request: Request, actor: &Actor) -> Result<Answer, ControlError> {
        match request {
            Request::Status(_) => Ok(Answer::Status(Box::new(self.status().await?))),
            Request::RecentBlocks(args) => Ok(Answer::RecentBlocks(Box::new(
                self.recent_blocks(args.package, args.limit).await?,
            ))),
            Request::Inspect(args) => Ok(Answer::Inspect(Box::new(
                self.inspect(&args.package, args.version.as_deref()).await?,
            ))),
            Request::Allow(args) => Ok(Answer::Rule(Box::new(
                self.allow(&args.package, &args.version, args.reason, actor)
                    .await?,
            ))),
            Request::Deny(args) => Ok(Answer::Rule(Box::new(
                self.deny(&args.package, &args.version, args.reason, actor)
                    .await?,
            ))),
            Request::Rules(args) => Ok(Answer::Rules(Box::new(
                self.rules(args.package, args.verdict.as_deref()).await?,
            ))),
            Request::Ledger(args) => Ok(Answer::Ledger(Box::new(self.ledger(args.package).await?))),
            Request::Seed(args) => Ok(Answer::Seed(Box::new(self.seed(args, actor).await?))),
        }
    }

    /// Run a blocking store query off the async runtime.
    async fn with_store<T, F>(&self, task: F) -> Result<T, ControlError>
    where
        F: FnOnce(&Store) -> Result<T, StoreError> + Send + 'static,
        T: Send + 'static,
    {
        let store = Arc::clone(&self.store);
        match tokio::task::spawn_blocking(move || task(&store)).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(ControlError::Internal(format!(
                "npmfilter state database: {}",
                chain(&error)
            ))),
            Err(error) => Err(ControlError::Internal(format!(
                "npmfilter state task failed: {error}"
            ))),
        }
    }

    /// Fetch the full packument for a package.
    async fn packument(&self, package: &str) -> Result<Value, ControlError> {
        match self.upstream.fetch_packument(package, None).await {
            Ok(PackumentFetch::Document(document)) => Ok(document),
            Ok(PackumentFetch::Status(status)) => Err(ControlError::NotFound(format!(
                "upstream answered {} for {package} — {}",
                status.status,
                printable(&String::from_utf8_lossy(&status.body), 200)
            ))),
            Err(error) => Err(ControlError::Upstream(format!(
                "failed to fetch the packument for {package}: {}",
                chain(&error)
            ))),
        }
    }

    /// One version's metadata out of a packument.
    fn version_meta<'a>(
        packument: &'a Value,
        package: &str,
        version: &str,
    ) -> Result<&'a Value, ControlError> {
        packument
            .get("versions")
            .and_then(Value::as_object)
            .and_then(|versions| versions.get(version))
            .ok_or_else(|| {
                ControlError::NotFound(format!("{package} has no published version {version}"))
            })
    }

    /// DESIGN.md "MCP surface" — daemon health, active policy, rule counts.
    pub async fn status(&self) -> Result<StatusReport, ControlError> {
        let (allow, deny) = self.with_store(|store| store.rule_counts()).await?;
        let listen = self.config.listen;
        Ok(StatusReport {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            daemon: DaemonStatus {
                listen: listen.to_string(),
                // This answer came out of the daemon over its own control socket, so the
                // daemon is running by construction — there is nothing left to probe.
                reachable: true,
                upstream: self.config.upstream_base().to_owned(),
                checked_at: Utc::now().to_rfc3339(),
                detail: format!("the filtering proxy is serving on {listen}"),
            },
            policy: PolicyStatus {
                min_age_days: self.config.min_age_days,
                bypass_scopes: self.config.bypass_scopes.clone(),
                packument_ttl_secs: self.config.packument_ttl_secs,
            },
            rules: RuleCounts { allow, deny },
            state_path: self.config.state_path.display().to_string(),
            transport: format!(
                "unix socket {} — the daemon is the only writer of the state database",
                self.config.socket_path.display()
            ),
        })
    }

    /// DESIGN.md "MCP surface" — the entry point when an install fails.
    pub async fn recent_blocks(
        &self,
        package: Option<String>,
        limit: Option<u32>,
    ) -> Result<RecentBlocksReport, ControlError> {
        let limit = limit
            .unwrap_or(crate::mcp::DEFAULT_RECENT_LIMIT)
            .min(crate::mcp::MAX_RECENT_LIMIT);
        let wanted = usize::try_from(limit).unwrap_or(usize::MAX);
        // Approvals and denials share the audit table, so read wider and filter to blocks.
        let scan = wanted.saturating_mul(4).max(wanted);
        let filter = package.clone();
        let records = self
            .with_store(move |store| store.recent_audit(filter.as_deref(), scan))
            .await?;

        let blocks: Vec<RecentBlock> = records
            .iter()
            .filter(|record| blocks::is_block(record))
            .take(wanted)
            .map(blocks::from_audit)
            .collect();

        let note = if blocks.is_empty() {
            "no blocks recorded. Either nothing has been withheld yet, or the daemon has not \
             served a request since the state database was created — npmfilter only records a \
             block when npm actually asks for the package."
                .to_owned()
        } else {
            "newest first. Use npmfilter_inspect on anything you are considering approving."
                .to_owned()
        };

        Ok(RecentBlocksReport {
            package,
            count: blocks.len(),
            blocks,
            note,
        })
    }

    /// DESIGN.md "MCP surface" — stream the tarball, read only `package.json`, discard the rest.
    pub async fn inspect(
        &self,
        package: &str,
        version: Option<&str>,
    ) -> Result<InspectReport, ControlError> {
        let packument = self.packument(package).await?;
        let (version, source) =
            inspect::resolve_version(&packument, package, version).map_err(inspect_error)?;

        let meta = Self::version_meta(&packument, package, &version)?;
        let tarball = meta
            .get("dist")
            .and_then(|dist| dist.get("tarball"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                inspect_error(InspectError::NoTarball {
                    package: package.to_owned(),
                    version: version.clone(),
                })
            })?
            .to_owned();

        let scan = inspect::fetch_and_scan(self.upstream.client(), &tarball, self.limits)
            .await
            .map_err(inspect_error)?;

        Ok(inspect::build_report(
            package,
            &version,
            &source,
            &packument,
            &scan,
            self.limits,
            Utc::now(),
        ))
    }

    /// DESIGN.md "MCP surface" — approval pinned to the current integrity and script hashes.
    pub async fn allow(
        &self,
        package: &str,
        version: &str,
        reason: Option<String>,
        actor: &Actor,
    ) -> Result<RuleWritten, ControlError> {
        let packument = self.packument(package).await?;
        let meta = Self::version_meta(&packument, package, version)?;
        let integrity = crate::policy::version_integrity(meta).ok_or_else(|| {
            ControlError::Invalid(format!(
                "{package}@{version} publishes no dist.integrity, so no approval can be pinned \
                 to it"
            ))
        })?;
        let scripts = ScriptSet::from_version(meta);
        let hooks = inspect::packument_hooks(meta);

        let mut rule = NewRule::allow(package, version, integrity)
            .with_scripts(scripts)
            .with_actor(actor.render());
        if let Some(reason) = reason {
            rule = rule.with_reason(reason);
        }

        let now = Utc::now();
        let stored = self
            .with_store(move |store| store.record_rule_audited(&rule, now))
            .await?;

        // What this approval actually does right now. Reporting "is now admitted" for a
        // version the quarantine floor still withholds would be a claim the daemon knows to
        // be false, and the operator would only discover it when the install failed anyway.
        let commands = hooks
            .iter()
            .map(|hook| format!("{}: {}", hook.hook, hook.command))
            .collect::<Vec<_>>()
            .join("; ");
        let quarantine_days = self.config.install_script_quarantine_days;
        let published = crate::policy::published_at(&packument, version);
        let clears_at = (!hooks.is_empty() && quarantine_days > 0)
            .then(|| published.map(|at| at + chrono::Duration::days(i64::from(quarantine_days))))
            .flatten()
            .filter(|clears_at| *clears_at > now);

        let effect = match (&clears_at, hooks.is_empty()) {
            (Some(clears_at), _) => format!(
                "{package}@{version} is NOT admitted yet: it runs {commands} on install and is \
                 inside the {quarantine_days}-day quarantine floor, which no approval overrides. \
                 The rule is recorded and takes effect at {}, with no further action needed.",
                clears_at.to_rfc3339()
            ),
            (None, true) => {
                format!("{package}@{version} is now admitted while its dist.integrity is unchanged")
            }
            (None, false) => format!(
                "{package}@{version} is now admitted, and npm will run {commands} on install, \
                 while its dist.integrity is unchanged. The daemon picks this up on its next \
                 request."
            ),
        };

        Ok(RuleWritten {
            rule: RuleView::from_stored(&stored),
            effect,
        })
    }

    /// DESIGN.md "MCP surface" — block a version outright.
    pub async fn deny(
        &self,
        package: &str,
        version: &str,
        reason: Option<String>,
        actor: &Actor,
    ) -> Result<RuleWritten, ControlError> {
        let mut rule = NewRule::deny(package, version).with_actor(actor.render());
        if let Some(reason) = reason {
            rule = rule.with_reason(reason);
        }

        let now = Utc::now();
        let stored = self
            .with_store(move |store| store.record_rule_audited(&rule, now))
            .await?;

        Ok(RuleWritten {
            rule: RuleView::from_stored(&stored),
            effect: format!(
                "{package}@{version} is now withheld from every install, whatever its age or \
                 install hooks. The daemon picks this up on its next request."
            ),
        })
    }

    /// DESIGN.md "MCP surface" — list existing rules.
    pub async fn rules(
        &self,
        package: Option<String>,
        verdict: Option<&str>,
    ) -> Result<RulesReport, ControlError> {
        let verdict = match verdict {
            None => None,
            Some("allow") => Some(Verdict::Allow),
            Some("deny") => Some(Verdict::Deny),
            Some(other) => {
                return Err(ControlError::Invalid(format!(
                    "verdict must be \"allow\" or \"deny\", got {:?}",
                    printable(other, 32)
                )));
            }
        };

        let filter = RuleFilter {
            name: package,
            verdict,
        };
        let stored = self
            .with_store(move |store| store.list_rules(&filter))
            .await?;
        let rules: Vec<RuleView> = stored.iter().map(RuleView::from_stored).collect();

        Ok(RulesReport {
            count: rules.len(),
            rules,
        })
    }

    /// DESIGN.md "MCP surface" — integrity history and any replacement events.
    pub async fn ledger(&self, package: String) -> Result<LedgerReport, ControlError> {
        let name = package.clone();
        let history = self
            .with_store(move |store| store.ledger_history(&name))
            .await?;
        let name = package.clone();
        let audit = self
            .with_store(move |store| {
                store.recent_audit(
                    Some(&name),
                    usize::try_from(crate::mcp::MAX_RECENT_LIMIT).unwrap_or(500),
                )
            })
            .await?;

        let versions: Vec<LedgerVersion> = history
            .into_iter()
            .map(|(version, entry)| LedgerVersion {
                version,
                integrity: entry.integrity,
                first_seen: entry.first_seen.to_rfc3339(),
                last_seen: entry.last_seen.to_rfc3339(),
                times_seen: entry.times_seen,
                mismatch_count: entry.mismatch_count,
                last_mismatch: entry.last_mismatch.map(|at| at.to_rfc3339()),
            })
            .collect();

        let integrity_changed: Vec<RecentBlock> = audit
            .iter()
            .filter(|record| record.entry.event == crate::store::EVENT_TAMPER)
            .map(blocks::from_audit)
            .collect();

        let mismatches: u64 = versions.iter().map(|version| version.mismatch_count).sum();
        let note = if mismatches == 0 && integrity_changed.is_empty() {
            "no version of this package has ever changed hash since npmfilter first saw it."
                .to_owned()
        } else {
            format!(
                "AT LEAST ONE VERSION CHANGED HASH after npmfilter first recorded it, and the \
                 daemon has served {mismatches} mismatched observation(s) since. npm versions \
                 are immutable, so this is version replacement — treat it as a compromise until \
                 proven otherwise. The recorded hash below is the FIRST one observed and is \
                 never overwritten; no allow rule can rescue a version in this state."
            )
        };

        Ok(LedgerReport {
            package,
            count: versions.len(),
            versions,
            integrity_changed,
            note,
        })
    }

    /// `npmfilter seed` — verify what a tree claims, then approve it.
    ///
    /// The client read `dist.integrity` out of a lockfile on disk. That file is exactly as
    /// trustworthy as the tree it describes, which is the thing being vetted, so the daemon
    /// does not take its word for anything: for every entry it fetches the packument upstream
    /// and confirms both the integrity **and** the install-hook commands match what the
    /// registry actually serves. An entry that does not match gets no rule and is reported.
    pub async fn seed(&self, args: SeedArgs, actor: &Actor) -> Result<SeedResult, ControlError> {
        let SeedArgs {
            root,
            dry_run,
            offline,
            entries,
        } = args;
        let root = printable(&root, super::protocol::MAX_PATH_BYTES);
        let upstream = self.config.upstream_base().to_owned();
        let now = Utc::now();

        let mut packuments: HashMap<String, Option<Value>> = HashMap::new();
        let mut outcomes = Vec::with_capacity(entries.len());
        let mut verified = 0usize;
        let mut written = 0usize;
        let mut refused = 0usize;

        for entry in entries {
            let verdict = if offline {
                Ok(SeedVerification::Unverified {
                    upstream: upstream.clone(),
                })
            } else {
                self.verify_seed_entry(&entry, &upstream, &mut packuments)
                    .await
            };

            match verdict {
                Ok(verification) => {
                    if matches!(verification, SeedVerification::Verified { .. }) {
                        verified += 1;
                    }
                    if dry_run {
                        outcomes.push(SeedOutcome {
                            name: entry.name.clone(),
                            version: entry.version.clone(),
                            status: if offline { "unverified" } else { "verified" }.to_owned(),
                            detail: verification.detail(),
                        });
                        continue;
                    }
                    let rule = seed_rule(&entry, &root, &verification, &actor.render(), now);
                    self.with_store(move |store| store.record_rule_audited(&rule, now))
                        .await?;
                    written += 1;
                    outcomes.push(SeedOutcome {
                        name: entry.name.clone(),
                        version: entry.version.clone(),
                        status: "written".to_owned(),
                        detail: verification.detail(),
                    });
                }
                Err(detail) => {
                    refused += 1;
                    let audit = AuditEntry {
                        ts: now,
                        event: EVENT_SEED_REFUSED.to_owned(),
                        severity: Severity::Warning,
                        name: entry.name.clone(),
                        version: Some(entry.version.clone()),
                        detail: detail.clone(),
                    };
                    // A refusal that is not recorded is a refusal nobody can review later.
                    self.with_store(move |store| store.append_audit(&audit).map(|_| ()))
                        .await?;
                    outcomes.push(SeedOutcome {
                        name: entry.name,
                        version: entry.version,
                        status: "refused".to_owned(),
                        detail,
                    });
                }
            }
        }

        let note = if offline {
            format!(
                "OFFLINE SEED — nothing was checked against {upstream}. Every rule written here \
                 is pinned to a hash read out of a lockfile on disk, and a lockfile is exactly \
                 as trustworthy as the tree it describes. Re-run without --offline to have the \
                 daemon confirm each hash against the registry."
            )
        } else if refused == 0 {
            format!("every entry was confirmed against {upstream} before it was approved.")
        } else {
            format!(
                "{refused} entr(y/ies) did NOT match what {upstream} serves and were refused. A \
                 lockfile hash that disagrees with the registry means the tree on disk is not \
                 the artefact the registry published — establish why before approving anything."
            )
        };

        Ok(SeedResult {
            dry_run,
            offline,
            verified,
            written,
            refused,
            outcomes,
            note,
        })
    }

    /// Confirm one seed entry against the registry. `Err` carries the refusal message.
    async fn verify_seed_entry(
        &self,
        entry: &SeedEntry,
        upstream: &str,
        packuments: &mut HashMap<String, Option<Value>>,
    ) -> Result<SeedVerification, String> {
        if !packuments.contains_key(&entry.name) {
            let fetched = self.packument(&entry.name).await.ok();
            packuments.insert(entry.name.clone(), fetched);
        }
        let Some(Some(packument)) = packuments.get(&entry.name) else {
            return Err(format!(
                "{}@{}: {upstream} did not serve a packument for this package, so the hash on \
                 disk could not be confirmed; no rule was written",
                entry.name, entry.version
            ));
        };
        let Some(meta) = packument
            .get("versions")
            .and_then(Value::as_object)
            .and_then(|versions| versions.get(&entry.version))
        else {
            return Err(format!(
                "{}@{}: {upstream} publishes no such version, so the tree on disk is not what \
                 the registry serves; no rule was written",
                entry.name, entry.version
            ));
        };

        let published = crate::policy::version_integrity(meta);
        if published != Some(entry.integrity.as_str()) {
            // Neither value is reproduced: one is upstream's and one came off disk, and this
            // message is read in a terminal. Fingerprints are enough to correlate.
            return Err(format!(
                "{}@{}: the dist.integrity in {} (fingerprint {}) is NOT the one {upstream} \
                 serves (fingerprint {}). A published npm version is immutable, so these must \
                 agree; no rule was written",
                entry.name,
                entry.version,
                printable(&entry.integrity_source, 128),
                crate::policy::fingerprint(Some(entry.integrity.as_str())),
                crate::policy::fingerprint(published),
            ));
        }

        let on_disk = ScriptSet::from_hooks(entry.hooks.clone());
        let upstream_scripts = crate::policy::scripts_sha256(meta);
        if on_disk.sha256() != upstream_scripts {
            return Err(format!(
                "{}@{}: the install-hook commands in the installed package.json (sha256 {}) are \
                 not the ones {upstream} publishes for this version (sha256 {}). An allow rule \
                 pinned to the on-disk commands would be refused by the daemon's own gate; no \
                 rule was written",
                entry.name,
                entry.version,
                on_disk.sha256(),
                upstream_scripts,
            ));
        }

        Ok(SeedVerification::Verified {
            upstream: upstream.to_owned(),
        })
    }
}

/// Render an inspection failure with the right error class.
fn inspect_error(error: InspectError) -> ControlError {
    let message = chain(&error);
    match error {
        InspectError::UnknownVersion { .. } | InspectError::NoTarball { .. } => {
            ControlError::NotFound(message)
        }
        _ => ControlError::Upstream(message),
    }
}
