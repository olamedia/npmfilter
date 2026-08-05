//! SQLite-backed rules store, integrity ledger and audit log — DESIGN.md "Rules store".
//!
//! One file holds all three tables:
//!
//! * `rules` — operator allow/deny verdicts, pinned to `(name, version, dist.integrity)` plus a
//!   sha256 over the exact install-hook commands that were approved.
//! * `seen` — the trust-on-first-use integrity ledger. Written for **every** version the daemon
//!   observes, including blocked ones, so the quarantine window doubles as an observation window.
//!   A recorded hash is evidence and is **never** overwritten by a later, differing observation.
//! * `audit` — every block / allow / tamper event, with a severity.
//!
//! [`Store`] implements the [`RuleStore`] and [`IntegrityLedger`] traits the policy engine takes,
//! so `policy::evaluate(&packument, &store, &store, …)` runs the real gates against real storage.
//! The ledger check stays policy step 0: an allow rule cannot rescue a version whose integrity
//! moved, because [`crate::policy::evaluate`] consults the ledger before it looks at any rule.
//!
//! Both trait methods are infallible by signature, so a storage failure has to be resolved here.
//! It is resolved **fail-closed**: a broken database denies versions rather than serving them,
//! and logs the error at `ERROR` level.

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::policy::{
    BlockRecord, IntegrityLedger, LedgerCheck, LedgerEntry, Rule, RuleStore, Verdict, install_hooks,
};

/// Where the state database lives when the config does not say otherwise (DESIGN.md
/// "Rules store").
pub const DEFAULT_STATE_PATH: &str = "/var/lib/npmfilter/rules.db";

/// The schema version this binary understands. Bumped when a migration is added.
///
/// v2 added `seen.mismatch_count` and `seen.last_mismatch_ts`: the recorded hash stays frozen
/// because it is the evidence, but repeated replacement attempts have to be countable.
///
/// v3 drops every `seen` row whose `integrity` is `NULL`. Those rows were written by earlier
/// binaries for versions publishing no `dist.integrity`, and they were evidence of nothing:
/// the comparison `NULL == NULL` reported *unchanged* on every later observation whatever
/// upstream served. The ledger now records [`crate::policy::version_identity`], which falls
/// back to `dist.shasum`, so those versions are re-observed under a value that can actually
/// change — and a version publishing no hash at all is withheld
/// ([`crate::policy::BlockReason::NoIntegrity`]) rather than recorded as `NULL` again.
pub const SCHEMA_VERSION: i64 = 3;

/// How long a `seen` row survives without being observed again.
///
/// The ledger is evidence, so this is deliberately long and deliberately narrow: a row is only
/// dropped when it has not been observed for this many days **and** has never recorded a
/// mismatch **and** no rule refers to it. Without any retention the table grows for ever —
/// one hostile packument is hundreds of thousands of permanent rows — and a full disk fails
/// every store write, which fails closed into "no npm install works on this machine".
///
/// The cost is stated plainly: a version nobody has resolved for a year loses its
/// trust-on-first-use baseline and is re-pinned to whatever is served next.
pub const SEEN_RETENTION_DAYS: i64 = 365;

/// How long a writer waits for a competing writer before giving up.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Audit event for a version withheld by one of the automatic gates or a deny rule.
pub const EVENT_BLOCK: &str = "block";
/// Audit event for an approval being recorded.
pub const EVENT_ALLOW: &str = "allow";
/// Audit event for a deny rule being recorded.
pub const EVENT_DENY: &str = "deny";
/// Audit event for an integrity mismatch — the strongest signal the daemon can produce.
pub const EVENT_TAMPER: &str = "tamper";
/// Audit event for a mutating HTTP request relayed upstream because the operator set
/// `allow_publish_passthrough = true`. The `Authorization` value is never recorded.
pub const EVENT_PUBLISH: &str = "publish_passthrough";
/// Audit event for an upstream serving `dist.tarball` URLs on a host that is not the
/// configured upstream. Recorded once per package: npmfilter relays the URL untouched
/// (DESIGN.md "Tarballs — pass-through"), so the operator is told rather than left to
/// discover it.
pub const EVENT_FOREIGN_TARBALL: &str = "foreign_tarball";
/// Audit event for a `seed` entry the daemon refused to trust — the lockfile's integrity or
/// install hooks did not match what upstream serves.
pub const EVENT_SEED_REFUSED: &str = "seed_refused";

/// The schema of DESIGN.md "Rules store", applied on first open.
const SCHEMA_SQL: &str = "\
CREATE TABLE IF NOT EXISTS rules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL,
    version        TEXT    NOT NULL,
    integrity      TEXT,
    verdict        TEXT    NOT NULL CHECK (verdict IN ('allow', 'deny')),
    scripts_json   TEXT,
    scripts_sha256 TEXT,
    reason         TEXT,
    actor          TEXT,
    created_ts     INTEGER NOT NULL,
    UNIQUE (name, version)
);
CREATE INDEX IF NOT EXISTS rules_name_idx ON rules (name);

CREATE TABLE IF NOT EXISTS seen (
    name             TEXT    NOT NULL,
    version          TEXT    NOT NULL,
    integrity        TEXT,
    first_seen_ts    INTEGER NOT NULL,
    last_seen_ts     INTEGER NOT NULL,
    times_seen       INTEGER NOT NULL,
    mismatch_count   INTEGER NOT NULL DEFAULT 0,
    last_mismatch_ts INTEGER,
    PRIMARY KEY (name, version)
);

CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    event    TEXT    NOT NULL,
    severity TEXT    NOT NULL,
    name     TEXT    NOT NULL,
    version  TEXT,
    detail   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_ts_idx ON audit (ts DESC, id DESC);
CREATE INDEX IF NOT EXISTS audit_name_idx ON audit (name);
";

/// Columns of `rules`, in the order every `SELECT` below reads them.
const RULE_COLUMNS: &str = "id, name, version, integrity, verdict, scripts_json, scripts_sha256, reason, actor, created_ts";

/// Anything that can go wrong talking to the state database.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("failed to create the npmfilter state directory {path}")]
    StateDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to open the npmfilter database at {path}")]
    Open {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("failed to migrate the npmfilter database")]
    Migrate(#[source] rusqlite::Error),
    #[error("failed to restrict the permissions of {path}")]
    Permissions {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("npmfilter database query failed")]
    Query(#[from] rusqlite::Error),
    #[error(
        "the npmfilter database is at schema version {found}, newer than the {supported} this binary understands"
    )]
    SchemaTooNew { found: i64, supported: i64 },
    #[error("the rules table holds an unknown verdict {0:?}")]
    UnknownVerdict(String),
    #[error("the audit table holds an unknown severity {0:?}")]
    UnknownSeverity(String),
    #[error("stored timestamp {0} is not a representable date")]
    BadTimestamp(i64),
}

/// How loud an audit event is. `Critical` is DESIGN.md's "critical audit event".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Routine bookkeeping — an approval recorded, a version served.
    Info,
    /// A version was withheld by an automatic gate or a deny rule.
    Warning,
    /// An integrity mismatch: a published version's bytes moved under a fixed version number.
    Critical,
}

impl Severity {
    /// Stable string form, as stored in the `audit` table.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }

    /// Parse the stored string form.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "info" => Some(Severity::Info),
            "warning" => Some(Severity::Warning),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The exact install-hook commands an approval is bound to.
///
/// The map is kept sorted, so [`ScriptSet::json`] and [`ScriptSet::sha256`] depend only on the
/// hook names and their commands — never on the order they arrived in (DESIGN.md: "`scripts_sha256`
/// is taken over the sorted install-hook map").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScriptSet {
    hooks: BTreeMap<String, String>,
}

impl ScriptSet {
    /// An empty set — a version that declares no install hooks at all.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from any hook/command pairs; later duplicates of a hook win.
    pub fn from_hooks<K, V, I>(hooks: I) -> Self
    where
        K: Into<String>,
        V: Into<String>,
        I: IntoIterator<Item = (K, V)>,
    {
        Self {
            hooks: hooks
                .into_iter()
                .map(|(hook, command)| (hook.into(), command.into()))
                .collect(),
        }
    }

    /// The `preinstall` / `install` / `postinstall` commands a packument version declares.
    pub fn from_version(meta: &Value) -> Self {
        Self::from_hooks(install_hooks(meta))
    }

    /// The hooks, sorted by name.
    pub fn hooks(&self) -> &BTreeMap<String, String> {
        &self.hooks
    }

    /// How many hooks are in the set.
    pub fn len(&self) -> usize {
        self.hooks.len()
    }

    /// Whether the version declares no install hooks.
    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    /// The canonical JSON of the sorted hook map — what the `scripts_json` column stores.
    pub fn json(&self) -> String {
        let mut object = JsonMap::new();
        for (hook, command) in &self.hooks {
            object.insert(hook.clone(), Value::String(command.clone()));
        }
        // `serde_json::Map` is a `BTreeMap` here (no `preserve_order` feature), so the rendered
        // keys are sorted and the text is stable for a given set of hooks.
        Value::Object(object).to_string()
    }

    /// sha256 over [`ScriptSet::json`], lowercase hex — what the `scripts_sha256` column stores.
    pub fn sha256(&self) -> String {
        hex_encode(Sha256::digest(self.json().as_bytes()).as_slice())
    }
}

/// A rule about to be recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRule {
    pub name: String,
    pub version: String,
    pub verdict: Verdict,
    /// The `dist.integrity` an allow rule is pinned to.
    pub integrity: Option<String>,
    /// The install hooks the approval covers.
    pub scripts: Option<ScriptSet>,
    pub reason: Option<String>,
    pub actor: Option<String>,
}

impl NewRule {
    /// An approval pinned to `integrity`.
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
            scripts: None,
            reason: None,
            actor: None,
        }
    }

    /// An outright block.
    pub fn deny(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            verdict: Verdict::Deny,
            integrity: None,
            scripts: None,
            reason: None,
            actor: None,
        }
    }

    /// Bind the rule to the exact install-hook commands.
    pub fn with_scripts(mut self, scripts: ScriptSet) -> Self {
        self.scripts = Some(scripts);
        self
    }

    /// Why the rule exists.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Who recorded it.
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// The audit entry that goes with recording this rule.
    pub fn audit_entry(&self, ts: DateTime<Utc>) -> AuditEntry {
        let (event, severity) = match self.verdict {
            Verdict::Allow => (EVENT_ALLOW, Severity::Info),
            Verdict::Deny => (EVENT_DENY, Severity::Warning),
        };
        let mut detail = match self.verdict {
            Verdict::Allow => format!(
                "approved, pinned to {}",
                self.integrity.as_deref().unwrap_or("<no dist.integrity>")
            ),
            Verdict::Deny => "denied".to_owned(),
        };
        if let Some(reason) = &self.reason {
            detail.push_str(": ");
            detail.push_str(reason);
        }
        AuditEntry {
            ts,
            event: event.to_owned(),
            severity,
            name: self.name.clone(),
            version: Some(self.version.clone()),
            detail,
        }
    }
}

/// A row of the `rules` table as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRule {
    pub id: i64,
    /// The part the policy engine consumes.
    pub rule: Rule,
    /// The canonical JSON of the approved install hooks.
    pub scripts_json: Option<String>,
    pub created: DateTime<Utc>,
}

/// Which rules to list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleFilter {
    /// Only rules for this exact package name.
    pub name: Option<String>,
    /// Only rules with this verdict.
    pub verdict: Option<Verdict>,
}

impl RuleFilter {
    /// Every rule.
    pub fn all() -> Self {
        Self::default()
    }

    /// Every rule for one package.
    pub fn for_package(name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            verdict: None,
        }
    }

    /// Narrow to one verdict.
    pub fn with_verdict(mut self, verdict: Verdict) -> Self {
        self.verdict = Some(verdict);
        self
    }
}

/// One line of the audit log, before it is written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: DateTime<Utc>,
    /// [`EVENT_BLOCK`], [`EVENT_ALLOW`], [`EVENT_DENY`] or [`EVENT_TAMPER`].
    pub event: String,
    pub severity: Severity,
    pub name: String,
    pub version: Option<String>,
    pub detail: String,
}

impl AuditEntry {
    /// The audit entry for a withheld version.
    ///
    /// An integrity mismatch — [`crate::policy::BlockReason::is_critical`] — is recorded as
    /// [`EVENT_TAMPER`] at [`Severity::Critical`]; every other gate is [`EVENT_BLOCK`] at
    /// [`Severity::Warning`]. The reason is carried in `detail`, so the row stands alone.
    pub fn block(name: impl Into<String>, record: &BlockRecord, ts: DateTime<Utc>) -> Self {
        let critical = record.reason.is_critical();
        Self {
            ts,
            event: if critical { EVENT_TAMPER } else { EVENT_BLOCK }.to_owned(),
            severity: if critical {
                Severity::Critical
            } else {
                Severity::Warning
            },
            name: name.into(),
            version: Some(record.version.clone()),
            detail: format!("{}: {}", record.reason, record.detail),
        }
    }

    /// An integrity mismatch spotted outside the policy engine — a hand-edited rule, say.
    pub fn tamper(
        name: impl Into<String>,
        version: impl Into<String>,
        detail: impl Into<String>,
        ts: DateTime<Utc>,
    ) -> Self {
        Self {
            ts,
            event: EVENT_TAMPER.to_owned(),
            severity: Severity::Critical,
            name: name.into(),
            version: Some(version.into()),
            detail: detail.into(),
        }
    }
}

/// A row of the `audit` table as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: i64,
    #[serde(flatten)]
    pub entry: AuditEntry,
}

/// The SQLite-backed rules store, integrity ledger and audit log.
///
/// Holds one connection behind a mutex: every method takes `&self`, so an axum handler can share
/// a single `Store` across tasks. A poisoned lock is recovered rather than propagated — the state
/// database must never bring down a request.
#[derive(Debug)]
pub struct Store {
    conn: Mutex<Connection>,
    path: Option<PathBuf>,
    /// The last storage failure the infallible trait impls swallowed while failing closed.
    ///
    /// [`RuleStore::lookup`] and [`IntegrityLedger::observe`] cannot return an error by
    /// signature, so a broken database withholds every version. The request path reads this
    /// slot to tell that apart from "policy withheld everything" and answers a gateway error
    /// instead of a silently empty packument.
    failure: Mutex<Option<String>>,
}

impl Store {
    /// Open (creating if needed) the database at `path`, applying the schema.
    ///
    /// Missing parent directories are created, so a fresh install works with nothing but the
    /// configured path.
    /// The database file holds the approval policy: anything that can write it can approve any
    /// package for the whole machine. It is created 0600 and its directory 0700, and the
    /// daemon is the only process that opens it — the MCP shim and the CLI go through the
    /// control socket instead.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            create_private_dir(parent)?;
            warn_if_shared(parent);
        }
        let conn = Connection::open(path).map_err(|source| StoreError::Open {
            path: path.to_path_buf(),
            source,
        })?;
        restrict_file(path)?;
        Self::prepare(conn, Some(path.to_path_buf()))
    }

    /// Open a private in-memory database. Used by tests and by `--dry-run` paths.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory().map_err(|source| StoreError::Open {
            path: PathBuf::from(":memory:"),
            source,
        })?;
        Self::prepare(conn, None)
    }

    /// Where this store lives, or `None` for an in-memory one.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    fn prepare(conn: Connection, path: Option<PathBuf>) -> Result<Self, StoreError> {
        conn.busy_timeout(BUSY_TIMEOUT)
            .map_err(StoreError::Migrate)?;
        if path.is_some() {
            // WAL keeps a reader (the proxy) from blocking the writer (an approval). The pragma
            // answers with the resulting mode, so it has to be run as a query.
            let _mode: String = conn
                .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
                .map_err(StoreError::Migrate)?;
        }
        // WAL creates `-wal` and `-shm` beside the database; they carry the same rows and
        // must not be more readable than it is.
        if let Some(path) = path.as_deref() {
            for suffix in ["-wal", "-shm"] {
                let mut sidecar = path.as_os_str().to_owned();
                sidecar.push(suffix);
                let sidecar = PathBuf::from(sidecar);
                if sidecar.exists() {
                    restrict_file(&sidecar)?;
                }
            }
        }
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            path,
            failure: Mutex::new(None),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn failure_lock(&self) -> MutexGuard<'_, Option<String>> {
        match self.failure.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Record a storage failure that a fail-closed trait impl had to swallow.
    ///
    /// The first failure of a batch is kept: it is the one that explains the rest.
    fn note_failure(&self, error: &StoreError) {
        let mut slot = self.failure_lock();
        if slot.is_none() {
            *slot = Some(error.to_string());
        }
    }

    /// Forget any recorded storage failure. Called before a policy evaluation, so what the
    /// evaluation then reports belongs to that evaluation.
    pub fn clear_failure(&self) {
        *self.failure_lock() = None;
    }

    /// Take the storage failure recorded since the last [`Store::clear_failure`], if any.
    pub fn take_failure(&self) -> Option<String> {
        self.failure_lock().take()
    }

    // -- rules ---------------------------------------------------------------------------

    /// Record an allow or deny rule, replacing any existing rule for the same `(name, version)`.
    ///
    /// This writes policy only. It never touches `seen`: the ledger is evidence, not policy, so
    /// an approval cannot rewrite what was observed.
    pub fn record_rule(
        &self,
        rule: &NewRule,
        now: DateTime<Utc>,
    ) -> Result<StoredRule, StoreError> {
        let scripts_json = rule.scripts.as_ref().map(ScriptSet::json);
        let scripts_sha256 = rule.scripts.as_ref().map(ScriptSet::sha256);
        let conn = self.lock();
        let id: i64 = conn.query_row(
            "INSERT INTO rules (name, version, integrity, verdict, scripts_json, scripts_sha256, reason, actor, created_ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (name, version) DO UPDATE SET
                 integrity      = excluded.integrity,
                 verdict        = excluded.verdict,
                 scripts_json   = excluded.scripts_json,
                 scripts_sha256 = excluded.scripts_sha256,
                 reason         = excluded.reason,
                 actor          = excluded.actor,
                 created_ts     = excluded.created_ts
             RETURNING id",
            params![
                rule.name,
                rule.version,
                rule.integrity,
                verdict_str(rule.verdict),
                scripts_json,
                scripts_sha256,
                rule.reason,
                rule.actor,
                now.timestamp(),
            ],
            |row| row.get(0),
        )?;
        Ok(StoredRule {
            id,
            rule: Rule {
                name: rule.name.clone(),
                version: rule.version.clone(),
                verdict: rule.verdict,
                integrity: rule.integrity.clone(),
                scripts_sha256,
                reason: rule.reason.clone(),
                actor: rule.actor.clone(),
            },
            scripts_json,
            created: now,
        })
    }

    /// Record a rule and append its audit entry in one transaction.
    pub fn record_rule_audited(
        &self,
        rule: &NewRule,
        now: DateTime<Utc>,
    ) -> Result<StoredRule, StoreError> {
        let stored = self.record_rule(rule, now)?;
        self.append_audit(&rule.audit_entry(now))?;
        Ok(stored)
    }

    /// The rule for one exact `(name, version)`, if any.
    pub fn try_lookup_rule(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Option<StoredRule>, StoreError> {
        let conn = self.lock();
        let raw = conn
            .query_row(
                &format!("SELECT {RULE_COLUMNS} FROM rules WHERE name = ?1 AND version = ?2"),
                params![name, version],
                rule_row,
            )
            .optional()?;
        raw.map(stored_rule).transpose()
    }

    /// Every rule matching `filter`, ordered by name then version.
    pub fn list_rules(&self, filter: &RuleFilter) -> Result<Vec<StoredRule>, StoreError> {
        let conn = self.lock();
        let mut statement = conn.prepare(&format!(
            "SELECT {RULE_COLUMNS} FROM rules
             WHERE (?1 IS NULL OR name = ?1)
               AND (?2 IS NULL OR verdict = ?2)
             ORDER BY name, version"
        ))?;
        let verdict = filter.verdict.map(verdict_str);
        let rows = statement.query_map(params![filter.name, verdict], rule_row)?;
        let mut rules = Vec::new();
        for row in rows {
            rules.push(stored_rule(row?)?);
        }
        Ok(rules)
    }

    /// How many rules are stored, by verdict — `(allow, deny)`.
    pub fn rule_counts(&self) -> Result<(u64, u64), StoreError> {
        let conn = self.lock();
        let mut counts = (0_u64, 0_u64);
        let mut statement = conn.prepare("SELECT verdict, COUNT(*) FROM rules GROUP BY verdict")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (verdict, count) = row?;
            let count = u64::try_from(count).unwrap_or_default();
            match parse_verdict(&verdict)? {
                Verdict::Allow => counts.0 = count,
                Verdict::Deny => counts.1 = count,
            }
        }
        Ok(counts)
    }

    // -- integrity ledger ----------------------------------------------------------------

    /// Trust-on-first-use: compare `integrity` against the recorded hash, recording the
    /// observation.
    ///
    /// * unseen `(name, version)` → inserted, [`LedgerCheck::Unseen`]
    /// * same hash → `last_seen_ts` and `times_seen` bumped, [`LedgerCheck::Match`]
    /// * different hash → [`LedgerCheck::Changed`], **and the stored row is left untouched**.
    ///   The first hash is the evidence; overwriting it would destroy the only proof that the
    ///   version was replaced.
    pub fn try_observe(
        &self,
        name: &str,
        version: &str,
        integrity: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<LedgerCheck, StoreError> {
        self.try_observe_with(name, version, integrity, now, true)
    }

    /// Observe every version of one packument in a **single** transaction.
    ///
    /// One `IMMEDIATE` transaction per version is what let a hostile upstream turn a single
    /// `GET` into minutes of disk-bound work: a 64 MiB packument is hundreds of thousands of
    /// versions, and each one paid for its own commit behind the connection mutex. The whole
    /// document is now one commit.
    ///
    /// Semantics per entry are exactly [`Store::try_observe_with`]'s, in the same order as
    /// `observations`, which is `(version, identity)` — the identity being
    /// [`crate::policy::version_identity`], not necessarily `dist.integrity`.
    pub fn try_observe_batch(
        &self,
        name: &str,
        observations: &[(String, Option<String>)],
        now: DateTime<Utc>,
        bump: bool,
    ) -> Result<Vec<LedgerCheck>, StoreError> {
        if observations.is_empty() {
            return Ok(Vec::new());
        }
        let mut conn = self.lock();
        // A cache hit re-runs the policy without re-recording anything, so it opens a read
        // transaction and only takes the write lock if something actually has to be written.
        let behaviour = if bump {
            TransactionBehavior::Immediate
        } else {
            TransactionBehavior::Deferred
        };
        let transaction = conn.transaction_with_behavior(behaviour)?;
        let mut checks = Vec::with_capacity(observations.len());
        {
            let mut select =
                transaction.prepare("SELECT integrity FROM seen WHERE name = ?1 AND version = ?2")?;
            let mut insert = transaction.prepare(
                "INSERT INTO seen (name, version, integrity, first_seen_ts, last_seen_ts, times_seen,
                                   mismatch_count, last_mismatch_ts)
                 VALUES (?1, ?2, ?3, ?4, ?4, 1, 0, NULL)",
            )?;
            let mut bump_seen = transaction.prepare(
                "UPDATE seen SET last_seen_ts = ?3, times_seen = times_seen + 1
                  WHERE name = ?1 AND version = ?2",
            )?;
            // The recorded hash is never overwritten — it is the only proof the version was
            // replaced. What moves is the mismatch bookkeeping.
            let mut note = transaction.prepare(
                "UPDATE seen SET mismatch_count = mismatch_count + 1, last_mismatch_ts = ?3
                  WHERE name = ?1 AND version = ?2",
            )?;
            for (version, identity) in observations {
                let recorded: Option<Option<String>> = select
                    .query_row(params![name, version], |row| row.get(0))
                    .optional()?;
                let check = match recorded {
                    Some(recorded) => {
                        if recorded.as_deref() == identity.as_deref() {
                            if bump {
                                bump_seen.execute(params![name, version, now.timestamp()])?;
                            }
                            LedgerCheck::Match
                        } else {
                            note.execute(params![name, version, now.timestamp()])?;
                            LedgerCheck::Changed { recorded }
                        }
                    }
                    None => {
                        insert.execute(params![name, version, identity, now.timestamp()])?;
                        LedgerCheck::Unseen
                    }
                };
                checks.push(check);
            }
        }
        transaction.commit()?;
        Ok(checks)
    }

    /// [`Store::try_observe`] with the `last_seen_ts` / `times_seen` bump made optional.
    ///
    /// `bump = false` compares without writing when the version is already on record. The
    /// request path uses it for a packument served from the in-memory TTL cache: the policy is
    /// re-run per request, but the observation was already recorded when that document was
    /// fetched, and re-recording it would cost one `IMMEDIATE` write transaction per version
    /// per request behind the single connection mutex. A version that has never been seen is
    /// still inserted, cache hit or not — DESIGN.md records **every** version observed.
    pub fn try_observe_with(
        &self,
        name: &str,
        version: &str,
        integrity: Option<&str>,
        now: DateTime<Utc>,
        bump: bool,
    ) -> Result<LedgerCheck, StoreError> {
        let observations = [(version.to_owned(), integrity.map(str::to_owned))];
        let checks = self.try_observe_batch(name, &observations, now, bump)?;
        // One observation in, one out. An empty answer is impossible, and if it ever happened
        // it would have to fail closed rather than let a version through unobserved.
        Ok(checks
            .into_iter()
            .next()
            .unwrap_or(LedgerCheck::Changed { recorded: None }))
    }

    /// The ledger row for one version, if it has ever been observed.
    pub fn ledger_entry(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Option<LedgerEntry>, StoreError> {
        let conn = self.lock();
        let raw = conn
            .query_row(
                "SELECT integrity, first_seen_ts, last_seen_ts, times_seen, mismatch_count,
                        last_mismatch_ts
                   FROM seen
                  WHERE name = ?1 AND version = ?2",
                params![name, version],
                ledger_row,
            )
            .optional()?;
        raw.map(ledger_entry).transpose()
    }

    /// Every observed version of a package, newest observation first — `(version, entry)`.
    pub fn ledger_history(&self, name: &str) -> Result<Vec<(String, LedgerEntry)>, StoreError> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT version, integrity, first_seen_ts, last_seen_ts, times_seen, mismatch_count,
                    last_mismatch_ts
               FROM seen
              WHERE name = ?1 ORDER BY first_seen_ts DESC, version DESC",
        )?;
        let rows = statement.query_map(params![name], |row| {
            let version: String = row.get(0)?;
            Ok((
                version,
                (
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ),
            ))
        })?;
        let mut history = Vec::new();
        for row in rows {
            let (version, raw) = row?;
            history.push((version, ledger_entry(raw)?));
        }
        Ok(history)
    }

    // -- audit ---------------------------------------------------------------------------

    /// Append one audit row, returning its id.
    pub fn append_audit(&self, entry: &AuditEntry) -> Result<i64, StoreError> {
        let conn = self.lock();
        conn.execute(
            "INSERT INTO audit (ts, event, severity, name, version, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                entry.ts.timestamp(),
                entry.event,
                entry.severity.as_str(),
                entry.name,
                entry.version,
                entry.detail,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Append one audit row per **newly** withheld version, in a single transaction.
    ///
    /// This is how the request path turns a [`crate::policy::PolicyOutcome`] into audit history:
    /// integrity mismatches land as `tamper`/`critical`, every other gate as `block`/`warning`.
    ///
    /// A verdict is only appended when it is new: if the latest row for `(name, version, event)`
    /// already carries the same [`crate::policy::BlockReason`], nothing is written. The policy
    /// runs per request against the cached document, so without this one `npm install` of a
    /// package with 478 withheld versions writes 478 identical rows on every retry, and
    /// `npmfilter_recent_blocks` answers with the same block repeated instead of the distinct
    /// recent events. Returns how many rows were actually appended.
    pub fn record_blocks(
        &self,
        name: &str,
        blocked: &[BlockRecord],
        now: DateTime<Utc>,
    ) -> Result<usize, StoreError> {
        if blocked.is_empty() {
            return Ok(0);
        }
        let mut written = 0usize;
        let mut conn = self.lock();
        let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        {
            let mut latest = transaction.prepare(
                "SELECT detail FROM audit
                 WHERE name = ?1 AND version = ?2 AND event = ?3
                 ORDER BY id DESC LIMIT 1",
            )?;
            let mut insert = transaction.prepare(
                "INSERT INTO audit (ts, event, severity, name, version, detail)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for record in blocked {
                let entry = AuditEntry::block(name, record, now);
                let previous: Option<String> = latest
                    .query_row(
                        params![entry.name, entry.version, entry.event],
                        |row| row.get(0),
                    )
                    .optional()?;
                // `AuditEntry::block` writes `"<reason>: <detail>"`, and the detail itself moves
                // (the age gate renders a live age), so the reason prefix is what identifies a
                // repeated verdict.
                let prefix = format!("{}: ", record.reason);
                if previous.is_some_and(|detail| detail.starts_with(&prefix)) {
                    continue;
                }
                insert.execute(params![
                    entry.ts.timestamp(),
                    entry.event,
                    entry.severity.as_str(),
                    entry.name,
                    entry.version,
                    entry.detail,
                ])?;
                written += 1;
            }
        }
        transaction.commit()?;
        Ok(written)
    }

    /// Delete audit rows older than `before`, returning how many went.
    ///
    /// Nothing else prunes `audit`, and a machine that reinstalls on a schedule appends to it
    /// forever. `npmfilter serve` calls this once at startup with the configured retention.
    pub fn prune_audit(&self, before: DateTime<Utc>) -> Result<usize, StoreError> {
        let conn = self.lock();
        let removed = conn.execute("DELETE FROM audit WHERE ts < ?1", params![before.timestamp()])?;
        Ok(removed)
    }

    /// Delete `seen` rows untouched since `before`, returning how many went.
    ///
    /// Three conditions, all of them required, because this table is evidence:
    ///
    /// * not observed since `before` — a version still being resolved keeps its baseline;
    /// * `mismatch_count = 0` — a row that ever recorded a replacement attempt is kept for
    ///   ever, since that is the strongest signal this daemon can produce;
    /// * no `rules` row names the same `(name, version)` — an approved or denied version keeps
    ///   the observation its verdict was formed against.
    ///
    /// Without this the ledger grows without bound, and a full disk fails every store write.
    /// Those failures are fail-closed, so the end state is a machine where no `npm install`
    /// resolves and the state database needs manual repair.
    pub fn prune_seen(&self, before: DateTime<Utc>) -> Result<usize, StoreError> {
        let conn = self.lock();
        let removed = conn.execute(
            "DELETE FROM seen
              WHERE last_seen_ts < ?1
                AND mismatch_count = 0
                AND NOT EXISTS (
                        SELECT 1 FROM rules
                         WHERE rules.name = seen.name AND rules.version = seen.version
                    )",
            params![before.timestamp()],
        )?;
        Ok(removed)
    }

    /// Append `entry` only if no row with the same `(name, event)` exists yet.
    ///
    /// For observations that are true of a *package* rather than of one request — an upstream
    /// serving tarballs on a foreign host, say — so the fact is recorded once instead of on
    /// every resolution. Returns whether a row was written.
    pub fn append_audit_once(&self, entry: &AuditEntry) -> Result<bool, StoreError> {
        let mut conn = self.lock();
        let transaction = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let seen: Option<i64> = transaction
            .query_row(
                "SELECT 1 FROM audit WHERE name = ?1 AND event = ?2 LIMIT 1",
                params![entry.name, entry.event],
                |row| row.get(0),
            )
            .optional()?;
        if seen.is_some() {
            transaction.commit()?;
            return Ok(false);
        }
        transaction.execute(
            "INSERT INTO audit (ts, event, severity, name, version, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                entry.ts.timestamp(),
                entry.event,
                entry.severity.as_str(),
                entry.name,
                entry.version,
                entry.detail,
            ],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// The most recent audit rows, newest first, optionally for one package only.
    pub fn recent_audit(
        &self,
        name: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditRecord>, StoreError> {
        let conn = self.lock();
        let mut statement = conn.prepare(
            "SELECT id, ts, event, severity, name, version, detail FROM audit
             WHERE (?1 IS NULL OR name = ?1)
             ORDER BY ts DESC, id DESC
             LIMIT ?2",
        )?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = statement.query_map(params![name, limit], audit_row)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(audit_record(row?)?);
        }
        Ok(records)
    }
}

impl RuleStore for Store {
    /// Fails closed: if the rules table cannot be read, the version is denied rather than served.
    ///
    /// The failure is also recorded on the store, so the request path can answer a gateway
    /// error rather than an empty packument that looks like an ordinary policy verdict.
    fn lookup(&self, name: &str, version: &str) -> Option<Rule> {
        match self.try_lookup_rule(name, version) {
            Ok(found) => found.map(|stored| stored.rule),
            Err(error) => {
                self.note_failure(&error);
                tracing::error!(
                    package = name,
                    version,
                    %error,
                    "rules store unavailable — failing closed and withholding this version"
                );
                Some(
                    Rule::deny(name, version)
                        .with_reason(format!("rules store unavailable: {error}")),
                )
            }
        }
    }
}

impl Store {
    /// [`IntegrityLedger::observe`] with the `seen` bookkeeping bump made optional.
    ///
    /// Fails closed: if the ledger cannot be consulted, the version is treated as changed, which
    /// is the one verdict no rule can override. The failure is recorded on the store as well, so
    /// the request path can report it instead of serving an empty packument.
    /// [`Store::try_observe_batch`], failing closed.
    ///
    /// A ledger that cannot be read reports every version as changed, which is the one verdict
    /// no rule can override, and records the failure so the request path answers a gateway
    /// error instead of an empty packument.
    pub fn observe_batch(
        &self,
        name: &str,
        observations: &[(String, Option<String>)],
        now: DateTime<Utc>,
        bump: bool,
    ) -> Vec<LedgerCheck> {
        match self.try_observe_batch(name, observations, now, bump) {
            Ok(checks) => checks,
            Err(error) => {
                self.note_failure(&error);
                tracing::error!(
                    package = name,
                    versions = observations.len(),
                    %error,
                    "integrity ledger unavailable — failing closed and withholding this packument"
                );
                vec![LedgerCheck::Changed { recorded: None }; observations.len()]
            }
        }
    }

    pub fn observe_with(
        &self,
        name: &str,
        version: &str,
        integrity: Option<&str>,
        now: DateTime<Utc>,
        bump: bool,
    ) -> LedgerCheck {
        match self.try_observe_with(name, version, integrity, now, bump) {
            Ok(check) => check,
            Err(error) => {
                self.note_failure(&error);
                tracing::error!(
                    package = name,
                    version,
                    %error,
                    "integrity ledger unavailable — failing closed and withholding this version"
                );
                LedgerCheck::Changed { recorded: None }
            }
        }
    }
}

impl IntegrityLedger for Store {
    /// Fails closed: if the ledger cannot be consulted, the version is treated as changed, which
    /// is the one verdict no rule can override.
    fn observe(
        &self,
        name: &str,
        version: &str,
        integrity: Option<&str>,
        now: DateTime<Utc>,
    ) -> LedgerCheck {
        self.observe_with(name, version, integrity, now, true)
    }
}

/// Apply the schema if this database is older than [`SCHEMA_VERSION`].
fn migrate(conn: &Connection) -> Result<(), StoreError> {
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(StoreError::Migrate)?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew {
            found: version,
            supported: SCHEMA_VERSION,
        });
    }
    if version < SCHEMA_VERSION {
        conn.execute_batch(SCHEMA_SQL)
            .map_err(StoreError::Migrate)?;
        // `CREATE TABLE IF NOT EXISTS` cannot add a column to a table that already exists, so
        // a database written by an earlier binary needs the v2 columns bolted on.
        add_missing_column(conn, "seen", "mismatch_count", "INTEGER NOT NULL DEFAULT 0")?;
        add_missing_column(conn, "seen", "last_mismatch_ts", "INTEGER")?;
        // v3: a `NULL` recorded integrity was never evidence of anything — every later
        // observation compared absent against absent and reported the version unchanged. Those
        // rows are dropped so the version is re-observed under an identity that can change
        // (`dist.shasum`, prefixed), and a version with no hash at all is now withheld outright.
        conn.execute_batch("DELETE FROM seen WHERE integrity IS NULL")
            .map_err(StoreError::Migrate)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(StoreError::Migrate)?;
    }
    Ok(())
}

/// Add `column` to `table` unless it is already there.
fn add_missing_column(
    conn: &Connection,
    table: &str,
    column: &str,
    declaration: &str,
) -> Result<(), StoreError> {
    let mut statement = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(StoreError::Migrate)?;
    let mut present = false;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(StoreError::Migrate)?;
    for row in rows {
        if row.map_err(StoreError::Migrate)? == column {
            present = true;
            break;
        }
    }
    drop(statement);
    if !present {
        conn.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {declaration}"
        ))
        .map_err(StoreError::Migrate)?;
    }
    Ok(())
}

/// Create `dir` (and its parents) with the private mode, when it does not exist yet.
///
/// `create_dir_all` applies the mode only to directories it actually creates; an existing
/// directory keeps whatever it had, which is why [`warn_if_shared`] then looks at it.
fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(|source| StoreError::StateDir {
        path: dir.to_path_buf(),
        source,
    })
}

/// Restrict one file to owner read/write.
#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|source| {
        StoreError::Permissions {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

/// Say so, loudly, if the state directory is readable or writable by anyone but its owner.
///
/// The mode of a directory this daemon did not create is not silently rewritten — the path is
/// operator-configured and could be shared with something else. It is reported instead, and
/// the packaged unit ships `StateDirectoryMode=0700` so the shipped path is already right.
#[cfg(unix)]
fn warn_if_shared(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(metadata) = std::fs::metadata(dir) else {
        return;
    };
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        tracing::warn!(
            path = %dir.display(),
            mode = format!("{mode:04o}"),
            "the npmfilter state directory is accessible beyond its owner — anything that can \
             write it can approve any package for this machine; `chmod 0700` it"
        );
    }
}

#[cfg(not(unix))]
fn warn_if_shared(_dir: &Path) {}

/// The `rules` columns, straight out of SQLite.
type RuleRow = (
    i64,
    String,
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
);

fn rule_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RuleRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
    ))
}

fn stored_rule(raw: RuleRow) -> Result<StoredRule, StoreError> {
    let (
        id,
        name,
        version,
        integrity,
        verdict,
        scripts_json,
        scripts_sha256,
        reason,
        actor,
        created,
    ) = raw;
    Ok(StoredRule {
        id,
        rule: Rule {
            name,
            version,
            verdict: parse_verdict(&verdict)?,
            integrity,
            scripts_sha256,
            reason,
            actor,
        },
        scripts_json,
        created: timestamp(created)?,
    })
}

/// The `seen` columns, straight out of SQLite.
type LedgerRow = (Option<String>, i64, i64, i64, i64, Option<i64>);

fn ledger_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LedgerRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn ledger_entry(raw: LedgerRow) -> Result<LedgerEntry, StoreError> {
    let (integrity, first_seen, last_seen, times_seen, mismatch_count, last_mismatch) = raw;
    Ok(LedgerEntry {
        integrity,
        first_seen: timestamp(first_seen)?,
        last_seen: timestamp(last_seen)?,
        times_seen: u64::try_from(times_seen).unwrap_or_default(),
        mismatch_count: u64::try_from(mismatch_count).unwrap_or_default(),
        last_mismatch: match last_mismatch {
            Some(ts) => Some(timestamp(ts)?),
            None => None,
        },
    })
}

/// The `audit` columns, straight out of SQLite.
type AuditRow = (i64, i64, String, String, String, Option<String>, String);

fn audit_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
    ))
}

fn audit_record(raw: AuditRow) -> Result<AuditRecord, StoreError> {
    let (id, ts, event, severity, name, version, detail) = raw;
    Ok(AuditRecord {
        id,
        entry: AuditEntry {
            ts: timestamp(ts)?,
            event,
            severity: Severity::parse(&severity)
                .ok_or_else(|| StoreError::UnknownSeverity(severity.clone()))?,
            name,
            version,
            detail,
        },
    })
}

/// The stored string form of a verdict.
fn verdict_str(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
    }
}

fn parse_verdict(raw: &str) -> Result<Verdict, StoreError> {
    match raw {
        "allow" => Ok(Verdict::Allow),
        "deny" => Ok(Verdict::Deny),
        other => Err(StoreError::UnknownVerdict(other.to_owned())),
    }
}

/// Turn stored unix seconds back into a UTC timestamp.
fn timestamp(secs: i64) -> Result<DateTime<Utc>, StoreError> {
    DateTime::from_timestamp(secs, 0).ok_or(StoreError::BadTimestamp(secs))
}

/// Lowercase hex, without pulling in a hex crate.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)]);
        out.push(DIGITS[usize::from(byte & 0x0f)]);
    }
    out
}
