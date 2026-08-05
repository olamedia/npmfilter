//! In-memory [`RuleStore`] and [`IntegrityLedger`] implementations.
//!
//! These are the reference implementations the engine is tested against, and what the
//! step 3 proxy runs on until step 4 lands the SQLite-backed stores. They hold the same
//! shape as the `rules` and `seen` tables of DESIGN.md "Rules store".

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Utc};

use super::{IntegrityLedger, LedgerCheck, Rule, RuleStore};

/// A row of the `seen` table — the trust-on-first-use integrity ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    /// The `dist.integrity` recorded the first time this version was observed.
    pub integrity: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub times_seen: u64,
    /// How many times a *different* integrity has been observed for this version. The
    /// recorded hash never moves; this counter is what makes repeated replacement attempts
    /// visible.
    pub mismatch_count: u64,
    /// When the most recent mismatch was observed.
    pub last_mismatch: Option<DateTime<Utc>>,
}

/// An in-memory rules store keyed by `(name, version)`.
#[derive(Debug, Default)]
pub struct InMemoryRules {
    rules: HashMap<(String, String), Rule>,
}

impl InMemoryRules {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a rule, replacing any existing rule for the same `(name, version)`.
    pub fn insert(&mut self, rule: Rule) {
        self.rules
            .insert((rule.name.clone(), rule.version.clone()), rule);
    }

    /// Record a rule, builder style.
    pub fn with(mut self, rule: Rule) -> Self {
        self.insert(rule);
        self
    }

    /// How many rules are stored.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl RuleStore for InMemoryRules {
    fn lookup(&self, name: &str, version: &str) -> Option<Rule> {
        self.rules
            .get(&(name.to_owned(), version.to_owned()))
            .cloned()
    }
}

/// An in-memory trust-on-first-use integrity ledger.
///
/// Uses interior mutability so the engine can observe through a shared reference. A poisoned
/// lock is recovered rather than propagated: the ledger must never bring down a request.
#[derive(Debug, Default)]
pub struct InMemoryLedger {
    entries: Mutex<HashMap<(String, String), LedgerEntry>>,
}

impl InMemoryLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-seed an observation, as if the daemon had seen it at `first_seen`.
    pub fn seed(
        &self,
        name: &str,
        version: &str,
        integrity: Option<&str>,
        first_seen: DateTime<Utc>,
    ) {
        let mut entries = self.lock();
        entries.insert(
            (name.to_owned(), version.to_owned()),
            LedgerEntry {
                integrity: integrity.map(str::to_owned),
                first_seen,
                last_seen: first_seen,
                times_seen: 1,
                mismatch_count: 0,
                last_mismatch: None,
            },
        );
    }

    /// The recorded entry for a version, if any.
    pub fn entry(&self, name: &str, version: &str) -> Option<LedgerEntry> {
        self.lock()
            .get(&(name.to_owned(), version.to_owned()))
            .cloned()
    }

    /// How many `(name, version)` pairs have been observed.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(String, String), LedgerEntry>> {
        match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl IntegrityLedger for InMemoryLedger {
    fn observe(
        &self,
        name: &str,
        version: &str,
        integrity: Option<&str>,
        now: DateTime<Utc>,
    ) -> LedgerCheck {
        let mut entries = self.lock();
        match entries.get_mut(&(name.to_owned(), version.to_owned())) {
            Some(entry) => {
                if entry.integrity.as_deref() == integrity {
                    entry.last_seen = now;
                    entry.times_seen = entry.times_seen.saturating_add(1);
                    LedgerCheck::Match
                } else {
                    // The recorded hash is evidence and is never overwritten by a later,
                    // different observation. Only the mismatch bookkeeping moves.
                    entry.mismatch_count = entry.mismatch_count.saturating_add(1);
                    entry.last_mismatch = Some(now);
                    LedgerCheck::Changed {
                        recorded: entry.integrity.clone(),
                    }
                }
            }
            None => {
                entries.insert(
                    (name.to_owned(), version.to_owned()),
                    LedgerEntry {
                        integrity: integrity.map(str::to_owned),
                        first_seen: now,
                        last_seen: now,
                        times_seen: 1,
                        mismatch_count: 0,
                        last_mismatch: None,
                    },
                );
                LedgerCheck::Unseen
            }
        }
    }
}
