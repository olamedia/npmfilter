//! The in-memory packument cache — DESIGN.md "Request path".
//!
//! > Short **in-memory** packument TTL (default 60s, configurable) to avoid hammering
//! > upstream. This is metadata only, never written to disk — it is not a package cache.
//!
//! What is cached is the *upstream* document, before any policy runs. Filtering happens per
//! request, so a rule recorded through `npmfilter allow` takes effect on the very next
//! request instead of waiting out the TTL, and every request still writes its observation to
//! the integrity ledger.
//!
//! Entries are keyed by package **and** by a SHA-256 fingerprint of the client's
//! `Authorization` header, so a packument fetched with one credential can never be served to
//! a different one. The token itself is never held in the key.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Hard ceiling on how many packuments are held at once.
///
/// Expiry alone does not bound this map: one `npm install` across a monorepo resolves several
/// thousand distinct packuments inside a single 60s TTL, and every one of them is a full
/// upstream document (lodash 248 KB, `@types/node` and `aws-sdk` upwards of 10 MB). Once the
/// cache is full the oldest entries are evicted whether or not they have expired, so the
/// daemon's memory is bounded by the cap rather than by the client's working set.
pub const DEFAULT_MAX_ENTRIES: usize = 1024;

/// Hard ceiling on how much the cache holds, in estimated retained bytes.
///
/// An entry count on its own bounds nothing that matters: a packument may be
/// [`super::MAX_PACKUMENT_BYTES`] on the wire and rather more once parsed, so 1024 entries is
/// tens of gigabytes at the limit. It does not take a hostile upstream either — 1024 distinct
/// package names, or the same name under 1024 different `Authorization` headers, is an
/// unprivileged local process driving the daemon into the OOM killer and taking every
/// `npm install` on the machine down with it.
///
/// So the cache is budgeted in bytes as well, and a single document larger than the whole
/// budget is served but never held. Both are compile-time constants (DESIGN.md "Hard limits").
pub const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// What a cached packument is keyed by.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    package: String,
    credential: Option<String>,
}

impl CacheKey {
    /// Key for `package`, scoped to the credential the request carried (if any).
    pub fn new(package: impl Into<String>, authorization: Option<&[u8]>) -> Self {
        Self {
            package: package.into(),
            credential: authorization.map(fingerprint),
        }
    }

    /// The package this key belongs to.
    pub fn package(&self) -> &str {
        &self.package
    }

    /// The credential fingerprint, or `None` for an anonymous request.
    pub fn credential(&self) -> Option<&str> {
        self.credential.as_deref()
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    document: Arc<Value>,
    stored: Instant,
    /// Estimated retained size of `document`, in bytes — see [`estimate_size`].
    bytes: usize,
}

/// The map and its running byte total, kept together so they cannot drift apart.
#[derive(Debug, Default)]
struct CacheInner {
    entries: HashMap<CacheKey, CacheEntry>,
    bytes: usize,
}

impl CacheInner {
    /// Drop one entry, keeping the byte total honest.
    fn remove(&mut self, key: &CacheKey) -> Option<CacheEntry> {
        let entry = self.entries.remove(key)?;
        self.bytes = self.bytes.saturating_sub(entry.bytes);
        Some(entry)
    }
}

/// A TTL cache of upstream packuments, shared across every request handler.
///
/// Cheap to clone (the map lives behind an `Arc`) and safe under concurrent requests: the
/// lock is only ever held for a map operation, never across an `await`.
#[derive(Debug, Clone)]
pub struct PackumentCache {
    ttl: Duration,
    max_entries: usize,
    max_bytes: usize,
    inner: Arc<Mutex<CacheInner>>,
}

impl PackumentCache {
    /// A cache holding entries for `ttl`. A zero TTL disables caching.
    pub fn new(ttl: Duration) -> Self {
        Self::with_capacity(ttl, DEFAULT_MAX_ENTRIES)
    }

    /// A cache holding at most `max_entries` documents for `ttl` each, under the default byte
    /// budget.
    ///
    /// A zero capacity disables caching just as a zero TTL does.
    pub fn with_capacity(ttl: Duration, max_entries: usize) -> Self {
        Self::with_limits(ttl, max_entries, DEFAULT_MAX_BYTES)
    }

    /// A cache bounded by **both** an entry count and a byte budget.
    ///
    /// Either limit at zero disables caching.
    pub fn with_limits(ttl: Duration, max_entries: usize, max_bytes: usize) -> Self {
        Self {
            ttl,
            max_entries,
            max_bytes,
            inner: Arc::new(Mutex::new(CacheInner::default())),
        }
    }

    /// A cache holding entries for `secs` seconds — the `packument_ttl_secs` config field.
    pub fn from_secs(secs: u64) -> Self {
        Self::new(Duration::from_secs(secs))
    }

    /// How long an entry stays fresh.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The most entries this cache will ever hold.
    pub fn capacity(&self) -> usize {
        self.max_entries
    }

    /// The most bytes this cache will ever hold.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Estimated bytes currently held.
    pub fn bytes(&self) -> usize {
        self.lock().bytes
    }

    /// The cached document for `key`, if it is still fresh.
    pub fn get(&self, key: &CacheKey) -> Option<Arc<Value>> {
        self.get_at(key, Instant::now())
    }

    /// [`PackumentCache::get`] with an explicit clock, so expiry is testable without sleeping.
    pub fn get_at(&self, key: &CacheKey, now: Instant) -> Option<Arc<Value>> {
        let inner = self.lock();
        let entry = inner.entries.get(key)?;
        if self.is_fresh(entry, now) {
            Some(Arc::clone(&entry.document))
        } else {
            None
        }
    }

    /// Store `document` under `key`.
    pub fn insert(&self, key: CacheKey, document: Arc<Value>) {
        self.insert_at(key, document, Instant::now());
    }

    /// [`PackumentCache::insert`] with an explicit clock.
    pub fn insert_at(&self, key: CacheKey, document: Arc<Value>, now: Instant) {
        if self.ttl.is_zero() || self.max_entries == 0 || self.max_bytes == 0 {
            return;
        }
        let bytes = estimate_size(&document);
        let mut inner = self.lock();
        // Replacing a key frees what it held first, so the budget never counts it twice.
        inner.remove(&key);
        if bytes > self.max_bytes {
            // Serving it is fine; holding it would hand one request the whole budget.
            tracing::debug!(
                package = key.package(),
                bytes,
                budget = self.max_bytes,
                "packument is larger than the cache budget and will not be held"
            );
            return;
        }
        make_room(&mut inner, self.ttl, self.max_entries, self.max_bytes, bytes, now);
        inner.bytes = inner.bytes.saturating_add(bytes);
        inner.entries.insert(
            key,
            CacheEntry {
                document,
                stored: now,
                bytes,
            },
        );
    }

    /// How many entries are held, fresh or not.
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// Is the cache empty?
    pub fn is_empty(&self) -> bool {
        self.lock().entries.is_empty()
    }

    /// Drop every entry.
    pub fn clear(&self) {
        let mut inner = self.lock();
        inner.entries.clear();
        inner.bytes = 0;
    }

    fn is_fresh(&self, entry: &CacheEntry, now: Instant) -> bool {
        now.saturating_duration_since(entry.stored) < self.ttl
    }

    /// A poisoned cache lock is recovered rather than propagated: the map is a plain
    /// `HashMap` of immutable documents, so a panic elsewhere cannot have left it torn.
    fn lock(&self) -> MutexGuard<'_, CacheInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Make room for `incoming_bytes` more: drop what has expired, then evict oldest-stored first
/// until **both** the entry cap and the byte budget fit.
///
/// Expiry alone frees nothing when the whole working set is younger than the TTL, which is
/// exactly the shape of a large `npm install`, so the second pass is what actually bounds the
/// map.
fn make_room(
    inner: &mut CacheInner,
    ttl: Duration,
    max_entries: usize,
    max_bytes: usize,
    incoming_bytes: usize,
    now: Instant,
) {
    if fits(inner, max_entries, max_bytes, incoming_bytes) {
        return;
    }

    let mut freed = 0usize;
    inner.entries.retain(|_, entry| {
        let fresh = now.saturating_duration_since(entry.stored) < ttl;
        if !fresh {
            freed = freed.saturating_add(entry.bytes);
        }
        fresh
    });
    inner.bytes = inner.bytes.saturating_sub(freed);
    if fits(inner, max_entries, max_bytes, incoming_bytes) {
        return;
    }

    let mut by_age: Vec<(Instant, CacheKey)> = inner
        .entries
        .iter()
        .map(|(key, entry)| (entry.stored, key.clone()))
        .collect();
    by_age.sort_by(|left, right| left.0.cmp(&right.0));
    for (_, key) in by_age {
        if fits(inner, max_entries, max_bytes, incoming_bytes) {
            return;
        }
        inner.remove(&key);
    }
}

/// Is there room for one more entry of `incoming_bytes`?
fn fits(inner: &CacheInner, max_entries: usize, max_bytes: usize, incoming_bytes: usize) -> bool {
    inner.entries.len() < max_entries
        && inner.bytes.saturating_add(incoming_bytes) <= max_bytes
}

/// Estimated retained size of a parsed document, in bytes.
///
/// Walked with an explicit stack rather than by recursion: the input is an upstream-supplied
/// document, and nothing that reads one may be able to overflow the stack. The numbers are
/// per-node overheads for `serde_json`'s representation — an estimate whose only job is to
/// make a 10 MB packument cost roughly a hundred times a 100 KB one, so eviction is driven by
/// what the cache actually holds.
fn estimate_size(document: &Value) -> usize {
    const NODE: usize = 24;
    let mut total = 0usize;
    let mut stack = vec![document];
    while let Some(value) = stack.pop() {
        total = total.saturating_add(NODE);
        match value {
            Value::String(text) => total = total.saturating_add(text.len()),
            Value::Array(items) => {
                total = total.saturating_add(items.len() * 8);
                stack.extend(items.iter());
            }
            Value::Object(fields) => {
                for (key, value) in fields {
                    total = total.saturating_add(key.len() + NODE + 8);
                    stack.push(value);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    total
}

/// SHA-256 of a credential, lowercase hex. The secret itself is never stored.
fn fingerprint(secret: &[u8]) -> String {
    let digest = Sha256::digest(secret);
    let bytes = digest.as_slice();
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
