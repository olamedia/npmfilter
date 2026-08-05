# npmfilter — threat model

What this daemon defends against, what it does not, and where the line is. Written for
someone deciding whether to put it in front of every `npm install` on a machine.

npmfilter is a local npm registry proxy that gates **resolution**. It fetches the full
packument upstream, withholds versions that are too new or that run install hooks, and
re-serializes what is left. Approvals are pinned to `dist.integrity` plus a hash of the exact
install-hook commands, and they are recorded only by the daemon.

---

## Trust boundaries

### Who can approve a package

One group: `npmfilter`. Membership means "may open `/run/npmfilter/npmfilter.sock`", which
means "may ask the daemon to write an allow or deny rule". Grant it as deliberately as
`docker`. The alternative is to run the commands as the daemon's own user
(`sudo -u npmfilter npmfilter allow …`).

The socket is mode `0660`, owner `npmfilter:npmfilter`, in a `0750` runtime directory. It is
not an authentication boundary — anything that can open it can approve anything — but it is a
**validation and attribution** boundary, and that is the point:

- every request is a bounded, strictly-parsed frame; unknown fields and unknown operations are
  refused, not partially understood;
- every field is length- and charset-checked before it reaches the store;
- the `actor` recorded on a rule comes from the connection's peer credentials (`SO_PEERCRED`),
  which the kernel fills in and a client cannot choose. A request may carry a *label* saying
  which entry point it is (`mcp`, `cli`, `seed`); it may not carry an identity;
- every mutation lands in the audit log, on the same code path, in the same process.

**This replaced something weaker.** Earlier, `npmfilter mcp` and the CLI opened
`/var/lib/npmfilter/rules.db` directly, which forced the state directory to ship
group-writable (`2770`). Membership of `npmfilter` was then the ability to write allow rules
*straight into the policy store* — `UPDATE rules SET integrity = …` was a supported way to
approve a package, around the validator and around the audit log. The database is now `0600`
in a `0700` directory, and `npmfilter serve` is the only process that opens it.

### What the daemon trusts

- **`/etc/npmfilter/config.toml`**, and root, who writes it. An unknown key there is a hard
  error rather than a silently ignored one, so a typo cannot leave you believing in a policy
  that is not being enforced.
- **Its own state database.** Rules, the integrity ledger and the audit log are taken as
  written. Anyone who can write that file has already won; that is why nothing but the daemon
  opens it.
- **Not** the *contents* of its own state directory, when root is the one touching them. The
  `npmfilter` account owns `/var/lib/npmfilter`, so the package's `postinst` treats every path
  in it as attacker-controlled: it refuses anything that is not a real, unshared regular file,
  never dereferences (`chown -h`), and drops the `chmod` to the daemon's own account where it
  can. Following a symlink there would have turned a compromised daemon account into
  ownership of any file on the machine, on the next package upgrade.
- **The peer credentials of a control connection**, i.e. the kernel.
- **The TLS chain to the configured upstream**, via the system trust store.

### What the daemon never trusts

- **The upstream registry.** Packument JSON is parsed under a hard byte cap, and no value out
  of it is reproduced in anything sent back to a client — see "Never echo" below.
- **The client on the loopback port.** Paths are percent-decoded after splitting, so no
  spelling of a URL escapes the policy; a path carrying a `.` or `..` segment is refused
  outright rather than forwarded, because a URL parser downstream would read it differently;
  only `GET`/`HEAD` (and `POST` to the two read-only registry endpoints) are treated as reads,
  so a verb nobody anticipated is refused rather than relayed; every resolution endpoint
  answers from the same filtered document; request bodies are capped.
- **A control-socket request**, per the validator above.
- **A `node_modules` tree, or the lockfile describing it.** `seed` sends what it found to the
  daemon, and the daemon confirms every `(name, version, dist.integrity)` and every
  install-hook command against what the registry actually serves before it writes a rule.
  A lockfile is exactly as trustworthy as the tree it describes, and the tree is the thing
  being vetted.
- **A published tarball.** `inspect` streams it under four separate limits, reads only
  `package.json`, and discards every other byte. Nothing is written to disk.

### Never echo

The `_npmfilter` summary, the per-version 404 body and every header npmfilter adds carry no
value that upstream chose. A block says which gate fired and which tool shows the evidence;
it does not reproduce the tampered integrity string, the install-hook command line or an
unparseable publish time. Where an operator needs to correlate two observations, the daemon
emits a `sha256:` fingerprint it computed itself, never the original text.

The evidence still exists — in the audit log and over the control socket, both of which are
reachable only by someone already trusted to approve packages. Text that arrives over the
socket is capped and stripped of control characters before it is printed, so a hostile
registry's error body cannot repaint an operator's terminal.

The one exception is deliberate: a non-2xx upstream answer (404 for an unknown package, 401
for a private one) is forwarded verbatim, because npm needs the registry's own answer. That
body is upstream's, presented as upstream's.

---

## Attacker classes considered

### 1. A hostile upstream or a compromised mirror

Can serve any packument, including one that changes the bytes behind a version number.

- **Integrity ledger (trust on first use).** Every version npmfilter observes is recorded as
  `(name, version) -> identity`, the identity being `dist.integrity`, or the `sha1`
  `dist.shasum` under a `shasum-sha1:` prefix for versions published before npm 5. A later
  fetch showing a different value for the same version is blocked as `integrity_changed`, at
  `critical`, and **no allow rule can rescue it** — the ledger check is policy gate 0, before
  rules are consulted.
- **A version with no content hash at all is withheld** (`no_integrity`). Recording it as
  `NULL` made the ledger a no-op for exactly the versions nothing else pins: `NULL == NULL`
  reported *unchanged* on every later observation, so the artefact behind such a version could
  be repointed for ever with no tamper event and no mismatch count. Upgrading the schema drops
  the `NULL` rows earlier versions wrote.
- **The recorded hash is frozen.** A mismatch never overwrites it; it is the evidence. What
  moves is a mismatch counter and a last-mismatch timestamp, so a replacement attempt that
  repeats is visible in `npmfilter ledger`.
- **The quarantine window doubles as an observation window.** A version published today has
  its hash recorded today and is only served after `min_age_days` of that hash not moving.
- Packument bodies are read under a 64 MiB cap **and** a 20 000-version cap; the
  parse-and-clone cost, the per-version policy work and the ledger rows that follow are
  therefore all bounded. Over either limit is a refusal, never a truncated packument that
  would look like a smaller one.
- Every version of a packument is observed in one database transaction, so a document with a
  great many versions cannot turn one request into one write transaction per version.
- `dist.tarball` is relayed untouched, and npmfilter does **not** require it to point at the
  configured upstream — see "What is NOT defended". An upstream that serves tarballs from
  elsewhere is recorded once per package as `foreign_tarball`, at `warning`.
- No string from the packument reaches a client through npmfilter's own reporting.

### 2. A compromised package

The Shai-Hulud shape: a version that newly acquires `"preinstall": "node setup.mjs"`.

- Any version declaring `preinstall`, `install` or `postinstall` — or carrying upstream's
  `hasInstallScript` flag with no `scripts` map to review — is withheld until approved.
- An approval is pinned to `dist.integrity` **and** to a sha256 over the sorted install-hook
  map. A changed command never inherits the approval: it blocks as `scripts_changed`, at
  `critical`.
- `npmfilter inspect` reports the **script delta against the previous published version**,
  which is the highest-signal field available: a version that newly acquires an install hook
  is exactly the compromise shape.
- `min_age_days` (default 30) keeps a freshly published version out of resolution for the
  window in which these campaigns are usually caught.

### 3. An unprivileged local user

Any account on the machine that is not in group `npmfilter`.

- Cannot read or write the state database (`0600` in a `0700` directory).
- Cannot open the control socket (`0660` in a `0750` directory), so cannot record, alter or
  delete a rule, and cannot read the audit log through npmfilter.
- Can still reach the loopback registry port, like any local process — see class 4.

### 4. A malicious client on the loopback port

Anything that can connect to `127.0.0.1:4874`.

- Gets filtered answers only. Every resolution endpoint — the packument,
  `GET /{package}/{version}`, `GET /-/package/{package}/dist-tags` — is answered from the same
  filtered document, and a path that is ambiguous is filtered rather than proxied.
- Cannot write anything: `PUT`, `DELETE`, `PATCH` and `POST` to a package path are all refused
  the same way, with one actionable error. (They used to disagree: `PUT` answered 405 while
  `DELETE` and `PATCH` fell through to the verbatim proxy **with the client's `Authorization`
  header**, so `npm unpublish` went straight through a daemon whose own error text said writes
  were refused.)
- With `allow_publish_passthrough = true` those methods are relayed — and every one of them is
  written to the audit log with its method, path and peer address. If the audit row cannot be
  written, the request is not relayed. The `Authorization` value is never recorded; that one
  was present is.
- Bounded, not unbounded: proxied request bodies are capped at 8 MiB; the packument cache is
  capped at 1024 documents **and** at 64 MiB of held documents; at most 8 packuments are
  fetched and evaluated at once, so what is in flight is bounded as well as what is kept; and
  every upstream call has a timeout. The entry cap alone was not a bound — a packument may be
  64 MiB, so 1024 of them is tens of gigabytes, and 1024 distinct package names (or one name
  under 1024 different `Authorization` headers, since the cache key carries a credential
  fingerprint) was an unprivileged local process driving the daemon into the OOM killer.
- **Can use whatever credential it sends.** npmfilter forwards the client's `Authorization`
  header upstream so private packages resolve. Keep `listen` on loopback; anything that can
  reach the port can use the credential *it supplies*, not one npmfilter holds.

---

## What is NOT defended — read this part

### The gate is resolution-time only. `npm ci` bypasses it entirely.

Tarballs are pass-through: `dist.tarball` keeps pointing at the upstream registry, so lockfiles
stay portable and no package bytes transit this daemon. The direct cost is that a committed
lockfile already contains `registry.npmjs.org` URLs, and `npm ci` fetches them without ever
asking npmfilter anything. **Locked installs are covered by the lockfile's own sha512, not by
this daemon.** npmfilter shapes what goes *into* a lockfile; it does not police what comes out
of one.

### `dist.tarball` is not pinned to the upstream host

npmfilter relays the tarball URL exactly as published — that is what keeps lockfiles portable
and keeps package bytes out of this daemon. It does not require that URL to be on the host
`upstream` names, because a mirror that serves `registry.npmjs.org` URLs is the arrangement
this tool was designed around and a registry fronted by a CDN is ordinary; refusing them would
withhold every version of every package for those operators. A foreign host is **recorded**
(one `foreign_tarball` audit row per package, at `warning`) rather than blocked. What
actually verifies those bytes is the version's own `dist.integrity`, which npm checks on
download — and a version publishing no hash at all is withheld before it can be served.

### The integrity ledger has a retention

A `seen` row that has not been observed for a year, has never recorded a mismatch and is named
by no rule is deleted. That version's trust-on-first-use baseline goes with it, and the next
observation becomes the new baseline. The alternative is a table that only ever grows —
a hostile upstream can add hundreds of thousands of rows per request — and a full disk fails
every store write, which is fail-closed and therefore a machine where no `npm install`
resolves at all. Rows that are evidence of anything are kept regardless of age.

### The integrity ledger is trust on first use

The first hash npmfilter ever sees for a version becomes the trusted baseline. If that first
observation is already malicious, the ledger will faithfully defend the compromised bytes. The
age gate limits the exposure — versions are normally first observed while quarantined and only
served after the window — but a package first seen *after* it was already compromised inherits
the bad hash. There is no external attestation, no signature verification and no
cross-machine consensus here.

### `seed` verifies the hash, not the choice

The daemon confirms that every hash it is offered is the one the registry serves for that exact
version, so a tampered lockfile cannot mint an approval for bytes nobody published. What it
cannot tell you is whether those were the right versions to install: if the tree was resolved
from a compromised lockfile, its packages are genuine registry artefacts of genuinely
compromised versions, and seeding approves them. Only seed a tree you installed from a lockfile
you trust. `--offline` skips verification entirely and is a deliberate downgrade — it warns
loudly and records the reduced assurance in every rule it writes.

### The daemon holds no credentials, so it is not a credential boundary

npmfilter stores no tokens and has no registry account. It forwards the `Authorization` header
a client sends, and it refuses writes rather than relaying your publish token by default.
Putting a publish behind it does not protect the token — the right place for a publish is the
registry that should receive it, via a scoped `@yourscope:registry=` entry or an explicit
`--registry`.

### Age and scripts do not catch everything

A compromised package older than the quarantine window that carries no install hook passes both
automatic gates. Install-hook detection reads packument metadata; the tarball is only opened at
`inspect` time, which is where the sha pin is established.

### npmfilter becomes a hard dependency of installs

Once a package manager points at it, a stopped daemon means failing installs. That is the
intended failure direction — a security gate that fails open is not one — and it is why the
`.deb` neither starts nor enables the service for you. `Restart=always` and loud errors
mitigate; they do not eliminate.

### Out of scope entirely

Other ecosystems (PyPI, crates.io, Go), git dependencies (`prepare` scripts do not run for
registry tarball installs, but they do for git deps), non-loopback deployment, multi-user
approval workflows, and anything to do with what a package does at *runtime* rather than at
install time.

---

## Hard limits

These are compile-time constants, not config keys. A config field for a hard limit is a way to
weaken the daemon, so none is offered.

| Limit | Value | Where |
|---|---|---|
| Upstream packument body | 64 MiB | `proxy::MAX_PACKUMENT_BYTES` |
| Proxied request body | 8 MiB | `proxy::MAX_PROXY_BODY` |
| Upstream packument versions | 20 000 | `proxy::MAX_PACKUMENT_VERSIONS` |
| Packument cache entries | 1024 | `proxy::cache::DEFAULT_MAX_ENTRIES` |
| Packument cache bytes | 64 MiB | `proxy::cache::DEFAULT_MAX_BYTES` |
| Packuments evaluated at once | 8 | `proxy::MAX_CONCURRENT_PACKUMENTS` |
| Upstream request / connect timeout | 60 s / 10 s | `proxy::upstream` |
| Control frame (request) | 4 MiB | `control::MAX_REQUEST_BYTES` |
| Control frame (response, client side) | 64 MiB | `control::protocol::MAX_RESPONSE_BYTES` |
| Packages per `seed` request | 4096 | `control::MAX_SEED_ENTRIES` |
| Package name / version / reason | 214 B / 256 B / 1024 B | `control::protocol` |
| Integrity / path / hook command | 512 B / 4096 B / 8 KiB | `control::protocol` |
| Control connection lifetime | 300 s | `control::protocol::CONNECTION_TIMEOUT` |
| Control request deadline | 5 s | `control::protocol::REQUEST_TIMEOUT` |
| Concurrent control connections | 8 | `control::protocol::MAX_CONCURRENT_CONNECTIONS` |
| Integrity-ledger retention | 365 d | `store::SEEN_RETENTION_DAYS` |
| Audit / ledger pruning interval | 6 h | `proxy::MAINTENANCE_INTERVAL` |
| Tarball: compressed / unpacked | 64 MiB / 256 MiB | `mcp::inspect` |
| Tarball: `package.json` / entries | 4 MiB / 200 000 | `mcp::inspect` |
| `node_modules` walk depth | 32 | `seed` |
| SQLite busy timeout | 5 s | `store` |
| Audit rows returned per call | 500 | `mcp::MAX_RECENT_LIMIT` |

Every one of them fails **closed**: over the limit is a refusal, never a truncated answer that
looks like a smaller one. Two are ceilings rather than refusals, and say so here because the
difference matters: a ninth control connection is **refused** (`busy`) rather than queued —
queuing was how eight peers that said nothing could hold every approval on the machine — while
a ninth concurrent packument evaluation waits for a slot, because refusing a resolution would
fail an install that is inside every limit it is subject to.

## Fail-closed behaviour

- A rules-store or ledger read that fails withholds the version, and the request answers `502`
  with the storage error rather than an empty packument that could be mistaken for a policy
  verdict.
- A version with no usable publish time cannot clear the age gate.
- A packument with no `time` entry for a version cannot clear the age gate.
- An `integrity_changed` verdict cannot be overridden by any rule.
- A relayed mutating request that cannot be audited is not relayed.
- A control connection that sends no request inside 5 s is dropped, so a slot cannot be held
  by saying nothing; over the connection ceiling, a connection is refused rather than queued.
- A packument that cannot be canonicalised (a `.` or `..` in the path) is refused rather than
  forwarded, and a method outside the read allow-list is refused rather than relayed.
- A version with no content hash is withheld rather than served under a ledger comparison that
  cannot fail.
- If the control socket cannot be bound, the daemon does not start: a daemon that filters but
  cannot be told to approve anything is a daemon that has to be killed to unblock an install.

## Reporting

This is a single-operator tool with no release channel. Fix it in place, or open an issue in
whatever tracker the repository lives in.
