# npmfilter — operator manual

Reference and playbooks: what each block reason means, every command, every
config key, and how to read the audit log.

The other three: [README.md](README.md) is what npmfilter is and how it decides.
[INSTALL.md](INSTALL.md) sets it up. [SECURITY.md](SECURITY.md) is the threat
model.

---

## An install just failed. Start here.

npm does not say "npmfilter withheld this". It says the version does not exist,
because from the resolver's point of view it does not:

```
npm error notarget No matching version found for esbuild@^0.21.0
```

Find out what happened:

```sh
npmfilter status                       # is the daemon even up?
curl -s http://127.0.0.1:4874/esbuild | jq '._npmfilter'
```

The `_npmfilter` object lists every withheld version and its gate. Or ask the
daemon directly through MCP — `npmfilter_recent_blocks` is built for exactly this
moment and reports the next step per block.

Then read the reason off the table below. **Three of the six are routine. Two of
them mean stop.**

### Block reasons

| Wire reason | Meaning | What to do |
|---|---|---|
| `too_new` | Published less than `min_age_days` ago (default 30). The quarantine window. | **Routine.** Wait, pin an older version, or approve deliberately if you have a reason to trust it now. |
| `install_script_quarantine` | Carries an install hook and is younger than the quarantine floor (default 7 days). | **Approval does not override this.** Approve anyway if you have reviewed it — the rule is recorded and activates when the window clears — or install a version already past it. |
| `install_script` | Carries `preinstall`, `install` or `postinstall`, or upstream flags `hasInstallScript`. | **Routine but read it.** `inspect` first — check the *script delta*. A build tool that always had a hook is ordinary; one that just grew one is not. |
| `no_integrity` | Publishes neither `dist.integrity` nor `dist.shasum`. | **Routine, rare.** Nothing can pin it, so the ledger could never detect a replacement. Approve only if you accept that. |
| `deny_rule` | You (or someone in group `npmfilter`) denied it. | Expected. `npmfilter rules -p <pkg>` shows who and why. |
| `scripts_changed` | An approved version's **install commands no longer hash the same** as when you approved it. | **STOP.** The approval was pinned to exact commands. Do not re-approve without understanding why they moved. |
| `integrity_changed` | A version npm treats as immutable came back with a **different hash** than first recorded. | **STOP — this is the alarm.** An allow rule cannot rescue it, by design. See below. |

### `integrity_changed` — what to actually do

A published npm version is immutable. If its bytes changed, one of these is true:
your upstream is compromised or lying, something is intercepting the connection,
or the registry did something it is not supposed to do.

```sh
journalctl -u npmfilter | grep -iE 'tamper|integrity_changed'
```

For the full history — first-seen hash, current hash, mismatch count and
timestamps — use the **`npmfilter_ledger` MCP tool**. There is no `ledger`
subcommand; the ledger is readable over MCP only.

The recorded hash is never overwritten — it is evidence. Mismatches bump a counter
and a timestamp, so `mismatch_count` tells you whether this is a one-off or
something retrying. Do not route around it. There is no supported way to approve
past it, and that is deliberate.

---

## Command reference

Every subcommand except `serve` is a **client of the daemon's control socket**.
If the daemon is not running they fail and say so; none of them ever writes
`rules.db` directly.

Global options, available on all subcommands:

| Option | Effect |
|---|---|
| `-c`, `--config <PATH>` | Config file instead of `/etc/npmfilter/config.toml` |
| `--log-level <LEVEL>` | Tracing directive, overriding `log_level` from config |

| Command | Arguments | Notes |
|---|---|---|
| `serve` | — | The daemon. Binds the HTTP listener and the control socket. |
| `mcp` | — | stdio MCP shim. Register it with your MCP client; it talks to the socket. |
| `inspect` | `<PACKAGE> [VERSION]` | Version defaults to newest published. Streams the tarball, keeps `package.json` and a sha256 per file, retains no package bytes. |
| `allow` | `<PACKAGE> <VERSION>` `[-r, --reason]` | Pins to the integrity **and** script hashes the registry serves right now. |
| `deny` | `<PACKAGE> <VERSION>` `[-r, --reason]` | Blocks outright, above every gate but the ledger. |
| `rules` | `[-p, --package <PKG>]` | Lists allow/deny rules. |
| `status` | — | Daemon reachability, active policy, rule counts. |
| `seed` | `[PATH]` `[--dry-run]` `[--offline]` | PATH defaults to `.`. See below. |

### `seed`

Walks a `node_modules` tree, finds packages declaring install hooks, and has the
daemon record one allow rule each — after **verifying every hash and every hook
command against the registry**. An entry that disagrees is refused, reported and
audited (`seed_refused`), and gets no rule.

```sh
npmfilter seed ~/project --dry-run     # verifies everything, writes nothing
npmfilter seed ~/project
npmfilter seed ~/project --offline     # skips verification, loudly
```

`--offline` pins to whatever the on-disk lockfile claims, unchecked, and records
that reduced assurance in every rule's reason. Re-seed online when you can.

Seeding verifies the *hash*, not the *choice*. It proves those bytes are genuine;
it cannot tell you those versions should have been installed. Only seed a tree you
installed from a lockfile you trust.

---

## MCP tools

Register the shim (Claude Code, all projects of the current user):

```sh
claude mcp add npmfilter -s user -- /usr/bin/npmfilter mcp
```

If your session predates joining group `npmfilter`, the shim will connect but
every tool will fail on the socket — start a new login session, or register it as
`sg npmfilter -c "exec /usr/bin/npmfilter mcp"`.

| Tool | Purpose |
|---|---|
| `npmfilter_recent_blocks` | **Start here after a failed install.** What was withheld, which gate, the offending commands. |
| `npmfilter_inspect` | Age, integrity, install hooks with hashes, maintainers, provenance, sizes claimed vs observed, the **script delta against the previous version**, a **sha256 per published file**, and — once the package has a pinned approval — how this version's files compare to the ones that approval pinned. |
| `npmfilter_allow` | Approve, pinned to current integrity + script hashes, and optionally to **named files by content**. |
| `npmfilter_deny` | Block outright. |
| `npmfilter_rules` | List existing rules. |
| `npmfilter_ledger` | Integrity history and tamper events for one package. |
| `npmfilter_status` | Daemon health, active policy, rule counts. |

The script delta is the highest-signal field. A version that *newly acquires* an
install hook is the exact shape of a maintainer-account compromise — `keyv@6.0.0`
grew a `preinstall` that 5.x never had.

### Pinning files

The script delta compares *command strings*. `postinstall: node install.js` reads
identically in every version, and says nothing about what `install.js` contains — so
"the commands did not change" is the weakest possible reassurance for exactly the
packages that need the strongest.

`npmfilter_inspect` therefore reports a sha256 for every file in the published
tarball, and `npmfilter_allow` accepts a list of paths to pin:

```sh
npmfilter allow esbuild 0.25.12 \
  --reason "reviewed install.js: downloads the platform binary from the registry" \
  --pin install.js --pin lib/main.js
```

The daemon does not take the caller's word for any digest. It fetches the published
tarball itself, hashes each named file, and stores **its own** computation. A path
that is not in the tarball fails the approval outright, and a caller-supplied
`sha256` that disagrees with the daemon's fails it too — an approval never records a
digest npmfilter did not compute.

Pinning adds **evidence, not enforcement**. `dist.integrity` already covers every
byte of the tarball and npm verifies it on install; a pinned file cannot be swapped
under an approved version. What pinning buys is the *next* version: when 0.25.13
appears, `npmfilter_inspect` compares its files against what 0.25.12's approval
pinned and reports each one as unchanged, changed, or absent. A changed install
script under an unchanged command is the finding the command-level delta cannot
produce.

Up to 64 files may be pinned per approval. Paths are relative to the package root
(the tarball's `package/` prefix stripped) — `install.js`, not `package/install.js`.

Approvals from MCP and from a terminal are the same request to the same daemon and
write the same audit rows. The actor recorded is the uid the kernel reports for the
connection, never something the caller claims.

---

## Configuration

`/etc/npmfilter/config.toml`. **An unknown key is a hard error and the daemon
refuses to start** — a typo'd `bypass_scope` that silently did nothing would leave
you trusting a policy that is not being enforced.

| Key | Default | Effect |
|---|---|---|
| `listen` | `127.0.0.1:4874` | Proxy listen address. **Keep it on loopback** — the daemon forwards the client's `Authorization` upstream. |
| `upstream` | `https://registry.npmjs.org` | Where packuments come from. Tarballs are never proxied. |
| `min_age_days` | `30` | Quarantine window. `0` disables the age gate. |
| `bypass_scopes` | `[]` | Scopes exempt from the age and install-script gates. The ledger and deny rules still apply. |
| `packument_ttl_secs` | `60` | In-memory metadata reuse. The *unfiltered* document is cached and policy re-runs per request, so a new approval takes effect on the next request. |
| `audit_retention_days` | `90` | Audit rows kept. `0` keeps everything. |
| `log_level` | `"info"` | Tracing directive. `RUST_LOG` in the unit overrides it. |
| `state_path` | `/var/lib/npmfilter/rules.db` | Rules, ledger, audit log. `0600` in a `0700` directory. |
| `socket_path` | `/run/npmfilter/npmfilter.sock` | Control socket, `0660` `npmfilter:npmfilter`. |
| `allow_publish_passthrough` | `false` | `true` relays mutating methods and audits every one. |
| `install_script_quarantine_days` | `7` | Days a hook-carrying version must be public before **any** approval admits it. The one gate an approval cannot override. `0` disables it. |
| `allow_dist_tag_downgrade` | `false` | `true` moves a tag whose target was withheld onto an older release. Leave it off: that is a **silent downgrade**, and older releases are the ones with known vulnerabilities. |

`sudo systemctl restart npmfilter` after editing.

### Not configurable, on purpose

A config field for a hard limit is a way to weaken the daemon. These are
compile-time constants:

| Limit | Value |
|---|---|
| Ledger retention | 365 days — rows that ever mismatched, or that a rule names, are never pruned |
| Maintenance interval | 6 hours (prunes audit + ledger; also runs at startup) |
| Upstream packument body cap | 64 MiB |
| Packument version cap | 20,000 versions |
| Concurrent packument evaluations | 8 |
| Control-socket connections | 8, with a 5s deadline on the request frame |

---

## HTTP responses

| Status | `code` | Meaning |
|---|---|---|
| 200 | — | Served. Check `x-npmfilter-withheld` and `x-npmfilter-reasons`. |
| 400 | `invalid_path` | Path contained a `.` or `..` segment. Never forwarded, any method. |
| 404 | `version_withheld` | A gate blocked this exact version. The body names the gate. |
| 404 | `version_not_found` | Upstream has no such version. |
| 405 | `publish_refused` | A mutating method. Publish to the registry that should receive it. |
| 502 | `upstream_unavailable` | Upstream unreachable or failed. |
| 502 | `packument_too_large` / `packument_too_many_versions` | Upstream exceeded a hard limit. |
| 502 | `store_unavailable` | `rules.db` unreadable. **Fails closed** — nothing resolves. |

Every filtered answer carries `x-npmfilter-withheld`, and `x-npmfilter-reasons`
when anything was withheld — visible under `npm --loglevel=http`, including in the
abbreviated shape `npm install` requests, which has no room for `_npmfilter`.

Response bodies never reproduce a tampered hash, an install command, or anything
else the upstream chose. The evidence is in the audit log and on the control
socket, where only someone already trusted to approve packages can read it.

### Which methods and paths get through

`GET` and `HEAD`, plus `POST` to `/-/v1/search` and
`/-/npm/v1/security/advisories/bulk`, are the entire allow-list. Those two POST
endpoints are what `npm search` and `npm audit` use, and both are proxied
untouched — as is any path the daemon does not recognise.

Everything else answers `405 publish_refused`: `PUT`, `DELETE`, `PATCH`, `POST`
to a package path, and any other verb, `COPY` and `PROPFIND` included. npmfilter
holds no credentials, so a publish belongs at the registry that should receive
it. `allow_publish_passthrough = true` relays them instead and audits every one.

---

## The audit log

In `rules.db`, alongside rules and the ledger.

| Event | Severity | Meaning |
|---|---|---|
| `block` | warning | A gate withheld a version |
| `tamper` | **critical** | `integrity_changed` or `scripts_changed` |
| `allow` / `deny` | info | A rule was recorded, with actor |
| `seed_refused` | warning | A seed entry failed registry verification |
| `foreign_tarball` | warning | `dist.tarball` on a host other than upstream (recorded, not blocked) |
| `publish_passthrough` | info | A mutating method was relayed (only with `allow_publish_passthrough`) |

```sh
journalctl -u npmfilter -f
journalctl -u npmfilter | grep -iE 'tamper|critical'
```

`rules.db` is the only thing worth backing up. Losing it costs your approvals and
the ledger's history — which then re-establishes itself with trust-on-first-use
semantics again.

---

## Troubleshooting

**`npmfilter status` says the daemon is not running.** `systemctl status npmfilter`,
then `journalctl -u npmfilter -n 50`. A config error is a refusal to start — check
for an unknown key first.

**Permission denied on the control socket.** The socket is `0660`
`npmfilter:npmfilter`. Either join the group (`sudo adduser $USER npmfilter`, then
a new login session) or run as the daemon's user:
`sudo -u npmfilter npmfilter status`. Membership is the ability to approve any
package machine-wide — grant it as deliberately as `docker`.

**Everything is blocked at once.** Almost always the first install after adoption
without seeding. Seed, or check for `store_unavailable` — a `rules.db` that cannot
be read fails closed by design.

**An install must go through right now.** Point that one install back at the real
registry:

```sh
npm install --registry https://registry.npmjs.org
```

Reversible and scoped to one command. Prefer it to disabling the daemon.

**Verify the filter is actually engaged:**

```sh
curl -si http://127.0.0.1:4874/esbuild | grep -i x-npmfilter
```

No `x-npmfilter-*` header means you are not talking to npmfilter.
