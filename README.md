# npmfilter

A local npm registry proxy that gates **resolution**. Point npm (or bun) at it and
the universe of installable versions shrinks to the ones that have survived a
quarantine period and carry no install hooks — everything else is withheld until
you approve it deliberately.

npm has no release-age setting. There is no per-project config that protects a
project from a package published four hours ago, which is the window worms like
Shai-Hulud live in. npmfilter is the single control point that covers every
project on the machine at once, whatever its package manager config says.

## What it actually does

On `GET /:package` it fetches the **full** packument from the upstream registry,
runs every version through the policy engine, drops the ones that fail, and
re-serializes into whichever shape the client asked for. npm's own resolver then
simply cannot see the withheld versions.

**`dist-tags` are never moved.** `latest` keeps naming the version upstream
published, even when that version is withheld, so resolving it fails and says so.
Moving the tag onto an older surviving release would be a silent downgrade — and
older releases are the ones carrying known vulnerabilities, so a gate that quietly
does that is causing harm rather than preventing it. Set
`allow_dist_tag_downgrade = true` if you want the old behaviour anyway.

Each version is evaluated in this order:

| # | Gate | Outcome |
|---|---|---|
| 0 | **Integrity ledger.** `(name, version)` was seen before with a different identity — `dist.integrity`, or `dist.shasum` for versions published before npm 5 | **block** — `integrity_changed`, critical. Nothing below can override it |
| 1 | Explicit **deny** rule | block — `deny_rule` |
| 2 | Carries an install hook and is younger than `install_script_quarantine_days` (default 7) | **block — `install_script_quarantine`, and no approval overrides it.** The allow gate runs above the age gate, so without this floor surviving one review turns a version published minutes ago into immediate execution. An approval made inside the window is still recorded and takes effect when it clears |
| 2 | **Allow** rule whose pinned sha512 equals this version's `dist.integrity` **and** whose approved commands still hash the same | allow, skipping the gates below (hash differs → block `integrity_changed`, critical; commands differ → block `scripts_changed`, critical) |
| 3 | Package scope is in `bypass_scopes` | allow |
| 4 | The version publishes **no** content hash at all — neither `dist.integrity` nor `dist.shasum` | block — `no_integrity`. Nothing pins it, so the ledger could never report a replacement of it |
| 5 | Published less than `min_age_days` ago (default 30) | block — `too_new` |
| 6 | `scripts` carries `preinstall`, `install` or `postinstall`, or upstream flags `hasInstallScript` | block — `install_script`, carrying the commands |
| 7 | otherwise | allow |

Every endpoint that answers a resolution question is filtered through the same
document: the packument, `GET /{package}/{version}` (a withheld version is a 404
naming the gate) and `GET /-/package/{package}/dist-tags`. A trailing or
duplicated slash resolves to the same package, so no spelling of a URL escapes
the policy. Each of those answers carries `x-npmfilter-withheld` and, when
anything was withheld, `x-npmfilter-reasons` — visible under `npm --loglevel=http`
even in the abbreviated shape `npm install` asks for, which has no room for the
`_npmfilter` summary.

What a client is told about a block names the gate and the tool that shows the
evidence — never the tampered hash, the offending command line or anything else
the registry chose. Reproducing a hostile upstream's strings into the body npm
parses would be lending it a channel it did not have. The evidence itself is in
the audit log and on the control socket, where only someone already trusted to
approve packages can read it.

Three things it deliberately does not do:

- **Tarballs are pass-through.** `dist.tarball` keeps pointing at the upstream
  registry, so no package bytes ever transit or are stored here and lockfiles
  stay portable on machines that have never heard of npmfilter.
- **Only reads get through.** `GET` and `HEAD`, plus `POST` to the two
  read-only registry endpoints, are the whole allow-list. `PUT`, `DELETE`,
  `PATCH`, `POST` to a package path and any other verb — `COPY` and `PROPFIND`
  included — all answer `405` with the same actionable error: npmfilter is a
  read-through filter and holds no credentials, so a publish belongs at the
  registry that should receive it. Put `@yourscope:registry=https://your.registry/`
  in `.npmrc`, or pass `--registry`. `allow_publish_passthrough = true` relays
  them instead and audits every one.
- **A path with a `.` or `..` segment answers `400`** and is never forwarded.
  npmfilter reads the path as written; a URL parser downstream would collapse
  the dot segments first, and two readings of one path is a way past every gate
  above.
- **`npm audit` and search keep working** — `/-/v1/search` and
  `/-/npm/v1/security/advisories/bulk` are proxied untouched, as is any path the
  daemon does not recognise.

Because the ledger records every version it observes, including blocked ones, the
quarantine window doubles as an observation window: a version published today has
its hash recorded today, and when it becomes old enough to install, the daemon
already knows whether that hash held still for thirty days. A recorded hash is
never overwritten — it is the evidence — so a mismatch bumps a counter and a
timestamp instead, and the `npmfilter_ledger` MCP tool shows how many times a
replacement has been attempted.

The full threat model, including what npmfilter explicitly does **not** defend
against, is in [SECURITY.md](SECURITY.md). Read it before you rely on this.

[USAGE.md](USAGE.md) is the operator manual: the playbook for a failed install,
what each block reason means and which two of them mean *stop*, and the full
command, MCP, config and audit reference.

## Install

```sh
sudo dpkg -i npmfilter_0.1.0_amd64.deb
sudo systemctl enable --now npmfilter
systemctl status npmfilter
curl -s http://127.0.0.1:4874/is-odd | head -c 200
```

The package installs the binary to `/usr/bin/npmfilter`, the config to
`/etc/npmfilter/config.toml` (a conffile — your edits survive upgrades), and a
systemd unit that runs the daemon as a dedicated `npmfilter` system user with
`/var/lib/npmfilter` (mode `0700`) as its only writable path and
`/run/npmfilter` for its control socket.

**The package does not start the service and does not enable it.** Installing a
`.deb` is not consent to start a daemon that every `npm install` on the machine
will then depend on; `postinst` prints the two commands and stops. **Nothing
resolves through it until you adopt it** either, which is the next step and is
also deliberately yours to take.

To build the package yourself:

```sh
cargo deb                      # -> target/debian/npmfilter_0.1.0_amd64.deb
dpkg -c target/debian/npmfilter_0.1.0_amd64.deb
```

## Adopt

Seed first (next section), then point a package manager at the daemon.

Per project — reversible, reviewable, and what you want while you are still
deciding whether you like this:

```sh
echo 'registry=http://127.0.0.1:4874/' >> .npmrc
```

For every npm project of the current user:

```sh
npm config set registry http://127.0.0.1:4874/
npm config delete registry              # to undo
```

bun reads its own file. Add to the project's `bunfig.toml`, or `~/.bunfig.toml`
to cover everything:

```toml
[install]
registry = "http://127.0.0.1:4874/"
```

The package will never write these files for you. Redirecting a package manager
changes how every install in that scope resolves, and installing a `.deb` is not
consent to that.

Once adopted, the daemon is a hard dependency of installs in that scope. It is
`Restart=always`, and a failure is loud rather than silent, but the dependency is
real — see the limitations at the bottom.

## Seed before you switch

Every version carrying an install hook is withheld, and a normal `node_modules`
tree is full of them: `esbuild`, `sqlite3`, `better-sqlite3`, `lightningcss`,
`@parcel/watcher`. Without seeding, the first install after adoption stops dead
on all of them at once, which teaches you nothing except that the gate works.

`seed` walks a tree you already have, finds every installed package that declares
an install hook, and has the daemon record one allow rule each — pinned to the
real `dist.integrity` npm recorded on disk (`node_modules/.package-lock.json`,
`package-lock.json`, `npm-shrinkwrap.json`) **and** to a sha256 of the exact hook
commands.

The lockfile is not taken at its word. Before it writes anything, the daemon
fetches the packument for every `(name, version)` and confirms that both the hash
**and** the install-hook commands are the ones the registry actually serves. A
lockfile is exactly as trustworthy as the tree it describes, and the tree is the
thing being vetted. An entry that disagrees is refused, reported and audited —
and gets no rule.

```sh
npmfilter seed ~/your-project --dry-run    # verifies everything, writes nothing
npmfilter seed ~/your-project              # records the rules
npmfilter seed ~/your-project --offline    # skips verification. See below.
```

`--dry-run` prints, per package, the hook commands, their script hash, the
`dist.integrity` it would pin to and where on disk it read it from, plus a
reproducible hash of the unpacked directory so you can compare two machines — and
the daemon's verdict on each. A package whose integrity is nowhere on disk (a
workspace link, a `file:` dependency) is listed as unpinnable and gets **no** rule
rather than a poisoned one.

`--offline` skips the upstream check entirely. It prints a prominent warning and
records the reduced assurance in every rule's reason, because a rule written that
way is pinned to whatever the file on disk said, unchecked. Re-seed online when
you can.

Seeding still trusts this tree's *choice* of versions. The daemon can prove a hash
is genuine; it cannot tell whether that version should have been installed. Only
seed a tree you installed from a lockfile you trust.

The daemon must be running: it is the only thing that writes rules. They take
effect on the next request, with no restart.

## Approving a blocked package

When an install fails, the reason is in the daemon's audit log. Both approval
paths write the same rows the same way, because both are requests to the same
daemon: `npmfilter inspect`, `allow`, `deny`, `rules` and `status` at a terminal,
and the MCP tools for an agent that can inspect a package and approve it in one
conversation. Register the shim with your MCP client:

Claude Code, registered for every project of the current user:

```sh
claude mcp add npmfilter -s user -- /usr/bin/npmfilter mcp
claude mcp list                    # npmfilter should report Connected
```

Any other MCP client:

```json
{
  "mcpServers": {
    "npmfilter": {
      "command": "/usr/bin/npmfilter",
      "args": ["mcp"]
    }
  }
}
```

**The shim starts whether or not it can reach the daemon**, because it does not
open the socket until a tool is actually called. So a client registered from a
login session that predates your `adduser` will connect happily and then fail on
every tool. Either start a new login session, or register it wrapped so the group
is applied regardless:

```sh
claude mcp add npmfilter -s user -- sg npmfilter -c "exec /usr/bin/npmfilter mcp"
```

The shim opens no database. It is a **client** of the daemon's Unix control
socket, `/run/npmfilter/npmfilter.sock` — as are `npmfilter allow`, `deny`,
`rules`, `status`, `inspect` and `seed`. The daemon is the only process that
writes `rules.db`, so every approval crosses one validator, is attributed to the
uid the kernel reports for the connection, and lands in one audit log. If the
daemon is not running, these commands fail and tell you how to start it; they
never fall back to writing the database directly.

The socket is `npmfilter:npmfilter`, mode `0660`, so:

```sh
sudo adduser $USER npmfilter        # then start a new login session
```

Membership in that group is the ability to approve any package for the whole
machine. Grant it as deliberately as you would `docker`. The alternative, if you
would rather not, is to run the shim as the daemon's own user
(`"command": "sudo", "args": ["-u", "npmfilter", "/usr/bin/npmfilter", "mcp"]`).

The flow, once a `bun install` or `npm install` has failed:

1. **`npmfilter_recent_blocks`** — what was withheld, which version, which gate,
   and the offending script commands with their hashes. This is the entry point;
   it also tells you the next step per block.
2. **`npmfilter_inspect(package, version)`** — fetches that version's tarball and
   streams it, keeping only `package.json` and a sha256 per entry; no package
   bytes are ever stored. Returns publish time and age, `dist.integrity`, the
   install hooks with per-hook hashes, maintainers and `_npmUser`, provenance
   attestation presence, file count and unpacked size as claimed versus observed,
   a **digest for every published file** — and the **script delta against the
   previous published version**. That delta is the highest-signal field here: a
   version that *newly acquires* an install hook is exactly the shape of a
   compromise (`keyv@6.0.0` grew a `preinstall` that 5.x never had). It also flags
   when the tarball's hooks differ from the packument's, and — once the package
   has a pinned approval — reports every pinned file as unchanged, changed, or
   absent in this version.
3. **`npmfilter_allow(package, version, reason, pins)`** — records the approval
   pinned to the integrity and script hashes the registry is publishing right now,
   plus any files named in `pins`. The daemon hashes those files out of the
   published tarball itself and stores only its own digests: a path the tarball
   does not contain, or a caller-supplied digest that disagrees, fails the whole
   approval. The next request serves that version.

   Pinning is **evidence, not enforcement** — `dist.integrity` already covers every
   byte and npm verifies it, so nothing can be swapped under an approved version.
   What it buys is the next one: a `postinstall: node install.js` reads identically
   in every release, so the command-level delta cannot see `install.js` being
   rewritten. A pinned digest can.

Also available: `npmfilter_deny(package, version, reason)`,
`npmfilter_rules(filter)`, `npmfilter_ledger(package)` (integrity history and any
tampering for one package), and `npmfilter_status` (daemon reachability, active
policy, rule counts).

An `integrity_changed` block is different in kind from the others. It means a
version that npm treats as immutable came back with a different hash than the one
recorded the first time. Do not approve your way past it — an allow rule cannot
rescue that version by design.

Every subcommand is wired: `serve` is the daemon, and `mcp`, `inspect`, `allow`,
`deny`, `rules`, `status` and `seed` are all clients of its control socket.

## Configuration

`/etc/npmfilter/config.toml`, all defaults shown:

```toml
listen = "127.0.0.1:4874"
upstream = "https://registry.npmjs.org"
min_age_days = 30                 # 0 disables the age gate
bypass_scopes = []                # e.g. ["@yourscope"] for first-party packages
packument_ttl_secs = 60           # in-memory metadata cache, never on disk
audit_retention_days = 90         # pruned at startup and every 6h; 0 keeps everything
log_level = "info"
state_path = "/var/lib/npmfilter/rules.db"
socket_path = "/run/npmfilter/npmfilter.sock"
allow_publish_passthrough = false # true relays mutating methods, auditing each
allow_dist_tag_downgrade  = false # true lets a withheld tag move to an older release
install_script_quarantine_days = 7 # no approval admits a hook-carrying version younger than this
```

An **unknown key is a hard error** and the daemon refuses to start: a typo'd
`bypass_scope` that silently did nothing would leave you trusting a policy that is
not being enforced. The hard limits are deliberately not here — see
[USAGE.md](USAGE.md#not-configurable-on-purpose).

`sudo systemctl restart npmfilter` after editing. `bypass_scopes` skips the age
and install-script gates for your own packages; the integrity ledger and deny
rules still apply to them.

Keep `listen` on loopback. The daemon forwards the client's `Authorization`
header upstream, so anything that can reach it can use your registry credentials.

## Operating it

```sh
systemctl status npmfilter
journalctl -u npmfilter -f
```

The daemon logs one line per filtered packument with the withheld count and a
breakdown by reason. The full-form response carries an `_npmfilter` object
listing every withheld version and why, so `curl` against the daemon is a
first-class debugging tool:

```sh
curl -s http://127.0.0.1:4874/esbuild | jq '._npmfilter'
```

State lives in `/var/lib/npmfilter/rules.db` — rules, the integrity ledger and
the audit log. It is `0600` in a `0700` directory and the daemon is the only
process that opens it. It is the only thing worth backing up, and losing it costs
you your approvals plus the ledger's history (which then re-establishes itself on
first use, with trust-on-first-use semantics again).

If the daemon is down and the registry points at it, installs fail. That is the
intended failure direction: a security gate that fails open is not one.

## Known limitations

The short list. The reasoned version, with the attacker classes each of these
does and does not cover, is [SECURITY.md](SECURITY.md).

- **The gate is resolution-time only.** A committed lockfile pins `registry.npmjs.org` tarball URLs, so `npm ci` bypasses NpmFilter entirely. This is the direct cost of pass-through tarballs and portable lockfiles. Locked installs are covered by the lockfile's own sha512, not by this daemon.
- **The daemon becomes a hard dependency of installs** once the registry points at it. `Restart=always` plus a clear failure message mitigate; they do not eliminate.
- Age and script gates do not detect a compromised package that is older than the window and carries no install hook.
- Packument metadata is trusted for script detection; the tarball is only read at `inspect`/approval time, which is where the sha pin is established.
- **The integrity ledger is trust-on-first-use.** If the very first observation of a version is already malicious, that hash becomes the trusted baseline. The age gate limits the damage — versions are normally first observed while quarantined and only served after 30 unchanged days — but a package first seen *after* it was already compromised inherits the bad hash.
- **The integrity ledger has a retention.** A version not observed for a year, never mismatched and named by no rule is dropped from the ledger and re-pinned to whatever is served next. The alternative is a table that only grows; a full disk fails closed into a machine where nothing installs.
- **`dist.tarball` is not pinned to the upstream host.** A tarball URL on another host is recorded once per package (`foreign_tarball`, warning) rather than blocked — a mirror serving `registry.npmjs.org` URLs is the arrangement this tool is built around. The version's own `dist.integrity` is what verifies those bytes, and a version with no hash at all never gets served.
- **Seeding verifies the hash, not the choice.** The daemon proves every pinned hash is the one the registry serves; it cannot tell you those were the right versions to install.
- **npmfilter holds no credentials, so it is not a credential boundary.** It forwards the header a client sends and stores no token of its own.
