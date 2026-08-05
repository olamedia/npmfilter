# npmfilter

A local npm registry proxy that decides which versions your package manager is
even allowed to see. Point npm or bun at it, and anything published in the last
30 days — or anything that would run a script on install — is withheld until you
look at it and say yes.

npm has no release-age setting. No per-project config protects you from a package
published four hours ago, which is the window worms like Shai-Hulud live in. One
daemon on loopback covers every project on the machine at once, whatever each
project's config says.

**Docs:** [INSTALL.md](INSTALL.md) to set it up · [USAGE.md](USAGE.md) when an
install fails · [SECURITY.md](SECURITY.md) for the threat model. Read SECURITY.md
before you rely on this for anything.

## What it looks like

You ask for a package. The newest release runs a `postinstall`, so it is not
served:

```console
$ bun add esbuild
error: Package "esbuild" with tag "latest" not found, but package exists
error: esbuild@ failed to resolve
```

You look at what was withheld and why:

```console
$ npmfilter inspect esbuild 0.28.1
esbuild@0.28.1

version source  requested
published       2026-06-11T22:47:05.085Z (54 days old)
dist.integrity  sha512-HrJrvZv5ayxBzPfwphOoNzkzOIIlifzk0KJrGK2c8R4+LKpMtpYLQeUdjnwjWv/LZlkH2laZk+4w78pi99D4Vw==

install hooks (from the tarball's package.json)
  postinstall: node install.js
  scripts sha256  23bddf6d3adf9f611110e313125c7c8a2cf2f88c5301dcd43a2eede75b206456
  packument agrees: true

script delta versus the previous published version
  previous        0.28.0
  newly acquires install hooks: false
  the install-hook COMMANDS are identical to 0.28.0; the files those commands run
  were not compared — pin them to cover that

publisher
  _npmUser        GitHub Actions
  maintainers     esbuild <evan.exe+esbuild@gmail.com>
  provenance      attested=true signatures=1

file manifest — sha256 of every published file, for `--pin`
  7 file(s)
  417cbbaf3ea9cb87       11037  install.js
  9425d36afcd1c854       87971  lib/main.js
  ...
```

Then you approve it, naming the files you actually read:

```console
$ npmfilter allow esbuild 0.28.1 \
    --reason "install.js downloads the platform binary from the registry" \
    --pin install.js

  allow esbuild@0.28.1
    pinned to       sha512-HrJrvZv5ayxBzPfwphOoNzkzOIIl...
    hook            postinstall: node install.js
    pinned file     417cbbaf3ea9cb878011832b70eeaa00ce49419a0589cbbf4b65d258c4d7c1dd install.js

esbuild@0.28.1 is now admitted, and npm will run postinstall: node install.js on
install, while its dist.integrity is unchanged.
```

The install now works. Next time esbuild ships a release, `inspect` tells you
whether `install.js` is still the file you read:

```console
pinned files versus the approval on 0.28.1
  CHANGED  install.js
           pinned   417cbbaf3ea9cb878011832b70eeaa00ce49419a0589cbbf4b65d258c4d7c1dd
           observed 10f6fa3644d8d23d066ff67b0ae449074e75884503546a9fedb667f1dcb9ade2
```

That finding is the reason pinning exists. `postinstall: node install.js` reads
identically in every esbuild release ever published, so comparing commands can
never see `install.js` being rewritten. Comparing digests can.

An agent can do all of this in one conversation over MCP — same daemon, same
audit rows. See [INSTALL.md](INSTALL.md#register-the-mcp-shim).

## How a version is judged

On `GET /:package` the daemon fetches the **full** packument upstream, runs every
version through the policy engine, drops the ones that fail, and re-serializes
into whichever shape the client asked for. npm's own resolver then cannot see the
withheld versions at all.

| # | Gate | Outcome |
|---|---|---|
| 0 | **Integrity ledger.** `(name, version)` was seen before with a different identity — `dist.integrity`, or `dist.shasum` for versions published before npm 5 | **block** — `integrity_changed`, critical. Nothing below can override it |
| 1 | Explicit **deny** rule | block — `deny_rule` |
| 2 | Carries an install hook and is younger than `install_script_quarantine_days` (default 7) | **block — `install_script_quarantine`, and no approval overrides it.** The allow gate runs above the age gate, so without this floor surviving one review turns a version published minutes ago into immediate execution. An approval made inside the window is still recorded and takes effect when it clears |
| 3 | **Allow** rule whose pinned sha512 equals this version's `dist.integrity` **and** whose approved commands still hash the same | allow, skipping the gates below (hash differs → block `integrity_changed`, critical; commands differ → block `scripts_changed`, critical) |
| 4 | Package scope is in `bypass_scopes` | allow |
| 5 | The version publishes **no** content hash at all — neither `dist.integrity` nor `dist.shasum` | block — `no_integrity`. Nothing pins it, so the ledger could never report a replacement of it |
| 6 | Published less than `min_age_days` ago (default 30) | block — `too_new` |
| 7 | `scripts` carries `preinstall`, `install` or `postinstall`, or upstream flags `hasInstallScript` | block — `install_script`, carrying the commands |
| 8 | otherwise | allow |

Every endpoint that answers a resolution question runs through the same filtered
document: the packument, `GET /{package}/{version}` (a withheld version is a 404
naming the gate) and `GET /-/package/{package}/dist-tags`. A trailing or
duplicated slash resolves to the same package, so no spelling of a URL escapes
the policy. Each answer carries `x-npmfilter-withheld` and, when anything was
withheld, `x-npmfilter-reasons` — visible under `npm --loglevel=http` even in the
abbreviated shape `npm install` asks for, which has no room for the `_npmfilter`
summary.

**`dist-tags` are never moved.** `latest` keeps naming the version upstream
published, even when that version is withheld, so asking for it fails and says
so. Moving the tag onto an older surviving release would be a silent downgrade,
and older releases are the ones carrying known vulnerabilities. Set
`allow_dist_tag_downgrade = true` if you want that behaviour anyway. There is one
gap here worth knowing about — see the limitations below.

Because the ledger records every version it observes, including the blocked ones,
the quarantine window doubles as an observation window. A version published today
has its hash recorded today, and by the time it is old enough to install, the
daemon already knows whether that hash held still for thirty days. A recorded
hash is never overwritten — it is the evidence — so a mismatch bumps a counter
and a timestamp instead, and `npmfilter_ledger` shows how many times a
replacement has been attempted.

## What it refuses to do

- **Tarballs are pass-through.** `dist.tarball` keeps pointing at the upstream
  registry, so no package bytes ever transit or are stored here, and your
  lockfiles stay portable on machines that have never heard of npmfilter.
- **Only reads get through.** `GET` and `HEAD`, plus `POST` to the two read-only
  registry endpoints, are the whole allow-list. `PUT`, `DELETE`, `PATCH`, `POST`
  to a package path and any other verb — `COPY` and `PROPFIND` included — answer
  `405` with the same actionable error: npmfilter is a read-through filter and
  holds no credentials, so a publish belongs at the registry that should receive
  it. Put `@yourscope:registry=https://your.registry/` in `.npmrc`, or pass
  `--registry`. `allow_publish_passthrough = true` relays them instead and audits
  every one.
- **A path with a `.` or `..` segment answers `400`** and is never forwarded.
  npmfilter reads the path as written; a URL parser downstream would collapse the
  dot segments first, and two readings of one path is a way past every gate.
- **Error bodies never echo the registry.** What a client is told names the gate
  and the tool that shows the evidence, never the tampered hash or the offending
  command line. Reproducing a hostile upstream's strings into the body npm parses
  would be lending it a channel it did not have. The evidence lives in the audit
  log and on the control socket, where only someone already trusted to approve
  packages can read it.
- **`npm audit` and search keep working.** `/-/v1/search` and
  `/-/npm/v1/security/advisories/bulk` are proxied untouched, as is any path the
  daemon does not recognise.

## Watching it work

```sh
systemctl status npmfilter
journalctl -u npmfilter -f
```

One log line per filtered packument, with the withheld count and a breakdown by
reason. The full-form response carries an `_npmfilter` object listing every
withheld version and why, which makes `curl` a first-class debugging tool:

```sh
curl -s http://127.0.0.1:4874/esbuild | jq '._npmfilter'
```

State lives in `/var/lib/npmfilter/rules.db` — rules, the integrity ledger and
the audit log, mode `0600` in a `0700` directory, opened by the daemon and
nothing else. It is the only thing here worth backing up. Losing it costs you
your approvals plus the ledger's history, which then re-establishes itself on
first use with trust-on-first-use semantics again.

## Known limitations

The short list. The reasoned version, with the attacker classes each of these
does and does not cover, is [SECURITY.md](SECURITY.md).

- **`npm install <pkg>` with no version can still resolve to an old release.** A
  bare install asks npm for the range `*`, not for the `latest` tag, so when
  `latest` is withheld npm quietly takes the newest surviving version instead of
  failing. On a package where every recent release carries an install hook that
  can be a very old one. bun fails cleanly here; npm does not. Ask for a version
  explicitly, or approve the one `latest` names.
- **The gate is resolution-time only.** A committed lockfile pins
  `registry.npmjs.org` tarball URLs, so `npm ci` bypasses npmfilter entirely.
  That is the direct cost of pass-through tarballs and portable lockfiles. Locked
  installs are covered by the lockfile's own sha512, not by this daemon.
- **The daemon becomes a hard dependency of installs** once the registry points
  at it. `Restart=always` and a loud failure mitigate; they do not eliminate.
- Age and script gates do not detect a compromised package that is older than the
  window and carries no install hook.
- Packument metadata is trusted for script detection. The tarball is read only at
  `inspect` and approval time, which is where the sha pin is established.
- **The integrity ledger is trust-on-first-use.** If the very first observation
  of a version is already malicious, that hash becomes the trusted baseline. The
  age gate limits the damage — versions are normally first observed while
  quarantined and only served after 30 unchanged days — but a package first seen
  *after* it was already compromised inherits the bad hash.
- **The integrity ledger has a retention.** A version not observed for a year,
  never mismatched and named by no rule, is dropped and re-pinned to whatever is
  served next. The alternative is a table that only grows, and a full disk fails
  closed into a machine where nothing installs.
- **`dist.tarball` is not pinned to the upstream host.** A tarball URL on another
  host is recorded once per package (`foreign_tarball`, warning) rather than
  blocked — a mirror serving `registry.npmjs.org` URLs is the arrangement this
  tool is built around. The version's own `dist.integrity` verifies those bytes,
  and a version with no hash at all is never served.
- **Seeding verifies the hash, not the choice.** The daemon proves every pinned
  hash is the one the registry serves. It cannot tell you those were the right
  versions to install.
- **npmfilter holds no credentials, so it is not a credential boundary.** It
  forwards the header a client sends and stores no token of its own.
