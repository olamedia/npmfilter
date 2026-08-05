# npmfilter

Someone steals a maintainer's npm password and pushes a new version of a package
you already use, with one line added:

```json
"scripts": { "preinstall": "node setup.mjs" }
```

Your next `npm install` runs it. It takes your npm token, your AWS keys, your
GitHub token — then uses your npm token to do the same to the packages *you*
publish.

This happened on 4 August 2026 to `keyv`, `flat-cache` and about 434 other
packages. It will happen again.

**Every attack like this needs the same thing: that you install a version
published a few hours ago.** Nobody has noticed it yet. That is the whole window.

npm has no way to say *wait a month before handing me anything new*.

**npmfilter is that wait.** It sits between your package manager and npm. A
version has to be a month old, or approved by you, before you can get it.
Anything that runs a script while installing always needs your approval.

Nothing else changes — `npm install` and `bun install` work as they did.

## Why not something you already have

| | |
|---|---|
| `npm audit`, Dependabot, Snyk | They only know about problems someone already reported. This morning's package is on no list yet |
| `--ignore-scripts` | All or nothing. `esbuild` and `sqlite3` really do need theirs, so you turn it back on and you are where you started |
| pnpm and bun release-age settings | Good, use them too. But they are per project, and npm has nothing like them. One npm project is one hole |
| A lockfile | Protects what you already installed, not the package you are about to add |
| Verdaccio, Nexus, Artifactory | Mirrors. They copy npm, they do not say no to it |
| Hosted scanners | Your dependency list goes to someone else's server, and you need an account |

What is different here:

- **One thing, covering the whole machine.** npm and bun both go through it. A
  project that configured nothing is covered anyway.
- **It says no instead of warning you.** A blocked version simply is not offered,
  so there is nothing to click past at 6pm on a Friday.
- **Nothing leaves your machine.** No account, no upload, no copies of packages
  kept anywhere.
- **Approving is not forever.** Your yes covers exactly the version you looked
  at. Change the files, and it stops counting.
- **It notices when a version is quietly swapped.** Published versions never
  change. When one does, that is what you want to hear about.

What you give up:

- **A day of setup.** Your existing projects are full of packages that run
  install scripts. One command approves the ones you already have; new ones you
  approve as they come up.
- **Installs need the service running.** If it is down, installs fail. On
  purpose — a lock that opens when it breaks is not a lock.
- **`npm ci` skips it.** Lockfile installs go straight to npm.
- **`npm install <name>` can still pick an old version** instead of failing, when
  the newest one is being held. bun fails properly; npm does not.

**Next:** [INSTALL.md](INSTALL.md) to set it up · [USAGE.md](USAGE.md) when an
install fails · [SECURITY.md](SECURITY.md) for what it does and does not defend.

---

## What using it feels like

esbuild runs a script when it installs, so you are asked about it:

```console
$ bun add esbuild
error: Package "esbuild" with tag "latest" not found, but package exists
```

Ask what it wants to run (shortened — the real output says more):

```console
$ npmfilter inspect esbuild 0.28.1
published       2026-06-11T22:47:05.085Z (54 days old)

install hooks (from the tarball's package.json)
  postinstall: node install.js

script delta versus the previous published version
  previous        0.28.0
  newly acquires install hooks: false

publisher
  _npmUser        GitHub Actions
  provenance      attested=true signatures=1

file manifest — sha256 of every published file, for `--pin`
  417cbbaf3ea9cb87       11037  install.js
  9425d36afcd1c854       87971  lib/main.js
```

Read `install.js`, decide it is fine, and say so:

```console
$ npmfilter allow esbuild 0.28.1 --pin install.js \
    --reason "downloads the platform binary from npm"
```

That is it — esbuild installs from now on. And when esbuild ships its next
release, you are told whether the file you read is still the same file:

```console
pinned files versus the approval on 0.28.1
  CHANGED  install.js
```

That last line is the point. `postinstall: node install.js` looks the same in
every esbuild release ever published, so nobody watching the command would ever
see `install.js` itself being rewritten. You would.

An agent can do all of this for you — see
[INSTALL.md](INSTALL.md#register-the-mcp-shim).

## What it checks, in order

Each version of a package is asked these questions. The first one that answers
decides, and the answer is never a warning — the version is either offered to
your package manager or it is not there at all.

| | | |
|---|---|---|
| 1 | Has this exact version been served before with different content? | **No.** Nothing overrides this one, not even your approval |
| 2 | Did you say no to it? | No |
| 3 | Does it run something on install, and is it less than a week old? | **No.** Your approval is recorded and starts working when the week is up |
| 4 | Did you approve it, and is it still exactly what you approved? | Yes |
| 5 | Is it one of your own scopes? | Yes |
| 6 | Does it publish no checksum at all? | No — there would be nothing to hold it to |
| 7 | Is it younger than 30 days? | No |
| 8 | Does it run something on install? | No, and you are told the command |
| 9 | Otherwise | Yes |

Each answer has a short reason code that shows up when an install fails.
[USAGE.md](USAGE.md#block-reasons) lists them and what to do about each.

**`latest` always means latest.** When the newest release is being held,
npmfilter does not quietly point `latest` at an older one. Asking for it fails
and tells you why. A silent downgrade would hand you a release with known
problems in it, which is not an improvement.

Every version it sees gets written down, held or not. So by the time something
becomes old enough to install, npmfilter already knows whether it sat still for
those 30 days or was changed underneath.

## A few things worth knowing

- **Packages still download from npm directly.** Nothing is cached or copied
  here, so your lockfiles work on machines that never heard of npmfilter.
- **You cannot publish through it.** It holds no login of yours, so a publish
  goes to the registry that should receive it. Details in
  [USAGE.md](USAGE.md#http-responses).
- **`npm audit` and search work as before.**
- **Everything it does is in one file** — your approvals, the history and the
  log, at `/var/lib/npmfilter/rules.db`. That file is the only thing here worth
  backing up.

```sh
journalctl -u npmfilter -f
```

## What it does not defend

The four you meet in practice are at the top of this page. The full account, with
the kind of attacker each gap lets through, is in [SECURITY.md](SECURITY.md).
Read it before you rely on this.
