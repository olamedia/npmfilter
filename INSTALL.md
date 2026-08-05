# Installing npmfilter

Four steps, in this order. Steps 1 and 2 are safe to do and undo; step 3 is the
one that changes how your machine installs packages.

1. [Install the package](#1-install-the-package) — puts the binary and the unit on disk
2. [Start the daemon](#2-start-the-daemon) — it filters nothing until you point something at it
3. [Seed from a tree you already trust](#3-seed-before-you-switch) — do this **before** step 4
4. [Adopt it](#4-adopt-it) — point npm or bun at the daemon

Then, optionally, [register the MCP shim](#register-the-mcp-shim) so an agent can
inspect and approve packages for you.

---

## 1. Install the package

```sh
sudo dpkg -i npmfilter_0.5.5_amd64.deb          # Debian, Ubuntu
sudo rpm -i npmfilter-0.5.5-1.x86_64.rpm        # Fedora, RHEL, openSUSE
```

You get:

| Path | What |
|---|---|
| `/usr/bin/npmfilter` | the binary — daemon, CLI and MCP shim in one |
| `/etc/npmfilter/config.toml` | config, marked as a conffile so your edits survive upgrades |
| `/var/lib/npmfilter/` | rules, the integrity ledger and the audit log, mode `0700` |
| `/run/npmfilter/npmfilter.sock` | the control socket, `npmfilter:npmfilter` mode `0660` |
| systemd unit `npmfilter.service` | runs as a dedicated `npmfilter` system user |

**Installing does not start anything.** `postinst` prints the commands and stops.
A daemon that every `npm install` on the machine will depend on should start
because you decided it should, not because a package manager unpacked a file.

To build the packages yourself:

```sh
cargo deb                                        # -> target/debian/npmfilter_0.5.5_amd64.deb
cargo generate-rpm                               # -> target/generate-rpm/npmfilter-0.5.5-1.x86_64.rpm
dpkg -c target/debian/npmfilter_0.5.5_amd64.deb  # inspect before installing
```

`cargo deb` and `cargo generate-rpm` come from `cargo install cargo-deb
cargo-generate-rpm`. The build needs `cmake` — reqwest's TLS stack builds its C
sources with it.

## 2. Start the daemon

```sh
sudo systemctl enable --now npmfilter
systemctl status npmfilter
curl -s http://127.0.0.1:4874/is-odd | head -c 200
```

That last line proves the proxy answers. Nothing resolves through it yet — no
package manager knows it exists until step 4.

Join the group that may approve packages, then start a **new login session** so
the membership applies:

```sh
sudo adduser $USER npmfilter
```

Membership in `npmfilter` is the ability to approve any package for the whole
machine. Grant it as deliberately as you would `docker`.

## 3. Seed before you switch

Every version carrying an install hook is withheld, and a normal `node_modules`
tree is full of them: `esbuild`, `sqlite3`, `better-sqlite3`, `lightningcss`,
`@parcel/watcher`. Skip this step and your first install after adopting stops
dead on all of them at once, which teaches you nothing except that the gate
works.

`seed` walks a tree you already have, finds every installed package that declares
an install hook, and has the daemon record one allow rule each — pinned to the
real `dist.integrity` npm recorded on disk (`node_modules/.package-lock.json`,
`package-lock.json`, `npm-shrinkwrap.json`) **and** to a sha256 of the exact hook
commands.

```sh
npmfilter seed ~/your-project --dry-run    # verifies everything, writes nothing
npmfilter seed ~/your-project              # records the rules
```

The lockfile is not taken at its word. Before writing anything, the daemon
fetches the packument for every `(name, version)` and confirms that both the hash
**and** the install-hook commands are what the registry actually serves. A
lockfile is exactly as trustworthy as the tree it describes, and the tree is the
thing being vetted. An entry that disagrees is refused, reported and audited, and
gets no rule.

`--dry-run` prints, per package, the hook commands, their script hash, the
`dist.integrity` it would pin to and where on disk it read it from, plus a
reproducible hash of the unpacked directory so you can compare two machines — and
the daemon's verdict on each. A package whose integrity is nowhere on disk (a
workspace link, a `file:` dependency) is listed as unpinnable and gets **no** rule
rather than a poisoned one.

```sh
npmfilter seed ~/your-project --offline    # skips verification
```

`--offline` skips the upstream check entirely. It prints a prominent warning and
records the reduced assurance in every rule's reason, because a rule written that
way is pinned to whatever the file on disk said, unchecked. Re-seed online when
you can.

Seeding still trusts this tree's *choice* of versions. The daemon can prove a
hash is genuine; it cannot tell whether that version should have been installed
in the first place. Only seed a tree you installed from a lockfile you trust.

The daemon must be running — it is the only thing that writes rules. They take
effect on the next request, with no restart.

## 4. Adopt it

Start per project. It is reversible, reviewable, and what you want while you are
still deciding whether you like this:

```sh
echo 'registry=http://127.0.0.1:4874/' >> .npmrc
```

For every npm project of the current user:

```sh
npm config set registry http://127.0.0.1:4874/
npm config delete registry              # to undo
```

bun reads its own file. Add this to the project's `bunfig.toml`, or to
`~/.bunfig.toml` to cover everything:

```toml
[install]
registry = "http://127.0.0.1:4874/"
```

**The package will never write these files for you.** Redirecting a package
manager changes how every install in that scope resolves, and unpacking a `.deb`
is not consent to that.

Once adopted, the daemon is a hard dependency of installs in that scope. It runs
`Restart=always` and a failure is loud, but the dependency is real: if the daemon
is down and the registry points at it, installs fail. That is the intended
direction.

---

## Register the MCP shim

The shim lets an agent run the whole review in one conversation: see what was
blocked, inspect the package, approve it. Both paths write the same rows the same
way, because both are requests to the same daemon.

Claude Code, for every project of the current user:

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
open the socket until a tool is actually called. A client registered from a login
session older than your `adduser` connects happily and then fails on every tool.
Either start a new login session, or register it wrapped so the group applies
regardless:

```sh
claude mcp add npmfilter -s user -- sg npmfilter -c "exec /usr/bin/npmfilter mcp"
```

If you would rather not put your own account in the `npmfilter` group, run the
shim as the daemon's user instead:

```json
{ "command": "sudo", "args": ["-u", "npmfilter", "/usr/bin/npmfilter", "mcp"] }
```

The shim opens no database. It is a **client** of the control socket, exactly
like `npmfilter allow`, `deny`, `rules`, `status`, `inspect` and `seed`. The
daemon is the only process that writes `rules.db`, so every approval crosses one
validator, is attributed to the uid the kernel reports for the connection, and
lands in one audit log. If the daemon is not running, these commands fail and
tell you how to start it. They never fall back to writing the database directly.

---

## Configure it

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

`sudo systemctl restart npmfilter` after editing.

An **unknown key is a hard error** and the daemon refuses to start. A typo'd
`bypass_scope` that silently did nothing would leave you trusting a policy that
is not being enforced.

Two settings deserve a second thought before you change them:

- **`listen` should stay on loopback.** The daemon forwards the client's
  `Authorization` header upstream, so anything that can reach it can use your
  registry credentials.
- **`bypass_scopes` skips the age and install-script gates** for the scopes you
  name. The integrity ledger and deny rules still apply to them.

The full option reference is in [USAGE.md](USAGE.md#configuration), including the
limits that are deliberately not configurable.

## Uninstall

```sh
sudo systemctl disable --now npmfilter
npm config delete registry              # and remove any registry= lines you added
sudo dpkg -r npmfilter                  # or: sudo rpm -e npmfilter
```

Undo the adoption **before** removing the package, or every install in that scope
fails until you do. `dpkg -r` leaves `/var/lib/npmfilter` in place; `dpkg -P`
purges it, which throws away your approvals and the integrity ledger's history.
