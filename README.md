# npmfilter

## The problem

Someone steals a maintainer's npm password and pushes a new version of a package
you already use, with one line added to it: `"preinstall": "node setup.mjs"`.
Your next `npm install` runs that line before anything else happens. It takes
your npm token, your AWS keys and your GitHub token, and then uses your npm token
to do the same thing to the packages you publish.

On 4 August 2026 the Shai-Hulud worm did this through `keyv`, `flat-cache` and
around 434 other packages.

## The window

Every attack of this shape needs one thing from you: that you install a version
published a few hours ago, while nobody has noticed it yet. npm has no setting, at
any level, that says *wait a month before handing me anything new*.

## What npmfilter does

npmfilter is that wait. It sits between your package manager and npm, and a
version has to be a month old, or approved by you, before you can install it.
Anything that runs a script while installing always needs your approval, however
old it is. Nothing else changes — `npm install` and `bun install` work the way
they always did.

## Why not what you already run

`npm audit`, Dependabot and Snyk match against lists of problems somebody has
already reported, and this morning's package is on no list yet. `--ignore-scripts`
is all or nothing, and `esbuild` and `sqlite3` genuinely need theirs. pnpm and bun
can enforce a minimum release age, which is worth switching on, but it is per
project and npm has no equivalent. Verdaccio, Nexus and Artifactory mirror npm;
refusing a version is not what they do. Hosted scanners want your dependency list
on their server and an account to go with it.

## Let the agent do the reviewing

Your coding agent sees what was held back, reads the install script, and records
the approval against that exact file — so the same
file quietly rewritten in a later release comes back as a question instead of an
update. Registering it is one command, in
[INSTALL.md](INSTALL.md#register-the-mcp-shim).

## What it costs you

Setting it up is a few lines of copy-paste. After that, installs need the service
running: if it is down, they fail on purpose. Your CI is untouched — `npm ci`
installs exactly what the lockfile pins and checks those hashes itself, and it
never picks up a version you did not choose. New versions arrive on your own
machine, which is where this sits. One rough edge: `npm install <name>` with no
version can still settle on an older release instead of failing, when the newest
one is being held. bun fails properly; npm does not.

## Where to go next

[INSTALL.md](INSTALL.md) sets it up. [USAGE.md](USAGE.md) is what you read when
an install stops — every check it makes, in order, and what each refusal means.
[SECURITY.md](SECURITY.md) is where the gaps are written down, including the ones
above. Read that one before you rely on any of this.
