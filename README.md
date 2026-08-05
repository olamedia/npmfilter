# npmfilter

## The problem

Someone steals a maintainer's npm password and pushes a new version of a package
you already use, with one line added to it: `"preinstall": "node setup.mjs"`.
Your next `npm install` runs that line before anything else happens. It takes
your npm token, your AWS keys and your GitHub token, and then uses your npm token
to do the same thing to the packages you publish.

That is not hypothetical. On 4 August 2026 the Shai-Hulud worm did exactly this
through `keyv`, `flat-cache` and around 434 other packages, and it was not the
first time.

## The window

Every attack of this shape needs one thing from you: that you install a version
published a few hours ago, while nobody has noticed it yet. That window is the
whole attack. npm gives you no way to hold it shut — there is no setting, at any
level, that says *wait a month before handing me anything new*.

## What npmfilter does

npmfilter is that wait. It sits between your package manager and npm, and a
version has to be a month old, or approved by you, before you can install it.
Anything that runs a script while installing always needs your approval, however
old it is. Nothing else changes — `npm install` and `bun install` work the way
they always did.

## Why not what you already run

You may think something you already run covers this. Most likely it does not.
`npm audit`, Dependabot and Snyk match against lists of problems somebody has
already reported, and this morning's package is on no list yet. `--ignore-scripts`
is all or nothing, and `esbuild` and `sqlite3` genuinely need theirs, so you turn
it back on and you are where you started. pnpm and bun can enforce a minimum
release age, which is worth switching on, but it is per project and npm has
nothing like it, so one npm project is one hole. Verdaccio, Nexus and Artifactory
mirror npm rather than refuse it. Hosted scanners want your dependency list on
their server and an account to go with it.

## Let the agent do the reviewing

Point your coding agent at npmfilter and the reviewing stops being your job: it
sees what was held back, reads the install script itself, and records the
approval against that exact file, so the same file quietly rewritten in a later
release comes back to you as a question instead of an update. Registering it is
one command, in [INSTALL.md](INSTALL.md#register-the-mcp-shim).

## What it costs you

Setting the whole thing up is a few lines of copy-paste. After that the real cost
is that installs need the service running: if it is down they fail, on purpose,
because a lock that opens when it breaks is not a lock. Your CI is untouched —
`npm ci` installs exactly what the lockfile pins and checks those hashes itself,
and it never picks up a version you did not choose, which is the only thing
npmfilter is here to stop. New versions arrive on your own machine, and that is
where this sits. One rough edge worth knowing: `npm install <name>` with no
version can still settle on an older release rather than failing, when the newest
one is being held. bun fails properly; npm does not.

## Where to go next

[INSTALL.md](INSTALL.md) sets it up. [USAGE.md](USAGE.md) is what you read when
an install stops — every check it makes, in order, and what each refusal means.
[SECURITY.md](SECURITY.md) is where the gaps are written down, including the ones
above. Read that one before you rely on any of this.
