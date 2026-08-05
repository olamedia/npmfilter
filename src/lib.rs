//! NpmFilter — local npm registry filtering daemon.
//!
//! See `DESIGN.md` at the repository root. This crate is built in the order given by
//! DESIGN.md "Build order"; step 1 delivers the skeleton (config + CLI) and step 2's
//! policy engine, which is a pure function over `serde_json` values. Step 4 delivers the
//! SQLite [`store`], which backs that engine's `RuleStore` and `IntegrityLedger` traits with
//! the `rules`, `seen` and `audit` tables. Step 3 delivers the [`proxy`] — the axum daemon
//! behind `npmfilter serve`, which is what actually filters what npm resolves. Step 5 delivers
//! [`seed`] and step 6 the [`mcp`] stdio shim.
//!
//! [`control`] is the Unix socket of DESIGN.md "MCP transport", and it is what makes the
//! daemon the **sole writer** of the state database: `mcp`, `seed` and every CLI subcommand
//! are clients of it, so every approval crosses one validator and lands in one audit log.

pub mod cli;
pub mod config;
pub mod control;
pub mod mcp;
pub mod policy;
pub mod proxy;
pub mod seed;
pub mod store;
