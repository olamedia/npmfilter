//! The control plane — DESIGN.md "MCP transport": a Unix socket to the daemon.
//!
//! Everything that changes npmfilter's policy goes through here. `npmfilter allow` at a
//! terminal, `npmfilter_allow` from an agent over MCP, and `npmfilter seed` are all clients of
//! one socket; the daemon behind it is the only process that ever opens `rules.db`.
//!
//! # What this replaces, and why
//!
//! The first implementation had the MCP shim and the CLI open the SQLite state file directly.
//! That is why `/var/lib/npmfilter` shipped `2770`: for the shim to write an approval, group
//! `npmfilter` had to be able to write the database. The consequence was that group membership
//! was the ability to **write allow rules straight into the policy store**, bypassing the
//! daemon's validation and its audit log — an `UPDATE rules SET integrity = …` was a supported
//! way to approve a package, and nothing recorded that it had happened.
//!
//! With the socket, the same group membership means "may ask the daemon to approve something".
//! The request is bounded, parsed strictly, validated field by field, attributed to a peer the
//! kernel identified, and recorded. The database is `0600` in a `0700` directory and has one
//! writer.
//!
//! # Hard limits
//!
//! The frame cap, the per-field lengths, the seed-entry ceiling, the connection timeout and
//! the concurrency ceiling are compile-time constants in [`protocol`]. None of them is a
//! config key: a config field for a hard limit is a way to weaken the daemon.

pub mod client;
pub mod protocol;
pub mod server;
pub mod service;

#[cfg(test)]
mod tests;

pub use client::{ClientError, ControlClient};
pub use protocol::{
    Answer, MAX_REQUEST_BYTES, MAX_SEED_ENTRIES, PROTOCOL_VERSION, Request, RequestEnvelope,
    ResponseEnvelope, SeedArgs, SeedEntry, SeedOutcome, SeedResult, ValidationError,
};
pub use service::{ControlError, ControlService};

/// The mode the control socket is set to: owner and group read/write, nothing for others.
///
/// Group `npmfilter` is the approval group. Making this `0666` would hand every local account
/// the right to approve any package on the machine.
pub const SOCKET_MODE: u32 = 0o660;

/// The client label `npmfilter mcp` sends.
pub const LABEL_MCP: &str = "mcp";
/// The client label the CLI subcommands send.
pub const LABEL_CLI: &str = "cli";
/// The client label `npmfilter seed` sends.
pub const LABEL_SEED: &str = "seed";

/// Who asked.
///
/// The uid, gid and pid come from the connection's peer credentials, which the kernel fills in
/// and a client cannot choose. The label comes from the request and is decoration: it says
/// which entry point was used, not who used it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    /// The peer's user id.
    pub uid: u32,
    /// The peer's primary group id.
    pub gid: u32,
    /// The peer's process id, when the platform reports one.
    pub pid: Option<i32>,
    /// The entry point the request claims to be.
    pub label: String,
}

impl Actor {
    /// Build from the peer credentials of a connection.
    pub fn from_cred(cred: &tokio::net::unix::UCred) -> Self {
        Self {
            uid: cred.uid(),
            gid: cred.gid(),
            pid: cred.pid(),
            label: String::new(),
        }
    }

    /// Attach the label the request carried, keeping it short and printable.
    pub fn with_label(mut self, label: &str) -> Self {
        self.label = label
            .chars()
            .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
            .take(32)
            .collect();
        self
    }

    /// How this actor is written to the `actor` column and the audit log.
    ///
    /// The uid comes first because it is the part that was verified.
    pub fn render(&self) -> String {
        let mut out = format!("uid={}", self.uid);
        if let Some(pid) = self.pid {
            out.push_str(&format!(" pid={pid}"));
        }
        if !self.label.is_empty() {
            out.push_str(&format!(" via={}", self.label));
        }
        out
    }
}
