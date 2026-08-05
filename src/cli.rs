//! Command-line surface — DESIGN.md "Architecture".
//!
//! All eight subcommands are wired. `serve` is the daemon. Everything else — `mcp`, `inspect`,
//! `allow`, `deny`, `rules`, `status`, `seed` — is a **client of the daemon's control socket**
//! ([`crate::control`]), so an approval recorded from a terminal and one recorded by an agent
//! are the same row, written by the same validated and audited code path in the same process.
//! Only the rendering differs: the MCP tools answer JSON, these answer text.
//!
//! None of them opens the state database. If the daemon is not running they fail and say how
//! to start it; there is no silent fallback to writing `rules.db` directly.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::Config;
use crate::control::LABEL_CLI;
use crate::control::client::{ControlClient, send_blocking};
use crate::control::protocol::{
    AllowArgs, Answer, DenyArgs, InspectArgs, PinRequest, Request, RulesArgs, StatusArgs,
};
use crate::mcp::inspect::InspectReport;
use crate::mcp::{RuleView, RuleWritten, RulesReport, StatusReport};

/// Local npm registry filtering daemon.
#[derive(Debug, Parser)]
#[command(name = "npmfilter", version, about, long_about = None)]
pub struct Cli {
    /// Config file to load instead of /etc/npmfilter/config.toml.
    #[arg(short, long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Tracing filter directive, overriding `log_level` from the config.
    #[arg(long, global = true, value_name = "LEVEL")]
    pub log_level: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

/// The subcommands of `npmfilter`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the filtering registry proxy.
    Serve,

    /// Run the MCP stdio shim that talks to the daemon.
    Mcp,

    /// Inspect a package version: age, integrity, install hooks, script delta.
    Inspect {
        /// Package name, e.g. `sqlite3` or `@scope/name`.
        package: String,
        /// Version to inspect. Defaults to the newest published version.
        version: Option<String>,
    },

    /// Approve a package version, pinned to its current integrity and script hashes.
    Allow {
        /// Package name.
        package: String,
        /// Exact version to approve.
        version: String,
        /// Why this approval was granted.
        #[arg(short, long)]
        reason: Option<String>,
        /// A file inside the published tarball this approval is pinned to, package-relative
        /// (e.g. `install.js`). Repeatable. The daemon fetches the tarball and hashes each
        /// one itself, so a pin always describes bytes that were really published.
        #[arg(long = "pin")]
        pin: Vec<String>,
    },

    /// Block a package version outright.
    Deny {
        /// Package name.
        package: String,
        /// Exact version to deny.
        version: String,
        /// Why this version was denied.
        #[arg(short, long)]
        reason: Option<String>,
    },

    /// List existing allow/deny rules.
    Rules {
        /// Only show rules for this package.
        #[arg(short, long)]
        package: Option<String>,
    },

    /// Show daemon health, active policy and rule counts.
    Status,

    /// Pre-approve the install-script packages already present in a node_modules tree.
    #[command(long_about = crate::seed::seed_long_about())]
    Seed {
        /// Project root or node_modules directory to seed from.
        #[arg(default_value = ".")]
        path: PathBuf,
        /// List what would be approved without writing any rule. The daemon still verifies
        /// every entry against the registry.
        #[arg(long)]
        dry_run: bool,
        /// Skip the upstream verification of every pinned hash. Reduced assurance: the rules
        /// are pinned to whatever the lockfile on disk says, unchecked. Recorded as such.
        #[arg(long)]
        offline: bool,
    },
}

impl Command {
    /// Short name of the subcommand, for logs and messages.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Serve => "serve",
            Command::Mcp => "mcp",
            Command::Inspect { .. } => "inspect",
            Command::Allow { .. } => "allow",
            Command::Deny { .. } => "deny",
            Command::Rules { .. } => "rules",
            Command::Status => "status",
            Command::Seed { .. } => "seed",
        }
    }
}

/// Run one subcommand.
pub fn run(command: &Command, config: Config) -> anyhow::Result<()> {
    match command {
        // DESIGN.md "Build order" step 3 — the filtering registry proxy.
        Command::Serve => crate::proxy::serve_blocking(config),
        // DESIGN.md "Build order" step 6 — the MCP stdio shim.
        Command::Mcp => crate::mcp::serve_blocking(config),
        // DESIGN.md "Build order" step 5 — pre-approve what is already installed.
        Command::Seed {
            path,
            dry_run,
            offline,
        } => crate::seed::run(path, *dry_run, *offline, &config),
        Command::Status => {
            let report = match ask(&config, Request::Status(StatusArgs {}))? {
                Answer::Status(report) => *report,
                other => return Err(mismatch("status", &other)),
            };
            print!("{}", render_status(&report));
            Ok(())
        }
        Command::Inspect { package, version } => {
            let request = Request::Inspect(InspectArgs {
                package: package.clone(),
                version: version.clone(),
            });
            let report = match ask(&config, request)? {
                Answer::Inspect(report) => *report,
                other => return Err(mismatch("inspect", &other)),
            };
            print!("{}", render_inspect(&report));
            Ok(())
        }
        Command::Allow {
            package,
            version,
            reason,
            pin,
        } => {
            let request = Request::Allow(AllowArgs {
                package: package.clone(),
                version: version.clone(),
                reason: reason.clone(),
                pins: pin
                    .iter()
                    .map(|path| PinRequest {
                        path: path.clone(),
                        sha256: None,
                    })
                    .collect(),
            });
            let written = match ask(&config, request)? {
                Answer::Rule(written) => *written,
                other => return Err(mismatch("allow", &other)),
            };
            print!("{}", render_rule_written(&written));
            Ok(())
        }
        Command::Deny {
            package,
            version,
            reason,
        } => {
            let request = Request::Deny(DenyArgs {
                package: package.clone(),
                version: version.clone(),
                reason: reason.clone(),
            });
            let written = match ask(&config, request)? {
                Answer::Rule(written) => *written,
                other => return Err(mismatch("deny", &other)),
            };
            print!("{}", render_rule_written(&written));
            Ok(())
        }
        Command::Rules { package } => {
            let request = Request::Rules(RulesArgs {
                package: package.clone(),
                verdict: None,
            });
            let report = match ask(&config, request)? {
                Answer::Rules(report) => *report,
                other => return Err(mismatch("rules", &other)),
            };
            print!("{}", render_rules(&report));
            Ok(())
        }
    }
}

/// Send one request to the daemon over its control socket.
fn ask(config: &Config, request: Request) -> anyhow::Result<Answer> {
    let client = ControlClient::new(config.socket_path.clone(), LABEL_CLI);
    send_blocking(&client, request)
}

/// The daemon answered a different operation than the one that was asked.
fn mismatch(operation: &str, answer: &Answer) -> anyhow::Error {
    anyhow::anyhow!("the npmfilter daemon answered {operation} with a different result: {answer:?}")
}

/// `npmfilter status`.
pub fn render_status(report: &StatusReport) -> String {
    let mut out = format!("npmfilter {}\n\n", report.version);
    out.push_str(&format!(
        "daemon      {} — {}\n",
        report.daemon.listen,
        if report.daemon.reachable {
            "reachable"
        } else {
            "NOT REACHABLE"
        }
    ));
    out.push_str(&format!("upstream    {}\n", report.daemon.upstream));
    out.push_str(&format!(
        "policy      min_age_days={} install_script_quarantine_days={} packument_ttl_secs={} \
         bypass_scopes={}\n",
        report.policy.min_age_days,
        report.policy.install_script_quarantine_days,
        report.policy.packument_ttl_secs,
        if report.policy.bypass_scopes.is_empty() {
            "(none)".to_owned()
        } else {
            report.policy.bypass_scopes.join(", ")
        }
    ));
    out.push_str(&format!(
        "rules       {} allow, {} deny\n",
        report.rules.allow, report.rules.deny
    ));
    out.push_str(&format!("state       {}\n", report.state_path));
    out.push_str(&format!("transport   {}\n\n", report.transport));
    out.push_str(&report.daemon.detail);
    out.push('\n');
    out
}

/// `npmfilter rules`.
pub fn render_rules(report: &RulesReport) -> String {
    if report.rules.is_empty() {
        return "no rules recorded.\n".to_owned();
    }
    let mut out = format!("{} rule(s)\n", report.count);
    for rule in &report.rules {
        out.push_str(&render_rule(rule));
    }
    out
}

/// One rule, as `rules`, `allow` and `deny` all print it.
fn render_rule(rule: &RuleView) -> String {
    let mut out = format!("\n  {} {}@{}\n", rule.verdict, rule.package, rule.version);
    if let Some(integrity) = &rule.integrity {
        out.push_str(&format!("    pinned to       {integrity}\n"));
    }
    for hook in &rule.scripts {
        out.push_str(&format!(
            "    hook            {}: {}\n",
            hook.hook, hook.command
        ));
    }
    if let Some(scripts) = &rule.scripts_sha256 {
        out.push_str(&format!("    scripts sha256  {scripts}\n"));
    }
    for pin in rule.pins.iter().flatten() {
        out.push_str(&format!(
            "    pinned file     {} {}\n",
            pin.sha256, pin.path
        ));
    }
    if let Some(reason) = &rule.reason {
        out.push_str(&format!("    reason          {reason}\n"));
    }
    out.push_str(&format!(
        "    recorded        {} by {}\n",
        rule.created,
        rule.actor.as_deref().unwrap_or("<unknown>")
    ));
    out
}

/// `npmfilter allow` / `npmfilter deny`.
pub fn render_rule_written(written: &RuleWritten) -> String {
    format!("{}\n{}\n", render_rule(&written.rule), written.effect)
}

/// `npmfilter inspect`.
pub fn render_inspect(report: &InspectReport) -> String {
    let mut out = format!("{}@{}\n\n", report.package, report.version);
    out.push_str(&format!("version source  {}\n", report.version_source));
    out.push_str(&format!(
        "published       {} ({})\n",
        report.published.as_deref().unwrap_or("<unknown>"),
        report.age.as_deref().unwrap_or("age unknown")
    ));
    out.push_str(&format!(
        "dist.integrity  {}\n",
        report.dist_integrity.as_deref().unwrap_or("<none>")
    ));
    out.push_str(&format!(
        "dist.tarball    {}\n",
        report.dist_tarball.as_deref().unwrap_or("<none>")
    ));

    out.push_str("\ninstall hooks (from the tarball's package.json)\n");
    if report.install_hooks.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for hook in &report.install_hooks {
            out.push_str(&format!("  {}: {}\n", hook.hook, hook.command));
        }
    }
    out.push_str(&format!("  scripts sha256  {}\n", report.scripts_sha256));
    out.push_str(&format!(
        "  packument agrees: {}\n",
        report.scripts_match_packument
    ));

    out.push_str("\nscript delta versus the previous published version\n");
    out.push_str(&format!(
        "  previous        {}\n",
        report
            .script_delta
            .previous_version
            .as_deref()
            .unwrap_or("<none>")
    ));
    out.push_str(&format!(
        "  newly acquires install hooks: {}\n",
        report.script_delta.newly_acquires_install_hooks
    ));
    for hook in &report.script_delta.added {
        out.push_str(&format!("  added    {}: {}\n", hook.hook, hook.command));
    }
    for hook in &report.script_delta.removed {
        out.push_str(&format!("  removed  {}: {}\n", hook.hook, hook.command));
    }
    for change in &report.script_delta.changed {
        out.push_str(&format!(
            "  changed  {}: {} -> {}\n",
            change.hook, change.previous, change.current
        ));
    }
    out.push_str(&format!("  {}\n", report.script_delta.summary));

    if let Some(audit) = &report.pin_audit {
        out.push_str(&format!(
            "\npinned files versus the approval on {}\n",
            audit.pinned_version
        ));
        for change in &audit.changed {
            out.push_str(&format!(
                "  CHANGED  {}\n           pinned   {}\n           observed {}\n",
                change.path, change.pinned_sha256, change.observed_sha256
            ));
        }
        for path in &audit.missing {
            out.push_str(&format!("  MISSING  {path}\n"));
        }
        for path in &audit.unchanged {
            out.push_str(&format!("  same     {path}\n"));
        }
        out.push_str(&format!("  {}\n", audit.summary));
    }

    out.push_str("\npublisher\n");
    out.push_str(&format!(
        "  _npmUser        {}\n",
        report.npm_user.as_deref().unwrap_or("<unknown>")
    ));
    out.push_str(&format!(
        "  maintainers     {}\n",
        if report.maintainers.is_empty() {
            "<none>".to_owned()
        } else {
            report.maintainers.join(", ")
        }
    ));
    out.push_str(&format!(
        "  provenance      attested={} signatures={}\n",
        report.provenance.attested, report.provenance.signatures
    ));

    out.push_str("\ncontents\n");
    out.push_str(&format!(
        "  files           registry {} / observed {}\n",
        describe_measured(report.file_count.registry),
        report.file_count.observed
    ));
    out.push_str(&format!(
        "  unpacked bytes  registry {} / observed {}\n",
        describe_measured(report.unpacked_size.registry),
        report.unpacked_size.observed
    ));
    out.push_str(&format!(
        "  compressed      {} bytes streamed and discarded\n",
        report.compressed_bytes
    ));

    if !report.files.is_empty() {
        out.push_str(&format!(
            "\nfile manifest — sha256 of every published file, for `--pin`\n  {} file(s){}\n",
            report.file_count.observed,
            if report.files_truncated {
                format!(", showing the first {}", report.files.len())
            } else {
                String::new()
            }
        ));
        for file in &report.files {
            out.push_str(&format!(
                "  {}  {:>10}  {}\n",
                &file.sha256[..16],
                file.size,
                file.path
            ));
        }
    }

    if !report.notes.is_empty() {
        out.push_str("\nnotes\n");
        for note in &report.notes {
            out.push_str(&format!("  - {note}\n"));
        }
    }
    out
}

fn describe_measured(value: Option<u64>) -> String {
    match value {
        Some(value) => value.to_string(),
        None => "<none>".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn serve_parses_with_global_config_flag() {
        let cli = Cli::try_parse_from(["npmfilter", "--config", "/tmp/x.toml", "serve"])
            .expect("serve parses");
        assert_eq!(
            cli.config.as_deref(),
            Some(std::path::Path::new("/tmp/x.toml"))
        );
        assert!(matches!(cli.command, Command::Serve));
    }

    #[test]
    fn every_subcommand_parses() {
        let cases: Vec<Vec<&str>> = vec![
            vec!["npmfilter", "serve"],
            vec!["npmfilter", "mcp"],
            vec!["npmfilter", "inspect", "sqlite3"],
            vec!["npmfilter", "inspect", "sqlite3", "5.1.7"],
            vec![
                "npmfilter",
                "allow",
                "sqlite3",
                "5.1.7",
                "--reason",
                "build tool",
            ],
            vec!["npmfilter", "deny", "keyv", "6.0.0"],
            vec!["npmfilter", "rules", "--package", "keyv"],
            vec!["npmfilter", "status"],
            vec!["npmfilter", "seed", "/srv/app", "--dry-run"],
            vec!["npmfilter", "seed", "/srv/app", "--offline"],
        ];
        for case in cases {
            let cli = Cli::try_parse_from(case.clone()).unwrap_or_else(|e| panic!("{case:?}: {e}"));
            assert!(!cli.command.name().is_empty());
        }
    }

    #[test]
    fn seed_defaults_to_current_directory() {
        let cli = Cli::try_parse_from(["npmfilter", "seed"]).expect("seed parses");
        match cli.command {
            Command::Seed {
                path,
                dry_run,
                offline,
            } => {
                assert_eq!(path, PathBuf::from("."));
                assert!(!dry_run);
                assert!(!offline, "verification is on unless it is switched off");
            }
            other => panic!("expected seed, got {other:?}"),
        }
    }

    #[test]
    fn status_renders_the_policy_and_the_rule_counts() {
        let report = StatusReport {
            version: "0.1.0".to_owned(),
            daemon: crate::mcp::DaemonStatus {
                listen: "127.0.0.1:4874".to_owned(),
                reachable: false,
                upstream: "https://registry.npmjs.org".to_owned(),
                checked_at: "2026-08-05T00:00:00Z".to_owned(),
                detail: "nothing is listening".to_owned(),
            },
            policy: crate::mcp::PolicyStatus {
                min_age_days: 30,
                install_script_quarantine_days: 7,
                bypass_scopes: vec!["@olamedia".to_owned()],
                packument_ttl_secs: 60,
            },
            rules: crate::mcp::RuleCounts { allow: 7, deny: 2 },
            state_path: "/var/lib/npmfilter/rules.db".to_owned(),
            transport: "unix socket /run/npmfilter/npmfilter.sock".to_owned(),
        };
        let text = render_status(&report);
        assert!(text.contains("NOT REACHABLE"), "{text}");
        assert!(text.contains("min_age_days=30"), "{text}");
        assert!(text.contains("7 allow, 2 deny"), "{text}");
        assert!(text.contains("@olamedia"), "{text}");
    }

    #[test]
    fn rules_renders_an_empty_list_without_pretending_it_has_rules() {
        let text = render_rules(&RulesReport {
            count: 0,
            rules: Vec::new(),
        });
        assert_eq!(text, "no rules recorded.\n");
    }
}
