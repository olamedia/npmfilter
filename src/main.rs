//! `npmfilter` — local npm registry filtering daemon. See `DESIGN.md`.

use anyhow::{Context, Result};
use clap::Parser;
use npmfilter::cli::Cli;
use npmfilter::config::Config;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let cli = Cli::parse();

    let config = Config::load(cli.config.as_deref()).context("loading npmfilter configuration")?;
    let directive = cli
        .log_level
        .as_deref()
        .unwrap_or(config.log_level.as_str());
    init_tracing(directive)?;

    tracing::debug!(
        command = cli.command.name(),
        listen = %config.listen,
        upstream = config.upstream_base(),
        min_age_days = config.min_age_days,
        packument_ttl_secs = config.packument_ttl_secs,
        "npmfilter starting"
    );

    npmfilter::cli::run(&cli.command, config)
}

/// Initialise tracing. `RUST_LOG` wins when set; otherwise the config directive applies.
///
/// Logs go to stderr because stdout is reserved for the MCP stdio protocol.
fn init_tracing(directive: &str) -> Result<()> {
    let filter = match EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => EnvFilter::try_new(directive)
            .with_context(|| format!("invalid log level {directive:?}"))?,
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
    Ok(())
}
