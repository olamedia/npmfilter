//! Daemon configuration — DESIGN.md "Config".
//!
//! Loaded from `/etc/npmfilter/config.toml` unless an override path is given. Every field
//! has a default, so the daemon runs with no config file present at all.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::policy::PolicyConfig;
use crate::store::{DEFAULT_STATE_PATH, Store, StoreError};

/// Where the daemon looks for its config when no override path is given.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/npmfilter/config.toml";
/// Default control-socket path — the daemon's only mutation entry point (DESIGN.md
/// "MCP transport"). systemd's `RuntimeDirectory=npmfilter` creates the parent.
pub const DEFAULT_SOCKET_PATH: &str = "/run/npmfilter/npmfilter.sock";
/// Default listen address — loopback only, port 4874 (DESIGN.md "Config").
pub const DEFAULT_LISTEN: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4874);
/// Default upstream registry.
pub const DEFAULT_UPSTREAM: &str = "https://registry.npmjs.org";
/// Default release-age gate, in days.
pub const DEFAULT_MIN_AGE_DAYS: u32 = 30;
/// Default in-memory packument TTL, in seconds.
pub const DEFAULT_PACKUMENT_TTL_SECS: u64 = 60;
/// Default audit-log retention, in days. `0` keeps every row forever.
pub const DEFAULT_AUDIT_RETENTION_DAYS: u32 = 90;
/// Default tracing filter directive.
pub const DEFAULT_LOG_LEVEL: &str = "info";
/// Default for `allow_publish_passthrough`: mutating methods are refused.
pub const DEFAULT_ALLOW_PUBLISH_PASSTHROUGH: bool = false;

/// Default for [`Config::allow_dist_tag_downgrade`]: never move a tag onto an older release.
///
/// A gate that silently downgrades is worse than one that fails: older versions are the ones
/// carrying known vulnerabilities, and the client is given no sign anything happened.
pub const DEFAULT_ALLOW_DIST_TAG_DOWNGRADE: bool = false;

/// Default for [`Config::install_script_quarantine_days`].
///
/// Seven days: long enough that a malicious release is normally found and pulled first
/// (Shai-Hulud's packages went within about a day), short enough that a genuinely urgent
/// native-package fix is not unreachable for a month.
pub const DEFAULT_INSTALL_SCRIPT_QUARANTINE_DAYS: u32 = 7;

/// Anything that can go wrong loading the config.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

/// Daemon configuration.
///
/// `deny_unknown_fields` is deliberate: a typo'd `bypass_scopes` or `min_age_days` that
/// silently did nothing would leave the operator believing in a policy the daemon is not
/// enforcing. An unknown key fails the load, and `npmfilter serve` refuses to start.
///
/// Note what is **not** here. The daemon's hard limits — body caps, cache capacity, tarball
/// limits, control-socket frame size, connection ceilings — are compile-time constants
/// ([`crate::proxy::MAX_PACKUMENT_BYTES`], [`crate::control::MAX_REQUEST_BYTES`], and the
/// rest). A config field is a way to weaken the daemon; these are not offered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Address the proxy binds to.
    pub listen: SocketAddr,
    /// Upstream registry base URL.
    pub upstream: String,
    /// Versions younger than this are withheld (0 disables the age gate).
    pub min_age_days: u32,
    /// Scopes exempt from the automatic gates, e.g. `@olamedia`.
    pub bypass_scopes: Vec<String>,
    /// In-memory packument cache TTL, in seconds.
    pub packument_ttl_secs: u64,
    /// How many days of `audit` rows to keep. `npmfilter serve` prunes older rows once at
    /// startup; `0` keeps everything.
    pub audit_retention_days: u32,
    /// Tracing filter directive, e.g. `info` or `npmfilter=debug,tower_http=info`.
    pub log_level: String,
    /// Where the rules store, integrity ledger and audit log live
    /// (DESIGN.md "Rules store"). Defaults to [`DEFAULT_STATE_PATH`].
    ///
    /// Only `npmfilter serve` ever opens this file. The MCP shim and the CLI subcommands
    /// reach daemon state over [`Config::socket_path`] instead, so the daemon is the single
    /// writer and every mutation is validated and audited on one code path.
    pub state_path: PathBuf,
    /// The Unix socket `npmfilter mcp` and the CLI subcommands talk to (DESIGN.md
    /// "MCP transport"). Mode 0660, owned by the daemon's user and group.
    pub socket_path: PathBuf,
    /// Whether mutating HTTP methods (`PUT`, `DELETE`, `PATCH`, and `POST` to a package path)
    /// are proxied upstream instead of refused.
    ///
    /// `false` — the default — refuses them all with an actionable error. `true` relays them
    /// **and** writes every one to the audit log with its method, path and actor. The
    /// `Authorization` value is never logged.
    pub allow_publish_passthrough: bool,
    /// Whether a `dist-tags` entry whose target was withheld may be moved to an older
    /// surviving version.
    ///
    /// `false` — the default — keeps every tag as upstream published it, so `latest` always
    /// means latest. A client asking for a withheld version fails to resolve and is told to
    /// review it; it is never quietly handed an older release instead. Set this to `true` only
    /// if you have decided you want that downgrade, deliberately and per machine.
    pub allow_dist_tag_downgrade: bool,
    /// Days a version carrying an install hook must have been published before ANY
    /// approval can admit it. `0` disables the floor.
    ///
    /// Every other automatic gate is a default an operator may overrule after review.
    /// This one is not: the allow gate runs above the age gate, so without a floor,
    /// surviving one review turns a version published minutes ago into immediate
    /// execution. An approval made inside the window is still recorded — it simply takes
    /// effect when the window clears.
    pub install_script_quarantine_days: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN,
            upstream: DEFAULT_UPSTREAM.to_owned(),
            min_age_days: DEFAULT_MIN_AGE_DAYS,
            bypass_scopes: Vec::new(),
            packument_ttl_secs: DEFAULT_PACKUMENT_TTL_SECS,
            audit_retention_days: DEFAULT_AUDIT_RETENTION_DAYS,
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            state_path: PathBuf::from(DEFAULT_STATE_PATH),
            socket_path: PathBuf::from(DEFAULT_SOCKET_PATH),
            allow_publish_passthrough: DEFAULT_ALLOW_PUBLISH_PASSTHROUGH,
            allow_dist_tag_downgrade: DEFAULT_ALLOW_DIST_TAG_DOWNGRADE,
            install_script_quarantine_days: DEFAULT_INSTALL_SCRIPT_QUARANTINE_DAYS,
        }
    }
}

impl Config {
    /// Load the config.
    ///
    /// * `Some(path)` — that file MUST exist and parse; a missing file is an error, because
    ///   the operator explicitly asked for it.
    /// * `None` — read [`DEFAULT_CONFIG_PATH`] if it exists, otherwise return the defaults.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        match path {
            Some(path) => Self::load_file(path),
            None => {
                let default = Path::new(DEFAULT_CONFIG_PATH);
                if default.is_file() {
                    Self::load_file(default)
                } else {
                    Ok(Self::default())
                }
            }
        }
    }

    /// Read and parse a specific config file. A missing file is an error.
    pub fn load_file(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Parse config text. Absent keys take their default; an **unknown** key is an error.
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// The subset of the config the policy engine consumes.
    pub fn policy(&self) -> PolicyConfig {
        PolicyConfig {
            min_age_days: self.min_age_days,
            bypass_scopes: self.bypass_scopes.clone(),
            allow_dist_tag_downgrade: self.allow_dist_tag_downgrade,
            install_script_quarantine_days: self.install_script_quarantine_days,
        }
    }

    /// Upstream base URL without a trailing slash, so request paths can be appended directly.
    pub fn upstream_base(&self) -> &str {
        self.upstream.trim_end_matches('/')
    }

    /// Open the state database at [`Config::state_path`], creating it and its directory on
    /// first run and applying the schema.
    ///
    /// Only `npmfilter serve` calls this. Nothing else in this binary opens the database.
    pub fn open_store(&self) -> Result<Store, StoreError> {
        Store::open(&self.state_path)
    }

    /// The control socket path as a `&Path`.
    pub fn socket(&self) -> &Path {
        &self.socket_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "npmfilter-config-{}-{tag}.toml",
            std::process::id()
        ))
    }

    #[test]
    fn defaults_match_design() {
        let config = Config::default();
        assert_eq!(config.listen.to_string(), "127.0.0.1:4874");
        assert_eq!(config.upstream, "https://registry.npmjs.org");
        assert_eq!(config.min_age_days, 30);
        assert!(config.bypass_scopes.is_empty());
        assert_eq!(config.packument_ttl_secs, 60);
        assert_eq!(config.log_level, "info");
        assert_eq!(
            config.state_path,
            PathBuf::from("/var/lib/npmfilter/rules.db")
        );
    }

    #[test]
    fn state_path_is_overridable() {
        let parsed =
            Config::parse("state_path = \"/srv/npmfilter/state.db\"\n").expect("state_path parses");
        assert_eq!(parsed.state_path, PathBuf::from("/srv/npmfilter/state.db"));
        assert_eq!(
            Config::default().state_path,
            PathBuf::from(crate::store::DEFAULT_STATE_PATH)
        );
    }

    #[test]
    fn empty_config_text_yields_defaults() {
        let parsed = Config::parse("").expect("empty config parses");
        assert_eq!(parsed, Config::default());
    }

    #[test]
    fn partial_config_overrides_only_named_fields() {
        let parsed = Config::parse(
            r#"
            min_age_days = 7
            bypass_scopes = ["@olamedia", "internal"]
            "#,
        )
        .expect("partial config parses");
        assert_eq!(parsed.min_age_days, 7);
        assert_eq!(parsed.bypass_scopes, vec!["@olamedia", "internal"]);
        assert_eq!(parsed.listen, Config::default().listen);
        assert_eq!(parsed.packument_ttl_secs, 60);
    }

    #[test]
    fn full_config_round_trips() {
        let parsed = Config::parse(
            r#"
            listen = "0.0.0.0:8901"
            upstream = "https://registry.example.test/"
            min_age_days = 45
            bypass_scopes = ["@olamedia"]
            packument_ttl_secs = 15
            log_level = "npmfilter=debug"
            "#,
        )
        .expect("full config parses");
        assert_eq!(parsed.listen.to_string(), "0.0.0.0:8901");
        assert_eq!(parsed.upstream_base(), "https://registry.example.test");
        assert_eq!(parsed.min_age_days, 45);
        assert_eq!(parsed.packument_ttl_secs, 15);
        assert_eq!(parsed.log_level, "npmfilter=debug");
        assert_eq!(parsed.policy().min_age_days, 45);
        assert_eq!(parsed.policy().bypass_scopes, vec!["@olamedia".to_owned()]);
    }

    #[test]
    fn an_unknown_key_fails_the_load_loudly() {
        // A typo'd key that silently did nothing would leave the operator believing in a
        // policy the daemon is not enforcing.
        let error = Config::parse("what_is_this = 1\nmin_age_days = 3\n")
            .expect_err("an unknown key must fail the load");
        assert!(error.to_string().contains("what_is_this"), "{error}");
    }

    #[test]
    fn a_typo_in_a_real_key_fails_the_load() {
        for text in [
            "bypass_scope = [\"@olamedia\"]\n",
            "min_age_day = 7\n",
            "allow_publish_passthru = true\n",
        ] {
            assert!(
                Config::parse(text).is_err(),
                "a near-miss key must not be silently ignored: {text:?}"
            );
        }
    }

    #[test]
    fn an_unknown_key_in_a_file_is_a_parse_error() {
        let path = temp_path("unknown-key");
        fs::write(&path, "min_age_days = 3\nbypass_scope = []\n").expect("write fixture");
        let err = Config::load(Some(&path)).expect_err("unknown keys must fail");
        assert!(matches!(err, ConfigError::Parse { .. }), "got {err:?}");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn the_socket_path_and_publish_passthrough_have_secure_defaults() {
        let config = Config::default();
        assert_eq!(
            config.socket_path,
            PathBuf::from("/run/npmfilter/npmfilter.sock")
        );
        assert!(
            !config.allow_publish_passthrough,
            "mutating methods are refused unless the operator opts in"
        );
        let parsed =
            Config::parse("socket_path = \"/tmp/x.sock\"\nallow_publish_passthrough = true\n")
                .expect("both keys parse");
        assert_eq!(parsed.socket_path, PathBuf::from("/tmp/x.sock"));
        assert!(parsed.allow_publish_passthrough);
    }

    #[test]
    fn broken_toml_is_a_parse_error() {
        let path = temp_path("broken");
        fs::write(&path, "min_age_days = \"thirty\"\n").expect("write fixture");
        let err = Config::load(Some(&path)).expect_err("bad value must fail");
        assert!(matches!(err, ConfigError::Parse { .. }), "got {err:?}");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn explicit_missing_path_is_an_error() {
        let path = temp_path("absent");
        let _ = fs::remove_file(&path);
        let err = Config::load(Some(&path)).expect_err("explicit path must exist");
        assert!(matches!(err, ConfigError::Read { .. }), "got {err:?}");
    }

    #[test]
    fn explicit_path_is_loaded() {
        let path = temp_path("ok");
        fs::write(&path, "min_age_days = 90\n").expect("write fixture");
        let loaded = Config::load(Some(&path)).expect("config loads");
        assert_eq!(loaded.min_age_days, 90);
        assert_eq!(loaded.upstream, DEFAULT_UPSTREAM);
        let _ = fs::remove_file(&path);
    }
}
