use std::path::PathBuf;

use serde::Deserialize;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub db_path: PathBuf,

    /// Explicit API URL. Optional when discovery is enabled; used as the
    /// last-resort fallback if discovery has no answer.
    #[serde(default)]
    pub api_base: String,

    /// Explicit websocket URL. Same rules as `api_base`.
    #[serde(default)]
    pub ws_url: String,

    #[serde(default)]
    pub discovery: DiscoveryConfig,

    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// "text" (default) or "json". Unknown values fall back to "text".
    #[serde(default = "default_log_format")]
    pub log_format: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryConfig {
    /// When false, `api_base` and `ws_url` are used directly.
    #[serde(default = "default_discovery_enabled")]
    pub enabled: bool,

    /// Location of the JSON file describing the current backend.
    #[serde(default = "default_discovery_url")]
    pub url: String,

    /// How long a fetched file is considered fresh, in seconds.
    #[serde(default = "default_discovery_ttl")]
    pub ttl_seconds: u64,

    /// Network timeout for the discovery fetch, in seconds.
    #[serde(default = "default_discovery_timeout")]
    pub timeout_seconds: u64,

    /// Where to cache the fetched file. Defaults to a sibling of the database.
    #[serde(default)]
    pub cache_path: Option<PathBuf>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: default_discovery_enabled(),
            url: default_discovery_url(),
            ttl_seconds: default_discovery_ttl(),
            timeout_seconds: default_discovery_timeout(),
            cache_path: None,
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

fn default_discovery_enabled() -> bool {
    true
}

fn default_discovery_url() -> String {
    "https://raw.githubusercontent.com/SomSomovich/friendshub-core/master/discovery.json".to_string()
}

fn default_discovery_ttl() -> u64 {
    3600
}

fn default_discovery_timeout() -> u64 {
    5
}

impl Config {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let cfg: Config = serde_json::from_slice(bytes)
            .map_err(|e| Error::Config(e.to_string()))?;

        if cfg.db_path.as_os_str().is_empty() {
            return Err(Error::Config("db_path is empty".into()));
        }

        if !cfg.discovery.enabled && (cfg.api_base.is_empty() || cfg.ws_url.is_empty()) {
            return Err(Error::Config(
                "discovery disabled but api_base and ws_url are not both set".into(),
            ));
        }

        Ok(cfg)
    }
}
