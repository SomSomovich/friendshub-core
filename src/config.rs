use std::path::PathBuf;

use serde::Deserialize;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub api_base: String,
    pub ws_url: String,
    pub db_path: PathBuf,

    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// "text" (default) or "json". Unknown values fall back to "text".
    #[serde(default = "default_log_format")]
    pub log_format: String,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

impl Config {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let cfg: Config = serde_json::from_slice(bytes)
            .map_err(|e| Error::Config(e.to_string()))?;

        if cfg.api_base.is_empty() {
            return Err(Error::Config("api_base is empty".into()));
        }
        if cfg.ws_url.is_empty() {
            return Err(Error::Config("ws_url is empty".into()));
        }
        if cfg.db_path.as_os_str().is_empty() {
            return Err(Error::Config("db_path is empty".into()));
        }

        Ok(cfg)
    }
}
