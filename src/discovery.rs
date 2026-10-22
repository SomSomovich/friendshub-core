//! Runtime discovery of the backend URL.
//!
//! The API and websocket URLs are not compiled into the binary. At `fh_init`
//! the library fetches a small JSON file from a well-known location and uses
//! the URLs it contains. That file is the single source of truth: an operator
//! can move the backend without shipping a new client build.
//!
//! Resolution order, best source first:
//!
//! 1. Cache on disk, if younger than the configured TTL.
//! 2. Fetch from the discovery URL. On success, refresh the cache.
//! 3. Cache on disk, even if stale.
//! 4. `api_base` / `ws_url` from the config, if both are set.
//! 5. Fail: init cannot proceed without a URL.
//!
//! No signature is verified at this time. The threat that a signature would
//! address is a compromise of the hosting account, but that account is the
//! same one that publishes the source: an attacker who can push a malicious
//! discovery file can already push malicious code. A signature becomes
//! meaningful once binaries are distributed from a key kept offline.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::util::time::now_unix;

/// Shape of the file fetched from the discovery URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Discovery {
    /// Schema version. Currently 1.
    #[serde(default = "default_version")]
    pub version: u32,

    pub api_base: String,
    pub ws_url: String,

    /// Informational: when the operator last changed the file.
    #[serde(default)]
    pub updated_at: Option<i64>,
}

fn default_version() -> u32 { 1 }

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    fetched_at: i64,
    discovery: Discovery,
}

/// Resolves the backend URLs for this handle.
pub async fn resolve(config: &Config) -> Result<Discovery> {
    if !config.discovery.enabled {
        if config.api_base.is_empty() || config.ws_url.is_empty() {
            return Err(Error::Config(
                "discovery disabled but api_base and ws_url are not both set".into(),
            ));
        }
        return Ok(Discovery {
            version: 0,
            api_base: config.api_base.clone(),
            ws_url: config.ws_url.clone(),
            updated_at: None,
        });
    }

    let cache_path = config
        .discovery
        .cache_path
        .clone()
        .unwrap_or_else(|| default_cache_path(&config.db_path));
    let ttl = config.discovery.ttl_seconds as i64;
    let timeout = Duration::from_secs(config.discovery.timeout_seconds);

    // 1. Fresh cache.
    if let Some(entry) = read_cache(&cache_path) {
        let age = now_unix() - entry.fetched_at;
        if (0..ttl).contains(&age) {
            tracing::debug!(age_secs = age, "discovery: using fresh cache");
            return Ok(entry.discovery);
        }
    }

    // 2. Fetch.
    match fetch(&config.discovery.url, timeout).await {
        Ok(d) => {
            if let Err(e) = write_cache(&cache_path, &d) {
                tracing::warn!(error = ?e, "discovery: cache write failed");
            }
            tracing::info!(api_base = %d.api_base, url = %config.discovery.url, "discovery: fetched");
            return Ok(d);
        }
        Err(e) => {
            tracing::warn!(error = %e, url = %config.discovery.url, "discovery: fetch failed");
        }
    }

    // 3. Stale cache.
    if let Some(entry) = read_cache(&cache_path) {
        tracing::warn!("discovery: falling back to stale cache");
        return Ok(entry.discovery);
    }

    // 4. Config URLs.
    if !config.api_base.is_empty() && !config.ws_url.is_empty() {
        tracing::warn!("discovery: falling back to config api_base / ws_url");
        return Ok(Discovery {
            version: 0,
            api_base: config.api_base.clone(),
            ws_url: config.ws_url.clone(),
            updated_at: None,
        });
    }

    Err(Error::Config(
        "discovery failed and no api_base / ws_url fallback in config".into(),
    ))
}

async fn fetch(url: &str, timeout: Duration) -> Result<Discovery> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(concat!("friendshub-core/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| Error::Network(format!("discovery client: {e}")))?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| Error::Network(format!("discovery fetch: {e}")))?;

    if !resp.status().is_success() {
        return Err(Error::Network(format!(
            "discovery fetch: HTTP {}",
            resp.status().as_u16()
        )));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| Error::Network(format!("discovery body: {e}")))?;

    let d: Discovery = serde_json::from_slice(&bytes)
        .map_err(|e| Error::InvalidPayload(format!("discovery json: {e}")))?;

    if d.api_base.is_empty() || d.ws_url.is_empty() {
        return Err(Error::InvalidPayload(
            "discovery file missing api_base or ws_url".into(),
        ));
    }

    Ok(d)
}

/// Blocking file read. Called only during init, before the run loop starts,
/// so there is nothing else waiting on the runtime while this completes.
fn read_cache(path: &Path) -> Option<CacheEntry> {
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Blocking file write. Same reasoning as `read_cache`.
fn write_cache(path: &Path, discovery: &Discovery) -> std::io::Result<()> {
    let entry = CacheEntry {
        fetched_at: now_unix(),
        discovery: discovery.clone(),
    };
    let data = serde_json::to_string_pretty(&entry)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, data)
}

fn default_cache_path(db_path: &Path) -> PathBuf {
    match db_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            parent.join(".friendshub-discovery.json")
        }
        _ => PathBuf::from(".friendshub-discovery.json"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_deserializes() {
        let raw = br#"{"api_base":"https://x","ws_url":"wss://x/ws"}"#;
        let d: Discovery = serde_json::from_slice(raw).unwrap();
        assert_eq!(d.version, 1);
        assert_eq!(d.api_base, "https://x");
    }

    #[test]
    fn cache_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("fh-disc-test-{}.json", std::process::id()));
        let d = Discovery {
            version: 1,
            api_base: "https://a".into(),
            ws_url: "wss://a/ws".into(),
            updated_at: None,
        };
        write_cache(&tmp, &d).unwrap();
        let entry = read_cache(&tmp).unwrap();
        assert_eq!(entry.discovery.api_base, "https://a");
        let _ = std::fs::remove_file(&tmp);
    }
}
