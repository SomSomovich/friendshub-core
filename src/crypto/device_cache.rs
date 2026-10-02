//! Peer device lists, cached locally.
//!
//! Multi-device fanout needs to know every device of the recipient before
//! encrypting. The server exposes one endpoint per account, and asking it on
//! every send would add a round trip to each message. The list is therefore
//! cached in SQLite with a short TTL.
//!
//! The TTL is a tradeoff. A device that was added seconds ago will not
//! receive a message until the cache expires or the caller forces a refresh.
//! Five minutes keeps that window small without hammering the endpoint.

use serde::{Deserialize, Serialize};

use crate::api::common::bearer;
use crate::error::{Error, Result};
use crate::runtime::ActorState;
use crate::util::time::now_unix;

/// How long a cached device list is considered fresh.
pub const CACHE_TTL_SECS: i64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedDevice {
    pub device_number: i64,
    pub registration_id: i64,
    pub identity_key_pub: String,
}

/// Returns the recipient's device list, from cache when it is fresh.
pub async fn get(state: &ActorState, account_id: &str) -> Result<Vec<CachedDevice>> {
    let row: Option<(String, i64)> = sqlx::query_as(
        "SELECT devices_json, fetched_at FROM device_cache WHERE account_id = ?",
    )
    .bind(account_id)
    .fetch_optional(&state.db)
    .await?;

    if let Some((json, fetched_at)) = row
        && now_unix() - fetched_at < CACHE_TTL_SECS {
            let devices: Vec<CachedDevice> = serde_json::from_str(&json)
                .map_err(|e| Error::InvalidPayload(format!("cached devices: {e}")))?;
            return Ok(devices);
        }

    force_refresh(state, account_id).await
}

/// Fetches the device list regardless of cache state and stores it.
pub async fn force_refresh(
    state: &ActorState,
    account_id: &str,
) -> Result<Vec<CachedDevice>> {
    let devices = fetch_from_server(state, account_id).await?;
    let json = serde_json::to_string(&devices)?;
    let now = now_unix();

    let sql = "INSERT INTO device_cache (account_id, devices_json, fetched_at) VALUES (?, ?, ?) ON CONFLICT(account_id) DO UPDATE SET devices_json = excluded.devices_json, fetched_at = excluded.fetched_at";
    sqlx::query(sql)
        .bind(account_id)
        .bind(&json)
        .bind(now)
        .execute(&state.db)
        .await?;

    Ok(devices)
}

/// Drops the cached entry for one account, so the next `get` fetches again.
pub async fn invalidate(state: &ActorState, account_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM device_cache WHERE account_id = ?")
        .bind(account_id)
        .execute(&state.db)
        .await?;
    Ok(())
}

async fn fetch_from_server(
    state: &ActorState,
    account_id: &str,
) -> Result<Vec<CachedDevice>> {
    let token = bearer(state).await?;
    let path = format!("/api/v1/accounts/{account_id}/devices");
    let devices: Vec<CachedDevice> = state.http.get(&path, Some(&token)).await?;
    Ok(devices)
}
