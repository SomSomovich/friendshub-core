use std::sync::Arc;

use serde::Deserialize;

use crate::crypto::device_cache;
use crate::error::Result;
use crate::runtime::ActorState;

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub account_id: String,
}

/// Refetches and stores the device list for one account.
///
/// Useful right after learning that a peer added a device: the sender can
/// call this proactively so the next `send_message` fans out to the new
/// device without waiting for the cache TTL to expire.
pub async fn refresh(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: RefreshRequest = serde_json::from_slice(&payload)?;
    let devices = device_cache::force_refresh(state, &req.account_id)
        .await?;
    Ok(serde_json::to_vec(&serde_json::json!({
        "count": devices.len(),
        "device_numbers": devices.iter().map(|d| d.device_number).collect::<Vec<_>>(),
    }))?)
}

#[derive(Debug, Deserialize)]
pub struct InvalidateRequest {
    pub account_id: String,
}

/// Drops the cached device list without fetching a new one. The next
/// `send_message` will fetch fresh.
pub async fn invalidate(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: InvalidateRequest = serde_json::from_slice(&payload)?;
    device_cache::invalidate(state, &req.account_id)
        .await?;
    Ok(br#"{"invalidated":true}"#.to_vec())
}
