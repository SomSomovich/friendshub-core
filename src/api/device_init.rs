use std::sync::Arc;

use serde::Deserialize;

use crate::crypto::init;
use crate::error::{Error, Result};
use crate::runtime::ActorState;

#[derive(Debug, Deserialize)]
pub struct InitRequest {
    /// Human-readable device label (e.g. "iPhone 15", "Desktop").
    pub name: String,
}

/// Starts or resumes local identity creation, server registration, and initial
/// prekey provisioning. A completed setup cannot be initialized a second time.
pub async fn initialize(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: InitRequest = serde_json::from_slice(&payload)?;
    let result = init::initialize(state, &req.name)
        .await
        .map_err(|e| Error::Internal(format!("device init: {e}")))?;
    Ok(serde_json::to_vec(&result)?)
}

pub async fn status(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let initialized = init::is_initialized(state)
        .await
        .map_err(|e| Error::Internal(format!("device status: {e}")))?;

    let available_otk: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pre_keys")
        .fetch_one(&state.db)
        .await
        .map_err(|e| Error::Database(e.to_string()))?;

    let available_kyber: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kyber_pre_keys
          WHERE key_kind = 'one_time' AND used = 0",
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| Error::Database(e.to_string()))?;

    Ok(serde_json::to_vec(&serde_json::json!({
        "initialized": initialized,
        "one_time_prekeys": available_otk,
        "kyber_one_time_prekeys": available_kyber,
        "min_threshold": init::MIN_OTK_THRESHOLD,
    }))?)
}

/// Generates and uploads more prekeys when the local pool is running low.
/// Safe to call on a schedule.
pub async fn ensure_prekeys(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let generated = init::ensure_prekeys(state)
        .await
        .map_err(|e| Error::Internal(format!("prekey replenish: {e}")))?;
    Ok(serde_json::to_vec(&serde_json::json!({
        "generated": generated,
    }))?)
}
