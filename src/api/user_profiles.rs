use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::{bearer, str_field};
use crate::error::Result;
use crate::runtime::ActorState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleLookupResponse {
    pub entity_type: String,
    pub entity_id: String,
    pub handle_display: String,
    pub handle_normalized: String,
}

pub async fn lookup(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let handle = str_field(&v, "handle")?;
    let path = format!("/api/v1/handles/{handle}");
    let resp: HandleLookupResponse = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleAvailabilityResponse {
    pub handle: String,
    pub normalized: String,
    pub available: bool,
    pub handle_kind: String,
}

pub async fn check_available(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let handle = str_field(&v, "handle")?;
    let path = format!("/api/v1/handles/{handle}/available");
    let resp: HandleAvailabilityResponse = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchLookupRequest {
    pub handles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchLookupItem {
    pub handle_input: String,
    pub normalized: String,
    pub found: bool,
    pub entity_type: Option<String>,
    pub entity_id: Option<String>,
    pub handle_display: Option<String>,
    pub handle_normalized: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchLookupResponse {
    pub items: Vec<BatchLookupItem>,
}

pub async fn batch_lookup(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: BatchLookupRequest = serde_json::from_slice(&payload)?;
    let resp: BatchLookupResponse = state
        .http
        .post("/api/v1/handles/batch", &req, Some(&token))
        .await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[allow(dead_code)]
fn _unused(_: HandleAvailabilityResponse, _: BatchLookupItem) {}
