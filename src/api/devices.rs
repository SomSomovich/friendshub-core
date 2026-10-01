use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::{bearer, id_from};
use crate::error::Result;
use crate::runtime::ActorState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceItem {
    pub id: String,
    pub device_number: i64,
    pub name: String,
    pub registration_id: i64,
    pub identity_key_pub: String,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
}

pub async fn list(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let rows: Vec<DeviceItem> = state.http.get("/api/v1/devices", Some(&token)).await?;
    Ok(serde_json::to_vec(&rows)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterDeviceRequest {
    pub name: String,
    pub registration_id: i64,
    pub identity_key_pub: String,
}

pub async fn register(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: RegisterDeviceRequest = serde_json::from_slice(&payload)?;
    let item: DeviceItem = state.http.post("/api/v1/devices", &req, Some(&token)).await?;
    Ok(serde_json::to_vec(&item)?)
}

pub async fn revoke(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/devices/{id}");
    let _: serde_json::Value = state.http.delete(&path, Some(&token)).await?;
    Ok(br#"{"revoked":true}"#.to_vec())
}
