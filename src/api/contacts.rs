use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::{bearer, id_from, str_field};
use crate::error::Result;
use crate::runtime::ActorState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactItem {
    pub target_account_id: String,
    pub local_username: String,
    pub user_id: i64,
    pub fh_number: String,
    pub username: String,
    pub avatar_url: Option<String>,
}

pub async fn list(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let rows: Vec<ContactItem> = state.http.get("/api/v1/contacts", Some(&token)).await?;
    Ok(serde_json::to_vec(&rows)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddRequest {
    pub target_fh_number: String,
    pub local_username: String,
}

pub async fn add(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: AddRequest = serde_json::from_slice(&payload)?;
    let item: ContactItem = state.http.post("/api/v1/contacts", &req, Some(&token)).await?;
    Ok(serde_json::to_vec(&item)?)
}

pub async fn remove(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/contacts/{id}");
    let _: serde_json::Value = state.http.delete(&path, Some(&token)).await?;
    Ok(br#"{"removed":true}"#.to_vec())
}

pub async fn block(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/blocks/{id}");
    let _: serde_json::Value = state.http.post(&path, &serde_json::json!({}), Some(&token)).await?;
    Ok(br#"{"blocked":true}"#.to_vec())
}

pub async fn unblock(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/blocks/{id}");
    let _: serde_json::Value = state.http.delete(&path, Some(&token)).await?;
    Ok(br#"{"unblocked":true}"#.to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedItem {
    pub account_id: String,
    pub fh_number: String,
    pub username: String,
    pub avatar_url: Option<String>,
    pub blocked_at: i64,
}

pub async fn list_blocked(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let rows: Vec<BlockedItem> = state.http.get("/api/v1/blocks", Some(&token)).await?;
    Ok(serde_json::to_vec(&rows)?)
}

#[allow(dead_code)]
fn _unused(_: AddRequest, _: BlockedItem, _: ContactItem, _: fn(&serde_json::Value, &str) -> Result<String>) {
    let _ = str_field;
}
