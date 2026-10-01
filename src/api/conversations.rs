use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::{bearer, id_from};
use crate::error::Result;
use crate::runtime::ActorState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationItem {
    pub id: String,
    pub kind: String,
    pub title: Option<String>,
    pub member_count: i64,
    pub last_envelope_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
    pub archived_at: Option<i64>,
    pub muted_until: Option<i64>,
}

pub async fn list(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let rows: Vec<ConversationItem> = state.http.get("/api/v1/conversations", Some(&token)).await?;
    Ok(serde_json::to_vec(&rows)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDirectRequest {
    pub peer_fh_number: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateDirectResponse {
    pub id: String,
    pub kind: String,
}

pub async fn create_direct(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: CreateDirectRequest = serde_json::from_slice(&payload)?;
    let resp: CreateDirectResponse = state
        .http
        .post("/api/v1/conversations/direct", &req, Some(&token))
        .await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationDetail {
    pub id: String,
    pub kind: String,
    pub title: Option<String>,
    pub created_by: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub members: Vec<String>,
}

pub async fn get_one(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/conversations/{id}");
    let detail: ConversationDetail = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&detail)?)
}

pub async fn leave(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/conversations/{id}/leave");
    let _: serde_json::Value = state.http.post(&path, &serde_json::json!({}), Some(&token)).await?;
    Ok(br#"{"left":true}"#.to_vec())
}

pub async fn archive(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/conversations/{id}/archive");
    let _: serde_json::Value = state.http.post(&path, &serde_json::json!({}), Some(&token)).await?;
    Ok(br#"{"archived":true}"#.to_vec())
}

pub async fn unarchive(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/conversations/{id}/archive");
    let _: serde_json::Value = state.http.delete(&path, Some(&token)).await?;
    Ok(br#"{"unarchived":true}"#.to_vec())
}

pub async fn mute(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let duration = v.get("duration_seconds").cloned().unwrap_or(serde_json::Value::Null);
    let path = format!("/api/v1/conversations/{id}/mute");
    let body = serde_json::json!({ "duration_seconds": duration });
    let _: serde_json::Value = state.http.post(&path, &body, Some(&token)).await?;
    Ok(br#"{"muted":true}"#.to_vec())
}

pub async fn unmute(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/conversations/{id}/mute");
    let _: serde_json::Value = state.http.delete(&path, Some(&token)).await?;
    Ok(br#"{"unmuted":true}"#.to_vec())
}

#[allow(dead_code)]
fn _unused(_: ConversationDetail, _: CreateDirectResponse) {}
