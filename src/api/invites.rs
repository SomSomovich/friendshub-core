use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::{bearer, id_from, str_field};
use crate::error::Result;
use crate::runtime::ActorState;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateInviteRequest {
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteResponse {
    pub id: String,
    pub token: String,
    pub kind: String,
    pub used_count: i64,
    pub max_uses: Option<i64>,
    pub created_at: i64,
}

pub async fn create(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let conversation_id = str_field(&v, "conversation_id")?;
    let req: CreateInviteRequest = serde_json::from_value(v)?;
    let path = format!("/api/v1/conversations/{conversation_id}/invites");
    let inv: InviteResponse = state.http.post(&path, &req, Some(&token)).await?;
    Ok(serde_json::to_vec(&inv)?)
}

pub async fn list(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let conversation_id = id_from(&v)?;
    let path = format!("/api/v1/conversations/{conversation_id}/invites");
    let rows: Vec<InviteResponse> = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&rows)?)
}

pub async fn revoke(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let invite_id = id_from(&v)?;
    let path = format!("/api/v1/invites/{invite_id}");
    let _: serde_json::Value = state.http.delete(&path, Some(&token)).await?;
    Ok(br#"{"revoked":true}"#.to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinResponse {
    pub conversation_id: String,
}

pub async fn join_by_token(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let invite_token = str_field(&v, "token")?;
    let path = format!("/api/v1/invites/join/{invite_token}");
    let resp: JoinResponse = state
        .http
        .post(&path, &serde_json::json!({}), Some(&token))
        .await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[allow(dead_code)]
fn _unused(_: InviteResponse, _: JoinResponse) {}
