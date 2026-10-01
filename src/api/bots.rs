use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::{bearer, id_from, str_field};
use crate::error::Result;
use crate::runtime::ActorState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBotResponse {
    pub bot_id: String,
    pub token: String,
    pub token_prefix: String,
}

pub async fn create(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let resp: CreateBotResponse = state
        .http
        .post("/api/v1/bots", &serde_json::json!({}), Some(&token))
        .await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotItem {
    pub id: String,
    pub token_prefix: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub handle: Option<String>,
}

pub async fn list(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let rows: Vec<BotItem> = state.http.get("/api/v1/bots", Some(&token)).await?;
    Ok(serde_json::to_vec(&rows)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetBotProfileRequest {
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotProfileResponse {
    pub handle: String,
    pub handle_normalized: String,
}

pub async fn set_profile(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let bot_id = str_field(&v, "bot_id")?;
    let req: SetBotProfileRequest = serde_json::from_value(v)?;
    let path = format!("/api/v1/bots/{bot_id}/profile");
    let resp: BotProfileResponse = state.http.post(&path, &req, Some(&token)).await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateTokenResponse {
    pub token: String,
}

pub async fn rotate_token(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let bot_id = id_from(&v)?;
    let path = format!("/api/v1/bots/{bot_id}/rotate-token");
    let resp: RotateTokenResponse = state
        .http
        .post(&path, &serde_json::json!({}), Some(&token))
        .await?;
    Ok(serde_json::to_vec(&resp)?)
}

pub async fn delete(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let bot_id = id_from(&v)?;
    let path = format!("/api/v1/bots/{bot_id}");
    let _: serde_json::Value = state.http.delete(&path, Some(&token)).await?;
    Ok(br#"{"deleted":true}"#.to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnedBotItem {
    pub bot_id: String,
    pub handle: Option<String>,
    pub token_prefix: String,
    pub created_at: i64,
    pub has_webhook: bool,
}

pub async fn list_my_bots(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let rows: Vec<OwnedBotItem> = state.http.get("/api/v1/user/bots", Some(&token)).await?;
    Ok(serde_json::to_vec(&rows)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotPublicInfo {
    pub bot_id: String,
    pub owner_account_id: String,
    pub handle: Option<String>,
    pub created_at: i64,
}

pub async fn get_bot_info(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let bot_id = id_from(&v)?;
    let path = format!("/api/v1/bots/{bot_id}/info");
    let info: BotPublicInfo = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&info)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotMessageItem {
    pub id: String,
    pub bot_id: String,
    pub sender_account_id: String,
    pub direction: String,
    pub text: String,
    pub reply_to_id: Option<String>,
    pub created_at: i64,
}

pub async fn get_history(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let bot_id = id_from(&v)?;
    let path = format!("/api/v1/bots/{bot_id}/messages");
    let rows: Vec<BotMessageItem> = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&rows)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendToBotRequest {
    pub text: String,
    pub reply_to_message_id: Option<String>,
}

pub async fn send_to_bot(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let bot_id = str_field(&v, "bot_id")?;
    let req: SendToBotRequest = serde_json::from_value(v)?;
    let path = format!("/api/v1/bots/{bot_id}/messages");
    let msg: BotMessageItem = state.http.post(&path, &req, Some(&token)).await?;
    Ok(serde_json::to_vec(&msg)?)
}

#[allow(dead_code)]
fn _unused(_: BotItem, _: OwnedBotItem, _: BotPublicInfo, _: BotMessageItem) {}
