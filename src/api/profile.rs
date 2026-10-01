use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::{bearer, id_from, str_field};
use crate::error::Result;
use crate::runtime::ActorState;

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateUsernameRequest {
    pub username: String,
}

pub async fn update_username(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: UpdateUsernameRequest = serde_json::from_slice(&payload)?;
    let _: serde_json::Value = state.http.put("/api/v1/profile/username", &req, Some(&token)).await?;
    Ok(br#"{"updated":true}"#.to_vec())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateStatusRequest {
    pub text: Option<String>,
    pub emoji: Option<String>,
    pub ttl_seconds: Option<i64>,
}

pub async fn update_custom_status(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: UpdateStatusRequest = serde_json::from_slice(&payload)?;
    let _: serde_json::Value = state.http.put("/api/v1/profile/status", &req, Some(&token)).await?;
    Ok(br#"{"updated":true}"#.to_vec())
}

pub async fn clear_custom_status(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let _: serde_json::Value = state.http.delete("/api/v1/profile/status", Some(&token)).await?;
    Ok(br#"{"cleared":true}"#.to_vec())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InvisibleModeRequest {
    pub enabled: bool,
}

pub async fn set_invisible_mode(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: InvisibleModeRequest = serde_json::from_slice(&payload)?;
    let _: serde_json::Value = state.http.put("/api/v1/profile/invisible", &req, Some(&token)).await?;
    Ok(br#"{"updated":true}"#.to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionItem {
    pub target_account_id: String,
    pub kind: String,
    pub created_at: i64,
}

pub async fn list_exceptions(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let rows: Vec<ExceptionItem> = state.http.get("/api/v1/profile/presence-exceptions", Some(&token)).await?;
    Ok(serde_json::to_vec(&rows)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExceptionRequest {
    pub target_account_id: String,
    pub kind: String,
}

pub async fn add_exception(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: ExceptionRequest = serde_json::from_slice(&payload)?;
    let _: serde_json::Value = state.http.post("/api/v1/profile/presence-exceptions", &req, Some(&token)).await?;
    Ok(br#"{"added":true}"#.to_vec())
}

pub async fn remove_exception(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: ExceptionRequest = serde_json::from_slice(&payload)?;
    let _: serde_json::Value = state.http.post("/api/v1/profile/presence-exceptions/remove", &req, Some(&token)).await?;
    Ok(br#"{"removed":true}"#.to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicProfile {
    pub id: String,
    pub user_id: i64,
    pub fh_number: String,
    pub username: String,
    pub avatar_url: Option<String>,
    pub custom_status_text: Option<String>,
    pub custom_status_emoji: Option<String>,
    pub custom_status_expires_at: Option<i64>,
    pub is_blocked_by_me: bool,
    pub is_contact: bool,
}

pub async fn get_public_profile(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/accounts/{id}/profile");
    let profile: PublicProfile = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&profile)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceResponse {
    pub account_id: String,
    pub is_online: bool,
    pub last_seen: Option<i64>,
    pub custom_status_text: Option<String>,
    pub custom_status_emoji: Option<String>,
    pub custom_status_expires_at: Option<i64>,
    pub visible: bool,
}

pub async fn get_presence(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = str_field(&v, "account_id")?;
    let path = format!("/api/v1/accounts/{id}/presence");
    let presence: PresenceResponse = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&presence)?)
}

#[allow(dead_code)]
fn _unused(_: PublicProfile, _: PresenceResponse, _: UpdateStatusRequest, _: InvisibleModeRequest) {}
