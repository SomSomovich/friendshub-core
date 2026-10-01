use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::{bearer, id_from, str_field};
use crate::error::Result;
use crate::runtime::ActorState;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateChannelRequest {
    pub title: String,
    pub description: Option<String>,
    #[serde(default)]
    pub is_public: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelResponse {
    pub conversation_id: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub owner_account_id: String,
    pub linked_group_conversation_id: Option<String>,
    pub is_public: bool,
    pub created_at: i64,
}

pub async fn create(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: CreateChannelRequest = serde_json::from_slice(&payload)?;
    let resp: ChannelResponse = state.http.post("/api/v1/channels", &req, Some(&token)).await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMemberItem {
    pub actor_type: String,
    pub actor_id: String,
    pub role: String,
    pub joined_at: i64,
}

pub async fn list_members(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/channels/{id}/members");
    let rows: Vec<ChannelMemberItem> = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&rows)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetRoleRequest {
    pub actor_type: String,
    pub actor_id: String,
    pub role: String,
}

pub async fn set_role(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = str_field(&v, "conversation_id")?;
    let req: SetRoleRequest = serde_json::from_value(v)?;
    let path = format!("/api/v1/channels/{id}/members/role");
    let _: serde_json::Value = state.http.post(&path, &req, Some(&token)).await?;
    Ok(br#"{"updated":true}"#.to_vec())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveMemberParams {
    pub actor_type: String,
    pub actor_id: String,
}

pub async fn remove_member(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = str_field(&v, "conversation_id")?;
    let req: RemoveMemberParams = serde_json::from_value(v)?;
    let path = format!("/api/v1/channels/{id}/members/remove");
    let _: serde_json::Value = state.http.post(&path, &req, Some(&token)).await?;
    Ok(br#"{"removed":true}"#.to_vec())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetLinkedGroupRequest {
    pub linked_group_conversation_id: Option<String>,
}

pub async fn set_linked_group(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = str_field(&v, "conversation_id")?;
    let req: SetLinkedGroupRequest = serde_json::from_value(v)?;
    let path = format!("/api/v1/channels/{id}/linked-group");
    let _: serde_json::Value = state.http.post(&path, &req, Some(&token)).await?;
    Ok(br#"{"updated":true}"#.to_vec())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetPublicRequest {
    pub is_public: bool,
}

pub async fn set_public(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = str_field(&v, "conversation_id")?;
    let req: SetPublicRequest = serde_json::from_value(v)?;
    let path = format!("/api/v1/channels/{id}/public");
    let _: serde_json::Value = state.http.post(&path, &req, Some(&token)).await?;
    Ok(br#"{"updated":true}"#.to_vec())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetUserProfileRequest {
    pub handle: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfileResponse {
    pub handle: String,
    pub handle_normalized: String,
}

pub async fn set_user_profile(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = str_field(&v, "conversation_id")?;
    let req: SetUserProfileRequest = serde_json::from_value(v)?;
    let path = format!("/api/v1/channels/{id}/profile");
    let resp: UserProfileResponse = state.http.post(&path, &req, Some(&token)).await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddBotRequest {
    pub bot_id: String,
}

pub async fn add_bot(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = str_field(&v, "conversation_id")?;
    let req: AddBotRequest = serde_json::from_value(v)?;
    let path = format!("/api/v1/channels/{id}/bots");
    let _: serde_json::Value = state.http.post(&path, &req, Some(&token)).await?;
    Ok(br#"{"added":true}"#.to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishCheckResponse {
    pub can_publish: bool,
}

pub async fn can_publish(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/channels/{id}/can-publish");
    let resp: PublishCheckResponse = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&resp)?)
}

pub async fn subscribe(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/channels/{id}/subscribe");
    let _: serde_json::Value = state.http.post(&path, &serde_json::json!({}), Some(&token)).await?;
    Ok(br#"{"subscribed":true}"#.to_vec())
}

pub async fn unsubscribe(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/channels/{id}/subscribe");
    let _: serde_json::Value = state.http.delete(&path, Some(&token)).await?;
    Ok(br#"{"unsubscribed":true}"#.to_vec())
}

#[allow(dead_code)]
fn _unused(_: ChannelResponse, _: ChannelMemberItem, _: PublishCheckResponse, _: SetRoleRequest) {}
