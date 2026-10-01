use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::{bearer, id_from, str_field};
use crate::error::Result;
use crate::runtime::ActorState;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub title: String,
    #[serde(default)]
    pub member_ids: Vec<String>,
    #[serde(default)]
    pub is_public: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupResponse {
    pub conversation_id: String,
    pub title: Option<String>,
    pub is_public: bool,
    pub description: Option<String>,
    pub owner_account_id: String,
    pub created_at: i64,
}

pub async fn create(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let req: CreateGroupRequest = serde_json::from_slice(&payload)?;
    let resp: GroupResponse = state.http.post("/api/v1/groups", &req, Some(&token)).await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberItem {
    pub account_id: String,
    pub role: String,
    pub permissions: i64,
    pub muted_until: Option<i64>,
    pub joined_at: i64,
}

pub async fn list_members(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/groups/{id}/members");
    let rows: Vec<MemberItem> = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&rows)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetRoleRequest {
    pub target_account_id: String,
    pub role: String,
    #[serde(default)]
    pub permissions: i64,
}

pub async fn set_role(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = str_field(&v, "conversation_id")?;
    let req: SetRoleRequest = serde_json::from_value(v)?;
    let path = format!("/api/v1/groups/{id}/members/role");
    let _: serde_json::Value = state.http.post(&path, &req, Some(&token)).await?;
    Ok(br#"{"updated":true}"#.to_vec())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MuteRequest {
    pub target_account_id: String,
    pub muted_until: Option<i64>,
}

pub async fn mute_member(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = str_field(&v, "conversation_id")?;
    let req: MuteRequest = serde_json::from_value(v)?;
    let path = format!("/api/v1/groups/{id}/members/mute");
    let _: serde_json::Value = state.http.post(&path, &req, Some(&token)).await?;
    Ok(br#"{"muted":true}"#.to_vec())
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
    let path = format!("/api/v1/groups/{id}/profile");
    let resp: UserProfileResponse = state.http.post(&path, &req, Some(&token)).await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicGroupItem {
    pub conversation_id: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub owner_account_id: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub member_count: i64,
    pub handle: Option<String>,
    pub handle_normalized: Option<String>,
}

pub async fn list_public(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload).unwrap_or(serde_json::json!({}));
    let limit = v.get("limit").and_then(|x| x.as_i64()).unwrap_or(50);
    let path = format!("/api/v1/groups/public?limit={limit}");
    let rows: Vec<PublicGroupItem> = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&rows)?)
}

pub async fn join_public(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let id = id_from(&v)?;
    let path = format!("/api/v1/groups/{id}/join");
    let _: serde_json::Value = state.http.post(&path, &serde_json::json!({}), Some(&token)).await?;
    Ok(br#"{"joined":true}"#.to_vec())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleToGroupResponse {
    pub conversation_id: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub member_count: i64,
    pub already_member: bool,
}

pub async fn lookup_by_handle(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let handle = str_field(&v, "handle")?;
    let path = format!("/api/v1/groups/by-handle/{handle}");
    let resp: HandleToGroupResponse = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[allow(dead_code)]
fn _unused(_: MemberItem, _: GroupResponse, _: PublicGroupItem) {}
