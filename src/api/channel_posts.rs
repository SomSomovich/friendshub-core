use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::{bearer, id_from, str_field};
use crate::error::Result;
use crate::runtime::ActorState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostItem {
    pub id: String,
    pub channel_id: String,
    pub author_type: String,
    pub author_id: String,
    pub text: String,
    pub attachment_ids: Vec<String>,
    pub forward_from: Option<String>,
    pub reply_to_post_id: Option<String>,
    pub created_at: i64,
    pub edited_at: Option<i64>,
    pub pinned_at: Option<i64>,
    pub discussion_comment_count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublishRequest {
    pub text: String,
    #[serde(default)]
    pub attachment_ids: Vec<String>,
    pub reply_to_post_id: Option<String>,
    pub forward_from: Option<String>,
}

pub async fn publish(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let channel_id = str_field(&v, "channel_id")?;
    let req: PublishRequest = serde_json::from_value(v)?;
    let path = format!("/api/v1/channels/{channel_id}/posts");
    let post: PostItem = state.http.post(&path, &req, Some(&token)).await?;
    Ok(serde_json::to_vec(&post)?)
}

pub async fn list(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let channel_id = str_field(&v, "channel_id")?;
    let before = v.get("before").and_then(|x| x.as_i64());
    let limit = v.get("limit").and_then(|x| x.as_i64()).unwrap_or(50);
    let path = match before {
        Some(b) => format!("/api/v1/channels/{channel_id}/posts?before={b}&limit={limit}"),
        None => format!("/api/v1/channels/{channel_id}/posts?limit={limit}"),
    };
    let rows: Vec<PostItem> = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&rows)?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EditRequest {
    pub text: String,
}

pub async fn edit(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let post_id = str_field(&v, "post_id")?;
    let req: EditRequest = serde_json::from_value(v)?;
    let path = format!("/api/v1/channel-posts/{post_id}");
    let _: serde_json::Value = state.http.patch(&path, &req, Some(&token)).await?;
    Ok(br#"{"edited":true}"#.to_vec())
}

pub async fn delete(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let post_id = id_from(&v)?;
    let path = format!("/api/v1/channel-posts/{post_id}");
    let _: serde_json::Value = state.http.delete(&path, Some(&token)).await?;
    Ok(br#"{"deleted":true}"#.to_vec())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReactionRequest {
    pub emoji: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionItem {
    pub actor_type: String,
    pub actor_id: String,
    pub emoji: String,
    pub created_at: i64,
}

pub async fn set_reaction(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let post_id = str_field(&v, "post_id")?;
    let req: ReactionRequest = serde_json::from_value(v)?;
    let path = format!("/api/v1/channel-posts/{post_id}/reactions");
    let _: serde_json::Value = state.http.post(&path, &req, Some(&token)).await?;
    Ok(br#"{"reacted":true}"#.to_vec())
}

pub async fn remove_reaction(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let post_id = id_from(&v)?;
    let path = format!("/api/v1/channel-posts/{post_id}/reactions");
    let _: serde_json::Value = state.http.delete(&path, Some(&token)).await?;
    Ok(br#"{"removed":true}"#.to_vec())
}

pub async fn list_reactions(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let post_id = id_from(&v)?;
    let path = format!("/api/v1/channel-posts/{post_id}/reactions");
    let rows: Vec<ReactionItem> = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&rows)?)
}

pub async fn pin(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let post_id = id_from(&v)?;
    let path = format!("/api/v1/channel-posts/{post_id}/pin");
    let _: serde_json::Value = state.http.post(&path, &serde_json::json!({}), Some(&token)).await?;
    Ok(br#"{"pinned":true}"#.to_vec())
}

pub async fn unpin(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let post_id = id_from(&v)?;
    let path = format!("/api/v1/channel-posts/{post_id}/pin");
    let _: serde_json::Value = state.http.delete(&path, Some(&token)).await?;
    Ok(br#"{"unpinned":true}"#.to_vec())
}

pub async fn list_pinned(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let channel_id = id_from(&v)?;
    let path = format!("/api/v1/channels/{channel_id}/pinned");
    let rows: Vec<PostItem> = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&rows)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscussionInfo {
    pub channel_id: String,
    pub post_id: String,
    pub linked_group_id: Option<String>,
    pub thread_id: String,
    pub comment_count: i64,
}

pub async fn get_discussion(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let post_id = id_from(&v)?;
    let path = format!("/api/v1/channel-posts/{post_id}/discussion");
    let resp: DiscussionInfo = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[allow(dead_code)]
fn _unused(_: PostItem, _: ReactionItem, _: DiscussionInfo) {}
