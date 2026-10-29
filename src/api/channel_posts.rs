use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::form_urlencoded;
use uuid::Uuid;

use crate::api::common::{bearer, id_from, str_field};
use crate::error::{Error, Result};
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

/// Creates a new key for one channel-post publication intent. Callers should
/// retain it while retrying that same publication after an uncertain result.
pub fn new_idempotency_key() -> String {
    Uuid::new_v4().to_string()
}

pub async fn publish(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let mut v: serde_json::Value = serde_json::from_slice(&payload)?;
    let idempotency_key = match v
        .as_object_mut()
        .and_then(|object| object.remove("__core_idempotency_key"))
    {
        Some(Value::String(key)) => key,
        Some(_) => {
            return Err(Error::InvalidPayload(
                "channel post idempotency key must be a string".into(),
            ));
        }
        None => new_idempotency_key(),
    };
    let channel_id = str_field(&v, "channel_id")?;
    let req: PublishRequest = serde_json::from_value(v)?;
    let path = format!("/api/v1/channels/{channel_id}/posts");
    let post: PostItem = state
        .http
        .post_with_idempotency_key(&path, &req, Some(&token), &idempotency_key)
        .await?;
    Ok(serde_json::to_vec(&post)?)
}

pub async fn list(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: Value = serde_json::from_slice(&payload)?;
    let channel_id = str_field(&v, "channel_id")?;
    let before = optional_uuid(&v, "before")?;
    let limit = optional_i64(&v, "limit")?;
    let path = query_path(
        &format!("/api/v1/channels/{channel_id}/posts"),
        &[
            ("before", before),
            ("limit", limit.map(|value| value.to_string())),
        ],
    );
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
    let v: Value = serde_json::from_slice(&payload)?;
    let post_id = id_from(&v)?;
    let before_created_at = optional_i64(&v, "before_created_at")?;
    let before_actor_id = optional_string(&v, "before_actor_id")?;
    // WEB's listPostReactions default is REACTIONS_PAGE_SIZE (200); the
    // backend's lower fallback of 50 applies only to callers that omit limit.
    let limit = optional_i64(&v, "limit")?.unwrap_or(200);
    let path = query_path(
        &format!("/api/v1/channel-posts/{post_id}/reactions"),
        &[
            (
                "before_created_at",
                before_created_at.map(|value| value.to_string()),
            ),
            ("before_actor_id", before_actor_id),
            ("limit", Some(limit.to_string())),
        ],
    );
    let rows: Vec<ReactionItem> = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&rows)?)
}

pub async fn pin(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let post_id = id_from(&v)?;
    let path = format!("/api/v1/channel-posts/{post_id}/pin");
    let _: serde_json::Value = state
        .http
        .post(&path, &serde_json::json!({}), Some(&token))
        .await?;
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

/// Loads one channel post. The server also records a unique analytics view
/// as part of this read, matching the WEB `getChannelPost` wrapper.
pub async fn get_one(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: Value = serde_json::from_slice(&payload)?;
    let post_id = required_uuid(&id_from(&v)?, "id")?;
    let path = format!("/api/v1/channel-posts/{post_id}");
    let post: PostItem = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&post)?)
}

fn required_uuid(value: &str, field: &str) -> Result<String> {
    Uuid::parse_str(value)
        .map(|id| id.hyphenated().to_string())
        .map_err(|_| Error::InvalidPayload(format!("{field} must be a UUID")))
}

fn optional_uuid(value: &Value, field: &str) -> Result<Option<String>> {
    optional_string(value, field)?
        .map(|value| required_uuid(&value, field))
        .transpose()
}

fn optional_string(value: &Value, field: &str) -> Result<Option<String>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(Error::InvalidPayload(format!("{field} must be a string"))),
    }
}

fn optional_i64(value: &Value, field: &str) -> Result<Option<i64>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number
            .as_i64()
            .map(Some)
            .ok_or_else(|| Error::InvalidPayload(format!("{field} must be an integer"))),
        Some(_) => Err(Error::InvalidPayload(format!("{field} must be an integer"))),
    }
}

fn query_path(path: &str, pairs: &[(&str, Option<String>)]) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        if let Some(value) = value {
            query.append_pair(key, value);
        }
    }
    let query = query.finish();
    if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    }
}

#[allow(dead_code)]
fn _unused(_: PostItem, _: ReactionItem, _: DiscussionInfo) {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const POST_ID: &str = "2f1acb9e-51c7-4d21-9c29-69fc7e9e8b5d";
    const ACTOR_ID: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn post_cursor_is_a_validated_uuid_string_and_limit_is_optional() {
        let request = json!({"before": POST_ID, "limit": 20});
        let before = optional_uuid(&request, "before").unwrap();
        let limit = optional_i64(&request, "limit").unwrap();
        assert_eq!(
            query_path(
                "/api/v1/channels/channel-id/posts",
                &[("before", before), ("limit", limit.map(|x| x.to_string()))]
            ),
            format!("/api/v1/channels/channel-id/posts?before={POST_ID}&limit=20")
        );

        assert_eq!(optional_uuid(&json!({}), "before").unwrap(), None);
        assert_eq!(optional_i64(&json!({}), "limit").unwrap(), None);
        assert!(optional_uuid(&json!({"before": 123}), "before").is_err());
        assert!(optional_uuid(&json!({"before": "not-a-uuid"}), "before").is_err());
        assert!(optional_i64(&json!({"limit": 1.5}), "limit").is_err());
        assert!(optional_i64(&json!({"limit": "20"}), "limit").is_err());
    }

    #[test]
    fn reaction_query_matches_web_cursor_and_default_page_size() {
        let request = json!({
            "before_created_at": 123456,
            "before_actor_id": ACTOR_ID
        });
        let before_created_at = optional_i64(&request, "before_created_at").unwrap();
        let before_actor_id = optional_string(&request, "before_actor_id").unwrap();
        let limit = optional_i64(&request, "limit").unwrap().unwrap_or(200);
        assert_eq!(limit, 200);
        assert_eq!(
            query_path(
                "/api/v1/channel-posts/post-id/reactions",
                &[
                    (
                        "before_created_at",
                        before_created_at.map(|value| value.to_string()),
                    ),
                    ("before_actor_id", before_actor_id),
                    ("limit", Some(limit.to_string())),
                ]
            ),
            format!(
                "/api/v1/channel-posts/post-id/reactions?before_created_at=123456&before_actor_id={ACTOR_ID}&limit=200"
            )
        );

        let encoded = query_path(
            "/api/v1/channel-posts/post-id/reactions",
            &[("before_actor_id", Some("actor+with&reserved".into()))],
        );
        assert_eq!(
            encoded,
            "/api/v1/channel-posts/post-id/reactions?before_actor_id=actor%2Bwith%26reserved"
        );
    }

    #[test]
    fn get_one_requires_uuid_id_and_builds_registered_route() {
        assert_eq!(required_uuid(POST_ID, "id").unwrap(), POST_ID);
        assert!(required_uuid("../other", "id").is_err());
        assert_eq!(
            format!(
                "/api/v1/channel-posts/{}",
                required_uuid(POST_ID, "id").unwrap()
            ),
            format!("/api/v1/channel-posts/{POST_ID}")
        );
        let item: PostItem = serde_json::from_value(json!({
            "id": POST_ID,
            "channel_id": "22222222-2222-4222-8222-222222222222",
            "author_type": "account",
            "author_id": ACTOR_ID,
            "text": "hello",
            "attachment_ids": [],
            "forward_from": null,
            "reply_to_post_id": null,
            "created_at": 123,
            "edited_at": null,
            "pinned_at": null,
            "discussion_comment_count": 0
        }))
        .unwrap();
        assert_eq!(item.id, POST_ID);
    }
}
