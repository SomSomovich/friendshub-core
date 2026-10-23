use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::{bearer, id_from, str_field};
use crate::error::{Error, Result};
use crate::runtime::ActorState;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub title: String,
    #[serde(default)]
    pub member_ids: Vec<String>,
    #[serde(default)]
    pub is_public: bool,
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_seconds: Option<i64>,
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
    let resp: GroupResponse = state
        .http
        .post("/api/v1/groups", &req, Some(&token))
        .await?;
    Ok(serde_json::to_vec(&resp)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberItem {
    pub account_id: String,
    pub role: String,
    pub permissions: i64,
    pub muted_until: Option<i64>,
    pub moderator_muted_until: Option<i64>,
    pub joined_at: i64,
    pub group_tag: Option<String>,
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
    let _: serde_json::Value = state
        .http
        .post(&path, &serde_json::json!({}), Some(&token))
        .await?;
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
    let handle = validate_group_handle(str_field(&v, "handle")?)?;
    let path = format!("/api/v1/groups/by-handle/{handle}");
    let resp: HandleToGroupResponse = state.http.get(&path, Some(&token)).await?;
    Ok(serde_json::to_vec(&resp)?)
}

/// Validates a regular group handle before it is inserted into a URL path.
/// Reserved-name and existence checks remain server-owned.
fn validate_group_handle(handle: String) -> Result<String> {
    let mut chars = handle.chars();
    let valid_first = chars.next().is_some_and(|ch| ch.is_ascii_alphabetic());
    let valid_rest = chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
    let length = handle.chars().count();
    if !(5..=32).contains(&length) || !valid_first || !valid_rest {
        return Err(Error::InvalidPayload(
            "handle must be 5-32 characters, start with a letter, and contain only ASCII letters, digits, or underscores".into(),
        ));
    }
    Ok(handle)
}

#[allow(dead_code)]
fn _unused(_: MemberItem, _: GroupResponse, _: PublicGroupItem) {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn create_request_preserves_optional_expiration() {
        let with_expiration: CreateGroupRequest = serde_json::from_value(json!({
            "title": "temporary",
            "member_ids": [],
            "is_public": false,
            "description": null,
            "expires_in_seconds": 3600
        }))
        .unwrap();
        assert_eq!(with_expiration.expires_in_seconds, Some(3600));
        assert_eq!(
            serde_json::to_value(with_expiration).unwrap()["expires_in_seconds"],
            3600
        );

        let without_expiration: CreateGroupRequest = serde_json::from_value(json!({
            "title": "ordinary",
            "member_ids": [],
            "is_public": false,
            "description": null
        }))
        .unwrap();
        assert_eq!(without_expiration.expires_in_seconds, None);
        assert!(
            serde_json::to_value(without_expiration)
                .unwrap()
                .get("expires_in_seconds")
                .is_none()
        );
    }

    #[test]
    fn member_response_preserves_all_web_fields() {
        let item: MemberItem = serde_json::from_value(json!({
            "account_id": "11111111-1111-4111-8111-111111111111",
            "role": "member",
            "permissions": 0,
            "muted_until": null,
            "moderator_muted_until": 123,
            "joined_at": 456,
            "group_tag": "helper"
        }))
        .unwrap();
        assert_eq!(item.moderator_muted_until, Some(123));
        assert_eq!(item.group_tag.as_deref(), Some("helper"));
        assert_eq!(
            serde_json::to_value(item).unwrap(),
            json!({
                "account_id": "11111111-1111-4111-8111-111111111111",
                "role": "member",
                "permissions": 0,
                "muted_until": null,
                "moderator_muted_until": 123,
                "joined_at": 456,
                "group_tag": "helper"
            })
        );
    }

    #[test]
    fn group_handle_validation_matches_web_route_shape() {
        assert_eq!(
            validate_group_handle("Group_42".into()).unwrap(),
            "Group_42"
        );
        for invalid in [
            "abcd",
            "4group",
            "bad-handle",
            "bad/handle",
            "group?x=1",
            &"a".repeat(33),
        ] {
            assert!(
                validate_group_handle(invalid.into()).is_err(),
                "accepted {invalid:?}"
            );
        }
    }
}
