//! Group and channel REST operations which are not covered by the initial
//! `groups` and `channels` dispatch methods.
//!
//! The public FFI surface remains JSON. `ActorState::http` selects the
//! protobuf REST codecs for each route and converts the response back to JSON.

use std::sync::Arc;

use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::api::common::{bearer, str_field};
use crate::error::{Error, Result};
use crate::runtime::ActorState;

const MAX_PUBLIC_LIST_LIMIT: i64 = 200;

#[derive(Debug, Serialize)]
struct UpdateGroupRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_public: Option<bool>,
}

#[derive(Debug, Serialize)]
struct TransferOwnerRequest {
    new_owner_account_id: String,
}

#[derive(Debug, Serialize)]
struct AddGroupMemberRequest {
    account_id: String,
}

#[derive(Debug, Serialize)]
struct SetGroupTagRequest {
    tag: String,
}

#[derive(Debug, Serialize)]
struct BanGroupMemberRequest {
    account_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

/// Validates a conversation/account identifier and returns its canonical UUID
/// spelling, which is safe to interpolate as one URL path segment.
fn uuid_field(value: &str, field: &str) -> Result<String> {
    Uuid::parse_str(value)
        .map(|id| id.hyphenated().to_string())
        .map_err(|_| Error::InvalidPayload(format!("{field} must be a UUID")))
}

fn group_id(value: &Value) -> Result<String> {
    uuid_field(&str_field(value, "conversation_id")?, "conversation_id")
}

fn channel_id(value: &Value) -> Result<String> {
    uuid_field(&str_field(value, "conversation_id")?, "conversation_id")
}

fn account_id(value: &Value, field: &str) -> Result<String> {
    uuid_field(&str_field(value, field)?, field)
}

/// Group and channel handles use the regular 5–32 character handle alphabet.
/// The server remains responsible for reserved-name and uniqueness checks.
fn validate_handle(handle: String) -> Result<String> {
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

/// Parses a public-list limit and mirrors the API's upper bound. A missing or
/// null value uses the provided frontend default, if any.
fn list_limit(value: &Value, default: Option<i64>) -> Result<Option<i64>> {
    let Some(raw) = value.get("limit") else {
        return Ok(default);
    };
    if raw.is_null() {
        return Ok(default);
    }
    let limit = raw
        .as_i64()
        .ok_or_else(|| Error::InvalidPayload("limit must be a non-negative integer".into()))?;
    if limit < 0 {
        return Err(Error::InvalidPayload(
            "limit must be a non-negative integer".into(),
        ));
    }
    Ok(Some(limit.min(MAX_PUBLIC_LIST_LIMIT)))
}

fn list_path(path: &str, limit: Option<i64>) -> String {
    match limit {
        Some(limit) => format!("{path}?limit={limit}"),
        None => path.to_owned(),
    }
}

fn group_path(id: &str, suffix: &str) -> String {
    if suffix.is_empty() {
        format!("/api/v1/groups/{id}")
    } else {
        format!("/api/v1/groups/{id}/{suffix}")
    }
}

fn channel_path(id: &str, suffix: &str) -> String {
    if suffix.is_empty() {
        format!("/api/v1/channels/{id}")
    } else {
        format!("/api/v1/channels/{id}/{suffix}")
    }
}

fn json_bytes(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(Into::into)
}

fn result_flag(name: &str) -> Vec<u8> {
    // These keys are compile-time literals at all call sites.
    format!("{{\"{name}\":true}}").into_bytes()
}

// --- Groups -----------------------------------------------------------------

pub async fn get_group(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(&payload)?;
    let id = group_id(&value)?;
    let token = bearer(state).await?;
    let response: Value = state.http.get(&group_path(&id, ""), Some(&token)).await?;
    json_bytes(&response)
}

pub async fn update_group(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(&payload)?;
    let id = group_id(&value)?;
    let request = UpdateGroupRequest {
        title: optional_string(&value, "title")?,
        description: optional_string(&value, "description")?,
        is_public: optional_bool(&value, "is_public")?,
    };
    let token = bearer(state).await?;
    let _: Value = state
        .http
        .patch(&group_path(&id, ""), &request, Some(&token))
        .await?;
    Ok(result_flag("updated"))
}

pub async fn delete_group(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(&payload)?;
    let id = group_id(&value)?;
    let token = bearer(state).await?;
    let _: Value = state
        .http
        .delete(&group_path(&id, ""), Some(&token))
        .await?;
    Ok(result_flag("deleted"))
}

pub async fn transfer_group_owner(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(&payload)?;
    let id = group_id(&value)?;
    let request = TransferOwnerRequest {
        new_owner_account_id: account_id(&value, "new_owner_account_id")?,
    };
    let token = bearer(state).await?;
    let _: Value = state
        .http
        .post(&group_path(&id, "owner"), &request, Some(&token))
        .await?;
    Ok(result_flag("transferred"))
}

pub async fn add_group_member(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(&payload)?;
    let id = group_id(&value)?;
    let request = AddGroupMemberRequest {
        account_id: account_id(&value, "account_id")?,
    };
    let token = bearer(state).await?;
    let _: Value = state
        .http
        .post(&group_path(&id, "members"), &request, Some(&token))
        .await?;
    Ok(result_flag("added"))
}

pub async fn remove_group_member(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(&payload)?;
    let id = group_id(&value)?;
    let member_id = account_id(&value, "account_id")?;
    let token = bearer(state).await?;
    let _: Value = state
        .http
        .delete(
            &group_path(&id, &format!("members/{member_id}")),
            Some(&token),
        )
        .await?;
    Ok(result_flag("removed"))
}

pub async fn set_group_member_tag(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(&payload)?;
    let id = group_id(&value)?;
    let member_id = account_id(&value, "account_id")?;
    let request = SetGroupTagRequest {
        tag: str_field(&value, "tag")?,
    };
    let token = bearer(state).await?;
    let _: Value = state
        .http
        .put(
            &group_path(&id, &format!("members/{member_id}/tag")),
            &request,
            Some(&token),
        )
        .await?;
    Ok(result_flag("updated"))
}

pub async fn remove_group_member_tag(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(&payload)?;
    let id = group_id(&value)?;
    let member_id = account_id(&value, "account_id")?;
    let token = bearer(state).await?;
    let _: Value = state
        .http
        .delete(
            &group_path(&id, &format!("members/{member_id}/tag")),
            Some(&token),
        )
        .await?;
    Ok(result_flag("updated"))
}

pub async fn list_group_bans(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(&payload)?;
    let id = group_id(&value)?;
    let token = bearer(state).await?;
    let response: Value = state
        .http
        .get(&group_path(&id, "bans"), Some(&token))
        .await?;
    json_bytes(&response)
}

pub async fn ban_group_member(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(&payload)?;
    let id = group_id(&value)?;
    let request = BanGroupMemberRequest {
        account_id: account_id(&value, "account_id")?,
        reason: optional_string(&value, "reason")?,
    };
    let token = bearer(state).await?;
    let _: Value = state
        .http
        .post(&group_path(&id, "bans"), &request, Some(&token))
        .await?;
    Ok(result_flag("banned"))
}

pub async fn unban_group_member(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(&payload)?;
    let id = group_id(&value)?;
    let member_id = account_id(&value, "account_id")?;
    let token = bearer(state).await?;
    let _: Value = state
        .http
        .delete(&group_path(&id, &format!("bans/{member_id}")), Some(&token))
        .await?;
    Ok(result_flag("unbanned"))
}

// --- Channels ---------------------------------------------------------------

pub async fn get_channel(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(&payload)?;
    let id = channel_id(&value)?;
    let token = bearer(state).await?;
    let response: Value = state.http.get(&channel_path(&id, ""), Some(&token)).await?;
    json_bytes(&response)
}

pub async fn list_public_channels(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let value: Value = parse_optional_object(&payload)?;
    let path = list_path("/api/v1/channels/public", list_limit(&value, Some(50))?);
    let token = bearer(state).await?;
    let response: Value = state.http.get(&path, Some(&token)).await?;
    json_bytes(&response)
}

pub async fn lookup_channel_by_handle(
    state: &Arc<ActorState>,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(&payload)?;
    let handle = validate_handle(str_field(&value, "handle")?)?;
    let token = bearer(state).await?;
    let response: Value = state
        .http
        .get(
            &format!("/api/v1/channels/by-handle/{handle}"),
            Some(&token),
        )
        .await?;
    json_bytes(&response)
}

pub async fn delete_channel(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(&payload)?;
    let id = channel_id(&value)?;
    let token = bearer(state).await?;
    let _: Value = state
        .http
        .delete(&channel_path(&id, ""), Some(&token))
        .await?;
    Ok(result_flag("deleted"))
}

pub async fn transfer_channel_owner(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(&payload)?;
    let id = channel_id(&value)?;
    let request = TransferOwnerRequest {
        new_owner_account_id: account_id(&value, "new_owner_account_id")?,
    };
    let token = bearer(state).await?;
    let _: Value = state
        .http
        .post(&channel_path(&id, "owner"), &request, Some(&token))
        .await?;
    Ok(result_flag("transferred"))
}

pub async fn get_channel_analytics(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(&payload)?;
    let id = channel_id(&value)?;
    let token = bearer(state).await?;
    let response: Value = state
        .http
        .get(&channel_path(&id, "analytics"), Some(&token))
        .await?;
    json_bytes(&response)
}

fn parse_optional_object(payload: &[u8]) -> Result<Value> {
    if payload.is_empty() {
        return Ok(Value::Object(Default::default()));
    }
    let value: Value = serde_json::from_slice(payload)?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(Error::InvalidPayload(
            "request must be a JSON object".into(),
        ))
    }
}

fn optional_string(value: &Value, field: &str) -> Result<Option<String>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(Error::InvalidPayload(format!("{field} must be a string"))),
    }
}

fn optional_bool(value: &Value, field: &str) -> Result<Option<bool>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(Error::InvalidPayload(format!("{field} must be a boolean"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CONVERSATION_ID: &str = "2f1acb9e-51c7-4d21-9c29-69fc7e9e8b5d";

    #[test]
    fn resource_ids_are_validated_and_canonicalized() {
        assert_eq!(
            uuid_field(CONVERSATION_ID, "conversation_id").unwrap(),
            CONVERSATION_ID
        );
        assert_eq!(
            group_id(&json!({"conversation_id": CONVERSATION_ID})).unwrap(),
            CONVERSATION_ID
        );
        assert_eq!(
            channel_id(&json!({"conversation_id": CONVERSATION_ID})).unwrap(),
            CONVERSATION_ID
        );
        assert_eq!(
            account_id(
                &json!({"account_id": "11111111-1111-4111-8111-111111111111"}),
                "account_id"
            )
            .unwrap(),
            "11111111-1111-4111-8111-111111111111"
        );
        assert!(group_id(&json!({})).is_err());
        assert!(channel_id(&json!({"conversation_id": "bad"})).is_err());
        assert!(uuid_field("not-an-id", "conversation_id").is_err());
        assert!(uuid_field("", "conversation_id").is_err());
    }

    #[test]
    fn handles_match_frontend_handle_shape() {
        assert_eq!(validate_handle("Team_42".into()).unwrap(), "Team_42");
        for invalid in [
            "abcd",
            "4group",
            "bad-handle",
            "bad/handle",
            &"a".repeat(33),
        ] {
            assert!(
                validate_handle(invalid.into()).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn public_list_limits_follow_default_and_api_cap() {
        assert_eq!(list_limit(&json!({}), None).unwrap(), None);
        assert_eq!(list_limit(&json!({}), Some(50)).unwrap(), Some(50));
        assert_eq!(
            list_limit(&json!({"limit": null}), Some(50)).unwrap(),
            Some(50)
        );
        assert_eq!(list_limit(&json!({"limit": 0}), None).unwrap(), Some(0));
        assert_eq!(list_limit(&json!({"limit": 250}), None).unwrap(), Some(200));
        assert!(list_limit(&json!({"limit": -1}), None).is_err());
        assert!(list_limit(&json!({"limit": "5"}), None).is_err());
    }

    #[test]
    fn route_builders_only_interpolate_validated_segments() {
        let id = uuid_field(CONVERSATION_ID, "conversation_id").unwrap();
        assert_eq!(
            group_path(&id, "members/11111111-1111-4111-8111-111111111111/tag"),
            format!(
                "/api/v1/groups/{CONVERSATION_ID}/members/11111111-1111-4111-8111-111111111111/tag"
            )
        );
        assert_eq!(
            channel_path(&id, "analytics"),
            format!("/api/v1/channels/{CONVERSATION_ID}/analytics")
        );
        assert_eq!(
            list_path("/api/v1/groups/public", None),
            "/api/v1/groups/public"
        );
        assert_eq!(
            list_path("/api/v1/channels/public", Some(50)),
            "/api/v1/channels/public?limit=50"
        );
    }

    #[test]
    fn optional_patch_fields_preserve_omission() {
        let request = UpdateGroupRequest {
            title: optional_string(&json!({"title":"new"}), "title").unwrap(),
            description: optional_string(&json!({}), "description").unwrap(),
            is_public: optional_bool(&json!({"is_public":false}), "is_public").unwrap(),
        };
        let json = serde_json::to_value(request).unwrap();
        assert_eq!(json, json!({"title":"new", "is_public":false}));
        assert!(optional_string(&json!({"title": 1}), "title").is_err());
        assert!(optional_bool(&json!({"is_public": "false"}), "is_public").is_err());
    }

    #[test]
    fn mutation_bodies_match_frontend_rest_fields() {
        assert_eq!(
            serde_json::to_value(TransferOwnerRequest {
                new_owner_account_id: "11111111-1111-4111-8111-111111111111".into(),
            })
            .unwrap(),
            json!({"new_owner_account_id": "11111111-1111-4111-8111-111111111111"})
        );
        assert_eq!(
            serde_json::to_value(AddGroupMemberRequest {
                account_id: "11111111-1111-4111-8111-111111111111".into(),
            })
            .unwrap(),
            json!({"account_id": "11111111-1111-4111-8111-111111111111"})
        );
        assert_eq!(
            serde_json::to_value(SetGroupTagRequest {
                tag: "moderator".into(),
            })
            .unwrap(),
            json!({"tag": "moderator"})
        );
        assert_eq!(
            serde_json::to_value(BanGroupMemberRequest {
                account_id: "11111111-1111-4111-8111-111111111111".into(),
                reason: None,
            })
            .unwrap(),
            json!({"account_id": "11111111-1111-4111-8111-111111111111"})
        );
        assert_eq!(
            serde_json::to_value(BanGroupMemberRequest {
                account_id: "11111111-1111-4111-8111-111111111111".into(),
                reason: Some("spam".into()),
            })
            .unwrap(),
            json!({"account_id": "11111111-1111-4111-8111-111111111111", "reason": "spam"})
        );
    }

    #[test]
    fn public_channel_payload_accepts_empty_object_only() {
        assert_eq!(parse_optional_object(b"").unwrap(), json!({}));
        assert_eq!(parse_optional_object(b"{}").unwrap(), json!({}));
        assert!(parse_optional_object(b"[]").is_err());
        assert!(parse_optional_object(b"not-json").is_err());
    }
}
