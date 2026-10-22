use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::{bearer, id_from, str_field};
use crate::error::Result;
use crate::runtime::ActorState;

const MAX_BOT_IDENTIFIER_CHARS: usize = 128;
const MAX_BOT_HISTORY_LIMIT: i64 = 200;

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
    pub reply_markup: Option<String>,
    #[serde(default, deserialize_with = "deserialize_deleted_flag")]
    pub is_deleted: bool,
}

pub async fn get_history(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    let bot_id = path_segment(&id_from(&v)?)?;
    let path = with_query(
        &format!("/api/v1/bots/{bot_id}/messages"),
        history_query(&v)?,
    );
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

fn deserialize_deleted_flag<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<i64>::deserialize(deserializer)?.is_some())
}

fn history_query(value: &serde_json::Value) -> Result<Vec<(&'static str, String)>> {
    let mut query = Vec::with_capacity(3);
    if let Some(before) = optional_integer(value, "before")? {
        query.push(("before", before.to_string()));
    }
    if let Some(before_id) = value.get("before_id") {
        if !before_id.is_null() {
            let before_id = before_id
                .as_str()
                .ok_or_else(|| invalid_payload("before_id must be a string"))?;
            validate_identifier(before_id, "before_id")?;
            query.push(("before_id", before_id.to_owned()));
        }
    }
    if let Some(limit) = optional_integer(value, "limit")? {
        if !(1..=MAX_BOT_HISTORY_LIMIT).contains(&limit) {
            return Err(invalid_payload(format!(
                "limit must be between 1 and {MAX_BOT_HISTORY_LIMIT}"
            )));
        }
        query.push(("limit", limit.to_string()));
    }
    Ok(query)
}

fn optional_integer(value: &serde_json::Value, field: &str) -> Result<Option<i64>> {
    match value.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(number) => number
            .as_i64()
            .map(Some)
            .ok_or_else(|| invalid_payload(format!("{field} must be an integer"))),
    }
}

fn validate_identifier(value: &str, field: &str) -> Result<()> {
    let length = value.chars().count();
    if length == 0 || length > MAX_BOT_IDENTIFIER_CHARS || value.chars().any(char::is_control) {
        return Err(invalid_payload(format!(
            "{field} has an invalid length or control character"
        )));
    }
    Ok(())
}

fn path_segment(value: &str) -> Result<String> {
    validate_identifier(value, "id")?;
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    Ok(encoded)
}

fn with_query(path: &str, pairs: Vec<(&str, String)>) -> String {
    if pairs.is_empty() {
        return path.to_owned();
    }
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(name, &value);
    }
    format!("{path}?{}", serializer.finish())
}

fn invalid_payload(message: impl Into<String>) -> crate::error::Error {
    crate::error::Error::InvalidPayload(message.into())
}

#[allow(dead_code)]
fn _unused(_: BotItem, _: OwnedBotItem, _: BotPublicInfo, _: BotMessageItem) {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bot_history_query_matches_web_cursor_and_encoding_contract() {
        let path = with_query(
            &format!("/api/v1/bots/{}/messages", path_segment("bot/id").unwrap()),
            history_query(&json!({"before": 0, "before_id": "id &/?", "limit": 200})).unwrap(),
        );
        assert_eq!(
            path,
            "/api/v1/bots/bot%2Fid/messages?before=0&before_id=id+%26%2F%3F&limit=200"
        );
        assert_eq!(
            with_query(
                "/api/v1/bots/bot/messages",
                history_query(&json!({"before": null, "before_id": null, "limit": null})).unwrap()
            ),
            "/api/v1/bots/bot/messages"
        );
    }

    #[test]
    fn bot_history_query_rejects_invalid_cursor_and_limit_values() {
        assert!(history_query(&json!({"before": "yesterday"})).is_err());
        assert!(history_query(&json!({"before_id": ""})).is_err());
        assert!(history_query(&json!({"before_id": "line\nbreak"})).is_err());
        assert!(history_query(&json!({"limit": 0})).is_err());
        assert!(history_query(&json!({"limit": 201})).is_err());
        assert!(history_query(&json!({"limit": 1.5})).is_err());
    }

    #[test]
    fn bot_message_dto_preserves_reply_markup_and_exposes_deleted_flag() {
        let live: BotMessageItem = serde_json::from_value(json!({
            "id": "live",
            "bot_id": "bot",
            "sender_account_id": "account",
            "direction": "to_bot",
            "text": "hello",
            "reply_to_id": null,
            "created_at": 10,
            "reply_markup": "{\"inline_keyboard\":[]}",
            "is_deleted": null
        }))
        .unwrap();
        let live = serde_json::to_value(live).unwrap();
        assert_eq!(live["reply_markup"], "{\"inline_keyboard\":[]}");
        assert_eq!(live["is_deleted"], false);

        let deleted: BotMessageItem = serde_json::from_value(json!({
            "id": "deleted",
            "bot_id": "bot",
            "sender_account_id": "account",
            "direction": "from_bot",
            "text": "gone",
            "reply_to_id": null,
            "created_at": 11,
            "reply_markup": null,
            "is_deleted": 11
        }))
        .unwrap();
        let deleted = serde_json::to_value(deleted).unwrap();
        assert_eq!(deleted["reply_markup"], serde_json::Value::Null);
        assert_eq!(deleted["is_deleted"], true);
    }
}
