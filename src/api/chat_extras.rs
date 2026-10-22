//! REST operations used by the web client's conversation, saved-message,
//! polling, folder, scheduling, and search APIs.
//!
//! Payloads use the web API's snake_case request fields. Responses are returned
//! as JSON bytes after `HttpClient` has performed the registered protobuf
//! decoding.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::api::common::{bearer, str_field};
use crate::error::{Error, Result};
use crate::runtime::ActorState;

const API: &str = "/api/v1";
const MAX_IDENTIFIER_CHARS: usize = 128;
const MAX_QUERY_CHARS: usize = 64;

/// Search this account's own contacts.
///
/// Payload: `{ "q": "...", "limit": 30 }`. The web API defaults `limit` to
/// 30 and accepts 1..=100.
pub async fn contact_search(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let query = search_query(&request, "q")?;
    let limit = bounded_optional_integer(&request, "limit", 1, 100)?.unwrap_or(30);
    let path = with_query(
        &format!("{API}/contacts/search"),
        vec![("q", query), ("limit", limit.to_string())],
    );
    get_json(state, &path).await
}

/// Read device-bound encrypted history for one conversation.
///
/// Payload: `{ "conversation_id": "...", "before": 123,
/// "before_id": "...", "limit": 100 }`.
pub async fn conversation_envelopes(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let conversation_id = path_field(&request, "conversation_id")?;
    let query = history_query(&request, 500)?;
    let path = with_query(
        &format!("{API}/conversations/{conversation_id}/envelopes"),
        query,
    );
    get_json(state, &path).await
}

/// List all per-account read markers for a conversation.
pub async fn conversation_reads(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let conversation_id = path_field(&request, "conversation_id")?;
    let path = format!("{API}/conversations/{conversation_id}/reads");
    get_json(state, &path).await
}

/// Move this account's read marker for a conversation.
///
/// Payload: `{ "conversation_id": "...", "up_to": 123 }`. Missing or null
/// `up_to` is sent as JSON null, matching the web client (server chooses now).
pub async fn conversation_mark_read(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let conversation_id = path_field(&request, "conversation_id")?;
    let up_to = optional_integer(&request, "up_to")?;
    if up_to.is_some_and(|value| value <= 0) {
        return Err(invalid("up_to must be a positive integer"));
    }
    let path = format!("{API}/conversations/{conversation_id}/read");
    let body = json!({ "up_to": up_to });
    post_empty(state, &path, &body).await
}

/// List messages pinned in a conversation, newest pin first.
pub async fn conversation_pins_list(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let conversation_id = path_field(&request, "conversation_id")?;
    let path = format!("{API}/conversations/{conversation_id}/pinned");
    get_json(state, &path).await
}

/// Pin a logical message ID in a conversation.
pub async fn conversation_pin(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let conversation_id = path_field(&request, "conversation_id")?;
    let message_id = path_field(&request, "message_id")?;
    let path = format!("{API}/conversations/{conversation_id}/pinned");
    post_empty(state, &path, &json!({ "message_id": message_id })).await
}

/// Remove a pinned logical message ID from a conversation.
pub async fn conversation_unpin(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let conversation_id = path_field(&request, "conversation_id")?;
    let message_id = path_field(&request, "message_id")?;
    let path = format!("{API}/conversations/{conversation_id}/pinned/{message_id}");
    delete_empty(state, &path).await
}

/// List poll records for a conversation, optionally using the web history cursor.
pub async fn conversation_polls_list(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let conversation_id = path_field(&request, "conversation_id")?;
    let query = history_query(&request, 500)?;
    let path = with_query(
        &format!("{API}/conversations/{conversation_id}/polls"),
        query,
    );
    get_json(state, &path).await
}

/// Get one poll by its ID.
pub async fn poll_get(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let poll_id = path_field(&request, "poll_id")?;
    get_json(state, &format!("{API}/polls/{poll_id}")).await
}

/// Create a poll in a conversation.
pub async fn poll_create(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let conversation_id = path_field(&request, "conversation_id")?;
    let poll_type = str_field(&request, "poll_type")?;
    if poll_type != "regular" && poll_type != "quiz" {
        return Err(invalid("poll_type must be 'regular' or 'quiz'"));
    }
    let allows_multiple = required_bool(&request, "allows_multiple")?;
    let allows_revoting = required_bool(&request, "allows_revoting")?;
    let allows_user_options = required_bool(&request, "allows_user_options")?;
    let encrypted_meta = required_string(&request, "encrypted_meta", 1, usize::MAX)?;
    let option_ids = string_array(&request, "option_ids", 64)?;
    let correct_option_id = optional_bounded_string(&request, "correct_option_id", 64)?;
    let mut body = json!({
        "poll_type": poll_type,
        "allows_multiple": allows_multiple,
        "allows_revoting": allows_revoting,
        "allows_user_options": allows_user_options,
        "encrypted_meta": encrypted_meta,
        "option_ids": option_ids,
        "correct_option_id": correct_option_id,
    });
    if request.get("open_period_seconds").is_some() {
        let open_period_seconds =
            bounded_optional_integer(&request, "open_period_seconds", 1, i64::MAX)?
                .ok_or_else(|| invalid("open_period_seconds cannot be null"))?;
        body["open_period_seconds"] = json!(open_period_seconds);
    }
    let path = format!("{API}/conversations/{conversation_id}/polls");
    post_json_no_retry(state, &path, &body).await
}

/// Vote for poll option IDs.
pub async fn poll_vote(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let poll_id = path_field(&request, "poll_id")?;
    let option_ids = string_array(&request, "option_ids", 64)?;
    post_json_no_retry(
        state,
        &format!("{API}/polls/{poll_id}/vote"),
        &json!({ "option_ids": option_ids }),
    )
    .await
}

/// Stop an open poll.
pub async fn poll_stop(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let poll_id = path_field(&request, "poll_id")?;
    post_empty_no_retry(state, &format!("{API}/polls/{poll_id}/stop"), &json!({})).await
}

/// Delete a poll.
pub async fn poll_delete(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let poll_id = path_field(&request, "poll_id")?;
    delete_empty_no_retry(state, &format!("{API}/polls/{poll_id}")).await
}

/// Add a proposed encrypted option to a poll.
pub async fn poll_add_option(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let poll_id = path_field(&request, "poll_id")?;
    let option_id = bounded_string(&request, "option_id", 1, 64)?;
    let encrypted_meta = required_string(&request, "encrypted_meta", 1, usize::MAX)?;
    post_empty_no_retry(
        state,
        &format!("{API}/polls/{poll_id}/options"),
        &json!({ "option_id": option_id, "encrypted_meta": encrypted_meta }),
    )
    .await
}

/// Remove a proposed option from a poll.
pub async fn poll_delete_option(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let poll_id = path_field(&request, "poll_id")?;
    let option_id = path_field(&request, "option_id")?;
    delete_empty_no_retry(state, &format!("{API}/polls/{poll_id}/options/{option_id}")).await
}

/// Resolve (and lazily create) this account's saved conversation.
pub async fn saved_conversation(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    get_json(state, &format!("{API}/saved")).await
}

/// Read current-device saved-message history, returning the web API's envelopes array.
pub async fn saved_messages(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let mut query = history_query(&request, 500)?;
    if let Some(envelope_type) = optional_integer(&request, "envelope_type")? {
        query.push(("envelope_type", envelope_type.to_string()));
    }
    let path = with_query(&format!("{API}/saved/messages"), query);
    let response = get_value(state, &path).await?;
    let envelopes = response
        .get("envelopes")
        .cloned()
        .ok_or_else(|| invalid("saved history response has no envelopes field"))?;
    serialize(&envelopes)
}

/// List this account's chat folders.
pub async fn folders_list(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    get_json(state, &format!("{API}/folders")).await
}

/// Create a chat folder.
pub async fn folder_create(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let name = bounded_string(&request, "name", 1, 64)?;
    post_json(state, &format!("{API}/folders"), &json!({ "name": name })).await
}

/// Change a chat folder's name and/or position.
pub async fn folder_update(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let folder_id = path_field(&request, "folder_id")?;
    let mut changes = serde_json::Map::new();
    if request.get("name").is_some() {
        changes.insert(
            "name".into(),
            json!(bounded_string(&request, "name", 1, 64)?),
        );
    }
    if request.get("position").is_some() {
        let position = optional_integer(&request, "position")?
            .ok_or_else(|| invalid("position must be an integer"))?;
        changes.insert("position".into(), json!(position));
    }
    if changes.is_empty() {
        return Err(invalid("folder update must include name or position"));
    }
    let token = bearer(state).await?;
    let response: Value = state
        .http
        .patch(
            &format!("{API}/folders/{folder_id}"),
            &Value::Object(changes),
            Some(&token),
        )
        .await?;
    serialize(&response)
}

/// Delete a chat folder.
pub async fn folder_delete(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let folder_id = path_field(&request, "folder_id")?;
    delete_empty(state, &format!("{API}/folders/{folder_id}")).await
}

/// Add a conversation to a folder.
pub async fn folder_add_conversation(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let folder_id = path_field(&request, "folder_id")?;
    let conversation_id = required_string(&request, "conversation_id", 1, MAX_IDENTIFIER_CHARS)?;
    post_empty(
        state,
        &format!("{API}/folders/{folder_id}/items"),
        &json!({ "conversation_id": conversation_id }),
    )
    .await
}

/// Remove a conversation from a folder.
pub async fn folder_remove_conversation(
    state: &Arc<ActorState>,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let folder_id = path_field(&request, "folder_id")?;
    let conversation_id = path_field(&request, "conversation_id")?;
    delete_empty(
        state,
        &format!("{API}/folders/{folder_id}/items/{conversation_id}"),
    )
    .await
}

/// List the current account's scheduled envelopes.
pub async fn scheduled_list(state: &Arc<ActorState>, _payload: Vec<u8>) -> Result<Vec<u8>> {
    get_json(state, &format!("{API}/scheduled")).await
}

/// Cancel a scheduled envelope.
pub async fn scheduled_cancel(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let envelope_id = path_field(&request, "envelope_id")?;
    delete_empty(state, &format!("{API}/scheduled/{envelope_id}")).await
}

/// Search accounts, groups, channels, and bots.
///
/// The web client defaults to `scope=all`, `limit=20`, then unwraps the
/// endpoint's `{ "results": [...] }` object to the result array.
pub async fn global_search(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_payload(&payload)?;
    let query = search_query(&request, "q")?;
    let scope = match request.get("scope") {
        None => "all",
        Some(Value::String(scope)) => scope.as_str(),
        Some(_) => return Err(invalid("scope must be a string")),
    };
    if scope != "all" && scope != "identifiers" {
        return Err(invalid("scope must be 'all' or 'identifiers'"));
    }
    let limit = bounded_optional_integer(&request, "limit", 1, 50)?.unwrap_or(20);
    let path = with_query(
        &format!("{API}/search"),
        vec![
            ("q", query),
            ("scope", scope.to_owned()),
            ("limit", limit.to_string()),
        ],
    );
    let response = get_value(state, &path).await?;
    let results = response
        .get("results")
        .cloned()
        .ok_or_else(|| invalid("search response has no results field"))?;
    serialize(&results)
}

async fn get_json(state: &Arc<ActorState>, path: &str) -> Result<Vec<u8>> {
    serialize(&get_value(state, path).await?)
}

async fn get_value(state: &Arc<ActorState>, path: &str) -> Result<Value> {
    let token = bearer(state).await?;
    state.http.get(path, Some(&token)).await
}

async fn post_json(state: &Arc<ActorState>, path: &str, body: &Value) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let response: Value = state.http.post(path, body, Some(&token)).await?;
    serialize(&response)
}

async fn post_json_no_retry(state: &Arc<ActorState>, path: &str, body: &Value) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let response: Value = state
        .http
        .post_no_rate_limit_retry(path, body, Some(&token))
        .await?;
    serialize(&response)
}

async fn post_empty(state: &Arc<ActorState>, path: &str, body: &Value) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    state.http.post_void(path, body, Some(&token)).await?;
    Ok(b"null".to_vec())
}

async fn post_empty_no_retry(state: &Arc<ActorState>, path: &str, body: &Value) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let _: Value = state
        .http
        .post_no_rate_limit_retry(path, body, Some(&token))
        .await?;
    Ok(b"null".to_vec())
}

async fn delete_empty(state: &Arc<ActorState>, path: &str) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let _: Value = state.http.delete(path, Some(&token)).await?;
    Ok(b"null".to_vec())
}

async fn delete_empty_no_retry(state: &Arc<ActorState>, path: &str) -> Result<Vec<u8>> {
    let token = bearer(state).await?;
    let _: Value = state
        .http
        .delete_no_rate_limit_retry(path, Some(&token))
        .await?;
    Ok(b"null".to_vec())
}

fn parse_payload(payload: &[u8]) -> Result<Value> {
    let value: Value = serde_json::from_slice(payload)?;
    if !value.is_object() {
        return Err(invalid("request payload must be a JSON object"));
    }
    Ok(value)
}

fn required_string(value: &Value, field: &str, min: usize, max: usize) -> Result<String> {
    let text = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{field} must be a string")))?;
    let length = text.chars().count();
    if length < min || length > max || text.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{field} has an invalid length or control character"
        )));
    }
    Ok(text.to_owned())
}

fn bounded_string(value: &Value, field: &str, min: usize, max: usize) -> Result<String> {
    required_string(value, field, min, max)
}

fn optional_bounded_string(value: &Value, field: &str, max: usize) -> Result<Option<String>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => required_string(value, field, 1, max).map(Some),
    }
}

/// Validates a path segment and percent-encodes every delimiter that could
/// alter routing. This mirrors the frontend's `encodeURIComponent` behavior.
fn path_field(value: &Value, field: &str) -> Result<String> {
    let raw = required_string(value, field, 1, MAX_IDENTIFIER_CHARS)?;
    Ok(encode_path_segment(&raw))
}

fn encode_path_segment(value: &str) -> String {
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
    encoded
}

fn optional_integer(value: &Value, field: &str) -> Result<Option<i64>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(number) => number
            .as_i64()
            .map(Some)
            .ok_or_else(|| invalid(format!("{field} must be an integer"))),
    }
}

fn bounded_optional_integer(value: &Value, field: &str, min: i64, max: i64) -> Result<Option<i64>> {
    let number = optional_integer(value, field)?;
    if number.is_some_and(|number| number < min || number > max) {
        return Err(invalid(format!("{field} must be between {min} and {max}")));
    }
    Ok(number)
}

fn required_bool(value: &Value, field: &str) -> Result<bool> {
    value
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(format!("{field} must be a boolean")))
}

fn string_array(value: &Value, field: &str, max_item_chars: usize) -> Result<Vec<String>> {
    let values = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("{field} must be an array of strings")))?;
    values
        .iter()
        .map(|item| {
            let text = item
                .as_str()
                .ok_or_else(|| invalid(format!("{field} must contain only strings")))?;
            let length = text.chars().count();
            if length == 0 || length > max_item_chars || text.chars().any(char::is_control) {
                return Err(invalid(format!("{field} contains an invalid string")));
            }
            Ok(text.to_owned())
        })
        .collect()
}

fn search_query(value: &Value, field: &str) -> Result<String> {
    required_string(value, field, 3, MAX_QUERY_CHARS)
}

fn history_query(value: &Value, max_limit: i64) -> Result<Vec<(&'static str, String)>> {
    let mut query = Vec::with_capacity(3);
    if let Some(before) = optional_integer(value, "before")? {
        query.push(("before", before.to_string()));
    }
    if let Some(before_id) = value.get("before_id") {
        if !before_id.is_null() {
            let raw = required_string(value, "before_id", 1, MAX_IDENTIFIER_CHARS)?;
            query.push(("before_id", raw));
        }
    }
    if let Some(limit) = bounded_optional_integer(value, "limit", 1, max_limit)? {
        query.push(("limit", limit.to_string()));
    }
    Ok(query)
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

fn serialize(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(Error::from)
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidPayload(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_segment_encodes_route_delimiters_and_unicode() {
        assert_eq!(encode_path_segment("id/part?x=1"), "id%2Fpart%3Fx%3D1");
        assert_eq!(encode_path_segment("дом"), "%D0%B4%D0%BE%D0%BC");
        assert_eq!(encode_path_segment("a-b_c.d"), "a-b_c.d");
    }

    #[test]
    fn path_identifier_rejects_missing_controls_and_oversize() {
        assert!(path_field(&json!({"id": ""}), "id").is_err());
        assert!(path_field(&json!({"id": "line\nbreak"}), "id").is_err());
        assert!(path_field(&json!({"id": "x".repeat(MAX_IDENTIFIER_CHARS + 1)}), "id").is_err());
    }

    #[test]
    fn query_serializer_matches_url_search_params_encoding() {
        assert_eq!(
            with_query(
                "/api/v1/search",
                vec![("q", "a b&c".into()), ("limit", "20".into())]
            ),
            "/api/v1/search?q=a+b%26c&limit=20"
        );
        assert_eq!(with_query("/api/v1/folders", vec![]), "/api/v1/folders");
    }

    #[test]
    fn query_validation_enforces_frontend_search_contract() {
        assert_eq!(search_query(&json!({"q":"user"}), "q").unwrap(), "user");
        assert!(search_query(&json!({"q":"ab"}), "q").is_err());
        assert_eq!(search_query(&json!({"q":"   "}), "q").unwrap(), "   ");
        assert!(search_query(&json!({"q":"x".repeat(65)}), "q").is_err());
        assert!(bounded_optional_integer(&json!({"limit":0}), "limit", 1, 50).is_err());
    }

    #[test]
    fn history_query_preserves_supported_cursor_fields_and_omits_nulls() {
        assert_eq!(
            history_query(
                &json!({"before": 42, "before_id":"env-1", "limit": 25}),
                500
            )
            .unwrap(),
            vec![
                ("before", "42".into()),
                ("before_id", "env-1".into()),
                ("limit", "25".into())
            ]
        );
        assert_eq!(
            history_query(&json!({"before": 0}), 500).unwrap(),
            vec![("before", "0".into())]
        );
        assert!(history_query(&json!({"limit": 501}), 500).is_err());
        assert!(
            history_query(
                &json!({"before": null, "before_id": null, "limit": null}),
                500
            )
            .unwrap()
            .is_empty()
        );
    }
}
