//! Native sender for the browser-compatible encrypted history transfer.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::api::common::bearer;
use crate::api::conversations::ConversationItem;
use crate::api::devices::DeviceItem;
use crate::crypto::history_protocol::{HistoryItemKind, history_chunks};
use crate::crypto::send::send_one;
use crate::db::auth as db_auth;
use crate::error::{Error, Result};
use crate::runtime::ActorState;

const ENVELOPE_TYPE_SYNC: i32 = 2;
const HISTORY_CHUNK_DELAY: Duration = Duration::from_millis(40);

/// One already-persisted local history record supplied by the client layer.
/// The native core does not own the caller's message or attachment database.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryItem {
    pub conversation_id: String,
    pub item_kind: HistoryItemKind,
    pub item_id: String,
    pub item: Value,
}

/// Input for responding to a server history request.
///
/// `items` contains the caller's durable message and attachment records plus
/// one final completion marker for every requested conversation. A supplied
/// `transfer_id` lets the caller retry an interrupted send; when omitted, the
/// library creates a UUIDv7.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SendHistoryRequest {
    pub from_device_number: i64,
    pub conversation_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_id: Option<String>,
    pub items: Vec<HistoryItem>,
}

/// Result of sequentially submitting history chunks to the WebSocket client.
/// `complete` means all chunks were accepted by the local WebSocket queue; it
/// does not claim that the server acknowledged or delivered them.
#[derive(Debug, Clone, Serialize)]
pub struct SendHistoryResponse {
    pub transfer_id: String,
    pub target_device_number: i64,
    pub conversation_count: usize,
    pub item_count: usize,
    pub chunk_count: usize,
    pub submitted_chunks: usize,
    pub complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedHistoryRequest {
    target_device_number: i64,
    conversation_ids: Vec<String>,
    transfer_id: String,
}

/// Respond to a WEB-compatible history request using caller-owned records.
/// All authorization and framing checks finish before the first network send.
pub async fn send_history(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request: SendHistoryRequest = serde_json::from_slice(&payload)?;
    let auth = db_auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;
    let account_id = auth.account_id.ok_or(Error::NotAuthenticated)?;
    let current_device_number = auth.device_number.ok_or(Error::NotAuthenticated)?;
    let token = bearer(state).await?;

    let own_devices: Vec<DeviceItem> = state.http.get("/api/v1/devices", Some(&token)).await?;
    let conversations: Vec<ConversationItem> = state
        .http
        .get("/api/v1/conversations", Some(&token))
        .await?;
    let active_device_numbers: Vec<_> = own_devices
        .into_iter()
        .map(|device| device.device_number)
        .collect();
    let accessible_conversations: Vec<_> = conversations
        .into_iter()
        .filter(|conversation| conversation.kind != "channel")
        .map(|conversation| conversation.id)
        .collect();

    let validated = validate_history_request(
        &request,
        &account_id,
        current_device_number,
        &active_device_numbers,
        &accessible_conversations,
    )?;
    let chunk_count = validate_history_items(&request.items, &validated)?;

    let mut response = SendHistoryResponse {
        transfer_id: validated.transfer_id.clone(),
        target_device_number: validated.target_device_number,
        conversation_count: validated.conversation_ids.len(),
        item_count: request.items.len(),
        chunk_count,
        submitted_chunks: 0,
        complete: false,
        error: None,
    };

    if !state.ws.is_running() {
        response.error = Some("websocket is not running".into());
        return Ok(serde_json::to_vec(&response)?);
    }

    for item in &request.items {
        let conversation_id = normalize_uuid(&item.conversation_id, "item.conversation_id")?;
        let chunks = history_chunks(
            &validated.transfer_id,
            &conversation_id,
            item.item_kind,
            &item.item_id,
            &item.item,
        )
        .map_err(|error| Error::InvalidPayload(error.to_string()))?;
        for chunk in chunks {
            if !state.ws.is_running() {
                response.error =
                    Some("history transfer disconnected; request it again to resume".into());
                return Ok(serde_json::to_vec(&response)?);
            }
            let plaintext = serde_json::to_vec(&chunk)?;
            if let Err(error) = send_one(
                state,
                &token,
                &account_id,
                current_device_number,
                &account_id,
                validated.target_device_number,
                &plaintext,
                ENVELOPE_TYPE_SYNC,
                Some(&conversation_id),
            )
            .await
            {
                response.error = Some(error.to_string());
                return Ok(serde_json::to_vec(&response)?);
            }
            response.submitted_chunks += 1;
            tokio::time::sleep(HISTORY_CHUNK_DELAY).await;
        }
    }

    response.complete = true;
    Ok(serde_json::to_vec(&response)?)
}

fn validate_history_request(
    request: &SendHistoryRequest,
    account_id: &str,
    current_device_number: i64,
    active_device_numbers: &[i64],
    accessible_conversations: &[String],
) -> Result<ValidatedHistoryRequest> {
    Uuid::parse_str(account_id)
        .map_err(|error| Error::InvalidPayload(format!("account_id: {error}")))?;
    if current_device_number <= 0 {
        return Err(Error::InvalidPayload(
            "current device number must be greater than zero".into(),
        ));
    }
    u32::try_from(current_device_number)
        .map_err(|_| Error::InvalidPayload("current device number is out of range".into()))?;
    if request.from_device_number <= 0 {
        return Err(Error::InvalidPayload(
            "from_device_number must be greater than zero".into(),
        ));
    }
    if request.from_device_number == current_device_number {
        return Err(Error::InvalidPayload(
            "history target must be another device".into(),
        ));
    }
    u32::try_from(request.from_device_number)
        .map_err(|_| Error::InvalidPayload("from_device_number is out of range".into()))?;
    if !active_device_numbers.contains(&request.from_device_number) {
        return Err(Error::InvalidPayload(
            "history target is not an active own device".into(),
        ));
    }

    let mut conversation_ids = Vec::new();
    let mut seen = HashSet::new();
    for (index, conversation_id) in request.conversation_ids.iter().enumerate() {
        let normalized = normalize_uuid(conversation_id, &format!("conversation_ids[{index}]"))?;
        if seen.insert(normalized.clone()) {
            conversation_ids.push(normalized);
        }
    }
    if conversation_ids.len() > 200 {
        return Err(Error::InvalidPayload(
            "conversation_ids must contain at most 200 distinct ids".into(),
        ));
    }

    let accessible: HashSet<_> = accessible_conversations
        .iter()
        .filter_map(|id| Uuid::parse_str(id).ok().map(|uuid| uuid.to_string()))
        .collect();
    if conversation_ids
        .iter()
        .any(|conversation_id| !accessible.contains(conversation_id))
    {
        return Err(Error::InvalidPayload(
            "history conversation is not accessible".into(),
        ));
    }

    let transfer_id = match request.transfer_id.as_deref() {
        Some(value) => normalize_uuid(value, "transfer_id")?,
        None => Uuid::now_v7().to_string(),
    };

    Ok(ValidatedHistoryRequest {
        target_device_number: request.from_device_number,
        conversation_ids,
        transfer_id,
    })
}

fn validate_history_items(
    items: &[HistoryItem],
    request: &ValidatedHistoryRequest,
) -> Result<usize> {
    let allowed: HashSet<_> = request
        .conversation_ids
        .iter()
        .map(String::as_str)
        .collect();
    let mut completed: HashSet<String> = HashSet::new();
    let mut message_counts: HashMap<String, usize> = HashMap::new();
    let mut seen_items: HashSet<(String, HistoryItemKind, String)> = HashSet::new();
    let mut chunk_count = 0usize;

    for item in items {
        let conversation_id = normalize_uuid(&item.conversation_id, "item.conversation_id")?;
        if !allowed.contains(conversation_id.as_str()) {
            return Err(Error::InvalidPayload(
                "history item conversation is not requested".into(),
            ));
        }
        if !item.item.is_object() {
            return Err(Error::InvalidPayload(
                "history item payload must be a JSON object".into(),
            ));
        }
        if completed.contains(conversation_id.as_str()) {
            return Err(Error::InvalidPayload(
                "history completion marker must be the final item".into(),
            ));
        }
        if !seen_items.insert((
            conversation_id.clone(),
            item.item_kind,
            item.item_id.clone(),
        )) {
            return Err(Error::InvalidPayload(
                "history transfer contains a duplicate item".into(),
            ));
        }

        let chunks = history_chunks(
            &request.transfer_id,
            &conversation_id,
            item.item_kind,
            &item.item_id,
            &item.item,
        )
        .map_err(|error| Error::InvalidPayload(error.to_string()))?;
        chunk_count = chunk_count
            .checked_add(chunks.len())
            .ok_or_else(|| Error::InvalidPayload("history chunk count overflow".into()))?;

        match item.item_kind {
            HistoryItemKind::Message => {
                let count = message_counts.entry(conversation_id.clone()).or_default();
                *count = count.checked_add(1).ok_or_else(|| {
                    Error::InvalidPayload("history message count overflow".into())
                })?;
            }
            HistoryItemKind::Attachment => {}
            HistoryItemKind::Complete => {
                if item.item_id != conversation_id {
                    return Err(Error::InvalidPayload(
                        "history completion item_id must match conversation_id".into(),
                    ));
                }
                let expected = item
                    .item
                    .get("message_count")
                    .and_then(Value::as_u64)
                    .and_then(|count| usize::try_from(count).ok())
                    .ok_or_else(|| {
                        Error::InvalidPayload(
                            "history completion message_count must be a non-negative integer"
                                .into(),
                        )
                    })?;
                if expected != message_counts.get(&conversation_id).copied().unwrap_or(0) {
                    return Err(Error::InvalidPayload(
                        "history completion message_count does not match sent messages".into(),
                    ));
                }
                completed.insert(conversation_id);
            }
        }
    }

    if request
        .conversation_ids
        .iter()
        .any(|conversation_id| !completed.contains(conversation_id.as_str()))
    {
        return Err(Error::InvalidPayload(
            "history transfer is missing a conversation completion marker".into(),
        ));
    }
    Ok(chunk_count)
}

fn normalize_uuid(value: &str, field: &str) -> Result<String> {
    Uuid::parse_str(value)
        .map(|uuid| uuid.to_string())
        .map_err(|error| Error::InvalidPayload(format!("{field}: {error}")))
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde_json::json;
    use uuid::Uuid;

    use super::*;
    use crate::crypto::history_protocol::{HISTORY_FRAGMENT_BYTES, HISTORY_MAX_ITEM_BYTES};

    const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER_DEVICE: i64 = 2;

    fn conversation_id(index: u128) -> String {
        Uuid::from_u128(index).to_string()
    }

    fn request(conversation_ids: Vec<String>, items: Vec<HistoryItem>) -> SendHistoryRequest {
        SendHistoryRequest {
            from_device_number: OTHER_DEVICE,
            conversation_ids,
            transfer_id: None,
            items,
        }
    }

    fn completion(conversation_id: &str, message_count: usize) -> HistoryItem {
        HistoryItem {
            conversation_id: conversation_id.into(),
            item_kind: HistoryItemKind::Complete,
            item_id: conversation_id.into(),
            item: json!({"message_count": message_count}),
        }
    }

    fn authorized(
        request: &SendHistoryRequest,
        active_devices: &[i64],
        accessible_conversations: &[String],
    ) -> Result<ValidatedHistoryRequest> {
        validate_history_request(
            request,
            ACCOUNT,
            1,
            active_devices,
            accessible_conversations,
        )
    }

    #[test]
    fn authorizes_another_active_own_device_and_generates_a_transfer_uuid() {
        let conversation = conversation_id(1);
        let request = request(
            vec![conversation.clone()],
            vec![completion(&conversation, 0)],
        );

        let validated = authorized(&request, &[1, 2], &[conversation.clone()]).unwrap();

        assert_eq!(validated.target_device_number, OTHER_DEVICE);
        assert_eq!(validated.conversation_ids, vec![conversation]);
        assert_eq!(
            Uuid::parse_str(&validated.transfer_id)
                .unwrap()
                .get_version_num(),
            7
        );
    }

    #[test]
    fn rejects_history_requests_for_the_current_or_inactive_device() {
        let conversation = conversation_id(1);
        let mut request = request(
            vec![conversation.clone()],
            vec![completion(&conversation, 0)],
        );
        request.from_device_number = 1;
        assert!(authorized(&request, &[1, 2], &[conversation.clone()]).is_err());

        request.from_device_number = OTHER_DEVICE;
        assert!(authorized(&request, &[1], &[conversation.clone()]).is_err());
    }

    #[test]
    fn accepts_at_most_two_hundred_distinct_conversations_and_deduplicates() {
        let conversations: Vec<_> = (1..=200).map(conversation_id).collect();
        let mut requested = conversations.clone();
        requested.push(conversations[0].clone());
        let req = request(requested, Vec::new());
        let validated = authorized(&req, &[1, 2], &conversations).unwrap();
        assert_eq!(validated.conversation_ids, conversations);

        let too_many: Vec<_> = (1..=201).map(conversation_id).collect();
        let req = request(too_many.clone(), Vec::new());
        assert!(authorized(&req, &[1, 2], &too_many).is_err());
    }

    #[test]
    fn rejects_a_channel_or_non_member_conversation() {
        let conversation = conversation_id(1);
        let req = request(vec![conversation], Vec::new());
        assert!(authorized(&req, &[1, 2], &[]).is_err());
    }

    #[test]
    fn validates_supplied_transfer_uuid_and_item_conversation_membership() {
        let conversation = conversation_id(1);
        let req = request(
            vec![conversation.clone()],
            vec![completion(&conversation, 0)],
        );
        let mut invalid_id = req.clone();
        invalid_id.transfer_id = Some("not-a-uuid".into());
        assert!(authorized(&invalid_id, &[1, 2], &[conversation.clone()]).is_err());

        let validated = authorized(&req, &[1, 2], &[conversation.clone()]).unwrap();
        let mut wrong_conversation = req;
        wrong_conversation.items[0].conversation_id = conversation_id(2);
        assert!(validate_history_items(&wrong_conversation.items, &validated).is_err());
    }

    #[test]
    fn requires_one_final_completion_marker_with_the_exact_message_count() {
        let conversation = conversation_id(1);
        let message = HistoryItem {
            conversation_id: conversation.clone(),
            item_kind: HistoryItemKind::Message,
            item_id: "message-1".into(),
            item: json!({"message":{"kind":"message","message_id":"message-1"}}),
        };
        let mut req = request(
            vec![conversation.clone()],
            vec![message.clone(), completion(&conversation, 1)],
        );
        let validated = authorized(&req, &[1, 2], &[conversation.clone()]).unwrap();
        assert!(validate_history_items(&req.items, &validated).is_ok());

        req.items[1] = completion(&conversation, 0);
        assert!(validate_history_items(&req.items, &validated).is_err());
        req.items = vec![completion(&conversation, 1), message];
        assert!(validate_history_items(&req.items, &validated).is_err());
        req.items = vec![completion(&conversation, 0), completion(&conversation, 0)];
        assert!(validate_history_items(&req.items, &validated).is_err());
    }

    #[test]
    fn fragments_items_with_the_web_history_sync_wire_shape_and_size() {
        let conversation = conversation_id(1);
        let transfer = "019c6e27-e55b-73d1-87d8-4e01f1f75043".to_string();
        let payload = json!({"message": {"text": "x".repeat(50 * 1024)}});

        let chunks = history_chunks(
            &transfer,
            &conversation,
            HistoryItemKind::Message,
            "message-1",
            &payload,
        )
        .unwrap();

        assert_eq!(chunks.len(), 3);
        for (index, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.kind, "history_sync");
            assert_eq!(chunk.version, 1);
            assert_eq!(chunk.transfer_id, transfer);
            assert_eq!(chunk.conversation_id, conversation);
            assert_eq!(chunk.item_kind, HistoryItemKind::Message);
            assert_eq!(chunk.item_id, "message-1");
            assert_eq!(chunk.part_index, index);
            assert_eq!(chunk.part_count, 3);
            assert!(chunk.data.len() <= HISTORY_FRAGMENT_BYTES * 4 / 3);
        }
        let bytes: Vec<_> = chunks
            .iter()
            .flat_map(|chunk| STANDARD.decode(&chunk.data).unwrap())
            .collect();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            payload
        );
    }

    #[test]
    fn item_validation_rejects_objects_larger_than_the_wire_limit() {
        let conversation = conversation_id(1);
        let item = HistoryItem {
            conversation_id: conversation.clone(),
            item_kind: HistoryItemKind::Attachment,
            item_id: "attachment-1".into(),
            item: json!({"blob":"x".repeat(HISTORY_MAX_ITEM_BYTES + 1)}),
        };
        let req = request(
            vec![conversation.clone()],
            vec![item, completion(&conversation, 0)],
        );
        let validated = authorized(&req, &[1, 2], &[conversation]).unwrap();
        assert!(validate_history_items(&req.items, &validated).is_err());
    }
}
