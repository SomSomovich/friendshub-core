use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::common::str_field;
use crate::crypto::groups;
use crate::crypto::history_stage::{
    self, CommitReceipt, CryptoSnapshot, DurableCommitResult, StageError,
};
use crate::crypto::manager::decrypt_envelope;
use crate::crypto::receive::{ReceiveMetadata, parse_decrypted_payload};
use crate::db::auth as db_auth;
use crate::error::{Error, Result};
use crate::runtime::ActorState;
use crate::util::time::now_unix;

const MAX_KNOWN_ENVELOPE_IDS: usize = 500;
const MAX_KNOWN_MESSAGE_IDS: usize = 5_000;
const MAX_ENVELOPE_ID_CHARS: usize = 128;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEnvelope {
    #[serde(alias = "envelope_id")]
    pub envelope_id: String,
    #[serde(alias = "sender_account_id")]
    pub sender_account_id: String,
    #[serde(alias = "sender_device_number")]
    pub sender_device_number: i64,
    #[serde(alias = "recipient_device_number")]
    pub recipient_device_number: i64,
    #[serde(alias = "envelope_type")]
    pub envelope_type: i64,
    #[serde(alias = "is_prekey_message")]
    pub is_prekey_message: bool,
    pub ciphertext: String,
    #[serde(alias = "client_timestamp")]
    pub client_timestamp: i64,
    #[serde(alias = "server_timestamp")]
    pub server_timestamp: i64,
    #[serde(default, alias = "conversation_id")]
    pub conversation_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReplayRequest {
    #[serde(default, alias = "conversationId")]
    conversation_id: Option<String>,
    #[serde(default, alias = "knownEnvelopeIds")]
    known_envelope_ids: Option<Vec<String>>,
    #[serde(
        default,
        alias = "knownMessageIds",
        alias = "knownLogicalMessageIds",
        alias = "known_logical_message_ids"
    )]
    known_message_ids: Option<Vec<String>>,
}

#[derive(Debug, Default)]
struct ReplayResult {
    messages: Vec<Value>,
    available: Vec<Value>,
    attachment_keys: Vec<Value>,
    processed_envelope_ids: Vec<String>,
    skipped_envelope_ids: Vec<String>,
    existing_message_ids: Vec<String>,
    identity_changes: Vec<Value>,
    existing: usize,
    unavailable: usize,
    ignored: usize,
}

enum ProcessedEnvelope {
    Message(Value),
    AttachmentKey(Value),
    SenderKey,
    Ignored,
}

/// Fetch and replay one conversation-history page against an isolated copy of
/// Signal state. The returned token must be committed only after the host has
/// durably saved the returned messages, attachment keys, and progress IDs.
pub async fn begin_conversation_page(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_replay_request(&payload)?;
    let conversation_id = request
        .conversation_id
        .as_deref()
        .ok_or_else(|| Error::InvalidPayload("conversation_id is missing".into()))?;
    validate_uuid(conversation_id, "conversation_id")?;
    let known_ids = validate_known_envelope_id_values(request.known_envelope_ids)?;
    let known_message_ids = validate_known_message_ids(request.known_message_ids)?;
    let (rest_payload, limit) =
        normalize_history_rest_payload(&payload, Some(conversation_id), 200)?;
    let response = crate::api::chat_extras::conversation_envelopes(state, rest_payload).await?;
    let rows = serde_json::from_slice::<Vec<HistoryEnvelope>>(&response)?;
    replay_page(
        state,
        conversation_id,
        rows,
        known_ids,
        known_message_ids,
        limit,
    )
    .await
}

/// Fetch and replay the current device's Saved Messages history. Resolving the
/// saved conversation uses the same REST endpoint as the WEB client and also
/// supplies the conversation ID absent from saved-envelope rows.
pub async fn begin_saved_page(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request = parse_replay_request(&payload)?;
    let known_ids = validate_known_envelope_id_values(request.known_envelope_ids)?;
    let known_message_ids = validate_known_message_ids(request.known_message_ids)?;
    let saved_conversation = crate::api::chat_extras::saved_conversation(state, Vec::new()).await?;
    let saved_conversation: Value = serde_json::from_slice(&saved_conversation)?;
    let conversation_id = saved_conversation
        .get("conversation_id")
        .or_else(|| saved_conversation.get("conversationId"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            Error::InvalidPayload("saved conversation response has no conversation_id".into())
        })?;
    validate_uuid(conversation_id, "conversation_id")?;

    let (rest_payload, limit) = normalize_history_rest_payload(&payload, None, 100)?;
    let response = crate::api::chat_extras::saved_messages(state, rest_payload).await?;
    let rows = serde_json::from_slice::<Vec<HistoryEnvelope>>(&response)?;
    let rows = rows
        .into_iter()
        .map(|mut row| {
            row.conversation_id = Some(conversation_id.to_owned());
            row
        })
        .collect();
    replay_page(
        state,
        conversation_id,
        rows,
        known_ids,
        known_message_ids,
        limit,
    )
    .await
}

/// Commit the isolated Signal transition after the host has saved its page.
/// Repeating a successful commit with the same token is idempotent for the
/// token's receipt lifetime, including when the first response was lost. If
/// `conflict` is true, the host must atomically roll back that page's saved
/// messages, attachment keys, and progress markers before retrying from fresh
/// state; the core does not own or modify those records.
pub async fn commit(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request: Value = serde_json::from_slice(&payload)?;
    let token =
        str_field(&request, "replay_token").or_else(|_| str_field(&request, "replayToken"))?;
    validate_token(&token)?;

    let mut registry = state.history_replay_stages.lock().await;
    let durable_receipt = history_stage::lookup_durable_receipt(&state.db, &token)
        .await
        .map_err(map_stage_error)?;
    let result = if let Some(receipt) = durable_receipt {
        match receipt {
            CommitReceipt::Committed => DurableCommitResult::AlreadyCommitted,
            CommitReceipt::Conflict => DurableCommitResult::PreviouslyConflicted,
        }
    } else {
        history_stage::commit_persisted_stage(&state.db, &token)
            .await
            .map_err(map_stage_error)?
    };
    let (committed, conflict, already_committed, receipt) = match result {
        DurableCommitResult::Committed => (true, false, false, CommitReceipt::Committed),
        DurableCommitResult::Conflict | DurableCommitResult::PreviouslyConflicted => {
            (false, true, false, CommitReceipt::Conflict)
        }
        DurableCommitResult::AlreadyCommitted => (true, false, true, CommitReceipt::Committed),
    };
    registry.finish_commit(&token, receipt);

    serde_json::to_vec(&json!({
        "committed": committed,
        "conflict": conflict,
        "alreadyCommitted": already_committed,
    }))
    .map_err(Error::from)
}

/// Discard a page that the host did not persist. This is intentionally
/// idempotent for unknown and expired tokens.
pub async fn discard(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request: Value = serde_json::from_slice(&payload)?;
    let token =
        str_field(&request, "replay_token").or_else(|_| str_field(&request, "replayToken"))?;
    validate_token(&token)?;

    let mut registry = state.history_replay_stages.lock().await;
    let memory_discarded = match registry.discard(&token) {
        Ok(()) => true,
        Err(StageError::UnknownOrExpired) => false,
        Err(error) => return Err(map_stage_error(error)),
    };
    let durable_discarded = history_stage::discard_persisted_stage(&state.db, &token)
        .await
        .map_err(map_stage_error)?;
    let discarded = memory_discarded || durable_discarded;
    serde_json::to_vec(&json!({ "discarded": discarded })).map_err(Error::from)
}

async fn replay_page(
    state: &Arc<ActorState>,
    conversation_id: &str,
    rows: Vec<HistoryEnvelope>,
    known_ids: HashSet<String>,
    known_message_ids: HashSet<String>,
    limit: usize,
) -> Result<Vec<u8>> {
    let auth = db_auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;
    let account_id = auth
        .account_id
        .as_deref()
        .filter(|id| !id.is_empty())
        .ok_or(Error::NotAuthenticated)?;
    let local_device_number = auth.device_number.unwrap_or(1);
    let cursor = rows
        .last()
        .map(|row| json!({ "before": row.server_timestamp, "beforeId": row.envelope_id }))
        .unwrap_or(Value::Null);
    let has_older = rows.len() >= limit;
    let ordered_rows = sort_history_envelopes(rows, &HashSet::new());

    let base = history_stage::load_snapshot(&state.db)
        .await
        .map_err(map_stage_error)?;
    if base.auth_context.as_ref().is_some_and(|context| {
        context.account_id.as_deref() != Some(account_id)
            || context.device_number.unwrap_or(1) != local_device_number
    }) {
        return Err(Error::NotAuthenticated);
    }

    let (staging_db, staging_state) =
        history_stage::clone_crypto_database(&state.config, &state.http, &auth, &base)
            .await
            .map_err(map_stage_error)?;

    let replay = replay_ordered_rows(
        &staging_state,
        account_id,
        local_device_number,
        conversation_id,
        ordered_rows,
        &known_ids,
        &known_message_ids,
    )
    .await;
    let (mut result, seen_ids) = match replay {
        Ok(result) => result,
        Err(error) => {
            drop(staging_state);
            staging_db.close().await;
            return Err(error);
        }
    };
    let staged = match history_stage::load_snapshot(&staging_db).await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            drop(staging_state);
            staging_db.close().await;
            return Err(map_stage_error(error));
        }
    };
    result.identity_changes = identity_changes_json(&staged, &base);
    drop(staging_state);
    staging_db.close().await;

    // `seen_ids` contains IDs that were either processed or skipped from the
    // host's known set. Keep the host-facing lists in server page order.
    result.skipped_envelope_ids = seen_ids
        .into_iter()
        .filter(|id| known_ids.contains(id))
        .collect();

    let mut registry = state.history_replay_stages.lock().await;
    let replay_token = registry
        .insert(base.clone(), staged.clone())
        .map_err(map_stage_error)?;
    if let Err(error) =
        history_stage::persist_pending_stage(&state.db, &replay_token, &base, &staged).await
    {
        let _ = registry.discard(&replay_token);
        return Err(map_stage_error(error));
    }
    drop(registry);

    let stage_registry = state.history_replay_stages.clone();
    tokio::spawn(async move {
        tokio::time::sleep(history_stage::HISTORY_REPLAY_STAGE_TTL).await;
        stage_registry.lock().await.purge_expired_now();
    });

    let rollback = rollback_ids(&result);
    let response = json!({
        "messages": result.messages,
        "available": result.available,
        "attachmentKeys": result.attachment_keys,
        "identityChanges": result.identity_changes,
        "processedEnvelopeIds": result.processed_envelope_ids,
        "skippedEnvelopeIds": result.skipped_envelope_ids,
        "existingMessageIds": result.existing_message_ids,
        "rollback": rollback,
        "existing": result.existing,
        "unavailable": result.unavailable,
        "ignored": result.ignored,
        "replayToken": replay_token,
        "expiresInSeconds": history_stage::HISTORY_REPLAY_STAGE_TTL.as_secs(),
        "cursor": cursor,
        "hasOlder": has_older,
    });
    match serde_json::to_vec(&response) {
        Ok(bytes) => Ok(bytes),
        Err(error) => {
            let _ = state
                .history_replay_stages
                .lock()
                .await
                .discard(&replay_token);
            let _ = history_stage::discard_persisted_stage(&state.db, &replay_token).await;
            Err(Error::from(error))
        }
    }
}

async fn replay_ordered_rows(
    state: &ActorState,
    account_id: &str,
    local_device_number: i64,
    conversation_id: &str,
    rows: Vec<HistoryEnvelope>,
    known_ids: &HashSet<String>,
    known_message_ids: &HashSet<String>,
) -> Result<(ReplayResult, Vec<String>)> {
    let mut result = ReplayResult::default();
    let mut seen = HashSet::new();
    let mut message_by_envelope: HashMap<String, Value> = HashMap::new();
    let mut message_by_logical_id = HashMap::new();
    let mut seen_ids = Vec::new();

    for row in rows {
        if row
            .conversation_id
            .as_deref()
            .is_some_and(|id| id != conversation_id)
            || row.recipient_device_number != local_device_number
        {
            result.unavailable += 1;
            continue;
        }
        validate_uuid(&row.envelope_id, "envelope_id")?;
        if !seen.insert(row.envelope_id.clone()) {
            if !known_ids.contains(&row.envelope_id)
                && let Some(message) = message_by_envelope.get(&row.envelope_id)
            {
                result.existing += 1;
                result.available.push(message.clone());
            }
            continue;
        }
        seen_ids.push(row.envelope_id.clone());
        if known_ids.contains(&row.envelope_id) {
            continue;
        }
        if !allowed_history_envelope_type(row.envelope_type) {
            result.ignored += 1;
            continue;
        }

        match process_history_envelope(state, account_id, conversation_id, &row).await? {
            ProcessedEnvelope::Message(record) => {
                record_message_result(
                    &mut result,
                    &row.envelope_id,
                    record,
                    known_message_ids,
                    &mut message_by_envelope,
                    &mut message_by_logical_id,
                )?;
            }
            ProcessedEnvelope::AttachmentKey(key) => {
                result.attachment_keys.push(key);
                result.processed_envelope_ids.push(row.envelope_id);
            }
            ProcessedEnvelope::SenderKey => {
                result.processed_envelope_ids.push(row.envelope_id);
            }
            ProcessedEnvelope::Ignored => {
                result.ignored += 1;
                result.processed_envelope_ids.push(row.envelope_id);
            }
        }
    }
    Ok((result, seen_ids))
}

fn record_message_result(
    result: &mut ReplayResult,
    envelope_id: &str,
    record: Value,
    known_message_ids: &HashSet<String>,
    message_by_envelope: &mut HashMap<String, Value>,
    message_by_logical_id: &mut HashMap<String, Value>,
) -> Result<()> {
    let logical_id = record
        .get("messageId")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::InvalidPayload("decrypted message has no logical ID".into()))?;
    if let Some(existing) = message_by_logical_id.get(logical_id) {
        message_by_envelope.insert(envelope_id.to_owned(), existing.clone());
        result.existing += 1;
        result.available.push(existing.clone());
    } else if known_message_ids.contains(logical_id) {
        result.existing += 1;
        if !result
            .existing_message_ids
            .iter()
            .any(|id| id == logical_id)
        {
            result.existing_message_ids.push(logical_id.to_owned());
        }
    } else {
        message_by_envelope.insert(envelope_id.to_owned(), record.clone());
        message_by_logical_id.insert(logical_id.to_owned(), record.clone());
        result.available.push(record.clone());
        result.messages.push(record);
    }
    result.processed_envelope_ids.push(envelope_id.to_owned());
    Ok(())
}

async fn process_history_envelope(
    state: &ActorState,
    account_id: &str,
    conversation_id: &str,
    row: &HistoryEnvelope,
) -> Result<ProcessedEnvelope> {
    validate_uuid(&row.sender_account_id, "sender_account_id")?;
    u32::try_from(row.sender_device_number)
        .map_err(|_| Error::InvalidPayload("sender_device_number is out of range".into()))?;
    let envelope = json!({
        "sender_account_id": row.sender_account_id,
        "sender_device_number": row.sender_device_number,
        "is_prekey_message": row.is_prekey_message,
        "ciphertext": row.ciphertext,
    });
    let plaintext = match row.envelope_type {
        1 => {
            let bytes = hex::decode(&row.ciphertext)
                .map_err(|error| Error::InvalidPayload(format!("ciphertext hex: {error}")))?;
            if groups::looks_like_sender_key_message(&bytes) {
                groups::decrypt_from_group(
                    state,
                    &row.sender_account_id,
                    row.sender_device_number,
                    &bytes,
                )
                .await
                .map_err(Error::from)?
            } else {
                decrypt_envelope(state, &envelope)
                    .await
                    .map_err(Error::from)?
            }
        }
        2 | 3 | 9 => decrypt_envelope(state, &envelope)
            .await
            .map_err(Error::from)?,
        _ => return Ok(ProcessedEnvelope::Ignored),
    };

    if row.envelope_type == 3 {
        let distribution_text = std::str::from_utf8(&plaintext).map_err(|error| {
            Error::InvalidPayload(format!("sender-key distribution UTF-8: {error}"))
        })?;
        let distribution = hex::decode(distribution_text).map_err(|error| {
            Error::InvalidPayload(format!("sender-key distribution hex: {error}"))
        })?;
        if distribution.is_empty() {
            return Err(Error::InvalidPayload(
                "sender-key distribution is empty".into(),
            ));
        }
        groups::process_distribution(
            state,
            &row.sender_account_id,
            row.sender_device_number,
            &distribution,
        )
        .await
        .map_err(Error::from)?;
        return Ok(ProcessedEnvelope::SenderKey);
    }

    let metadata = ReceiveMetadata {
        envelope_id: &row.envelope_id,
        client_timestamp: row.client_timestamp,
        local_account_id: Some(account_id),
        sender_account_id: Some(&row.sender_account_id),
        sender_device_number: Some(row.sender_device_number),
        recipient_account_id: Some(account_id),
        recipient_device_number: Some(row.recipient_device_number),
        conversation_id: Some(conversation_id),
    };
    let Some(parsed) = parse_decrypted_payload(row.envelope_type, metadata, &plaintext) else {
        return Ok(ProcessedEnvelope::Ignored);
    };
    match parsed.kind {
        "message_received" | "poll_received" => {
            Ok(ProcessedEnvelope::Message(build_message_record(
                account_id,
                conversation_id,
                row,
                &parsed.payload,
                now_unix(),
            )?))
        }
        "attachment_key_received" => Ok(ProcessedEnvelope::AttachmentKey(json!({
            "envelopeId": row.envelope_id,
            "attachmentId": parsed.payload["attachment_id"],
            "keyHex": parsed.payload["key_hex"],
            "baseNonceHex": parsed.payload["base_nonce_hex"],
            "conversationId": parsed.payload["conversation_id"],
        }))),
        _ => Ok(ProcessedEnvelope::Ignored),
    }
}

fn build_message_record(
    account_id: &str,
    conversation_id: &str,
    envelope: &HistoryEnvelope,
    payload: &Value,
    decrypted_at: i64,
) -> Result<Value> {
    let kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let message_id = match kind {
        "poll" => payload.get("poll_id").and_then(Value::as_str),
        "message" => payload.get("message_id").and_then(Value::as_str),
        _ => None,
    }
    .ok_or_else(|| Error::InvalidPayload("decrypted message has no logical ID".into()))?;
    let plaintext = if kind == "poll" {
        payload.get("title").and_then(Value::as_str)
    } else {
        payload.get("text").and_then(Value::as_str)
    }
    .ok_or_else(|| Error::InvalidPayload("decrypted message has no text".into()))?;
    let attachments = if kind == "poll" {
        json!([])
    } else {
        payload
            .get("attachment_ids")
            .cloned()
            .filter(Value::is_array)
            .unwrap_or_else(|| json!([]))
    };
    let reply_to = if kind == "poll" {
        Value::Null
    } else {
        map_reply(payload.get("reply_to"))
    };
    let forward_from = if kind == "poll" {
        Value::Null
    } else {
        map_forward(payload.get("forward_from"))
    };
    let mut record = json!({
        "messageId": message_id,
        "envelopeId": envelope.envelope_id,
        "accountId": account_id,
        "conversationId": conversation_id,
        "senderAccountId": envelope.sender_account_id,
        "senderDeviceNumber": envelope.sender_device_number,
        "recipientAccountId": account_id,
        "recipientDeviceNumber": envelope.recipient_device_number,
        "envelopeType": envelope.envelope_type,
        "plaintext": plaintext,
        "decryptedAt": decrypted_at,
        "clientTimestamp": normalize_unix_timestamp(envelope.client_timestamp, envelope.server_timestamp),
        "serverTimestamp": envelope.server_timestamp,
        "attachments": attachments,
        "replyTo": reply_to,
        "forwardFrom": forward_from,
        "editedAt": null,
        "isPinned": false,
        "reactions": [],
        "status": "sent",
    });
    if kind == "poll" {
        record["pollData"] = json!({
            "pollId": payload["poll_id"],
            "title": payload["title"],
            "description": payload["description"],
            "options": payload["options"],
        });
    }
    Ok(record)
}

/// Exact host-owned row keys to remove if the subsequent crypto commit
/// reports a CAS conflict. Pre-existing `skippedEnvelopeIds` are excluded.
fn rollback_ids(result: &ReplayResult) -> Value {
    let message_ids = result
        .messages
        .iter()
        .filter_map(|message| message.get("messageId").and_then(Value::as_str))
        .collect::<Vec<_>>();
    let attachment_ids = result
        .attachment_keys
        .iter()
        .filter_map(|key| key.get("attachmentId").and_then(Value::as_str))
        .collect::<Vec<_>>();
    let progress_envelope_ids = result
        .processed_envelope_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    json!({
        "messageIds": message_ids,
        "attachmentIds": attachment_ids,
        "progressEnvelopeIds": progress_envelope_ids,
    })
}

fn map_reply(reply: Option<&Value>) -> Value {
    let Some(reply) = reply.filter(|value| value.is_object()) else {
        return Value::Null;
    };
    json!({
        "messageId": reply.get("message_id").and_then(Value::as_str),
        "preview": reply.get("preview").cloned().unwrap_or(Value::Null),
        "senderAccountId": reply.get("sender_account_id").cloned().unwrap_or(Value::Null),
    })
}

fn map_forward(forward: Option<&Value>) -> Value {
    let Some(forward) = forward.filter(|value| value.is_object()) else {
        return Value::Null;
    };
    json!({
        "originalMessageId": forward.get("original_message_id").and_then(Value::as_str),
        "originalConversationId": forward.get("original_conversation_id").and_then(Value::as_str),
        "originalSenderAccountId": forward.get("original_sender_account_id").and_then(Value::as_str),
        "originalSenderDisplay": forward.get("original_sender_display").cloned().unwrap_or(Value::Null),
        "originalCreatedAt": forward.get("original_created_at").and_then(Value::as_i64).unwrap_or_default(),
    })
}

fn normalize_unix_timestamp(value: i64, fallback: i64) -> i64 {
    const MAX_SAFE_DATE_SECONDS: u64 = 8_640_000_000_000;
    if value.unsigned_abs() <= MAX_SAFE_DATE_SECONDS {
        value
    } else if fallback.unsigned_abs() <= MAX_SAFE_DATE_SECONDS {
        fallback
    } else {
        now_unix()
    }
}

fn identity_changes_json(staged: &CryptoSnapshot, base: &CryptoSnapshot) -> Vec<Value> {
    let existing_ids = base
        .identity_changes
        .iter()
        .map(|change| change.id)
        .collect::<HashSet<_>>();
    staged
        .identity_changes
        .iter()
        .filter(|change| !existing_ids.contains(&change.id))
        .map(|change| {
            json!({
                "id": change.id,
                "accountId": change.account_id,
                "deviceNumber": change.device_number,
                "oldKey": hex::encode(&change.old_key),
                "newKey": hex::encode(&change.new_key),
                "changedAt": change.changed_at,
                "notified": change.notified != 0,
            })
        })
        .collect()
}

fn parse_replay_request(payload: &[u8]) -> Result<ReplayRequest> {
    let request: Value = serde_json::from_slice(payload)?;
    if !request.is_object() {
        return Err(Error::InvalidPayload(
            "history replay request must be an object".into(),
        ));
    }
    serde_json::from_value(request).map_err(Error::from)
}

/// Normalize the public camelCase payload accepted by WEB's typed client to
/// the snake_case payload expected by the existing REST handlers. Keep cursor
/// and filter values intact, and reject conflicting duplicate spellings.
fn normalize_history_rest_payload(
    payload: &[u8],
    conversation_id: Option<&str>,
    default_limit: i64,
) -> Result<(Vec<u8>, usize)> {
    let mut request: Value = serde_json::from_slice(payload)?;
    let Some(object) = request.as_object_mut() else {
        return Err(Error::InvalidPayload(
            "history replay request must be an object".into(),
        ));
    };
    normalize_alias(object, "conversation_id", "conversationId")?;
    normalize_alias(object, "before_id", "beforeId")?;
    normalize_alias(object, "envelope_type", "envelopeType")?;
    let limit = match object.get("limit") {
        None | Some(Value::Null) => default_limit,
        Some(Value::Number(value)) => value
            .as_i64()
            .ok_or_else(|| Error::InvalidPayload("history limit must be an integer".into()))?,
        Some(_) => {
            return Err(Error::InvalidPayload(
                "history limit must be an integer".into(),
            ));
        }
    };
    if !(1..=500).contains(&limit) {
        return Err(Error::InvalidPayload(
            "history limit must be an integer from 1 to 500".into(),
        ));
    }
    object.insert("limit".into(), json!(limit));

    let before = match object.get("before") {
        None | Some(Value::Null) => None,
        Some(Value::Number(value)) => Some(value.as_i64().ok_or_else(|| {
            Error::InvalidPayload("history before must be a non-negative safe integer".into())
        })?),
        Some(_) => {
            return Err(Error::InvalidPayload(
                "history before must be a non-negative safe integer".into(),
            ));
        }
    };
    if before.is_some_and(|value| !(0..=MAX_SAFE_INTEGER).contains(&value)) {
        return Err(Error::InvalidPayload(
            "history before must be a non-negative safe integer".into(),
        ));
    }
    let before_id = match object.get("before_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => {
            validate_uuid(value, "before_id")?;
            Some(value.as_str())
        }
        Some(_) => {
            return Err(Error::InvalidPayload("before_id must be a UUID".into()));
        }
    };
    if before.is_none() && before_id.is_some() {
        return Err(Error::InvalidPayload(
            "history beforeId requires before".into(),
        ));
    }
    if let Some(conversation_id) = conversation_id {
        match object.get("conversation_id") {
            Some(value) if value.as_str() != Some(conversation_id) => {
                return Err(Error::InvalidPayload(
                    "conversation_id does not match the replay target".into(),
                ));
            }
            Some(_) => {}
            None => {
                object.insert("conversation_id".into(), json!(conversation_id));
            }
        }
    }
    serde_json::to_vec(&request)
        .map(|payload| (payload, limit as usize))
        .map_err(Error::from)
}

fn validate_uuid(value: &str, field: &str) -> Result<()> {
    if uuid::Uuid::parse_str(value).is_err() {
        return Err(Error::InvalidPayload(format!("{field} must be a UUID")));
    }
    Ok(())
}

fn normalize_alias(
    object: &mut serde_json::Map<String, Value>,
    canonical: &str,
    alias: &str,
) -> Result<()> {
    let Some(alias_value) = object.remove(alias) else {
        return Ok(());
    };
    if let Some(canonical_value) = object.get(canonical) {
        if canonical_value != &alias_value {
            return Err(Error::InvalidPayload(format!(
                "conflicting `{canonical}` and `{alias}` values"
            )));
        }
    } else {
        object.insert(canonical.to_owned(), alias_value);
    }
    Ok(())
}

fn validate_known_envelope_id_values(ids: Option<Vec<String>>) -> Result<HashSet<String>> {
    let ids = ids.unwrap_or_default();
    if ids.len() > MAX_KNOWN_ENVELOPE_IDS {
        return Err(Error::InvalidPayload(format!(
            "known_envelope_ids cannot exceed {MAX_KNOWN_ENVELOPE_IDS} entries"
        )));
    }
    let mut unique = HashSet::with_capacity(ids.len());
    for id in ids {
        validate_uuid(&id, "known_envelope_ids")?;
        if !unique.insert(id) {
            return Err(Error::InvalidPayload(
                "known_envelope_ids must not contain duplicates".into(),
            ));
        }
    }
    Ok(unique)
}

fn validate_known_message_ids(ids: Option<Vec<String>>) -> Result<HashSet<String>> {
    let ids = ids.unwrap_or_default();
    if ids.len() > MAX_KNOWN_MESSAGE_IDS {
        return Err(Error::InvalidPayload(format!(
            "known_message_ids cannot exceed {MAX_KNOWN_MESSAGE_IDS} entries"
        )));
    }
    let mut unique = HashSet::with_capacity(ids.len());
    for id in ids {
        validate_identifier(&id, "known_message_ids")?;
        if !unique.insert(id) {
            return Err(Error::InvalidPayload(
                "known_message_ids must not contain duplicates".into(),
            ));
        }
    }
    Ok(unique)
}

fn sort_history_envelopes(
    mut rows: Vec<HistoryEnvelope>,
    known_ids: &HashSet<String>,
) -> Vec<HistoryEnvelope> {
    rows.sort_by(|left, right| {
        left.server_timestamp
            .cmp(&right.server_timestamp)
            .then_with(|| left.envelope_id.cmp(&right.envelope_id))
    });
    rows.retain(|row| !known_ids.contains(&row.envelope_id));
    rows
}

fn allowed_history_envelope_type(envelope_type: i64) -> bool {
    matches!(envelope_type, 1 | 2 | 3 | 9)
}

fn validate_identifier(value: &str, field: &str) -> Result<()> {
    let length = value.chars().count();
    if length == 0 || length > MAX_ENVELOPE_ID_CHARS || value.chars().any(char::is_control) {
        return Err(Error::InvalidPayload(format!(
            "{field} contains an invalid identifier"
        )));
    }
    Ok(())
}

fn validate_token(token: &str) -> Result<()> {
    if token.len() != 36 || uuid::Uuid::parse_str(token).is_err() {
        return Err(Error::InvalidPayload("replay_token is invalid".into()));
    }
    Ok(())
}

fn map_stage_error(error: StageError) -> Error {
    match error {
        StageError::UnknownOrExpired => {
            Error::InvalidPayload("history replay token is invalid or expired".into())
        }
        StageError::Capacity => Error::Internal("too many pending history replay stages".into()),
        StageError::Database(message) => Error::Database(message),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use serde_json::{Value, json};

    use super::{
        HistoryEnvelope, ReplayRequest, ReplayResult, allowed_history_envelope_type,
        build_message_record, normalize_history_rest_payload, record_message_result, rollback_ids,
        sort_history_envelopes, validate_known_envelope_id_values, validate_known_message_ids,
    };
    use crate::crypto::receive::{ReceiveMetadata, parse_decrypted_payload};

    fn row(envelope_id: &str, server_timestamp: i64, envelope_type: i64) -> HistoryEnvelope {
        HistoryEnvelope {
            envelope_id: envelope_id.into(),
            sender_account_id: "sender".into(),
            sender_device_number: 3,
            recipient_device_number: 4,
            envelope_type,
            is_prekey_message: false,
            ciphertext: "00".into(),
            client_timestamp: 123,
            server_timestamp,
            conversation_id: Some("conversation".into()),
        }
    }

    #[test]
    fn replay_order_matches_web_server_timestamp_then_envelope_id() {
        let rows = vec![row("b", 20, 1), row("z", 10, 1), row("a", 10, 1)];
        let ordered = sort_history_envelopes(rows, &HashSet::new());
        assert_eq!(
            ordered
                .iter()
                .map(|row| row.envelope_id.as_str())
                .collect::<Vec<_>>(),
            vec!["a", "z", "b"]
        );
    }

    #[test]
    fn replay_skips_ids_already_persisted_by_the_web_client() {
        let mut known = HashSet::new();
        known.insert("already-saved".to_owned());
        let ordered =
            sort_history_envelopes(vec![row("new", 1, 1), row("already-saved", 2, 1)], &known);
        assert_eq!(ordered.len(), 1);
        assert_eq!(ordered[0].envelope_id, "new");
    }

    #[test]
    fn known_ids_must_be_unique_uuid_values_and_bounded() {
        let first = "11111111-1111-4111-8111-111111111111";
        let outside_page = "22222222-2222-4222-8222-222222222222";
        let known =
            validate_known_envelope_id_values(Some(vec![first.into(), outside_page.into()]))
                .unwrap();
        assert_eq!(known.len(), 2);
        assert!(validate_known_envelope_id_values(Some(vec![first.into(), first.into()])).is_err());
        assert!(validate_known_envelope_id_values(Some(vec!["not-a-uuid".into()])).is_err());
        assert!(
            validate_known_envelope_id_values(Some(
                (0..=super::MAX_KNOWN_ENVELOPE_IDS)
                    .map(|index| format!("{index:08x}-1111-4111-8111-111111111111"))
                    .collect(),
            ))
            .is_err()
        );
    }

    #[test]
    fn only_web_history_envelope_types_are_decrypted() {
        for envelope_type in [1, 2, 3, 9] {
            assert!(allowed_history_envelope_type(envelope_type));
        }
        for envelope_type in [0, 4, 5, 6, 10, 14, i64::MAX] {
            assert!(!allowed_history_envelope_type(envelope_type));
        }
    }

    #[test]
    fn normalizes_web_camel_case_rest_payload_and_preserves_cursor() {
        let payload = json!({
            "conversationId": "11111111-1111-4111-8111-111111111111",
            "before": 100,
            "beforeId": "22222222-2222-4222-8222-222222222222",
            "limit": 200,
            "envelopeType": 9,
            "knownEnvelopeIds": ["seen"],
        });

        let (normalized, limit) = normalize_history_rest_payload(
            &serde_json::to_vec(&payload).unwrap(),
            Some("11111111-1111-4111-8111-111111111111"),
            200,
        )
        .unwrap();
        let normalized: Value = serde_json::from_slice(&normalized).unwrap();
        assert_eq!(limit, 200);

        assert_eq!(
            normalized["conversation_id"],
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(normalized["before"], 100);
        assert_eq!(
            normalized["before_id"],
            "22222222-2222-4222-8222-222222222222"
        );
        assert_eq!(normalized["limit"], 200);
        assert_eq!(normalized["envelope_type"], 9);
        assert_eq!(normalized["knownEnvelopeIds"], json!(["seen"]));
        assert!(normalized.get("conversationId").is_none());
        assert!(normalized.get("beforeId").is_none());
        assert!(normalized.get("envelopeType").is_none());
    }

    #[test]
    fn rejects_conflicting_rest_field_spellings() {
        let payload = json!({ "before_id": "one", "beforeId": "two" });
        assert!(
            normalize_history_rest_payload(&serde_json::to_vec(&payload).unwrap(), None, 100)
                .is_err()
        );
    }

    #[test]
    fn saved_history_accepts_timestamp_only_cursor_but_rejects_id_only_cursor() {
        let (normalized, _) = normalize_history_rest_payload(
            &serde_json::to_vec(&json!({ "before": 123 })).unwrap(),
            None,
            100,
        )
        .unwrap();
        let normalized: Value = serde_json::from_slice(&normalized).unwrap();
        assert_eq!(normalized["before"], 123);
        assert!(normalized.get("before_id").is_none());

        let id_only = json!({ "beforeId": "11111111-1111-4111-8111-111111111111" });
        assert!(
            normalize_history_rest_payload(&serde_json::to_vec(&id_only).unwrap(), None, 100,)
                .is_err()
        );
    }

    #[test]
    fn replay_request_accepts_web_id_field_names() {
        let request: ReplayRequest = serde_json::from_value(json!({
            "conversationId": "conversation",
            "knownEnvelopeIds": ["envelope-1"],
            "knownLogicalMessageIds": ["message-1"],
        }))
        .unwrap();
        assert_eq!(request.conversation_id.as_deref(), Some("conversation"));
        assert_eq!(request.known_envelope_ids.unwrap(), vec!["envelope-1"]);
        assert_eq!(request.known_message_ids.unwrap(), vec!["message-1"]);
    }

    #[test]
    fn deserializes_web_camel_case_envelope_rows() {
        let envelope: HistoryEnvelope = serde_json::from_value(json!({
            "envelopeId": "envelope",
            "senderAccountId": "sender",
            "senderDeviceNumber": 3,
            "recipientDeviceNumber": 4,
            "envelopeType": 1,
            "isPrekeyMessage": false,
            "ciphertext": "00",
            "clientTimestamp": 123,
            "serverTimestamp": 456,
            "conversationId": "conversation"
        }))
        .unwrap();
        assert_eq!(envelope.envelope_id, "envelope");
        assert_eq!(envelope.server_timestamp, 456);
        assert_eq!(envelope.conversation_id.as_deref(), Some("conversation"));
    }

    #[test]
    fn conflict_rollback_contract_lists_host_owned_page_keys_only() {
        let result = ReplayResult {
            messages: vec![json!({ "messageId": "message-1" })],
            attachment_keys: vec![json!({ "attachmentId": "attachment-1" })],
            processed_envelope_ids: vec!["message-envelope".into(), "control-envelope".into()],
            skipped_envelope_ids: vec!["already-persisted".into()],
            ..ReplayResult::default()
        };

        let rollback = rollback_ids(&result);

        assert_eq!(rollback["messageIds"], json!(["message-1"]));
        assert_eq!(rollback["attachmentIds"], json!(["attachment-1"]));
        assert_eq!(
            rollback["progressEnvelopeIds"],
            json!(["message-envelope", "control-envelope"])
        );
        assert!(!rollback.to_string().contains("already-persisted"));
    }

    #[test]
    fn known_logical_message_is_not_returned_for_upsert_but_envelope_progresses() {
        let known = validate_known_message_ids(Some(vec!["message-1".into()])).unwrap();
        let mut result = ReplayResult::default();
        let mut by_envelope = std::collections::HashMap::new();
        let mut by_logical = std::collections::HashMap::new();

        record_message_result(
            &mut result,
            "envelope-1",
            json!({ "messageId": "message-1", "plaintext": "old local edit" }),
            &known,
            &mut by_envelope,
            &mut by_logical,
        )
        .unwrap();

        assert!(result.messages.is_empty());
        assert!(result.available.is_empty());
        assert_eq!(result.existing, 1);
        assert_eq!(result.existing_message_ids, vec!["message-1"]);
        assert_eq!(result.processed_envelope_ids, vec!["envelope-1"]);
        assert!(by_envelope.is_empty());
    }

    #[test]
    fn known_logical_message_ids_are_unique_valid_and_bounded() {
        assert_eq!(
            validate_known_message_ids(Some(vec!["m1".into(), "m2".into()])).unwrap(),
            HashSet::from(["m1".to_owned(), "m2".to_owned()])
        );
        assert!(validate_known_message_ids(Some(vec!["m1".into(), "m1".into()])).is_err());
        assert!(validate_known_message_ids(Some(vec!["\n".into()])).is_err());
        assert!(validate_known_message_ids(Some(vec!["x".repeat(129)])).is_err());
        assert!(
            validate_known_message_ids(Some(
                (0..=super::MAX_KNOWN_MESSAGE_IDS)
                    .map(|id| format!("message-{id}"))
                    .collect(),
            ))
            .is_err()
        );
    }

    #[test]
    fn message_record_matches_web_shape_including_poll_fields() {
        let metadata = ReceiveMetadata {
            envelope_id: "envelope",
            client_timestamp: 123,
            local_account_id: Some("local"),
            sender_account_id: Some("sender"),
            sender_device_number: Some(3),
            recipient_account_id: Some("local"),
            recipient_device_number: Some(4),
            conversation_id: Some("conversation"),
        };
        let parsed = parse_decrypted_payload(
            1,
            metadata,
            br#"{"kind":"poll","poll_id":"poll-1","title":"Lunch","description":"","options":[{"id":"a","text":"A"},{"id":"b","text":"B"}]}"#,
        )
        .unwrap();
        let record = build_message_record(
            "local",
            "conversation",
            &row("envelope", 456, 1),
            &parsed.payload,
            789,
        )
        .unwrap();
        assert_eq!(record["messageId"], "poll-1");
        assert_eq!(record["envelopeId"], "envelope");
        assert_eq!(record["accountId"], "local");
        assert_eq!(record["conversationId"], "conversation");
        assert_eq!(record["senderAccountId"], "sender");
        assert_eq!(record["recipientAccountId"], "local");
        assert_eq!(record["plaintext"], "Lunch");
        assert_eq!(record["status"], "sent");
        assert_eq!(record["attachments"], json!([]));
        assert_eq!(record["pollData"]["pollId"], "poll-1");
        assert!(record.get("editedAt").is_some());
        assert!(record.get("reactions").and_then(Value::as_array).is_some());
    }
}
