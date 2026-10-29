//! Account-encrypted native history transfer and replay persistence.
//!
//! Imported message bodies, attachment keys, replay cursors, and unfinished
//! transfer fragments are kept in the account's SQLCipher database. A replay
//! ratchet stage is committed only after its corresponding page is durable.

use std::collections::HashSet;

use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

use crate::api::common::bearer;
use crate::api::conversations::ConversationItem;
use crate::api::devices::DeviceItem;
use crate::crypto::attachments::decode_key_and_base;
use crate::crypto::history_protocol::{HistoryAssembler, HistoryChunk, parse_history_chunk};
use crate::db::auth as db_auth;
use crate::error::{Error, Result};
use crate::runtime::ActorState;
use crate::util::time::now_unix;

const HISTORY_PAGE_SIZE: i64 = 200;
const MAX_LIST_ITEMS: i64 = 5_000;
const MAX_KNOWN_ENVELOPES: usize = 500;
const MAX_KNOWN_MESSAGES: usize = 5_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiveChunkRequest {
    sender_account_id: String,
    sender_device_number: i64,
    recipient_account_id: String,
    recipient_device_number: i64,
    conversation_id: String,
    chunk: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConversationItemsRequest {
    conversation_id: String,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalPageRequest {
    conversation_id: String,
    #[serde(default)]
    older: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryRelayRequest {
    from_device_number: i64,
    conversation_ids: Vec<String>,
}

#[derive(Debug, Clone)]
struct HistoryItemRecord {
    item_kind: String,
    item_id: String,
    item: Value,
}

#[derive(Default)]
struct PersistedPage {
    inserted_attachment_keys: Vec<String>,
    inserted_envelopes: Vec<String>,
}

/// Persist an authenticated own-device history fragment before the caller
/// acknowledges its durable envelope event. Complete items are stored as JSON
/// records in the same SQLCipher database and returned for live UI refresh.
pub async fn receive_chunk(
    state: &std::sync::Arc<ActorState>,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let request: ReceiveChunkRequest = serde_json::from_slice(&payload)?;
    let chunk = parse_history_chunk(&request.chunk)
        .ok_or_else(|| Error::InvalidPayload("invalid history chunk".into()))?;
    let auth = db_auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;
    let account_id = auth.account_id.ok_or(Error::NotAuthenticated)?;
    let local_device = auth.device_number.ok_or(Error::NotAuthenticated)?;
    if request.sender_account_id != account_id
        || request.recipient_account_id != account_id
        || request.recipient_device_number != local_device
        || request.sender_device_number <= 0
        || request.sender_device_number == local_device
        || request.conversation_id != chunk.conversation_id
    {
        return Err(Error::InvalidPayload(
            "history chunk must come from another device on this account".into(),
        ));
    }
    validate_uuid(&request.conversation_id, "conversation_id")?;
    let source_device = u32::try_from(request.sender_device_number)
        .map_err(|_| Error::InvalidPayload("sender_device_number is out of range".into()))?;

    let now = now_unix();
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM native_history_fragments WHERE updated_at < ?1")
        .bind(now.saturating_sub(600))
        .execute(&mut *tx)
        .await?;
    let existing_fragment: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM native_history_fragments WHERE source_device_number = ?1 AND transfer_id = ?2 \
         AND conversation_id = ?3 AND item_kind = ?4 AND item_id = ?5",
    )
    .bind(i64::from(source_device))
    .bind(&chunk.transfer_id)
    .bind(&chunk.conversation_id)
    .bind(item_kind_name(chunk.item_kind))
    .bind(&chunk.item_id)
    .fetch_one(&mut *tx)
    .await?;
    if existing_fragment == 0 {
        let assembly_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM (SELECT 1 FROM native_history_fragments GROUP BY source_device_number, transfer_id, conversation_id, item_kind, item_id)",
        )
        .fetch_one(&mut *tx)
        .await?;
        if assembly_count >= 32 {
            return Err(Error::InvalidPayload(
                "too many incomplete history items".into(),
            ));
        }
    }
    sqlx::query(
        "INSERT INTO native_history_fragments \
         (source_device_number, transfer_id, conversation_id, item_kind, item_id, part_index, part_count, chunk_json, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
         ON CONFLICT(source_device_number, transfer_id, conversation_id, item_kind, item_id, part_index) DO NOTHING",
    )
    .bind(i64::from(source_device))
    .bind(&chunk.transfer_id)
    .bind(&chunk.conversation_id)
    .bind(item_kind_name(chunk.item_kind))
    .bind(&chunk.item_id)
    .bind(i64::try_from(chunk.part_index).map_err(|_| Error::InvalidPayload("part_index out of range".into()))?)
    .bind(i64::try_from(chunk.part_count).map_err(|_| Error::InvalidPayload("part_count out of range".into()))?)
    .bind(serde_json::to_string(&chunk)?)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    let rows = sqlx::query(
        "SELECT chunk_json FROM native_history_fragments \
         WHERE source_device_number = ?1 AND transfer_id = ?2 AND conversation_id = ?3 \
           AND item_kind = ?4 AND item_id = ?5 ORDER BY part_index",
    )
    .bind(i64::from(source_device))
    .bind(&chunk.transfer_id)
    .bind(&chunk.conversation_id)
    .bind(item_kind_name(chunk.item_kind))
    .bind(&chunk.item_id)
    .fetch_all(&mut *tx)
    .await?;
    let mut assembler = HistoryAssembler::default();
    let mut completed = None;
    for row in rows {
        let serialized: String = row.try_get("chunk_json")?;
        let fragment: HistoryChunk = serde_json::from_str(&serialized)?;
        completed = assembler
            .assemble(&account_id, source_device, &fragment)
            .map_err(|error| Error::InvalidPayload(error.to_string()))?;
    }

    let (item, conversation_complete, received_messages) = if let Some(item) = completed {
        validate_history_item(&chunk, &item)?;
        persist_history_item_tx(
            &mut tx,
            &chunk.transfer_id,
            &chunk.conversation_id,
            item_kind_name(chunk.item_kind),
            &chunk.item_id,
            source_device,
            &item,
        )
        .await?;
        if chunk.item_kind == crate::crypto::history_protocol::HistoryItemKind::Attachment {
            store_attachment_key_from_history(&mut tx, &chunk.conversation_id, &item).await?;
        }
        sqlx::query(
            "DELETE FROM native_history_fragments WHERE source_device_number = ?1 AND transfer_id = ?2 \
             AND conversation_id = ?3 AND item_kind = ?4 AND item_id = ?5",
        )
        .bind(i64::from(source_device))
        .bind(&chunk.transfer_id)
        .bind(&chunk.conversation_id)
        .bind(item_kind_name(chunk.item_kind))
        .bind(&chunk.item_id)
        .execute(&mut *tx)
        .await?;

        // The chunks are delivered independently, so the completion marker can
        // arrive before the last message. Re-check it after every assembled
        // item so that either arrival order eventually reports completion.
        let completion_json: Option<String> = sqlx::query_scalar(
            "SELECT item_json FROM native_history_items WHERE transfer_id = ?1 AND conversation_id = ?2 AND item_kind = 'complete' LIMIT 1",
        )
        .bind(&chunk.transfer_id)
        .bind(&chunk.conversation_id)
        .fetch_optional(&mut *tx)
        .await?;
        let expected = completion_json
            .as_deref()
            .map(serde_json::from_str::<Value>)
            .transpose()?
            .and_then(|item| item.get("message_count").and_then(Value::as_u64))
            .and_then(|value| usize::try_from(value).ok());
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM native_history_items WHERE transfer_id = ?1 AND conversation_id = ?2 AND item_kind = 'message'",
        )
        .bind(&chunk.transfer_id)
        .bind(&chunk.conversation_id)
        .fetch_one(&mut *tx)
        .await?;
        let conversation_complete =
            expected.is_some_and(|expected| usize::try_from(count).ok() == Some(expected));
        let received_messages: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM native_history_items WHERE transfer_id = ?1 AND conversation_id = ?2 AND item_kind = 'message'",
        )
        .bind(&chunk.transfer_id)
        .bind(&chunk.conversation_id)
        .fetch_one(&mut *tx)
        .await?;
        (Some(item), conversation_complete, received_messages)
    } else {
        let received_messages = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM native_history_items WHERE transfer_id = ?1 AND conversation_id = ?2 AND item_kind = 'message'",
        )
        .bind(&chunk.transfer_id)
        .bind(&chunk.conversation_id)
        .fetch_one(&mut *tx)
        .await?;
        (None, false, received_messages)
    };
    tx.commit().await?;

    let response = json!({
        "conversationId": chunk.conversation_id,
        "transferId": chunk.transfer_id,
        "itemKind": item_kind_name(chunk.item_kind),
        "itemId": chunk.item_id,
        "item": item,
        "conversationComplete": conversation_complete,
        "receivedMessages": received_messages,
    });
    Ok(serde_json::to_vec(&response)?)
}

/// List imported message and attachment records from the encrypted account
/// store, deduplicated by their logical item IDs.
pub async fn list_native_items(
    state: &std::sync::Arc<ActorState>,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let request: ConversationItemsRequest = serde_json::from_slice(&payload)?;
    validate_uuid(&request.conversation_id, "conversation_id")?;
    let limit = request
        .limit
        .unwrap_or(MAX_LIST_ITEMS)
        .clamp(1, MAX_LIST_ITEMS);
    let rows = sqlx::query(
        "SELECT item_kind, item_id, item_json, transfer_id FROM native_history_items \
         WHERE conversation_id = ?1 AND item_kind = 'message' \
         ORDER BY stored_at DESC LIMIT ?2",
    )
    .bind(&request.conversation_id)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    let mut seen = HashSet::new();
    let mut items = Vec::new();
    for row in rows {
        let item_kind: String = row.try_get("item_kind")?;
        let item_id: String = row.try_get("item_id")?;
        if !seen.insert((item_kind.clone(), item_id.clone())) {
            continue;
        }
        let item_json: String = row.try_get("item_json")?;
        let transfer_id: String = row.try_get("transfer_id")?;
        items.push(json!({
            "conversation_id": request.conversation_id,
            "item_kind": item_kind,
            "item_id": item_id,
            "transfer_id": transfer_id,
            "item": serde_json::from_str::<Value>(&item_json)?,
        }));
    }
    items.reverse();
    Ok(serde_json::to_vec(&items)?)
}

/// Reconstruct the WEB-compatible history response for a relay request from
/// the server history available to this device. Pages and attachment material
/// are written to SQLCipher before each replay token is committed.
pub async fn respond_request(
    state: &std::sync::Arc<ActorState>,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let request: HistoryRelayRequest = serde_json::from_slice(&payload)?;
    let auth = db_auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;
    let current_device = auth.device_number.ok_or(Error::NotAuthenticated)?;
    validate_uuid(auth.account_id.as_deref().unwrap_or_default(), "account_id")?;
    if request.from_device_number <= 0 || request.from_device_number == current_device {
        return Err(Error::InvalidPayload(
            "invalid history target device".into(),
        ));
    }
    if request.conversation_ids.is_empty() || request.conversation_ids.len() > 200 {
        return Err(Error::InvalidPayload(
            "history request must contain 1 to 200 conversations".into(),
        ));
    }
    let token = bearer(state).await?;
    let devices: Vec<DeviceItem> = state.http.get("/api/v1/devices", Some(&token)).await?;
    if !devices
        .iter()
        .any(|device| device.device_number == request.from_device_number)
    {
        return Err(Error::InvalidPayload(
            "history target is not an active account device".into(),
        ));
    }
    let conversations: Vec<ConversationItem> = state
        .http
        .get("/api/v1/conversations", Some(&token))
        .await?;
    let allowed = conversations
        .into_iter()
        .filter(|conversation| conversation.kind != "channel")
        .map(|conversation| conversation.id)
        .collect::<HashSet<_>>();
    let mut conversation_ids = Vec::new();
    let mut seen_conversations = HashSet::new();
    for conversation_id in request.conversation_ids {
        validate_uuid(&conversation_id, "conversation_id")?;
        if !allowed.contains(&conversation_id) {
            return Err(Error::InvalidPayload(
                "history conversation is unavailable".into(),
            ));
        }
        if seen_conversations.insert(conversation_id.clone()) {
            conversation_ids.push(conversation_id);
        }
    }

    let transfer_id = Uuid::now_v7().to_string();
    for conversation_id in &conversation_ids {
        export_conversation(state, &transfer_id, conversation_id, current_device).await?;
    }

    let mut items = Vec::new();
    for conversation_id in &conversation_ids {
        let rows = sqlx::query(
            "SELECT item_kind, item_id, item_json FROM native_history_items \
             WHERE conversation_id = ?1 AND item_kind IN ('message', 'attachment') \
             ORDER BY stored_at DESC",
        )
        .bind(conversation_id)
        .fetch_all(&state.db)
        .await?;
        let mut seen = HashSet::new();
        let mut message_count = 0usize;
        for row in rows {
            let item_kind: String = row.try_get("item_kind")?;
            let item_id: String = row.try_get("item_id")?;
            if !seen.insert((item_kind.clone(), item_id.clone())) {
                continue;
            }
            let item_json: String = row.try_get("item_json")?;
            let mut item: Value = serde_json::from_str(&item_json)?;
            if item_kind == "attachment"
                && item.get("chunk_count").and_then(Value::as_u64) == Some(0)
            {
                item = fill_attachment_metadata(state, &item).await?;
                sqlx::query(
                    "UPDATE native_history_items SET item_json = ?1 WHERE conversation_id = ?2 AND item_kind = 'attachment' AND item_id = ?3",
                )
                .bind(serde_json::to_string(&item)?)
                .bind(conversation_id)
                .bind(&item_id)
                .execute(&state.db)
                .await?;
            }
            if item_kind == "message" {
                message_count = message_count.saturating_add(1);
            }
            items.push(json!({
                "conversation_id": conversation_id,
                "item_kind": item_kind,
                "item_id": item_id,
                "item": item,
            }));
        }
        items.push(json!({
            "conversation_id": conversation_id,
            "item_kind": "complete",
            "item_id": conversation_id,
            "item": {"message_count": message_count},
        }));
    }
    let relay = json!({
        "from_device_number": request.from_device_number,
        "conversation_ids": conversation_ids,
        "transfer_id": transfer_id,
        "items": items,
    });
    crate::api::history_sync::send_history(state, serde_json::to_vec(&relay)?).await
}

/// Import one page of server history using a staged replay. The host-visible
/// page is committed to SQLCipher before the isolated Signal state is committed.
pub async fn load_local_page(
    state: &std::sync::Arc<ActorState>,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let request: LocalPageRequest = serde_json::from_slice(&payload)?;
    validate_uuid(&request.conversation_id, "conversation_id")?;
    let cursor_row = sqlx::query(
        "SELECT before_timestamp, before_id, has_older FROM native_history_cursors WHERE conversation_id = ?1",
    )
    .bind(&request.conversation_id)
    .fetch_optional(&state.db)
    .await?;
    let (before, before_id, has_older) = if let Some(row) = cursor_row {
        (
            row.try_get::<Option<i64>, _>("before_timestamp")?,
            row.try_get::<Option<String>, _>("before_id")?,
            row.try_get::<i64, _>("has_older")? != 0,
        )
    } else {
        (None, None, false)
    };
    if request.older && !has_older {
        return Err(Error::InvalidPayload(
            "there are no older history pages".into(),
        ));
    }
    let known = load_known_ids(&state.db, &request.conversation_id).await?;
    let cursor = if request.older {
        json!({"before":before, "beforeId":before_id})
    } else {
        Value::Null
    };
    let replay_request = json!({
        "conversationId": request.conversation_id,
        "before": cursor.get("before").cloned().unwrap_or(Value::Null),
        "beforeId": cursor.get("beforeId").cloned().unwrap_or(Value::Null),
        "limit": HISTORY_PAGE_SIZE,
        "knownEnvelopeIds": known.0,
        "knownMessageIds": known.1,
    });
    let page_bytes = crate::api::history_replay::begin_conversation_page(
        state,
        serde_json::to_vec(&replay_request)?,
    )
    .await?;
    let page: Value = serde_json::from_slice(&page_bytes)?;
    let replay_token = required_string(&page, "replayToken")?.to_owned();
    let transfer_id = Uuid::now_v7().to_string();
    let source_device = db_auth::load(&state.db)
        .await?
        .and_then(|auth| auth.device_number)
        .ok_or(Error::NotAuthenticated)?;
    let records = match replay_records(state, &page, false).await {
        Ok(records) => records,
        Err(error) => {
            let _ = crate::api::history_replay::discard(
                state,
                serde_json::to_vec(&json!({"replayToken": replay_token}))?,
            )
            .await;
            return Err(error);
        }
    };
    let persisted = match persist_page(
        state,
        &transfer_id,
        &request.conversation_id,
        source_device,
        &records,
        &page,
    )
    .await
    {
        Ok(persisted) => persisted,
        Err(error) => {
            let _ = crate::api::history_replay::discard(
                state,
                serde_json::to_vec(&json!({"replayToken": replay_token}))?,
            )
            .await;
            return Err(error);
        }
    };
    let commit = match crate::api::history_replay::commit(
        state,
        serde_json::to_vec(&json!({"replayToken": replay_token}))?,
    )
    .await
    {
        Ok(commit) => commit,
        Err(error) => {
            rollback_page(
                state,
                &transfer_id,
                &request.conversation_id,
                &records,
                &persisted,
            )
            .await?;
            let _ = crate::api::history_replay::discard(
                state,
                serde_json::to_vec(&json!({"replayToken": replay_token}))?,
            )
            .await;
            return Err(error);
        }
    };
    let commit: Value = serde_json::from_slice(&commit)?;
    if commit.get("conflict").and_then(Value::as_bool) == Some(true) {
        rollback_page(
            state,
            &transfer_id,
            &request.conversation_id,
            &records,
            &persisted,
        )
        .await?;
        let _ = crate::api::history_replay::discard(
            state,
            serde_json::to_vec(&json!({"replayToken": replay_token}))?,
        )
        .await;
        return Err(Error::Internal(
            "history replay state changed during local import".into(),
        ));
    }

    let page_cursor = page.get("cursor").cloned().unwrap_or(Value::Null);
    let new_before = page_cursor.get("before").and_then(Value::as_i64);
    let new_before_id = page_cursor.get("beforeId").and_then(Value::as_str);
    let next_has_older = page
        .get("hasOlder")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    sqlx::query(
        "INSERT INTO native_history_cursors (conversation_id, before_timestamp, before_id, has_older, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(conversation_id) DO UPDATE SET before_timestamp = excluded.before_timestamp, \
         before_id = excluded.before_id, has_older = excluded.has_older, updated_at = excluded.updated_at",
    )
    .bind(&request.conversation_id)
    .bind(new_before)
    .bind(new_before_id)
    .bind(if next_has_older { 1_i64 } else { 0_i64 })
    .bind(now_unix())
    .execute(&state.db)
    .await?;
    let message_count = records
        .iter()
        .filter(|record| record.item_kind == "message")
        .count();
    Ok(serde_json::to_vec(&json!({
        "conversationId": request.conversation_id,
        "messagesImported": message_count,
        "hasOlder": next_has_older,
        "cursor": page_cursor,
    }))?)
}

async fn export_conversation(
    state: &std::sync::Arc<ActorState>,
    transfer_id: &str,
    conversation_id: &str,
    source_device: i64,
) -> Result<()> {
    let mut cursor: Option<(i64, String)> = None;
    let mut reached_end = false;
    for _page_index in 0..10_000 {
        let known = load_known_ids(&state.db, conversation_id).await?;
        let request = json!({
            "conversationId": conversation_id,
            "before": cursor.as_ref().map(|cursor| cursor.0),
            "beforeId": cursor.as_ref().map(|cursor| cursor.1.as_str()),
            "limit": HISTORY_PAGE_SIZE,
            "knownEnvelopeIds": known.0,
            "knownMessageIds": known.1,
        });
        let page_bytes = crate::api::history_replay::begin_conversation_page(
            state,
            serde_json::to_vec(&request)?,
        )
        .await?;
        let page: Value = serde_json::from_slice(&page_bytes)?;
        let replay_token = required_string(&page, "replayToken")?.to_owned();
        let records = match replay_records(state, &page, true).await {
            Ok(records) => records,
            Err(error) => {
                let _ = crate::api::history_replay::discard(
                    state,
                    serde_json::to_vec(&json!({"replayToken": replay_token}))?,
                )
                .await;
                return Err(error);
            }
        };
        let persisted = match persist_page(
            state,
            transfer_id,
            conversation_id,
            source_device,
            &records,
            &page,
        )
        .await
        {
            Ok(persisted) => persisted,
            Err(error) => {
                let _ = crate::api::history_replay::discard(
                    state,
                    serde_json::to_vec(&json!({"replayToken": replay_token}))?,
                )
                .await;
                return Err(error);
            }
        };
        let commit = match crate::api::history_replay::commit(
            state,
            serde_json::to_vec(&json!({"replayToken": replay_token}))?,
        )
        .await
        {
            Ok(commit) => commit,
            Err(error) => {
                rollback_page(state, transfer_id, conversation_id, &records, &persisted).await?;
                let _ = crate::api::history_replay::discard(
                    state,
                    serde_json::to_vec(&json!({"replayToken": replay_token}))?,
                )
                .await;
                return Err(error);
            }
        };
        let commit: Value = serde_json::from_slice(&commit)?;
        if commit.get("conflict").and_then(Value::as_bool) == Some(true) {
            rollback_page(state, transfer_id, conversation_id, &records, &persisted).await?;
            let _ = crate::api::history_replay::discard(
                state,
                serde_json::to_vec(&json!({"replayToken": replay_token}))?,
            )
            .await;
            return Err(Error::Internal(
                "history replay state changed during export".into(),
            ));
        }

        let has_older = page
            .get("hasOlder")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let next = page
            .get("cursor")
            .and_then(Value::as_object)
            .and_then(|cursor| {
                Some((
                    cursor.get("before")?.as_i64()?,
                    cursor.get("beforeId")?.as_str()?.to_owned(),
                ))
            });
        if !has_older || next.is_none() || next == cursor {
            reached_end = true;
            break;
        }
        cursor = next;
    }
    if !reached_end {
        return Err(Error::InvalidPayload(
            "history exceeds the supported page count".into(),
        ));
    }
    Ok(())
}

async fn fill_attachment_metadata(
    state: &std::sync::Arc<ActorState>,
    item: &Value,
) -> Result<Value> {
    let attachment_id = required_string(item, "attachment_id")?;
    let token = bearer(state).await?;
    let path = format!("/api/v1/attachments/{attachment_id}");
    let metadata: crate::api::attachments::DownloadResponse =
        state.http.get(&path, Some(&token)).await?;
    let mut item = item.clone();
    item["total_size"] = json!(
        u64::try_from(metadata.total_size)
            .map_err(|_| Error::InvalidPayload("attachment size is invalid".into()))?
    );
    item["chunk_count"] = json!(metadata.chunk_count);
    Ok(item)
}

async fn replay_records(
    state: &std::sync::Arc<ActorState>,
    page: &Value,
    include_attachment_metadata: bool,
) -> Result<Vec<HistoryItemRecord>> {
    let messages = page
        .get("messages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let attachment_keys = page
        .get("attachmentKeys")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut records = Vec::with_capacity(messages.len() + attachment_keys.len());
    for message in messages {
        let message_id = required_string(&message, "messageId")?.to_owned();
        let text = required_string(&message, "plaintext")?;
        let sender_account_id = required_string(&message, "senderAccountId")?;
        let sender_device_number = required_i64(&message, "senderDeviceNumber")?;
        let server_timestamp = required_i64(&message, "serverTimestamp")?;
        let client_timestamp = message
            .get("clientTimestamp")
            .and_then(Value::as_i64)
            .unwrap_or(server_timestamp);
        let attachment_ids = message
            .get("attachments")
            .cloned()
            .unwrap_or_else(|| json!([]));
        let payload = json!({
            "kind": "message",
            "message_id": message_id,
            "text": text,
            "reply_to": wire_reply(message.get("replyTo")),
            "forward_from": wire_forward(message.get("forwardFrom")),
            "attachment_ids": attachment_ids,
            "created_at": client_timestamp,
        });
        let mut item = json!({
            "message": payload,
            "sender_account_id": sender_account_id,
            "sender_device_number": sender_device_number,
            "server_timestamp": server_timestamp,
            "edited_at": message.get("editedAt").cloned().unwrap_or(Value::Null),
            "reactions": message.get("reactions").cloned().unwrap_or_else(|| json!([])),
        });
        if let Some(poll_data) = message.get("pollData").filter(|value| value.is_object()) {
            item["format_version"] = json!(2);
            item["poll_data"] = json!({
                "poll_id": poll_data.get("pollId"),
                "title": poll_data.get("title"),
                "description": poll_data.get("description"),
                "options": poll_data.get("options"),
            });
        }
        records.push(HistoryItemRecord {
            item_kind: "message".into(),
            item_id: message_id,
            item,
        });
    }
    for attachment in attachment_keys {
        let attachment_id = attachment
            .get("attachmentId")
            .or_else(|| attachment.get("attachment_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| Error::InvalidPayload("history attachment has no id".into()))?
            .to_owned();
        let key_hex = attachment
            .get("keyHex")
            .or_else(|| attachment.get("key_hex"))
            .and_then(Value::as_str)
            .ok_or_else(|| Error::InvalidPayload("history attachment has no key".into()))?
            .to_owned();
        let base_nonce_hex = attachment
            .get("baseNonceHex")
            .or_else(|| attachment.get("base_nonce_hex"))
            .and_then(Value::as_str)
            .ok_or_else(|| Error::InvalidPayload("history attachment has no nonce".into()))?
            .to_owned();
        let (total_size, chunk_count) = if include_attachment_metadata {
            let path = format!("/api/v1/attachments/{attachment_id}");
            let token = bearer(state).await?;
            let metadata: crate::api::attachments::DownloadResponse =
                state.http.get(&path, Some(&token)).await?;
            let total_size = u64::try_from(metadata.total_size)
                .map_err(|_| Error::InvalidPayload("attachment size is invalid".into()))?;
            (total_size, metadata.chunk_count)
        } else {
            (0, 0)
        };
        let item = json!({
            "attachment_id": attachment_id,
            "key_hex": key_hex,
            "base_nonce_hex": base_nonce_hex,
            "file_name": null,
            "content_type": null,
            "total_size": total_size,
            "chunk_count": chunk_count,
            "kind": "attachment",
        });
        records.push(HistoryItemRecord {
            item_kind: "attachment".into(),
            item_id: attachment_id,
            item,
        });
    }
    Ok(records)
}

async fn persist_page(
    state: &std::sync::Arc<ActorState>,
    transfer_id: &str,
    conversation_id: &str,
    source_device: i64,
    records: &[HistoryItemRecord],
    page: &Value,
) -> Result<PersistedPage> {
    let mut tx = state.db.begin().await?;
    let mut journal = PersistedPage::default();
    for record in records {
        persist_history_item_tx(
            &mut tx,
            transfer_id,
            conversation_id,
            &record.item_kind,
            &record.item_id,
            u32::try_from(source_device)
                .map_err(|_| Error::InvalidPayload("device number out of range".into()))?,
            &record.item,
        )
        .await?;
        if record.item_kind == "attachment" {
            let attachment_id = required_string(&record.item, "attachment_id")?;
            let existed: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM attachment_keys WHERE attachment_id = ?1")
                    .bind(attachment_id)
                    .fetch_one(&mut *tx)
                    .await?;
            store_attachment_key_from_history(&mut tx, conversation_id, &record.item).await?;
            if existed == 0 {
                journal
                    .inserted_attachment_keys
                    .push(attachment_id.to_owned());
            }
        }
    }
    let processed = page
        .get("processedEnvelopeIds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for envelope in processed {
        let Some(envelope_id) = envelope.as_str() else {
            continue;
        };
        validate_uuid(envelope_id, "processedEnvelopeIds")?;
        let inserted = sqlx::query("INSERT INTO native_history_processed_envelopes (conversation_id, envelope_id) VALUES (?1, ?2) ON CONFLICT DO NOTHING")
            .bind(conversation_id)
            .bind(envelope_id)
            .execute(&mut *tx)
            .await?;
        if inserted.rows_affected() == 1 {
            journal.inserted_envelopes.push(envelope_id.to_owned());
        }
    }
    tx.commit().await?;
    Ok(journal)
}

async fn rollback_page(
    state: &std::sync::Arc<ActorState>,
    transfer_id: &str,
    conversation_id: &str,
    records: &[HistoryItemRecord],
    journal: &PersistedPage,
) -> Result<()> {
    let mut tx = state.db.begin().await?;
    for record in records {
        sqlx::query("DELETE FROM native_history_items WHERE transfer_id = ?1 AND conversation_id = ?2 AND item_kind = ?3 AND item_id = ?4")
            .bind(transfer_id)
            .bind(conversation_id)
            .bind(&record.item_kind)
            .bind(&record.item_id)
            .execute(&mut *tx)
            .await?;
    }
    for envelope in &journal.inserted_envelopes {
        sqlx::query("DELETE FROM native_history_processed_envelopes WHERE conversation_id = ?1 AND envelope_id = ?2")
            .bind(conversation_id)
            .bind(envelope)
            .execute(&mut *tx)
            .await?;
    }
    for attachment_id in &journal.inserted_attachment_keys {
        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM native_history_items WHERE item_kind = 'attachment' AND item_id = ?1",
        )
        .bind(attachment_id)
        .fetch_one(&mut *tx)
        .await?;
        if remaining == 0 {
            sqlx::query("DELETE FROM attachment_keys WHERE attachment_id = ?1")
                .bind(attachment_id)
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

async fn persist_history_item_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    transfer_id: &str,
    conversation_id: &str,
    item_kind: &str,
    item_id: &str,
    source_device: u32,
    item: &Value,
) -> Result<()> {
    let serialized = serde_json::to_string(item)?;
    sqlx::query(
        "INSERT INTO native_history_items (transfer_id, conversation_id, item_kind, item_id, source_device_number, item_json, stored_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT(transfer_id, conversation_id, item_kind, item_id) DO NOTHING",
    )
    .bind(transfer_id)
    .bind(conversation_id)
    .bind(item_kind)
    .bind(item_id)
    .bind(i64::from(source_device))
    .bind(&serialized)
    .bind(now_unix())
    .execute(&mut **tx)
    .await?;
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT item_json FROM native_history_items WHERE transfer_id = ?1 AND conversation_id = ?2 AND item_kind = ?3 AND item_id = ?4",
    )
    .bind(transfer_id)
    .bind(conversation_id)
    .bind(item_kind)
    .bind(item_id)
    .fetch_optional(&mut **tx)
    .await?;
    if stored.as_deref() != Some(serialized.as_str()) {
        return Err(Error::InvalidPayload(
            "history item conflicts with an existing record".into(),
        ));
    }
    Ok(())
}

async fn store_attachment_key_from_history(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    conversation_id: &str,
    item: &Value,
) -> Result<()> {
    let attachment_id = required_string(item, "attachment_id")?;
    let key_hex = required_string(item, "key_hex")?.to_ascii_lowercase();
    let base_nonce_hex = required_string(item, "base_nonce_hex")?.to_ascii_lowercase();
    validate_uuid(attachment_id, "attachment_id")?;
    decode_key_and_base(&key_hex, &base_nonce_hex)?;
    sqlx::query(
        "INSERT INTO attachment_keys (attachment_id, key_hex, base_nonce_hex, conversation_id) \
         VALUES (?1, ?2, ?3, ?4) ON CONFLICT(attachment_id) DO NOTHING",
    )
    .bind(attachment_id)
    .bind(&key_hex)
    .bind(&base_nonce_hex)
    .bind(conversation_id)
    .execute(&mut **tx)
    .await?;
    let existing: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT key_hex, base_nonce_hex, conversation_id FROM attachment_keys WHERE attachment_id = ?1",
    )
    .bind(attachment_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((existing_key, existing_nonce, existing_conversation)) = existing else {
        return Err(Error::Database(
            "attachment key record disappeared after history import".into(),
        ));
    };
    if existing_key != key_hex
        || existing_nonce != base_nonce_hex
        || existing_conversation
            .as_deref()
            .is_some_and(|existing| existing != conversation_id)
    {
        return Err(Error::InvalidPayload(
            "attachment key conflicts with existing account data".into(),
        ));
    }
    if existing_conversation.is_none() {
        sqlx::query("UPDATE attachment_keys SET conversation_id = ?1 WHERE attachment_id = ?2 AND conversation_id IS NULL")
            .bind(conversation_id)
            .bind(attachment_id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

fn validate_history_item(chunk: &HistoryChunk, item: &Value) -> Result<()> {
    if !item.is_object() {
        return Err(Error::InvalidPayload(
            "history item must be an object".into(),
        ));
    }
    match chunk.item_kind {
        crate::crypto::history_protocol::HistoryItemKind::Complete => {
            let count = item.get("message_count").and_then(Value::as_u64);
            if chunk.item_id != chunk.conversation_id || count.is_none() {
                return Err(Error::InvalidPayload(
                    "invalid history completion marker".into(),
                ));
            }
        }
        crate::crypto::history_protocol::HistoryItemKind::Attachment => {
            if item.get("attachment_id").and_then(Value::as_str) != Some(chunk.item_id.as_str()) {
                return Err(Error::InvalidPayload(
                    "history attachment id does not match its chunk".into(),
                ));
            }
            validate_uuid(&chunk.item_id, "attachment_id")?;
            let key_hex = required_string(item, "key_hex")?;
            let nonce_hex = required_string(item, "base_nonce_hex")?;
            decode_key_and_base(key_hex, nonce_hex)?;
            let size = item.get("total_size").and_then(Value::as_u64);
            let chunks = item.get("chunk_count").and_then(Value::as_u64);
            let kind = item.get("kind").and_then(Value::as_str);
            if size.is_none()
                || chunks.is_none_or(|count| count > 500)
                || !matches!(kind, Some("attachment" | "thumbnail"))
                || !bounded_nullable_string(item.get("file_name"), 4096)
                || !bounded_nullable_string(item.get("content_type"), 256)
            {
                return Err(Error::InvalidPayload(
                    "invalid history attachment metadata".into(),
                ));
            }
        }
        crate::crypto::history_protocol::HistoryItemKind::Message => {
            let message = item
                .get("message")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    Error::InvalidPayload("history message payload is missing".into())
                })?;
            let message_id = message.get("message_id").and_then(Value::as_str);
            let sender = item.get("sender_account_id").and_then(Value::as_str);
            let sender_device = item.get("sender_device_number").and_then(Value::as_u64);
            let created_at = message.get("created_at").and_then(Value::as_u64);
            let server_timestamp = item.get("server_timestamp").and_then(Value::as_u64);
            let text = message.get("text").and_then(Value::as_str);
            let attachments = message.get("attachment_ids").and_then(Value::as_array);
            if message.get("kind").and_then(Value::as_str) != Some("message")
                || message_id != Some(chunk.item_id.as_str())
                || sender.is_none()
                || sender_device.is_none_or(|value| value == 0)
                || created_at.is_none()
                || server_timestamp.is_none()
                || text.is_none()
                || attachments.is_none_or(|items| {
                    items.len() > 500
                        || items.iter().any(|id| {
                            id.as_str()
                                .is_none_or(|id| validate_uuid(id, "attachment_id").is_err())
                        })
                })
                || !validate_uuid(&chunk.item_id, "message_id").is_ok()
                || !sender.is_some_and(|sender| validate_uuid(sender, "sender_account_id").is_ok())
            {
                return Err(Error::InvalidPayload(
                    "invalid history message record".into(),
                ));
            }
        }
    }
    Ok(())
}

fn bounded_nullable_string(value: Option<&Value>, max: usize) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(value)) => value.len() <= max,
        _ => false,
    }
}

fn item_kind_name(kind: crate::crypto::history_protocol::HistoryItemKind) -> &'static str {
    match kind {
        crate::crypto::history_protocol::HistoryItemKind::Message => "message",
        crate::crypto::history_protocol::HistoryItemKind::Attachment => "attachment",
        crate::crypto::history_protocol::HistoryItemKind::Complete => "complete",
    }
}

async fn load_known_ids(
    db: &crate::db::Db,
    conversation_id: &str,
) -> Result<(Vec<String>, Vec<String>)> {
    let envelopes = sqlx::query_scalar::<_, String>(
        "SELECT envelope_id FROM native_history_processed_envelopes WHERE conversation_id = ?1 ORDER BY stored_at DESC LIMIT ?2",
    )
    .bind(conversation_id)
    .bind(i64::try_from(MAX_KNOWN_ENVELOPES).unwrap_or(500))
    .fetch_all(db)
    .await?;
    let rows = sqlx::query_scalar::<_, String>(
        "SELECT item_json FROM native_history_items WHERE conversation_id = ?1 AND item_kind = 'message' ORDER BY stored_at DESC LIMIT ?2",
    )
    .bind(conversation_id)
    .bind(i64::try_from(MAX_KNOWN_MESSAGES).unwrap_or(5_000))
    .fetch_all(db)
    .await?;
    let mut message_ids = Vec::new();
    for row in rows {
        let item: Value = serde_json::from_str(&row)?;
        if let Some(id) = item.pointer("/message/message_id").and_then(Value::as_str) {
            if !message_ids.iter().any(|known| known == id) {
                message_ids.push(id.to_owned());
            }
        }
    }
    Ok((envelopes, message_ids))
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::InvalidPayload(format!("{key} is missing")))
}

fn required_i64(value: &Value, key: &str) -> Result<i64> {
    value
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| Error::InvalidPayload(format!("{key} is missing")))
}

fn validate_uuid(value: &str, field: &str) -> Result<()> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| Error::InvalidPayload(format!("{field} must be a UUID")))
}

fn wire_reply(value: Option<&Value>) -> Value {
    let Some(value) = value.filter(|value| value.is_object()) else {
        return Value::Null;
    };
    json!({
        "message_id": value.get("messageId"),
        "preview": value.get("preview"),
        "sender_account_id": value.get("senderAccountId"),
    })
}

fn wire_forward(value: Option<&Value>) -> Value {
    let Some(value) = value.filter(|value| value.is_object()) else {
        return Value::Null;
    };
    json!({
        "original_message_id": value.get("originalMessageId"),
        "original_conversation_id": value.get("originalConversationId"),
        "original_sender_account_id": value.get("originalSenderAccountId"),
        "original_sender_display": value.get("originalSenderDisplay"),
        "original_created_at": value.get("originalCreatedAt"),
    })
}
