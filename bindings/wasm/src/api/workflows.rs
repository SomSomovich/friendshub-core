//! End-to-end encrypted send workflows for the browser binding.
//!
//! REST lookups, Signal encryption, recipient fan-out, and WebSocket envelope
//! upload happen in Rust. The browser still owns its IndexedDB database, so a
//! caller must pass `persistSignalSnapshot(accountId, snapshotJson)`. The
//! callback is awaited before any envelope is uploaded. Every result also
//! carries the snapshot so a failed persistence callback cannot hide mutated
//! Signal state from the host.

use super::BrowserApi;
use crate::BrowserPushClient;
use friendshub_core::crypto::history_protocol::{
    HistoryChunk, HistoryItemKind, history_chunks, parse_history_chunk,
};
use friendshub_core::crypto::receive::{ReceiveMetadata, SemanticPayload, parse_decrypted_payload};
use friendshub_core::proto::EnvelopeType;
#[cfg(target_arch = "wasm32")]
use js_sys::Date;
use js_sys::{Array, Function, Promise, Reflect};
use rand::RngCore;
use serde_json::{Map, Value, json};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::rc::Rc;
use std::time::{Duration, Instant};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

const MESSAGE: i32 = EnvelopeType::Message as i32;
const SENDER_KEY: i32 = EnvelopeType::SenderKey as i32;
const EDIT: i32 = EnvelopeType::Edit as i32;
const DELETE: i32 = EnvelopeType::Delete as i32;
const REACTION: i32 = EnvelopeType::Reaction as i32;
const ATTACHMENT_KEY: i32 = EnvelopeType::AttachmentKey as i32;
const SYNC: i32 = EnvelopeType::Sync as i32;
const GROUP_CIPHERTEXT_PREFIX: u8 = 0x33;

thread_local! {
    static RECEIVE_TAILS: RefCell<HashMap<String, ReceiveQueueTail>> = RefCell::new(HashMap::new());
    static RECEIVE_TICKET: Cell<u64> = const { Cell::new(0) };
    static HISTORY_REPLAY_STAGES: RefCell<HashMap<String, HistoryReplayStage>> = RefCell::new(HashMap::new());
    static HISTORY_REPLAY_RECEIPTS: RefCell<HashMap<String, (Instant, Value)>> = RefCell::new(HashMap::new());
}

const HISTORY_REPLAY_STAGE_TTL: Duration = Duration::from_secs(15 * 60);
const HISTORY_REPLAY_MAX_PENDING: usize = 32;
const HISTORY_REPLAY_MAX_RECEIPTS: usize = 256;
const HISTORY_REPLAY_MAX_KNOWN_IDS: usize = 500;

#[derive(Clone)]
struct HistoryReplayStage {
    account_id: String,
    local_device_number: u32,
    conversation_id: String,
    base_snapshot: String,
    staged_snapshot: String,
    result: Value,
    expires_at: Instant,
}

struct ReceiveQueueTail {
    ticket: u64,
    gate: Promise,
}

struct ReceiveQueueGuard {
    account_id: String,
    ticket: u64,
    resolver: Function,
}

impl Drop for ReceiveQueueGuard {
    fn drop(&mut self) {
        let _ = self.resolver.call0(&JsValue::UNDEFINED);
        RECEIVE_TAILS.with(|tails| {
            let is_current = tails
                .borrow()
                .get(&self.account_id)
                .is_some_and(|tail| tail.ticket == self.ticket);
            if is_current {
                tails.borrow_mut().remove(&self.account_id);
            }
        });
    }
}

type JsResult<T> = Result<T, JsValue>;

#[wasm_bindgen]
impl BrowserApi {
    /// Answers an own-device history request using the WEB history wire format.
    /// The host supplies item records read from its IndexedDB; Rust validates
    /// them, creates one stable transfer UUID and completion marker per
    /// requested conversation, fragments/encrypts every item, persists the
    /// Signal snapshot, then queues the envelopes. `queued` is not a receipt.
    #[wasm_bindgen(js_name = sendHistoryWorkflow)]
    pub async fn send_history_workflow(
        &self,
        push: &BrowserPushClient,
        account_id: String,
        target_device_number: u32,
        conversation_ids: JsValue,
        item_records: JsValue,
        persist_signal_snapshot: Function,
    ) -> JsResult<JsValue> {
        let _signal_queue = acquire_receive_queue(&account_id).await?;
        let conversation_ids = match js_to_json(conversation_ids).and_then(|value| {
            validate_history_conversation_ids(&value).map_err(|error| js_error(&error))
        }) {
            Ok(value) => value,
            Err(error) => {
                return self
                    .failure_result(&account_id, &persist_signal_snapshot, error)
                    .await;
            }
        };
        let item_records = match js_to_json(item_records) {
            Ok(value) => value,
            Err(error) => {
                return self
                    .failure_result(&account_id, &persist_signal_snapshot, error)
                    .await;
            }
        };

        let prepared = async {
            validate_uuid(&account_id, "account_id")?;
            if target_device_number == 0 {
                return Err(js_error("target_device_number must be positive"));
            }
            self.validate_authenticated_account(&account_id).await?;
            let active_device = self.active_device_number()?;
            if target_device_number == active_device {
                return Err(js_error("history target must be another own device"));
            }
            let own_devices = self.resolve_devices(&account_id).await?;
            if !own_devices
                .iter()
                .any(|device| device.device_number == target_device_number)
            {
                return Err(js_error("history target is not an active own device"));
            }

            for conversation_id in &conversation_ids {
                let detail = self
                    .getConversation(json_to_js(&json!({ "conversationId": conversation_id }))?)
                    .await?;
                let detail = js_to_json(detail)?;
                if detail.get("kind").and_then(Value::as_str) == Some("channel") {
                    return Err(js_error("history is unavailable for channel conversations"));
                }
                let members = string_array_field(&detail, "members")?;
                if !members.iter().any(|member| member == &account_id) {
                    return Err(js_error("history conversation is not accessible"));
                }
            }

            let items = parse_history_send_items(&conversation_ids, &item_records)
                .map_err(|error| js_error(&error))?;
            let transfer_id = uuid_v7();
            let mut envelopes = Vec::new();
            let mut message_count = 0_usize;
            let mut attachment_count = 0_usize;
            let mut items_by_conversation: std::collections::HashMap<String, Vec<HistorySendItem>> =
                std::collections::HashMap::new();
            for item in items {
                items_by_conversation
                    .entry(item.conversation_id.clone())
                    .or_default()
                    .push(item);
            }
            for conversation_id in &conversation_ids {
                let conversation_items = items_by_conversation
                    .remove(conversation_id)
                    .unwrap_or_default();
                message_count += history_message_count(&conversation_items);
                attachment_count += conversation_items
                    .iter()
                    .filter(|item| item.item_kind == HistoryItemKind::Attachment)
                    .count();
                let chunks = history_chunks_for_conversation(
                    &transfer_id,
                    conversation_id,
                    &conversation_items,
                )
                .map_err(|error| js_error(&error))?;
                for chunk in chunks {
                    let options = EnvelopeOptions::new(current_unix_seconds() as f64, None)?;
                    let plaintext =
                        serde_json::to_vec(&chunk).map_err(|error| js_error(&error.to_string()))?;
                    let encrypted = self
                        .encrypt_for_device(
                            account_id.clone(),
                            account_id.clone(),
                            target_device_number,
                            active_device,
                            hex::encode(plaintext),
                        )
                        .await?;
                    let encrypted = js_to_json(encrypted)?;
                    let ciphertext = nonempty_string_field(&encrypted, "ciphertextHex")?;
                    let is_prekey = encrypted
                        .get("isPrekeyMessage")
                        .and_then(Value::as_bool)
                        .ok_or_else(|| js_error("Signal encryption omitted isPrekeyMessage"))?;
                    envelopes.push(pairwise_envelope(
                        &account_id,
                        active_device,
                        &account_id,
                        target_device_number,
                        SYNC,
                        is_prekey,
                        ciphertext,
                        Some(conversation_id),
                        options,
                    ));
                }
            }
            Ok(json!({
                "envelopes": envelopes,
                "transferId": transfer_id,
                "targetDeviceNumber": target_device_number,
                "conversationCount": conversation_ids.len(),
                "messageCount": message_count,
                "attachmentCount": attachment_count,
            }))
        };
        self.persist_and_upload(&account_id, &persist_signal_snapshot, push, prepared)
            .await
    }

    /// Decrypts one delivered WEB envelope, asks the host to commit the typed
    /// event and post-decrypt Signal snapshot atomically, then acknowledges the
    /// original durable envelope ID. `receive_transaction` first receives a
    /// `phase: "lookup"` request; it must return `{ committed: true }` for an
    /// already committed event (allowing ACK-only retry) or
    /// `{ committed: false }` when no committed event exists. After decryption
    /// it receives `phase: "commit"` and must resolve to `{ committed: true }`
    /// only after the IndexedDB transaction has durably written the semantic
    /// event, Signal snapshot, and (for history) the raw fragment keyed by the
    /// supplied storage key. For history, the host must persist raw chunks by
    /// that key, assemble from persisted fragments, and keep fragments until
    /// the assembled message/attachment writes are durable; the in-memory
    /// assembler alone is not sufficient to confirm this commit. A rejected
    /// or unconfirmed commit restores the pre-decrypt Signal snapshot and never
    /// ACKs. ACK failure leaves the committed state intact; the next delivery
    /// is recognized by `lookup`.
    #[wasm_bindgen(js_name = receiveEnvelopeWorkflow)]
    pub async fn receive_envelope_workflow(
        &self,
        push: &BrowserPushClient,
        account_id: String,
        local_device_number: u32,
        delivered_envelope: JsValue,
        receive_transaction: Function,
    ) -> JsResult<JsValue> {
        let delivered_value = match js_to_json(delivered_envelope) {
            Ok(value) => value,
            Err(error) => return receive_failure(None, js_value_message(&error)),
        };
        let envelope =
            match parse_delivered_envelope(&delivered_value, &account_id, local_device_number) {
                Ok(envelope) => envelope,
                Err(error) => return receive_failure(None, error),
            };
        if let Err(error) = validate_uuid(&account_id, "account_id") {
            return receive_failure(Some(&envelope.envelope_id), js_value_message(&error));
        }
        let _receive_queue = match acquire_receive_queue(&account_id).await {
            Ok(guard) => guard,
            Err(error) => {
                return receive_failure(
                    Some(&envelope.envelope_id),
                    format!(
                        "could not enter the per-account receive queue: {}",
                        js_value_message(&error)
                    ),
                );
            }
        };
        if local_device_number == 0 {
            return receive_failure(
                Some(&envelope.envelope_id),
                "local_device_number must be positive".to_owned(),
            );
        }
        if let Err(error) = self.validate_authenticated_account(&account_id).await {
            return receive_failure(Some(&envelope.envelope_id), js_value_message(&error));
        }
        match self.active_device_number() {
            Ok(active_device) if active_device == local_device_number => {}
            Ok(_) => {
                return receive_failure(
                    Some(&envelope.envelope_id),
                    "local_device_number does not match the authenticated session".to_owned(),
                );
            }
            Err(error) => {
                return receive_failure(Some(&envelope.envelope_id), js_value_message(&error));
            }
        }

        let lookup = json!({
            "contractVersion": 1,
            "phase": "lookup",
            "accountId": account_id,
            "localDeviceNumber": local_device_number,
            "eventId": envelope.envelope_id,
        });
        let already_committed =
            match call_receive_transaction(&receive_transaction, &lookup, false).await {
                Ok(committed) => committed,
                Err(error) => {
                    return receive_failure(
                        Some(&envelope.envelope_id),
                        format!("received-event lookup failed: {}", js_value_message(&error)),
                    );
                }
            };
        if already_committed {
            let acked = acknowledge_received_envelope(push, &envelope.envelope_id).await;
            return receive_result(
                acked.is_ok(),
                true,
                acked.is_ok(),
                true,
                &envelope.envelope_id,
                None,
                None,
                None,
                acked.err().map(|error| {
                    format!(
                        "event is committed but ACK failed: {}",
                        js_value_message(&error)
                    )
                }),
            );
        }

        let pre_decrypt_snapshot = match crate::signal::snapshot(&account_id) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return receive_failure(
                    Some(&envelope.envelope_id),
                    format!(
                        "could not snapshot Signal state before decrypt: {}",
                        js_value_message(&error)
                    ),
                );
            }
        };
        let prepared = prepare_received_commit(&account_id, local_device_number, &envelope);
        let (commit_payload, kind, payload, post_decrypt_snapshot) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                return rollback_receive_failure(
                    &account_id,
                    &envelope.envelope_id,
                    &pre_decrypt_snapshot,
                    js_value_message(&error),
                );
            }
        };

        match call_receive_transaction(&receive_transaction, &commit_payload, true).await {
            Ok(true) => {}
            Ok(false) => unreachable!("commit phase rejects an uncommitted result"),
            Err(error) => {
                return rollback_receive_failure(
                    &account_id,
                    &envelope.envelope_id,
                    &pre_decrypt_snapshot,
                    format!("received-event commit failed: {}", js_value_message(&error)),
                );
            }
        }

        let acked = acknowledge_received_envelope(push, &envelope.envelope_id).await;
        receive_result(
            acked.is_ok(),
            true,
            acked.is_ok(),
            false,
            &envelope.envelope_id,
            Some(kind),
            Some(payload),
            Some(post_decrypt_snapshot),
            acked.err().map(|error| {
                format!(
                    "event is committed but ACK failed: {}",
                    js_value_message(&error)
                )
            }),
        )
    }

    /// Fetches and decrypts one conversation HTTP-history page in an isolated
    /// Signal store. `known_envelope_ids` must come from the host database. The
    /// returned replay token is not committed until
    /// `commitHistoryReplayWorkflow` confirms one durable host transaction.
    #[wasm_bindgen(js_name = beginConversationHistoryPageWorkflow)]
    pub async fn begin_conversation_history_page_workflow(
        &self,
        account_id: String,
        conversation_id: String,
        query: JsValue,
        known_envelope_ids: JsValue,
    ) -> JsResult<JsValue> {
        let query = parse_history_page_query(query, 200)?;
        let known_ids = match js_to_json(known_envelope_ids)
            .and_then(|value| validate_known_history_ids(&value).map_err(|error| js_error(&error)))
        {
            Ok(ids) => ids,
            Err(error) => return history_replay_failure(None, js_value_message(&error)),
        };
        if let Err(error) = validate_uuid(&account_id, "account_id")
            .and_then(|_| validate_uuid(&conversation_id, "conversation_id"))
        {
            return history_replay_failure(None, js_value_message(&error));
        }
        if let Err(error) = self.validate_authenticated_account(&account_id).await {
            return history_replay_failure(None, js_value_message(&error));
        }
        let local_device_number = match self.active_device_number() {
            Ok(number) => number,
            Err(error) => return history_replay_failure(None, js_value_message(&error)),
        };
        let request = history_page_request(&conversation_id, &query);
        let rows = match self
            .getConversationEnvelopes(json_to_js(&request)?)
            .await
            .and_then(js_to_json)
        {
            Ok(Value::Array(rows)) => rows,
            Ok(_) => {
                return history_replay_failure(
                    None,
                    "conversation history response must be an array".to_owned(),
                );
            }
            Err(error) => return history_replay_failure(None, js_value_message(&error)),
        };
        let cursor = history_page_cursor(&rows);
        let has_older = rows.len() >= query.limit as usize;
        let _signal_queue = match acquire_receive_queue(&account_id).await {
            Ok(guard) => guard,
            Err(error) => return history_replay_failure(None, js_value_message(&error)),
        };
        match begin_history_replay_stage(
            &account_id,
            local_device_number,
            &conversation_id,
            rows,
            known_ids,
        ) {
            Ok(mut result) => {
                if let Some(object) = result.as_object_mut() {
                    object.insert("cursor".to_owned(), cursor);
                    object.insert("hasOlder".to_owned(), json!(has_older));
                }
                if let Some(token) = result.get("replayToken").and_then(Value::as_str) {
                    update_history_replay_stage_result(token, result.clone());
                }
                json_to_js(&result)
            }
            Err(error) => history_replay_failure(None, error),
        }
    }

    /// Fetches and decrypts the current device's Saved Messages HTTP-history
    /// page. Rust resolves `/saved` and `/saved/messages`; the caller supplies
    /// the same IndexedDB known-ID snapshot used for conversation history.
    #[wasm_bindgen(js_name = beginSavedHistoryPageWorkflow)]
    pub async fn begin_saved_history_page_workflow(
        &self,
        account_id: String,
        query: JsValue,
        known_envelope_ids: JsValue,
    ) -> JsResult<JsValue> {
        let query = parse_history_page_query(query, 100)?;
        let known_ids = match js_to_json(known_envelope_ids)
            .and_then(|value| validate_known_history_ids(&value).map_err(|error| js_error(&error)))
        {
            Ok(ids) => ids,
            Err(error) => return history_replay_failure(None, js_value_message(&error)),
        };
        if let Err(error) = validate_uuid(&account_id, "account_id") {
            return history_replay_failure(None, js_value_message(&error));
        }
        if let Err(error) = self.validate_authenticated_account(&account_id).await {
            return history_replay_failure(None, js_value_message(&error));
        }
        let local_device_number = match self.active_device_number() {
            Ok(number) => number,
            Err(error) => return history_replay_failure(None, js_value_message(&error)),
        };
        let saved = match self.getSavedConversation().await.and_then(js_to_json) {
            Ok(saved) => saved,
            Err(error) => return history_replay_failure(None, js_value_message(&error)),
        };
        let Some(conversation_id) = saved
            .get("conversationId")
            .or_else(|| saved.get("conversation_id"))
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return history_replay_failure(
                None,
                "saved conversation response omitted conversationId".to_owned(),
            );
        };
        if let Err(error) = validate_uuid(&conversation_id, "saved conversation_id") {
            return history_replay_failure(None, js_value_message(&error));
        }
        let rows = match self
            .get_saved_messages(json_to_js(&history_query_json(&query))?)
            .await
            .and_then(js_to_json)
        {
            Ok(Value::Array(rows)) => rows,
            Ok(_) => {
                return history_replay_failure(
                    None,
                    "saved history response must be an array".to_owned(),
                );
            }
            Err(error) => return history_replay_failure(None, js_value_message(&error)),
        };
        let cursor = history_page_cursor(&rows);
        let has_older = rows.len() >= query.limit as usize;
        let rows = rows
            .into_iter()
            .map(|mut row| {
                if let Some(object) = row.as_object_mut() {
                    object.insert("conversationId".to_owned(), json!(conversation_id));
                }
                row
            })
            .collect();
        let _signal_queue = match acquire_receive_queue(&account_id).await {
            Ok(guard) => guard,
            Err(error) => return history_replay_failure(None, js_value_message(&error)),
        };
        match begin_history_replay_stage(
            &account_id,
            local_device_number,
            &conversation_id,
            rows,
            known_ids,
        ) {
            Ok(mut result) => {
                if let Some(object) = result.as_object_mut() {
                    object.insert("cursor".to_owned(), cursor);
                    object.insert("hasOlder".to_owned(), json!(has_older));
                }
                if let Some(token) = result.get("replayToken").and_then(Value::as_str) {
                    update_history_replay_stage_result(token, result.clone());
                }
                json_to_js(&result)
            }
            Err(error) => history_replay_failure(None, error),
        }
    }

    /// Atomically commits one previously staged HTTP-history page through the
    /// host. The callback must compare `baseSignalSnapshot` with its persisted
    /// crypto snapshot and, in the same IndexedDB transaction, write messages,
    /// attachment keys, progress IDs, and `signalSnapshot`. On a CAS conflict
    /// it returns `{ committed: false, conflict: true }` without partial writes.
    /// It must deduplicate messages by `(accountId, conversationId, messageId)`;
    /// if an envelope decodes to an already stored logical message, record that
    /// envelope ID in `history_progress` so its ratchet is not consumed again.
    /// The callback also receives `rollbackEnvelopeIds` so a prior separately
    /// persisted copy of this page can be removed in the same transaction.
    /// If a caller had separately written this page, or active WASM state
    /// changes while the callback awaits, Rust asks the host to atomically roll
    /// back the token's records, attachment keys, progress, and snapshot.
    /// Rollback requests are idempotent; the host must return `rolledBack`.
    #[wasm_bindgen(js_name = commitHistoryReplayWorkflow)]
    pub async fn commit_history_replay_workflow(
        &self,
        account_id: String,
        replay_token: String,
        persist_history_transaction: Function,
    ) -> JsResult<JsValue> {
        if let Err(error) = validate_uuid(&account_id, "account_id") {
            return history_replay_failure(Some(&replay_token), js_value_message(&error));
        }
        if !is_history_uuid(&replay_token) {
            return history_replay_failure(
                Some(&replay_token),
                "invalid history replay token".to_owned(),
            );
        }
        let _signal_queue = match acquire_receive_queue(&account_id).await {
            Ok(guard) => guard,
            Err(error) => {
                return history_replay_failure(Some(&replay_token), js_value_message(&error));
            }
        };
        if let Some(receipt) = history_replay_receipt(&replay_token) {
            return json_to_js(&json!({
                "ok": true,
                "committed": true,
                "alreadyCommitted": true,
                "replayToken": replay_token,
                "receipt": receipt,
            }));
        }
        let Some(stage) = history_replay_stage(&replay_token) else {
            return history_replay_failure(
                Some(&replay_token),
                "history replay stage is unknown or expired".to_owned(),
            );
        };
        if stage.account_id != account_id {
            return history_replay_failure(
                Some(&replay_token),
                "history replay token belongs to another account".to_owned(),
            );
        }
        let current_snapshot = match crate::signal::snapshot(&account_id) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return history_replay_failure(Some(&replay_token), js_value_message(&error));
            }
        };
        if !same_snapshot(&current_snapshot, &stage.base_snapshot) {
            return rollback_committed_history_page(
                &account_id,
                &replay_token,
                &stage,
                &persist_history_transaction,
                "active Signal state changed after this history page was staged".to_owned(),
            )
            .await;
        }

        let request = history_replay_transaction_request(&replay_token, &stage);
        let reply =
            match call_history_replay_transaction(&persist_history_transaction, &request).await {
                Ok(reply) => reply,
                Err(error) => {
                    return history_replay_failure(Some(&replay_token), js_value_message(&error));
                }
            };
        if !reply.committed {
            if !reply.conflict {
                return history_replay_failure(
                    Some(&replay_token),
                    reply.error.unwrap_or_else(|| {
                        "host did not confirm the history transaction".to_owned()
                    }),
                );
            }
            return rollback_committed_history_page(
                &account_id,
                &replay_token,
                &stage,
                &persist_history_transaction,
                reply.error.unwrap_or_else(|| {
                    "host history snapshot changed; the callback did not commit the page".to_owned()
                }),
            )
            .await;
        }

        let after_callback = match crate::signal::snapshot(&account_id) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return rollback_committed_history_page(
                    &account_id,
                    &replay_token,
                    &stage,
                    &persist_history_transaction,
                    format!(
                        "could not verify Signal state after the host commit: {}",
                        js_value_message(&error)
                    ),
                )
                .await;
            }
        };
        if !same_snapshot(&after_callback, &stage.base_snapshot) {
            return rollback_committed_history_page(
                &account_id,
                &replay_token,
                &stage,
                &persist_history_transaction,
                "active Signal state changed while the host committed this history page".to_owned(),
            )
            .await;
        }
        if let Err(error) = crate::signal::restore(&account_id, &stage.staged_snapshot) {
            return rollback_committed_history_page(
                &account_id,
                &replay_token,
                &stage,
                &persist_history_transaction,
                format!(
                    "could not apply the staged Signal snapshot: {}",
                    js_value_message(&error)
                ),
            )
            .await;
        }
        let receipt = json!({
            "conversationId": stage.conversation_id,
            "processedEnvelopeIds": stage.result["processedEnvelopeIds"],
        });
        remember_history_replay_receipt(&replay_token, receipt.clone());
        discard_history_replay_stage(&replay_token);
        json_to_js(&json!({
            "ok": true,
            "committed": true,
            "alreadyCommitted": false,
            "replayToken": replay_token,
            "result": stage.result,
            "receipt": receipt,
        }))
    }

    /// Discards a staged HTTP-history page that the host did not persist.
    #[wasm_bindgen(js_name = discardHistoryReplayWorkflow)]
    pub fn discard_history_replay_workflow(&self, replay_token: String) -> JsResult<JsValue> {
        if !is_history_uuid(&replay_token) {
            return history_replay_failure(
                Some(&replay_token),
                "invalid history replay token".to_owned(),
            );
        }
        let discarded = discard_history_replay_stage(&replay_token);
        json_to_js(&json!({ "discarded": discarded, "replayToken": replay_token }))
    }

    /// Builds, encrypts, fans out, snapshots, and uploads one direct message.
    /// `message_id` and `created_at` are supplied by the caller exactly once so
    /// an offline retry can retain WEB's logical message identity and time.
    /// The result contains `localMessage` for the host's IndexedDB write and
    /// `signalSnapshot` for recovery. `queued` means the WebSocket accepted the
    /// upload into its send queue; it is not a server receipt.
    #[wasm_bindgen(js_name = sendMessageWorkflow)]
    pub async fn send_message_workflow(
        &self,
        push: &BrowserPushClient,
        account_id: String,
        conversation_id: String,
        draft: JsValue,
        message_id: String,
        created_at: f64,
        send_at: Option<f64>,
        persist_signal_snapshot: Function,
    ) -> JsResult<JsValue> {
        let _signal_queue = acquire_receive_queue(&account_id).await?;
        let draft_json = match js_to_json(draft) {
            Ok(value) => value,
            Err(error) => {
                return self
                    .failure_result(&account_id, &persist_signal_snapshot, error)
                    .await;
            }
        };
        let prepared = async {
            validate_send_inputs(
                &account_id,
                &conversation_id,
                &message_id,
                created_at,
                send_at,
            )?;
            self.validate_authenticated_account(&account_id).await?;
            let active_device = self.active_device_number()?;
            let detail = self
                .getConversation(json_to_js(&json!({ "conversationId": conversation_id }))?)
                .await?;
            let detail = js_to_json(detail)?;
            let members = string_array_field(&detail, "members")?;
            if !members.iter().any(|member| member == &account_id) {
                return Err(js_error("the active account is not a conversation member"));
            }
            let peer_id = members
                .iter()
                .find(|member| *member != &account_id)
                .cloned()
                .ok_or_else(|| js_error("direct conversation has no other member"))?;
            if detail.get("kind").and_then(Value::as_str) != Some("direct") {
                return Err(js_error(
                    "sendMessageWorkflow requires a direct conversation",
                ));
            }
            let payload_hex = encode_message_payload(&message_id, &draft_json, created_at)?;
            let options = EnvelopeOptions::new(created_at, send_at)?;
            let peer_devices = self.resolve_devices(&peer_id).await?;
            if peer_devices.is_empty() {
                return Err(js_error("the recipient has no active devices"));
            }
            let (mut envelopes, skipped, first_unreachable) = self
                .pairwise_fanout(
                    &account_id,
                    active_device,
                    &peer_id,
                    &peer_devices,
                    &payload_hex,
                    MESSAGE,
                    Some(&conversation_id),
                    options,
                    false,
                )
                .await?;
            if envelopes.is_empty() {
                return Err(first_unreachable.unwrap_or_else(|| {
                    js_error("the direct message could not reach any recipient device")
                }));
            }
            let own_devices = self
                .resolve_devices(&account_id)
                .await?
                .into_iter()
                .filter(|device| device.device_number != active_device)
                .collect::<Vec<_>>();
            let (own_envelopes, own_skipped, _) = self
                .pairwise_fanout(
                    &account_id,
                    active_device,
                    &account_id,
                    &own_devices,
                    &payload_hex,
                    MESSAGE,
                    Some(&conversation_id),
                    options,
                    false,
                )
                .await?;
            envelopes.extend(own_envelopes);
            let local_message = local_message_value(
                &account_id,
                active_device,
                &conversation_id,
                &message_id,
                &draft_json,
                created_at,
                envelopes.first().and_then(|value| value.get("envelopeId")),
            )?;
            Ok(json!({
                "envelopes": envelopes,
                "localMessage": local_message,
                "skippedRecipientDevices": skipped,
                "skippedOwnDevices": own_skipped,
            }))
        };
        self.persist_and_upload(&account_id, &persist_signal_snapshot, push, prepared)
            .await
    }

    /// Sends one group message. Sender-key distributions are pairwise encrypted
    /// and precede the sender-key-encrypted group message in the upload batch;
    /// this also makes repeated calls safe when the caller's membership list
    /// changes between sends.
    #[wasm_bindgen(js_name = sendGroupMessageWorkflow)]
    pub async fn send_group_message_workflow(
        &self,
        push: &BrowserPushClient,
        account_id: String,
        conversation_id: String,
        draft: JsValue,
        message_id: String,
        created_at: f64,
        send_at: Option<f64>,
        persist_signal_snapshot: Function,
    ) -> JsResult<JsValue> {
        let _signal_queue = acquire_receive_queue(&account_id).await?;
        let draft_json = match js_to_json(draft) {
            Ok(value) => value,
            Err(error) => {
                return self
                    .failure_result(&account_id, &persist_signal_snapshot, error)
                    .await;
            }
        };
        let prepared = async {
            validate_send_inputs(
                &account_id,
                &conversation_id,
                &message_id,
                created_at,
                send_at,
            )?;
            self.validate_authenticated_account(&account_id).await?;
            let active_device = self.active_device_number()?;
            let detail = self
                .getConversation(json_to_js(&json!({ "conversationId": conversation_id }))?)
                .await?;
            let detail = js_to_json(detail)?;
            if !detail
                .get("members")
                .and_then(Value::as_array)
                .is_some_and(|members| {
                    members
                        .iter()
                        .any(|member| member.as_str() == Some(account_id.as_str()))
                })
            {
                return Err(js_error("the active account is not a conversation member"));
            }
            if detail.get("kind").and_then(Value::as_str) == Some("direct") {
                return Err(js_error(
                    "sendGroupMessageWorkflow requires a group conversation",
                ));
            }
            let members = string_array_field(&detail, "members")?;
            let recipients = members
                .into_iter()
                .filter(|member| member != &account_id)
                .collect::<Vec<_>>();
            let payload_hex = encode_message_payload(&message_id, &draft_json, created_at)?;
            let options = EnvelopeOptions::new(created_at, send_at)?;
            let distribution_hex = crate::signal::create_sender_key_distribution(
                &account_id,
                active_device,
                &conversation_id,
            )?;
            let distribution_plaintext = hex::encode(distribution_hex.as_bytes());
            let mut distribution_envelopes = Vec::new();
            let mut skipped = Vec::new();
            let mut first_unreachable = None;
            for member_id in &recipients {
                let devices = self.resolve_devices(member_id).await?;
                let (mut member_envelopes, unreachable, cause) = self
                    .pairwise_fanout(
                        &account_id,
                        active_device,
                        member_id,
                        &devices,
                        &distribution_plaintext,
                        SENDER_KEY,
                        Some(&conversation_id),
                        EnvelopeOptions::default(),
                        true,
                    )
                    .await?;
                skipped.extend(unreachable);
                first_unreachable = first_unreachable.or(cause);
                distribution_envelopes.append(&mut member_envelopes);
            }
            if !recipients.is_empty() && distribution_envelopes.is_empty() {
                return Err(first_unreachable.unwrap_or_else(|| {
                    js_error("sender-key distribution could not reach any group member device")
                }));
            }

            let ciphertext_hex = crate::signal::group_encrypt(
                &account_id,
                active_device,
                &conversation_id,
                &payload_hex,
            )?;
            let mut message_envelopes = Vec::new();
            for member_id in &recipients {
                for device in self.resolve_devices(member_id).await? {
                    message_envelopes.push(group_envelope(
                        &account_id,
                        active_device,
                        member_id,
                        device,
                        &ciphertext_hex,
                        &conversation_id,
                        options,
                    ));
                }
            }
            if message_envelopes.is_empty() {
                return Err(js_error(
                    "group message has no active member devices to deliver to",
                ));
            }

            let own_devices = self
                .resolve_devices(&account_id)
                .await?
                .into_iter()
                .filter(|device| device.device_number != active_device)
                .collect::<Vec<_>>();
            let (own_envelopes, own_skipped, _) = self
                .pairwise_fanout(
                    &account_id,
                    active_device,
                    &account_id,
                    &own_devices,
                    &payload_hex,
                    MESSAGE,
                    Some(&conversation_id),
                    options,
                    false,
                )
                .await?;
            message_envelopes.extend(own_envelopes);
            distribution_envelopes.extend(message_envelopes);
            let first_message_id = distribution_envelopes
                .iter()
                .find(|envelope| {
                    envelope.get("envelopeType").and_then(Value::as_i64) == Some(i64::from(MESSAGE))
                })
                .and_then(|envelope| envelope.get("envelopeId"));
            let local_message = local_message_value(
                &account_id,
                active_device,
                &conversation_id,
                &message_id,
                &draft_json,
                created_at,
                first_message_id,
            )?;
            Ok(json!({
                "envelopes": distribution_envelopes,
                "localMessage": local_message,
                "skippedRecipientDevices": skipped,
                "skippedOwnDevices": own_skipped,
            }))
        };
        self.persist_and_upload(&account_id, &persist_signal_snapshot, push, prepared)
            .await
    }

    /// Sends a Saved Messages copy to this account's other devices. The caller
    /// may pass the saved conversation id already in its model; when omitted,
    /// Rust resolves `/saved`. A single-device account succeeds with no upload.
    #[wasm_bindgen(js_name = sendSavedMessageWorkflow)]
    pub async fn send_saved_message_workflow(
        &self,
        push: &BrowserPushClient,
        account_id: String,
        conversation_id: Option<String>,
        draft: JsValue,
        message_id: String,
        created_at: f64,
        persist_signal_snapshot: Function,
    ) -> JsResult<JsValue> {
        let _signal_queue = acquire_receive_queue(&account_id).await?;
        let draft_json = match js_to_json(draft) {
            Ok(value) => value,
            Err(error) => {
                return self
                    .failure_result(&account_id, &persist_signal_snapshot, error)
                    .await;
            }
        };
        let prepared = async {
            validate_uuid(&account_id, "account_id")?;
            validate_uuid(&message_id, "message_id")?;
            validate_unix_seconds(created_at, "created_at")?;
            self.validate_authenticated_account(&account_id).await?;
            let active_device = self.active_device_number()?;
            let conversation_id = match conversation_id.filter(|value| !value.trim().is_empty()) {
                Some(value) => value,
                None => {
                    let saved = self.getSavedConversation().await?;
                    let saved = js_to_json(saved)?;
                    nonempty_string_field(&saved, "conversationId")?.to_owned()
                }
            };
            validate_uuid(&conversation_id, "conversation_id")?;
            let payload_hex = encode_message_payload(&message_id, &draft_json, created_at)?;
            let options = EnvelopeOptions::new(created_at, None)?;
            let devices = self
                .resolve_devices(&account_id)
                .await?
                .into_iter()
                .filter(|device| device.device_number != active_device)
                .collect::<Vec<_>>();
            let (envelopes, skipped, _) = self
                .pairwise_fanout(
                    &account_id,
                    active_device,
                    &account_id,
                    &devices,
                    &payload_hex,
                    MESSAGE,
                    Some(&conversation_id),
                    options,
                    false,
                )
                .await?;
            let local_message = local_message_value(
                &account_id,
                active_device,
                &conversation_id,
                &message_id,
                &draft_json,
                created_at,
                envelopes.first().and_then(|value| value.get("envelopeId")),
            )?;
            Ok(json!({
                "envelopes": envelopes,
                "localMessage": local_message,
                "skippedOwnDevices": skipped,
                "conversationId": conversation_id,
            }))
        };
        self.persist_and_upload(&account_id, &persist_signal_snapshot, push, prepared)
            .await
    }

    /// Distributes a sender-key message to every current non-self member
    /// device. Calling this directly is useful when a group is created before
    /// its first message; group-message workflow also performs this step.
    #[wasm_bindgen(js_name = distributeGroupSenderKeyWorkflow)]
    pub async fn distribute_group_sender_key_workflow(
        &self,
        push: &BrowserPushClient,
        account_id: String,
        conversation_id: String,
        persist_signal_snapshot: Function,
    ) -> JsResult<JsValue> {
        let _signal_queue = acquire_receive_queue(&account_id).await?;
        let prepared = async {
            validate_uuid(&conversation_id, "conversation_id")?;
            self.validate_authenticated_account(&account_id).await?;
            let active_device = self.active_device_number()?;
            let detail = self
                .getConversation(json_to_js(&json!({ "conversationId": conversation_id }))?)
                .await?;
            let detail = js_to_json(detail)?;
            let members = string_array_field(&detail, "members")?
                .into_iter()
                .filter(|member| member != &account_id)
                .collect::<Vec<_>>();
            let distribution = crate::signal::create_sender_key_distribution(
                &account_id,
                active_device,
                &conversation_id,
            )?;
            let plaintext = hex::encode(distribution.as_bytes());
            let mut envelopes = Vec::new();
            let mut skipped = Vec::new();
            let mut cause = None;
            for member in members {
                let devices = self.resolve_devices(&member).await?;
                let (mut next, unreachable, next_cause) = self
                    .pairwise_fanout(
                        &account_id,
                        active_device,
                        &member,
                        &devices,
                        &plaintext,
                        SENDER_KEY,
                        Some(&conversation_id),
                        EnvelopeOptions::default(),
                        true,
                    )
                    .await?;
                skipped.extend(unreachable);
                cause = cause.or(next_cause);
                envelopes.append(&mut next);
            }
            if envelopes.is_empty() && !skipped.is_empty() {
                return Err(
                    cause.unwrap_or_else(|| js_error("sender key could not reach any device"))
                );
            }
            Ok(json!({ "envelopes": envelopes, "skippedRecipientDevices": skipped }))
        };
        self.persist_and_upload(&account_id, &persist_signal_snapshot, push, prepared)
            .await
    }

    /// Sends an edit, delete, or reaction to all other conversation members and
    /// best-effort syncs this account's other devices. `action` is one of
    /// `{kind:'edit',newText}`, `{kind:'delete'}`, or
    /// `{kind:'reaction',emoji:string|null}`.
    #[wasm_bindgen(js_name = sendMessageActionWorkflow)]
    pub async fn send_message_action_workflow(
        &self,
        push: &BrowserPushClient,
        account_id: String,
        conversation_id: String,
        target_message_id: String,
        action: JsValue,
        timestamp: f64,
        persist_signal_snapshot: Function,
    ) -> JsResult<JsValue> {
        let _signal_queue = acquire_receive_queue(&account_id).await?;
        let action_json = match js_to_json(action) {
            Ok(value) => value,
            Err(error) => {
                return self
                    .failure_result(&account_id, &persist_signal_snapshot, error)
                    .await;
            }
        };
        let prepared = async {
            validate_uuid(&conversation_id, "conversation_id")?;
            validate_uuid(&target_message_id, "target_message_id")?;
            validate_unix_seconds(timestamp, "timestamp")?;
            self.validate_authenticated_account(&account_id).await?;
            let active_device = self.active_device_number()?;
            let (kind, envelope_type, payload) =
                message_action_payload(&target_message_id, &action_json, timestamp)?;
            let payload_hex = hex::encode(
                serde_json::to_vec(&payload).map_err(|error| js_error(&error.to_string()))?,
            );
            let detail = self
                .getConversation(json_to_js(&json!({ "conversationId": conversation_id }))?)
                .await?;
            let detail = js_to_json(detail)?;
            let recipients = string_array_field(&detail, "members")?
                .into_iter()
                .filter(|member| member != &account_id)
                .collect::<Vec<_>>();
            let mut envelopes = Vec::new();
            let mut skipped = Vec::new();
            let mut cause = None;
            for recipient in &recipients {
                let devices = self.resolve_devices(recipient).await?;
                let (mut next, unreachable, next_cause) = self
                    .pairwise_fanout(
                        &account_id,
                        active_device,
                        recipient,
                        &devices,
                        &payload_hex,
                        envelope_type,
                        Some(&conversation_id),
                        EnvelopeOptions::default(),
                        false,
                    )
                    .await?;
                skipped.extend(unreachable);
                cause = cause.or(next_cause);
                envelopes.append(&mut next);
            }
            if envelopes.is_empty() {
                return Err(cause.unwrap_or_else(|| {
                    js_error("message action has no active recipient devices")
                }));
            }
            let own_devices = self
                .resolve_devices(&account_id)
                .await?
                .into_iter()
                .filter(|device| device.device_number != active_device)
                .collect::<Vec<_>>();
            let (mut own_envelopes, own_skipped, _) = self
                .pairwise_fanout(
                    &account_id,
                    active_device,
                    &account_id,
                    &own_devices,
                    &payload_hex,
                    envelope_type,
                    Some(&conversation_id),
                    EnvelopeOptions::default(),
                    false,
                )
                .await?;
            envelopes.append(&mut own_envelopes);
            Ok(json!({
                "envelopes": envelopes,
                "actionKind": kind,
                "targetMessageId": target_message_id,
                "skippedRecipientDevices": skipped,
                "skippedOwnDevices": own_skipped,
            }))
        };
        self.persist_and_upload(&account_id, &persist_signal_snapshot, push, prepared)
            .await
    }

    /// Pairwise-sends an attachment key to all devices of one recipient.
    /// Attachment bytes remain in the browser; only the already-created key
    /// and nonce metadata enter this encrypted envelope.
    #[wasm_bindgen(js_name = sendAttachmentKeyWorkflow)]
    pub async fn send_attachment_key_workflow(
        &self,
        push: &BrowserPushClient,
        account_id: String,
        recipient_account_id: String,
        attachment_id: String,
        key_hex: String,
        base_nonce_hex: String,
        conversation_id: Option<String>,
        persist_signal_snapshot: Function,
    ) -> JsResult<JsValue> {
        let _signal_queue = acquire_receive_queue(&account_id).await?;
        let prepared = async {
            validate_uuid(&account_id, "account_id")?;
            validate_uuid(&recipient_account_id, "recipient_account_id")?;
            self.validate_authenticated_account(&account_id).await?;
            validate_uuid(&attachment_id, "attachment_id")?;
            if key_hex.is_empty() || key_hex.len() % 2 != 0 || hex::decode(&key_hex).is_err() {
                return Err(js_error(
                    "key_hex must be non-empty even-length hexadecimal",
                ));
            }
            if base_nonce_hex.is_empty()
                || base_nonce_hex.len() % 2 != 0
                || hex::decode(&base_nonce_hex).is_err()
            {
                return Err(js_error(
                    "base_nonce_hex must be non-empty even-length hexadecimal",
                ));
            }
            if let Some(conversation_id) = conversation_id.as_deref() {
                validate_uuid(conversation_id, "conversation_id")?;
            }
            let active_device = self.active_device_number()?;
            let payload = json!({
                "kind": "attachment_key",
                "attachment_id": attachment_id,
                "key_hex": key_hex,
                "base_nonce_hex": base_nonce_hex,
                "conversation_id": conversation_id,
            });
            let payload_hex = hex::encode(
                serde_json::to_vec(&payload).map_err(|error| js_error(&error.to_string()))?,
            );
            let devices = self.resolve_devices(&recipient_account_id).await?;
            let (envelopes, skipped, cause) = self
                .pairwise_fanout(
                    &account_id,
                    active_device,
                    &recipient_account_id,
                    &devices,
                    &payload_hex,
                    ATTACHMENT_KEY,
                    conversation_id.as_deref(),
                    EnvelopeOptions::default(),
                    true,
                )
                .await?;
            if envelopes.is_empty() {
                return Err(cause.unwrap_or_else(|| {
                    js_error("attachment key has no reachable recipient devices")
                }));
            }
            Ok(json!({ "envelopes": envelopes, "skippedRecipientDevices": skipped }))
        };
        self.persist_and_upload(&account_id, &persist_signal_snapshot, push, prepared)
            .await
    }
}

impl BrowserApi {
    async fn validate_authenticated_account(&self, account_id: &str) -> JsResult<()> {
        let profile = self.getMe().await?;
        let profile = js_to_json(profile)?;
        let authenticated_id = profile
            .get("id")
            .or_else(|| profile.get("accountId"))
            .and_then(Value::as_str)
            .ok_or_else(|| js_error("authenticated profile omitted account id"))?;
        if authenticated_id != account_id {
            return Err(js_error(
                "account_id does not match the authenticated session",
            ));
        }
        Ok(())
    }

    fn active_device_number(&self) -> JsResult<u32> {
        self.device_number
            .filter(|device_number| *device_number > 0)
            .ok_or_else(|| js_error("an authenticated device number is required"))
    }

    async fn resolve_devices(&self, peer_account_id: &str) -> JsResult<Vec<Device>> {
        let response = self
            .listPeerDevices(json_to_js(&json!({ "peerAccountId": peer_account_id }))?)
            .await?;
        let devices_json = js_to_json(response)?;
        let rows = devices_json
            .as_array()
            .ok_or_else(|| js_error("device list response is not an array"))?;
        let mut devices = Vec::with_capacity(rows.len());
        let mut seen = std::collections::HashSet::new();
        for row in rows {
            let device_number = number_field(row, "deviceNumber", "device_number")?
                .and_then(|value| u32::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| js_error("device list contains an invalid device number"))?;
            if seen.insert(device_number) {
                devices.push(Device { device_number });
            }
        }
        Ok(devices)
    }

    async fn pairwise_fanout(
        &self,
        account_id: &str,
        local_device_number: u32,
        recipient_account_id: &str,
        devices: &[Device],
        plaintext_hex: &str,
        envelope_type: i32,
        conversation_id: Option<&str>,
        options: EnvelopeOptions,
        throwing: bool,
    ) -> JsResult<(Vec<Value>, Vec<u32>, Option<JsValue>)> {
        let mut envelopes = Vec::new();
        let mut skipped = Vec::new();
        let mut first_unreachable = None;
        for device in devices {
            match self
                .encrypt_for_device(
                    account_id.to_owned(),
                    recipient_account_id.to_owned(),
                    device.device_number,
                    local_device_number,
                    plaintext_hex.to_owned(),
                )
                .await
            {
                Ok(result) => {
                    let encrypted = js_to_json(result)?;
                    let ciphertext = nonempty_string_field(&encrypted, "ciphertextHex")?;
                    let prekey = encrypted
                        .get("isPrekeyMessage")
                        .and_then(Value::as_bool)
                        .ok_or_else(|| js_error("Signal encryption omitted isPrekeyMessage"))?;
                    envelopes.push(pairwise_envelope(
                        account_id,
                        local_device_number,
                        recipient_account_id,
                        device.device_number,
                        envelope_type,
                        prekey,
                        ciphertext,
                        conversation_id,
                        options,
                    ));
                }
                Err(error) if is_unreachable_device(&error) && !throwing => {
                    first_unreachable.get_or_insert(error);
                    skipped.push(device.device_number);
                }
                Err(error) => return Err(error),
            }
        }
        Ok((envelopes, skipped, first_unreachable))
    }

    async fn persist_and_upload<Prepare>(
        &self,
        account_id: &str,
        callback: &Function,
        push: &BrowserPushClient,
        prepared: Prepare,
    ) -> JsResult<JsValue>
    where
        Prepare: Future<Output = JsResult<Value>>,
    {
        let base_snapshot = match crate::signal::snapshot(account_id) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return self.failure_result(account_id, callback, error).await;
            }
        };
        let prepared = match rollback_signal_state_after_prepare_error(
            account_id,
            &base_snapshot,
            prepared.await,
        ) {
            Ok(value) => value,
            Err(error) => return self.failure_result(account_id, callback, error).await,
        };
        let snapshot = match crate::signal::snapshot(account_id) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return Ok(result_object(
                    false,
                    false,
                    false,
                    None,
                    Some(js_value_message(&error)),
                    None,
                )?);
            }
        };
        if let Err(error) = persist_snapshot_callback(callback, account_id, &snapshot).await {
            return Ok(result_object(
                false,
                false,
                false,
                Some(snapshot),
                Some(format!(
                    "Signal snapshot persistence failed: {}",
                    js_value_message(&error)
                )),
                Some(prepared),
            )?);
        }
        let envelopes = prepared
            .get("envelopes")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| js_error("workflow did not produce an envelopes array"))?;
        if !envelopes.is_empty() {
            let upload = push.upload_envelopes(json_to_js(&Value::Array(envelopes.clone()))?);
            if let Err(error) = JsFuture::from(upload).await {
                return Ok(result_object(
                    false,
                    false,
                    true,
                    Some(snapshot),
                    Some(js_value_message(&error)),
                    Some(prepared),
                )?);
            }
        }
        Ok(result_object(
            true,
            !envelopes.is_empty(),
            true,
            Some(snapshot),
            None,
            Some(prepared),
        )?)
    }

    async fn failure_result(
        &self,
        account_id: &str,
        callback: &Function,
        error: JsValue,
    ) -> JsResult<JsValue> {
        let snapshot = crate::signal::snapshot(account_id).ok();
        let persisted = if let Some(snapshot) = snapshot.as_deref() {
            persist_snapshot_callback(callback, account_id, snapshot)
                .await
                .is_ok()
        } else {
            false
        };
        let message = if persisted {
            js_value_message(&error)
        } else if snapshot.is_some() {
            format!(
                "{}; Signal snapshot persistence also failed or was not confirmed",
                js_value_message(&error)
            )
        } else {
            js_value_message(&error)
        };
        Ok(result_object(
            false,
            false,
            persisted,
            snapshot,
            Some(message),
            None,
        )?)
    }
}

fn rollback_signal_state_after_prepare_error<T>(
    account_id: &str,
    base_snapshot: &str,
    prepared: JsResult<T>,
) -> JsResult<T> {
    match prepared {
        Ok(value) => Ok(value),
        Err(error) => {
            crate::signal::restore(account_id, base_snapshot).map_err(|restore_error| {
                js_error(&format!(
                    "{}; failed to restore Signal state after outbound preparation: {}",
                    js_value_message(&error),
                    js_value_message(&restore_error)
                ))
            })?;
            Err(error)
        }
    }
}

#[derive(Debug, Clone)]
struct HistorySendItem {
    conversation_id: String,
    item_kind: HistoryItemKind,
    item_id: String,
    item: Value,
}

fn validate_history_conversation_ids(value: &Value) -> Result<Vec<String>, String> {
    let values = value
        .as_array()
        .ok_or_else(|| "conversation_ids must be an array".to_owned())?;
    if values.len() > 200 {
        return Err("history request exceeds 200 conversations".to_owned());
    }
    let mut ids = Vec::with_capacity(values.len());
    let mut seen = std::collections::HashSet::new();
    for value in values {
        let id = value
            .as_str()
            .filter(|id| is_history_uuid(id))
            .ok_or_else(|| "conversation_ids must contain UUIDs".to_owned())?;
        if seen.insert(id.to_owned()) {
            ids.push(id.to_owned());
        }
    }
    Ok(ids)
}

fn parse_history_send_items(
    conversation_ids: &[String],
    value: &Value,
) -> Result<Vec<HistorySendItem>, String> {
    let records = value
        .as_array()
        .ok_or_else(|| "item_records must be an array".to_owned())?;
    let requested = conversation_ids
        .iter()
        .map(String::as_str)
        .collect::<std::collections::HashSet<_>>();
    let mut seen = std::collections::HashSet::new();
    let mut items = Vec::with_capacity(records.len());
    for record in records {
        let conversation_id = record
            .get("conversationId")
            .and_then(Value::as_str)
            .filter(|id| requested.contains(*id))
            .filter(|id| is_history_uuid(id))
            .ok_or_else(|| "history item references an unrequested conversation".to_owned())?
            .to_owned();
        let item_kind = match record.get("itemKind").and_then(Value::as_str) {
            Some("message") => HistoryItemKind::Message,
            Some("attachment") => HistoryItemKind::Attachment,
            Some("complete") => {
                return Err("completion records are generated by the library".to_owned());
            }
            _ => return Err("itemKind must be message or attachment".to_owned()),
        };
        let item_id = record
            .get("itemId")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.encode_utf16().count() <= 128)
            .ok_or_else(|| "history item has an invalid itemId".to_owned())?
            .to_owned();
        let item = record
            .get("item")
            .filter(|item| item.is_object())
            .cloned()
            .ok_or_else(|| "history item payload must be an object".to_owned())?;
        validate_history_send_payload(item_kind, &item_id, &item)?;
        if !seen.insert((conversation_id.clone(), item_kind, item_id.clone())) {
            return Err("history item records contain a duplicate item".to_owned());
        }
        items.push(HistorySendItem {
            conversation_id,
            item_kind,
            item_id,
            item,
        });
    }
    Ok(items)
}

fn validate_history_send_payload(
    item_kind: HistoryItemKind,
    item_id: &str,
    item: &Value,
) -> Result<(), String> {
    match item_kind {
        HistoryItemKind::Attachment => {
            if item.get("attachment_id").and_then(Value::as_str) != Some(item_id)
                || !is_history_uuid(item_id)
                || !history_hex(item, "key_hex", 64)
                || !history_hex(item, "base_nonce_hex", 8)
                || !history_safe_integer(item.get("total_size"))
                || !history_safe_integer(item.get("chunk_count"))
                || item
                    .get("chunk_count")
                    .and_then(Value::as_f64)
                    .is_none_or(|count| count > 500.0)
                || !matches!(
                    item.get("kind").and_then(Value::as_str),
                    Some("attachment" | "thumbnail")
                )
                || !history_nullable_string(item.get("file_name"), 4096)
                || !history_nullable_string(item.get("content_type"), 256)
            {
                return Err("invalid WEB history attachment record".to_owned());
            }
        }
        HistoryItemKind::Message => {
            let message = item
                .get("message")
                .filter(|value| value.is_object())
                .ok_or_else(|| "history message record omitted message".to_owned())?;
            let attachment_ids = message.get("attachment_ids").and_then(Value::as_array);
            let reactions = item.get("reactions").and_then(Value::as_array);
            if message.get("kind").and_then(Value::as_str) != Some("message")
                || message.get("message_id").and_then(Value::as_str) != Some(item_id)
                || message.get("text").and_then(Value::as_str).is_none()
                || !history_safe_integer(message.get("created_at"))
                || attachment_ids.is_none_or(|ids| {
                    ids.iter()
                        .any(|id| id.as_str().is_none_or(|id| !is_history_uuid(id)))
                })
                || item
                    .get("sender_account_id")
                    .and_then(Value::as_str)
                    .is_none_or(|id| !is_history_uuid(id))
                || !item
                    .get("sender_device_number")
                    .is_some_and(history_positive_safe_integer)
                || !history_safe_integer(item.get("server_timestamp"))
                || !(item.get("edited_at") == Some(&Value::Null)
                    || history_safe_integer(item.get("edited_at")))
                || reactions.is_none_or(|rows| rows.len() > 5000)
                || reactions.is_some_and(|rows| {
                    rows.iter().any(|reaction| {
                        reaction
                            .get("actor_id")
                            .and_then(Value::as_str)
                            .is_none_or(|id| !is_history_uuid(id))
                            || reaction
                                .get("emoji")
                                .and_then(Value::as_str)
                                .is_none_or(|emoji| emoji.chars().count() > 16)
                            || !history_safe_integer(reaction.get("created_at"))
                    })
                })
                || !valid_history_reply(message.get("reply_to"))
                || !valid_history_forward(message.get("forward_from"))
            {
                return Err("invalid WEB history message record".to_owned());
            }
            validate_history_poll(item)?;
        }
        HistoryItemKind::Complete => {
            return Err("completion records are generated by the library".to_owned());
        }
    }
    Ok(())
}

fn validate_history_poll(item: &Value) -> Result<(), String> {
    match item.get("format_version") {
        None if item.get("poll_data").is_none() => Ok(()),
        Some(version) if version.as_u64() == Some(2) => {
            let poll = item
                .get("poll_data")
                .filter(|poll| poll.is_object())
                .ok_or_else(|| "invalid WEB history poll metadata".to_owned())?;
            let options = poll.get("options").and_then(Value::as_array);
            if poll
                .get("poll_id")
                .and_then(Value::as_str)
                .is_none_or(|id| !is_history_uuid(id))
                || poll
                    .get("title")
                    .and_then(Value::as_str)
                    .is_none_or(|title| title.chars().count() > 64)
                || poll
                    .get("description")
                    .and_then(Value::as_str)
                    .is_none_or(|description| description.chars().count() > 128)
                || options.is_none_or(|options| !(2..=15).contains(&options.len()))
            {
                return Err("invalid WEB history poll metadata".to_owned());
            }
            let options = options.expect("validated above");
            let mut ids = std::collections::HashSet::new();
            for option in options {
                let id = option
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty() && id.encode_utf16().count() <= 64)
                    .ok_or_else(|| "invalid WEB history poll option".to_owned())?;
                if option
                    .get("text")
                    .and_then(Value::as_str)
                    .is_none_or(|text| text.is_empty() || text.chars().count() > 128)
                {
                    return Err("invalid WEB history poll option".to_owned());
                }
                if !ids.insert(id) {
                    return Err("duplicate WEB history poll option".to_owned());
                }
            }
            Ok(())
        }
        Some(_) => Err("invalid WEB history format version".to_owned()),
        None => Err("invalid WEB history poll metadata".to_owned()),
    }
}

fn valid_history_reply(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Null) => true,
        Some(reply) => {
            reply.is_object()
                && reply.get("message_id").and_then(Value::as_str).is_some()
                && history_optional_string(reply.get("preview"))
                && history_optional_string(reply.get("sender_account_id"))
        }
        None => false,
    }
}

fn valid_history_forward(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Null) => true,
        Some(forward) => {
            forward.is_object()
                && forward
                    .get("original_message_id")
                    .and_then(Value::as_str)
                    .is_some()
                && forward
                    .get("original_conversation_id")
                    .and_then(Value::as_str)
                    .is_some()
                && forward
                    .get("original_sender_account_id")
                    .and_then(Value::as_str)
                    .is_some()
                && history_nullable_string(forward.get("original_sender_display"), usize::MAX)
                && history_safe_integer(forward.get("original_created_at"))
        }
        None => false,
    }
}

fn history_optional_string(value: Option<&Value>) -> bool {
    matches!(value, None | Some(Value::Null) | Some(Value::String(_)))
}

fn history_nullable_string(value: Option<&Value>, max_utf16: usize) -> bool {
    match value {
        Some(Value::Null) => true,
        Some(Value::String(value)) => value.encode_utf16().count() <= max_utf16,
        _ => false,
    }
}

fn history_safe_integer(value: Option<&Value>) -> bool {
    value.and_then(Value::as_f64).is_some_and(|number| {
        number.is_finite()
            && number >= 0.0
            && number <= 9_007_199_254_740_991.0
            && number.fract() == 0.0
    })
}

fn history_positive_safe_integer(value: &Value) -> bool {
    history_safe_integer(Some(value)) && value.as_f64().is_some_and(|number| number >= 1.0)
}

fn history_hex(value: &Value, field: &str, len: usize) -> bool {
    value
        .get(field)
        .and_then(Value::as_str)
        .is_some_and(|hex| hex.len() == len && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn is_history_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn history_completion_item(message_count: usize) -> Value {
    json!({ "message_count": message_count })
}

fn history_message_count(items: &[HistorySendItem]) -> usize {
    items
        .iter()
        .filter(|item| item.item_kind == HistoryItemKind::Message)
        .count()
}

fn history_chunks_for_conversation(
    transfer_id: &str,
    conversation_id: &str,
    items: &[HistorySendItem],
) -> Result<Vec<HistoryChunk>, String> {
    let mut chunks = Vec::new();
    for item in items {
        let next = history_chunks(
            transfer_id,
            conversation_id,
            item.item_kind,
            &item.item_id,
            &item.item,
        )
        .map_err(|error| error.to_string())?;
        chunks.extend(next);
    }
    let message_count = history_message_count(items);
    let completion = history_chunks(
        transfer_id,
        conversation_id,
        HistoryItemKind::Complete,
        conversation_id,
        &history_completion_item(message_count),
    )
    .map_err(|error| error.to_string())?;
    chunks.extend(completion);
    Ok(chunks)
}

#[derive(Clone, Copy)]
struct EnvelopeOptions {
    client_timestamp: u64,
    send_at: Option<u64>,
}

impl EnvelopeOptions {
    fn new(client_timestamp: f64, send_at: Option<f64>) -> JsResult<Self> {
        Ok(Self {
            client_timestamp: validate_unix_seconds(client_timestamp, "created_at")?,
            send_at: send_at
                .map(|value| validate_unix_seconds(value, "send_at"))
                .transpose()?,
        })
    }
}

impl Default for EnvelopeOptions {
    fn default() -> Self {
        Self {
            client_timestamp: current_unix_seconds(),
            send_at: None,
        }
    }
}

#[derive(Clone, Copy)]
struct Device {
    device_number: u32,
}

fn validate_send_inputs(
    account_id: &str,
    conversation_id: &str,
    message_id: &str,
    created_at: f64,
    send_at: Option<f64>,
) -> JsResult<()> {
    validate_uuid(account_id, "account_id")?;
    validate_uuid(conversation_id, "conversation_id")?;
    validate_uuid(message_id, "message_id")?;
    validate_unix_seconds(created_at, "created_at")?;
    if let Some(send_at) = send_at {
        validate_unix_seconds(send_at, "send_at")?;
    }
    Ok(())
}

fn validate_unix_seconds(value: f64, name: &str) -> JsResult<u64> {
    checked_unix_seconds(value, name).map_err(|error| js_error(&error))
}

fn checked_unix_seconds(value: f64, name: &str) -> Result<u64, String> {
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > 9_007_199_254_740_991.0
    {
        return Err(format!("{name} must be a non-negative safe integer"));
    }
    Ok(value as u64)
}

fn validate_uuid(value: &str, name: &str) -> JsResult<()> {
    uuid::Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| js_error(&format!("{name} must be a UUID")))
}

fn encode_message_payload(message_id: &str, draft: &Value, created_at: f64) -> JsResult<String> {
    let payload = super::messaging::build_message_payload(message_id, draft, created_at)
        .map_err(|error| js_error(&error))?;
    let serialized = serde_json::to_vec(&payload).map_err(|error| js_error(&error.to_string()))?;
    Ok(hex::encode(serialized))
}

fn message_action_payload(
    target_message_id: &str,
    action: &Value,
    at: f64,
) -> JsResult<(&'static str, i32, Value)> {
    let kind = action
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| js_error("action.kind must be a string"))?;
    match kind {
        "edit" => {
            let new_text = action
                .get("newText")
                .and_then(Value::as_str)
                .ok_or_else(|| js_error("edit action requires string newText"))?;
            Ok((
                "edit",
                EDIT,
                json!({
                    "kind": "edit",
                    "target_message_id": target_message_id,
                    "new_text": new_text,
                    "edited_at": at,
                }),
            ))
        }
        "delete" => Ok((
            "delete",
            DELETE,
            json!({
                "kind": "delete",
                "target_message_id": target_message_id,
                "deleted_at": at,
            }),
        )),
        "reaction" => {
            let emoji = match action.get("emoji") {
                None | Some(Value::Null) => Value::Null,
                Some(Value::String(value)) => Value::String(value.clone()),
                Some(_) => return Err(js_error("reaction action emoji must be a string or null")),
            };
            Ok((
                "reaction",
                REACTION,
                json!({
                    "kind": "reaction",
                    "target_message_id": target_message_id,
                    "emoji": emoji,
                    "created_at": at,
                }),
            ))
        }
        _ => Err(js_error("action.kind must be edit, delete, or reaction")),
    }
}

fn pairwise_envelope(
    sender_account_id: &str,
    sender_device_number: u32,
    recipient_account_id: &str,
    recipient_device_number: u32,
    envelope_type: i32,
    is_prekey_message: bool,
    ciphertext: &str,
    conversation_id: Option<&str>,
    options: EnvelopeOptions,
) -> Value {
    let mut envelope = json!({
        "envelopeId": uuid_v7(),
        "senderAccountId": sender_account_id,
        "senderDeviceNumber": sender_device_number,
        "recipientAccountId": recipient_account_id,
        "recipientDeviceNumber": recipient_device_number,
        "envelopeType": envelope_type,
        "isPrekeyMessage": is_prekey_message,
        "ciphertext": ciphertext,
        "clientTimestamp": options.client_timestamp,
        "conversationId": conversation_id,
        "senderIsBot": false,
    });
    if let Some(send_at) = options.send_at {
        envelope["sendAt"] = Value::from(send_at);
    }
    envelope
}

fn group_envelope(
    sender_account_id: &str,
    sender_device_number: u32,
    recipient_account_id: &str,
    recipient: Device,
    ciphertext: &str,
    conversation_id: &str,
    options: EnvelopeOptions,
) -> Value {
    pairwise_envelope(
        sender_account_id,
        sender_device_number,
        recipient_account_id,
        recipient.device_number,
        MESSAGE,
        false,
        ciphertext,
        Some(conversation_id),
        options,
    )
}

fn local_message_value(
    account_id: &str,
    device_number: u32,
    conversation_id: &str,
    message_id: &str,
    draft: &Value,
    created_at: f64,
    envelope_id: Option<&Value>,
) -> JsResult<Value> {
    let text = draft
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| js_error("message draft text must be a string"))?;
    let attachment_ids = match draft.get("attachmentIds") {
        None => Value::Array(Vec::new()),
        Some(Value::Array(values)) if values.iter().all(Value::is_string) => {
            Value::Array(values.clone())
        }
        Some(_) => return Err(js_error("attachmentIds must be an array of strings")),
    };
    let created_at = validate_unix_seconds(created_at, "created_at")?;
    Ok(json!({
        "messageId": message_id,
        "envelopeId": envelope_id
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(uuid_v7),
        "accountId": account_id,
        "conversationId": conversation_id,
        "senderAccountId": account_id,
        "senderDeviceNumber": device_number,
        "recipientAccountId": account_id,
        "recipientDeviceNumber": device_number,
        "envelopeType": MESSAGE,
        "plaintext": text,
        "decryptedAt": created_at,
        "clientTimestamp": created_at,
        "serverTimestamp": created_at,
        "attachments": attachment_ids,
        "replyTo": draft.get("replyTo").filter(|value| !value.is_null()).cloned().unwrap_or(Value::Null),
        "forwardFrom": draft.get("forwardFrom").filter(|value| !value.is_null()).cloned().unwrap_or(Value::Null),
        "editedAt": null,
        "isPinned": false,
        "reactions": [],
        "status": "sending",
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HistoryPageQuery {
    before: Option<i64>,
    before_id: Option<String>,
    limit: u32,
}

#[derive(Debug, Clone)]
struct HttpHistoryEnvelope {
    envelope_id: String,
    sender_account_id: String,
    sender_device_number: u32,
    recipient_device_number: u32,
    envelope_type: i32,
    is_prekey_message: bool,
    ciphertext: String,
    client_timestamp: i64,
    server_timestamp: i64,
    conversation_id: Option<String>,
}

fn parse_history_page_query(
    value: JsValue,
    default_limit: u32,
) -> Result<HistoryPageQuery, JsValue> {
    let value = if value.is_null() || value.is_undefined() {
        Value::Null
    } else {
        js_to_json(value)?
    };
    parse_history_page_query_value(&value, default_limit).map_err(|error| js_error(&error))
}

fn parse_history_page_query_value(
    value: &Value,
    default_limit: u32,
) -> Result<HistoryPageQuery, String> {
    if !value.is_null() && !value.is_object() {
        return Err("history query must be an object".to_owned());
    }
    let before = match value.get("before") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            receive_safe_integer(Some(value))
                .and_then(|number| i64::try_from(number).ok())
                .ok_or_else(|| {
                    "history query before must be a non-negative safe integer".to_owned()
                })?,
        ),
    };
    let before_id = match value.get("beforeId") {
        None | Some(Value::Null) => None,
        Some(Value::String(id)) if is_history_uuid(id) => Some(id.clone()),
        Some(_) => return Err("history query beforeId must be a UUID".to_owned()),
    };
    if before.is_none() && before_id.is_some() {
        return Err("history query beforeId requires before".to_owned());
    }
    let limit = match value.get("limit") {
        None | Some(Value::Null) => default_limit,
        Some(value) => receive_safe_integer(Some(value))
            .and_then(|number| u32::try_from(number).ok())
            .filter(|limit| (1..=500).contains(limit))
            .ok_or_else(|| "history query limit must be an integer from 1 to 500".to_owned())?,
    };
    Ok(HistoryPageQuery {
        before,
        before_id,
        limit,
    })
}

fn history_query_json(query: &HistoryPageQuery) -> Value {
    let mut value = serde_json::Map::new();
    if let Some(before) = query.before {
        value.insert("before".to_owned(), json!(before));
    }
    if let Some(before_id) = &query.before_id {
        value.insert("beforeId".to_owned(), json!(before_id));
    }
    value.insert("limit".to_owned(), json!(query.limit));
    Value::Object(value)
}

fn history_page_request(conversation_id: &str, query: &HistoryPageQuery) -> Value {
    let mut request = history_query_json(query)
        .as_object()
        .cloned()
        .unwrap_or_default();
    request.insert("conversationId".to_owned(), json!(conversation_id));
    Value::Object(request)
}

fn history_page_cursor(rows: &[Value]) -> Value {
    rows.last()
        .and_then(|row| {
            Some(json!({
                "before": row.get("serverTimestamp")?,
                "beforeId": row.get("envelopeId")?,
            }))
        })
        .unwrap_or(Value::Null)
}

fn validate_known_history_ids(value: &Value) -> Result<HashSet<String>, String> {
    let values = value
        .as_array()
        .ok_or_else(|| "knownEnvelopeIds must be an array from host IndexedDB".to_owned())?;
    if values.len() > HISTORY_REPLAY_MAX_KNOWN_IDS {
        return Err(format!(
            "knownEnvelopeIds exceeds the {}-ID page limit",
            HISTORY_REPLAY_MAX_KNOWN_IDS
        ));
    }
    let mut ids = HashSet::with_capacity(values.len());
    for value in values {
        let id = value
            .as_str()
            .ok_or_else(|| "knownEnvelopeIds must contain only UUID strings".to_owned())?;
        if !is_history_uuid(id) {
            return Err("knownEnvelopeIds contains an invalid envelope UUID".to_owned());
        }
        ids.insert(id.to_owned());
    }
    Ok(ids)
}

fn parse_http_history_envelope(value: Value) -> Result<HttpHistoryEnvelope, String> {
    let required_string = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .ok_or_else(|| format!("HTTP history row omitted {key}"))
    };
    let envelope_id = required_string("envelopeId")?.to_owned();
    let sender_account_id = required_string("senderAccountId")?.to_owned();
    for (field, id) in [
        ("envelopeId", envelope_id.as_str()),
        ("senderAccountId", sender_account_id.as_str()),
    ] {
        if !is_history_uuid(id) {
            return Err(format!("HTTP history row has invalid {field}"));
        }
    }
    let sender_device_number = history_row_u32(&value, "senderDeviceNumber")?;
    let recipient_device_number = history_row_u32(&value, "recipientDeviceNumber")?;
    let envelope_type = value
        .get("envelopeType")
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| "HTTP history row has invalid envelopeType".to_owned())?;
    let is_prekey_message = value
        .get("isPrekeyMessage")
        .and_then(Value::as_bool)
        .ok_or_else(|| "HTTP history row has invalid isPrekeyMessage".to_owned())?;
    let ciphertext = required_string("ciphertext")?.to_owned();
    hex::decode(&ciphertext).map_err(|error| format!("HTTP history ciphertext hex: {error}"))?;
    let client_timestamp = value
        .get("clientTimestamp")
        .and_then(Value::as_i64)
        .ok_or_else(|| "HTTP history row has invalid clientTimestamp".to_owned())?;
    let server_timestamp = value
        .get("serverTimestamp")
        .and_then(Value::as_i64)
        .ok_or_else(|| "HTTP history row has invalid serverTimestamp".to_owned())?;
    let row_conversation_id = value
        .get("conversationId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(HttpHistoryEnvelope {
        envelope_id,
        sender_account_id,
        sender_device_number,
        recipient_device_number,
        envelope_type,
        is_prekey_message,
        ciphertext,
        client_timestamp,
        server_timestamp,
        conversation_id: row_conversation_id,
    })
}

fn history_row_u32(value: &Value, key: &str) -> Result<u32, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|number| u32::try_from(number).ok())
        .filter(|number| *number > 0)
        .ok_or_else(|| format!("HTTP history row has invalid {key}"))
}

fn restore_history_snapshot(account_id: &str, snapshot: &str) -> Result<(), String> {
    crate::signal::restore(account_id, snapshot).map_err(|error| js_value_message(&error))
}

fn begin_history_replay_stage(
    account_id: &str,
    local_device_number: u32,
    conversation_id: &str,
    raw_rows: Vec<Value>,
    known_ids: HashSet<String>,
) -> Result<Value, String> {
    if local_device_number == 0 {
        return Err("local device number must be positive".to_owned());
    }
    let mut rows = raw_rows
        .into_iter()
        .map(parse_http_history_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    order_http_history_rows(&mut rows);
    let base_snapshot =
        crate::signal::snapshot(account_id).map_err(|error| js_value_message(&error))?;
    // Signal addresses include the authenticated local account ID. Replay on
    // this account synchronously, capture its staged snapshot, then restore
    // the base before yielding to JavaScript or another workflow.
    let replay_result = replay_http_history_rows(
        account_id,
        account_id,
        local_device_number,
        conversation_id,
        rows,
        &known_ids,
    );
    let result = match replay_result {
        Ok(result) => result,
        Err(error) => {
            return match restore_history_snapshot(account_id, &base_snapshot) {
                Ok(()) => Err(error),
                Err(restore_error) => Err(format!(
                    "{error}; restoring the pre-replay Signal snapshot also failed: {restore_error}"
                )),
            };
        }
    };
    let staged_snapshot = match crate::signal::snapshot(account_id) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let error = format!(
                "could not snapshot staged history replay: {}",
                js_value_message(&error)
            );
            return match restore_history_snapshot(account_id, &base_snapshot) {
                Ok(()) => Err(error),
                Err(restore_error) => Err(format!(
                    "{error}; restoring the pre-replay Signal snapshot also failed: {restore_error}"
                )),
            };
        }
    };
    let identity_changes = match crate::signal::identity_changes(account_id).and_then(|json| {
        serde_json::from_str::<Value>(&json).map_err(|error| js_error(&error.to_string()))
    }) {
        Ok(changes) => changes,
        Err(error) => {
            let error = format!(
                "could not read history replay identity changes: {}",
                js_value_message(&error)
            );
            return match restore_history_snapshot(account_id, &base_snapshot) {
                Ok(()) => Err(error),
                Err(restore_error) => Err(format!(
                    "{error}; restoring the pre-replay Signal snapshot also failed: {restore_error}"
                )),
            };
        }
    };
    restore_history_snapshot(account_id, &base_snapshot)?;

    let token = uuid_v7();
    let expires_at = Instant::now() + HISTORY_REPLAY_STAGE_TTL;
    let mut result = result;
    if let Some(object) = result.as_object_mut() {
        object.insert("identityChanges".to_owned(), identity_changes);
        object.insert("replayToken".to_owned(), json!(token));
        object.insert(
            "expiresInSeconds".to_owned(),
            json!(HISTORY_REPLAY_STAGE_TTL.as_secs()),
        );
    }
    let stage = HistoryReplayStage {
        account_id: account_id.to_owned(),
        local_device_number,
        conversation_id: conversation_id.to_owned(),
        base_snapshot,
        staged_snapshot,
        result: result.clone(),
        expires_at,
    };
    insert_history_replay_stage(token, stage)?;
    Ok(result)
}

fn order_http_history_rows(rows: &mut [HttpHistoryEnvelope]) {
    rows.sort_by(|left, right| {
        left.server_timestamp
            .cmp(&right.server_timestamp)
            .then_with(|| left.envelope_id.cmp(&right.envelope_id))
    });
}

fn replay_http_history_rows(
    replay_account_id: &str,
    authenticated_account_id: &str,
    local_device_number: u32,
    conversation_id: &str,
    rows: Vec<HttpHistoryEnvelope>,
    known_ids: &HashSet<String>,
) -> Result<Value, String> {
    let mut result = json!({
        "messages": [],
        "available": [],
        "attachmentKeys": [],
        "identityChanges": [],
        "processedEnvelopeIds": [],
        "skippedEnvelopeIds": [],
        "progressIds": [],
        "existing": 0,
        "unavailable": 0,
        "ignored": 0,
    });
    let mut seen = HashSet::new();
    let mut message_by_envelope = HashMap::<String, Value>::new();
    for row in rows {
        if !seen.insert(row.envelope_id.clone()) {
            if let Some(message) = message_by_envelope.get(&row.envelope_id).cloned() {
                result["existing"] = json!(result["existing"].as_u64().unwrap_or(0) + 1);
                result["available"]
                    .as_array_mut()
                    .expect("array initialized")
                    .push(message);
            }
            continue;
        }
        if row.recipient_device_number != local_device_number
            || row.conversation_id.as_deref() != Some(conversation_id)
        {
            result["unavailable"] = json!(result["unavailable"].as_u64().unwrap_or(0) + 1);
            continue;
        }
        if known_ids.contains(&row.envelope_id) {
            result["skippedEnvelopeIds"]
                .as_array_mut()
                .expect("array initialized")
                .push(json!(row.envelope_id));
            result["existing"] = json!(result["existing"].as_u64().unwrap_or(0) + 1);
            continue;
        }
        if !matches!(
            row.envelope_type,
            MESSAGE | SYNC | SENDER_KEY | ATTACHMENT_KEY
        ) {
            result["ignored"] = json!(result["ignored"].as_u64().unwrap_or(0) + 1);
            continue;
        }

        let plaintext_hex =
            match decrypt_http_history_envelope(replay_account_id, local_device_number, &row) {
                Ok(plaintext) => plaintext,
                Err(error) => {
                    return Err(format!(
                        "history envelope {} could not be decrypted: {error}",
                        row.envelope_id
                    ));
                }
            };
        if row.envelope_type == SENDER_KEY {
            let distribution_text = String::from_utf8_lossy(
                &hex::decode(plaintext_hex)
                    .map_err(|error| format!("sender-key distribution plaintext hex: {error}"))?,
            )
            .into_owned();
            let distribution = hex::decode(distribution_text)
                .map_err(|error| format!("sender-key distribution hex: {error}"))?;
            if distribution.is_empty() {
                return Err("sender-key distribution is empty".to_owned());
            }
            crate::signal::process_sender_key_distribution(
                replay_account_id,
                &row.sender_account_id,
                row.sender_device_number,
                &hex::encode(distribution),
            )
            .map_err(|error| js_value_message(&error))?;
            append_history_processed_id(&mut result, &row.envelope_id, true);
            continue;
        }

        let plaintext = hex::decode(plaintext_hex)
            .map_err(|error| format!("history plaintext hex: {error}"))?;
        let metadata = ReceiveMetadata {
            envelope_id: &row.envelope_id,
            client_timestamp: row.client_timestamp,
            local_account_id: Some(authenticated_account_id),
            sender_account_id: Some(&row.sender_account_id),
            sender_device_number: Some(i64::from(row.sender_device_number)),
            recipient_account_id: Some(authenticated_account_id),
            recipient_device_number: Some(i64::from(row.recipient_device_number)),
            conversation_id: row.conversation_id.as_deref(),
        };
        let parsed = parse_decrypted_payload(i64::from(row.envelope_type), metadata, &plaintext);
        match parsed {
            Some(semantic) if matches!(semantic.kind, "message_received" | "poll_received") => {
                let record = build_http_history_message(
                    authenticated_account_id,
                    conversation_id,
                    &row,
                    &semantic.payload,
                    current_unix_seconds() as i64,
                )?;
                message_by_envelope.insert(row.envelope_id.clone(), record.clone());
                result["messages"]
                    .as_array_mut()
                    .expect("array initialized")
                    .push(record.clone());
                result["available"]
                    .as_array_mut()
                    .expect("array initialized")
                    .push(record);
                append_history_processed_id(&mut result, &row.envelope_id, false);
            }
            Some(semantic) if semantic.kind == "attachment_key_received" => {
                let payload = semantic.payload;
                let attachment_id = payload
                    .get("attachment_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "decoded attachment key omitted attachment_id".to_owned())?;
                validate_history_uuid(attachment_id, "attachment_id")?;
                let key_hex = payload
                    .get("key_hex")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "decoded attachment key omitted key_hex".to_owned())?;
                let base_nonce_hex = payload
                    .get("base_nonce_hex")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "decoded attachment key omitted base_nonce_hex".to_owned())?;
                let key_bytes =
                    hex::decode(key_hex).map_err(|error| format!("attachment key hex: {error}"))?;
                let nonce_bytes = hex::decode(base_nonce_hex)
                    .map_err(|error| format!("attachment nonce hex: {error}"))?;
                if key_bytes.len() != 32 || nonce_bytes.len() != 12 {
                    return Err("decoded attachment key has invalid key or nonce length".to_owned());
                }
                result["attachmentKeys"].as_array_mut().expect("array initialized").push(json!({
                    "envelopeId": row.envelope_id,
                    "attachmentId": attachment_id,
                    "keyHex": key_hex,
                    "baseNonceHex": base_nonce_hex,
                    "conversationId": payload.get("conversation_id").filter(|value| !value.is_null()).cloned().unwrap_or(Value::Null),
                }));
                append_history_processed_id(&mut result, &row.envelope_id, true);
            }
            _ => {
                result["ignored"] = json!(result["ignored"].as_u64().unwrap_or(0) + 1);
                append_history_processed_id(&mut result, &row.envelope_id, true);
            }
        }
    }
    Ok(result)
}

fn decrypt_http_history_envelope(
    account_id: &str,
    local_device_number: u32,
    row: &HttpHistoryEnvelope,
) -> Result<String, String> {
    if row.envelope_type == MESSAGE
        && !row.is_prekey_message
        && received_ciphertext_is_group(&row.ciphertext)?
    {
        return crate::signal::group_decrypt(
            account_id,
            &row.sender_account_id,
            row.sender_device_number,
            &row.ciphertext,
        )
        .map_err(|error| js_value_message(&error));
    }
    crate::signal::decrypt(
        account_id,
        &row.sender_account_id,
        row.sender_device_number,
        local_device_number,
        &row.ciphertext,
        row.is_prekey_message,
    )
    .map_err(|error| js_value_message(&error))
}

fn append_history_processed_id(result: &mut Value, envelope_id: &str, progress: bool) {
    result["processedEnvelopeIds"]
        .as_array_mut()
        .expect("array initialized")
        .push(json!(envelope_id));
    if progress {
        result["progressIds"]
            .as_array_mut()
            .expect("array initialized")
            .push(json!(envelope_id));
    }
}

fn build_http_history_message(
    account_id: &str,
    conversation_id: &str,
    envelope: &HttpHistoryEnvelope,
    payload: &Value,
    decrypted_at: i64,
) -> Result<Value, String> {
    let kind = payload
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let (message_id, plaintext) = match kind {
        "message" => (
            payload.get("message_id").and_then(Value::as_str),
            payload.get("text").and_then(Value::as_str),
        ),
        "poll" => (
            payload.get("poll_id").and_then(Value::as_str),
            payload.get("title").and_then(Value::as_str),
        ),
        _ => (None, None),
    };
    let message_id =
        message_id.ok_or_else(|| "decrypted history message omitted logical ID".to_owned())?;
    let plaintext = plaintext.ok_or_else(|| "decrypted history message omitted text".to_owned())?;
    let poll = kind == "poll";
    let attachments = if poll {
        json!([])
    } else {
        payload
            .get("attachment_ids")
            .filter(|value| value.is_array())
            .cloned()
            .unwrap_or_else(|| json!([]))
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
        "clientTimestamp": normalize_history_timestamp(envelope.client_timestamp, envelope.server_timestamp),
        "serverTimestamp": envelope.server_timestamp,
        "attachments": attachments,
        "replyTo": if poll { Value::Null } else { history_reply_to(payload.get("reply_to")) },
        "forwardFrom": if poll { Value::Null } else { history_forward_from(payload.get("forward_from")) },
        "editedAt": null,
        "isPinned": false,
        "reactions": [],
        "status": "sent",
    });
    if poll {
        record["pollData"] = json!({
            "pollId": payload["poll_id"],
            "title": payload["title"],
            "description": payload["description"],
            "options": payload["options"],
        });
    }
    Ok(record)
}

fn history_reply_to(value: Option<&Value>) -> Value {
    let Some(value) = value.filter(|value| value.is_object()) else {
        return Value::Null;
    };
    let Some(message_id) = value.get("message_id").and_then(Value::as_str) else {
        return Value::Null;
    };
    json!({
        "messageId": message_id,
        "preview": value.get("preview").filter(|value| !value.is_null()).cloned().unwrap_or(Value::Null),
        "senderAccountId": value.get("sender_account_id").filter(|value| !value.is_null()).cloned().unwrap_or(Value::Null),
    })
}

fn history_forward_from(value: Option<&Value>) -> Value {
    let Some(value) = value.filter(|value| value.is_object()) else {
        return Value::Null;
    };
    let required = [
        "original_message_id",
        "original_conversation_id",
        "original_sender_account_id",
    ];
    if required
        .iter()
        .any(|field| value.get(*field).and_then(Value::as_str).is_none())
    {
        return Value::Null;
    }
    json!({
        "originalMessageId": value["original_message_id"],
        "originalConversationId": value["original_conversation_id"],
        "originalSenderAccountId": value["original_sender_account_id"],
        "originalSenderDisplay": value.get("original_sender_display").filter(|value| !value.is_null()).cloned().unwrap_or(Value::Null),
        "originalCreatedAt": value.get("original_created_at").cloned().unwrap_or(json!(0)),
    })
}

fn normalize_history_timestamp(value: i64, fallback: i64) -> i64 {
    const MAX_UNIX_SECONDS_FOR_DATE: i64 = 8_640_000_000_000;
    if value.unsigned_abs() <= MAX_UNIX_SECONDS_FOR_DATE as u64 {
        value
    } else if fallback.unsigned_abs() <= MAX_UNIX_SECONDS_FOR_DATE as u64 {
        fallback
    } else {
        current_unix_seconds() as i64
    }
}

fn validate_history_uuid(value: &str, name: &str) -> Result<(), String> {
    if is_history_uuid(value) {
        Ok(())
    } else {
        Err(format!("{name} must be a UUID"))
    }
}

fn history_replay_transaction_request(token: &str, stage: &HistoryReplayStage) -> Value {
    json!({
        "contractVersion": 1,
        "phase": "commit",
        "replayToken": token,
        "accountId": stage.account_id,
        "localDeviceNumber": stage.local_device_number,
        "conversationId": stage.conversation_id,
        "baseSignalSnapshot": stage.base_snapshot,
        "signalSnapshot": stage.staged_snapshot,
        "messages": stage.result["messages"],
        "attachmentKeys": stage.result["attachmentKeys"],
        "progressIds": stage.result["progressIds"],
        "processedEnvelopeIds": stage.result["processedEnvelopeIds"],
        "rollbackEnvelopeIds": stage.result["processedEnvelopeIds"],
        "skippedEnvelopeIds": stage.result["skippedEnvelopeIds"],
        "result": stage.result,
    })
}

struct HistoryReplayTransactionReply {
    committed: bool,
    rolled_back: bool,
    conflict: bool,
    error: Option<String>,
}

async fn call_history_replay_transaction(
    callback: &Function,
    request: &Value,
) -> JsResult<HistoryReplayTransactionReply> {
    let value = callback.call1(&JsValue::UNDEFINED, &json_to_js(request)?)?;
    let value = JsFuture::from(Promise::resolve(&value)).await?;
    let value = js_to_json(value)?;
    let phase = request
        .get("phase")
        .and_then(Value::as_str)
        .unwrap_or("commit");
    parse_history_replay_transaction_reply(&value, phase).map_err(|error| js_error(&error))
}

fn parse_history_replay_transaction_reply(
    value: &Value,
    phase: &str,
) -> Result<HistoryReplayTransactionReply, String> {
    if !value.is_object() {
        return Err("history persistence callback must resolve to an object".to_owned());
    }
    let committed = if phase == "commit" {
        value
            .get("committed")
            .and_then(Value::as_bool)
            .ok_or_else(|| "history persistence callback omitted boolean committed".to_owned())?
    } else {
        false
    };
    let rolled_back = if phase == "rollback" {
        Some(
            value
                .get("rolledBack")
                .and_then(Value::as_bool)
                .ok_or_else(|| "history rollback callback omitted boolean rolledBack".to_owned())?,
        )
    } else {
        value.get("rolledBack").and_then(Value::as_bool)
    };
    let conflict = value
        .get("conflict")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let error = value
        .get("error")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if committed && conflict {
        return Err(
            "history persistence callback cannot report both committed and conflict".to_owned(),
        );
    }
    Ok(HistoryReplayTransactionReply {
        committed,
        rolled_back: rolled_back.unwrap_or(false),
        conflict,
        error,
    })
}

async fn rollback_committed_history_page(
    account_id: &str,
    replay_token: &str,
    stage: &HistoryReplayStage,
    callback: &Function,
    reason: String,
) -> JsResult<JsValue> {
    let rollback_request = history_replay_rollback_request(account_id, replay_token, stage);
    let rollback = call_history_replay_transaction(callback, &rollback_request).await;
    let (rolled_back, rollback_error) = match rollback {
        Ok(reply) => (reply.rolled_back, reply.error),
        Err(error) => (false, Some(js_value_message(&error))),
    };
    discard_history_replay_stage(replay_token);
    let mut result = json!({
        "ok": false,
        "committed": false,
        "conflict": true,
        "rollbackRequired": !rolled_back,
        "rolledBack": rolled_back,
        "replayToken": replay_token,
        "error": reason,
        "rollbackEnvelopeIds": stage.result["processedEnvelopeIds"],
    });
    if let Some(error) = rollback_error {
        result["rollbackError"] = json!(error);
    }
    json_to_js(&result)
}

fn history_replay_rollback_request(
    account_id: &str,
    replay_token: &str,
    stage: &HistoryReplayStage,
) -> Value {
    json!({
        "contractVersion": 1,
        "phase": "rollback",
        "replayToken": replay_token,
        "accountId": account_id,
        "localDeviceNumber": stage.local_device_number,
        "conversationId": stage.conversation_id,
        "baseSignalSnapshot": stage.base_snapshot,
        "signalSnapshot": stage.staged_snapshot,
        "messages": stage.result["messages"],
        "attachmentKeys": stage.result["attachmentKeys"],
        "progressIds": stage.result["progressIds"],
        "processedEnvelopeIds": stage.result["processedEnvelopeIds"],
        "rollbackEnvelopeIds": stage.result["processedEnvelopeIds"],
    })
}

fn same_snapshot(left: &str, right: &str) -> bool {
    fn normalized(snapshot: &str) -> Option<Value> {
        let mut value = serde_json::from_str::<Value>(snapshot).ok()?;
        let Some(object) = value.as_object_mut() else {
            return Some(value);
        };
        for field in [
            "peer_identities",
            "pre_keys",
            "signed_pre_keys",
            "kyber_pre_keys",
            "sessions",
            "sender_keys",
            "group_sender_keys",
        ] {
            if let Some(Value::Array(entries)) = object.get_mut(field) {
                entries
                    .sort_by_cached_key(|entry| serde_json::to_string(entry).unwrap_or_default());
            }
        }
        Some(value)
    }

    match (normalized(left), normalized(right)) {
        (Some(left), Some(right)) => left == right,
        _ => left == right,
    }
}

fn insert_history_replay_stage(token: String, stage: HistoryReplayStage) -> Result<(), String> {
    HISTORY_REPLAY_STAGES.with(|stages| {
        let mut stages = stages.borrow_mut();
        stages.retain(|_, stage| stage.expires_at > Instant::now());
        if stages.len() >= HISTORY_REPLAY_MAX_PENDING {
            return Err("too many pending HTTP-history replay pages".to_owned());
        }
        stages.insert(token, stage);
        Ok(())
    })
}

fn history_replay_stage(token: &str) -> Option<HistoryReplayStage> {
    HISTORY_REPLAY_STAGES.with(|stages| {
        let mut stages = stages.borrow_mut();
        stages.retain(|_, stage| stage.expires_at > Instant::now());
        stages.get(token).cloned()
    })
}

fn update_history_replay_stage_result(token: &str, result: Value) {
    HISTORY_REPLAY_STAGES.with(|stages| {
        if let Some(stage) = stages.borrow_mut().get_mut(token) {
            stage.result = result;
        }
    });
}

fn discard_history_replay_stage(token: &str) -> bool {
    HISTORY_REPLAY_STAGES.with(|stages| stages.borrow_mut().remove(token).is_some())
}

fn history_replay_receipt(token: &str) -> Option<Value> {
    HISTORY_REPLAY_RECEIPTS.with(|receipts| {
        let mut receipts = receipts.borrow_mut();
        receipts.retain(|_, (expires_at, _)| *expires_at > Instant::now());
        receipts.get(token).map(|(_, receipt)| receipt.clone())
    })
}

fn remember_history_replay_receipt(token: &str, receipt: Value) {
    HISTORY_REPLAY_RECEIPTS.with(|receipts| {
        let mut receipts = receipts.borrow_mut();
        receipts.retain(|_, (expires_at, _)| *expires_at > Instant::now());
        while receipts.len() >= HISTORY_REPLAY_MAX_RECEIPTS {
            let Some(oldest) = receipts
                .iter()
                .min_by_key(|(_, (expires_at, _))| *expires_at)
                .map(|(token, _)| token.clone())
            else {
                break;
            };
            receipts.remove(&oldest);
        }
        receipts.insert(
            token.to_owned(),
            (Instant::now() + HISTORY_REPLAY_STAGE_TTL, receipt),
        );
    });
}

fn history_replay_failure(token: Option<&str>, error: String) -> JsResult<JsValue> {
    let mut result = json!({ "ok": false, "committed": false, "error": error });
    if let Some(token) = token {
        result["replayToken"] = json!(token);
    }
    json_to_js(&result)
}

async fn acquire_receive_queue(account_id: &str) -> JsResult<ReceiveQueueGuard> {
    let resolver_slot = Rc::new(RefCell::new(None::<Function>));
    let resolver_capture = Rc::clone(&resolver_slot);
    let gate = Promise::new(&mut move |resolve, _reject| {
        *resolver_capture.borrow_mut() = Some(resolve);
    });
    let resolver = resolver_slot
        .borrow_mut()
        .take()
        .ok_or_else(|| js_error("could not create receive queue gate"))?;
    let ticket = RECEIVE_TICKET.with(|next| {
        let ticket = next.get().wrapping_add(1).max(1);
        next.set(ticket);
        ticket
    });
    let previous = RECEIVE_TAILS.with(|tails| {
        let mut tails = tails.borrow_mut();
        let previous = tails.get(account_id).map(|tail| tail.gate.clone());
        tails.insert(
            account_id.to_owned(),
            ReceiveQueueTail {
                ticket,
                gate: gate.clone(),
            },
        );
        previous
    });
    let guard = ReceiveQueueGuard {
        account_id: account_id.to_owned(),
        ticket,
        resolver,
    };
    if let Some(previous) = previous {
        if let Err(error) = JsFuture::from(previous).await {
            drop(guard);
            return Err(error);
        }
    }
    Ok(guard)
}

#[derive(Debug, Clone)]
struct DeliveredEnvelope {
    value: Value,
    envelope_id: String,
    sender_account_id: String,
    sender_device_number: u32,
    recipient_account_id: String,
    recipient_device_number: u32,
    envelope_type: i32,
    is_prekey_message: bool,
    ciphertext: String,
    client_timestamp: i64,
    conversation_id: Option<String>,
}

fn parse_delivered_envelope(
    value: &Value,
    account_id: &str,
    local_device_number: u32,
) -> Result<DeliveredEnvelope, String> {
    let required_string = |field: &str| {
        value
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("delivered envelope omitted {field}"))
    };
    let envelope_id = required_string("envelopeId")?.to_owned();
    let sender_account_id = required_string("senderAccountId")?.to_owned();
    let recipient_account_id = required_string("recipientAccountId")?.to_owned();
    for (field, id) in [
        ("envelopeId", envelope_id.as_str()),
        ("senderAccountId", sender_account_id.as_str()),
        ("recipientAccountId", recipient_account_id.as_str()),
    ] {
        if !is_history_uuid(id) {
            return Err(format!("delivered envelope has an invalid {field}"));
        }
    }
    if account_id.is_empty() || !is_history_uuid(account_id) {
        return Err("account_id must be a UUID".to_owned());
    }
    if local_device_number == 0 {
        return Err("local_device_number must be positive".to_owned());
    }
    let sender_device_number = value
        .get("senderDeviceNumber")
        .and_then(Value::as_u64)
        .and_then(|number| u32::try_from(number).ok())
        .filter(|number| *number > 0)
        .ok_or_else(|| "delivered envelope has an invalid senderDeviceNumber".to_owned())?;
    let recipient_device_number = value
        .get("recipientDeviceNumber")
        .and_then(Value::as_u64)
        .and_then(|number| u32::try_from(number).ok())
        .filter(|number| *number > 0)
        .ok_or_else(|| "delivered envelope has an invalid recipientDeviceNumber".to_owned())?;
    if recipient_account_id != account_id || recipient_device_number != local_device_number {
        return Err(
            "delivered envelope is not addressed to the authenticated local device".to_owned(),
        );
    }
    let envelope_type = value
        .get("envelopeType")
        .and_then(Value::as_i64)
        .and_then(|number| i32::try_from(number).ok())
        .filter(|number| *number >= 0)
        .ok_or_else(|| "delivered envelope has an invalid envelopeType".to_owned())?;
    let is_prekey_message = value
        .get("isPrekeyMessage")
        .and_then(Value::as_bool)
        .ok_or_else(|| "delivered envelope has an invalid isPrekeyMessage".to_owned())?;
    let ciphertext = required_string("ciphertext")?.to_owned();
    hex::decode(&ciphertext)
        .map_err(|_| "delivered envelope ciphertext is not valid hex".to_owned())?;
    let client_timestamp = receive_safe_integer(value.get("clientTimestamp"))
        .and_then(|number| i64::try_from(number).ok())
        .ok_or_else(|| "delivered envelope has an invalid clientTimestamp".to_owned())?;
    let conversation_id = match value.get("conversationId") {
        Some(Value::Null) => None,
        Some(Value::String(id)) if is_history_uuid(id) => Some(id.clone()),
        _ => return Err("delivered envelope has an invalid conversationId".to_owned()),
    };
    if value.get("senderIsBot").and_then(Value::as_bool).is_none() {
        return Err("delivered envelope has an invalid senderIsBot".to_owned());
    }
    if let Some(send_at) = value.get("sendAt") {
        if receive_safe_integer(Some(send_at)).is_none() {
            return Err("delivered envelope has an invalid sendAt".to_owned());
        }
    }

    let mut normalized = serde_json::Map::new();
    for field in [
        "envelopeId",
        "senderAccountId",
        "senderDeviceNumber",
        "recipientAccountId",
        "recipientDeviceNumber",
        "envelopeType",
        "isPrekeyMessage",
        "ciphertext",
        "clientTimestamp",
        "conversationId",
        "senderIsBot",
    ] {
        normalized.insert(
            field.to_owned(),
            value
                .get(field)
                .expect("required envelope fields were validated")
                .clone(),
        );
    }
    if let Some(send_at) = value.get("sendAt") {
        normalized.insert("sendAt".to_owned(), send_at.clone());
    }

    Ok(DeliveredEnvelope {
        value: Value::Object(normalized),
        envelope_id,
        sender_account_id,
        sender_device_number,
        recipient_account_id,
        recipient_device_number,
        envelope_type,
        is_prekey_message,
        ciphertext,
        client_timestamp,
        conversation_id,
    })
}

fn receive_safe_integer(value: Option<&Value>) -> Option<u64> {
    let number = value?.as_f64()?;
    (number.is_finite()
        && number >= 0.0
        && number <= 9_007_199_254_740_991.0
        && number.fract() == 0.0)
        .then_some(number as u64)
}

fn prepare_received_commit(
    account_id: &str,
    local_device_number: u32,
    envelope: &DeliveredEnvelope,
) -> JsResult<(Value, String, Value, String)> {
    let plaintext_hex = decrypt_received_envelope(account_id, local_device_number, envelope)?;
    if envelope.envelope_type == SENDER_KEY {
        crate::signal::process_sender_key_distribution(
            account_id,
            &envelope.sender_account_id,
            envelope.sender_device_number,
            &plaintext_hex,
        )?;
    }
    let plaintext = hex::decode(plaintext_hex).map_err(|error| js_error(&error.to_string()))?;
    let metadata = ReceiveMetadata {
        envelope_id: &envelope.envelope_id,
        client_timestamp: envelope.client_timestamp,
        local_account_id: Some(account_id),
        sender_account_id: Some(&envelope.sender_account_id),
        sender_device_number: Some(i64::from(envelope.sender_device_number)),
        recipient_account_id: Some(&envelope.recipient_account_id),
        recipient_device_number: Some(i64::from(envelope.recipient_device_number)),
        conversation_id: envelope.conversation_id.as_deref(),
    };
    let semantic = parse_decrypted_payload(i64::from(envelope.envelope_type), metadata, &plaintext);
    let (kind, payload) = classify_received_semantic(envelope.envelope_type, semantic);
    let identity_changes =
        serde_json::from_str::<Value>(&crate::signal::identity_changes(account_id)?)
            .map_err(|error| js_error(&format!("invalid Signal identity-change state: {error}")))?;
    let post_decrypt_snapshot = crate::signal::snapshot(account_id)?;
    let commit = receive_commit_payload(
        account_id,
        local_device_number,
        envelope,
        &kind,
        &payload,
        &identity_changes,
        &post_decrypt_snapshot,
    )
    .map_err(|error| js_error(&error))?;
    Ok((commit, kind, payload, post_decrypt_snapshot))
}

fn decrypt_received_envelope(
    account_id: &str,
    local_device_number: u32,
    envelope: &DeliveredEnvelope,
) -> JsResult<String> {
    if envelope.envelope_type == MESSAGE {
        if !envelope.is_prekey_message
            && received_ciphertext_is_group(&envelope.ciphertext)
                .map_err(|error| js_error(&error))?
        {
            return crate::signal::group_decrypt(
                account_id,
                &envelope.sender_account_id,
                envelope.sender_device_number,
                &envelope.ciphertext,
            );
        }
    }
    if matches!(
        envelope.envelope_type,
        SYNC | SENDER_KEY | EDIT | DELETE | REACTION | ATTACHMENT_KEY
    ) || is_call_signal_type(envelope.envelope_type)
        || envelope.envelope_type == MESSAGE
    {
        return crate::signal::decrypt(
            account_id,
            &envelope.sender_account_id,
            envelope.sender_device_number,
            local_device_number,
            &envelope.ciphertext,
            envelope.is_prekey_message,
        );
    }
    // WEB deliberately does not try to decrypt envelope types it does not
    // handle. The unknown-envelope event still goes through host commit/ACK.
    Ok(String::new())
}

fn is_call_signal_type(envelope_type: i32) -> bool {
    (EnvelopeType::CallOffer as i32..=EnvelopeType::CallReject as i32).contains(&envelope_type)
}

fn classify_received_semantic(
    envelope_type: i32,
    semantic: Option<SemanticPayload>,
) -> (String, Value) {
    if envelope_type == SENDER_KEY {
        ("sender_key_received".to_owned(), Value::Null)
    } else if let Some(semantic) = semantic {
        (semantic.kind.to_owned(), semantic.payload)
    } else if is_call_signal_type(envelope_type) {
        // WEB retains the call event even when its payload is malformed; the
        // call layer receives null and decides whether it can act on it.
        ("call_signal_received".to_owned(), Value::Null)
    } else {
        ("ignored".to_owned(), Value::Null)
    }
}

fn received_ciphertext_is_group(ciphertext_hex: &str) -> Result<bool, String> {
    let ciphertext = hex::decode(ciphertext_hex).map_err(|error| error.to_string())?;
    Ok(ciphertext.first() == Some(&GROUP_CIPHERTEXT_PREFIX))
}

fn receive_commit_payload(
    account_id: &str,
    local_device_number: u32,
    envelope: &DeliveredEnvelope,
    kind: &str,
    payload: &Value,
    identity_changes: &Value,
    signal_snapshot: &str,
) -> Result<Value, String> {
    let history = if matches!(kind, "history_chunk_received" | "history_complete_received") {
        let chunk = parse_history_chunk(payload)
            .ok_or_else(|| "typed history event did not contain a valid WEB chunk".to_owned())?;
        if envelope.conversation_id.as_deref() != Some(chunk.conversation_id.as_str()) {
            return Err(
                "history chunk does not match the delivered envelope conversation".to_owned(),
            );
        }
        let durable_chunk = serde_json::to_value(&chunk).map_err(|error| error.to_string())?;
        let item_kind = match chunk.item_kind {
            HistoryItemKind::Message => "message",
            HistoryItemKind::Attachment => "attachment",
            HistoryItemKind::Complete => "complete",
        };
        json!({
            "durability": if chunk.item_kind == HistoryItemKind::Complete { "completion" } else { "fragment" },
            "eventId": envelope.envelope_id,
            "sourceDeviceNumber": envelope.sender_device_number,
            "transferId": chunk.transfer_id,
            "conversationId": chunk.conversation_id,
            "itemKind": item_kind,
            "itemId": chunk.item_id,
            "partIndex": chunk.part_index,
            "partCount": chunk.part_count,
            "storageKey": {
                "accountId": account_id,
                "sourceDeviceNumber": envelope.sender_device_number,
                "transferId": chunk.transfer_id,
                "conversationId": chunk.conversation_id,
                "itemKind": item_kind,
                "itemId": chunk.item_id,
                "partIndex": chunk.part_index,
            },
            "chunk": durable_chunk,
        })
    } else {
        Value::Null
    };
    Ok(json!({
        "contractVersion": 1,
        "phase": "commit",
        "accountId": account_id,
        "localDeviceNumber": local_device_number,
        "eventId": envelope.envelope_id,
        "envelope": envelope.value,
        "kind": kind,
        "payload": payload,
        "identityChanges": identity_changes,
        "signalSnapshot": signal_snapshot,
        "history": history,
    }))
}

fn receive_commit_reply(value: &Value, commit_phase: bool) -> Result<bool, String> {
    if !value.is_object() {
        return Err("receive_transaction must resolve to an object".to_owned());
    }
    let committed = value
        .get("committed")
        .and_then(Value::as_bool)
        .ok_or_else(|| "receive_transaction reply omitted boolean committed".to_owned())?;
    if commit_phase && !committed {
        return Err("receive_transaction did not confirm durable commit".to_owned());
    }
    Ok(committed)
}

async fn call_receive_transaction(
    callback: &Function,
    request: &Value,
    commit_phase: bool,
) -> JsResult<bool> {
    let result = callback.call1(&JsValue::UNDEFINED, &json_to_js(request)?)?;
    let result = JsFuture::from(Promise::resolve(&result)).await?;
    let result = js_to_json(result)?;
    receive_commit_reply(&result, commit_phase).map_err(|error| js_error(&error))
}

async fn acknowledge_received_envelope(
    push: &BrowserPushClient,
    envelope_id: &str,
) -> JsResult<()> {
    let ids = Array::new();
    ids.push(&JsValue::from_str(envelope_id));
    JsFuture::from(push.ack_envelopes(ids.into())).await?;
    Ok(())
}

fn rollback_receive_failure(
    account_id: &str,
    event_id: &str,
    pre_decrypt_snapshot: &str,
    error: String,
) -> JsResult<JsValue> {
    match crate::signal::restore(account_id, pre_decrypt_snapshot) {
        Ok(()) => receive_failure(Some(event_id), error),
        Err(restore_error) => receive_failure(
            Some(event_id),
            format!(
                "{error}; restoring pre-decrypt Signal state also failed: {}",
                js_value_message(&restore_error)
            ),
        ),
    }
}

fn receive_failure(event_id: Option<&str>, error: String) -> JsResult<JsValue> {
    let mut result = json!({
        "ok": false,
        "committed": false,
        "acked": false,
        "error": error,
    });
    if let (Some(event_id), Some(object)) = (event_id, result.as_object_mut()) {
        object.insert("eventId".to_owned(), Value::String(event_id.to_owned()));
    }
    json_to_js(&result)
}

fn receive_result(
    ok: bool,
    committed: bool,
    acked: bool,
    duplicate: bool,
    event_id: &str,
    kind: Option<String>,
    payload: Option<Value>,
    signal_snapshot: Option<String>,
    error: Option<String>,
) -> JsResult<JsValue> {
    let mut result = json!({
        "ok": ok,
        "committed": committed,
        "acked": acked,
        "duplicate": duplicate,
        "eventId": event_id,
    });
    let object = result
        .as_object_mut()
        .ok_or_else(|| js_error("receive result must be an object"))?;
    if let Some(kind) = kind {
        object.insert("kind".to_owned(), Value::String(kind));
    }
    if let Some(payload) = payload {
        object.insert("payload".to_owned(), payload);
    }
    if let Some(signal_snapshot) = signal_snapshot {
        object.insert("signalSnapshot".to_owned(), Value::String(signal_snapshot));
    }
    if let Some(error) = error {
        object.insert("error".to_owned(), Value::String(error));
    }
    json_to_js(&result)
}

fn result_object(
    ok: bool,
    queued: bool,
    snapshot_persisted: bool,
    snapshot: Option<String>,
    error: Option<String>,
    details: Option<Value>,
) -> JsResult<JsValue> {
    let mut object = Map::new();
    object.insert("ok".into(), Value::Bool(ok));
    object.insert("queued".into(), Value::Bool(queued));
    object.insert("snapshotPersisted".into(), Value::Bool(snapshot_persisted));
    if let Some(snapshot) = snapshot {
        object.insert("signalSnapshot".into(), Value::String(snapshot));
    }
    if let Some(error) = error {
        object.insert("error".into(), Value::String(error));
    }
    if let Some(details) = details {
        if let Some(details) = details.as_object() {
            object.extend(details.clone());
        }
    }
    json_to_js(&Value::Object(object))
}

async fn persist_snapshot_callback(
    callback: &Function,
    account_id: &str,
    snapshot: &str,
) -> JsResult<()> {
    let result = callback.call2(
        &JsValue::UNDEFINED,
        &JsValue::from_str(account_id),
        &JsValue::from_str(snapshot),
    )?;
    JsFuture::from(Promise::resolve(&result)).await?;
    Ok(())
}

fn js_to_json(value: JsValue) -> JsResult<Value> {
    super::super::js_value_to_json(value).map_err(|error| error.into_js())
}

fn json_to_js(value: &Value) -> JsResult<JsValue> {
    super::super::json_to_js_value(value).map_err(|error| error.into_js())
}

fn js_error(message: &str) -> JsValue {
    js_sys::Error::new(message).into()
}

fn js_value_message(value: &JsValue) -> String {
    Reflect::get(value, &JsValue::from_str("message"))
        .ok()
        .and_then(|message| message.as_string())
        .filter(|message| !message.is_empty())
        .or_else(|| value.as_string())
        .unwrap_or_else(|| format!("{value:?}"))
}

fn is_unreachable_device(error: &JsValue) -> bool {
    let status = Reflect::get(error, &JsValue::from_str("status"))
        .ok()
        .and_then(|status| status.as_f64())
        .map(|status| status as u16);
    let code = Reflect::get(error, &JsValue::from_str("code"))
        .ok()
        .and_then(|code| code.as_string());
    status == Some(404) || code.as_deref() == Some("replenish_required")
}

fn string_array_field(value: &Value, field: &str) -> JsResult<Vec<String>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| js_error(&format!("response is missing {field} array")))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| js_error(&format!("response {field} contains a non-string value")))
        })
        .collect()
}

fn nonempty_string_field<'a>(value: &'a Value, field: &str) -> JsResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| js_error(&format!("response is missing {field}")))
}

fn number_field(value: &Value, camel: &str, snake: &str) -> JsResult<Option<u64>> {
    let field = value.get(camel).or_else(|| value.get(snake));
    match field {
        None => Ok(None),
        Some(Value::Number(number)) => number
            .as_u64()
            .map(Some)
            .ok_or_else(|| js_error(&format!("device field {camel} must be an unsigned integer"))),
        Some(_) => Err(js_error(&format!("device field {camel} must be a number"))),
    }
}

fn uuid_v7() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    let timestamp_ms = current_unix_millis();
    for (index, shift) in (0..6).rev().enumerate() {
        bytes[index] = ((timestamp_ms >> (shift * 8)) & 0xff) as u8;
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

fn current_unix_seconds() -> u64 {
    current_unix_millis() / 1_000
}

#[cfg(target_arch = "wasm32")]
fn current_unix_millis() -> u64 {
    Date::now().max(0.0) as u64
}

#[cfg(not(target_arch = "wasm32"))]
fn current_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn web_message_payload_keeps_stable_caller_id_and_seconds() {
        let payload = json!({
            "text": "hello",
            "replyTo": { "messageId": "11111111-1111-4111-8111-111111111111", "preview": "quoted" },
            "attachmentIds": ["22222222-2222-4222-8222-222222222222"],
        });
        let encoded = encode_message_payload(
            "33333333-3333-4333-8333-333333333333",
            &payload,
            1_777_777_777.0,
        )
        .unwrap();
        let decoded: Value = serde_json::from_slice(&hex::decode(encoded).unwrap()).unwrap();
        assert_eq!(
            decoded["message_id"],
            "33333333-3333-4333-8333-333333333333"
        );
        assert_eq!(decoded["created_at"], 1_777_777_777_u64);
        assert_eq!(
            decoded["reply_to"]["message_id"],
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(
            decoded["attachment_ids"][0],
            "22222222-2222-4222-8222-222222222222"
        );
    }

    #[test]
    fn envelope_wire_shape_matches_web_and_omits_unscheduled_send_at() {
        let options = EnvelopeOptions::new(123.0, None).unwrap();
        let envelope = pairwise_envelope(
            "11111111-1111-4111-8111-111111111111",
            7,
            "22222222-2222-4222-8222-222222222222",
            3,
            MESSAGE,
            true,
            "aabbcc",
            Some("33333333-3333-4333-8333-333333333333"),
            options,
        );
        assert_eq!(envelope["envelopeType"], MESSAGE);
        assert_eq!(envelope["clientTimestamp"], 123);
        assert_eq!(envelope["isPrekeyMessage"], true);
        assert!(envelope.get("sendAt").is_none());
        assert_eq!(envelope["senderDeviceNumber"], 7);
        assert_eq!(envelope["recipientDeviceNumber"], 3);
        assert!(uuid::Uuid::parse_str(envelope["envelopeId"].as_str().unwrap()).is_ok());
        assert_eq!(
            envelope["envelopeId"].as_str().unwrap().as_bytes()[14],
            b'7'
        );
    }

    #[test]
    fn scheduled_envelope_preserves_send_time_and_group_ciphertext_is_not_prekey() {
        let options = EnvelopeOptions::new(100.0, Some(200.0)).unwrap();
        let envelope = pairwise_envelope(
            "11111111-1111-4111-8111-111111111111",
            1,
            "22222222-2222-4222-8222-222222222222",
            2,
            MESSAGE,
            false,
            "ccdd",
            Some("33333333-3333-4333-8333-333333333333"),
            options,
        );
        assert_eq!(envelope["sendAt"], 200);
        assert_eq!(envelope["isPrekeyMessage"], false);
    }

    #[test]
    fn action_payloads_match_web_wire_names_and_null_reaction_removes_it() {
        let target = "11111111-1111-4111-8111-111111111111";
        let (kind, envelope_type, edit) = message_action_payload(
            target,
            &json!({
                "kind": "edit", "newText": "new"
            }),
            321.0,
        )
        .unwrap();
        assert_eq!(kind, "edit");
        assert_eq!(envelope_type, EDIT);
        assert_eq!(edit["target_message_id"], target);
        assert_eq!(edit["edited_at"], 321.0);

        let (kind, envelope_type, reaction) =
            message_action_payload(target, &json!({ "kind": "reaction", "emoji": null }), 322.0)
                .unwrap();
        assert_eq!(kind, "reaction");
        assert_eq!(envelope_type, REACTION);
        assert_eq!(reaction["emoji"], Value::Null);
        assert_eq!(reaction["created_at"], 322.0);
    }

    #[test]
    fn attachment_key_payload_has_web_contract() {
        let payload = json!({
            "kind": "attachment_key",
            "attachment_id": "11111111-1111-4111-8111-111111111111",
            "key_hex": "aabb",
            "base_nonce_hex": "ccdd",
            "conversation_id": null,
        });
        assert_eq!(payload["kind"], "attachment_key");
        assert!(payload["conversation_id"].is_null());
        assert_eq!(ATTACHMENT_KEY, EnvelopeType::AttachmentKey as i32);
    }

    #[test]
    fn scheduled_and_message_timestamps_reject_fractional_or_negative_values() {
        assert!(checked_unix_seconds(-1.0, "created_at").is_err());
        assert!(checked_unix_seconds(1.1, "created_at").is_err());
        assert!(checked_unix_seconds(f64::INFINITY, "send_at").is_err());
    }

    fn history_message(id: &str) -> Value {
        json!({
            "message": {
                "kind": "message",
                "message_id": id,
                "text": "history",
                "reply_to": null,
                "forward_from": null,
                "attachment_ids": [],
                "created_at": 1_777_777_777_u64,
            },
            "sender_account_id": "11111111-1111-4111-8111-111111111111",
            "sender_device_number": 2,
            "server_timestamp": 1_777_777_778_u64,
            "edited_at": null,
            "reactions": [],
        })
    }

    fn history_records(conversation_id: &str) -> Value {
        let message_id = "22222222-2222-4222-8222-222222222222";
        json!([
            {
                "conversationId": conversation_id,
                "itemKind": "attachment",
                "itemId": "33333333-3333-4333-8333-333333333333",
                "item": {
                    "attachment_id": "33333333-3333-4333-8333-333333333333",
                    "key_hex": "aabb".repeat(16),
                    "base_nonce_hex": "aabbccdd",
                    "file_name": null,
                    "content_type": "image/png",
                    "total_size": 17,
                    "chunk_count": 1,
                    "kind": "attachment",
                },
            },
            {
                "conversationId": conversation_id,
                "itemKind": "message",
                "itemId": message_id,
                "item": history_message(message_id),
            }
        ])
    }

    #[test]
    fn history_request_caps_raw_conversation_count_and_deduplicates_in_order() {
        let id = "11111111-1111-4111-8111-111111111111";
        let ids = validate_history_conversation_ids(&json!([id, id])).unwrap();
        assert_eq!(ids, vec![id.to_owned()]);

        let too_many = Value::Array((0..201).map(|_| json!(id)).collect());
        assert!(validate_history_conversation_ids(&too_many).is_err());
        assert!(validate_history_conversation_ids(&json!(["not-a-uuid"])).is_err());
    }

    #[test]
    fn history_records_require_web_snake_case_payload_and_requested_conversations() {
        let conversation_id = "44444444-4444-4444-8444-444444444444";
        let allowed = vec![conversation_id.to_owned()];
        let parsed = parse_history_send_items(&allowed, &history_records(conversation_id)).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].item_kind, HistoryItemKind::Attachment);
        assert!(
            parse_history_send_items(
                &allowed,
                &json!([{
                    "conversationId": conversation_id,
                    "itemKind": "message",
                    "itemId": "22222222-2222-4222-8222-222222222222",
                    "item": { "message": { "kind": "message", "messageId": "wrong-camel-case" } },
                }])
            )
            .is_err()
        );
        assert!(
            parse_history_send_items(
                &allowed,
                &json!([{
                    "conversationId": "55555555-5555-4555-8555-555555555555",
                    "itemKind": "message",
                    "itemId": "22222222-2222-4222-8222-222222222222",
                    "item": history_message("22222222-2222-4222-8222-222222222222"),
                }])
            )
            .is_err()
        );
    }

    #[test]
    fn history_completion_count_counts_messages_and_chunk_ids_are_stable() {
        let conversation_id = "44444444-4444-4444-8444-444444444444";
        let transfer_id = "66666666-6666-4666-8666-666666666666";
        let items = parse_history_send_items(
            &[conversation_id.to_owned()],
            &history_records(conversation_id),
        )
        .unwrap();
        let completion = history_completion_item(history_message_count(&items));
        assert_eq!(completion, json!({ "message_count": 1 }));
        let chunks = history_chunks_for_conversation(transfer_id, conversation_id, &items).unwrap();
        assert!(chunks.iter().all(|chunk| chunk.transfer_id == transfer_id));
        let marker = chunks
            .iter()
            .find(|chunk| chunk.item_kind == HistoryItemKind::Complete)
            .unwrap();
        assert_eq!(marker.item_id, conversation_id);
        assert_eq!(marker.part_index, 0);
        assert_eq!(marker.part_count, 1);
    }

    #[test]
    fn history_messages_are_fragmented_at_the_shared_twenty_four_kibibyte_limit() {
        let conversation_id = "44444444-4444-4444-8444-444444444444";
        let message_id = "22222222-2222-4222-8222-222222222222";
        let mut record = history_message(message_id);
        record["message"]["text"] = Value::String("x".repeat(25 * 1024));
        let items = parse_history_send_items(
            &[conversation_id.to_owned()],
            &json!([{
                "conversationId": conversation_id,
                "itemKind": "message",
                "itemId": message_id,
                "item": record,
            }]),
        )
        .unwrap();
        let chunks = history_chunks_for_conversation(
            "66666666-6666-4666-8666-666666666666",
            conversation_id,
            &items,
        )
        .unwrap();
        let message_chunks = chunks
            .iter()
            .filter(|chunk| chunk.item_kind == HistoryItemKind::Message)
            .collect::<Vec<_>>();
        assert_eq!(message_chunks.len(), 2);
        assert!(message_chunks.iter().all(|chunk| chunk.part_count == 2));
        assert_eq!(message_chunks[0].part_index, 0);
        assert_eq!(message_chunks[1].part_index, 1);
    }

    fn http_history_row(
        envelope_id: &str,
        conversation_id: &str,
        server_timestamp: i64,
        envelope_type: i32,
    ) -> Value {
        json!({
            "envelopeId": envelope_id,
            "senderAccountId": "11111111-1111-4111-8111-111111111111",
            "senderDeviceNumber": 2,
            "recipientDeviceNumber": 3,
            "envelopeType": envelope_type,
            "isPrekeyMessage": false,
            "ciphertext": "aabb",
            "clientTimestamp": 1_777_777_777_i64,
            "serverTimestamp": server_timestamp,
            "conversationId": conversation_id,
        })
    }

    #[test]
    fn http_history_query_matches_web_pagination_and_accepts_saved_before_only_cursor() {
        assert_eq!(
            parse_history_page_query_value(&Value::Null, 200).unwrap(),
            HistoryPageQuery {
                before: None,
                before_id: None,
                limit: 200
            },
        );
        let query = parse_history_page_query_value(
            &json!({ "before": 123, "beforeId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "limit": 75 }),
            100,
        ).unwrap();
        assert_eq!(query.before, Some(123));
        assert_eq!(
            query.before_id.as_deref(),
            Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        );
        assert_eq!(query.limit, 75);
        assert_eq!(
            history_query_json(&query),
            json!({
                "before": 123,
                "beforeId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "limit": 75,
            })
        );

        let before_only =
            parse_history_page_query_value(&json!({ "before": 123, "limit": 75 }), 100).unwrap();
        assert_eq!(
            before_only,
            HistoryPageQuery {
                before: Some(123),
                before_id: None,
                limit: 75,
            }
        );
        assert_eq!(
            history_query_json(&before_only),
            json!({ "before": 123, "limit": 75 })
        );

        assert!(
            parse_history_page_query_value(
                &json!({ "beforeId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }),
                100
            )
            .is_err()
        );
        assert!(parse_history_page_query_value(&json!({ "limit": 501 }), 100).is_err());
    }

    #[test]
    fn known_http_history_ids_are_bounded_deduplicated_and_uuid_validated() {
        let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let known = validate_known_history_ids(&json!([id, id])).unwrap();
        assert_eq!(known.len(), 1);
        assert!(validate_known_history_ids(&json!(["not-a-uuid"])).is_err());
        assert!(validate_known_history_ids(&json!("not-an-array")).is_err());
        assert!(
            validate_known_history_ids(&Value::Array(
                (0..=HISTORY_REPLAY_MAX_KNOWN_IDS)
                    .map(|_| json!(id))
                    .collect()
            ))
            .is_err()
        );
    }

    #[test]
    fn http_history_orders_rows_by_server_time_then_envelope_id_and_keeps_bad_context_unavailable()
    {
        let conversation = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let mut rows = vec![
            parse_http_history_envelope(http_history_row(
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                conversation,
                20,
                MESSAGE,
            ))
            .unwrap(),
            parse_http_history_envelope(http_history_row(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                conversation,
                10,
                MESSAGE,
            ))
            .unwrap(),
            parse_http_history_envelope(http_history_row(
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                conversation,
                20,
                MESSAGE,
            ))
            .unwrap(),
        ];
        order_http_history_rows(&mut rows);
        assert_eq!(
            rows.iter()
                .map(|row| row.envelope_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            ]
        );
        let foreign = parse_http_history_envelope(http_history_row(
            "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            30,
            MESSAGE,
        ))
        .unwrap();
        assert_ne!(foreign.conversation_id.as_deref(), Some(conversation));
    }

    #[test]
    fn http_history_message_record_matches_web_storage_shape() {
        let account = "11111111-1111-4111-8111-111111111111";
        let conversation = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let message = parse_http_history_envelope(http_history_row(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            conversation,
            1_777_777_778,
            MESSAGE,
        ))
        .unwrap();
        let record = build_http_history_message(account, conversation, &message, &json!({
            "kind": "message",
            "message_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "text": "hello",
            "reply_to": { "message_id": "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "preview": "quote", "sender_account_id": account },
            "forward_from": {
                "original_message_id": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                "original_conversation_id": conversation,
                "original_sender_account_id": account,
                "original_sender_display": "A",
                "original_created_at": 17,
            },
            "attachment_ids": ["ffffffff-ffff-4fff-8fff-ffffffffffff"],
            "created_at": 1_777_777_777,
        }), 1_777_777_779).unwrap();
        assert_eq!(record["messageId"], "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
        assert_eq!(record["envelopeId"], message.envelope_id);
        assert_eq!(record["plaintext"], "hello");
        assert_eq!(record["status"], "sent");
        assert_eq!(
            record["replyTo"]["messageId"],
            "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        );
        assert_eq!(record["forwardFrom"]["originalCreatedAt"], 17);
        assert_eq!(
            record["attachments"][0],
            "ffffffff-ffff-4fff-8fff-ffffffffffff"
        );
        assert_eq!(record["serverTimestamp"], 1_777_777_778);
    }

    #[test]
    fn http_history_replay_decrypts_in_a_clone_without_advancing_live_ratchet() {
        let sender = uuid_v7();
        let recipient = uuid_v7();
        let conversation = uuid_v7();
        let envelope_id = uuid_v7();
        let message_id = uuid_v7();
        crate::signal::generate_identity(&sender, 71).unwrap();
        crate::signal::generate_identity(&recipient, 72).unwrap();
        let prekeys: Value =
            serde_json::from_str(&crate::signal::generate_prekeys(&recipient, 2).unwrap()).unwrap();
        let bundle = json!({
            "registration_id": 72,
            "device_number": 1,
            "identity_key_pub": crate::signal::local_identity_public(&recipient).unwrap(),
            "signed_prekey": prekeys["signed_prekey"],
            "kyber_last_resort": prekeys["kyber_last_resort"],
            "one_time_prekey": prekeys["one_time_prekeys"][0],
        });
        crate::signal::establish_session(&sender, &recipient, 1, 1, &bundle.to_string()).unwrap();
        let plaintext = json!({
            "kind": "message",
            "message_id": message_id,
            "text": "HTTP history payload",
            "reply_to": null,
            "forward_from": null,
            "attachment_ids": [],
            "created_at": 1_777_777_777,
        });
        let encrypted: Value = serde_json::from_str(
            &crate::signal::encrypt(
                &sender,
                &recipient,
                1,
                1,
                &hex::encode(plaintext.to_string()),
            )
            .unwrap(),
        )
        .unwrap();
        let mut row = http_history_row(&envelope_id, &conversation, 1_777_777_778, MESSAGE);
        row["senderAccountId"] = json!(sender);
        row["senderDeviceNumber"] = json!(1);
        row["recipientDeviceNumber"] = json!(1);
        row["isPrekeyMessage"] = encrypted["is_prekey_message"].clone();
        row["ciphertext"] = encrypted["ciphertext_hex"].clone();

        let base_snapshot = crate::signal::snapshot(&recipient).unwrap();
        let result =
            begin_history_replay_stage(&recipient, 1, &conversation, vec![row], HashSet::new())
                .unwrap();
        let token = result["replayToken"].as_str().unwrap();
        let stage = history_replay_stage(token).unwrap();
        assert_eq!(result["messages"].as_array().unwrap().len(), 1);
        assert_eq!(result["messages"][0]["messageId"], message_id);
        assert_eq!(result["messages"][0]["plaintext"], "HTTP history payload");
        assert!(same_snapshot(&stage.base_snapshot, &base_snapshot));
        assert!(!same_snapshot(&stage.staged_snapshot, &stage.base_snapshot));
        assert!(same_snapshot(
            &crate::signal::snapshot(&recipient).unwrap(),
            &base_snapshot
        ));

        crate::signal::restore(&recipient, &stage.staged_snapshot).unwrap();
        let followup: Value = serde_json::from_str(
            &crate::signal::encrypt(&sender, &recipient, 1, 1, &hex::encode("follow-up")).unwrap(),
        )
        .unwrap();
        let opened = crate::signal::decrypt(
            &recipient,
            &sender,
            1,
            1,
            followup["ciphertext_hex"].as_str().unwrap(),
            followup["is_prekey_message"].as_bool().unwrap(),
        )
        .unwrap();
        assert_eq!(hex::decode(opened).unwrap(), b"follow-up");

        discard_history_replay_stage(token);
        crate::signal::reset(&sender);
        crate::signal::reset(&recipient);
    }

    #[test]
    fn history_commit_callback_contract_carries_cas_snapshot_and_atomic_page_writes() {
        let stage = HistoryReplayStage {
            account_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            local_device_number: 3,
            conversation_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_owned(),
            base_snapshot: "{\"sessions\":[]}".to_owned(),
            staged_snapshot: "{\"sessions\":[\"next\"]}".to_owned(),
            result: json!({
                "messages": [{ "messageId": "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }],
                "attachmentKeys": [{ "attachmentId": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }],
                "progressIds": ["ffffffff-ffff-4fff-8fff-ffffffffffff"],
                "processedEnvelopeIds": ["ffffffff-ffff-4fff-8fff-ffffffffffff"],
                "skippedEnvelopeIds": [],
            }),
            expires_at: Instant::now() + HISTORY_REPLAY_STAGE_TTL,
        };
        let request =
            history_replay_transaction_request("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", &stage);
        assert_eq!(request["phase"], "commit");
        assert_eq!(
            request["replayToken"],
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        );
        assert_eq!(request["baseSignalSnapshot"], stage.base_snapshot);
        assert_eq!(request["signalSnapshot"], stage.staged_snapshot);
        assert_eq!(request["messages"], stage.result["messages"]);
        assert_eq!(request["attachmentKeys"], stage.result["attachmentKeys"]);
        assert_eq!(request["progressIds"], stage.result["progressIds"]);
        assert_eq!(
            request["rollbackEnvelopeIds"],
            stage.result["processedEnvelopeIds"]
        );
    }

    #[test]
    fn failed_outbound_preparation_restores_signal_state_before_reporting_error() {
        let account = uuid_v7();
        let base_snapshot = crate::signal::snapshot(&account).unwrap();
        crate::signal::generate_identity(&account, 91).unwrap();
        assert!(!same_snapshot(
            &crate::signal::snapshot(&account).unwrap(),
            &base_snapshot
        ));

        let result = rollback_signal_state_after_prepare_error(
            &account,
            &base_snapshot,
            Err::<(), _>(JsValue::NULL),
        );

        assert!(
            result.is_err(),
            "the original preparation error is preserved"
        );
        assert!(same_snapshot(
            &crate::signal::snapshot(&account).unwrap(),
            &base_snapshot
        ));
        crate::signal::reset(&account);
    }

    #[test]
    fn history_conflict_rollback_request_targets_only_that_page() {
        let stage = HistoryReplayStage {
            account_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            local_device_number: 3,
            conversation_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".to_owned(),
            base_snapshot: "{\"sessions\":[]}".to_owned(),
            staged_snapshot: "{\"sessions\":[\"next\"]}".to_owned(),
            result: json!({
                "messages": [{ "messageId": "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }],
                "attachmentKeys": [{ "attachmentId": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }],
                "progressIds": ["ffffffff-ffff-4fff-8fff-ffffffffffff"],
                "processedEnvelopeIds": ["ffffffff-ffff-4fff-8fff-ffffffffffff"],
            }),
            expires_at: Instant::now() + HISTORY_REPLAY_STAGE_TTL,
        };
        let request = history_replay_rollback_request(
            &stage.account_id,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            &stage,
        );

        assert_eq!(request["phase"], "rollback");
        assert_eq!(
            request["replayToken"],
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        );
        assert_eq!(request["accountId"], stage.account_id);
        assert_eq!(request["conversationId"], stage.conversation_id);
        assert_eq!(
            request["rollbackEnvelopeIds"],
            stage.result["processedEnvelopeIds"]
        );
        assert_eq!(request["progressIds"], stage.result["progressIds"]);
    }

    #[test]
    fn history_transaction_reply_requires_commit_or_explicit_conflict_and_rollback() {
        assert!(parse_history_replay_transaction_reply(&json!({}), "commit").is_err());
        let conflict = parse_history_replay_transaction_reply(
            &json!({ "committed": false, "conflict": true }),
            "commit",
        )
        .unwrap();
        assert!(!conflict.committed);
        assert!(conflict.conflict);
        assert!(!conflict.rolled_back);
        let committed =
            parse_history_replay_transaction_reply(&json!({ "committed": true }), "commit")
                .unwrap();
        assert!(committed.committed);
        assert!(
            parse_history_replay_transaction_reply(&json!({ "rolledBack": true }), "rollback",)
                .unwrap()
                .rolled_back
        );
        assert!(parse_history_replay_transaction_reply(&json!({}), "rollback").is_err());
    }

    #[test]
    fn signal_snapshot_comparison_ignores_hashmap_entry_order_only() {
        let left = json!({
            "sessions": [["peer-b", 2, "session-b"], ["peer-a", 1, "session-a"]],
            "pre_keys": [[2, "prekey-b"], [1, "prekey-a"]],
            "identity_changes": [{ "account_id": "peer-a", "device_number": 1 }],
        });
        let right = json!({
            "sessions": [["peer-a", 1, "session-a"], ["peer-b", 2, "session-b"]],
            "pre_keys": [[1, "prekey-a"], [2, "prekey-b"]],
            "identity_changes": [{ "account_id": "peer-a", "device_number": 1 }],
        });
        assert!(same_snapshot(&left.to_string(), &right.to_string()));

        let changed_journal_order = json!({
            "sessions": [["peer-a", 1, "session-a"], ["peer-b", 2, "session-b"]],
            "pre_keys": [[1, "prekey-a"], [2, "prekey-b"]],
            "identity_changes": [
                { "account_id": "peer-b", "device_number": 2 },
                { "account_id": "peer-a", "device_number": 1 },
            ],
        });
        assert!(!same_snapshot(
            &left.to_string(),
            &changed_journal_order.to_string()
        ));
    }

    fn delivered_envelope() -> Value {
        json!({
            "envelopeId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "senderAccountId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "senderDeviceNumber": 4,
            "recipientAccountId": "11111111-1111-4111-8111-111111111111",
            "recipientDeviceNumber": 2,
            "envelopeType": MESSAGE,
            "isPrekeyMessage": false,
            "ciphertext": "33aabb",
            "clientTimestamp": 1_777_777_777_u64,
            "conversationId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "senderIsBot": false,
            "sendAt": 0,
        })
    }

    #[test]
    fn received_envelope_validation_preserves_event_id_and_requires_local_recipient() {
        let account_id = "11111111-1111-4111-8111-111111111111";
        let envelope = parse_delivered_envelope(&delivered_envelope(), account_id, 2).unwrap();
        assert_eq!(envelope.envelope_id, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        assert_eq!(envelope.sender_device_number, 4);
        assert_eq!(envelope.recipient_device_number, 2);
        assert_eq!(envelope.envelope_type, MESSAGE);
        assert_eq!(
            envelope.conversation_id.as_deref(),
            Some("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
        );

        let mut foreign = delivered_envelope();
        foreign["recipientAccountId"] = json!("dddddddd-dddd-4ddd-8ddd-dddddddddddd");
        assert!(parse_delivered_envelope(&foreign, account_id, 2).is_err());
        assert!(parse_delivered_envelope(&delivered_envelope(), account_id, 3).is_err());
    }

    #[test]
    fn receive_commit_contract_preserves_durable_history_fragment_identity() {
        let account_id = "11111111-1111-4111-8111-111111111111";
        let mut value = delivered_envelope();
        value["envelopeType"] = json!(SYNC);
        let envelope = parse_delivered_envelope(&value, account_id, 2).unwrap();
        let chunk = json!({
            "kind": "history_sync",
            "version": 1,
            "transfer_id": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            "conversation_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "item_kind": "message",
            "item_id": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            "part_index": 1,
            "part_count": 3,
            "data": "YWJj",
        });
        let commit = receive_commit_payload(
            account_id,
            2,
            &envelope,
            "history_chunk_received",
            &chunk,
            &json!([]),
            "signal-snapshot",
        )
        .unwrap();

        assert_eq!(commit["eventId"], envelope.envelope_id);
        assert_eq!(commit["history"]["durability"], "fragment");
        assert_eq!(commit["history"]["eventId"], envelope.envelope_id);
        assert_eq!(commit["history"]["sourceDeviceNumber"], 4);
        assert_eq!(commit["history"]["transferId"], chunk["transfer_id"]);
        assert_eq!(commit["history"]["partIndex"], 1);
        assert_eq!(commit["history"]["partCount"], 3);
        assert_eq!(commit["history"]["chunk"], chunk);
        assert_eq!(commit["signalSnapshot"], "signal-snapshot");
    }

    #[test]
    fn receive_commit_reply_fails_closed_unless_indexeddb_confirms_commit() {
        assert_eq!(
            receive_commit_reply(&json!({ "committed": false }), false),
            Ok(false)
        );
        assert_eq!(
            receive_commit_reply(&json!({ "committed": true }), false),
            Ok(true)
        );
        assert!(receive_commit_reply(&json!({ "committed": false }), true).is_err());
        assert!(receive_commit_reply(&json!({}), false).is_err());
    }

    #[test]
    fn group_routing_uses_the_web_ciphertext_marker_not_signal_version_byte() {
        assert_eq!(received_ciphertext_is_group("33aabb"), Ok(true));
        assert_eq!(received_ciphertext_is_group("03aabb"), Ok(false));
        assert!(received_ciphertext_is_group("33aab").is_err());
    }

    #[test]
    fn received_semantic_routing_matches_web_control_event_behavior() {
        assert_eq!(
            classify_received_semantic(SENDER_KEY, None),
            ("sender_key_received".to_owned(), Value::Null)
        );
        assert_eq!(
            classify_received_semantic(EnvelopeType::CallOffer as i32, None),
            ("call_signal_received".to_owned(), Value::Null)
        );
        assert_eq!(
            classify_received_semantic(99, None),
            ("ignored".to_owned(), Value::Null)
        );
        assert_eq!(
            classify_received_semantic(
                MESSAGE,
                Some(SemanticPayload {
                    kind: "message_received",
                    payload: json!({ "message_id": "stable-envelope-id" }),
                }),
            ),
            (
                "message_received".to_owned(),
                json!({ "message_id": "stable-envelope-id" })
            )
        );
    }
}
