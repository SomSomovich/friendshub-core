//! Edit, delete, and reaction envelopes.
//!
//! These are ordinary Signal-encrypted envelopes with a different
//! `envelope_type`. The plaintext carries the action-specific fields.

use std::sync::Arc;

use serde::Deserialize;

use crate::api::common::bearer;
use crate::crypto::device_cache;
use crate::crypto::send::send_one;
use crate::db::auth as db_auth;
use crate::error::{Error, Result};
use crate::runtime::ActorState;

const ENVELOPE_TYPE_EDIT: i32 = 4;
const ENVELOPE_TYPE_DELETE: i32 = 5;
const ENVELOPE_TYPE_REACTION: i32 = 6;

#[derive(Debug, Deserialize)]
struct CommonFields {
    recipient_account_id: String,
    conversation_id: String,
    #[serde(default)]
    device_number: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct EditRequest {
    #[serde(flatten)]
    common: CommonFields,
    target_envelope_id: String,
    new_plaintext_hex: String,
}

pub async fn send_edit(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: EditRequest = serde_json::from_slice(&payload)?;
    let inner = serde_json::json!({
        "kind": "edit",
        "target_envelope_id": req.target_envelope_id,
        "new_plaintext_hex": req.new_plaintext_hex,
    });
    let inner_bytes = serde_json::to_vec(&inner)?;
    send_to_devices(
        state,
        &req.common.recipient_account_id,
        req.common.device_number,
        &inner_bytes,
        ENVELOPE_TYPE_EDIT,
        Some(&req.common.conversation_id),
)
    .await
}

#[derive(Debug, Deserialize)]
pub struct DeleteRequest {
    #[serde(flatten)]
    common: CommonFields,
    target_envelope_id: String,
}

pub async fn send_delete(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: DeleteRequest = serde_json::from_slice(&payload)?;
    let inner = serde_json::json!({
        "kind": "delete",
        "target_envelope_id": req.target_envelope_id,
    });
    let inner_bytes = serde_json::to_vec(&inner)?;
    send_to_devices(
        state,
        &req.common.recipient_account_id,
        req.common.device_number,
        &inner_bytes,
        ENVELOPE_TYPE_DELETE,
        Some(&req.common.conversation_id),
)
    .await
}

#[derive(Debug, Deserialize)]
pub struct ReactionRequest {
    #[serde(flatten)]
    common: CommonFields,
    target_envelope_id: String,
    /// Empty string removes the reaction.
    pub emoji: String,
}

pub async fn send_reaction(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: ReactionRequest = serde_json::from_slice(&payload)?;
    let inner = serde_json::json!({
        "kind": "reaction",
        "target_envelope_id": req.target_envelope_id,
        "emoji": req.emoji,
    });
    let inner_bytes = serde_json::to_vec(&inner)?;
    send_to_devices(
        state,
        &req.common.recipient_account_id,
        req.common.device_number,
        &inner_bytes,
        ENVELOPE_TYPE_REACTION,
        Some(&req.common.conversation_id),
)
    .await
}

async fn send_to_devices(
    state: &Arc<ActorState>,
    recipient: &str,
    device_number: Option<i64>,
    payload: &[u8],
    envelope_type: i32,
    conversation_id: Option<&str>,
) -> Result<Vec<u8>> {
    let auth = db_auth::load(&state.db).await?.ok_or(Error::NotAuthenticated)?;
    let sender_account_id = auth.account_id.ok_or(Error::NotAuthenticated)?;
    let sender_device_number = auth.device_number.unwrap_or(1);
    let token = bearer(state).await?;

    let devices: Vec<i64> = match device_number {
        Some(d) => vec![d],
        None => device_cache::get(state, recipient)
            .await?
            .into_iter()
            .map(|d| d.device_number)
            .collect(),
    };

    if devices.is_empty() {
        return Err(Error::InvalidPayload(format!(
            "recipient {recipient} has no active devices"
        )));
    }

    let mut envelopes = Vec::new();
    let mut errors = Vec::new();

    for d in devices {
        match send_one(
            state,
            &token,
            &sender_account_id,
            sender_device_number,
            recipient,
            d,
            payload,
            envelope_type,
            conversation_id,
)
        .await
        {
            Ok(info) => envelopes.push(info),
            Err(e) => errors.push(serde_json::json!({
                "device_number": d,
                "error": e.to_string(),
            })),
        }
    }

    Ok(serde_json::to_vec(&serde_json::json!({
        "envelopes": envelopes,
        "device_errors": errors,
    }))?)
}
