use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::bearer;
use crate::crypto::device_cache;
use crate::crypto::groups;
use crate::crypto::send::send_one;
use crate::db::auth as db_auth;
use crate::error::{Error, Result};
use crate::runtime::ActorState;

/// ENVELOPE_TYPE_SENDER_KEY from friendshub.proto.
pub(crate) const ENVELOPE_TYPE_SENDER_KEY: i32 = 3;
/// ENVELOPE_TYPE_MESSAGE from friendshub.proto.
pub(crate) const ENVELOPE_TYPE_MESSAGE: i32 = 1;
/// ENVELOPE_TYPE_SYNC from friendshub.proto.
pub(crate) const ENVELOPE_TYPE_SYNC: i32 = 2;

// ---------------------------------------------------------------
// Create / rotate this device's sender key for a conversation
// ---------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateDistributionRequest {
    pub conversation_id: String,
    #[serde(default)]
    pub rotate: bool,
}

#[derive(Debug, Serialize)]
pub struct DistributionEnvelope {
    pub recipient_account_id: String,
    pub device_number: i64,
    pub envelope_id: String,
}

#[derive(Debug, Serialize)]
pub struct CreateDistributionResponse {
    pub distribution_id: String,
    pub skdm_len: usize,
    pub envelopes: Vec<DistributionEnvelope>,
    pub device_errors: Vec<serde_json::Value>,
}

/// Generates this device's sender key for a group (or rotates it), then
/// distributes the public half to every device of every member.
pub async fn create_distribution(
    state: &Arc<ActorState>,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let req: CreateDistributionRequest = serde_json::from_slice(&payload)?;
    let members = member_account_ids(state, &req.conversation_id).await?;

    let dist_id = if req.rotate {
        groups::rotate_distribution(state, &req.conversation_id)
            .await
            .map_err(Error::from)?
    } else {
        groups::distribution_id_for(state, &req.conversation_id)
            .await
            .map_err(Error::from)?
    };

    let skdm = groups::create_distribution(state, &req.conversation_id)
        .await
        .map_err(Error::from)?;

    let auth = db_auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;
    let sender_account_id = auth.account_id.clone().ok_or(Error::NotAuthenticated)?;
    let sender_device_number = auth.device_number.unwrap_or(1);
    let token = bearer(state).await?;

    let mut envelopes = Vec::new();
    let mut errors: Vec<serde_json::Value> = Vec::new();

    for member_account_id in &members {
        let devices = match device_cache::get(state, member_account_id).await {
            Ok(d) => d,
            Err(e) => {
                errors.push(serde_json::json!({
                    "account_id": member_account_id,
                    "error": e.to_string(),
                }));
                continue;
            }
        };

        for d in devices {
            match send_one(
                state,
                &token,
                &sender_account_id,
                sender_device_number,
                member_account_id,
                d.device_number,
                &skdm,
                ENVELOPE_TYPE_SENDER_KEY,
                Some(&req.conversation_id),
)
            .await
            {
                Ok(info) => envelopes.push(DistributionEnvelope {
                    recipient_account_id: member_account_id.clone(),
                    device_number: d.device_number,
                    envelope_id: info.envelope_id,
                }),
                Err(e) => errors.push(serde_json::json!({
                    "account_id": member_account_id,
                    "device_number": d.device_number,
                    "error": e.to_string(),
                })),
            }
        }
    }

    Ok(serde_json::to_vec(&CreateDistributionResponse {
        distribution_id: dist_id.to_string(),
        skdm_len: skdm.len(),
        envelopes,
        device_errors: errors,
    })?)
}

// ---------------------------------------------------------------
// Encrypt once, fan out to every member device, sync to own devices
// ---------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SendGroupRequest {
    pub conversation_id: String,
    pub plaintext_hex: String,
    /// When true (default), a copy of the outgoing message is sent to the
    /// caller's own other devices, under ENVELOPE_TYPE_SYNC. Their local
    /// conversation state would otherwise not reflect what the caller sent.
    #[serde(default = "default_true")]
    pub sync: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize)]
pub struct SendGroupResponse {
    pub ciphertext_len: usize,
    pub envelopes: Vec<DistributionEnvelope>,
    pub device_errors: Vec<serde_json::Value>,
    pub sync_envelopes: Vec<DistributionEnvelope>,
    pub sync_errors: Vec<serde_json::Value>,
}

/// Encrypts the plaintext once for the whole group, then sends the same
/// SenderKeyMessage to every device of every member.
///
/// When `sync` is true, the caller's own other devices get a separate copy
/// through the pairwise session path. That copy is a small JSON payload that
/// tells the device "the following was sent by one of your sibling devices",
/// not the group ciphertext: a device cannot decrypt its own sender key
/// output, and does not need to.
pub async fn send_group_message(
    state: &Arc<ActorState>,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let req: SendGroupRequest = serde_json::from_slice(&payload)?;
    let plaintext = hex::decode(&req.plaintext_hex)
        .map_err(|e| Error::InvalidPayload(format!("plaintext hex: {e}")))?;

    let skm = groups::encrypt_for_group(state, &req.conversation_id, &plaintext)
        .await
        .map_err(Error::from)?;

    let members = member_account_ids(state, &req.conversation_id).await?;

    let auth = db_auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;
    let sender_account_id = auth.account_id.clone().ok_or(Error::NotAuthenticated)?;
    let sender_device_number = auth.device_number.unwrap_or(1);
    let token = bearer(state).await?;

    let mut envelopes = Vec::new();
    let mut errors: Vec<serde_json::Value> = Vec::new();

    for member_account_id in &members {
        if *member_account_id == sender_account_id {
            // A device cannot decrypt its own sender key output. Its sibling
            // devices receive the sync copy below instead.
            continue;
        }

        let devices = match device_cache::get(state, member_account_id).await {
            Ok(d) => d,
            Err(e) => {
                errors.push(serde_json::json!({
                    "account_id": member_account_id,
                    "error": e.to_string(),
                }));
                continue;
            }
        };

        for d in devices {
            match send_one(
                state,
                &token,
                &sender_account_id,
                sender_device_number,
                member_account_id,
                d.device_number,
                &skm,
                ENVELOPE_TYPE_MESSAGE,
                Some(&req.conversation_id),
)
            .await
            {
                Ok(info) => envelopes.push(DistributionEnvelope {
                    recipient_account_id: member_account_id.clone(),
                    device_number: d.device_number,
                    envelope_id: info.envelope_id,
                }),
                Err(e) => errors.push(serde_json::json!({
                    "account_id": member_account_id,
                    "device_number": d.device_number,
                    "error": e.to_string(),
                })),
            }
        }
    }

    let mut sync_envelopes = Vec::new();
    let mut sync_errors: Vec<serde_json::Value> = Vec::new();

    if req.sync && !envelopes.is_empty() {
        let sync_payload = serde_json::json!({
            "kind": "group_sync_sent",
            "conversation_id": req.conversation_id,
            "plaintext_hex": req.plaintext_hex,
            "recipient_envelope_ids": envelopes.iter().map(|e| e.envelope_id.clone()).collect::<Vec<_>>(),
        });
        let sync_bytes = serde_json::to_vec(&sync_payload)?;

        let own_devices = device_cache::get(state, &sender_account_id).await?;
        for d in own_devices {
            if d.device_number == sender_device_number {
                continue;
            }
            match send_one(
                state,
                &token,
                &sender_account_id,
                sender_device_number,
                &sender_account_id,
                d.device_number,
                &sync_bytes,
                ENVELOPE_TYPE_SYNC,
                Some(&req.conversation_id),
)
            .await
            {
                Ok(info) => sync_envelopes.push(DistributionEnvelope {
                    recipient_account_id: sender_account_id.clone(),
                    device_number: d.device_number,
                    envelope_id: info.envelope_id,
                }),
                Err(e) => sync_errors.push(serde_json::json!({
                    "device_number": d.device_number,
                    "error": e.to_string(),
                })),
            }
        }
    }

    Ok(serde_json::to_vec(&SendGroupResponse {
        ciphertext_len: skm.len(),
        envelopes,
        device_errors: errors,
        sync_envelopes,
        sync_errors,
    })?)
}

// ---------------------------------------------------------------
// Member resolution
// ---------------------------------------------------------------

/// Returns the account ids of everyone in the conversation, including the
/// caller. Only accounts, not bots. Order is not guaranteed.
async fn member_account_ids(
    state: &Arc<ActorState>,
    conversation_id: &str,
) -> Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT account_id FROM conversation_members WHERE conversation_id = ? AND left_at IS NULL",
    )
    .bind(conversation_id)
    .fetch_all(&state.db)
    .await?;

    Ok(rows.into_iter().map(|(a,)| a).collect())
}
