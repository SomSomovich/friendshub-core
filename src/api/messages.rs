use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::bearer;
use crate::crypto::device_cache;
use crate::crypto::manager::{decrypt_envelope, encrypt_for_device, establish_outbound_session};
use crate::crypto::send::{send_one, SentEnvelope};
use crate::db::auth as db_auth;
use crate::error::{Error, Result};
use crate::runtime::ActorState;

/// ENVELOPE_TYPE_MESSAGE from friendshub.proto.
pub(crate) const ENVELOPE_TYPE_MESSAGE: i32 = 1;
/// ENVELOPE_TYPE_SYNC from friendshub.proto.
pub(crate) const ENVELOPE_TYPE_SYNC: i32 = 2;

#[derive(Debug, Serialize, Deserialize)]
pub struct EstablishSessionRequest {
    pub recipient_account_id: String,
    pub device_number: i64,
    pub bundle: serde_json::Value,
}

pub async fn establish_session(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: EstablishSessionRequest = serde_json::from_slice(&payload)?;
    establish_outbound_session(state, &req.recipient_account_id, req.device_number, &req.bundle)
        .await
        .map_err(Error::from)?;
    Ok(br#"{"ok":true}"#.to_vec())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendRequest {
    pub recipient_account_id: String,
    pub device_number: i64,
    pub plaintext_hex: String,
    #[serde(default)]
    pub conversation_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendResponse {
    pub ciphertext_hex: String,
    pub is_prekey_message: bool,
    pub envelope_type: i32,
}

pub async fn send(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: SendRequest = serde_json::from_slice(&payload)?;
    let plaintext = hex::decode(&req.plaintext_hex)
        .map_err(|e| Error::InvalidPayload(format!("plaintext hex: {e}")))?;

    let (ciphertext, is_prekey) = encrypt_for_device(
        state,
        &req.recipient_account_id,
        req.device_number,
        &plaintext,
    )
    .await
    .map_err(Error::from)?;

    Ok(serde_json::to_vec(&SendResponse {
        ciphertext_hex: hex::encode(&ciphertext),
        is_prekey_message: is_prekey,
        envelope_type: ENVELOPE_TYPE_MESSAGE,
    })?)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptResponse {
    pub plaintext_hex: String,
}

pub async fn decrypt(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let envelope: serde_json::Value = serde_json::from_slice(&payload)?;
    let plaintext = decrypt_envelope(state, &envelope).await.map_err(Error::from)?;
    Ok(serde_json::to_vec(&DecryptResponse {
        plaintext_hex: hex::encode(&plaintext),
    })?)
}

// ---------------------------------------------------------------
// High-level send: recipients + own devices, in one call.
// ---------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub recipient_account_id: String,
    pub plaintext_hex: String,

    /// When absent, the message goes to every active device of the recipient.
    #[serde(default)]
    pub device_number: Option<i64>,

    #[serde(default)]
    pub conversation_id: Option<String>,

    /// When true, the cached device list is refetched first.
    #[serde(default)]
    pub refresh_devices: bool,

    /// When true (default), a copy of the outgoing message is sent to the
    /// caller's other devices, so their local conversation state stays in
    /// step with the one that sent it.
    #[serde(default = "default_true")]
    pub sync: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceError {
    pub device_number: i64,
    pub error: String,
}

#[derive(Debug, Serialize)]
pub struct SendMessageResponse {
    pub envelopes: Vec<SentEnvelope>,
    pub device_errors: Vec<DeviceError>,
    pub sync_envelopes: Vec<SentEnvelope>,
    pub sync_errors: Vec<DeviceError>,
}

/// Full send path: recipient devices, then own devices for sync.
///
/// A device that fails does not abort the batch. Per-device detail is more
/// useful to the caller than a single boolean. If every device fails on the
/// recipient side the response still returns, with an empty `envelopes` and
/// a populated `device_errors`; the caller decides whether to retry.
pub async fn send_message(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: SendMessageRequest = serde_json::from_slice(&payload)?;
    let plaintext = hex::decode(&req.plaintext_hex)
        .map_err(|e| Error::InvalidPayload(format!("plaintext hex: {e}")))?;

    let auth = db_auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;
    let sender_account_id = auth.account_id.clone().ok_or(Error::NotAuthenticated)?;
    let sender_device_number = auth.device_number.unwrap_or(1);

    let target_devices: Vec<i64> = match req.device_number {
        Some(d) => vec![d],
        None => {
            let devices = if req.refresh_devices {
                device_cache::force_refresh(state, &req.recipient_account_id).await?
            } else {
                device_cache::get(state, &req.recipient_account_id).await?
            };

            if devices.is_empty() {
                return Err(Error::InvalidPayload(format!(
                    "recipient {} has no active devices",
                    req.recipient_account_id
                )));
            }
            devices.into_iter().map(|d| d.device_number).collect()
        }
    };

    let token = bearer(state).await?;

    let mut envelopes = Vec::with_capacity(target_devices.len());
    let mut device_errors = Vec::new();

    for device_number in &target_devices {
        match send_one(
            state,
            &token,
            &sender_account_id,
            sender_device_number,
            &req.recipient_account_id,
            *device_number,
            &plaintext,
            ENVELOPE_TYPE_MESSAGE,
            req.conversation_id.as_deref(),
)
        .await
        {
            Ok(info) => envelopes.push(info),
            Err(e) => device_errors.push(DeviceError {
                device_number: *device_number,
                error: e.to_string(),
            }),
        }
    }

    let mut sync_envelopes = Vec::new();
    let mut sync_errors = Vec::new();

    if req.sync && !envelopes.is_empty() {
        let sync_payload = serde_json::json!({
            "kind": "sync_sent",
            "to_account": req.recipient_account_id,
            "to_devices": target_devices,
            "conversation_id": req.conversation_id,
            "plaintext_hex": req.plaintext_hex,
            "envelope_ids": envelopes.iter().map(|e| e.envelope_id.clone()).collect::<Vec<_>>(),
        });
        let sync_bytes = serde_json::to_vec(&sync_payload)?;

        match sync_to_own_devices(
            state,
            &token,
            &sender_account_id,
            sender_device_number,
            &sync_bytes,
            req.conversation_id.as_deref(),
)
        .await
        {
            Ok((envs, errs)) => {
                sync_envelopes = envs;
                sync_errors = errs;
            }
            Err(e) => {
                sync_errors.push(DeviceError {
                    device_number: 0,
                    error: format!("sync fanout failed: {e}"),
                });
            }
        }
    }

    Ok(serde_json::to_vec(&SendMessageResponse {
        envelopes,
        device_errors,
        sync_envelopes,
        sync_errors,
    })?)
}

async fn sync_to_own_devices(
    state: &Arc<ActorState>,
    token: &str,
    sender_account_id: &str,
    sender_device_number: i64,
    payload: &[u8],
    conversation_id: Option<&str>,
) -> Result<(Vec<SentEnvelope>, Vec<DeviceError>)> {
    let devices = device_cache::get(state, sender_account_id).await?;
    let mut envelopes = Vec::new();
    let mut errors = Vec::new();

    for d in devices {
        if d.device_number == sender_device_number {
            continue;
        }
        match send_one(
            state,
            token,
            sender_account_id,
            sender_device_number,
            sender_account_id,
            d.device_number,
            payload,
            ENVELOPE_TYPE_SYNC,
            conversation_id,
)
        .await
        {
            Ok(info) => envelopes.push(info),
            Err(e) => errors.push(DeviceError {
                device_number: d.device_number,
                error: e.to_string(),
            }),
        }
    }

    Ok((envelopes, errors))
}
