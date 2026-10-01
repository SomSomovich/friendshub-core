use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::bearer;
use crate::crypto::device_cache;
use crate::crypto::manager::{
    decrypt_envelope, encrypt_for_device, establish_outbound_session, has_session,
};
use crate::db::auth as db_auth;
use crate::error::{Error, Result};
use crate::runtime::ActorState;
use crate::transport::ws::upload_envelope;
use crate::util::time::now_unix;

#[derive(Debug, Serialize, Deserialize)]
pub struct EstablishSessionRequest {
    pub recipient_account_id: String,
    pub device_number: i64,
    pub bundle: serde_json::Value,
}

pub async fn establish_session(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: EstablishSessionRequest = serde_json::from_slice(&payload)?;
    establish_outbound_session(
        state,
        &req.recipient_account_id,
        req.device_number,
        &req.bundle,
    )
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

/// Low-level single-device encrypt. Use `send_message` unless you need to
/// drive session management yourself.
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
        envelope_type: 1,
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
// High-level send: fetch device list, bundle, session, encrypt, upload.
// ---------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub recipient_account_id: String,
    /// Plaintext as hex: the same encoding that crosses the wire, so the JSON
    /// payload stays a single string and cannot trip over text encoding.
    pub plaintext_hex: String,

    /// Optional. When absent, the message goes to every active device of the
    /// recipient. When present, only that device receives a copy -- useful for
    /// retrying a device that failed on a previous attempt.
    #[serde(default)]
    pub device_number: Option<i64>,

    #[serde(default)]
    pub conversation_id: Option<String>,

    /// When true, the cached device list is discarded and refetched before
    /// sending. Use after learning that the recipient added a device.
    #[serde(default)]
    pub refresh_devices: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SentEnvelope {
    pub device_number: i64,
    pub envelope_id: String,
    pub is_prekey_message: bool,
    pub ciphertext_len: usize,
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
}

/// The whole send path in one call.
///
/// 1. Loads the local auth state.
/// 2. Resolves the target devices: either the single one in the request, or
///    every active device of the recipient (from cache, or freshly fetched).
/// 3. For each device: establishes a session when none exists, encrypts,
///    uploads the envelope.
///
/// A device that fails does not abort the whole send. The response carries
/// one entry per successful device and one error per failed device. The
/// caller decides what to do with partial success -- retry the failed
/// devices, surface the error to the user, or ignore it.
///
/// Device list TTL is `device_cache::CACHE_TTL_SECS`; pass
/// `refresh_devices: true` to bypass it.
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

    for device_number in target_devices {
        match send_to_one_device(
            state,
            &token,
            &sender_account_id,
            sender_device_number,
            &req,
            &plaintext,
            device_number,
        )
        .await
        {
            Ok(info) => envelopes.push(info),
            Err(e) => device_errors.push(DeviceError {
                device_number,
                error: e.to_string(),
            }),
        }
    }

    Ok(serde_json::to_vec(&SendMessageResponse {
        envelopes,
        device_errors,
    })?)
}

#[allow(clippy::too_many_arguments)]
async fn send_to_one_device(
    state: &Arc<ActorState>,
    token: &str,
    sender_account_id: &str,
    sender_device_number: i64,
    req: &SendMessageRequest,
    plaintext: &[u8],
    device_number: i64,
) -> Result<SentEnvelope> {
    // Establish a session only when one is missing. The local query is cheap;
    // the bundle fetch is a network round trip and is skipped entirely once a
    // session exists.
    let have = has_session(state, &req.recipient_account_id, device_number)
        .await
        .map_err(Error::from)?;

    if !have {
        let path = format!(
            "/api/v1/accounts/{}/devices/{}/bundle",
            req.recipient_account_id, device_number
        );
        let bundle: serde_json::Value = state.http.get(&path, Some(token)).await?;
        establish_outbound_session(
            state,
            &req.recipient_account_id,
            device_number,
            &bundle,
        )
        .await
        .map_err(Error::from)?;
    }

    let (ciphertext, is_prekey) = encrypt_for_device(
        state,
        &req.recipient_account_id,
        device_number,
        plaintext,
    )
    .await
    .map_err(Error::from)?;

    let envelope_id = uuid::Uuid::now_v7().to_string();

    let envelope = serde_json::json!({
        "envelope_id": envelope_id,
        "sender_account_id": sender_account_id,
        "sender_device_number": sender_device_number,
        "recipient_account_id": req.recipient_account_id,
        "recipient_device_number": device_number,
        "envelope_type": 1, // ENVELOPE_TYPE_MESSAGE
        "is_prekey_message": is_prekey,
        "ciphertext": hex::encode(&ciphertext),
        "client_timestamp": now_unix(),
        "conversation_id": req.conversation_id,
        "sender_is_bot": false,
    });

    upload_envelope(state, envelope).await?;

    Ok(SentEnvelope {
        device_number,
        envelope_id,
        is_prekey_message: is_prekey,
        ciphertext_len: ciphertext.len(),
    })
}
