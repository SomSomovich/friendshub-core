use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::crypto::manager::{decrypt_envelope, encrypt_for_device, establish_outbound_session};
use crate::error::{Error, Result};
use crate::runtime::ActorState;

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
        envelope_type: 1, // ENVELOPE_TYPE_MESSAGE
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
