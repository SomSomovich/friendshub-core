//! Single-envelope send path, shared by messages, sync, and WebRTC signaling.
//!
//! One call, one recipient device: fetch the bundle when no session exists,
//! encrypt, upload. The caller picks the envelope_type and the recipient.

use std::sync::Arc;

use serde::Serialize;

use crate::crypto::manager::{encrypt_for_device, establish_outbound_session, has_session};
use crate::error::{Error, Result};
use crate::runtime::ActorState;
use crate::transport::ws::upload_envelope;
use crate::util::time::now_unix;

#[derive(Debug, Clone, Serialize)]
pub struct SentEnvelope {
    pub device_number: i64,
    pub envelope_id: String,
    pub is_prekey_message: bool,
    pub ciphertext_len: usize,
}

/// Sends one payload to one device.
///
/// `envelope_type` distinguishes semantics on the receiving side. It rides
/// in the Envelope struct outside the encryption, so two envelopes with the
/// same ciphertext but different types are different signals.
#[allow(clippy::too_many_arguments)]
pub async fn send_one(
    state: &Arc<ActorState>,
    token: &str,
    sender_account_id: &str,
    sender_device_number: i64,
    recipient_account_id: &str,
    device_number: i64,
    plaintext: &[u8],
    envelope_type: i32,
    conversation_id: Option<&str>,
) -> Result<SentEnvelope> {
    let have = has_session(state, recipient_account_id, device_number)
        .await
        .map_err(Error::from)?;

    if !have {
        let path = format!(
            "/api/v1/accounts/{recipient_account_id}/devices/{device_number}/bundle"
        );
        let bundle: serde_json::Value = state.http.get(&path, Some(token)).await?;
        establish_outbound_session(state, recipient_account_id, device_number, &bundle)
            .await
            .map_err(Error::from)?;
    }

    let (ciphertext, is_prekey) = encrypt_for_device(
        state,
        recipient_account_id,
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
        "recipient_account_id": recipient_account_id,
        "recipient_device_number": device_number,
        "envelope_type": envelope_type,
        "is_prekey_message": is_prekey,
        "ciphertext": hex::encode(&ciphertext),
        "client_timestamp": now_unix(),
        "conversation_id": conversation_id,
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
