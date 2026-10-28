use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::{bearer, validate_scheduled_send_at};
use crate::api::conversations::ConversationDetail;
use crate::crypto::device_cache;
use crate::crypto::groups;
use crate::crypto::send::{SentEnvelope, send_one, send_one_with_send_at};
use crate::db::auth as db_auth;
use crate::error::{Error, Result};
use crate::runtime::ActorState;
use crate::transport::ws::upload_envelope;
use crate::util::time::now_unix;

/// ENVELOPE_TYPE_SENDER_KEY from friendshub.proto.
pub(crate) const ENVELOPE_TYPE_SENDER_KEY: i32 = 3;
/// ENVELOPE_TYPE_MESSAGE from friendshub.proto.
pub(crate) const ENVELOPE_TYPE_MESSAGE: i32 = 1;

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
pub async fn create_distribution(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
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
        if *member_account_id == sender_account_id {
            // Sender-key distributions go to other accounts only. Sibling
            // devices receive the outgoing message through pairwise SYNC.
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
                &pairwise_distribution_plaintext(&skdm),
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

#[derive(Debug, Serialize, Deserialize)]
pub struct SendGroupRequest {
    pub conversation_id: String,
    /// Hex-encoded shared message payload (the `message_payload` builder's
    /// JSON output), used for both group encryption and own-device sync.
    pub plaintext_hex: String,
    /// When true (default), a copy of the outgoing message is sent to the
    /// caller's own other devices, as ordinary MESSAGE envelopes. Their local
    /// conversation state would otherwise not reflect what the caller sent.
    #[serde(default = "default_true")]
    pub sync: bool,
}

/// Wrapper for the existing group-send request with optional scheduled
/// delivery. Serde flattens `request`, preserving the current JSON keys.
#[derive(Debug, Serialize, Deserialize)]
pub struct ScheduledSendGroupRequest {
    #[serde(flatten)]
    pub request: SendGroupRequest,
    /// Unix timestamp in seconds. `None` or zero means immediate delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_at: Option<i64>,
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

/// Encrypts the shared message payload once for the whole group, then sends
/// the same SenderKeyMessage to every device of every other member.
///
/// When `sync` is true, the caller's own other devices get the original shared
/// message payload through the pairwise session path. A device cannot decrypt
/// its own sender-key output, so sync carries the same plaintext payload that
/// was encrypted for the group.
pub async fn send_group_message(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let scheduled: ScheduledSendGroupRequest = serde_json::from_slice(&payload)?;
    let req = scheduled.request;
    let send_at = validate_scheduled_send_at(scheduled.send_at)?;
    let plaintext = hex::decode(&req.plaintext_hex)
        .map_err(|e| Error::InvalidPayload(format!("plaintext hex: {e}")))?;

    // Resolve authoritative membership before advancing the sender-key ratchet.
    // A failed server read must leave the local group key state untouched.
    let members = member_account_ids(state, &req.conversation_id).await?;
    let skm = groups::encrypt_for_group(state, &req.conversation_id, &plaintext)
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
            match send_sender_key_message(
                state,
                &sender_account_id,
                sender_device_number,
                member_account_id,
                d.device_number,
                &skm,
                &req.conversation_id,
                send_at,
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
        let own_devices = device_cache::get(state, &sender_account_id).await?;
        for d in own_devices {
            if d.device_number == sender_device_number {
                continue;
            }
            match send_one_with_send_at(
                state,
                &token,
                &sender_account_id,
                sender_device_number,
                &sender_account_id,
                d.device_number,
                // Keep the same shared message payload on sibling devices;
                // only the remote group members receive SenderKey ciphertext.
                &plaintext,
                ENVELOPE_TYPE_MESSAGE,
                Some(&req.conversation_id),
                send_at,
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

/// WEB hex-encodes the serialized SKDM, then UTF-8-hex encodes that string
/// before pairwise encryption. Pairwise decryption therefore yields the
/// serialized SKDM as ASCII hex, not as the raw binary message.
fn pairwise_distribution_plaintext(skdm: &[u8]) -> Vec<u8> {
    hex::encode(skdm).into_bytes()
}

/// Builds the websocket envelope for a group ciphertext. Group ciphertext is
/// already encrypted with Sender Keys and must remain byte-for-byte intact in
/// the protobuf Envelope; it is not encrypted through a pairwise session.
#[cfg(test)]
fn raw_group_envelope(
    sender_account_id: &str,
    sender_device_number: i64,
    recipient_account_id: &str,
    recipient_device_number: i64,
    conversation_id: &str,
    envelope_id: &str,
    client_timestamp: i64,
    ciphertext: &[u8],
) -> serde_json::Value {
    raw_group_envelope_with_send_at(
        sender_account_id,
        sender_device_number,
        recipient_account_id,
        recipient_device_number,
        conversation_id,
        envelope_id,
        client_timestamp,
        ciphertext,
        0,
    )
}

#[allow(clippy::too_many_arguments)]
fn raw_group_envelope_with_send_at(
    sender_account_id: &str,
    sender_device_number: i64,
    recipient_account_id: &str,
    recipient_device_number: i64,
    conversation_id: &str,
    envelope_id: &str,
    client_timestamp: i64,
    ciphertext: &[u8],
    send_at: i64,
) -> serde_json::Value {
    let mut envelope = serde_json::json!({
        "envelope_id": envelope_id,
        "sender_account_id": sender_account_id,
        "sender_device_number": sender_device_number,
        "recipient_account_id": recipient_account_id,
        "recipient_device_number": recipient_device_number,
        "envelope_type": ENVELOPE_TYPE_MESSAGE,
        "is_prekey_message": false,
        "ciphertext": hex::encode(ciphertext),
        "client_timestamp": client_timestamp,
        "conversation_id": conversation_id,
        "sender_is_bot": false,
    });
    if send_at > 0 {
        envelope["send_at"] = serde_json::json!(send_at);
    }
    envelope
}

async fn send_sender_key_message(
    state: &Arc<ActorState>,
    sender_account_id: &str,
    sender_device_number: i64,
    recipient_account_id: &str,
    recipient_device_number: i64,
    ciphertext: &[u8],
    conversation_id: &str,
    send_at: i64,
) -> Result<SentEnvelope> {
    let envelope_id = uuid::Uuid::now_v7().to_string();
    let value = raw_group_envelope_with_send_at(
        sender_account_id,
        sender_device_number,
        recipient_account_id,
        recipient_device_number,
        conversation_id,
        &envelope_id,
        now_unix(),
        ciphertext,
        send_at,
    );
    upload_envelope(state, value).await?;

    Ok(SentEnvelope {
        device_number: recipient_device_number,
        envelope_id,
        is_prekey_message: false,
        ciphertext_len: ciphertext.len(),
    })
}

// ---------------------------------------------------------------
// Member resolution
// ---------------------------------------------------------------

/// Returns the account ids of everyone in the conversation, including the
/// caller. Membership is authoritative on the server; it is not duplicated in
/// the local client database.
async fn member_account_ids(state: &Arc<ActorState>, conversation_id: &str) -> Result<Vec<String>> {
    let token = bearer(state).await?;
    let path = format!("/api/v1/conversations/{conversation_id}");
    let detail: ConversationDetail = state.http.get(&path, Some(&token)).await?;
    Ok(detail.members)
}

#[cfg(test)]
mod tests {
    use super::{ENVELOPE_TYPE_MESSAGE, pairwise_distribution_plaintext, raw_group_envelope};
    use serde_json::json;

    #[test]
    fn sender_key_distribution_is_pairwise_plaintext_ascii_hex() {
        assert_eq!(
            pairwise_distribution_plaintext(&[0x03, 0xFE, 0x00]),
            b"03fe00"
        );
    }

    #[test]
    fn group_envelope_preserves_sender_key_ciphertext_without_pairwise_wrapping() {
        let envelope = raw_group_envelope(
            "sender-account",
            7,
            "recipient-account",
            9,
            "group-conversation",
            "envelope-id",
            123,
            &[0x03, 0xFE, 0x00],
        );

        assert_eq!(
            envelope,
            json!({
                "envelope_id": "envelope-id",
                "sender_account_id": "sender-account",
                "sender_device_number": 7,
                "recipient_account_id": "recipient-account",
                "recipient_device_number": 9,
                "envelope_type": ENVELOPE_TYPE_MESSAGE,
                "is_prekey_message": false,
                "ciphertext": "03fe00",
                "client_timestamp": 123,
                "conversation_id": "group-conversation",
                "sender_is_bot": false
            })
        );
    }
}
