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
pub const ENVELOPE_TYPE_SENDER_KEY: i32 = 3;
/// ENVELOPE_TYPE_MESSAGE from friendshub.proto.
pub const ENVELOPE_TYPE_MESSAGE: i32 = 1;

// ---------------------------------------------------------------
// Create / rotate this device's sender key for a conversation
// ---------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateDistributionRequest {
    pub conversation_id: String,
    /// When true, a new distribution id is generated even if one exists.
    /// This is what a member removal should trigger: it rekeys the group
    /// and the removed device cannot read anything sent afterwards.
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
///
/// The caller supplies the list of member account ids. The library fetches
/// each member's devices, sends the distribution, and reports per-device
/// success. Failures on individual devices do not abort the whole call.
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
        // Skip our own account: `send_one` would create a session with our
        // own device, which is not what distribution means. Our own other
        // devices still need the distribution, and they get it through the
        // same loop below, just as a separate `send_one` call.
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
            // Sending the distribution to our own device through the Signal
            // session with ourselves is not supported by the protocol; that
            // path is a no-op for now. Own-device distribution needs a
            // dedicated mechanism, which is out of scope here.
            if *member_account_id == sender_account_id {
                continue;
            }

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
// Encrypt once, fan out to every member device
// ---------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SendGroupRequest {
    pub conversation_id: String,
    pub plaintext_hex: String,
}

#[derive(Debug, Serialize)]
pub struct SendGroupResponse {
    pub ciphertext_len: usize,
    pub envelopes: Vec<DistributionEnvelope>,
    pub device_errors: Vec<serde_json::Value>,
}

/// Encrypts the plaintext once, then sends the same SenderKeyMessage to every
/// device of every member of the conversation.
///
/// The plaintext is sealed once for the whole group; every recipient device
/// decrypts with the sender key it was given at distribution time. That is
/// the whole point of group sending: one encryption, many recipients.
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
        // Skip our own account for the same reason as in distribution: the
        // protocol does not allow a session with yourself. Our own other
        // devices receive the same ciphertext through the group fanout that
        // includes them if they are listed as members.
        if *member_account_id == sender_account_id {
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

    Ok(serde_json::to_vec(&SendGroupResponse {
        ciphertext_len: skm.len(),
        envelopes,
        device_errors: errors,
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
    // conversation_members holds direct and group members; channel_members
    // holds channel subscribers. A group message is a group concern, so only
    // the conversation_members side is read here. A channel that uses the
    // group send path would first need to be a group.
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT account_id FROM conversation_members WHERE conversation_id = ? AND left_at IS NULL",
    )
    .bind(conversation_id)
    .fetch_all(&state.db)
    .await?;

    Ok(rows.into_iter().map(|(a,)| a).collect())
}
