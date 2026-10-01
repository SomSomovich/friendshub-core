//! Call signaling over the existing Signal-encrypted envelope channel.
//!
//! SDP offers, answers and ICE candidates travel as ordinary encrypted
//! envelopes with a call-specific envelope_type. There is no separate
//! signaling protocol: the peer connection events feed this module, and
//! the recipient sees an `envelope_received` with the right envelope_type.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::common::bearer;
use crate::crypto::device_cache;
use crate::crypto::send::{send_one, SentEnvelope};
use crate::db::auth as db_auth;
use crate::error::{Error, Result};
use crate::runtime::ActorState;

const CALL_OFFER: i32 = 10;
const CALL_ANSWER: i32 = 11;
const CALL_ICE: i32 = 12;
const CALL_HANGUP: i32 = 13;
const CALL_REJECT: i32 = 14;

/// The plaintext carried inside a call-signaling envelope. The recipient
/// reads `kind` first, then the field that matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSignal {
    pub call_id: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

async fn send_to_recipient(
    state: &Arc<ActorState>,
    recipient_account_id: &str,
    payload: &[u8],
    envelope_type: i32,
) -> Result<(Vec<SentEnvelope>, Vec<(i64, String)>)> {
    let auth = db_auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;
    let sender_account_id = auth.account_id.clone().ok_or(Error::NotAuthenticated)?;
    let sender_device_number = auth.device_number.unwrap_or(1);
    let token = bearer(state).await?;

    let devices = device_cache::get(state, recipient_account_id).await?;
    if devices.is_empty() {
        return Err(Error::InvalidPayload(format!(
            "recipient {recipient_account_id} has no active devices"
        )));
    }

    let mut sent = Vec::new();
    let mut errors = Vec::new();
    for d in devices {
        match send_one(
            state,
            &token,
            &sender_account_id,
            sender_device_number,
            recipient_account_id,
            d.device_number,
            payload,
            envelope_type,
            None,
)
        .await
        {
            Ok(info) => sent.push(info),
            Err(e) => errors.push((d.device_number, e.to_string())),
        }
    }
    Ok((sent, errors))
}

pub async fn send_call_offer(
    state: &Arc<ActorState>,
    recipient_account_id: &str,
    call_id: &str,
    sdp: &str,
) -> Result<Vec<SentEnvelope>> {
    let signal = CallSignal {
        call_id: call_id.to_string(),
        kind: "offer".into(),
        sdp: Some(sdp.to_string()),
        candidate: None,
        reason: None,
    };
    let payload = serde_json::to_vec(&signal)?;
    let (sent, errs) = send_to_recipient(state, recipient_account_id, &payload, CALL_OFFER).await?;
    if sent.is_empty() && !errs.is_empty() {
        return Err(Error::Internal(format!("all recipient devices failed: {errs:?}")));
    }
    Ok(sent)
}

pub async fn send_call_answer(
    state: &Arc<ActorState>,
    recipient_account_id: &str,
    call_id: &str,
    sdp: &str,
) -> Result<Vec<SentEnvelope>> {
    let signal = CallSignal {
        call_id: call_id.to_string(),
        kind: "answer".into(),
        sdp: Some(sdp.to_string()),
        candidate: None,
        reason: None,
    };
    let payload = serde_json::to_vec(&signal)?;
    let (sent, _) = send_to_recipient(state, recipient_account_id, &payload, CALL_ANSWER).await?;
    Ok(sent)
}

pub async fn send_call_ice(
    state: &Arc<ActorState>,
    recipient_account_id: &str,
    call_id: &str,
    candidate: serde_json::Value,
) -> Result<Vec<SentEnvelope>> {
    let signal = CallSignal {
        call_id: call_id.to_string(),
        kind: "ice".into(),
        sdp: None,
        candidate: Some(candidate),
        reason: None,
    };
    let payload = serde_json::to_vec(&signal)?;
    let (sent, _) = send_to_recipient(state, recipient_account_id, &payload, CALL_ICE).await?;
    Ok(sent)
}

pub async fn send_call_hangup(
    state: &Arc<ActorState>,
    recipient_account_id: &str,
    call_id: &str,
    reason: Option<&str>,
) -> Result<Vec<SentEnvelope>> {
    let signal = CallSignal {
        call_id: call_id.to_string(),
        kind: "hangup".into(),
        sdp: None,
        candidate: None,
        reason: reason.map(String::from),
    };
    let payload = serde_json::to_vec(&signal)?;
    let (sent, _) = send_to_recipient(state, recipient_account_id, &payload, CALL_HANGUP).await?;
    Ok(sent)
}

pub async fn send_call_reject(
    state: &Arc<ActorState>,
    recipient_account_id: &str,
    call_id: &str,
    reason: Option<&str>,
) -> Result<Vec<SentEnvelope>> {
    let signal = CallSignal {
        call_id: call_id.to_string(),
        kind: "reject".into(),
        sdp: None,
        candidate: None,
        reason: reason.map(String::from),
    };
    let payload = serde_json::to_vec(&signal)?;
    let (sent, _) = send_to_recipient(state, recipient_account_id, &payload, CALL_REJECT).await?;
    Ok(sent)
}
