use std::sync::Arc;

use serde::Deserialize;

use crate::db::pending_events;
use crate::error::{Error, Result};
use crate::runtime::ActorState;
use crate::transport::ws::{ack_envelopes, upload_envelope};

pub async fn start(state: &Arc<ActorState>) -> Result<Vec<u8>> {
    state.ws.clone().start(state.clone()).await?;
    Ok(br#"{"started":true}"#.to_vec())
}

pub async fn stop(state: &Arc<ActorState>) -> Result<Vec<u8>> {
    state.ws.stop().await?;
    Ok(br#"{"stopped":true}"#.to_vec())
}

pub async fn send_envelope(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let v: serde_json::Value = serde_json::from_slice(&payload)?;
    upload_envelope(state, v).await?;
    Ok(br#"{"sent":true}"#.to_vec())
}

#[derive(Deserialize)]
pub struct AckEventRequest {
    pub event_id: u64,
}

/// Acking a durable event releases the database row and, when the event is
/// an incoming envelope, sends the receipt the sender is waiting for.
pub async fn ack_event(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: AckEventRequest = serde_json::from_slice(&payload)?;
    let id = req.event_id as i64;

    let Some(ev) = pending_events::get(&state.db, id).await? else {
        return Err(Error::InvalidPayload(format!("unknown event {id}")));
    };

    if ev.event_type == "envelope_received" {
        let parsed: serde_json::Value = serde_json::from_str(&ev.payload)?;
        if let Some(env_id) = parsed.get("envelope_id").and_then(|x| x.as_str()) {
            // A failed receipt is not fatal: the envelope is still in the
            // database and will be redelivered by the server on the next
            // connection if it never gets acked.
            if let Err(e) = ack_envelopes(state, &[env_id.to_string()]).await {
                tracing::warn!(error = %e, "failed to send envelope receipt");
            }
        }
    }

    pending_events::ack(&state.db, id).await?;
    Ok(br#"{"acked":true}"#.to_vec())
}
