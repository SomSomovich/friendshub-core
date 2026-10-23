use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use crate::db::pending_events;
use crate::error::{Error, Result};
use crate::runtime::ActorState;
use crate::transport::ws::{
    ack_envelopes, request_history as send_history_request, send_nudge as send_ws_nudge,
    send_typing as send_ws_typing, upload_envelope,
};

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

pub async fn send_typing(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    send_ws_typing(state, payload).await
}

pub async fn send_nudge(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    send_ws_nudge(state, payload).await
}

pub async fn request_history(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    send_history_request(state, payload).await
}

pub async fn ping(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let timeout_ms = if payload.is_empty() {
        5_000
    } else {
        let value: serde_json::Value = serde_json::from_slice(&payload)?;
        if !value.is_object() {
            return Err(Error::InvalidPayload(
                "ping request must be a JSON object".into(),
            ));
        }
        match value.get("timeout_ms") {
            None => 5_000,
            Some(timeout) => timeout.as_u64().ok_or_else(|| {
                Error::InvalidPayload("timeout_ms must be a non-negative integer".into())
            })?,
        }
    };
    if timeout_ms > u32::MAX as u64 {
        return Err(Error::InvalidPayload(
            "timeout_ms must not exceed 4294967295".into(),
        ));
    }
    let round_trip_ms = state.ws.ping(Duration::from_millis(timeout_ms)).await?;
    Ok(serde_json::to_vec(&round_trip_ms)?)
}

#[derive(Deserialize)]
pub struct AckEventRequest {
    pub event_id: u64,
}

/// Acking a durable event releases the database row and, when the event is
/// an incoming envelope, sends the receipt the sender is waiting for.
pub async fn ack_event(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let event_id = if payload.len() == std::mem::size_of::<u64>() {
        u64::from_le_bytes(
            payload
                .as_slice()
                .try_into()
                .expect("payload length was checked"),
        )
    } else {
        serde_json::from_slice::<AckEventRequest>(&payload)?.event_id
    };
    let id = i64::try_from(event_id).map_err(|_| {
        Error::InvalidPayload("event_id exceeds the supported database ID range".into())
    })?;

    let Some(ev) = pending_events::get(&state.db, id).await? else {
        return Err(Error::InvalidPayload(format!("unknown event {id}")));
    };

    if ev.event_type == "envelope_received" {
        let parsed: serde_json::Value = serde_json::from_str(&ev.payload)?;
        if let Some(env_id) = parsed.get("envelope_id").and_then(|x| x.as_str()) {
            // Keep the durable row until the receipt is accepted by the
            // websocket sender. If the send fails, the caller can retry this
            // ACK and the envelope remains available for crash recovery.
            ack_envelopes(state, &[env_id.to_string()]).await?;
        }
    }

    pending_events::ack(&state.db, id).await?;
    Ok(br#"{"acked":true}"#.to_vec())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::config::Config;
    use crate::db::{self, pending_events};
    use crate::runtime::ActorState;
    use crate::transport::HttpClient;

    use super::ack_event;

    #[tokio::test]
    async fn failed_envelope_receipt_keeps_the_durable_event_for_retry() {
        let db_path = std::env::temp_dir().join(format!(
            "friendshub-core-ack-retry-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let config: Config = serde_json::from_value(serde_json::json!({
            "db_path": db_path,
            "api_base": "http://127.0.0.1:1",
            "ws_url": "ws://127.0.0.1:1",
            "discovery": { "enabled": false },
            "log_level": "off",
            "log_format": "text"
        }))
        .unwrap();
        let db = db::pool::open(&config.db_path).await.unwrap();
        db::migrations::MIGRATOR.run(&db).await.unwrap();
        let http = HttpClient::new(&config).unwrap();
        let state = Arc::new(ActorState::new(config, db, http));
        let envelope_id = uuid::Uuid::new_v4().to_string();
        let event_id = pending_events::push(
            &state.db,
            "envelope_received",
            &serde_json::json!({ "envelope_id": envelope_id }).to_string(),
        )
        .await
        .unwrap();

        let error = ack_event(&state, (event_id as u64).to_le_bytes().to_vec())
            .await
            .expect_err("a stopped websocket must reject the receipt");
        assert!(error.to_string().contains("websocket is not running"));
        assert!(
            pending_events::get(&state.db, event_id)
                .await
                .unwrap()
                .is_some(),
            "failed receipt must leave the durable event available for retry"
        );

        state.db.close().await;
        drop(state);
        let _ = std::fs::remove_file(db_path);
    }
}
