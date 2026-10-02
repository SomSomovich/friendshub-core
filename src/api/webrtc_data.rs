use std::sync::Arc;

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::runtime::ActorState;

#[derive(Debug, Deserialize)]
pub struct SendDataRequest {
    pub call_id: String,
    pub label: String,
    pub data_base64: String,
    #[serde(default)]
    pub is_text: bool,
}

/// Writes into a data channel that is already open. The channel must have
/// fired `data_channel_opened`; otherwise the write fails and the caller
/// knows to wait for the event before retrying.
pub async fn send_channel_data(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    use base64::Engine;

    let req: SendDataRequest = serde_json::from_slice(&payload)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(req.data_base64.as_bytes())
        .map_err(|e| Error::InvalidPayload(format!("data_base64: {e}")))?;

    state
        .webrtc
        .send_data(&req.call_id, &req.label, bytes, req.is_text)
        .await?;

    Ok(br#"{"sent":true}"#.to_vec())
}
