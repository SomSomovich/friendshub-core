use std::sync::Arc;

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::runtime::ActorState;

#[derive(Debug, Deserialize)]
pub struct AddVideoRequest {
    pub call_id: String,
    /// Label for the track. Purely informational; the peer sees it in the
    /// SDP as the msid.
    #[serde(default = "default_label")]
    pub label: String,
}

fn default_label() -> String { "video".to_string() }

/// Adds an outgoing VP8 video track to an active call.
///
/// The track starts empty; nothing is sent until frames are written via
/// `0x0012_0021`. After this call, the peer must be told the new track
/// exists, which happens through the next offer/answer exchange. In practice
/// the typical order is: create offer, add track, send offer.
pub async fn add_video_track(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let req: AddVideoRequest = serde_json::from_slice(&payload)?;
    state
        .webrtc
        .add_video_track(&req.call_id, &req.label)
        .await?;
    Ok(serde_json::to_vec(&serde_json::json!({
        "added": true,
        "mime": crate::webrtc::video::VideoTracks::outgoing_mime(),
    }))?)
}

#[derive(Debug, Deserialize)]
pub struct WriteFrameRequest {
    pub call_id: String,
    /// Base64-encoded compressed frame. VP8 bitstream in the default codec.
    pub data_base64: String,
    /// Frame duration in milliseconds; used for pacing hints. 33 for 30 fps.
    #[serde(default = "default_duration_ms")]
    pub duration_ms: u64,
}

fn default_duration_ms() -> u64 { 33 }

/// Writes one encoded frame to the outgoing video track.
///
/// The library does not encode; the caller produces VP8 frames (camera
/// capture, screen capture, a file) and hands them here.
pub async fn write_video_frame(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    use base64::Engine;

    let req: WriteFrameRequest = serde_json::from_slice(&payload)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(req.data_base64.as_bytes())
        .map_err(|e| Error::InvalidPayload(format!("data_base64: {e}")))?;

    state
        .webrtc
        .write_video_frame(&req.call_id, bytes, req.duration_ms)
        .await?;

    Ok(br#"{"written":true}"#.to_vec())
}

#[derive(Debug, Deserialize)]
pub struct ReadFrameRequest {
    pub call_id: String,
    /// Milliseconds to wait for a frame. Defaults to 1000: long enough to
    /// cover a normal 30 fps interval with margin, short enough that a
    /// stalled call does not block a UI thread.
    #[serde(default = "default_read_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_read_timeout_ms() -> u64 { 1000 }

/// Reads the next complete video frame from the remote track on a call.
///
/// Returns `{"timeout": true}` when no frame arrived within the window,
/// or `{"data_base64": "...", "size": N}` when one did.
///
/// A consumer that wants smooth playback calls this in a loop with a
/// small timeout and drops nothing: whatever comes back is the newest
/// frame the buffer holds. If the loop is slower than the sender, frames
/// are dropped internally rather than queued, so the picture stays in
/// real time.
pub async fn read_video_frame(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    use base64::Engine;

    let req: ReadFrameRequest = serde_json::from_slice(&payload)?;
    let timeout = std::time::Duration::from_millis(req.timeout_ms);

    match state.webrtc.video.read_frame(&req.call_id, timeout).await {
        Some(data) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
            Ok(serde_json::to_vec(&serde_json::json!({
                "timeout": false,
                "size": data.len(),
                "data_base64": encoded,
            }))?)
        }
        None => Ok(serde_json::to_vec(&serde_json::json!({ "timeout": true }))?),
    }
}
