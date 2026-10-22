use serde::{Deserialize, Serialize};

/// A single event handed to the consumer.
///
/// A durable event has `id = Some(n)` and must be acknowledged with
/// fh_ack_event. An ephemeral event has `id = None` and is gone once read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    pub kind: String,
    pub payload: serde_json::Value,
}

impl Event {
    pub fn ephemeral(kind: &str, payload: serde_json::Value) -> Self {
        Self {
            id: None,
            kind: kind.to_string(),
            payload,
        }
    }
}

/// Receives events pushed by [`super::queue::EventQueue`] on its callback
/// thread.
///
/// Each event kind has its own method so consumers can subscribe to the
/// events they understand without inspecting a shared catch-all callback.
/// Methods are called with a borrowed event; its memory remains owned by the
/// library and is valid only for the duration of the callback. Durable event
/// IDs are preserved in [`Event::id`].
pub trait EventHandler: Send + Sync + 'static {
    fn on_ws_connected(&self, _event: &Event) {}
    fn on_ws_disconnected(&self, _event: &Event) {}
    fn on_ws_stopped(&self, _event: &Event) {}
    fn on_envelope_received(&self, _event: &Event) {}
    fn on_receipt(&self, _event: &Event) {}
    fn on_server_error(&self, _event: &Event) {}
    fn on_fatal_error(&self, _event: &Event) {}
    fn on_presence_updated(&self, _event: &Event) {}
    fn on_bot_message(&self, _event: &Event) {}
    fn on_channel_post(&self, _event: &Event) {}
    fn on_typing(&self, _event: &Event) {}
    fn on_read_receipt(&self, _event: &Event) {}
    fn on_conversation_updated(&self, _event: &Event) {}
    fn on_history_request(&self, _event: &Event) {}
    fn on_nudge(&self, _event: &Event) {}
    fn on_nudge_result(&self, _event: &Event) {}
    fn on_conversation_expired(&self, _event: &Event) {}
    fn on_scheduled_created(&self, _event: &Event) {}
    fn on_scheduled_cancelled(&self, _event: &Event) {}
    fn on_folders_updated(&self, _event: &Event) {}
    fn on_bot_message_edited(&self, _event: &Event) {}
    fn on_bot_message_deleted(&self, _event: &Event) {}
    fn on_bot_callback_answered(&self, _event: &Event) {}
    fn on_poll_updated(&self, _event: &Event) {}
    fn on_poll_deleted(&self, _event: &Event) {}
    fn on_call_signal(&self, _event: &Event) {}
    fn on_identity_changed(&self, _event: &Event) {}

    // `webrtc_event` uses an inner event discriminator in its JSON payload.
    fn on_webrtc_ice_candidate(&self, _event: &Event) {}
    fn on_webrtc_signaling_state_changed(&self, _event: &Event) {}
    fn on_webrtc_ice_connection_state_changed(&self, _event: &Event) {}
    fn on_webrtc_ice_gathering_state_changed(&self, _event: &Event) {}
    fn on_webrtc_connection_state_changed(&self, _event: &Event) {}
    fn on_webrtc_data_channel_opened(&self, _event: &Event) {}
    fn on_webrtc_data_channel_closed(&self, _event: &Event) {}
    fn on_webrtc_data_channel_message(&self, _event: &Event) {}
    fn on_webrtc_track_received(&self, _event: &Event) {}
    fn on_webrtc_closed(&self, _event: &Event) {}

    /// Receives a kind or WebRTC subtype not recognized by this version.
    fn on_unhandled(&self, _event: &Event) {}
}
