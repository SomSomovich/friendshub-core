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
        Self { id: None, kind: kind.to_string(), payload }
    }
}
