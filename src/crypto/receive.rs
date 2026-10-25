//! Classifies decrypted websocket envelopes into semantic push events.
//!
//! The transport persists and emits `envelope_received` before application
//! callbacks run. This module performs a side-effect-free interpretation at
//! callback time, so the original durable event ID remains the ID the consumer
//! must acknowledge after it has committed the event locally.

use serde_json::{Value, json};

#[cfg(feature = "native")]
use crate::events::types::Event;

const ENVELOPE_MESSAGE: i64 = 1;
const ENVELOPE_SYNC: i64 = 2;
#[cfg(feature = "native")]
const ENVELOPE_SENDER_KEY: i64 = 3;
const ENVELOPE_EDIT: i64 = 4;
const ENVELOPE_DELETE: i64 = 5;
const ENVELOPE_REACTION: i64 = 6;
const ENVELOPE_ATTACHMENT_KEY: i64 = 9;
const ENVELOPE_CALL_OFFER: i64 = 10;
const ENVELOPE_CALL_ANSWER: i64 = 11;
const ENVELOPE_CALL_ICE: i64 = 12;
const ENVELOPE_CALL_HANGUP: i64 = 13;
const ENVELOPE_CALL_REJECT: i64 = 14;

/// A recognized decrypted envelope payload shared by native and WASM clients.
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticPayload {
    pub kind: &'static str,
    pub payload: Value,
}

/// Envelope metadata needed to parse payloads that depend on delivery context.
///
/// IDs and device numbers are optional because non-history semantic payloads do
/// not need them. History chunks fail closed unless authenticated local
/// identity, source, recipient, and conversation fields identify another
/// device on the receiving account.
#[derive(Debug, Clone, Copy)]
pub struct ReceiveMetadata<'a> {
    pub envelope_id: &'a str,
    pub client_timestamp: i64,
    /// Account identity authenticated by the current session, not envelope
    /// metadata supplied by the sender or server.
    pub local_account_id: Option<&'a str>,
    pub sender_account_id: Option<&'a str>,
    pub sender_device_number: Option<i64>,
    pub recipient_account_id: Option<&'a str>,
    pub recipient_device_number: Option<i64>,
    pub conversation_id: Option<&'a str>,
}

/// Parse an already decrypted wire payload using WEB's receive contracts.
///
/// The returned value contains the semantic family and its normalized payload.
/// Unrecognized control payloads return `None`; legacy message text remains a
/// message, as in WEB. Native callers preserve the original raw envelope when
/// this function returns `None`.
pub fn parse_decrypted_payload(
    envelope_type: i64,
    metadata: ReceiveMetadata<'_>,
    plaintext: &[u8],
) -> Option<SemanticPayload> {
    let plaintext = String::from_utf8_lossy(plaintext);
    let decoded_json = serde_json::from_str::<Value>(&plaintext).ok();
    let payload = match envelope_type {
        ENVELOPE_MESSAGE => {
            let normalized = decoded_json.as_ref().and_then(|value| {
                match value.get("kind").and_then(Value::as_str) {
                    Some("message") => normalize_message(value).map(|payload| SemanticPayload {
                        kind: "message_received",
                        payload,
                    }),
                    Some("poll") => normalize_poll(value).map(|payload| SemanticPayload {
                        kind: "poll_received",
                        payload,
                    }),
                    _ => None,
                }
            });
            normalized.unwrap_or_else(|| SemanticPayload {
                kind: "message_received",
                payload: plain_text_payload(
                    metadata.envelope_id,
                    metadata.client_timestamp,
                    &plaintext,
                ),
            })
        }
        ENVELOPE_SYNC => parse_sync_payload(metadata, decoded_json.as_ref())?,
        ENVELOPE_EDIT | ENVELOPE_DELETE | ENVELOPE_REACTION => {
            let value = decoded_json.as_ref()?;
            let kind = value.get("kind").and_then(Value::as_str)?;
            let (kind, payload) = match kind {
                "edit" => ("message_edited", normalize_edit(value)?),
                "delete" => ("message_deleted", normalize_delete(value)?),
                "reaction" => ("message_reaction", normalize_reaction(value)?),
                _ => return None,
            };
            SemanticPayload { kind, payload }
        }
        ENVELOPE_ATTACHMENT_KEY => SemanticPayload {
            kind: "attachment_key_received",
            payload: normalize_attachment_key(decoded_json.as_ref()?)?,
        },
        ENVELOPE_CALL_OFFER | ENVELOPE_CALL_ANSWER | ENVELOPE_CALL_ICE | ENVELOPE_CALL_HANGUP
        | ENVELOPE_CALL_REJECT => SemanticPayload {
            kind: "call_signal_received",
            payload: normalize_call(decoded_json.as_ref()?)?,
        },
        _ => return None,
    };
    Some(payload)
}

/// Return a typed callback event for a decrypted envelope, or `None` when the
/// original raw `envelope_received` callback must be preserved.
///
/// The typed event carries the full envelope metadata and adds the decoded
/// value as `decrypted_payload`. It retains the durable event ID, so callers
/// can commit the payload before acknowledging that same ID.
#[cfg(feature = "native")]
pub fn classify_received_envelope(event: &Event) -> Option<Event> {
    if event.kind != "envelope_received" || !event.payload.is_object() {
        return None;
    }

    let envelope_type = event.payload.get("envelope_type")?.as_i64()?;
    if event
        .payload
        .get("decrypt_error")
        .is_some_and(|value| !value.is_null())
    {
        return None;
    }

    if envelope_type == ENVELOPE_SENDER_KEY
        && event.payload.get("distribution").and_then(Value::as_bool) == Some(true)
    {
        return Some(typed_event(event, "sender_key_received", None));
    }

    let plaintext_hex = event.payload.get("plaintext_hex")?.as_str()?;
    let plaintext = hex::decode(plaintext_hex).ok()?;
    let envelope_id = event.payload.get("envelope_id")?.as_str()?;
    let timestamp = event
        .payload
        .get("client_timestamp")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let metadata = ReceiveMetadata {
        envelope_id,
        client_timestamp: timestamp,
        local_account_id: event
            .payload
            .get("local_account_id")
            .and_then(Value::as_str),
        sender_account_id: event
            .payload
            .get("sender_account_id")
            .and_then(Value::as_str),
        sender_device_number: event
            .payload
            .get("sender_device_number")
            .and_then(Value::as_i64),
        recipient_account_id: event
            .payload
            .get("recipient_account_id")
            .and_then(Value::as_str),
        recipient_device_number: event
            .payload
            .get("recipient_device_number")
            .and_then(Value::as_i64),
        conversation_id: event.payload.get("conversation_id").and_then(Value::as_str),
    };
    let parsed = parse_decrypted_payload(envelope_type, metadata, &plaintext)?;
    Some(typed_event(event, parsed.kind, Some(parsed.payload)))
}

#[cfg(feature = "native")]
fn typed_event(source: &Event, kind: &str, decoded_payload: Option<Value>) -> Event {
    let mut payload = source.payload.clone();
    if let (Some(object), Some(decoded_payload)) = (payload.as_object_mut(), decoded_payload) {
        object.insert("decrypted_payload".into(), decoded_payload);
    }
    Event {
        id: source.id,
        kind: kind.into(),
        payload,
    }
}

fn plain_text_payload(envelope_id: &str, client_timestamp: i64, plaintext: &str) -> Value {
    json!({
        "kind": "message",
        "message_id": envelope_id,
        "text": plaintext,
        "reply_to": null,
        "forward_from": null,
        "attachment_ids": [],
        "created_at": client_timestamp,
    })
}

fn parse_sync_payload(
    metadata: ReceiveMetadata<'_>,
    decoded_json: Option<&Value>,
) -> Option<SemanticPayload> {
    let value = decoded_json?;
    if let Some(chunk) = crate::crypto::history_protocol::parse_history_chunk(value) {
        let local_account_id = metadata.local_account_id?;
        let sender_account_id = metadata.sender_account_id?;
        let recipient_account_id = metadata.recipient_account_id?;
        let sender_device_number = metadata.sender_device_number?;
        let recipient_device_number = metadata.recipient_device_number?;
        let envelope_conversation_id = metadata.conversation_id?;
        if local_account_id.is_empty()
            || sender_account_id.is_empty()
            || sender_account_id != local_account_id
            || recipient_account_id != local_account_id
            || sender_account_id != recipient_account_id
            || sender_device_number == recipient_device_number
            || chunk.conversation_id != envelope_conversation_id
        {
            return None;
        }
        let complete =
            chunk.item_kind == crate::crypto::history_protocol::HistoryItemKind::Complete;
        return Some(SemanticPayload {
            kind: if complete {
                "history_complete_received"
            } else {
                "history_chunk_received"
            },
            payload: value.clone(),
        });
    }

    // Older versions wrapped the old own-device copy in a JSON object. WEB
    // still recovers its plaintext when the nested field is present.
    if let Some(legacy_hex) = value.get("plaintext_hex").and_then(Value::as_str) {
        let text = hex::decode(legacy_hex).ok()?;
        let text = String::from_utf8_lossy(&text);
        return Some(SemanticPayload {
            kind: "message_received",
            payload: plain_text_payload(metadata.envelope_id, metadata.client_timestamp, &text),
        });
    }
    None
}

fn normalize_message(value: &Value) -> Option<Value> {
    let message_id = value.get("message_id")?.as_str()?;
    let text = value.get("text")?.as_str()?;

    let reply_to = value
        .get("reply_to")
        .and_then(|reply| {
            Some(json!({
                "message_id": reply.get("message_id")?.as_str()?,
                "preview": optional_string(reply.get("preview")),
                "sender_account_id": optional_string(reply.get("sender_account_id")),
            }))
        })
        .unwrap_or(Value::Null);
    let forward_from = value
        .get("forward_from")
        .and_then(|forward| {
            Some(json!({
                "original_message_id": forward.get("original_message_id")?.as_str()?,
                "original_conversation_id": forward.get("original_conversation_id")?.as_str()?,
                "original_sender_account_id": forward.get("original_sender_account_id")?.as_str()?,
                "original_sender_display": optional_string(forward.get("original_sender_display")),
                "original_created_at": number_or_zero(forward.get("original_created_at")),
            }))
        })
        .unwrap_or(Value::Null);
    let attachment_ids = value
        .get("attachment_ids")
        .and_then(Value::as_array)
        .map(|ids| ids.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();

    Some(json!({
        "kind": "message",
        "message_id": message_id,
        "text": text,
        "reply_to": reply_to,
        "forward_from": forward_from,
        "attachment_ids": attachment_ids,
        "created_at": number_or_zero(value.get("created_at")),
    }))
}

fn normalize_poll(value: &Value) -> Option<Value> {
    let (Some(title), Some(description), Some(options)) = (
        value.get("title").and_then(Value::as_str),
        value.get("description").and_then(Value::as_str),
        value.get("options").and_then(Value::as_array),
    ) else {
        return None;
    };
    let poll_id = value.get("poll_id")?.as_str()?;
    if title.chars().count() > 64
        || description.chars().count() > 128
        || !(2..=15).contains(&options.len())
    {
        return None;
    }
    let mut seen = std::collections::HashSet::with_capacity(options.len());
    let mut normalized_options = Vec::with_capacity(options.len());
    for option in options {
        let (Some(id), Some(text)) = (
            option.get("id").and_then(Value::as_str),
            option.get("text").and_then(Value::as_str),
        ) else {
            return None;
        };
        let id_len = id.encode_utf16().count();
        let text_len = text.chars().count();
        if !(1..=64).contains(&id_len) || !(1..=128).contains(&text_len) || !seen.insert(id) {
            return None;
        }
        normalized_options.push(json!({"id": id, "text": text}));
    }

    Some(json!({
        "kind": "poll",
        "poll_id": poll_id,
        "title": title,
        "description": description,
        "options": normalized_options,
    }))
}

fn normalize_edit(value: &Value) -> Option<Value> {
    if value.get("kind").and_then(Value::as_str) != Some("edit") {
        return None;
    }
    Some(json!({
        "kind": "edit",
        "target_message_id": value.get("target_message_id")?.as_str()?,
        "new_text": value.get("new_text")?.as_str()?,
        "edited_at": number_or_zero(value.get("edited_at")),
    }))
}

fn normalize_delete(value: &Value) -> Option<Value> {
    if value.get("kind").and_then(Value::as_str) != Some("delete") {
        return None;
    }
    Some(json!({
        "kind": "delete",
        "target_message_id": value.get("target_message_id")?.as_str()?,
        "deleted_at": number_or_zero(value.get("deleted_at")),
    }))
}

fn normalize_reaction(value: &Value) -> Option<Value> {
    if value.get("kind").and_then(Value::as_str) != Some("reaction") {
        return None;
    }
    let emoji = value.get("emoji")?;
    if !emoji.is_null() && !emoji.is_string() {
        return None;
    }
    Some(json!({
        "kind": "reaction",
        "target_message_id": value.get("target_message_id")?.as_str()?,
        "emoji": emoji,
        "created_at": number_or_zero(value.get("created_at")),
    }))
}

fn normalize_attachment_key(value: &Value) -> Option<Value> {
    if value.get("kind").and_then(Value::as_str) != Some("attachment_key") {
        return None;
    }
    Some(json!({
        "kind": "attachment_key",
        "attachment_id": value.get("attachment_id")?.as_str()?,
        "key_hex": value.get("key_hex")?.as_str()?,
        "base_nonce_hex": value.get("base_nonce_hex")?.as_str()?,
        "conversation_id": optional_string(value.get("conversation_id")),
    }))
}

fn normalize_call(value: &Value) -> Option<Value> {
    let call_id = value.get("call_id")?.as_str()?;
    let kind = value.get("kind")?.as_str()?;
    if !matches!(kind, "offer" | "answer" | "ice" | "hangup" | "reject") {
        return None;
    }
    Some(json!({
        "call_id": call_id,
        "kind": kind,
        "sdp": optional_string(value.get("sdp")),
        "candidate": value.get("candidate").cloned().unwrap_or(Value::Null),
        "reason": optional_string(value.get("reason")),
    }))
}

fn optional_string(value: Option<&Value>) -> Value {
    value
        .and_then(Value::as_str)
        .map(Value::from)
        .unwrap_or(Value::Null)
}

fn number_or_zero(value: Option<&Value>) -> Value {
    value
        .filter(|value| value.as_f64().is_some_and(f64::is_finite))
        .cloned()
        .unwrap_or_else(|| Value::from(0))
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use serde_json::{Value, json};

    use super::classify_received_envelope;
    use crate::events::types::Event;

    fn envelope(envelope_type: i64, plaintext: Option<&Value>) -> Event {
        let plaintext_hex = plaintext.map(|value| hex::encode(value.to_string()));
        Event {
            id: Some(507),
            kind: "envelope_received".into(),
            payload: json!({
                "envelope_id": "logical-envelope", "envelope_type": envelope_type,
                "sender_account_id": "account", "sender_device_number": 4,
                "recipient_account_id": "account", "recipient_device_number": 8,
                "local_account_id": "account",
                "conversation_id": plaintext.and_then(|value| value.get("conversation_id")).cloned().unwrap_or(Value::from("conversation")),
                "client_timestamp": 123,
                "ciphertext": "aabb", "plaintext_hex": plaintext_hex,
            }),
        }
    }

    #[test]
    fn message_payload_is_typed_and_keeps_the_durable_ack_id() {
        let raw = envelope(
            1,
            Some(&json!({"kind":"message","message_id":"m1","text":"hello"})),
        );
        let received = classify_received_envelope(&raw).unwrap();
        assert_eq!(received.kind, "message_received");
        assert_eq!(received.id, Some(507));
        assert_eq!(received.payload["decrypted_payload"]["message_id"], "m1");
        assert_eq!(received.payload["envelope_id"], "logical-envelope");
    }

    #[test]
    fn message_payload_matches_web_normalization_of_optional_fields() {
        let raw = envelope(
            1,
            Some(&json!({
                "kind":"message", "message_id":"m1", "text":"hello",
                "reply_to":{"message_id":"quoted","preview":17,"sender_account_id":"alice","extra":true},
                "forward_from":{"original_message_id":"f1","original_conversation_id":"c1","original_sender_account_id":"alice","original_sender_display":17,"original_created_at":4},
                "attachment_ids":["a1",17,"a2"], "created_at":"invalid", "extra":true
            })),
        );

        let received = classify_received_envelope(&raw).unwrap();
        assert_eq!(
            received.payload["decrypted_payload"],
            json!({
                "kind":"message", "message_id":"m1", "text":"hello",
                "reply_to":{"message_id":"quoted","preview":null,"sender_account_id":"alice"},
                "forward_from":{"original_message_id":"f1","original_conversation_id":"c1","original_sender_account_id":"alice","original_sender_display":null,"original_created_at":4},
                "attachment_ids":["a1","a2"], "created_at":0
            })
        );
    }

    #[test]
    fn legacy_plain_text_remains_a_message_as_in_web() {
        let raw = Event {
            payload: json!({
                "envelope_id":"old-envelope", "envelope_type":1,
                "client_timestamp":45, "plaintext_hex":hex::encode("old client text"),
            }),
            ..envelope(1, None)
        };
        let received = classify_received_envelope(&raw).unwrap();
        assert_eq!(received.kind, "message_received");
        assert_eq!(
            received.payload["decrypted_payload"]["text"],
            "old client text"
        );
        assert_eq!(
            received.payload["decrypted_payload"]["message_id"],
            "old-envelope"
        );
    }

    #[test]
    fn poll_is_separate_and_malformed_poll_uses_web_legacy_text_fallback() {
        let poll = json!({"kind":"poll","poll_id":"p1","title":"Question","description":"","options":[{"id":"a","text":"A"},{"id":"b","text":"B"}]});
        assert_eq!(
            classify_received_envelope(&envelope(1, Some(&poll)))
                .unwrap()
                .kind,
            "poll_received"
        );
        let malformed = json!({"kind":"poll","poll_id":"p1","title":"Question","description":"","options":[{"id":"a","text":"A"}]});
        let fallback = classify_received_envelope(&envelope(1, Some(&malformed))).unwrap();
        assert_eq!(fallback.kind, "message_received");
        assert_eq!(
            fallback.payload["decrypted_payload"]["text"],
            malformed.to_string()
        );
    }

    #[test]
    fn edit_delete_reaction_and_attachment_use_type_specific_callbacks() {
        let cases = [
            (
                4,
                json!({"kind":"edit","target_message_id":"m","new_text":"new"}),
                "message_edited",
            ),
            (
                5,
                json!({"kind":"delete","target_message_id":"m"}),
                "message_deleted",
            ),
            (
                6,
                json!({"kind":"reaction","target_message_id":"m","emoji":null}),
                "message_reaction",
            ),
            (
                9,
                json!({"kind":"attachment_key","attachment_id":"a","key_hex":"aa","base_nonce_hex":"bb","conversation_id":null}),
                "attachment_key_received",
            ),
        ];
        for (envelope_type, payload, expected_kind) in cases {
            let received =
                classify_received_envelope(&envelope(envelope_type, Some(&payload))).unwrap();
            assert_eq!(received.kind, expected_kind);
        }
        // WEB routes edit/delete/reaction from the decrypted discriminator
        // across all three action envelope types, rather than trusting only
        // the outer envelope type.
        let cross_type = envelope(
            4,
            Some(&json!({
                "kind":"delete", "target_message_id":"m", "deleted_at":"invalid"
            })),
        );
        let received = classify_received_envelope(&cross_type).unwrap();
        assert_eq!(received.kind, "message_deleted");
        assert_eq!(received.payload["decrypted_payload"]["deleted_at"], 0);
    }

    #[test]
    fn edit_delete_and_reaction_timestamps_match_web_defaults() {
        let cases = [
            (
                4,
                json!({"kind":"edit","target_message_id":"m","new_text":"new","edited_at":"invalid","extra":true}),
                "message_edited",
                json!({"kind":"edit","target_message_id":"m","new_text":"new","edited_at":0}),
            ),
            (
                5,
                json!({"kind":"delete","target_message_id":"m","deleted_at":null}),
                "message_deleted",
                json!({"kind":"delete","target_message_id":"m","deleted_at":0}),
            ),
            (
                6,
                json!({"kind":"reaction","target_message_id":"m","emoji":null,"created_at":"invalid"}),
                "message_reaction",
                json!({"kind":"reaction","target_message_id":"m","emoji":null,"created_at":0}),
            ),
        ];

        for (envelope_type, payload, expected_kind, expected_payload) in cases {
            let received =
                classify_received_envelope(&envelope(envelope_type, Some(&payload))).unwrap();
            assert_eq!(received.kind, expected_kind);
            assert_eq!(received.payload["decrypted_payload"], expected_payload);
        }
    }

    #[test]
    fn call_signal_type_routes_only_a_valid_call_payload() {
        let received = classify_received_envelope(&envelope(
            10,
            Some(
                &json!({"call_id":"c1","kind":"offer","sdp":"v=0","candidate":null,"reason":null}),
            ),
        ))
        .unwrap();
        assert_eq!(received.kind, "call_signal_received");
        assert_eq!(
            received.payload["decrypted_payload"],
            json!({"call_id":"c1","kind":"offer","sdp":"v=0","candidate":null,"reason":null})
        );
        assert!(
            classify_received_envelope(&envelope(10, Some(&json!({"kind":"offer"})))).is_none()
        );
    }

    #[test]
    fn attachment_key_and_call_optional_fields_match_web_normalization() {
        let attachment = classify_received_envelope(&envelope(
            9,
            Some(&json!({
                "kind":"attachment_key", "attachment_id":"a", "key_hex":"aa",
                "base_nonce_hex":"bb", "conversation_id":{"bad":"type"}, "extra":true
            })),
        ))
        .unwrap();
        assert_eq!(
            attachment.payload["decrypted_payload"],
            json!({
                "kind":"attachment_key", "attachment_id":"a", "key_hex":"aa",
                "base_nonce_hex":"bb", "conversation_id":null
            })
        );

        let call = classify_received_envelope(&envelope(
            12,
            Some(&json!({
                "call_id":"c2", "kind":"ice", "sdp":17,
                "candidate":{"candidate":"candidate:1"}, "reason":false, "extra":true
            })),
        ))
        .unwrap();
        assert_eq!(
            call.payload["decrypted_payload"],
            json!({
                "call_id":"c2", "kind":"ice", "sdp":null,
                "candidate":{"candidate":"candidate:1"}, "reason":null
            })
        );
    }

    #[test]
    fn history_chunk_and_completion_are_distinct_callbacks() {
        let base = json!({"kind":"history_sync","version":1,"transfer_id":"550e8400-e29b-41d4-a716-446655440000","conversation_id":"550e8400-e29b-41d4-a716-446655440001","item_kind":"message","item_id":"m1","part_index":0,"part_count":1,"data":"e30="});
        assert_eq!(
            classify_received_envelope(&envelope(2, Some(&base)))
                .unwrap()
                .kind,
            "history_chunk_received"
        );
        let mut complete = base;
        complete["item_kind"] = Value::from("complete");
        assert_eq!(
            classify_received_envelope(&envelope(2, Some(&complete)))
                .unwrap()
                .kind,
            "history_complete_received"
        );
        complete["part_index"] = Value::from(1);
        assert!(classify_received_envelope(&envelope(2, Some(&complete))).is_none());
    }

    #[test]
    fn foreign_same_device_or_mismatched_conversation_history_stays_raw() {
        let chunk = json!({
            "kind":"history_sync", "version":1,
            "transfer_id":"550e8400-e29b-41d4-a716-446655440000",
            "conversation_id":"550e8400-e29b-41d4-a716-446655440001",
            "item_kind":"message", "item_id":"m1", "part_index":0,
            "part_count":1, "data":"e30="
        });
        let raw = envelope(2, Some(&chunk));
        assert_eq!(
            classify_received_envelope(&raw).unwrap().kind,
            "history_chunk_received"
        );

        let mut local_identity_missing = raw.clone();
        local_identity_missing
            .payload
            .as_object_mut()
            .unwrap()
            .remove("local_account_id");
        assert!(classify_received_envelope(&local_identity_missing).is_none());

        let mut foreign_pair = raw.clone();
        foreign_pair.payload["local_account_id"] = Value::from("local-account");
        foreign_pair.payload["sender_account_id"] = Value::from("foreign-account");
        foreign_pair.payload["recipient_account_id"] = Value::from("foreign-account");
        assert!(classify_received_envelope(&foreign_pair).is_none());

        let mut foreign = raw.clone();
        foreign.payload["sender_account_id"] = Value::from("another-account");
        assert!(classify_received_envelope(&foreign).is_none());

        let mut foreign_recipient = raw.clone();
        foreign_recipient.payload["recipient_account_id"] = Value::from("another-account");
        assert!(classify_received_envelope(&foreign_recipient).is_none());

        let mut same_device = raw.clone();
        same_device.payload["sender_device_number"] = Value::from(8);
        assert!(classify_received_envelope(&same_device).is_none());

        let mut different_conversation = raw;
        different_conversation.payload["conversation_id"] = Value::from("another-conversation");
        assert!(classify_received_envelope(&different_conversation).is_none());
    }

    #[test]
    fn ciphertext_decrypt_errors_unknown_types_and_sender_keys_remain_safe() {
        let mut failed = envelope(1, None);
        failed.payload["decrypt_error"] = Value::from("bad MAC");
        assert!(classify_received_envelope(&failed).is_none());
        assert!(
            classify_received_envelope(&envelope(
                99,
                Some(&json!({"kind":"message","message_id":"m","text":"x"}))
            ))
            .is_none()
        );
        let mut sender_key = envelope(3, None);
        sender_key.payload["distribution"] = Value::from(true);
        let received = classify_received_envelope(&sender_key).unwrap();
        assert_eq!(received.kind, "sender_key_received");
        assert_eq!(received.id, Some(507));
    }
}

#[cfg(test)]
mod portable_tests {
    use serde_json::{Value, json};

    use super::{ReceiveMetadata, SemanticPayload, parse_decrypted_payload};

    fn parse(envelope_type: i64, value: &Value) -> Option<SemanticPayload> {
        let plaintext = serde_json::to_vec(value).unwrap();
        let metadata = ReceiveMetadata {
            envelope_id: "envelope-1",
            client_timestamp: 123,
            sender_account_id: Some("account"),
            local_account_id: Some("account"),
            sender_device_number: Some(1),
            recipient_account_id: Some("account"),
            recipient_device_number: Some(2),
            conversation_id: value.get("conversation_id").and_then(Value::as_str),
        };
        parse_decrypted_payload(envelope_type, metadata, &plaintext)
    }

    #[test]
    fn legacy_message_text_is_preserved_as_a_typed_message() {
        let parsed = parse_decrypted_payload(
            1,
            ReceiveMetadata {
                envelope_id: "legacy-id",
                client_timestamp: 45,
                sender_account_id: None,
                local_account_id: None,
                sender_device_number: None,
                recipient_account_id: None,
                recipient_device_number: None,
                conversation_id: None,
            },
            b"old client text",
        )
        .unwrap();
        assert_eq!(parsed.kind, "message_received");
        assert_eq!(
            parsed.payload,
            json!({
                "kind":"message", "message_id":"legacy-id", "text":"old client text",
                "reply_to":null, "forward_from":null, "attachment_ids":[], "created_at":45
            })
        );
    }

    #[test]
    fn message_and_poll_payloads_are_normalized() {
        let message = parse(
            1,
            &json!({
                "kind":"message", "message_id":"m1", "text":"hello",
                "reply_to":{"message_id":"quoted","preview":17},
                "attachment_ids":["a1",false], "created_at":"bad", "ignored":true
            }),
        )
        .unwrap();
        assert_eq!(message.kind, "message_received");
        assert_eq!(
            message.payload,
            json!({
                "kind":"message", "message_id":"m1", "text":"hello",
                "reply_to":{"message_id":"quoted","preview":null,"sender_account_id":null},
                "forward_from":null, "attachment_ids":["a1"], "created_at":0
            })
        );

        let poll = parse(
            1,
            &json!({
                "kind":"poll", "poll_id":"p1", "title":"Q", "description":"",
                "options":[{"id":"a","text":"A","ignored":true},{"id":"b","text":"B"}]
            }),
        )
        .unwrap();
        assert_eq!(poll.kind, "poll_received");
        assert_eq!(
            poll.payload,
            json!({
                "kind":"poll", "poll_id":"p1", "title":"Q", "description":"",
                "options":[{"id":"a","text":"A"},{"id":"b","text":"B"}]
            })
        );
    }

    #[test]
    fn action_kind_selects_callback_and_timestamps_default_like_web() {
        let parsed = parse(
            4,
            &json!({
                "kind":"reaction", "target_message_id":"m1", "emoji":null,
                "created_at":"bad", "ignored":true
            }),
        )
        .unwrap();
        assert_eq!(parsed.kind, "message_reaction");
        assert_eq!(
            parsed.payload,
            json!({
                "kind":"reaction", "target_message_id":"m1", "emoji":null, "created_at":0
            })
        );
        assert!(parse(6, &json!({"kind":"edit","target_message_id":"m1"})).is_none());
    }

    #[test]
    fn history_chunks_and_completion_markers_have_distinct_kinds() {
        let mut chunk = json!({
            "kind":"history_sync", "version":1,
            "transfer_id":"550e8400-e29b-41d4-a716-446655440000",
            "conversation_id":"550e8400-e29b-41d4-a716-446655440001",
            "item_kind":"message", "item_id":"m1", "part_index":0,
            "part_count":1, "data":"e30="
        });
        assert_eq!(parse(2, &chunk).unwrap().kind, "history_chunk_received");
        chunk["item_kind"] = Value::from("complete");
        assert_eq!(parse(2, &chunk).unwrap().kind, "history_complete_received");
        chunk["part_index"] = Value::from(1);
        assert!(parse(2, &chunk).is_none());
    }

    #[test]
    fn history_requires_same_account_distinct_device_and_matching_conversation() {
        let chunk = json!({
            "kind":"history_sync", "version":1,
            "transfer_id":"550e8400-e29b-41d4-a716-446655440000",
            "conversation_id":"550e8400-e29b-41d4-a716-446655440001",
            "item_kind":"message", "item_id":"m1", "part_index":0,
            "part_count":1, "data":"e30="
        });
        let plaintext = serde_json::to_vec(&chunk).unwrap();
        let metadata = ReceiveMetadata {
            envelope_id: "envelope-1",
            client_timestamp: 123,
            sender_account_id: Some("account"),
            local_account_id: Some("account"),
            sender_device_number: Some(1),
            recipient_account_id: Some("account"),
            recipient_device_number: Some(2),
            conversation_id: Some("550e8400-e29b-41d4-a716-446655440001"),
        };
        assert_eq!(
            parse_decrypted_payload(2, metadata, &plaintext)
                .unwrap()
                .kind,
            "history_chunk_received"
        );
        assert!(
            parse_decrypted_payload(
                2,
                ReceiveMetadata {
                    local_account_id: None,
                    ..metadata
                },
                &plaintext,
            )
            .is_none()
        );
        assert!(
            parse_decrypted_payload(
                2,
                ReceiveMetadata {
                    local_account_id: Some("another-account"),
                    ..metadata
                },
                &plaintext,
            )
            .is_none()
        );
        assert!(
            parse_decrypted_payload(
                2,
                ReceiveMetadata {
                    sender_account_id: Some("foreign"),
                    ..metadata
                },
                &plaintext,
            )
            .is_none()
        );
        assert!(
            parse_decrypted_payload(
                2,
                ReceiveMetadata {
                    recipient_account_id: Some("foreign"),
                    ..metadata
                },
                &plaintext,
            )
            .is_none()
        );
        assert!(
            parse_decrypted_payload(
                2,
                ReceiveMetadata {
                    recipient_account_id: None,
                    ..metadata
                },
                &plaintext,
            )
            .is_none()
        );
        assert!(
            parse_decrypted_payload(
                2,
                ReceiveMetadata {
                    sender_device_number: Some(2),
                    ..metadata
                },
                &plaintext,
            )
            .is_none()
        );
        assert!(
            parse_decrypted_payload(
                2,
                ReceiveMetadata {
                    conversation_id: Some("other"),
                    ..metadata
                },
                &plaintext,
            )
            .is_none()
        );
    }

    #[test]
    fn attachment_and_call_payloads_keep_web_optional_field_shapes() {
        let attachment = parse(
            9,
            &json!({
                "kind":"attachment_key", "attachment_id":"a1", "key_hex":"aa",
                "base_nonce_hex":"bb", "conversation_id":17
            }),
        )
        .unwrap();
        assert_eq!(attachment.kind, "attachment_key_received");
        assert_eq!(
            attachment.payload,
            json!({
                "kind":"attachment_key", "attachment_id":"a1", "key_hex":"aa",
                "base_nonce_hex":"bb", "conversation_id":null
            })
        );

        let call = parse(
            12,
            &json!({
                "call_id":"c1", "kind":"ice", "sdp":17,
                "candidate":{"candidate":"candidate:1"}, "reason":false
            }),
        )
        .unwrap();
        assert_eq!(call.kind, "call_signal_received");
        assert_eq!(
            call.payload,
            json!({
                "call_id":"c1", "kind":"ice", "sdp":null,
                "candidate":{"candidate":"candidate:1"}, "reason":null
            })
        );
    }
}
