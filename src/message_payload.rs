//! Conversion from client message drafts to the encrypted payload wire format.

use serde_json::{Map, Number, Value, json};

/// Builds the message payload shared with the WEB client.
///
/// The caller supplies the stable logical message id and creation timestamp.
/// Draft fields use camelCase; the encrypted payload uses snake_case. Optional
/// references become null and omitted attachment ids become an empty array.
/// Validation follows the existing WASM builder, including JavaScript's safe
/// integer range for `created_at`.
pub fn build_message_payload(
    message_id: &str,
    draft: &Value,
    created_at: f64,
) -> Result<Value, String> {
    if message_id.trim().is_empty() {
        return Err("message_id must not be empty".into());
    }
    if !created_at.is_finite()
        || created_at.fract() != 0.0
        || created_at.abs() > 9_007_199_254_740_991.0
    {
        return Err("created_at must be a safe integer".into());
    }
    let created_at = Number::from(created_at as i64);
    let draft = draft
        .as_object()
        .ok_or_else(|| "message draft must be an object".to_owned())?;
    let text = draft
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| "message draft text must be a string".to_owned())?;

    let reply_to = match draft.get("replyTo") {
        None | Some(Value::Null) => Value::Null,
        Some(value) => build_reply(value)?,
    };
    let forward_from = match draft.get("forwardFrom") {
        None | Some(Value::Null) => Value::Null,
        Some(value) => build_forward(value)?,
    };
    let attachment_ids = match draft.get("attachmentIds") {
        None => Value::Array(Vec::new()),
        Some(Value::Array(values)) => {
            if values.iter().any(|value| !value.is_string()) {
                return Err("attachmentIds must contain only strings".into());
            }
            Value::Array(values.clone())
        }
        Some(_) => return Err("attachmentIds must be an array".into()),
    };

    Ok(json!({
        "kind": "message",
        "message_id": message_id,
        "text": text,
        "reply_to": reply_to,
        "forward_from": forward_from,
        "attachment_ids": attachment_ids,
        "created_at": created_at,
    }))
}

fn build_reply(value: &Value) -> Result<Value, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "replyTo must be an object or null".to_owned())?;
    let message_id = required_string(object, "messageId", "replyTo.messageId")?;
    Ok(json!({
        "message_id": message_id,
        "preview": optional_string(object, "preview"),
        "sender_account_id": optional_string(object, "senderAccountId"),
    }))
}

fn build_forward(value: &Value) -> Result<Value, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "forwardFrom must be an object or null".to_owned())?;
    let original_message_id =
        required_string(object, "originalMessageId", "forwardFrom.originalMessageId")?;
    let original_conversation_id = required_string(
        object,
        "originalConversationId",
        "forwardFrom.originalConversationId",
    )?;
    let original_sender_account_id = required_string(
        object,
        "originalSenderAccountId",
        "forwardFrom.originalSenderAccountId",
    )?;
    let original_created_at = object
        .get("originalCreatedAt")
        .and_then(Value::as_number)
        .cloned()
        .ok_or_else(|| "forwardFrom.originalCreatedAt must be a number".to_owned())?;
    Ok(json!({
        "original_message_id": original_message_id,
        "original_conversation_id": original_conversation_id,
        "original_sender_account_id": original_sender_account_id,
        "original_sender_display": optional_string(object, "originalSenderDisplay"),
        "original_created_at": original_created_at,
    }))
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<&'a str, String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label} must be a string"))
}

fn optional_string(object: &Map<String, Value>, key: &str) -> Value {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(|value| Value::String(value.to_owned()))
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::build_message_payload;
    use serde_json::{Value, json};

    #[test]
    fn converts_complete_draft_to_the_encrypted_web_wire_shape() {
        let draft = json!({
            "text": "Привет 👋\nquoted \"text\"",
            "replyTo": {
                "messageId": "reply-id",
                "preview": "quote",
                "senderAccountId": "reply-sender",
                "extra": "discard"
            },
            "forwardFrom": {
                "originalMessageId": "forward-id",
                "originalConversationId": "source-conversation",
                "originalSenderAccountId": "source-sender",
                "originalSenderDisplay": "Alice",
                "originalCreatedAt": 42.5,
                "extra": "discard"
            },
            "attachmentIds": ["b", "a", "b", ""],
            "extra": "discard"
        });
        let original = draft.clone();

        assert_eq!(
            build_message_payload(" message-id ", &draft, 123.0).unwrap(),
            json!({
                "kind": "message",
                "message_id": " message-id ",
                "text": "Привет 👋\nquoted \"text\"",
                "reply_to": {
                    "message_id": "reply-id",
                    "preview": "quote",
                    "sender_account_id": "reply-sender"
                },
                "forward_from": {
                    "original_message_id": "forward-id",
                    "original_conversation_id": "source-conversation",
                    "original_sender_account_id": "source-sender",
                    "original_sender_display": "Alice",
                    "original_created_at": 42.5
                },
                "attachment_ids": ["b", "a", "b", ""],
                "created_at": 123
            })
        );
        assert_eq!(draft, original);
    }

    #[test]
    fn omitted_or_null_references_emit_explicit_null_and_empty_attachments() {
        for draft in [
            json!({"text": ""}),
            json!({"text": "", "replyTo": null, "forwardFrom": null}),
        ] {
            assert_eq!(
                build_message_payload("m", &draft, 0.0).unwrap(),
                json!({
                    "kind": "message",
                    "message_id": "m",
                    "text": "",
                    "reply_to": null,
                    "forward_from": null,
                    "attachment_ids": [],
                    "created_at": 0
                })
            );
        }
    }

    #[test]
    fn optional_nested_strings_coerce_non_strings_and_missing_values_to_null() {
        for optional in [None, Some(Value::Null), Some(json!(17)), Some(json!({}))] {
            let mut draft = json!({
                "text": "x",
                "replyTo": {"messageId": ""},
                "forwardFrom": {
                    "originalMessageId": "",
                    "originalConversationId": "",
                    "originalSenderAccountId": "",
                    "originalCreatedAt": -1
                }
            });
            if let Some(value) = optional {
                draft["replyTo"]["preview"] = value.clone();
                draft["replyTo"]["senderAccountId"] = value.clone();
                draft["forwardFrom"]["originalSenderDisplay"] = value;
            }

            let payload = build_message_payload("m", &draft, 1.0).unwrap();
            assert_eq!(
                payload["reply_to"],
                json!({"message_id": "", "preview": null, "sender_account_id": null})
            );
            assert_eq!(
                payload["forward_from"]["original_sender_display"],
                Value::Null
            );
            assert_eq!(payload["forward_from"]["original_created_at"], -1);
        }
    }

    #[test]
    fn rejects_empty_message_ids() {
        for id in ["", " \t\n", "\u{2003}"] {
            assert_eq!(
                build_message_payload(id, &json!({"text": "x"}), 1.0).unwrap_err(),
                "message_id must not be empty"
            );
        }
    }

    #[test]
    fn accepts_signed_safe_integer_timestamps_and_normalizes_negative_zero() {
        for (timestamp, expected) in [
            (9_007_199_254_740_991.0, 9_007_199_254_740_991_i64),
            (-9_007_199_254_740_991.0, -9_007_199_254_740_991_i64),
            (-0.0, 0_i64),
            (-42.0, -42_i64),
        ] {
            let payload = build_message_payload("m", &json!({"text": "x"}), timestamp).unwrap();
            assert_eq!(payload["created_at"], json!(expected));
        }
    }

    #[test]
    fn rejects_non_finite_fractional_and_unsafe_timestamps() {
        for timestamp in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            1.5,
            -0.5,
            9_007_199_254_740_992.0,
            -9_007_199_254_740_992.0,
        ] {
            assert_eq!(
                build_message_payload("m", &json!({"text": "x"}), timestamp).unwrap_err(),
                "created_at must be a safe integer"
            );
        }
    }

    #[test]
    fn rejects_non_object_drafts_and_missing_or_non_string_text() {
        for draft in [Value::Null, json!([]), json!("text"), json!(4)] {
            assert_eq!(
                build_message_payload("m", &draft, 1.0).unwrap_err(),
                "message draft must be an object"
            );
        }
        for draft in [json!({}), json!({"text": null}), json!({"text": 4})] {
            assert_eq!(
                build_message_payload("m", &draft, 1.0).unwrap_err(),
                "message draft text must be a string"
            );
        }
    }

    #[test]
    fn rejects_malformed_replies() {
        for (reply, error) in [
            (json!([]), "replyTo must be an object or null"),
            (json!("m"), "replyTo must be an object or null"),
            (json!({}), "replyTo.messageId must be a string"),
            (
                json!({"messageId": null}),
                "replyTo.messageId must be a string",
            ),
        ] {
            assert_eq!(
                build_message_payload("m", &json!({"text": "x", "replyTo": reply}), 1.0)
                    .unwrap_err(),
                error
            );
        }
    }

    #[test]
    fn rejects_malformed_forwards_and_requires_each_original_field() {
        for forward in [json!([]), json!("m"), json!(4)] {
            assert_eq!(
                build_message_payload("m", &json!({"text": "x", "forwardFrom": forward}), 1.0)
                    .unwrap_err(),
                "forwardFrom must be an object or null"
            );
        }
        let valid = json!({
            "originalMessageId": "m",
            "originalConversationId": "c",
            "originalSenderAccountId": "a",
            "originalCreatedAt": 42
        });
        for (field, error) in [
            (
                "originalMessageId",
                "forwardFrom.originalMessageId must be a string",
            ),
            (
                "originalConversationId",
                "forwardFrom.originalConversationId must be a string",
            ),
            (
                "originalSenderAccountId",
                "forwardFrom.originalSenderAccountId must be a string",
            ),
            (
                "originalCreatedAt",
                "forwardFrom.originalCreatedAt must be a number",
            ),
        ] {
            for invalid in [None, Some(Value::Null), Some(json!(false))] {
                let mut forward = valid.clone();
                if let Some(value) = invalid {
                    forward[field] = value;
                } else {
                    forward.as_object_mut().unwrap().remove(field);
                }
                assert_eq!(
                    build_message_payload("m", &json!({"text": "x", "forwardFrom": forward}), 1.0)
                        .unwrap_err(),
                    error
                );
            }
        }
    }

    #[test]
    fn rejects_null_non_array_or_mixed_attachments() {
        for attachments in [Value::Null, json!("a"), json!({})] {
            assert_eq!(
                build_message_payload(
                    "m",
                    &json!({"text": "x", "attachmentIds": attachments}),
                    1.0
                )
                .unwrap_err(),
                "attachmentIds must be an array"
            );
        }
        for invalid in [Value::Null, json!(4), json!({}), json!([])] {
            assert_eq!(
                build_message_payload(
                    "m",
                    &json!({"text": "x", "attachmentIds": ["ok", invalid]}),
                    1.0
                )
                .unwrap_err(),
                "attachmentIds must contain only strings"
            );
        }
    }
}
