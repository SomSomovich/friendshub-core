use serde_json::{Map, Number, Value, json};

/// Builds the encrypted message payload used by the browser client. This is
/// deliberately a wire-shape conversion rather than a domain model: WEB has
/// already assigned stable ids/timestamps and Rust owns the serialized shape.
pub(super) fn build_message_payload(
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

#[test]
fn message_payload_preserves_web_wire_contract() {
    let draft = json!({
        "text": "hello",
        "replyTo": {
            "messageId": "11111111-1111-4111-8111-111111111111",
            "preview": "quoted",
            "senderAccountId": "22222222-2222-4222-8222-222222222222"
        },
        "forwardFrom": {
            "originalMessageId": "33333333-3333-4333-8333-333333333333",
            "originalConversationId": "44444444-4444-4444-8444-444444444444",
            "originalSenderAccountId": "55555555-5555-4555-8555-555555555555",
            "originalSenderDisplay": "Alice",
            "originalCreatedAt": 42
        },
        "attachmentIds": ["66666666-6666-4666-8666-666666666666"]
    });

    let payload = build_message_payload("77777777-7777-4777-8777-777777777777", &draft, 123.0)
        .expect("valid WEB message draft");

    assert_eq!(payload["kind"], "message");
    assert_eq!(
        payload["message_id"],
        "77777777-7777-4777-8777-777777777777"
    );
    assert_eq!(payload["created_at"], 123);
    assert_eq!(
        payload["reply_to"]["message_id"],
        "11111111-1111-4111-8111-111111111111"
    );
    assert_eq!(
        payload["reply_to"]["sender_account_id"],
        "22222222-2222-4222-8222-222222222222"
    );
    assert_eq!(
        payload["forward_from"]["original_message_id"],
        "33333333-3333-4333-8333-333333333333"
    );
    assert_eq!(payload["forward_from"]["original_created_at"], 42);
    assert_eq!(
        payload["attachment_ids"][0],
        "66666666-6666-4666-8666-666666666666"
    );
}

#[test]
fn message_payload_rejects_invalid_or_missing_text() {
    assert!(build_message_payload("m", &json!({}), 1.0).is_err());
    assert!(build_message_payload("m", &json!({ "text": 42 }), 1.0).is_err());
}

#[test]
fn message_payload_defaults_optional_fields_like_web() {
    let payload = build_message_payload("m", &json!({ "text": "hello" }), 1.0).unwrap();
    assert_eq!(payload["reply_to"], Value::Null);
    assert_eq!(payload["forward_from"], Value::Null);
    assert_eq!(payload["attachment_ids"], json!([]));
}

#[test]
fn message_payload_rejects_malformed_structured_fields() {
    assert!(build_message_payload("m", &json!({ "text": "x", "replyTo": {} }), 1.0).is_err());
    assert!(
        build_message_payload(
            "m",
            &json!({ "text": "x", "attachmentIds": ["ok", 7] }),
            1.0,
        )
        .is_err()
    );
    assert!(build_message_payload(" ", &json!({ "text": "x" }), 1.0).is_err());
    assert!(build_message_payload("m", &json!({ "text": "x" }), f64::NAN).is_err());
    assert!(build_message_payload("m", &json!({ "text": "x" }), 1.5).is_err());
}
