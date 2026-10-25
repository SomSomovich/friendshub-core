use serde_json::Value;

/// Keeps the browser API on the same payload builder as the native client.
pub(super) fn build_message_payload(
    message_id: &str,
    draft: &Value,
    created_at: f64,
) -> Result<Value, String> {
    friendshub_core::message_payload::build_message_payload(message_id, draft, created_at)
}

#[cfg(test)]
use serde_json::json;

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
