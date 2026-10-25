//! Edit, delete, and reaction envelopes.
//!
//! The encrypted action refers to the logical message id shared by all
//! devices. It is sent to every other conversation member and best-effort
//! synced to this account's sibling devices, following WEB's message-action
//! workflow.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::{common::bearer, conversations::ConversationDetail};
use crate::crypto::{device_cache, send::send_one};
use crate::db::auth as db_auth;
use crate::error::{Error, Result};
use crate::runtime::ActorState;
use crate::util::time::now_unix;

const ENVELOPE_TYPE_EDIT: i32 = 4;
const ENVELOPE_TYPE_DELETE: i32 = 5;
const ENVELOPE_TYPE_REACTION: i32 = 6;

#[derive(Debug, Deserialize)]
struct CommonFields {
    conversation_id: String,
    target_message_id: String,
}

#[derive(Debug, Deserialize)]
pub struct EditRequest {
    #[serde(flatten)]
    common: CommonFields,
    new_text: String,
}

pub async fn send_edit(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request: EditRequest = serde_json::from_slice(&payload)?;
    send_action(
        state,
        request.common,
        ActionKind::Edit {
            new_text: request.new_text,
        },
    )
    .await
}

#[derive(Debug, Deserialize)]
pub struct DeleteRequest {
    #[serde(flatten)]
    common: CommonFields,
}

pub async fn send_delete(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request: DeleteRequest = serde_json::from_slice(&payload)?;
    send_action(state, request.common, ActionKind::Delete).await
}

#[derive(Debug, Deserialize)]
pub struct ReactionRequest {
    #[serde(flatten)]
    common: CommonFields,
    /// `null` removes the reaction, exactly as on WEB.
    #[serde(default)]
    emoji: Option<String>,
}

pub async fn send_reaction(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request: ReactionRequest = serde_json::from_slice(&payload)?;
    send_action(
        state,
        request.common,
        ActionKind::Reaction {
            emoji: request.emoji,
        },
    )
    .await
}

#[derive(Debug, Clone)]
enum ActionKind {
    Edit { new_text: String },
    Delete,
    Reaction { emoji: Option<String> },
}

impl ActionKind {
    fn envelope_type(&self) -> i32 {
        match self {
            Self::Edit { .. } => ENVELOPE_TYPE_EDIT,
            Self::Delete => ENVELOPE_TYPE_DELETE,
            Self::Reaction { .. } => ENVELOPE_TYPE_REACTION,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Edit { .. } => "edit",
            Self::Delete => "delete",
            Self::Reaction { .. } => "reaction",
        }
    }
}

fn build_action_payload(target_message_id: &str, action: ActionKind, timestamp: i64) -> Value {
    match action {
        ActionKind::Edit { new_text } => json!({
            "kind": "edit",
            "target_message_id": target_message_id,
            "new_text": new_text,
            "edited_at": timestamp,
        }),
        ActionKind::Delete => json!({
            "kind": "delete",
            "target_message_id": target_message_id,
            "deleted_at": timestamp,
        }),
        ActionKind::Reaction { emoji } => json!({
            "kind": "reaction",
            "target_message_id": target_message_id,
            "emoji": emoji,
            "created_at": timestamp,
        }),
    }
}

fn validate_common_fields(common: &CommonFields) -> Result<()> {
    uuid::Uuid::parse_str(&common.conversation_id)
        .map_err(|error| Error::InvalidPayload(format!("conversation_id: {error}")))?;
    uuid::Uuid::parse_str(&common.target_message_id)
        .map_err(|error| Error::InvalidPayload(format!("target_message_id: {error}")))?;
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ActionDelivery {
    recipient_account_id: String,
    device_number: i64,
    envelope_id: String,
    is_prekey_message: bool,
    ciphertext_len: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ActionResponse {
    envelopes: Vec<ActionDelivery>,
    action_kind: &'static str,
    target_message_id: String,
    skipped_recipient_devices: Vec<i64>,
    skipped_own_devices: Vec<i64>,
}

async fn send_action(
    state: &Arc<ActorState>,
    common: CommonFields,
    action: ActionKind,
) -> Result<Vec<u8>> {
    validate_common_fields(&common)?;
    let auth = db_auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;
    let sender_account_id = auth.account_id.ok_or(Error::NotAuthenticated)?;
    let sender_device_number = auth.device_number.unwrap_or(1);
    let token = bearer(state).await?;

    // The server's member list is authoritative. The request cannot redirect
    // an action at one account or one device: every other member gets it.
    let detail: ConversationDetail = state
        .http
        .get(
            &format!("/api/v1/conversations/{}", common.conversation_id),
            Some(&token),
        )
        .await?;
    let mut recipients = Vec::new();
    for member in detail.members {
        if member != sender_account_id && !recipients.contains(&member) {
            recipients.push(member);
        }
    }

    let action_kind = action.name();
    let envelope_type = action.envelope_type();
    let plaintext = serde_json::to_vec(&build_action_payload(
        &common.target_message_id,
        action,
        now_unix(),
    ))?;

    let mut envelopes = Vec::new();
    let mut skipped_recipient_devices = Vec::new();
    let mut unreachable_cause = None;

    for recipient_account_id in recipients {
        let devices = device_cache::get(state, &recipient_account_id).await?;
        send_to_account_devices(
            state,
            &token,
            &sender_account_id,
            sender_device_number,
            &recipient_account_id,
            &devices,
            &plaintext,
            envelope_type,
            &common.conversation_id,
            &mut envelopes,
            &mut skipped_recipient_devices,
            &mut unreachable_cause,
        )
        .await?;
    }

    // The operation must fail if it only changed this device's local copy.
    if envelopes.is_empty() {
        return Err(unreachable_cause.unwrap_or_else(|| {
            Error::InvalidPayload("message action has no active recipient devices".into())
        }));
    }

    let own_devices = device_cache::get(state, &sender_account_id).await?;
    let mut skipped_own_devices = Vec::new();
    let own_devices = own_devices
        .into_iter()
        .filter(|device| device.device_number != sender_device_number)
        .collect::<Vec<_>>();
    send_to_account_devices(
        state,
        &token,
        &sender_account_id,
        sender_device_number,
        &sender_account_id,
        &own_devices,
        &plaintext,
        envelope_type,
        &common.conversation_id,
        &mut envelopes,
        &mut skipped_own_devices,
        &mut None,
    )
    .await?;

    Ok(serde_json::to_vec(&ActionResponse {
        envelopes,
        action_kind,
        target_message_id: common.target_message_id,
        skipped_recipient_devices,
        skipped_own_devices,
    })?)
}

#[allow(clippy::too_many_arguments)]
async fn send_to_account_devices(
    state: &Arc<ActorState>,
    token: &str,
    sender_account_id: &str,
    sender_device_number: i64,
    recipient_account_id: &str,
    devices: &[device_cache::CachedDevice],
    plaintext: &[u8],
    envelope_type: i32,
    conversation_id: &str,
    envelopes: &mut Vec<ActionDelivery>,
    skipped_devices: &mut Vec<i64>,
    unreachable_cause: &mut Option<Error>,
) -> Result<()> {
    for device in devices {
        match send_one(
            state,
            token,
            sender_account_id,
            sender_device_number,
            recipient_account_id,
            device.device_number,
            plaintext,
            envelope_type,
            Some(conversation_id),
        )
        .await
        {
            Ok(info) => envelopes.push(ActionDelivery {
                recipient_account_id: recipient_account_id.to_owned(),
                device_number: info.device_number,
                envelope_id: info.envelope_id,
                is_prekey_message: info.is_prekey_message,
                ciphertext_len: info.ciphertext_len,
            }),
            Err(error) if is_unreachable_device_error(&error) => {
                skipped_devices.push(device.device_number);
                if unreachable_cause.is_none() {
                    *unreachable_cause = Some(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// WEB treats only revoked devices and exhausted prekey pools as unreachable;
/// every other failure aborts the operation and is surfaced to the caller.
fn is_unreachable_device_error(error: &Error) -> bool {
    match error {
        Error::Server { status: 404, .. } => true,
        Error::Server { body, .. } => serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|body| body.get("code").and_then(Value::as_str).map(str::to_owned))
            .is_some_and(|code| code == "replenish_required"),
        Error::InvalidPayload(message) => {
            message.starts_with("recipient device ")
                && message.ends_with("does not exist; cache refreshed, retry")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActionKind, CommonFields, build_action_payload, is_unreachable_device_error,
        validate_common_fields,
    };
    use crate::error::Error;
    use serde_json::{Value, json};

    const CONVERSATION: &str = "conversation-1";
    const MESSAGE: &str = "logical-message-1";
    const CONVERSATION_UUID: &str = "11111111-1111-4111-8111-111111111111";
    const MESSAGE_UUID: &str = "22222222-2222-4222-8222-222222222222";

    #[test]
    fn edit_action_uses_logical_message_id_and_web_wire_fields() {
        let payload = build_action_payload(
            MESSAGE,
            ActionKind::Edit {
                new_text: "edited text".into(),
            },
            1_700_000_000,
        );

        assert_eq!(
            payload,
            json!({
                "kind": "edit",
                "target_message_id": MESSAGE,
                "new_text": "edited text",
                "edited_at": 1_700_000_000,
            })
        );
    }

    #[test]
    fn delete_action_has_logical_id_and_deleted_timestamp() {
        assert_eq!(
            build_action_payload(MESSAGE, ActionKind::Delete, 1_700_000_001),
            json!({
                "kind": "delete",
                "target_message_id": MESSAGE,
                "deleted_at": 1_700_000_001,
            })
        );
    }

    #[test]
    fn reaction_removal_is_null_and_has_created_timestamp() {
        let remove =
            build_action_payload(MESSAGE, ActionKind::Reaction { emoji: None }, 1_700_000_002);
        assert_eq!(
            remove,
            json!({
                "kind": "reaction",
                "target_message_id": MESSAGE,
                "emoji": Value::Null,
                "created_at": 1_700_000_002,
            })
        );

        let add = build_action_payload(
            MESSAGE,
            ActionKind::Reaction {
                emoji: Some("💙".into()),
            },
            1_700_000_003,
        );
        assert_eq!(add["emoji"], "💙");
    }

    #[test]
    fn action_request_uses_conversation_and_logical_message_not_device_target() {
        let request: super::EditRequest = serde_json::from_value(json!({
            "conversation_id": CONVERSATION,
            "target_message_id": MESSAGE,
            "new_text": "edited",
        }))
        .expect("WEB action request fields should deserialize");

        assert_eq!(request.common.conversation_id, CONVERSATION);
        assert_eq!(request.common.target_message_id, MESSAGE);
        assert_eq!(request.new_text, "edited");
    }

    #[test]
    fn reaction_request_accepts_null_as_removal() {
        let request: super::ReactionRequest = serde_json::from_value(json!({
            "conversation_id": CONVERSATION,
            "target_message_id": MESSAGE,
            "emoji": null,
        }))
        .expect("null reaction means remove");
        assert_eq!(request.emoji, None);
    }

    #[test]
    fn action_ids_follow_web_uuid_validation() {
        assert!(
            validate_common_fields(&CommonFields {
                conversation_id: CONVERSATION_UUID.into(),
                target_message_id: MESSAGE_UUID.into(),
            })
            .is_ok()
        );
        assert!(
            validate_common_fields(&CommonFields {
                conversation_id: CONVERSATION.into(),
                target_message_id: MESSAGE_UUID.into(),
            })
            .is_err()
        );
        assert!(
            validate_common_fields(&CommonFields {
                conversation_id: CONVERSATION_UUID.into(),
                target_message_id: MESSAGE.into(),
            })
            .is_err()
        );
    }

    #[test]
    fn only_stale_or_unprovisioned_devices_are_skipped() {
        assert!(is_unreachable_device_error(&Error::Server {
            status: 404,
            body: "not found".into(),
        }));
        assert!(is_unreachable_device_error(&Error::Server {
            status: 422,
            body: r#"{"code":"replenish_required"}"#.into(),
        }));
        assert!(is_unreachable_device_error(&Error::InvalidPayload(
            "recipient device 4 does not exist; cache refreshed, retry".into(),
        )));
        assert!(!is_unreachable_device_error(&Error::Server {
            status: 500,
            body: "server failed".into(),
        }));
        assert!(!is_unreachable_device_error(&Error::Network(
            "offline".into()
        )));
    }
}
