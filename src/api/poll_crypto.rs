//! Native counterparts of WEB's encrypted poll payloads and history copy.

use crate::api::{chat_extras, common::bearer, conversations::ConversationDetail};
use crate::crypto::{device_cache, groups, manager};
use crate::db::auth;
use crate::error::{Error, Result};
use crate::proto::{ClientFrame, Envelope, EnvelopeUpload, client_frame};
use crate::runtime::ActorState;
use crate::util::time::now_unix;
use base64::{
    Engine, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose::STANDARD},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PollMetadata {
    pub title: String,
    pub description: String,
    pub options: Vec<PollOption>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PollOption {
    pub id: String,
    pub text: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PollSettings {
    pub poll_type: String,
    pub allows_multiple: bool,
    pub allows_revoting: bool,
    pub allows_user_options: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_period_seconds: Option<i64>,
    pub correct_option_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateConversationPollRequest {
    pub conversation_id: String,
    pub metadata: PollMetadata,
    pub settings: PollSettings,
}

/// The authoritative REST record is retained when its later history copy fails.
#[derive(Debug, Serialize, Deserialize)]
pub struct CreatedPoll {
    pub item: Value,
    pub metadata: PollMetadata,
    pub history_synced: bool,
}

#[derive(Debug, Deserialize)]
pub struct EncryptPollPayloadRequest {
    pub conversation_id: String,
    pub payload: Value,
}

#[derive(Debug, Deserialize)]
pub struct EncryptPollOptionRequest {
    pub conversation_id: String,
    pub text: String,
}

#[derive(Debug, Deserialize)]
pub struct DecryptPollPayloadRequest {
    pub sender_account_id: String,
    pub sender_device_number: i64,
    pub encrypted_meta: String,
}

async fn encrypt_json(
    state: &ActorState,
    conversation_id: &str,
    payload: &Value,
) -> Result<String> {
    let ciphertext =
        groups::encrypt_for_group(state, conversation_id, &serde_json::to_vec(payload)?)
            .await
            .map_err(Error::from)?;
    Ok(STANDARD.encode(ciphertext))
}

/// Encrypt JSON with the conversation's sender key, distributing it first.
pub async fn encrypt_poll_payload(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request: EncryptPollPayloadRequest = serde_json::from_slice(&payload)?;
    prepare_conversation(state, &request.conversation_id).await?;
    Ok(serde_json::to_vec(
        &encrypt_json(state, &request.conversation_id, &request.payload).await?,
    )?)
}

/// Encrypt the WEB option payload `{ "text": text }` under the sender key.
pub async fn encrypt_poll_option(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request: EncryptPollOptionRequest = serde_json::from_slice(&payload)?;
    encrypt_poll_payload(
        state,
        serde_json::to_vec(&serde_json::json!({
            "conversation_id": request.conversation_id, "payload": {"text":request.text}
        }))?,
    )
    .await
}

/// Decode WEB's standard-base64 SenderKeyMessage into its JSON value.
pub async fn decrypt_poll_payload(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    let request: DecryptPollPayloadRequest = serde_json::from_slice(&payload)?;
    uuid_bytes(&request.sender_account_id, "sender_account_id")?;
    device_number(request.sender_device_number)?;
    let ciphertext = decode_web_base64(&request.encrypted_meta)?;
    let plaintext = groups::decrypt_from_group(
        state,
        &request.sender_account_id,
        request.sender_device_number,
        &ciphertext,
    )
    .await
    .map_err(Error::from)?;
    let value: Value = serde_json::from_slice(&plaintext)?;
    Ok(serde_json::to_vec(&value)?)
}

/// Create the encrypted REST poll, then publish its poll-id-linked history copy.
/// Signal state uses the existing stores; no local poll records are invented.
pub async fn create_conversation_poll(
    state: &Arc<ActorState>,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let request: CreateConversationPollRequest = serde_json::from_slice(&payload)?;
    if !matches!(request.settings.poll_type.as_str(), "regular" | "quiz") {
        return Err(Error::InvalidPayload(
            "poll_type must be 'regular' or 'quiz'".into(),
        ));
    }
    if request
        .settings
        .open_period_seconds
        .is_some_and(|period| period <= 0)
    {
        return Err(Error::InvalidPayload(
            "open_period_seconds must be positive".into(),
        ));
    }
    validate_poll_draft(&request.metadata, &request.settings)?;
    prepare_conversation(state, &request.conversation_id).await?;
    let metadata = serde_json::to_value(&request.metadata)?;
    let encrypted_meta = encrypt_json(state, &request.conversation_id, &metadata).await?;
    let mut body = serde_json::to_value(&request.settings)?;
    body["conversation_id"] = serde_json::json!(request.conversation_id);
    body["encrypted_meta"] = serde_json::json!(encrypted_meta);
    body["option_ids"] = serde_json::json!(
        request
            .metadata
            .options
            .iter()
            .map(|option| &option.id)
            .collect::<Vec<_>>()
    );
    let response = chat_extras::poll_create(state, serde_json::to_vec(&body)?).await?;
    let item: Value = serde_json::from_slice(&response)?;
    let history = async {
        let poll_id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::InvalidPayload("poll response has no id".into()))?;
        send_history(state, &request.conversation_id, poll_id, &request.metadata).await
    }
    .await;
    if let Err(error) = &history {
        tracing::warn!(%error, "poll created but its encrypted history copy could not be sent");
    }
    Ok(serde_json::to_vec(&CreatedPoll {
        item,
        metadata: request.metadata,
        history_synced: history.is_ok(),
    })?)
}

/// Match WEB's isValidPollDraft before reading membership or mutating keys.
fn validate_poll_draft(metadata: &PollMetadata, settings: &PollSettings) -> Result<()> {
    if !has_javascript_trimmed_content(&metadata.title)
        || metadata.title.chars().take(65).count() > 64
    {
        return Err(Error::InvalidPayload(
            "poll title must contain non-whitespace text and at most 64 characters".into(),
        ));
    }
    if metadata.description.chars().take(129).count() > 128 {
        return Err(Error::InvalidPayload(
            "poll description must contain at most 128 characters".into(),
        ));
    }
    if !(2..=15).contains(&metadata.options.len()) {
        return Err(Error::InvalidPayload(
            "poll must contain between 2 and 15 options".into(),
        ));
    }
    let mut seen = HashSet::new();
    for option in &metadata.options {
        // WEB measures opaque ids with String.length (UTF-16 code units),
        // whereas human-readable text uses [...text].length (code points).
        if option.id.is_empty()
            || option.id.encode_utf16().take(65).count() > 64
            || !seen.insert(option.id.as_str())
        {
            return Err(Error::InvalidPayload(
                "poll option ids must be unique and contain 1 to 64 UTF-16 code units".into(),
            ));
        }
        if !has_javascript_trimmed_content(&option.text)
            || option.text.chars().take(129).count() > 128
        {
            return Err(Error::InvalidPayload(
                "poll option text must contain non-whitespace text and at most 128 characters"
                    .into(),
            ));
        }
    }
    if settings.poll_type == "quiz"
        && !settings
            .correct_option_id
            .as_deref()
            .is_some_and(|id| seen.contains(id))
    {
        return Err(Error::InvalidPayload(
            "quiz correct_option_id must identify an existing option".into(),
        ));
    }
    Ok(())
}

fn has_javascript_trimmed_content(value: &str) -> bool {
    value.chars().any(|character| {
        !matches!(
            character,
            '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{00a0}' | '\u{1680}'
                | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}'
                | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
        )
    })
}

struct ConversationSender {
    account_id: String,
    device_number: i64,
    token: String,
    recipients: Vec<(String, i64)>,
}

async fn prepare_conversation(
    state: &Arc<ActorState>,
    conversation_id: &str,
) -> Result<ConversationSender> {
    uuid_bytes(conversation_id, "conversation_id")?;
    let auth = auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;
    let account_id = auth.account_id.ok_or(Error::NotAuthenticated)?;
    uuid_bytes(&account_id, "account_id")?;
    let device = auth.device_number.ok_or(Error::NotAuthenticated)?;
    device_number(device)?;
    let token = bearer(state).await?;
    let detail: ConversationDetail = state
        .http
        .get(
            &format!("/api/v1/conversations/{conversation_id}"),
            Some(&token),
        )
        .await?;
    let mut recipients = Vec::new();
    for member in detail.members {
        if member == account_id {
            continue;
        }
        uuid_bytes(&member, "member_account_id")?;
        for device in device_cache::get(state, &member).await? {
            device_number(device.device_number)?;
            if !recipients.contains(&(member.clone(), device.device_number)) {
                recipients.push((member.clone(), device.device_number));
            }
        }
    }
    let sender = ConversationSender {
        account_id,
        device_number: device,
        token,
        recipients,
    };
    let crypto_snapshot = crate::crypto::history_stage::load_snapshot(&state.db)
        .await
        .map_err(|error| Error::Database(format!("failed to snapshot crypto state: {error}")))?;
    let prepared = async {
        let distribution = groups::create_distribution(state, conversation_id)
            .await
            .map_err(Error::from)?;
        // WEB seals UTF-8 hex text in a pairwise SENDER_KEY envelope.
        let distribution_text = hex::encode(distribution);
        let mut envelopes = Vec::new();
        for (account, device) in &sender.recipients {
            envelopes.push(
                pairwise_envelope(
                    state,
                    &sender,
                    account,
                    *device,
                    conversation_id,
                    distribution_text.as_bytes(),
                    3,
                )
                .await?,
            );
        }
        Ok(envelopes)
    }
    .await;
    let envelopes =
        rollback_crypto_snapshot_on_prepare_error(state, &crypto_snapshot, prepared).await?;
    upload(state, envelopes).await?;
    Ok(sender)
}

async fn rollback_crypto_snapshot_on_prepare_error<T>(
    state: &ActorState,
    base_snapshot: &crate::crypto::history_stage::CryptoSnapshot,
    prepared: Result<T>,
) -> Result<T> {
    match prepared {
        Ok(value) => Ok(value),
        Err(error) => {
            if let Err(rollback_error) =
                crate::crypto::history_stage::replace_snapshot(&state.db, base_snapshot).await
            {
                return Err(Error::Database(format!(
                    "{error}; failed to restore crypto state after sender-key fanout preparation: {rollback_error}"
                )));
            }
            Err(error)
        }
    }
}

async fn send_history(
    state: &Arc<ActorState>,
    conversation_id: &str,
    poll_id: &str,
    metadata: &PollMetadata,
) -> Result<()> {
    let sender = prepare_conversation(state, conversation_id).await?;
    let plaintext = history_plaintext(poll_id, metadata)?;
    let ciphertext = groups::encrypt_for_group(state, conversation_id, &plaintext)
        .await
        .map_err(Error::from)?;
    let mut envelopes = Vec::new();
    for (account, device) in &sender.recipients {
        envelopes.push(envelope(
            &sender,
            account,
            *device,
            conversation_id,
            ciphertext.clone(),
            false,
            1,
        )?);
    }
    for device in device_cache::get(state, &sender.account_id).await? {
        if device.device_number == sender.device_number {
            continue;
        }
        match pairwise_envelope(
            state,
            &sender,
            &sender.account_id,
            device.device_number,
            conversation_id,
            &plaintext,
            1,
        )
        .await
        {
            Ok(copy) => envelopes.push(copy),
            Err(Error::Server { status: 404, .. }) => {}
            Err(Error::Server { body, .. }) if body.contains("replenish_required") => {}
            Err(error) => return Err(error),
        }
    }
    upload(state, envelopes).await
}

async fn pairwise_envelope(
    state: &ActorState,
    sender: &ConversationSender,
    account: &str,
    device: i64,
    conversation_id: &str,
    plaintext: &[u8],
    kind: i32,
) -> Result<Envelope> {
    if !manager::has_session(state, account, device)
        .await
        .map_err(Error::from)?
    {
        let bundle: Value = state
            .http
            .get(
                &format!("/api/v1/accounts/{account}/devices/{device}/bundle"),
                Some(&sender.token),
            )
            .await?;
        manager::establish_outbound_session(state, account, device, &bundle)
            .await
            .map_err(Error::from)?;
    }
    let (ciphertext, is_prekey) = manager::encrypt_for_device(state, account, device, plaintext)
        .await
        .map_err(Error::from)?;
    envelope(
        sender,
        account,
        device,
        conversation_id,
        ciphertext,
        is_prekey,
        kind,
    )
}

fn envelope(
    sender: &ConversationSender,
    account: &str,
    device: i64,
    conversation_id: &str,
    ciphertext: Vec<u8>,
    is_prekey_message: bool,
    envelope_type: i32,
) -> Result<Envelope> {
    Ok(Envelope {
        envelope_id: Uuid::now_v7().as_bytes().to_vec(),
        sender_account_id: uuid_bytes(&sender.account_id, "sender_account_id")?,
        sender_device_number: device_number(sender.device_number)?,
        recipient_account_id: uuid_bytes(account, "recipient_account_id")?,
        recipient_device_number: device_number(device)?,
        conversation_id: uuid_bytes(conversation_id, "conversation_id")?,
        ciphertext,
        is_prekey_message,
        envelope_type,
        client_timestamp: now_unix(),
        sender_is_bot: false,
        send_at: 0,
    })
}

async fn upload(state: &ActorState, envelopes: Vec<Envelope>) -> Result<()> {
    if !envelopes.is_empty() {
        state
            .ws
            .send_frame(ClientFrame {
                kind: Some(client_frame::Kind::Upload(EnvelopeUpload { envelopes })),
            })
            .await?;
    }
    Ok(())
}

fn uuid_bytes(value: &str, field: &str) -> Result<Vec<u8>> {
    Uuid::parse_str(value)
        .map(|id| id.as_bytes().to_vec())
        .map_err(|error| Error::InvalidPayload(format!("{field}: {error}")))
}

fn device_number(value: i64) -> Result<u32> {
    let number =
        u32::try_from(value).map_err(|_| Error::InvalidPayload("invalid device number".into()))?;
    libsignal_protocol::DeviceId::try_from(number)
        .map_err(|_| Error::InvalidPayload("invalid device number".into()))?;
    Ok(number)
}

fn history_plaintext(poll_id: &str, metadata: &PollMetadata) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::json!({
        "kind":"poll", "poll_id":poll_id, "title":metadata.title,
        "description":metadata.description, "options":metadata.options
    }))?)
}

fn decode_web_base64(value: &str) -> Result<Vec<u8>> {
    // Match browser atob's forgiving-base64 rules, including its exact ASCII
    // whitespace set. Padding may be omitted but may not be partially supplied.
    let mut normalized: Vec<u8> = value
        .bytes()
        .filter(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0c))
        .collect();
    if normalized.len() % 4 == 0 {
        let padding = if normalized.ends_with(b"==") {
            2
        } else if normalized.ends_with(b"=") {
            1
        } else {
            0
        };
        normalized.truncate(normalized.len() - padding);
    }
    const DECODER: GeneralPurpose = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    );
    DECODER
        .decode(normalized)
        .map_err(|error| Error::InvalidPayload(format!("encrypted_meta base64: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        crypto::groups,
        db::{self, auth::AuthState},
        transport::HttpClient,
    };
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde_json::json;
    use sqlx::sqlite::SqlitePoolOptions;

    const ALICE: &str = "11111111-1111-4111-8111-111111111111";
    const BOB: &str = "22222222-2222-4222-8222-222222222222";
    const CONVERSATION: &str = "33333333-3333-4333-8333-333333333333";

    async fn state(account_id: &str) -> Arc<ActorState> {
        state_at(account_id, "http://127.0.0.1:1").await
    }

    async fn state_at(account_id: &str, api_base: &str) -> Arc<ActorState> {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        db::migrations::MIGRATOR.run(&db).await.unwrap();
        db::auth::store(
            &db,
            &AuthState {
                account_id: Some(account_id.into()),
                device_number: Some(1),
                session_token: Some("poll-fixture-session".into()),
                totp_enabled: Some(0),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let config: Config = serde_json::from_value(json!({
            "db_path":"/tmp/unused-poll-fixture.sqlite", "api_base":api_base,
            "ws_url":"ws://127.0.0.1:1", "discovery":{"enabled":false},
            "log_level":"off", "log_format":"text"
        }))
        .unwrap();
        let http = HttpClient::new(&config).unwrap();
        Arc::new(ActorState::new(config, db, http))
    }

    fn valid_poll_draft() -> Value {
        json!({
            "conversation_id":CONVERSATION,
            "metadata":{"title":"Meet", "description":"", "options":[
                {"id":"one", "text":"Friday"}, {"id":"two", "text":"Saturday"}
            ]},
            "settings":{"poll_type":"regular", "allows_multiple":false,
                "allows_revoting":true, "allows_user_options":false, "correct_option_id":null}
        })
    }

    async fn assert_invalid_poll_draft(request: Value) {
        // This authenticated fixture has no HTTP listener. A request that
        // reaches membership resolution fails as Network instead of InvalidPayload.
        let sender = state(ALICE).await;
        let error = create_conversation_poll(&sender, serde_json::to_vec(&request).unwrap())
            .await
            .expect_err("invalid draft must fail before membership lookup");
        assert!(
            matches!(error, Error::InvalidPayload(_)),
            "expected pre-network validation, got {error}"
        );
        let keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM group_sender_keys")
            .fetch_one(&sender.db)
            .await
            .unwrap();
        assert_eq!(
            keys, 0,
            "invalid draft must leave sender-key state untouched"
        );
    }

    #[tokio::test]
    async fn poll_draft_rejects_empty_whitespace_and_long_titles_before_network() {
        for title in [
            "".to_string(),
            " \t\r\n".to_string(),
            "\u{feff}\u{00a0}".to_string(),
            "🌍".repeat(65),
        ] {
            let mut request = valid_poll_draft();
            request["metadata"]["title"] = json!(title);
            assert_invalid_poll_draft(request).await;
        }
    }

    #[tokio::test]
    async fn poll_draft_rejects_long_description_before_network() {
        let mut request = valid_poll_draft();
        request["metadata"]["description"] = json!("🌍".repeat(129));
        assert_invalid_poll_draft(request).await;
    }

    #[tokio::test]
    async fn poll_draft_rejects_option_counts_outside_two_through_fifteen_before_network() {
        for count in [0, 1, 16] {
            let mut request = valid_poll_draft();
            request["metadata"]["options"] = json!(
                (0..count)
                    .map(|index| json!({"id":format!("option-{index}"),"text":"yes"}))
                    .collect::<Vec<_>>()
            );
            assert_invalid_poll_draft(request).await;
        }
    }

    #[tokio::test]
    async fn poll_draft_rejects_empty_duplicate_and_overlong_option_ids_before_network() {
        for id in [
            "".to_string(),
            "two".to_string(),
            "a".repeat(65),
            "🌍".repeat(33),
        ] {
            let mut request = valid_poll_draft();
            request["metadata"]["options"][0]["id"] = json!(id);
            assert_invalid_poll_draft(request).await;
        }
    }

    #[tokio::test]
    async fn poll_draft_rejects_empty_whitespace_and_long_option_text_before_network() {
        for text in [
            "".to_string(),
            " \t\n".to_string(),
            "\u{feff}".to_string(),
            "🌍".repeat(129),
        ] {
            let mut request = valid_poll_draft();
            request["metadata"]["options"][0]["text"] = json!(text);
            assert_invalid_poll_draft(request).await;
        }
    }

    #[tokio::test]
    async fn poll_draft_rejects_quiz_without_an_existing_correct_option_before_network() {
        for answer in [Value::Null, json!("missing")] {
            let mut request = valid_poll_draft();
            request["settings"]["poll_type"] = json!("quiz");
            request["settings"]["correct_option_id"] = answer;
            assert_invalid_poll_draft(request).await;
        }
    }

    #[tokio::test]
    async fn poll_draft_rejects_invalid_conversation_uuid_before_network() {
        let mut request = valid_poll_draft();
        request["conversation_id"] = json!("not-a-uuid");
        assert_invalid_poll_draft(request).await;
    }

    #[tokio::test]
    async fn poll_draft_accepts_web_unicode_boundaries_opaque_ids_and_quiz_membership() {
        let sender = state(ALICE).await;
        let mut boundary = valid_poll_draft();
        boundary["metadata"]["title"] = json!("🌍".repeat(64));
        boundary["metadata"]["description"] = json!("🌍".repeat(128));
        boundary["metadata"]["options"] = json!(
            (0..15)
                .map(|index| json!({
                    "id": if index == 0 {"🌍".repeat(32)} else {format!("opaque-id-{index}")},
                    "text":"🌍".repeat(128)
                }))
                .collect::<Vec<_>>()
        );
        let mut javascript_trim = valid_poll_draft();
        // U+0085 is Rust whitespace, but JavaScript String.trim retains it.
        javascript_trim["metadata"]["title"] = json!("\u{0085}");
        javascript_trim["metadata"]["options"][0]["text"] = json!("\u{0085}");
        let mut quiz = valid_poll_draft();
        quiz["settings"]["poll_type"] = json!("quiz");
        quiz["settings"]["correct_option_id"] = json!("two");
        for request in [boundary, javascript_trim, quiz] {
            let error = create_conversation_poll(&sender, serde_json::to_vec(&request).unwrap())
                .await
                .expect_err("valid drafts reach this fixture's offline HTTP boundary");
            assert!(
                matches!(error, Error::Network(_)),
                "valid WEB draft was rejected: {error}"
            );
        }
    }

    #[tokio::test]
    async fn poll_payload_is_base64_sender_key_json_readable_by_another_device() {
        let sender = state(ALICE).await;
        let receiver = state(BOB).await;
        let distribution = groups::create_distribution(&sender, CONVERSATION)
            .await
            .unwrap();
        groups::process_distribution(&receiver, ALICE, 1, &distribution)
            .await
            .unwrap();
        let metadata = json!({"title":"Встреча 🌍", "description":"", "options":[
            {"id":"one", "text":"Пятница"}, {"id":"two", "text":"Суббота"}
        ]});
        let encoded = encrypt_json(&sender, CONVERSATION, &metadata)
            .await
            .expect("encrypt poll metadata");
        let ciphertext = STANDARD.decode(&encoded).expect("standard base64");
        assert_ne!(ciphertext, serde_json::to_vec(&metadata).unwrap());
        let decrypted = groups::decrypt_from_group(&receiver, ALICE, 1, &ciphertext)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&decrypted).unwrap(),
            metadata
        );
    }

    #[tokio::test]
    async fn decrypt_poll_payload_decodes_web_base64_sender_key_json() {
        let sender = state(ALICE).await;
        let receiver = state(BOB).await;
        let distribution = groups::create_distribution(&sender, CONVERSATION)
            .await
            .unwrap();
        groups::process_distribution(&receiver, ALICE, 1, &distribution)
            .await
            .unwrap();
        let ciphertext = groups::encrypt_for_group(&sender, CONVERSATION, br#"{"text":"Friday"}"#)
            .await
            .unwrap();
        let decrypted = decrypt_poll_payload(
            &receiver,
            serde_json::to_vec(&json!({
                "sender_account_id":ALICE, "sender_device_number":1,
                "encrypted_meta":STANDARD.encode(ciphertext)
            }))
            .unwrap(),
        )
        .await
        .expect("decode poll option");
        assert_eq!(
            serde_json::from_slice::<Value>(&decrypted).unwrap(),
            json!({"text":"Friday"})
        );
    }

    #[tokio::test]
    async fn decrypt_accepts_unpadded_base64_with_browser_ascii_whitespace() {
        let sender = state(ALICE).await;
        let receiver = state(BOB).await;
        let distribution = groups::create_distribution(&sender, CONVERSATION)
            .await
            .unwrap();
        groups::process_distribution(&receiver, ALICE, 1, &distribution)
            .await
            .unwrap();
        let ciphertext =
            groups::encrypt_for_group(&sender, CONVERSATION, br#"{"text":"atob compatibility"}"#)
                .await
                .unwrap();
        let encoded = STANDARD.encode(ciphertext);
        let unpadded = encoded.trim_end_matches('=');
        let (first, second) = unpadded.split_at(unpadded.len() / 2);
        let result = decrypt_poll_payload(
            &receiver,
            serde_json::to_vec(&json!({
                "sender_account_id":ALICE,"sender_device_number":1,
                "encrypted_meta":format!(" \n{first}\t{second}\r\u{000c}")
            }))
            .unwrap(),
        )
        .await
        .expect("browser atob accepts whitespace and omitted padding");
        assert_eq!(
            serde_json::from_slice::<Value>(&result).unwrap(),
            json!({"text":"atob compatibility"})
        );
    }

    #[tokio::test]
    async fn malformed_base64_and_invalid_sender_device_are_rejected_before_crypto() {
        let receiver = state(BOB).await;
        for (device, encoded) in [(1_i64, "%%invalid"), (0, "AA=="), (4294967297, "AA==")] {
            let error = decrypt_poll_payload(
                &receiver,
                serde_json::to_vec(&json!({
                    "sender_account_id":ALICE,"sender_device_number":device,"encrypted_meta":encoded
                }))
                .unwrap(),
            )
            .await
            .expect_err("invalid poll ciphertext input");
            assert!(matches!(error, Error::InvalidPayload(_)), "{error}");
        }
    }

    #[tokio::test]
    async fn failed_sender_key_fanout_restores_all_preparation_crypto_state() {
        let sender = state(ALICE).await;
        let base = crate::crypto::history_stage::load_snapshot(&sender.db)
            .await
            .unwrap();
        groups::create_distribution(&sender, CONVERSATION)
            .await
            .expect("sender-key creation simulates an earlier successful fanout preparation");
        assert_ne!(
            crate::crypto::history_stage::load_snapshot(&sender.db)
                .await
                .unwrap(),
            base
        );

        let error = Error::Network("later device bundle failed".into());
        let result =
            rollback_crypto_snapshot_on_prepare_error(&sender, &base, Err::<(), _>(error)).await;

        assert!(matches!(
            result,
            Err(Error::Network(message)) if message == "later device bundle failed"
        ));
        assert_eq!(
            crate::crypto::history_stage::load_snapshot(&sender.db)
                .await
                .unwrap(),
            base,
            "failed preparation must restore sender keys and pairwise sessions"
        );
    }

    #[tokio::test]
    async fn history_copy_is_a_raw_group_message_with_the_rest_poll_id_and_web_payload() {
        let sender = state(ALICE).await;
        let receiver = state(BOB).await;
        let distribution = groups::create_distribution(&sender, CONVERSATION)
            .await
            .unwrap();
        groups::process_distribution(&receiver, ALICE, 1, &distribution)
            .await
            .unwrap();
        let metadata: PollMetadata = serde_json::from_value(json!({
            "title":"Meet", "description":"Where?", "options":[{"id":"park","text":"Park"}]
        }))
        .unwrap();
        let plaintext =
            history_plaintext("server-poll-id", &metadata).expect("encode poll history");
        let ciphertext = groups::encrypt_for_group(&sender, CONVERSATION, &plaintext)
            .await
            .unwrap();
        let outgoing = envelope(
            &ConversationSender {
                account_id: ALICE.into(),
                device_number: 1,
                token: "unused".into(),
                recipients: vec![],
            },
            BOB,
            1,
            CONVERSATION,
            ciphertext.clone(),
            false,
            1,
        )
        .unwrap();
        assert_eq!(outgoing.envelope_type, 1);
        assert!(!outgoing.is_prekey_message);
        assert_eq!(outgoing.ciphertext, ciphertext);
        let decrypted = groups::decrypt_from_group(&receiver, ALICE, 1, &outgoing.ciphertext)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&decrypted).unwrap(),
            json!({
                "kind":"poll", "poll_id":"server-poll-id", "title":"Meet", "description":"Where?",
                "options":[{"id":"park","text":"Park"}]
            })
        );
    }

    #[tokio::test]
    async fn created_poll_survives_failed_history_delivery_and_sends_only_ciphertext_to_rest() {
        use crate::proto::rest::chat;
        use prost::Message;
        use std::io::{BufRead, Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut encrypted_meta = None;
            for index in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut reader = std::io::BufReader::new(&mut stream);
                let mut first_line = String::new();
                reader.read_line(&mut first_line).unwrap();
                let mut content_length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            content_length = value.trim().parse().unwrap();
                        }
                    }
                }
                let mut body = vec![0; content_length];
                reader.read_exact(&mut body).unwrap();
                drop(reader);
                let (status, response) = match index {
                    0 => {
                        assert_eq!(
                            first_line.trim(),
                            format!("GET /api/v1/conversations/{CONVERSATION} HTTP/1.1")
                        );
                        (
                            200,
                            chat::ConversationDetailResponse {
                                id: CONVERSATION.into(),
                                members: vec![ALICE.into()],
                                ..Default::default()
                            }
                            .encode_to_vec(),
                        )
                    }
                    1 => {
                        assert_eq!(
                            first_line.trim(),
                            format!("POST /api/v1/conversations/{CONVERSATION}/polls HTTP/1.1")
                        );
                        let request = chat::CreatePollRequest::decode(body.as_slice()).unwrap();
                        assert_eq!(request.option_ids.unwrap().items, ["one", "two"]);
                        assert!(!request.encrypted_meta.as_ref().unwrap().contains("Friday"));
                        encrypted_meta = request.encrypted_meta;
                        (
                            200,
                            chat::PollItem {
                                id: "server-poll-id".into(),
                                conversation_id: CONVERSATION.into(),
                                encrypted_meta: encrypted_meta.clone().unwrap(),
                                ..Default::default()
                            }
                            .encode_to_vec(),
                        )
                    }
                    _ => (503, vec![]),
                };
                write!(stream, "HTTP/1.1 {status} Fixture\r\nContent-Type: application/x-protobuf\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
                stream.write_all(&response).unwrap();
            }
            encrypted_meta.unwrap()
        });
        let sender = state_at(ALICE, &format!("http://{address}")).await;
        let distribution = groups::create_distribution(&sender, CONVERSATION)
            .await
            .unwrap();
        let metadata = json!({"title":"Friday", "description":"", "options":[{"id":"one","text":"yes"},{"id":"two","text":"no"}]});
        let result = create_conversation_poll(&sender, serde_json::to_vec(&json!({
            "conversation_id":CONVERSATION, "metadata":metadata,
            "settings":{"poll_type":"regular","allows_multiple":false,"allows_revoting":true,"allows_user_options":false,"correct_option_id":null}
        })).unwrap()).await.expect("REST success must survive history failure");
        let result: Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(result["item"]["id"], "server-poll-id");
        assert_eq!(result["metadata"], metadata);
        assert_eq!(result["history_synced"], false);
        let encrypted_meta = server.join().unwrap();
        let receiver = state(BOB).await;
        groups::process_distribution(&receiver, ALICE, 1, &distribution)
            .await
            .unwrap();
        let ciphertext = STANDARD.decode(encrypted_meta).unwrap();
        let decrypted = groups::decrypt_from_group(&receiver, ALICE, 1, &ciphertext)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&decrypted).unwrap(),
            metadata
        );
    }
}
