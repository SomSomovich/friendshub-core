use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use serde_json::json;
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::crypto::groups;
use crate::db::{auth as db_auth, pending_events};
use crate::error::{Error, Result};
use crate::events::types::Event;
use crate::proto::{
    client_frame, server_frame, ClientFrame, ClientHello, Envelope, EnvelopeAck, EnvelopeUpload,
    Ping, ServerFrame,
};
use crate::runtime::ActorState;
use crate::util::time::now_unix;

const PROTOCOL_MAJOR: u32 = 0;
const PROTOCOL_MINOR: u32 = 1;
const PROTOCOL_PATCH: u32 = 0;
const PING_INTERVAL_SECS: u64 = 30;
const CLIENT_NAME: &str = "friendshub-core";

const ENVELOPE_TYPE_MESSAGE: i32 = 1;
const ENVELOPE_TYPE_SENDER_KEY: i32 = 3;

enum Cmd {
    Send(ClientFrame),
    Shutdown,
}

#[derive(Clone)]
pub struct WsClient {
    inner: Arc<WsInner>,
}

struct WsInner {
    cmd_tx: Mutex<Option<mpsc::UnboundedSender<Cmd>>>,
    running: AtomicBool,
}

impl WsClient {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(WsInner {
                cmd_tx: Mutex::new(None),
                running: AtomicBool::new(false),
            }),
        }
    }

    pub fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::SeqCst)
    }

    /// Starts the connect loop as a background task. Returns immediately.
    /// The caller learns about connection state from ws_connected /
    /// ws_disconnected events rather than from this call.
    ///
    /// spawn_local, not spawn: decrypting envelopes calls libsignal, whose
    /// store traits are declared with `#[async_trait(?Send)]`, which makes the
    /// futures `!Send`. A plain `tokio::spawn` will not accept them.
    pub async fn start(self: Arc<Self>, state: Arc<ActorState>) -> Result<()> {
        if self.inner.running.swap(true, Ordering::SeqCst) {
            return Err(Error::Internal("websocket already running".into()));
        }

        let (tx, rx) = mpsc::unbounded_channel();
        *self.inner.cmd_tx.lock().await = Some(tx);

        let self_clone = self.clone();
        tokio::task::spawn_local(async move {
            run_loop(state, self_clone, rx).await;
        });

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        let tx = self.inner.cmd_tx.lock().await.take();
        if let Some(tx) = tx {
            let _ = tx.send(Cmd::Shutdown);
        }
        Ok(())
    }

    pub async fn send_frame(&self, frame: ClientFrame) -> Result<()> {
        let tx = self.inner.cmd_tx.lock().await.clone();
        let tx = tx.ok_or(Error::Internal("websocket is not running".into()))?;
        tx.send(Cmd::Send(frame)).map_err(|_| Error::ActorClosed)
    }
}

impl Default for WsClient {
    fn default() -> Self {
        Self::new()
    }
}

async fn run_loop(
    state: Arc<ActorState>,
    self_ref: Arc<WsClient>,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
) {
    let mut backoff_secs: u64 = 1;

    while self_ref.is_running() {
        match run_once(&state, &mut cmd_rx).await {
            Ok(stopped) => {
                if stopped {
                    break;
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "websocket disconnected");
                state.events.push(Event::ephemeral(
                    "ws_disconnected",
                    json!({ "reason": e.to_string() }),
                ));
            }
        }

        if !self_ref.is_running() {
            break;
        }

        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(60);
    }

    self_ref.inner.running.store(false, Ordering::SeqCst);
    state.events.push(Event::ephemeral("ws_stopped", json!({})));
}

/// Returns Ok(true) when a Shutdown command ended the loop on purpose.
async fn run_once(
    state: &Arc<ActorState>,
    cmd_rx: &mut mpsc::UnboundedReceiver<Cmd>,
) -> Result<bool> {
    let auth = db_auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;

    let token = auth
        .session_token
        .clone()
        .filter(|t| !t.is_empty())
        .ok_or(Error::NotAuthenticated)?;
    let device_number = auth.device_number.unwrap_or(1);

    let (ws, _resp) = connect_async(&state.config.ws_url)
        .await
        .map_err(|e| Error::Network(format!("ws connect failed: {e}")))?;

    let (mut sink, mut stream) = ws.split();

    let hello = ClientFrame {
        kind: Some(client_frame::Kind::Hello(ClientHello {
            session_token: token,
            device_number: device_number as u32,
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            protocol_patch: PROTOCOL_PATCH,
            client_name: CLIENT_NAME.to_string(),
            client_version: env!("CARGO_PKG_VERSION").to_string(),
        })),
    };
    send_proto(&mut sink, &hello).await?;

    let mut ping = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
    ping.tick().await;

    let first = next_frame(&mut stream).await?;
    match first.kind {
        Some(server_frame::Kind::Hello(_)) => {}
        Some(server_frame::Kind::Error(e)) => {
            return Err(Error::Network(format!(
                "server rejected hello: {} ({})",
                e.message, e.code
            )));
        }
        _ => return Err(Error::Network("first server frame was not Hello".into())),
    }

    state.events.push(Event::ephemeral(
        "ws_connected",
        json!({ "device_number": device_number }),
    ));

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(Cmd::Send(frame)) => {
                        send_proto(&mut sink, &frame).await?;
                    }
                    Some(Cmd::Shutdown) | None => {
                        let _ = sink.close().await;
                        return Ok(true);
                    }
                }
            }
            _ = ping.tick() => {
                let p = ClientFrame {
                    kind: Some(client_frame::Kind::Ping(Ping {
                        client_timestamp: now_unix() as u64,
                    })),
                };
                send_proto(&mut sink, &p).await?;
            }
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Binary(bytes))) => {
                        let frame = match ServerFrame::decode(&bytes[..]) {
                            Ok(f) => f,
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to decode server frame");
                                continue;
                            }
                        };
                        handle_frame(state, frame).await;
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        return Err(Error::Network("server closed connection".into()));
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        let _ = sink.send(Message::Pong(payload)).await;
                    }
                    Some(Ok(Message::Pong(_))) | Some(Ok(Message::Text(_))) => continue,
                    Some(Ok(Message::Frame(_))) => continue,
                    Some(Err(e)) => {
                        return Err(Error::Network(e.to_string()));
                    }
                }
            }
        }
    }
}

async fn send_proto<S>(sink: &mut S, frame: &ClientFrame) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
    <S as futures::Sink<Message>>::Error: std::fmt::Display,
{
    let mut buf = Vec::with_capacity(frame.encoded_len());
    frame
        .encode(&mut buf)
        .map_err(|e| Error::Internal(format!("encode failed: {e}")))?;
    sink.send(Message::Binary(buf.into()))
        .await
        .map_err(|e| Error::Network(format!("send failed: {e}")))?;
    Ok(())
}

async fn next_frame<S>(stream: &mut S) -> Result<ServerFrame>
where
    S: futures::Stream<
            Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>,
        > + Unpin,
{
    loop {
        match stream.next().await {
            Some(Ok(Message::Binary(bytes))) => {
                let frame = ServerFrame::decode(&bytes[..])
                    .map_err(|e| Error::Network(format!("decode failed: {e}")))?;
                return Ok(frame);
            }
            Some(Ok(Message::Close(_))) | None => {
                return Err(Error::Network("connection closed before frame".into()));
            }
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Err(Error::Network(e.to_string())),
        }
    }
}

async fn handle_frame(state: &Arc<ActorState>, frame: ServerFrame) {
    let Some(kind) = frame.kind else { return };

    match kind {
        server_frame::Kind::Hello(h) => {
            if let Err(e) = sqlx::query("UPDATE auth_state SET session_id = ? WHERE id = 1")
                .bind(&h.session_id)
                .execute(&state.db)
                .await
            {
                tracing::warn!(error = ?e, "failed to persist session_id");
            }
        }

        server_frame::Kind::Delivery(d) => {
            for env in &d.envelopes {
                handle_envelope(state, env).await;
            }
        }

        server_frame::Kind::Receipt(_) => {}

        server_frame::Kind::Pong(_) => {}

        server_frame::Kind::Error(e) => {
            let payload = json!({
                "code": e.code,
                "message": e.message,
                "fatal": e.fatal,
            });
            state.events.push(Event::ephemeral("server_error", payload));
        }

        server_frame::Kind::Presence(p) => {
            let payload = json!({
                "account_id": uuid_or_hex(&p.account_id),
                "is_online": p.is_online,
                "last_seen": p.last_seen,
                "custom_status_text": p.custom_status_text,
                "custom_status_emoji": p.custom_status_emoji,
                "custom_status_expires_at": p.custom_status_expires_at,
            });
            state.events.push(Event::ephemeral("presence_updated", payload));
        }

        server_frame::Kind::BotMessage(m) => {
            let payload = json!({
                "message_id": m.message_id,
                "bot_id": uuid_or_hex(&m.bot_id),
                "account_id": uuid_or_hex(&m.account_id),
                "text": m.text,
                "reply_to_message_id": m.reply_to_message_id,
                "created_at": m.created_at,
            });
            state.events.push(Event::ephemeral("bot_message", payload));
        }

        server_frame::Kind::ChannelPost(p) => {
            let payload = json!({
                "post_id": p.post_id,
                "channel_id": uuid_or_hex(&p.channel_id),
                "author_type": p.author_type,
                "author_id": uuid_or_hex(&p.author_id),
                "text": p.text,
                "attachment_ids": p.attachment_ids,
                "reply_to_post_id": p.reply_to_post_id,
                "created_at": p.created_at,
            });
            state.events.push(Event::ephemeral("channel_post", payload));
        }
    }
}

/// One envelope, three possibilities.
///
/// - `SENDER_KEY`: a distribution message from another member of a group.
///   Fed to the group machinery; the sender key it carries is stored so
///   future group messages from that device can be decrypted. No plaintext
///   is produced.
/// - `MESSAGE` whose ciphertext begins with the SenderKeyMessage version byte:
///   a group message. Decrypted through the group path.
/// - anything else: an ordinary Signal-encrypted envelope, decrypted through
///   the pairwise session.
async fn handle_envelope(state: &Arc<ActorState>, env: &Envelope) {
    let mut payload = envelope_to_json(env);

    let sender_account_id = uuid_or_hex(&env.sender_account_id);
    let sender_device_number = env.sender_device_number as i64;
    let conversation_id = if env.conversation_id.is_empty() {
        None
    } else {
        Some(uuid_or_hex(&env.conversation_id))
    };

    let outcome = if env.envelope_type == ENVELOPE_TYPE_SENDER_KEY {
        match groups::process_distribution(
            state,
            &sender_account_id,
            sender_device_number,
            &env.ciphertext,
        )
        .await
        {
            Ok(()) => EnvelopeOutcome::DistributionStored,
            Err(e) => EnvelopeOutcome::Failed(e.to_string()),
        }
    } else if env.envelope_type == ENVELOPE_TYPE_MESSAGE
        && groups::looks_like_sender_key_message(&env.ciphertext)
    {
        match groups::decrypt_from_group(
            state,
            &sender_account_id,
            sender_device_number,
            &env.ciphertext,
        )
        .await
        {
            Ok(pt) => EnvelopeOutcome::Plaintext(hex::encode(&pt)),
            Err(e) => EnvelopeOutcome::Failed(e.to_string()),
        }
    } else {
        match crate::crypto::manager::decrypt_envelope(state, &payload).await {
            Ok(pt) => EnvelopeOutcome::Plaintext(hex::encode(&pt)),
            Err(e) => EnvelopeOutcome::Failed(e.to_string()),
        }
    };

    match outcome {
        EnvelopeOutcome::Plaintext(hex) => {
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("plaintext_hex".into(), json!(hex));
                obj.insert("group".into(), json!(env.envelope_type == ENVELOPE_TYPE_MESSAGE && groups::looks_like_sender_key_message(&env.ciphertext)));
            }
        }
        EnvelopeOutcome::DistributionStored => {
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("plaintext_hex".into(), json!(null));
                obj.insert("distribution".into(), json!(true));
            }
        }
        EnvelopeOutcome::Failed(reason) => {
            tracing::debug!(
                error = %reason,
                envelope_type = env.envelope_type,
                "envelope could not be decrypted; delivering ciphertext only"
            );
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("plaintext_hex".into(), json!(null));
                obj.insert("decrypt_error".into(), json!(reason));
            }
        }
    }

    // The conversation_id is only recorded in the payload so a consumer can
    // route the event; it plays no role in decryption.
    let _ = conversation_id;

    let text = match serde_json::to_string(&payload) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "failed to serialize envelope");
            return;
        }
    };

    let id = match pending_events::push(&state.db, "envelope_received", &text).await {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = ?e, "failed to persist pending envelope");
            return;
        }
    };

    state.events.push(Event {
        id: Some(id as u64),
        kind: "envelope_received".to_string(),
        payload,
    });
}

enum EnvelopeOutcome {
    Plaintext(String),
    DistributionStored,
    Failed(String),
}

fn envelope_to_json(e: &Envelope) -> serde_json::Value {
    json!({
        "envelope_id": uuid_or_hex(&e.envelope_id),
        "sender_account_id": uuid_or_hex(&e.sender_account_id),
        "sender_device_number": e.sender_device_number,
        "recipient_account_id": uuid_or_hex(&e.recipient_account_id),
        "recipient_device_number": e.recipient_device_number,
        "envelope_type": e.envelope_type,
        "is_prekey_message": e.is_prekey_message,
        "ciphertext": hex::encode(&e.ciphertext),
        "client_timestamp": e.client_timestamp,
        "conversation_id": if e.conversation_id.is_empty() { None } else { Some(uuid_or_hex(&e.conversation_id)) },
        "sender_is_bot": e.sender_is_bot,
    })
}

fn uuid_or_hex(bytes: &[u8]) -> String {
    if bytes.len() == 16 {
        uuid::Uuid::from_slice(bytes)
            .map(|u| u.to_string())
            .unwrap_or_else(|_| hex::encode(bytes))
    } else {
        hex::encode(bytes)
    }
}

/// Builds an envelope from a JSON description and uploads it over the WS.
pub async fn upload_envelope(state: &Arc<ActorState>, value: serde_json::Value) -> Result<()> {
    let env = json_to_envelope(&value)?;

    let frame = ClientFrame {
        kind: Some(client_frame::Kind::Upload(EnvelopeUpload {
            envelopes: vec![env],
        })),
    };

    state.ws.send_frame(frame).await
}

/// Sends a receipt for one or more envelope ids.
pub async fn ack_envelopes(state: &Arc<ActorState>, ids: &[String]) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }

    let mut raw: Vec<Vec<u8>> = Vec::with_capacity(ids.len());
    for id in ids {
        let bytes = uuid::Uuid::parse_str(id)
            .map(|u| u.as_bytes().to_vec())
            .map_err(|e| Error::InvalidPayload(format!("envelope id: {e}")))?;
        raw.push(bytes);
    }

    let frame = ClientFrame {
        kind: Some(client_frame::Kind::Ack(EnvelopeAck { envelope_ids: raw })),
    };

    state.ws.send_frame(frame).await
}

fn json_to_envelope(v: &serde_json::Value) -> Result<Envelope> {
    let envelope_id = parse_uuid_bytes(v, "envelope_id")?;
    let sender_account_id = parse_uuid_bytes(v, "sender_account_id")?;
    let recipient_account_id = parse_uuid_bytes(v, "recipient_account_id")?;

    let conversation_id = match v.get("conversation_id").and_then(|c| c.as_str()) {
        Some(s) if !s.is_empty() => uuid::Uuid::parse_str(s)
            .map(|u| u.as_bytes().to_vec())
            .map_err(|e| Error::InvalidPayload(format!("conversation_id: {e}")))?,
        _ => Vec::new(),
    };

    let ciphertext = v
        .get("ciphertext")
        .and_then(|c| c.as_str())
        .map(hex::decode)
        .transpose()
        .map_err(|e| Error::InvalidPayload(format!("ciphertext hex: {e}")))?
        .unwrap_or_default();

    Ok(Envelope {
        envelope_id,
        sender_account_id,
        sender_device_number: get_u32(v, "sender_device_number")?,
        recipient_account_id,
        recipient_device_number: get_u32(v, "recipient_device_number")?,
        envelope_type: get_i32(v, "envelope_type")?,
        is_prekey_message: get_bool(v, "is_prekey_message"),
        ciphertext,
        client_timestamp: get_i64(v, "client_timestamp"),
        conversation_id,
        sender_is_bot: false,
    })
}

fn parse_uuid_bytes(v: &serde_json::Value, key: &str) -> Result<Vec<u8>> {
    let s = v
        .get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| Error::InvalidPayload(format!("{key} is missing")))?;
    uuid::Uuid::parse_str(s)
        .map(|u| u.as_bytes().to_vec())
        .map_err(|e| Error::InvalidPayload(format!("{key}: {e}")))
}

fn get_u32(v: &serde_json::Value, key: &str) -> Result<u32> {
    v.get(key)
        .and_then(|x| x.as_u64())
        .map(|n| n as u32)
        .ok_or_else(|| Error::InvalidPayload(format!("{key} is missing or not a number")))
}

fn get_i32(v: &serde_json::Value, key: &str) -> Result<i32> {
    v.get(key)
        .and_then(|x| x.as_i64())
        .map(|n| n as i32)
        .ok_or_else(|| Error::InvalidPayload(format!("{key} is missing or not a number")))
}

fn get_i64(v: &serde_json::Value, key: &str) -> i64 {
    v.get(key).and_then(|x| x.as_i64()).unwrap_or(0)
}

fn get_bool(v: &serde_json::Value, key: &str) -> bool {
    v.get(key).and_then(|x| x.as_bool()).unwrap_or(false)
}
