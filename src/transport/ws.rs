use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use futures::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::crypto::groups;
use crate::db::{auth as db_auth, pending_events};
use crate::error::{Error, Result};
use crate::events::types::Event;
use crate::proto::{
    BotCallbackAnswered, CallSignal, ClientFrame, ClientHello, Envelope, EnvelopeAck,
    EnvelopeUpload, ErrorFrame, HistoryRequest, Nudge, Ping, ServerFrame, TypingFrame,
    client_frame, server_frame,
};
use crate::runtime::ActorState;
use crate::util::time::now_unix;

const PROTOCOL_MAJOR: u32 = 0;
const PROTOCOL_MINOR: u32 = 1;
const PROTOCOL_PATCH: u32 = 0;
const PING_INTERVAL_SECS: u64 = 30;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RECONNECT_BACKOFF_SECS: u64 = 30;
const CLIENT_NAME: &str = "friendshub-core";

const ENVELOPE_TYPE_MESSAGE: i32 = 1;
const ENVELOPE_TYPE_SENDER_KEY: i32 = 3;

enum Cmd {
    Send(ClientFrame),
    Ping {
        client_timestamp: u64,
        sent_at: Instant,
        reply: oneshot::Sender<Result<u64>>,
    },
    CancelPing(u64),
    Shutdown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameAction {
    Continue,
    Reconnect,
    Stop,
}

#[derive(Clone)]
pub struct WsClient {
    inner: Arc<WsInner>,
}

struct WsInner {
    cmd_tx: Mutex<Option<mpsc::UnboundedSender<Cmd>>>,
    stop_signal: watch::Sender<bool>,
    running: AtomicBool,
    next_ping_timestamp: std::sync::atomic::AtomicU64,
}

impl WsClient {
    pub fn new() -> Self {
        let (stop_signal, _) = watch::channel(false);
        Self {
            inner: Arc::new(WsInner {
                cmd_tx: Mutex::new(None),
                stop_signal,
                running: AtomicBool::new(false),
                next_ping_timestamp: std::sync::atomic::AtomicU64::new(0),
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
        self.inner.stop_signal.send_replace(false);
        let stop_rx = self.inner.stop_signal.subscribe();

        let self_clone = self.clone();
        tokio::task::spawn_local(async move {
            run_loop(state, self_clone, rx, stop_rx).await;
        });

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        self.inner.stop_signal.send_replace(true);
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

    /// Sends a server ping and resolves with round-trip milliseconds when the
    /// matching protobuf Pong arrives.
    pub async fn ping(&self, timeout: Duration) -> Result<u64> {
        if !self.is_running() {
            return Err(Error::Internal("websocket is not running".into()));
        }
        let tx = self
            .inner
            .cmd_tx
            .lock()
            .await
            .clone()
            .ok_or_else(|| Error::Internal("websocket is not running".into()))?;
        let now_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros()
            .min(u64::MAX as u128) as u64;
        let client_timestamp = next_unique_timestamp(&self.inner.next_ping_timestamp, now_micros);
        let (reply, response) = oneshot::channel();
        tx.send(Cmd::Ping {
            client_timestamp,
            sent_at: Instant::now(),
            reply,
        })
        .map_err(|_| Error::ActorClosed)?;

        match tokio::time::timeout(timeout, response).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(Error::ActorClosed),
            Err(_) => {
                let _ = tx.send(Cmd::CancelPing(client_timestamp));
                Err(Error::Network("no Pong before ping timeout".into()))
            }
        }
    }
}

fn next_unique_timestamp(last: &std::sync::atomic::AtomicU64, now_micros: u64) -> u64 {
    let mut previous = last.load(Ordering::SeqCst);
    loop {
        let next = now_micros.max(previous.saturating_add(1));
        match last.compare_exchange(previous, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return next,
            Err(actual) => previous = actual,
        }
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
    mut stop_rx: watch::Receiver<bool>,
) {
    let mut backoff_secs: u64 = 1;

    while self_ref.is_running() {
        let mut connected_this_attempt = false;
        match run_once(
            &state,
            &mut cmd_rx,
            &mut backoff_secs,
            &mut connected_this_attempt,
        )
        .await
        {
            Ok(stopped) => {
                if stopped {
                    break;
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "websocket disconnected");
                if connected_this_attempt {
                    state.events.push(Event::ephemeral(
                        "ws_disconnected",
                        disconnected_payload(e.to_string(), false),
                    ));
                }
            }
        }

        if !self_ref.is_running() {
            break;
        }

        if !wait_before_reconnect(Duration::from_secs(backoff_secs), &mut stop_rx).await {
            break;
        }
        backoff_secs = next_reconnect_backoff(backoff_secs);
    }

    self_ref.inner.running.store(false, Ordering::SeqCst);
    state.events.push(Event::ephemeral("ws_stopped", json!({})));
}

async fn wait_before_reconnect(delay: Duration, stop_rx: &mut watch::Receiver<bool>) -> bool {
    if *stop_rx.borrow() {
        return false;
    }

    tokio::select! {
        _ = tokio::time::sleep(delay) => true,
        changed = stop_rx.changed() => changed.is_ok() && !*stop_rx.borrow(),
    }
}

/// Returns Ok(true) when a Shutdown command ended the loop on purpose.
async fn run_once(
    state: &Arc<ActorState>,
    cmd_rx: &mut mpsc::UnboundedReceiver<Cmd>,
    backoff_secs: &mut u64,
    connected_this_attempt: &mut bool,
) -> Result<bool> {
    let auth = db_auth::load(&state.db)
        .await?
        .ok_or(Error::NotAuthenticated)?;

    let token = auth
        .session_token
        .clone()
        .filter(|t| !t.is_empty())
        .ok_or(Error::NotAuthenticated)?;
    let local_account_id = auth.account_id.clone();
    let device_number = auth.device_number.unwrap_or(1);

    let (ws, _resp) = with_ws_timeout("ws connect", CONNECT_TIMEOUT, async {
        connect_async(&state.config.ws_url)
            .await
            .map_err(|e| Error::Network(format!("ws connect failed: {e}")))
    })
    .await?;

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
    let mut ping = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
    ping.tick().await;
    let mut pending_pings: HashMap<u64, (Instant, oneshot::Sender<Result<u64>>)> = HashMap::new();

    let first = with_ws_timeout("ws hello", HELLO_TIMEOUT, async {
        send_proto(&mut sink, &hello).await?;
        next_frame(&mut stream).await
    })
    .await?;
    match first.kind {
        Some(server_frame::Kind::Hello(hello)) => {
            *connected_this_attempt = true;
            *backoff_secs = 1;
            state.events.push(Event::ephemeral(
                "ws_connected",
                json!({
                    "session_id": hello.session_id,
                    "account_id": uuid_or_hex(&hello.account_id),
                    "device_number": hello.device_number,
                    "server_timestamp": hello.server_timestamp,
                    "protocol_major": hello.protocol_major,
                    "protocol_minor": hello.protocol_minor,
                    "protocol_patch": hello.protocol_patch,
                }),
            ));
        }
        Some(server_frame::Kind::Error(e)) => {
            let action = handle_server_error(state, e);
            return match action {
                FrameAction::Stop => Ok(true),
                FrameAction::Continue | FrameAction::Reconnect => {
                    Err(Error::Network("server rejected websocket hello".into()))
                }
            };
        }
        _ => return Err(Error::Network("first server frame was not Hello".into())),
    }

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(Cmd::Send(frame)) => {
                        send_proto(&mut sink, &frame).await?;
                    }
                    Some(Cmd::Ping { client_timestamp, sent_at, reply }) => {
                        let frame = ClientFrame {
                            kind: Some(client_frame::Kind::Ping(Ping { client_timestamp })),
                        };
                        if let Err(error) = send_proto(&mut sink, &frame).await {
                            let _ = reply.send(Err(Error::Network(error.to_string())));
                            return Err(error);
                        }
                        pending_pings.insert(client_timestamp, (sent_at, reply));
                    }
                    Some(Cmd::CancelPing(client_timestamp)) => {
                        pending_pings.remove(&client_timestamp);
                    }
                    Some(Cmd::Shutdown) | None => {
                        state.events.push(Event::ephemeral(
                            "ws_disconnected",
                            disconnected_payload("client closed", true),
                        ));
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
                            Ok(frame) => frame,
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to decode server frame");
                                continue;
                            }
                        };
                        if let Some(server_frame::Kind::Pong(pong)) = frame.kind.as_ref() {
                            resolve_pending_ping(&mut pending_pings, pong.client_timestamp);
                        }
                        let crypto_guard = if matches!(
                            frame.kind.as_ref(),
                            Some(server_frame::Kind::Delivery(_))
                        ) {
                            Some(state.crypto_state_lock.lock().await)
                        } else {
                            None
                        };
                        let action = handle_frame(state, frame, local_account_id.as_deref()).await;
                        if crypto_guard.is_some() {
                            crate::api::emit_pending_identity_changes(state).await;
                        } else {
                            let _crypto_guard = state.crypto_state_lock.lock().await;
                            crate::api::emit_pending_identity_changes(state).await;
                        }
                        match action {
                            FrameAction::Continue => {}
                            FrameAction::Reconnect => {
                                return Ok(false);
                            }
                            FrameAction::Stop => return Ok(true),
                        }
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
    S: futures::Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    loop {
        match stream.next().await {
            Some(Ok(Message::Binary(bytes))) => {
                return ServerFrame::decode(&bytes[..])
                    .map_err(|e| Error::Network(format!("decode failed: {e}")));
            }
            Some(Ok(Message::Close(_))) | None => {
                return Err(Error::Network("connection closed before frame".into()));
            }
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Err(Error::Network(e.to_string())),
        }
    }
}

fn resolve_pending_ping(
    pending: &mut HashMap<u64, (Instant, oneshot::Sender<Result<u64>>)>,
    client_timestamp: u64,
) {
    if let Some((sent_at, reply)) = pending.remove(&client_timestamp) {
        let round_trip_ms = sent_at.elapsed().as_millis().min(u64::MAX as u128) as u64;
        let _ = reply.send(Ok(round_trip_ms));
    }
}

async fn handle_frame(
    state: &Arc<ActorState>,
    frame: ServerFrame,
    local_account_id: Option<&str>,
) -> FrameAction {
    let Some(kind) = frame.kind else {
        return FrameAction::Continue;
    };

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
                handle_envelope(state, env, local_account_id).await;
            }
        }

        server_frame::Kind::Receipt(receipt) => {
            let payload = json!({
                "envelope_ids": receipt.envelope_ids.iter().map(|id| uuid_or_hex(id)).collect::<Vec<_>>(),
                "server_timestamps": receipt.server_timestamps,
            });
            state.events.push(Event::ephemeral("receipt", payload));
        }

        server_frame::Kind::Pong(_) => {}

        server_frame::Kind::Error(e) => {
            let reason = if e.code == "internal" {
                "internal server error".to_owned()
            } else {
                e.message.clone()
            };
            let action = handle_server_error(state, e);
            if action == FrameAction::Stop {
                state.events.push(Event::ephemeral(
                    "ws_disconnected",
                    disconnected_payload(reason, true),
                ));
            } else if action == FrameAction::Reconnect {
                state.events.push(Event::ephemeral(
                    "ws_disconnected",
                    disconnected_payload(reason, false),
                ));
            }
            return action;
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
            state
                .events
                .push(Event::ephemeral("presence_updated", payload));
        }

        server_frame::Kind::BotMessage(m) => {
            let payload = json!({
                "message_id": m.message_id,
                "bot_id": uuid_or_hex(&m.bot_id),
                "account_id": uuid_or_hex(&m.account_id),
                "text": m.text,
                "reply_to_message_id": m.reply_to_message_id,
                "reply_markup": m.reply_markup,
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

        server_frame::Kind::Typing(typing) => {
            state.events.push(Event::ephemeral(
                "typing",
                json!({
                    "conversation_id": uuid_or_hex(&typing.conversation_id),
                    "account_id": uuid_or_hex(&typing.account_id),
                }),
            ));
        }

        server_frame::Kind::ReadReceipt(receipt) => {
            state.events.push(Event::ephemeral(
                "read_receipt",
                json!({
                    "conversation_id": uuid_or_hex(&receipt.conversation_id),
                    "account_id": uuid_or_hex(&receipt.account_id),
                    "last_read_at": receipt.last_read_at,
                }),
            ));
        }

        server_frame::Kind::ConversationUpdated(update) => {
            state.events.push(Event::ephemeral(
                "conversation_updated",
                json!({
                    "conversation_id": uuid_or_hex(&update.conversation_id),
                    "title": update.title,
                    "description": update.description,
                    "is_public": update.is_public,
                    "members_changed": update.members_changed,
                }),
            ));
        }

        server_frame::Kind::HistoryRequestRelay(request) => {
            state.events.push(Event::ephemeral(
                "history_request",
                json!({
                    "from_device_number": request.from_device_number,
                    "conversation_ids": request.conversation_ids.iter().map(|id| uuid_or_hex(id)).collect::<Vec<_>>(),
                }),
            ));
        }

        server_frame::Kind::Nudge(nudge) => {
            state.events.push(Event::ephemeral(
                "nudge",
                json!({
                    "conversation_id": uuid_or_hex(&nudge.conversation_id),
                    "from_account_id": uuid_or_hex(&nudge.from_account_id),
                }),
            ));
        }

        server_frame::Kind::NudgeResult(result) => {
            state.events.push(Event::ephemeral(
                "nudge_result",
                json!({ "delivered": result.delivered }),
            ));
        }

        server_frame::Kind::ConversationExpired(expired) => {
            state.events.push(Event::ephemeral(
                "conversation_expired",
                json!({ "conversation_id": uuid_or_hex(&expired.conversation_id) }),
            ));
        }

        server_frame::Kind::ScheduledCreated(created) => {
            state.events.push(Event::ephemeral(
                "scheduled_created",
                json!({
                    "envelope_id": uuid_or_hex(&created.envelope_id),
                    "conversation_id": if created.conversation_id.is_empty() {
                        None
                    } else {
                        Some(uuid_or_hex(&created.conversation_id))
                    },
                    "send_at": created.send_at,
                }),
            ));
        }

        server_frame::Kind::ScheduledCancelled(cancelled) => {
            state.events.push(Event::ephemeral(
                "scheduled_cancelled",
                json!({ "envelope_id": uuid_or_hex(&cancelled.envelope_id) }),
            ));
        }

        server_frame::Kind::FoldersUpdated(updated) => {
            state.events.push(Event::ephemeral(
                "folders_updated",
                json!({ "account_id": uuid_or_hex(&updated.account_id) }),
            ));
        }

        server_frame::Kind::BotMessageEdited(edited) => {
            state.events.push(Event::ephemeral(
                "bot_message_edited",
                json!({
                    "message_id": edited.message_id,
                    "text": edited.text,
                    "reply_markup": edited.reply_markup,
                    "edited_at": edited.edited_at,
                }),
            ));
        }

        server_frame::Kind::BotMessageDeleted(deleted) => {
            state.events.push(Event::ephemeral(
                "bot_message_deleted",
                json!({
                    "message_id": deleted.message_id,
                    "deleted_at": deleted.deleted_at,
                }),
            ));
        }

        server_frame::Kind::PollUpdated(updated) => {
            let payload = json!({
                "poll_id": updated.poll_id,
                "conversation_id": uuid_or_hex(&updated.conversation_id),
                "revision": updated.revision,
                "counts": updated.counts.iter().map(|count| json!({
                    "option_id": count.option_id,
                    "count": count.count,
                })).collect::<Vec<_>>(),
                "total_voters": updated.total_voters,
                "closed_at": updated.closed_at,
                "correct_option_id": updated.correct_option_id,
                "extra_options": updated.extra_options.iter().map(|option| json!({
                    "option_id": option.option_id,
                    "encrypted_meta": base64::engine::general_purpose::STANDARD.encode(&option.encrypted_meta),
                    "proposed_by_account_id": option.proposed_by_account_id,
                    "proposed_by_device_number": option.proposed_by_device_number,
                    "created_at": option.created_at,
                })).collect::<Vec<_>>(),
                "deleted_option_ids": updated.deleted_option_ids,
            });
            state.events.push(Event::ephemeral("poll_updated", payload));
        }

        server_frame::Kind::PollDeleted(deleted) => {
            state.events.push(Event::ephemeral(
                "poll_deleted",
                json!({
                    "poll_id": deleted.poll_id,
                    "conversation_id": uuid_or_hex(&deleted.conversation_id),
                }),
            ));
        }

        server_frame::Kind::CallSignal(signal) => {
            state.events.push(call_signal_event(signal));
        }

        server_frame::Kind::BotCallbackAnswered(answer) => {
            state.events.push(bot_callback_answered_event(answer));
        }
    }

    FrameAction::Continue
}

fn handle_server_error(state: &Arc<ActorState>, error: ErrorFrame) -> FrameAction {
    let action = server_error_action(&error.code, error.fatal);
    state.events.push(Event::ephemeral(
        "server_error",
        server_error_payload(&error),
    ));
    action
}

fn server_error_payload(error: &ErrorFrame) -> serde_json::Value {
    let reference = error
        .reference
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| reference_from_legacy_message(&error.message));
    let message = if error.code == "internal" {
        "internal server error"
    } else {
        &error.message
    };
    json!({
        "code": error.code,
        "message": message,
        "fatal": error.fatal,
        "reference": reference,
    })
}

fn reference_from_legacy_message(message: &str) -> Option<String> {
    let reference = message
        .strip_prefix("internal server error (reference: ")?
        .strip_suffix(')')?
        .trim();
    (!reference.is_empty()).then(|| reference.to_owned())
}

fn disconnected_payload(reason: impl Into<String>, final_disconnect: bool) -> serde_json::Value {
    json!({ "reason": reason.into(), "final": final_disconnect })
}

fn next_reconnect_backoff(current_secs: u64) -> u64 {
    current_secs
        .saturating_mul(2)
        .min(MAX_RECONNECT_BACKOFF_SECS)
}

async fn with_ws_timeout<T, F>(operation: &'static str, timeout: Duration, future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    tokio::time::timeout(timeout, future).await.map_err(|_| {
        Error::Network(format!(
            "{operation} timed out after {} ms",
            timeout.as_millis()
        ))
    })?
}

fn server_error_action(code: &str, fatal: bool) -> FrameAction {
    if !fatal {
        FrameAction::Continue
    } else if code == "flood" {
        FrameAction::Reconnect
    } else {
        FrameAction::Stop
    }
}

fn call_signal_event(signal: CallSignal) -> Event {
    Event::ephemeral(
        "call_signal",
        json!({
            "conversation_id": uuid_or_hex(&signal.conversation_id),
            "peer_account_id": uuid_or_hex(&signal.peer_account_id),
            "peer_device_number": signal.peer_device_number,
            "kind": signal.kind,
            "payload": base64::engine::general_purpose::STANDARD.encode(&signal.payload),
        }),
    )
}

fn bot_callback_answered_event(answer: BotCallbackAnswered) -> Event {
    Event::ephemeral(
        "bot_callback_answered",
        json!({
            "callback_query_id": answer.callback_query_id,
            "text": answer.text,
            "message_id": answer.message_id,
            "show_alert": answer.show_alert,
        }),
    )
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
async fn handle_envelope(state: &Arc<ActorState>, env: &Envelope, local_account_id: Option<&str>) {
    let mut payload = envelope_to_json(env);
    attach_local_account_id(&mut payload, local_account_id);

    let sender_account_id = uuid_or_hex(&env.sender_account_id);
    let sender_device_number = env.sender_device_number as i64;
    let conversation_id = if env.conversation_id.is_empty() {
        None
    } else {
        Some(uuid_or_hex(&env.conversation_id))
    };

    let outcome = if env.envelope_type == ENVELOPE_TYPE_SENDER_KEY {
        match crate::crypto::manager::decrypt_envelope(state, &payload).await {
            Ok(plaintext) => match decode_sender_key_distribution(&plaintext) {
                Ok(distribution) => match groups::process_distribution(
                    state,
                    &sender_account_id,
                    sender_device_number,
                    &distribution,
                )
                .await
                {
                    Ok(()) => EnvelopeOutcome::DistributionStored,
                    Err(error) => EnvelopeOutcome::Failed(error.to_string()),
                },
                Err(error) => EnvelopeOutcome::Failed(error.to_string()),
            },
            Err(error) => EnvelopeOutcome::Failed(error.to_string()),
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
                obj.insert(
                    "group".into(),
                    json!(
                        env.envelope_type == ENVELOPE_TYPE_MESSAGE
                            && groups::looks_like_sender_key_message(&env.ciphertext)
                    ),
                );
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

fn attach_local_account_id(payload: &mut serde_json::Value, local_account_id: Option<&str>) {
    let (Some(local_account_id), Some(object)) = (local_account_id, payload.as_object_mut()) else {
        return;
    };
    object.insert("local_account_id".into(), json!(local_account_id));
}

enum EnvelopeOutcome {
    Plaintext(String),
    DistributionStored,
    Failed(String),
}

/// WEB pairwise-encrypts the sender-key distribution's hexadecimal text.
/// Recover its binary SKDM only after decrypting the ordinary Signal envelope.
fn decode_sender_key_distribution(plaintext: &[u8]) -> Result<Vec<u8>> {
    let encoded = std::str::from_utf8(plaintext).map_err(|error| {
        Error::InvalidPayload(format!(
            "sender-key distribution is not UTF-8 hex text: {error}"
        ))
    })?;
    if encoded.is_empty() {
        return Err(Error::InvalidPayload(
            "sender-key distribution is empty".into(),
        ));
    }
    hex::decode(encoded).map_err(|error| {
        Error::InvalidPayload(format!("sender-key distribution hex is invalid: {error}"))
    })
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
        "send_at": e.send_at,
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
        kind: Some(client_frame::Kind::Ack(EnvelopeAck {
            envelope_ids: raw,
            server_timestamps: Vec::new(),
        })),
    };

    state.ws.send_frame(frame).await
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TypingRequest {
    conversation_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NudgeRequest {
    conversation_id: String,
    target_account_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryRequestInput {
    target_device_number: u32,
    conversation_ids: Vec<String>,
}

fn parse_typing_frame(payload: &[u8]) -> Result<ClientFrame> {
    let request: TypingRequest = serde_json::from_slice(payload)?;
    Ok(ClientFrame {
        kind: Some(client_frame::Kind::Typing(TypingFrame {
            conversation_id: parse_uuid_text(&request.conversation_id, "conversation_id")?,
        })),
    })
}

fn parse_nudge_frame(payload: &[u8]) -> Result<ClientFrame> {
    let request: NudgeRequest = serde_json::from_slice(payload)?;
    Ok(ClientFrame {
        kind: Some(client_frame::Kind::Nudge(Nudge {
            conversation_id: parse_uuid_text(&request.conversation_id, "conversation_id")?,
            target_account_id: parse_uuid_text(&request.target_account_id, "target_account_id")?,
        })),
    })
}

fn parse_history_request_frame(payload: &[u8]) -> Result<ClientFrame> {
    let request: HistoryRequestInput = serde_json::from_slice(payload)?;
    if request.target_device_number == 0 {
        return Err(Error::InvalidPayload(
            "target_device_number must be greater than zero".into(),
        ));
    }
    if request.conversation_ids.len() > 200 {
        return Err(Error::InvalidPayload(
            "conversation_ids must contain at most 200 ids".into(),
        ));
    }
    let conversation_ids = request
        .conversation_ids
        .iter()
        .enumerate()
        .map(|(index, id)| parse_uuid_text(id, &format!("conversation_ids[{index}]")))
        .collect::<Result<Vec<_>>>()?;

    Ok(ClientFrame {
        kind: Some(client_frame::Kind::HistoryRequest(HistoryRequest {
            target_device_number: request.target_device_number,
            conversation_ids,
        })),
    })
}

fn parse_uuid_text(value: &str, field: &str) -> Result<Vec<u8>> {
    uuid::Uuid::parse_str(value)
        .map(|id| id.as_bytes().to_vec())
        .map_err(|error| Error::InvalidPayload(format!("{field}: {error}")))
}

pub async fn send_typing(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    state.ws.send_frame(parse_typing_frame(&payload)?).await?;
    Ok(br#"{"sent":true}"#.to_vec())
}

pub async fn send_nudge(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    state.ws.send_frame(parse_nudge_frame(&payload)?).await?;
    Ok(br#"{"sent":true}"#.to_vec())
}

pub async fn request_history(state: &Arc<ActorState>, payload: Vec<u8>) -> Result<Vec<u8>> {
    state
        .ws
        .send_frame(parse_history_request_frame(&payload)?)
        .await?;
    Ok(br#"{"sent":true}"#.to_vec())
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
        send_at: get_i64(v, "send_at"),
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
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| {
            Error::InvalidPayload(format!("{key} is missing, not a number, or out of range"))
        })
}

fn get_i32(v: &serde_json::Value, key: &str) -> Result<i32> {
    v.get(key)
        .and_then(|x| x.as_i64())
        .and_then(|n| i32::try_from(n).ok())
        .ok_or_else(|| {
            Error::InvalidPayload(format!("{key} is missing, not a number, or out of range"))
        })
}

fn get_i64(v: &serde_json::Value, key: &str) -> i64 {
    v.get(key).and_then(|x| x.as_i64()).unwrap_or(0)
}

fn get_bool(v: &serde_json::Value, key: &str) -> bool {
    v.get(key).and_then(|x| x.as_bool()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_event_carries_authenticated_local_account_identity_for_history_validation() {
        let mut payload = json!({
            "sender_account_id":"account-a",
            "recipient_account_id":"account-a"
        });
        attach_local_account_id(&mut payload, Some("account-a"));
        assert_eq!(payload["local_account_id"], "account-a");

        let mut unavailable = json!({
            "sender_account_id":"account-a",
            "recipient_account_id":"account-a"
        });
        attach_local_account_id(&mut unavailable, None);
        assert!(unavailable.get("local_account_id").is_none());
    }

    #[test]
    fn sender_key_distribution_plaintext_matches_web_pairwise_hex_contract() {
        assert_eq!(
            decode_sender_key_distribution(b"0001ff").unwrap(),
            [0x00, 0x01, 0xff]
        );
        assert!(decode_sender_key_distribution(&[0x00, 0x01, 0xff]).is_err());
        assert!(decode_sender_key_distribution(b"0001 ").is_err());
        assert!(decode_sender_key_distribution(b"").is_err());
    }

    #[test]
    fn call_signal_event_preserves_fields_and_base64_encodes_payload() {
        let event = call_signal_event(CallSignal {
            conversation_id: vec![0x12; 16],
            peer_account_id: vec![0x34; 16],
            peer_device_number: 7,
            kind: 3,
            payload: vec![0, 1, 255],
        });

        assert_eq!(event.kind, "call_signal");
        assert_eq!(
            event.payload,
            json!({
                "conversation_id": "12121212-1212-1212-1212-121212121212",
                "peer_account_id": "34343434-3434-3434-3434-343434343434",
                "peer_device_number": 7,
                "kind": 3,
                "payload": "AAH/",
            })
        );
    }

    #[test]
    fn bot_callback_answered_event_preserves_optional_fields() {
        let event = bot_callback_answered_event(BotCallbackAnswered {
            callback_query_id: "query-1".into(),
            text: Some("Done".into()),
            message_id: None,
            show_alert: true,
        });

        assert_eq!(event.kind, "bot_callback_answered");
        assert_eq!(
            event.payload,
            json!({
                "callback_query_id": "query-1",
                "text": "Done",
                "message_id": null,
                "show_alert": true,
            })
        );
    }

    #[test]
    fn outgoing_typing_nudge_and_history_frames_match_proto_contract() {
        let conversation_id = "00000000-0000-0000-0000-000000000001";
        let target_account_id = "00000000-0000-0000-0000-000000000002";

        let typing = parse_typing_frame(
            json!({ "conversation_id": conversation_id })
                .to_string()
                .as_bytes(),
        )
        .unwrap();
        let Some(client_frame::Kind::Typing(typing)) = typing.kind else {
            panic!("expected typing frame");
        };
        assert_eq!(
            typing.conversation_id,
            parse_uuid_text(conversation_id, "id").unwrap()
        );

        let nudge = parse_nudge_frame(
            json!({
                "conversation_id": conversation_id,
                "target_account_id": target_account_id,
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let Some(client_frame::Kind::Nudge(nudge)) = nudge.kind else {
            panic!("expected nudge frame");
        };
        assert_eq!(
            nudge.conversation_id,
            parse_uuid_text(conversation_id, "id").unwrap()
        );
        assert_eq!(
            nudge.target_account_id,
            parse_uuid_text(target_account_id, "id").unwrap()
        );

        let history = parse_history_request_frame(
            json!({
                "target_device_number": 2,
                "conversation_ids": [conversation_id, target_account_id],
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let Some(client_frame::Kind::HistoryRequest(history)) = history.kind else {
            panic!("expected history request frame");
        };
        assert_eq!(history.target_device_number, 2);
        assert_eq!(history.conversation_ids.len(), 2);
        assert_eq!(
            history.conversation_ids[0],
            parse_uuid_text(conversation_id, "id").unwrap()
        );
        assert_eq!(
            history.conversation_ids[1],
            parse_uuid_text(target_account_id, "id").unwrap()
        );
    }

    #[test]
    fn outgoing_ws_arguments_reject_invalid_uuids_and_history_bounds() {
        assert!(parse_typing_frame(br#"{"conversation_id":"not-a-uuid"}"#).is_err());
        assert!(parse_nudge_frame(
            br#"{"conversation_id":"00000000-0000-0000-0000-000000000001","target_account_id":"bad"}"#
        )
        .is_err());
        assert!(
            parse_history_request_frame(br#"{"target_device_number":0,"conversation_ids":[]}"#)
                .is_err()
        );

        let too_many = json!({
            "target_device_number": 1,
            "conversation_ids": vec!["00000000-0000-0000-0000-000000000001"; 201],
        });
        assert!(parse_history_request_frame(too_many.to_string().as_bytes()).is_err());

        assert!(
            parse_typing_frame(
                br#"{"conversation_id":"00000000-0000-0000-0000-000000000001","extra":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn envelope_numeric_fields_reject_values_outside_the_protobuf_ranges() {
        assert!(get_u32(&json!({ "value": 4_294_967_295_u64 }), "value").is_ok());
        assert!(get_u32(&json!({ "value": 4_294_967_296_u64 }), "value").is_err());
        assert!(get_u32(&json!({ "value": 4_294_967_297_u64 }), "value").is_err());
        assert!(get_i32(&json!({ "value": i32::MIN }), "value").is_ok());
        assert!(get_i32(&json!({ "value": i32::MAX }), "value").is_ok());
        assert!(get_i32(&json!({ "value": i64::from(i32::MAX) + 1 }), "value").is_err());
        assert!(get_i32(&json!({ "value": i64::from(i32::MIN) - 1 }), "value").is_err());
    }

    #[tokio::test]
    async fn matching_pong_resolves_only_its_ping_and_returns_round_trip_time() {
        let (reply, response) = oneshot::channel();
        let mut pending = HashMap::new();
        pending.insert(123, (Instant::now(), reply));

        resolve_pending_ping(&mut pending, 456);
        assert_eq!(pending.len(), 1);
        resolve_pending_ping(&mut pending, 123);
        assert!(pending.is_empty());
        assert!(response.await.unwrap().unwrap() <= 1_000);
    }

    #[test]
    fn ping_timestamps_are_unique_even_with_same_clock_value() {
        let last = std::sync::atomic::AtomicU64::new(0);
        let first = next_unique_timestamp(&last, 42);
        let second = next_unique_timestamp(&last, 42);
        assert_eq!(first, 42);
        assert_eq!(second, 43);
    }

    #[tokio::test]
    async fn stop_signal_interrupts_reconnect_backoff() {
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let waiting = tokio::spawn(async move {
            wait_before_reconnect(Duration::from_secs(60), &mut stop_rx).await
        });

        stop_tx.send_replace(true);
        assert!(!waiting.await.unwrap());
    }

    #[test]
    fn fatal_server_errors_stop_except_flood() {
        assert_eq!(
            server_error_action("invalid_session", true),
            FrameAction::Stop
        );
        assert_eq!(server_error_action("flood", true), FrameAction::Reconnect);
        assert_eq!(
            server_error_action("internal", false),
            FrameAction::Continue
        );
    }

    #[test]
    fn server_error_payload_matches_web_reference_and_internal_sanitization() {
        let error = ErrorFrame {
            code: "internal".into(),
            message: "database password must not escape".into(),
            fatal: true,
            reference: Some("  req-123  ".into()),
        };

        assert_eq!(
            server_error_payload(&error),
            json!({
                "code": "internal",
                "message": "internal server error",
                "fatal": true,
                "reference": "req-123",
            })
        );
    }

    #[test]
    fn server_error_payload_falls_back_to_legacy_reference_or_null() {
        let legacy = ErrorFrame {
            code: "internal".into(),
            message: "internal server error (reference: req-legacy)".into(),
            fatal: false,
            reference: None,
        };
        assert_eq!(
            server_error_payload(&legacy),
            json!({
                "code": "internal",
                "message": "internal server error",
                "fatal": false,
                "reference": "req-legacy",
            })
        );

        let without_reference = ErrorFrame {
            code: "permission_denied".into(),
            message: "not allowed".into(),
            fatal: false,
            reference: None,
        };
        assert_eq!(
            server_error_payload(&without_reference),
            json!({
                "code": "permission_denied",
                "message": "not allowed",
                "fatal": false,
                "reference": null,
            })
        );
    }

    #[test]
    fn error_reference_survives_protobuf_server_frame_decode() {
        let frame = ServerFrame {
            kind: Some(server_frame::Kind::Error(ErrorFrame {
                code: "internal".into(),
                message: "opaque".into(),
                fatal: true,
                reference: Some("req-wire".into()),
            })),
        };
        let bytes = frame.encode_to_vec();
        let decoded = ServerFrame::decode(bytes.as_slice()).unwrap();
        let Some(server_frame::Kind::Error(error)) = decoded.kind else {
            panic!("expected error frame");
        };
        assert_eq!(error.reference.as_deref(), Some("req-wire"));
    }

    #[test]
    fn disconnected_payload_marks_retryable_and_final_closes() {
        assert_eq!(
            disconnected_payload("connection lost", false),
            json!({ "reason": "connection lost", "final": false })
        );
        assert_eq!(
            disconnected_payload("client closed", true),
            json!({ "reason": "client closed", "final": true })
        );
    }

    #[test]
    fn reconnect_delay_follows_web_sequence_and_stays_capped() {
        let mut delay = 1;
        let mut observed = Vec::new();
        for _ in 0..8 {
            observed.push(delay);
            delay = next_reconnect_backoff(delay);
        }
        assert_eq!(observed, [1, 2, 4, 8, 16, 30, 30, 30]);
    }

    #[tokio::test]
    async fn connect_deadline_matches_web_and_times_out_a_stalled_attempt() {
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(30));
        let error = with_ws_timeout(
            "ws connect",
            Duration::from_millis(1),
            std::future::pending::<Result<()>>(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, Error::Network(message) if message == "ws connect timed out after 1 ms")
        );
    }

    #[tokio::test]
    async fn hello_deadline_matches_web_and_times_out_a_stalled_handshake() {
        assert_eq!(HELLO_TIMEOUT, Duration::from_secs(10));
        let error = with_ws_timeout(
            "ws hello",
            Duration::from_millis(1),
            std::future::pending::<Result<()>>(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, Error::Network(message) if message == "ws hello timed out after 1 ms")
        );
    }
}
