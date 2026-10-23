//! Browser WebSocket transport for the FriendsHub protobuf push protocol.
//!
//! JavaScript owns only the input/output values it passes here. The client
//! validates and copies outgoing values into Rust-owned protobuf frames, and
//! converts incoming frames into fresh camelCase objects before invoking the
//! registered event callback.

use friendshub_core::proto::{
    self as fh, ClientFrame, ClientHello, Envelope, EnvelopeAck, EnvelopeUpload, Ping, ServerFrame,
    client_frame::Kind as ClientKind, server_frame::Kind as ServerKind,
};
use js_sys::{Array, Date, Function, Object, Promise, Reflect, Uint8Array};
use prost::Message;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::{Rc, Weak};
use url::Url;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, future_to_promise};
use web_sys::{CloseEvent, Event, MessageEvent, WebSocket};

const PROTOCOL_MAJOR: u32 = 0;
const PROTOCOL_MINOR: u32 = 1;
const PROTOCOL_PATCH: u32 = 0;
const CLIENT_NAME: &str = "friendshub-web";
const CLIENT_VERSION: &str = "0.1.0";
const CONNECT_TIMEOUT_MS: i32 = 30_000;
const HELLO_TIMEOUT_MS: i32 = 10_000;
const PING_INTERVAL_MS: i32 = 30_000;
const CLOSE_TIMEOUT_MS: i32 = 2_000;
const RECONNECT_DELAYS_MS: [i32; 6] = [1_000, 2_000, 4_000, 8_000, 16_000, 30_000];
const MAX_ENVELOPES_PER_FRAME: usize = 128;
const MAX_FRAME_BYTES: usize = 256 * 1024;
const MAX_CIPHERTEXT_BYTES: usize = 64 * 1024;
const MAX_BUFFERED_BYTES: u32 = 64 * 1024;

type JsCallback = Function;

/// Browser WebSocket client. Call `start(token, deviceNumber)` and install
/// event handlers with the individual `set_on_*` methods before connecting.
#[wasm_bindgen]
pub struct BrowserPushClient {
    state: Rc<RefCell<PushState>>,
}

impl Drop for BrowserPushClient {
    fn drop(&mut self) {
        drop_client(&self.state);
    }
}

#[wasm_bindgen]
impl BrowserPushClient {
    /// Creates a push client for an absolute `ws://`/`wss://` URL or a URL
    /// relative to the current page. HTTP(S) URLs are converted to WS(S).
    #[wasm_bindgen(constructor)]
    pub fn new(url: String) -> Result<BrowserPushClient, JsValue> {
        let base = web_sys::window().and_then(|window| window.location().href().ok());
        let url = normalize_ws_url(&url, base.as_deref())
            .map_err(|message| push_error("invalid_url", &message))?;
        Ok(Self {
            state: Rc::new(RefCell::new(PushState::new(url))),
        })
    }

    /// Opens the socket and resolves with the first ServerHello. A failed
    /// initial connection rejects this promise and does not reconnect.
    pub fn start(&mut self, session_token: String, device_number: u32) -> Promise {
        start_client(&self.state, session_token, device_number)
    }

    /// Closes the connection and resolves after the browser reports close, or
    /// after a two-second close deadline. Calling it repeatedly is safe.
    pub fn close(&mut self) -> Promise {
        close_client(&self.state)
    }

    /// Resolves when every frame in the input batch has been handed to Fetch's
    /// WebSocket send queue. Input must be an array of WEB camelCase Envelope
    /// objects: UUID strings for ids, hex ciphertext, numeric timestamps, and
    /// the remaining fields shown in the crate README.
    pub fn upload_envelopes(&self, envelopes: JsValue) -> Promise {
        upload_envelopes(&self.state, envelopes)
    }

    /// Acknowledges envelopes by UUID string. IDs are sent in batches of 128.
    pub fn ack_envelopes(&self, envelope_ids: JsValue) -> Promise {
        ack_envelopes(&self.state, envelope_ids)
    }

    /// Sends a typing indication for a conversation UUID.
    pub fn send_typing(&self, conversation_id: String) -> Result<(), JsValue> {
        let conversation_id =
            parse_uuid(&conversation_id).map_err(|error| push_error("bad_request", &error))?;
        send_frame(
            &self.state,
            ClientKind::Typing(fh::TypingFrame { conversation_id }),
        )
    }

    /// Requests history from another active device. `target_device_number`
    /// must be a non-zero u32 and at most 200 conversation UUIDs may be given.
    pub fn request_history(
        &self,
        target_device_number: u32,
        conversation_ids: JsValue,
    ) -> Result<(), JsValue> {
        if target_device_number == 0 {
            return Err(push_error(
                "bad_request",
                "target device number must be non-zero",
            ));
        }
        let ids = parse_uuid_array(&conversation_ids, 200, "conversation_ids")
            .map_err(|error| push_error("bad_request", &error))?;
        send_frame(
            &self.state,
            ClientKind::HistoryRequest(fh::HistoryRequest {
                target_device_number,
                conversation_ids: ids,
            }),
        )
    }

    /// Sends a nudge to the given account inside a conversation.
    pub fn send_nudge(
        &self,
        conversation_id: String,
        target_account_id: String,
    ) -> Result<(), JsValue> {
        let conversation_id =
            parse_uuid(&conversation_id).map_err(|error| push_error("bad_request", &error))?;
        let target_account_id =
            parse_uuid(&target_account_id).map_err(|error| push_error("bad_request", &error))?;
        send_frame(
            &self.state,
            ClientKind::Nudge(fh::Nudge {
                conversation_id,
                target_account_id,
            }),
        )
    }

    /// True while the browser WebSocket has completed the ServerHello exchange.
    #[wasm_bindgen(getter, js_name = isConnected)]
    pub fn is_connected(&self) -> bool {
        let state = self.state.borrow();
        state.connected
            && state
                .socket
                .as_ref()
                .is_some_and(|socket| socket.ready_state() == WebSocket::OPEN)
    }
}

macro_rules! callback_setters {
    ($(($method:ident, $key:literal)),+ $(,)?) => {
        #[wasm_bindgen]
        impl BrowserPushClient {
            $(
                pub fn $method(&mut self, callback: Option<Function>) {
                    set_callback(&self.state, $key, callback);
                }
            )+
        }
    };
}

callback_setters!(
    (set_on_hello, "hello"),
    (set_on_delivery, "delivery"),
    (set_on_receipt, "receipt"),
    (set_on_pong, "pong"),
    (set_on_server_error, "error"),
    (set_on_presence, "presence"),
    (set_on_bot_message, "botMessage"),
    (set_on_channel_post, "channelPost"),
    (set_on_typing, "typing"),
    (set_on_read_receipt, "readReceipt"),
    (set_on_conversation_updated, "conversationUpdated"),
    (set_on_history_request_relay, "historyRequestRelay"),
    (set_on_nudge, "nudge"),
    (set_on_nudge_result, "nudgeResult"),
    (set_on_conversation_expired, "conversationExpired"),
    (set_on_scheduled_created, "scheduledCreated"),
    (set_on_scheduled_cancelled, "scheduledCancelled"),
    (set_on_folders_updated, "foldersUpdated"),
    (set_on_bot_message_edited, "botMessageEdited"),
    (set_on_bot_message_deleted, "botMessageDeleted"),
    (set_on_bot_callback_answered, "botCallbackAnswered"),
    (set_on_poll_updated, "pollUpdated"),
    (set_on_poll_deleted, "pollDeleted"),
    (set_on_connected, "connected"),
    (set_on_disconnected, "disconnected"),
    (set_on_stopped, "stopped"),
    (set_on_transport_error, "transportError"),
    (set_on_protocol_error, "protocolError"),
    (set_on_fatal_error, "fatalError"),
    (set_on_callback_error, "callbackError"),
);

struct PushState {
    url: String,
    session_token: Option<String>,
    device_number: Option<u32>,
    socket: Option<WebSocket>,
    generation: u64,
    connected: bool,
    ever_connected: bool,
    closed_by_user: bool,
    fatal: bool,
    reconnect_attempt: usize,
    callbacks: HashMap<&'static str, JsCallback>,
    listeners: Option<SocketListeners>,
    timers: HashMap<TimerKind, TimerSlot>,
    start_resolver: Option<Function>,
    start_rejector: Option<Function>,
    close_resolvers: Vec<Function>,
}

impl PushState {
    fn new(url: String) -> Self {
        Self {
            url,
            session_token: None,
            device_number: None,
            socket: None,
            generation: 0,
            connected: false,
            ever_connected: false,
            closed_by_user: false,
            fatal: false,
            reconnect_attempt: 0,
            callbacks: HashMap::new(),
            listeners: None,
            timers: HashMap::new(),
            start_resolver: None,
            start_rejector: None,
            close_resolvers: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum TimerKind {
    ConnectDeadline,
    HelloDeadline,
    PingInterval,
    Reconnect,
    CloseDeadline,
}

struct TimerSlot {
    handle: i32,
    interval: bool,
    callback: Closure<dyn FnMut()>,
}

struct SocketListeners {
    _open: Closure<dyn FnMut(Event)>,
    _message: Closure<dyn FnMut(MessageEvent)>,
    _error: Closure<dyn FnMut(Event)>,
    _close: Closure<dyn FnMut(CloseEvent)>,
}

fn set_callback(state: &Rc<RefCell<PushState>>, name: &'static str, callback: Option<Function>) {
    let mut state = state.borrow_mut();
    if let Some(callback) = callback {
        state.callbacks.insert(name, callback);
    } else {
        state.callbacks.remove(name);
    }
}

fn start_client(state: &Rc<RefCell<PushState>>, token: String, device: u32) -> Promise {
    let state = Rc::clone(state);
    Promise::new(&mut move |resolve, reject| {
        if token.trim().is_empty() || device == 0 {
            let _ = reject.call1(
                &JsValue::UNDEFINED,
                &push_error(
                    "bad_request",
                    "session token and non-zero device number are required",
                ),
            );
            return;
        }
        {
            let mut inner = state.borrow_mut();
            if inner.socket.is_some() || inner.connected || inner.start_resolver.is_some() {
                let _ = reject.call1(
                    &JsValue::UNDEFINED,
                    &push_error(
                        "already_started",
                        "close the current push client before starting it again",
                    ),
                );
                return;
            }
            inner.session_token = Some(token.clone());
            inner.device_number = Some(device);
            inner.closed_by_user = false;
            inner.fatal = false;
            inner.ever_connected = false;
            inner.reconnect_attempt = 0;
            inner.start_resolver = Some(resolve);
            inner.start_rejector = Some(reject);
        }
        connect_socket(&state);
    })
}

fn close_client(state: &Rc<RefCell<PushState>>) -> Promise {
    let state = Rc::clone(state);
    Promise::new(&mut move |resolve, _reject| {
        let socket = {
            let mut inner = state.borrow_mut();
            inner.closed_by_user = true;
            inner.fatal = false;
            inner.close_resolvers.push(resolve.clone());
            reject_start(&mut inner, "closed", "the push client was closed");
            inner.socket.clone()
        };
        cancel_timer(&state, TimerKind::Reconnect);
        cancel_timer(&state, TimerKind::ConnectDeadline);
        cancel_timer(&state, TimerKind::HelloDeadline);
        cancel_timer(&state, TimerKind::PingInterval);
        let Some(socket) = socket else {
            finalize_socket(&state, 0, "closed".into());
            return;
        };
        match socket.ready_state() {
            WebSocket::CLOSED => {
                let generation = state.borrow().generation;
                handle_close(&state, generation, 1000, "closed".into());
            }
            _ => {
                if let Err(error) = socket.close() {
                    report_transport_error(&state, "failed to close WebSocket", error);
                    let generation = state.borrow().generation;
                    handle_close(&state, generation, 1006, "close failed".into());
                } else {
                    schedule_timer(&state, TimerKind::CloseDeadline, CLOSE_TIMEOUT_MS, false);
                }
            }
        }
    })
}

fn drop_client(state: &Rc<RefCell<PushState>>) {
    let (socket, listeners, close_resolvers) = {
        let mut inner = state.borrow_mut();
        inner.closed_by_user = true;
        inner.connected = false;
        reject_start(&mut inner, "closed", "the push client was dropped");
        (
            inner.socket.take(),
            inner.listeners.take(),
            std::mem::take(&mut inner.close_resolvers),
        )
    };
    cancel_timer(state, TimerKind::Reconnect);
    cancel_timer(state, TimerKind::ConnectDeadline);
    cancel_timer(state, TimerKind::HelloDeadline);
    cancel_timer(state, TimerKind::PingInterval);
    cancel_timer(state, TimerKind::CloseDeadline);
    if let Some(socket) = socket {
        detach_socket(&socket);
        if socket.ready_state() == WebSocket::OPEN || socket.ready_state() == WebSocket::CONNECTING
        {
            let _ = socket.close();
        }
    }
    if let Some(listeners) = listeners {
        defer_drop(listeners);
    }
    for resolver in close_resolvers {
        let _ = resolver.call0(&JsValue::UNDEFINED);
    }
}

fn connect_socket(state: &Rc<RefCell<PushState>>) {
    let (url, generation) = {
        let mut inner = state.borrow_mut();
        if inner.closed_by_user || inner.fatal {
            return;
        }
        inner.generation = inner.generation.wrapping_add(1);
        inner.connected = false;
        (inner.url.clone(), inner.generation)
    };
    let socket = match WebSocket::new(&url) {
        Ok(socket) => socket,
        Err(error) => {
            report_transport_error(state, "failed to create WebSocket", error.clone());
            fail_connection_attempt(state, generation, error);
            return;
        }
    };
    socket.set_binary_type(web_sys::BinaryType::Arraybuffer);
    let weak = Rc::downgrade(state);
    let open = Closure::wrap(Box::new(move |_event: Event| {
        if let Some(state) = weak.upgrade() {
            handle_open(&state, generation);
        }
    }) as Box<dyn FnMut(Event)>);
    let weak = Rc::downgrade(state);
    let message = Closure::wrap(Box::new(move |event: MessageEvent| {
        if let Some(state) = weak.upgrade() {
            handle_message(&state, generation, event);
        }
    }) as Box<dyn FnMut(MessageEvent)>);
    let weak = Rc::downgrade(state);
    let error = Closure::wrap(Box::new(move |event: Event| {
        if let Some(state) = weak.upgrade() {
            report_transport_error(&state, "WebSocket emitted an error event", event.into());
        }
    }) as Box<dyn FnMut(Event)>);
    let weak = Rc::downgrade(state);
    let close = Closure::wrap(Box::new(move |event: CloseEvent| {
        if let Some(state) = weak.upgrade() {
            handle_close(&state, generation, event.code(), event.reason());
        }
    }) as Box<dyn FnMut(CloseEvent)>);

    socket.set_onopen(Some(open.as_ref().unchecked_ref()));
    socket.set_onmessage(Some(message.as_ref().unchecked_ref()));
    socket.set_onerror(Some(error.as_ref().unchecked_ref()));
    socket.set_onclose(Some(close.as_ref().unchecked_ref()));
    {
        let mut inner = state.borrow_mut();
        inner.socket = Some(socket);
        inner.listeners = Some(SocketListeners {
            _open: open,
            _message: message,
            _error: error,
            _close: close,
        });
    }
    schedule_timer(state, TimerKind::ConnectDeadline, CONNECT_TIMEOUT_MS, false);
}

fn handle_open(state: &Rc<RefCell<PushState>>, generation: u64) {
    if !generation_is_current(state, generation) {
        return;
    }
    cancel_timer(state, TimerKind::ConnectDeadline);
    schedule_timer(state, TimerKind::HelloDeadline, HELLO_TIMEOUT_MS, false);
    let hello = {
        let inner = state.borrow();
        ClientHello {
            session_token: inner.session_token.clone().unwrap_or_default(),
            device_number: inner.device_number.unwrap_or_default(),
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            protocol_patch: PROTOCOL_PATCH,
            client_name: CLIENT_NAME.into(),
            client_version: CLIENT_VERSION.into(),
        }
    };
    if let Err(error) = send_encoded(
        state,
        ClientFrame {
            kind: Some(ClientKind::Hello(hello)),
        },
    ) {
        report_transport_error(state, "failed to send ClientHello", error.clone());
        fail_connection_attempt(state, generation, error);
    }
}

fn handle_message(state: &Rc<RefCell<PushState>>, generation: u64, event: MessageEvent) {
    if !generation_is_current(state, generation) {
        return;
    }
    let data = event.data();
    let bytes = if let Ok(buffer) = data.clone().dyn_into::<js_sys::ArrayBuffer>() {
        Uint8Array::new(&buffer).to_vec()
    } else if let Ok(view) = data.clone().dyn_into::<Uint8Array>() {
        view.to_vec()
    } else {
        report_protocol_error(state, "WebSocket frame was not binary data");
        return;
    };
    let frame = match ServerFrame::decode(bytes.as_slice()) {
        Ok(frame) => frame,
        Err(error) => {
            report_protocol_error(state, &format!("invalid ServerFrame protobuf: {error}"));
            return;
        }
    };
    dispatch_server_frame(state, generation, frame);
}

fn dispatch_server_frame(state: &Rc<RefCell<PushState>>, generation: u64, frame: ServerFrame) {
    let Some(kind) = frame.kind else {
        report_protocol_error(state, "ServerFrame has no event kind");
        return;
    };
    match kind {
        ServerKind::Hello(message) => {
            if !generation_is_current(state, generation) || state.borrow().connected {
                report_protocol_error(state, "unexpected ServerHello");
                return;
            }
            cancel_timer(state, TimerKind::HelloDeadline);
            let payload = server_hello_shape(&message).into_js();
            {
                let mut inner = state.borrow_mut();
                inner.connected = true;
                inner.ever_connected = true;
                inner.reconnect_attempt = 0;
            }
            schedule_timer(state, TimerKind::PingInterval, PING_INTERVAL_MS, true);
            invoke_callback(state, "hello", payload.clone());
            invoke_callback(state, "connected", payload.clone());
            let resolver = state.borrow_mut().start_resolver.take();
            state.borrow_mut().start_rejector = None;
            if let Some(resolver) = resolver {
                let _ = resolver.call1(&JsValue::UNDEFINED, &payload);
            }
        }
        ServerKind::Delivery(message) => {
            dispatch_event(state, "delivery", envelope_delivery_shape(&message))
        }
        ServerKind::Receipt(message) => {
            dispatch_event(state, "receipt", envelope_ack_shape(&message))
        }
        ServerKind::Pong(message) => dispatch_event(state, "pong", pong_shape(&message)),
        ServerKind::Error(mut message) => {
            if message.code == "internal" {
                message.message = "internal server error".into();
            }
            let payload = error_frame_shape(&message).into_js();
            let fatal = message.fatal;
            let flood = message.code == "flood";
            let code = message.code.clone();
            let text = message.message.clone();
            invoke_callback(state, "error", payload);
            if fatal {
                if flood {
                    let connected = state.borrow().connected;
                    invoke_callback(
                        state,
                        "fatalError",
                        object_shape(vec![
                            ("code", Shape::String(code)),
                            ("message", Shape::String(text.clone())),
                        ])
                        .into_js(),
                    );
                    if connected {
                        reconnect_after_close(state);
                    } else {
                        fail_connection_attempt(state, generation, push_error("flood", &text));
                    }
                } else {
                    {
                        let mut inner = state.borrow_mut();
                        inner.fatal = true;
                    }
                    reject_start_value(state, push_error(&code, &text));
                    invoke_callback(
                        state,
                        "fatalError",
                        object_shape(vec![
                            ("code", Shape::String(code)),
                            ("message", Shape::String(text)),
                        ])
                        .into_js(),
                    );
                    let socket = state.borrow().socket.clone();
                    if let Some(socket) = socket {
                        let _ = socket.close();
                    } else {
                        finalize_socket(state, 0, "fatal server error".into());
                    }
                }
            }
        }
        ServerKind::Presence(message) => {
            dispatch_event(state, "presence", presence_shape(&message))
        }
        ServerKind::BotMessage(message) => {
            dispatch_event(state, "botMessage", bot_message_shape(&message))
        }
        ServerKind::ChannelPost(message) => {
            dispatch_event(state, "channelPost", channel_post_shape(&message))
        }
        ServerKind::Typing(message) => dispatch_event(state, "typing", typing_shape(&message)),
        ServerKind::ReadReceipt(message) => {
            dispatch_event(state, "readReceipt", read_receipt_shape(&message))
        }
        ServerKind::ConversationUpdated(message) => dispatch_event(
            state,
            "conversationUpdated",
            conversation_updated_shape(&message),
        ),
        ServerKind::HistoryRequestRelay(message) => dispatch_event(
            state,
            "historyRequestRelay",
            history_request_relay_shape(&message),
        ),
        ServerKind::Nudge(message) => {
            dispatch_event(state, "nudge", nudge_delivery_shape(&message))
        }
        ServerKind::NudgeResult(message) => {
            dispatch_event(state, "nudgeResult", nudge_result_shape(&message))
        }
        ServerKind::ConversationExpired(message) => dispatch_event(
            state,
            "conversationExpired",
            conversation_expired_shape(&message),
        ),
        ServerKind::ScheduledCreated(message) => {
            dispatch_event(state, "scheduledCreated", scheduled_created_shape(&message))
        }
        ServerKind::ScheduledCancelled(message) => dispatch_event(
            state,
            "scheduledCancelled",
            scheduled_cancelled_shape(&message),
        ),
        ServerKind::FoldersUpdated(message) => {
            dispatch_event(state, "foldersUpdated", folders_updated_shape(&message))
        }
        // WEB exchanges call signals inside Signal-encrypted envelopes and
        // does not dispatch this plaintext frame.
        ServerKind::CallSignal(_message) => {}
        ServerKind::BotMessageEdited(message) => dispatch_event(
            state,
            "botMessageEdited",
            bot_message_edited_shape(&message),
        ),
        ServerKind::BotMessageDeleted(message) => dispatch_event(
            state,
            "botMessageDeleted",
            bot_message_deleted_shape(&message),
        ),
        ServerKind::BotCallbackAnswered(message) => dispatch_event(
            state,
            "botCallbackAnswered",
            bot_callback_answered_shape(&message),
        ),
        ServerKind::PollUpdated(message) => {
            dispatch_event(state, "pollUpdated", poll_updated_shape(&message))
        }
        ServerKind::PollDeleted(message) => {
            dispatch_event(state, "pollDeleted", poll_deleted_shape(&message))
        }
    }
}

fn dispatch_event(state: &Rc<RefCell<PushState>>, name: &'static str, shape: Shape) {
    invoke_callback(state, name, shape.into_js());
}

fn handle_close(state: &Rc<RefCell<PushState>>, generation: u64, code: u16, reason: String) {
    if !generation_is_current(state, generation) {
        return;
    }
    let (was_connected, stopping, ever_connected) = {
        let inner = state.borrow();
        (
            inner.connected,
            inner.closed_by_user || inner.fatal,
            inner.ever_connected,
        )
    };
    if was_connected {
        invoke_callback(
            state,
            "disconnected",
            object_shape(vec![
                (
                    "reason",
                    Shape::String(if reason.is_empty() {
                        format!("code {code}")
                    } else {
                        reason.clone()
                    }),
                ),
                ("final", Shape::Bool(stopping)),
            ])
            .into_js(),
        );
    }
    finalize_socket(state, code, reason.clone());
    if stopping {
        invoke_callback(
            state,
            "stopped",
            object_shape(vec![(
                "reason",
                Shape::String(if reason.is_empty() {
                    format!("code {code}")
                } else {
                    reason
                }),
            )])
            .into_js(),
        );
    } else if was_connected || ever_connected {
        schedule_reconnect(state);
    } else {
        reject_start(
            &mut state.borrow_mut(),
            "closed",
            &format!("the socket closed ({code})"),
        );
    }
}

fn finalize_socket(state: &Rc<RefCell<PushState>>, _code: u16, _reason: String) {
    cancel_timer(state, TimerKind::ConnectDeadline);
    cancel_timer(state, TimerKind::HelloDeadline);
    cancel_timer(state, TimerKind::PingInterval);
    cancel_timer(state, TimerKind::CloseDeadline);
    let (socket, listeners) = {
        let mut inner = state.borrow_mut();
        inner.connected = false;
        let socket = inner.socket.take();
        let listeners = inner.listeners.take();
        (socket, listeners)
    };
    if let Some(socket) = socket {
        detach_socket(&socket);
    }
    if let Some(listeners) = listeners {
        defer_drop(listeners);
    }
    let resolvers = std::mem::take(&mut state.borrow_mut().close_resolvers);
    for resolver in resolvers {
        let _ = resolver.call0(&JsValue::UNDEFINED);
    }
}

fn detach_socket(socket: &WebSocket) {
    socket.set_onopen(None);
    socket.set_onmessage(None);
    socket.set_onerror(None);
    socket.set_onclose(None);
}

fn reconnect_after_close(state: &Rc<RefCell<PushState>>) {
    cancel_timer(state, TimerKind::PingInterval);
    if let Some(socket) = state.borrow().socket.clone() {
        let _ = socket.close();
    } else {
        schedule_reconnect(state);
    }
}

fn schedule_reconnect(state: &Rc<RefCell<PushState>>) {
    let (delay, should_retry) = {
        let mut inner = state.borrow_mut();
        let allowed = !inner.closed_by_user && !inner.fatal && inner.ever_connected;
        let delay = reconnect_delay(inner.reconnect_attempt);
        if allowed {
            inner.reconnect_attempt = inner.reconnect_attempt.saturating_add(1);
        }
        (delay, allowed)
    };
    if should_retry {
        schedule_timer(state, TimerKind::Reconnect, delay, false);
    }
}

fn reconnect_delay(attempt: usize) -> i32 {
    RECONNECT_DELAYS_MS[attempt.min(RECONNECT_DELAYS_MS.len() - 1)]
}

fn fail_connection_attempt(state: &Rc<RefCell<PushState>>, generation: u64, error: JsValue) {
    if !generation_is_current(state, generation) {
        return;
    }
    let can_retry = {
        let inner = state.borrow();
        inner.ever_connected && !inner.closed_by_user && !inner.fatal
    };
    cancel_timer(state, TimerKind::ConnectDeadline);
    cancel_timer(state, TimerKind::HelloDeadline);
    if !can_retry {
        reject_start_value(state, error.clone());
    }
    if let Some(socket) = state.borrow().socket.clone() {
        let _ = socket.close();
    }
    if can_retry {
        // If construction itself failed there will be no close event to drive
        // the state machine, so ensure the next attempt is still scheduled.
        if state.borrow().socket.is_none() {
            schedule_reconnect(state);
        }
    }
}

fn handle_timer(state: &Rc<RefCell<PushState>>, kind: TimerKind, generation: u64) {
    if kind != TimerKind::Reconnect && !generation_is_current(state, generation) {
        return;
    }
    match kind {
        TimerKind::ConnectDeadline => {
            cancel_timer(state, kind);
            fail_connection_attempt(
                state,
                generation,
                push_error("connect_timeout", "WebSocket did not open within 30000 ms"),
            );
        }
        TimerKind::HelloDeadline => {
            cancel_timer(state, kind);
            fail_connection_attempt(
                state,
                generation,
                push_error("handshake_timeout", "no ServerHello within 10000 ms"),
            );
        }
        TimerKind::PingInterval => {
            let timestamp = (Date::now() / 1000.0).max(0.0) as u64;
            if let Err(error) = send_encoded(
                state,
                ClientFrame {
                    kind: Some(ClientKind::Ping(Ping {
                        client_timestamp: timestamp,
                    })),
                },
            ) {
                report_transport_error(state, "failed to send keep-alive ping", error.clone());
                if let Some(socket) = state.borrow().socket.clone() {
                    let _ = socket.close();
                }
            }
        }
        TimerKind::Reconnect => {
            cancel_timer(state, kind);
            connect_socket(state);
        }
        TimerKind::CloseDeadline => {
            cancel_timer(state, kind);
            let generation = state.borrow().generation;
            handle_close(state, generation, 1006, "close deadline elapsed".into());
        }
    }
}

fn schedule_timer(state: &Rc<RefCell<PushState>>, kind: TimerKind, delay_ms: i32, interval: bool) {
    cancel_timer(state, kind);
    let Some(window) = web_sys::window() else {
        report_simple_transport_error(state, "browser window is unavailable");
        return;
    };
    let generation = state.borrow().generation;
    let weak: Weak<RefCell<PushState>> = Rc::downgrade(state);
    let callback = Closure::wrap(Box::new(move || {
        if let Some(state) = weak.upgrade() {
            handle_timer(&state, kind, generation);
        }
    }) as Box<dyn FnMut()>);
    let result = if interval {
        window.set_interval_with_callback_and_timeout_and_arguments_0(
            callback.as_ref().unchecked_ref(),
            delay_ms,
        )
    } else {
        window.set_timeout_with_callback_and_timeout_and_arguments_0(
            callback.as_ref().unchecked_ref(),
            delay_ms,
        )
    };
    match result {
        Ok(handle) => {
            state.borrow_mut().timers.insert(
                kind,
                TimerSlot {
                    handle,
                    interval,
                    callback,
                },
            );
        }
        Err(error) => {
            report_transport_error(state, "failed to install WebSocket timer", error);
            defer_drop(callback);
        }
    }
}

fn cancel_timer(state: &Rc<RefCell<PushState>>, kind: TimerKind) {
    let slot = state.borrow_mut().timers.remove(&kind);
    if let Some(slot) = slot {
        if let Some(window) = web_sys::window() {
            if slot.interval {
                window.clear_interval_with_handle(slot.handle);
            } else {
                window.clear_timeout_with_handle(slot.handle);
            }
        }
        defer_drop(slot.callback);
    }
}

fn defer_drop<T: 'static>(value: T) {
    let callback = Closure::once_into_js(move || drop(value));
    if let Some(window) = web_sys::window() {
        let function: &js_sys::Function = callback.unchecked_ref();
        if window
            .set_timeout_with_callback_and_timeout_and_arguments_0(function, 0)
            .is_ok()
        {
            return;
        }
    }
    // Without a live window the callback cannot safely run later. Retain its
    // JS wrapper instead of freeing a closure that might still be on-stack.
    std::mem::forget(callback);
}

fn generation_is_current(state: &Rc<RefCell<PushState>>, generation: u64) -> bool {
    state.borrow().generation == generation && state.borrow().socket.is_some()
}

fn reject_start(state: &mut PushState, code: &str, message: &str) {
    if let Some(reject) = state.start_rejector.take() {
        state.start_resolver = None;
        let _ = reject.call1(&JsValue::UNDEFINED, &push_error(code, message));
    }
}

fn reject_start_value(state: &Rc<RefCell<PushState>>, error: JsValue) {
    let reject = {
        let mut inner = state.borrow_mut();
        inner.start_resolver = None;
        inner.start_rejector.take()
    };
    if let Some(reject) = reject {
        let _ = reject.call1(&JsValue::UNDEFINED, &error);
    }
}

fn invoke_callback(state: &Rc<RefCell<PushState>>, name: &'static str, payload: JsValue) {
    let callback = state.borrow().callbacks.get(name).cloned();
    let Some(callback) = callback else { return };
    if let Err(error) = callback.call1(&JsValue::UNDEFINED, &payload) {
        if name != "callbackError" {
            let details = object_shape(vec![
                ("event", Shape::String(name.into())),
                ("message", Shape::String(describe_js_value(&error))),
            ])
            .into_js();
            let callback_error = state.borrow().callbacks.get("callbackError").cloned();
            if let Some(callback_error) = callback_error {
                let _ = callback_error.call1(&JsValue::UNDEFINED, &details);
            }
        }
    }
}

fn report_simple_transport_error(state: &Rc<RefCell<PushState>>, message: &str) {
    report_transport_error(state, message, JsValue::UNDEFINED);
}

fn report_transport_error(state: &Rc<RefCell<PushState>>, context: &str, cause: JsValue) {
    let payload = object_shape(vec![
        ("code", Shape::String("transport".into())),
        (
            "message",
            Shape::String(if cause.is_undefined() {
                context.into()
            } else {
                format!("{context}: {}", describe_js_value(&cause))
            }),
        ),
    ])
    .into_js();
    invoke_callback(state, "transportError", payload);
}

fn report_protocol_error(state: &Rc<RefCell<PushState>>, message: &str) {
    invoke_callback(
        state,
        "protocolError",
        object_shape(vec![
            ("code", Shape::String("protocol".into())),
            ("message", Shape::String(message.into())),
        ])
        .into_js(),
    );
}

fn send_frame(state: &Rc<RefCell<PushState>>, kind: ClientKind) -> Result<(), JsValue> {
    send_encoded(state, ClientFrame { kind: Some(kind) })
}

fn send_encoded(state: &Rc<RefCell<PushState>>, frame: ClientFrame) -> Result<(), JsValue> {
    let bytes = frame.encode_to_vec();
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(push_error(
            "payload_too_large",
            "protobuf frame exceeds 256 KiB",
        ));
    }
    let socket = {
        let inner = state.borrow();
        if !inner.connected && !matches!(frame.kind, Some(ClientKind::Hello(_))) {
            return Err(push_error(
                "not_connected",
                "the WebSocket has not completed its handshake",
            ));
        }
        inner
            .socket
            .clone()
            .ok_or_else(|| push_error("not_connected", "the WebSocket is not open"))?
    };
    if socket.ready_state() != WebSocket::OPEN {
        return Err(push_error("not_connected", "the WebSocket is not open"));
    }
    socket
        .send_with_u8_array(bytes.as_slice())
        .map_err(|error| {
            push_error(
                "transport",
                &format!("WebSocket send failed: {}", describe_js_value(&error)),
            )
        })
}

fn upload_envelopes(state: &Rc<RefCell<PushState>>, value: JsValue) -> Promise {
    let parsed = parse_envelopes(&value);
    let state = Rc::clone(state);
    future_to_promise(async move {
        let envelopes = parsed.map_err(|error| push_error("bad_request", &error))?;
        let mut batch = Vec::new();
        let mut upload_payload_len = 0usize;
        for envelope in envelopes {
            let field_len = protobuf_message_field_len(envelope.encoded_len());
            let candidate_payload = upload_payload_len.saturating_add(field_len);
            if !batch.is_empty()
                && (batch.len() >= MAX_ENVELOPES_PER_FRAME
                    || client_upload_frame_len(candidate_payload) > MAX_FRAME_BYTES)
            {
                let bytes = ClientFrame {
                    kind: Some(ClientKind::Upload(EnvelopeUpload {
                        envelopes: std::mem::take(&mut batch),
                    })),
                }
                .encode_to_vec();
                wait_for_drain(&state).await?;
                send_bytes(&state, bytes)?;
                upload_payload_len = 0;
            }
            upload_payload_len = upload_payload_len.saturating_add(field_len);
            batch.push(envelope);
            if client_upload_frame_len(upload_payload_len) > MAX_FRAME_BYTES {
                return Err(push_error(
                    "payload_too_large",
                    "one envelope exceeds the 256 KiB frame limit",
                ));
            }
        }
        if !batch.is_empty() {
            let bytes = ClientFrame {
                kind: Some(ClientKind::Upload(EnvelopeUpload { envelopes: batch })),
            }
            .encode_to_vec();
            wait_for_drain(&state).await?;
            send_bytes(&state, bytes)?;
        }
        Ok(JsValue::UNDEFINED)
    })
}

fn protobuf_varint_len(mut value: usize) -> usize {
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}

fn protobuf_message_field_len(message_len: usize) -> usize {
    1 + protobuf_varint_len(message_len) + message_len
}

fn client_upload_frame_len(upload_payload_len: usize) -> usize {
    // ClientFrame.upload is oneof field 2; both its tag and the repeated
    // EnvelopeUpload.envelopes field tag fit in one byte.
    protobuf_message_field_len(upload_payload_len)
}

fn ack_envelopes(state: &Rc<RefCell<PushState>>, value: JsValue) -> Promise {
    let parsed = parse_uuid_array(&value, usize::MAX, "envelope_ids");
    let state = Rc::clone(state);
    future_to_promise(async move {
        let ids = parsed.map_err(|error| push_error("bad_request", &error))?;
        for chunk in ids.chunks(MAX_ENVELOPES_PER_FRAME) {
            let frame = ClientFrame {
                kind: Some(ClientKind::Ack(EnvelopeAck {
                    envelope_ids: chunk.to_vec(),
                    server_timestamps: Vec::new(),
                })),
            };
            let bytes = frame.encode_to_vec();
            wait_for_drain(&state).await?;
            send_bytes(&state, bytes)?;
        }
        Ok(JsValue::UNDEFINED)
    })
}

async fn wait_for_drain(state: &Rc<RefCell<PushState>>) -> Result<(), JsValue> {
    loop {
        let socket = state
            .borrow()
            .socket
            .clone()
            .ok_or_else(|| push_error("not_connected", "the WebSocket is not open"))?;
        if socket.ready_state() != WebSocket::OPEN || !state.borrow().connected {
            return Err(push_error(
                "not_connected",
                "the WebSocket disconnected before the send completed",
            ));
        }
        if socket.buffered_amount() <= MAX_BUFFERED_BYTES {
            return Ok(());
        }
        let promise = Promise::new(&mut |resolve, _reject| {
            let callback = Closure::once_into_js(move || {
                let _ = resolve.call0(&JsValue::UNDEFINED);
            });
            if let Some(window) = web_sys::window() {
                let function: &Function = callback.unchecked_ref();
                if window
                    .set_timeout_with_callback_and_timeout_and_arguments_0(function, 20)
                    .is_ok()
                {
                    return;
                }
            }
            std::mem::forget(callback);
        });
        JsFuture::from(promise).await.map_err(|error| error)?;
    }
}

fn send_bytes(state: &Rc<RefCell<PushState>>, bytes: Vec<u8>) -> Result<(), JsValue> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(push_error(
            "payload_too_large",
            "protobuf frame exceeds 256 KiB",
        ));
    }
    let socket = {
        let inner = state.borrow();
        if !inner.connected {
            return Err(push_error(
                "not_connected",
                "the WebSocket has not completed its handshake",
            ));
        }
        inner
            .socket
            .clone()
            .ok_or_else(|| push_error("not_connected", "the WebSocket is not open"))?
    };
    if socket.ready_state() != WebSocket::OPEN {
        return Err(push_error("not_connected", "the WebSocket is not open"));
    }
    socket
        .send_with_u8_array(bytes.as_slice())
        .map_err(|error| {
            push_error(
                "transport",
                &format!("WebSocket send failed: {}", describe_js_value(&error)),
            )
        })
}

fn parse_envelopes(value: &JsValue) -> Result<Vec<Envelope>, String> {
    if !Array::is_array(value) {
        return Err("envelopes must be an array of WEB camelCase Envelope objects".into());
    }
    let values = Array::from(value);
    let mut result = Vec::with_capacity(values.length() as usize);
    for index in 0..values.length() {
        let value = values.get(index);
        let prefix = format!("envelopes[{index}]");
        let envelope_id = parse_uuid(&required_string(&value, "envelopeId", &prefix)?)?;
        let sender_account_id = parse_uuid(&required_string(&value, "senderAccountId", &prefix)?)?;
        let recipient_account_id =
            parse_uuid(&required_string(&value, "recipientAccountId", &prefix)?)?;
        let sender_device_number = required_u32(&value, "senderDeviceNumber", &prefix, true)?;
        let recipient_device_number = required_u32(&value, "recipientDeviceNumber", &prefix, true)?;
        let envelope_type = required_u32(&value, "envelopeType", &prefix, false)?;
        let is_prekey_message = required_bool(&value, "isPrekeyMessage", &prefix)?;
        let ciphertext = decode_hex(&required_string(&value, "ciphertext", &prefix)?)?;
        let client_timestamp = required_i64(&value, "clientTimestamp", &prefix)?;
        let conversation_value = get_property(&value, "conversationId")?;
        let conversation_id = if conversation_value.is_null() || conversation_value.is_undefined() {
            Vec::new()
        } else {
            let id = conversation_value
                .as_string()
                .ok_or_else(|| format!("{prefix}.conversationId must be a UUID string or null"))?;
            parse_uuid(&id)?
        };
        let sender_is_bot = required_bool(&value, "senderIsBot", &prefix)?;
        let send_at = optional_i64(&value, "sendAt", 0, &prefix)?;
        let envelope = validate_envelope_parts(
            envelope_id,
            sender_account_id,
            recipient_account_id,
            sender_device_number,
            recipient_device_number,
            envelope_type,
            is_prekey_message,
            ciphertext,
            client_timestamp,
            conversation_id,
            sender_is_bot,
            send_at,
        )
        .map_err(|error| format!("{prefix}: {error}"))?;
        result.push(envelope);
    }
    Ok(result)
}

fn get_property(value: &JsValue, name: &str) -> Result<JsValue, String> {
    Reflect::get(value, &JsValue::from_str(name)).map_err(|_| format!("unable to read {name}"))
}

fn required_string(value: &JsValue, name: &str, prefix: &str) -> Result<String, String> {
    get_property(value, name)?
        .as_string()
        .ok_or_else(|| format!("{prefix}.{name} must be a string"))
}

fn required_bool(value: &JsValue, name: &str, prefix: &str) -> Result<bool, String> {
    get_property(value, name)?
        .as_bool()
        .ok_or_else(|| format!("{prefix}.{name} must be a boolean"))
}

fn required_u32(value: &JsValue, name: &str, prefix: &str, nonzero: bool) -> Result<u32, String> {
    let number = get_property(value, name)?
        .as_f64()
        .ok_or_else(|| format!("{prefix}.{name} must be a number"))?;
    if !number.is_finite()
        || number.fract() != 0.0
        || number < if nonzero { 1.0 } else { 0.0 }
        || number > u32::MAX as f64
    {
        return Err(format!(
            "{prefix}.{name} is outside the supported u32 range"
        ));
    }
    Ok(number as u32)
}

fn required_i64(value: &JsValue, name: &str, prefix: &str) -> Result<i64, String> {
    let number = get_property(value, name)?
        .as_f64()
        .ok_or_else(|| format!("{prefix}.{name} must be a number"))?;
    if !number.is_finite() || number.fract() != 0.0 || number.abs() > 9_007_199_254_740_991.0 {
        return Err(format!("{prefix}.{name} must be a safe integer"));
    }
    Ok(number as i64)
}

fn optional_i64(value: &JsValue, name: &str, default: i64, prefix: &str) -> Result<i64, String> {
    let field = get_property(value, name)?;
    if field.is_undefined() || field.is_null() {
        return Ok(default);
    }
    required_i64_value(&field, name, prefix)
}

fn required_i64_value(value: &JsValue, name: &str, prefix: &str) -> Result<i64, String> {
    let number = value
        .as_f64()
        .ok_or_else(|| format!("{prefix}.{name} must be a number"))?;
    if !number.is_finite() || number.fract() != 0.0 || number.abs() > 9_007_199_254_740_991.0 {
        return Err(format!("{prefix}.{name} must be a safe integer"));
    }
    Ok(number as i64)
}

fn parse_uuid_array(value: &JsValue, max: usize, name: &str) -> Result<Vec<Vec<u8>>, String> {
    if !Array::is_array(value) {
        return Err(format!("{name} must be an array of UUID strings"));
    }
    let values = Array::from(value);
    if values.length() as usize > max {
        return Err(format!("{name} contains more than {max} entries"));
    }
    (0..values.length())
        .map(|index| {
            let value = values
                .get(index)
                .as_string()
                .ok_or_else(|| format!("{name}[{index}] must be a UUID string"))?;
            parse_uuid(&value)
        })
        .collect()
}

fn parse_uuid(value: &str) -> Result<Vec<u8>, String> {
    let hex = value.replace('-', "");
    if hex.len() != 32 {
        return Err(format!("not a UUID: {value}"));
    }
    decode_hex(&hex).map_err(|_| format!("not a UUID: {value}"))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("hex data must have an even number of characters".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])
                .ok_or_else(|| "hex data contains a non-hexadecimal character".to_owned())?;
            let low = hex_digit(pair[1])
                .ok_or_else(|| "hex data contains a non-hexadecimal character".to_owned())?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn validate_envelope_parts(
    envelope_id: Vec<u8>,
    sender_account_id: Vec<u8>,
    recipient_account_id: Vec<u8>,
    sender_device_number: u32,
    recipient_device_number: u32,
    envelope_type: u32,
    is_prekey_message: bool,
    ciphertext: Vec<u8>,
    client_timestamp: i64,
    conversation_id: Vec<u8>,
    sender_is_bot: bool,
    send_at: i64,
) -> Result<Envelope, String> {
    if envelope_id.len() != 16 || sender_account_id.len() != 16 || recipient_account_id.len() != 16
    {
        return Err("envelope and account ids must be UUIDs".into());
    }
    if !conversation_id.is_empty() && conversation_id.len() != 16 {
        return Err("conversation id must be a UUID or empty".into());
    }
    if sender_device_number == 0 || recipient_device_number == 0 {
        return Err("device numbers must be non-zero".into());
    }
    if !(1..=15).contains(&envelope_type) || envelope_type == 8 {
        return Err("unsupported envelope type".into());
    }
    if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err("ciphertext exceeds 65536 bytes".into());
    }
    Ok(Envelope {
        envelope_id,
        sender_account_id,
        sender_device_number,
        recipient_account_id,
        recipient_device_number,
        envelope_type: envelope_type as i32,
        is_prekey_message,
        ciphertext,
        client_timestamp,
        conversation_id,
        sender_is_bot,
        send_at,
    })
}

#[derive(Clone, Debug, PartialEq)]
enum Shape {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<Shape>),
    Object(Vec<(&'static str, Shape)>),
}

fn object_shape(fields: Vec<(&'static str, Shape)>) -> Shape {
    Shape::Object(fields)
}
fn b(value: bool) -> Shape {
    Shape::Bool(value)
}
fn n(value: impl Into<f64>) -> Shape {
    Shape::Number(value.into())
}
fn s(value: impl Into<String>) -> Shape {
    Shape::String(value.into())
}
fn bytes(value: &[u8]) -> Shape {
    Shape::Bytes(value.to_vec())
}
fn opt_string(value: Option<&str>) -> Shape {
    value.map(s).unwrap_or(Shape::Null)
}
fn opt_i64(value: Option<i64>) -> Shape {
    value.map(|value| n(value as f64)).unwrap_or(Shape::Null)
}

impl Shape {
    fn into_js(self) -> JsValue {
        match self {
            Self::Null => JsValue::NULL,
            Self::Bool(value) => JsValue::from_bool(value),
            Self::Number(value) => JsValue::from_f64(value),
            Self::String(value) => JsValue::from_str(&value),
            Self::Bytes(value) => Uint8Array::from(value.as_slice()).into(),
            Self::Array(values) => {
                let output = Array::new();
                for value in values {
                    output.push(&value.into_js());
                }
                output.into()
            }
            Self::Object(fields) => {
                let output = Object::new();
                for (key, value) in fields {
                    let _ = Reflect::set(&output, &JsValue::from_str(key), &value.into_js());
                }
                output.into()
            }
        }
    }
}

fn server_hello_shape(value: &fh::ServerHello) -> Shape {
    object_shape(vec![
        ("sessionId", s(value.session_id.clone())),
        ("accountId", bytes(&value.account_id)),
        ("deviceNumber", n(value.device_number)),
        ("serverTimestamp", n(value.server_timestamp as f64)),
        ("protocolMajor", n(value.protocol_major)),
        ("protocolMinor", n(value.protocol_minor)),
        ("protocolPatch", n(value.protocol_patch)),
    ])
}

fn envelope_shape(value: &Envelope) -> Shape {
    object_shape(vec![
        ("envelopeId", bytes(&value.envelope_id)),
        ("senderAccountId", bytes(&value.sender_account_id)),
        ("senderDeviceNumber", n(value.sender_device_number)),
        ("recipientAccountId", bytes(&value.recipient_account_id)),
        ("recipientDeviceNumber", n(value.recipient_device_number)),
        ("envelopeType", n(value.envelope_type)),
        ("isPrekeyMessage", b(value.is_prekey_message)),
        ("ciphertext", bytes(&value.ciphertext)),
        ("clientTimestamp", n(value.client_timestamp as f64)),
        ("conversationId", bytes(&value.conversation_id)),
        ("senderIsBot", b(value.sender_is_bot)),
        ("sendAt", n(value.send_at as f64)),
    ])
}

fn envelope_delivery_shape(value: &fh::EnvelopeDelivery) -> Shape {
    object_shape(vec![(
        "envelopes",
        Shape::Array(value.envelopes.iter().map(envelope_shape).collect()),
    )])
}

fn envelope_ack_shape(value: &fh::EnvelopeAck) -> Shape {
    object_shape(vec![
        (
            "envelopeIds",
            Shape::Array(
                value
                    .envelope_ids
                    .iter()
                    .map(|value| bytes(value))
                    .collect(),
            ),
        ),
        (
            "serverTimestamps",
            Shape::Array(
                value
                    .server_timestamps
                    .iter()
                    .map(|value| n(*value as f64))
                    .collect(),
            ),
        ),
    ])
}

fn pong_shape(value: &fh::Pong) -> Shape {
    object_shape(vec![
        ("clientTimestamp", n(value.client_timestamp as f64)),
        ("serverTimestamp", n(value.server_timestamp as f64)),
    ])
}

fn error_frame_shape(value: &fh::ErrorFrame) -> Shape {
    object_shape(vec![
        ("code", s(value.code.clone())),
        ("message", s(value.message.clone())),
        ("fatal", b(value.fatal)),
        ("reference", opt_string(value.reference.as_deref())),
    ])
}

fn presence_shape(value: &fh::PresenceUpdate) -> Shape {
    object_shape(vec![
        ("accountId", bytes(&value.account_id)),
        ("isOnline", b(value.is_online)),
        ("lastSeen", opt_i64(value.last_seen)),
        (
            "customStatusText",
            opt_string(value.custom_status_text.as_deref()),
        ),
        (
            "customStatusEmoji",
            opt_string(value.custom_status_emoji.as_deref()),
        ),
        (
            "customStatusExpiresAt",
            opt_i64(value.custom_status_expires_at),
        ),
    ])
}

fn bot_message_shape(value: &fh::BotMessageDelivery) -> Shape {
    object_shape(vec![
        ("messageId", s(value.message_id.clone())),
        ("botId", bytes(&value.bot_id)),
        ("accountId", bytes(&value.account_id)),
        ("text", s(value.text.clone())),
        (
            "replyToMessageId",
            opt_string(value.reply_to_message_id.as_deref()),
        ),
        ("createdAt", n(value.created_at as f64)),
        ("replyMarkup", opt_string(value.reply_markup.as_deref())),
    ])
}

fn channel_post_shape(value: &fh::ChannelPostDelivery) -> Shape {
    object_shape(vec![
        ("postId", s(value.post_id.clone())),
        ("channelId", bytes(&value.channel_id)),
        ("authorType", s(value.author_type.clone())),
        ("authorId", bytes(&value.author_id)),
        ("text", s(value.text.clone())),
        (
            "attachmentIds",
            Shape::Array(value.attachment_ids.iter().cloned().map(s).collect()),
        ),
        (
            "replyToPostId",
            opt_string(value.reply_to_post_id.as_deref()),
        ),
        ("createdAt", n(value.created_at as f64)),
    ])
}

fn typing_shape(value: &fh::TypingDelivery) -> Shape {
    object_shape(vec![
        ("conversationId", bytes(&value.conversation_id)),
        ("accountId", bytes(&value.account_id)),
    ])
}

fn read_receipt_shape(value: &fh::ReadReceiptDelivery) -> Shape {
    object_shape(vec![
        ("conversationId", bytes(&value.conversation_id)),
        ("accountId", bytes(&value.account_id)),
        ("lastReadAt", n(value.last_read_at as f64)),
    ])
}

fn conversation_updated_shape(value: &fh::ConversationUpdatedDelivery) -> Shape {
    object_shape(vec![
        ("conversationId", bytes(&value.conversation_id)),
        ("title", opt_string(value.title.as_deref())),
        ("description", opt_string(value.description.as_deref())),
        ("isPublic", value.is_public.map(b).unwrap_or(Shape::Null)),
        ("membersChanged", b(value.members_changed)),
    ])
}

fn history_request_relay_shape(value: &fh::HistoryRequestRelay) -> Shape {
    object_shape(vec![
        ("fromDeviceNumber", n(value.from_device_number)),
        (
            "conversationIds",
            Shape::Array(value.conversation_ids.iter().map(|id| bytes(id)).collect()),
        ),
    ])
}

fn nudge_delivery_shape(value: &fh::NudgeDelivery) -> Shape {
    object_shape(vec![
        ("conversationId", bytes(&value.conversation_id)),
        ("fromAccountId", bytes(&value.from_account_id)),
    ])
}

fn nudge_result_shape(value: &fh::NudgeResult) -> Shape {
    object_shape(vec![("delivered", b(value.delivered))])
}
fn conversation_expired_shape(value: &fh::ConversationExpiredDelivery) -> Shape {
    object_shape(vec![("conversationId", bytes(&value.conversation_id))])
}

fn scheduled_created_shape(value: &fh::ScheduledEnvelopeCreated) -> Shape {
    object_shape(vec![
        ("envelopeId", bytes(&value.envelope_id)),
        ("conversationId", bytes(&value.conversation_id)),
        ("sendAt", n(value.send_at as f64)),
    ])
}

fn scheduled_cancelled_shape(value: &fh::ScheduledEnvelopeCancelled) -> Shape {
    object_shape(vec![("envelopeId", bytes(&value.envelope_id))])
}
fn folders_updated_shape(value: &fh::FoldersUpdated) -> Shape {
    object_shape(vec![("accountId", bytes(&value.account_id))])
}

fn bot_message_edited_shape(value: &fh::BotMessageEdited) -> Shape {
    object_shape(vec![
        ("messageId", s(value.message_id.clone())),
        ("text", s(value.text.clone())),
        ("replyMarkup", opt_string(value.reply_markup.as_deref())),
        ("editedAt", n(value.edited_at as f64)),
    ])
}

fn bot_message_deleted_shape(value: &fh::BotMessageDeleted) -> Shape {
    object_shape(vec![
        ("messageId", s(value.message_id.clone())),
        ("deletedAt", n(value.deleted_at as f64)),
    ])
}

fn bot_callback_answered_shape(value: &fh::BotCallbackAnswered) -> Shape {
    object_shape(vec![
        ("callbackQueryId", s(value.callback_query_id.clone())),
        ("text", opt_string(value.text.as_deref())),
        ("messageId", opt_string(value.message_id.as_deref())),
        ("showAlert", b(value.show_alert)),
    ])
}

fn poll_updated_shape(value: &fh::PollUpdated) -> Shape {
    object_shape(vec![
        ("pollId", s(value.poll_id.clone())),
        ("conversationId", bytes(&value.conversation_id)),
        (
            "counts",
            Shape::Array(
                value
                    .counts
                    .iter()
                    .map(|count| {
                        object_shape(vec![
                            ("optionId", s(count.option_id.clone())),
                            ("count", n(count.count as f64)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("totalVoters", n(value.total_voters as f64)),
        ("closedAt", opt_i64(value.closed_at)),
        (
            "correctOptionId",
            opt_string(value.correct_option_id.as_deref()),
        ),
        (
            "extraOptions",
            Shape::Array(
                value
                    .extra_options
                    .iter()
                    .map(|option| {
                        object_shape(vec![
                            ("optionId", s(option.option_id.clone())),
                            ("encryptedMeta", bytes(&option.encrypted_meta)),
                            (
                                "proposedByAccountId",
                                opt_string(option.proposed_by_account_id.as_deref()),
                            ),
                            (
                                "proposedByDeviceNumber",
                                option
                                    .proposed_by_device_number
                                    .map(|value| n(value))
                                    .unwrap_or(Shape::Null),
                            ),
                            ("createdAt", n(option.created_at as f64)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "deletedOptionIds",
            Shape::Array(value.deleted_option_ids.iter().cloned().map(s).collect()),
        ),
        ("revision", n(value.revision as f64)),
    ])
}

fn poll_deleted_shape(value: &fh::PollDeleted) -> Shape {
    object_shape(vec![
        ("pollId", s(value.poll_id.clone())),
        ("conversationId", bytes(&value.conversation_id)),
    ])
}

fn push_error(code: &str, message: &str) -> JsValue {
    let error = js_sys::Error::new(message);
    let object = error.as_ref();
    let _ = Reflect::set(
        object,
        &JsValue::from_str("name"),
        &JsValue::from_str("WebSocketError"),
    );
    let _ = Reflect::set(object, &JsValue::from_str("code"), &JsValue::from_str(code));
    error.into()
}

fn describe_js_value(value: &JsValue) -> String {
    Reflect::get(value, &JsValue::from_str("message"))
        .ok()
        .and_then(|message| message.as_string())
        .filter(|message| !message.is_empty())
        .or_else(|| value.as_string())
        .unwrap_or_else(|| format!("{value:?}"))
}

fn normalize_ws_url(value: &str, base: Option<&str>) -> Result<String, String> {
    if value.trim().is_empty() || value.starts_with("//") || value.contains('#') {
        return Err("WebSocket URL must be non-empty and must not be protocol-relative or contain a fragment".into());
    }
    let mut parsed = if let Ok(url) = Url::parse(value) {
        url
    } else {
        let base =
            base.ok_or_else(|| "relative WebSocket URL requires a browser page URL".to_owned())?;
        Url::parse(base)
            .map_err(|error| format!("invalid page URL: {error}"))?
            .join(value)
            .map_err(|error| format!("invalid relative WebSocket URL: {error}"))?
    };
    match parsed.scheme() {
        "http" => parsed
            .set_scheme("ws")
            .map_err(|_| "unable to convert HTTP URL to WebSocket".to_owned())?,
        "https" => parsed
            .set_scheme("wss")
            .map_err(|_| "unable to convert HTTPS URL to secure WebSocket".to_owned())?,
        "ws" | "wss" => {}
        _ => return Err("WebSocket URL must use ws, wss, http, or https".into()),
    }
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(
            "WebSocket URL must include a host and must not contain credentials or fragments"
                .into(),
        );
    }
    Ok(parsed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_url_selection_supports_api_schemes_and_page_relative_paths() {
        assert_eq!(
            normalize_ws_url("wss://api.example.test/ws", None).unwrap(),
            "wss://api.example.test/ws"
        );
        assert_eq!(
            normalize_ws_url("https://api.example.test/ws", None).unwrap(),
            "wss://api.example.test/ws"
        );
        assert_eq!(
            normalize_ws_url("/ws", Some("https://web.example.test/app/page")).unwrap(),
            "wss://web.example.test/ws"
        );
        assert_eq!(
            normalize_ws_url("ws", Some("https://web.example.test/app/page")).unwrap(),
            "wss://web.example.test/app/ws"
        );
        assert!(normalize_ws_url("//evil.example/ws", Some("https://web.example.test/")).is_err());
        assert!(normalize_ws_url("ftp://api.example.test/ws", None).is_err());
        assert!(normalize_ws_url("wss://user:pass@api.example.test/ws", None).is_err());
    }

    #[test]
    fn uuid_and_hex_validators_match_web_wire_conversions() {
        assert_eq!(
            parse_uuid("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            vec![
                0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255
            ]
        );
        assert!(parse_uuid("not-a-uuid").is_err());
        assert_eq!(decode_hex("00aAFF").unwrap(), vec![0, 170, 255]);
        assert!(decode_hex("abc").is_err());
        assert!(decode_hex("gg").is_err());
    }

    #[test]
    fn reconnect_delay_uses_exponential_steps_and_stays_capped() {
        assert_eq!(
            (0..8).map(reconnect_delay).collect::<Vec<_>>(),
            vec![1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000, 30_000]
        );
    }

    #[test]
    fn incremental_upload_size_matches_prost_frame_size() {
        for ciphertext_len in [0, 1, 126, 127, 128, 16_384, 65_536] {
            let envelope = Envelope {
                envelope_id: vec![1; 16],
                sender_account_id: vec![2; 16],
                sender_device_number: 1,
                recipient_account_id: vec![3; 16],
                recipient_device_number: 2,
                envelope_type: 1,
                is_prekey_message: false,
                ciphertext: vec![4; ciphertext_len],
                client_timestamp: 1_700_000_000,
                conversation_id: Vec::new(),
                sender_is_bot: false,
                send_at: 0,
            };
            let incremental =
                client_upload_frame_len(protobuf_message_field_len(envelope.encoded_len()));
            let actual = ClientFrame {
                kind: Some(ClientKind::Upload(EnvelopeUpload {
                    envelopes: vec![envelope],
                })),
            }
            .encoded_len();
            assert_eq!(incremental, actual, "ciphertext length {ciphertext_len}");
        }
    }

    #[test]
    fn envelope_input_validation_matches_web_camel_case_shape() {
        assert!(
            parse_envelope_json(&serde_json::json!({
                "envelopeId": "00112233-4455-6677-8899-aabbccddeeff",
                "senderAccountId": "00112233-4455-6677-8899-aabbccddeeff",
                "senderDeviceNumber": 1,
                "recipientAccountId": "ffeeddcc-bbaa-9988-7766-554433221100",
                "recipientDeviceNumber": 2,
                "envelopeType": 1,
                "isPrekeyMessage": false,
                "ciphertext": "aabb",
                "clientTimestamp": 1700000000,
                "conversationId": null,
                "senderIsBot": false,
                "sendAt": 0
            }))
            .is_ok()
        );
        assert!(
            parse_envelope_fields(
                "00112233445566778899aabbccddeeff",
                "00112233445566778899aabbccddeeff",
                "ffeeddccbbaa99887766554433221100",
                1,
                1,
                8,
                false,
                "aa",
                1,
                None,
                false,
                0
            )
            .is_err()
        );
    }

    #[test]
    fn server_frame_conversion_keeps_camel_case_fields_and_typed_bytes() {
        let frame = ServerFrame {
            kind: Some(ServerKind::Presence(fh::PresenceUpdate {
                account_id: vec![1, 2],
                is_online: true,
                last_seen: Some(42),
                custom_status_text: None,
                custom_status_emoji: Some("wave".into()),
                custom_status_expires_at: None,
            })),
        };
        let shape = presence_shape(match frame.kind.as_ref().unwrap() {
            ServerKind::Presence(value) => value,
            _ => unreachable!(),
        });
        assert_eq!(
            shape,
            object_shape(vec![
                ("accountId", Shape::Bytes(vec![1, 2])),
                ("isOnline", Shape::Bool(true)),
                ("lastSeen", Shape::Number(42.0)),
                ("customStatusText", Shape::Null),
                ("customStatusEmoji", Shape::String("wave".into())),
                ("customStatusExpiresAt", Shape::Null),
            ])
        );
    }

    fn parse_envelope_json(value: &serde_json::Value) -> Result<(), String> {
        let envelope_id = parse_uuid(value["envelopeId"].as_str().ok_or("missing envelopeId")?)?;
        let sender = parse_uuid(
            value["senderAccountId"]
                .as_str()
                .ok_or("missing senderAccountId")?,
        )?;
        let recipient = parse_uuid(
            value["recipientAccountId"]
                .as_str()
                .ok_or("missing recipientAccountId")?,
        )?;
        let _ = parse_envelope_fields(
            &hex(&envelope_id),
            &hex(&sender),
            &hex(&recipient),
            value["senderDeviceNumber"]
                .as_u64()
                .ok_or("missing senderDeviceNumber")? as u32,
            value["recipientDeviceNumber"]
                .as_u64()
                .ok_or("missing recipientDeviceNumber")? as u32,
            value["envelopeType"]
                .as_u64()
                .ok_or("missing envelopeType")? as u32,
            value["isPrekeyMessage"]
                .as_bool()
                .ok_or("missing isPrekeyMessage")?,
            value["ciphertext"].as_str().ok_or("missing ciphertext")?,
            value["clientTimestamp"]
                .as_i64()
                .ok_or("missing clientTimestamp")?,
            value["conversationId"].as_str(),
            value["senderIsBot"]
                .as_bool()
                .ok_or("missing senderIsBot")?,
            value["sendAt"].as_i64().unwrap_or(0),
        )?;
        Ok(())
    }

    fn parse_envelope_fields(
        envelope_id: &str,
        sender: &str,
        recipient: &str,
        sender_device: u32,
        recipient_device: u32,
        envelope_type: u32,
        prekey: bool,
        ciphertext: &str,
        timestamp: i64,
        conversation: Option<&str>,
        sender_bot: bool,
        send_at: i64,
    ) -> Result<Envelope, String> {
        validate_envelope_parts(
            parse_uuid(envelope_id)?,
            parse_uuid(sender)?,
            parse_uuid(recipient)?,
            sender_device,
            recipient_device,
            envelope_type,
            prekey,
            decode_hex(ciphertext)?,
            timestamp,
            conversation
                .map(parse_uuid)
                .transpose()?
                .unwrap_or_default(),
            sender_bot,
            send_at,
        )
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
