//! Browser call state machine for FriendsHub's encrypted-envelope signalling.
//!
//! This module owns one active call and the ordering around its SDP/ICE frames.
//! Media capture and peer-connection cleanup stay in [`crate::BrowserRtcManager`];
//! Signal encryption, device fan-out, WebSocket delivery, ICE-server REST access,
//! and call-history REST writes are supplied as callbacks by the binding user.
//! Those boundaries match the web client: signalling payloads remain opaque to
//! the server and travel inside the five `ENVELOPE_TYPE_CALL_*` envelopes.

use js_sys::{Array, Date, Error as JsError, Function, Object, Promise, Reflect};
use rand::RngCore;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::{Rc, Weak};
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, spawn_local};

const OFFER: u32 = 10;
const ANSWER: u32 = 11;
const ICE: u32 = 12;
const HANGUP: u32 = 13;
const REJECT: u32 = 14;
const INCOMING_TIMEOUT_MS: i32 = 60_000;
const MAX_HELD_LOCAL_CANDIDATES: usize = 256;
const MAX_FINISHED_INCOMING: usize = 512;
const FINISHED_INCOMING_RETENTION_MS: f64 = 24.0 * 60.0 * 60.0 * 1_000.0;

type JsResult<T> = Result<T, JsValue>;
type EventClosure = Closure<dyn FnMut(JsValue, JsValue)>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignalKind {
    Offer,
    Answer,
    Ice,
    Hangup,
    Reject,
}

impl SignalKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Offer => "offer",
            Self::Answer => "answer",
            Self::Ice => "ice",
            Self::Hangup => "hangup",
            Self::Reject => "reject",
        }
    }

    fn envelope_type(self) -> u32 {
        match self {
            Self::Offer => OFFER,
            Self::Answer => ANSWER,
            Self::Ice => ICE,
            Self::Hangup => HANGUP,
            Self::Reject => REJECT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    Incoming,
    Outgoing,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Incoming => "incoming",
            Self::Outgoing => "outgoing",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Incoming,
    Outgoing,
    Active,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Incoming => "incoming",
            Self::Outgoing => "outgoing",
            Self::Active => "active",
        }
    }
}

#[derive(Clone)]
struct ActiveCall {
    call_id: String,
    peer_account_id: String,
    conversation_id: Option<String>,
    direction: Direction,
    phase: Phase,
    with_video: bool,
    pending_offer_sdp: Option<String>,
    started_at: u64,
    connected: bool,
    connected_at: Option<u64>,
    failed: bool,
    signals_open: bool,
    held_candidates: VecDeque<JsValue>,
}

#[derive(Clone, Default)]
struct CallCallbacks {
    outgoing_call: Option<Function>,
    incoming_call: Option<Function>,
    phase_changed: Option<Function>,
    call_connected: Option<Function>,
    call_failed: Option<Function>,
    call_rejected: Option<Function>,
    call_ended: Option<Function>,
    signal_failed: Option<Function>,
    local_stream: Option<Function>,
    remote_stream: Option<Function>,
    remote_video: Option<Function>,
}

struct SignalRequest {
    call_id: String,
    kind: SignalKind,
    request: JsValue,
    completion: Option<(Function, Function)>,
}

#[derive(Clone, Copy)]
struct ActiveTimeout {
    id: u64,
    handle: i32,
}

struct OrchestratorState {
    rtc_manager: JsValue,
    get_ice_servers: Function,
    send_signal: Function,
    callbacks: CallCallbacks,
    has_finished_incoming: Option<Function>,
    call: Option<ActiveCall>,
    signals: VecDeque<SignalRequest>,
    sending_signals: bool,
    active_timeout: Option<ActiveTimeout>,
    timer_callbacks: HashMap<u64, Closure<dyn FnMut()>>,
    next_timer_id: u64,
    finished_incoming: HashMap<String, f64>,
}

/// Coordinates the caller/callee state machine around [`crate::BrowserRtcManager`].
///
/// `get_ice_servers` must return a Promise for the actual `GET /webrtc/ice-servers`
/// response (`{ iceServers, ttlSeconds }`). `send_signal` must return a Promise
/// that resolves when one frame has been encrypted/fanned out and handed to the
/// WebSocket sender. It receives one object per signal:
/// `{ peer_account_id, conversation_id, envelope_type, payload }`. `payload` is
/// the WEB-compatible JSON object `{ call_id, kind, sdp, candidate, reason }`.
/// A candidate is never batched with another signal.
#[wasm_bindgen]
pub struct BrowserCallManager {
    state: Rc<RefCell<OrchestratorState>>,
    rtc_event_handlers: Vec<EventClosure>,
}

#[wasm_bindgen]
impl BrowserCallManager {
    /// Takes the browser RTC manager plus the REST and encrypted-signal adapters.
    ///
    /// `get_ice_servers()` returns the web API's `{ iceServers, ttlSeconds }`.
    /// `send_signal(request)` encrypts the exact payload and uploads its single
    /// envelope batch via the active push connection. Both callbacks must return
    /// Promises. The send callback must map envelope types 10 through 14 to the
    /// generated FriendsHub protobuf enum values.
    #[wasm_bindgen(constructor)]
    pub fn new(
        rtc_manager: JsValue,
        get_ice_servers: Function,
        send_signal: Function,
    ) -> JsResult<BrowserCallManager> {
        if rtc_manager.is_null() || rtc_manager.is_undefined() {
            return Err(call_error("invalid_argument", "rtc_manager is required"));
        }
        let state = Rc::new(RefCell::new(OrchestratorState {
            rtc_manager,
            get_ice_servers,
            send_signal,
            callbacks: CallCallbacks::default(),
            has_finished_incoming: None,
            call: None,
            signals: VecDeque::new(),
            sending_signals: false,
            active_timeout: None,
            timer_callbacks: HashMap::new(),
            next_timer_id: 0,
            finished_incoming: HashMap::new(),
        }));

        let mut handlers = Vec::with_capacity(6);
        install_rtc_handler(
            &state,
            &mut handlers,
            "set_on_ice_candidate",
            |state, call_id, value| {
                on_local_ice(state, call_id, value);
            },
        )?;
        install_rtc_handler(
            &state,
            &mut handlers,
            "set_on_connected",
            |state, call_id, _| {
                on_rtc_connected(state, call_id);
            },
        )?;
        install_rtc_handler(
            &state,
            &mut handlers,
            "set_on_failed",
            |state, call_id, detail| {
                on_rtc_failed(state, call_id, detail);
            },
        )?;
        install_rtc_handler(
            &state,
            &mut handlers,
            "set_on_local_stream",
            |state, call_id, stream| {
                forward_stream(state, true, call_id, stream);
            },
        )?;
        install_rtc_handler(
            &state,
            &mut handlers,
            "set_on_remote_stream",
            |state, call_id, stream| {
                forward_stream(state, false, call_id, stream);
            },
        )?;
        install_rtc_handler(
            &state,
            &mut handlers,
            "set_on_remote_video",
            |state, call_id, _| {
                let callbacks = state.borrow().callbacks.clone();
                call_callback1(&callbacks.remote_video, call_id);
            },
        )?;

        Ok(Self {
            state,
            rtc_event_handlers: handlers,
        })
    }

    /// Registers a separate callback for a call started by this device.
    /// Receives the call descriptor.
    pub fn set_on_outgoing_call(&self, callback: Option<Function>) {
        self.state.borrow_mut().callbacks.outgoing_call = callback;
    }

    /// Registers a separate callback for a newly received offer.
    /// Receives the call descriptor, including `pending_offer_sdp`.
    pub fn set_on_incoming_call(&self, callback: Option<Function>) {
        self.state.borrow_mut().callbacks.incoming_call = callback;
    }

    /// Receives `(call_descriptor, previous_phase)` on each phase transition.
    pub fn set_on_phase_changed(&self, callback: Option<Function>) {
        self.state.borrow_mut().callbacks.phase_changed = callback;
    }

    /// Receives the call descriptor after the browser RTC connection succeeds.
    pub fn set_on_call_connected(&self, callback: Option<Function>) {
        self.state.borrow_mut().callbacks.call_connected = callback;
    }

    /// Receives `(call_descriptor, error)` for a recoverable setup/send failure.
    pub fn set_on_call_failed(&self, callback: Option<Function>) {
        self.state.borrow_mut().callbacks.call_failed = callback;
    }

    /// Receives the call descriptor and peer's optional reject reason.
    pub fn set_on_call_rejected(&self, callback: Option<Function>) {
        self.state.borrow_mut().callbacks.call_rejected = callback;
    }

    /// Receives `(call_descriptor, status)` exactly once when the call finishes.
    /// The status is one of `completed`, `missed`, `rejected`, `cancelled`, `failed`.
    pub fn set_on_call_ended(&self, callback: Option<Function>) {
        self.state.borrow_mut().callbacks.call_ended = callback;
    }

    /// Receives `(call_id, kind, error)` when a queued signal cannot be sent.
    pub fn set_on_signal_failed(&self, callback: Option<Function>) {
        self.state.borrow_mut().callbacks.signal_failed = callback;
    }

    /// Installs the WEB-owned persistence check for calls already finished in
    /// IndexedDB. Receives `call_id` and may return either a boolean or a
    /// Promise<boolean>. A failed check is treated as a cache miss, matching
    /// WEB's behavior when local settings cannot be read.
    pub fn set_finished_incoming_check(&self, callback: Option<Function>) {
        self.state.borrow_mut().has_finished_incoming = callback;
    }

    /// Receives `(call_id, MediaStream)` after local capture or camera switching.
    pub fn set_on_local_stream(&self, callback: Option<Function>) {
        self.state.borrow_mut().callbacks.local_stream = callback;
    }

    /// Receives `(call_id, MediaStream)` as remote tracks arrive.
    pub fn set_on_remote_stream(&self, callback: Option<Function>) {
        self.state.borrow_mut().callbacks.remote_stream = callback;
    }

    /// Receives `call_id` when a remote video track arrives.
    pub fn set_on_remote_video(&self, callback: Option<Function>) {
        self.state.borrow_mut().callbacks.remote_video = callback;
    }

    /// Starts an outgoing call and returns its time-ordered UUIDv7 call id.
    ///
    /// The offer is sent before locally gathered ICE candidates are released.
    /// Only one active call is allowed, matching the WEB call overlay.
    pub async fn start_call(
        &self,
        peer_account_id: String,
        conversation_id: Option<String>,
        with_video: bool,
    ) -> JsResult<String> {
        if peer_account_id.trim().is_empty() {
            return Err(call_error(
                "invalid_argument",
                "peer_account_id must not be empty",
            ));
        }
        let call_id = uuid_v7();
        let call = ActiveCall {
            call_id: call_id.clone(),
            peer_account_id,
            conversation_id,
            direction: Direction::Outgoing,
            phase: Phase::Outgoing,
            with_video,
            pending_offer_sdp: None,
            started_at: now_seconds(),
            connected: false,
            connected_at: None,
            failed: false,
            signals_open: false,
            held_candidates: VecDeque::new(),
        };
        {
            let mut state = self.state.borrow_mut();
            if state.call.is_some() {
                return Err(call_error("call_busy", "another call is already active"));
            }
            state.call = Some(call.clone());
        }
        emit_call_callback(&self.state, true, &call);

        let setup = async {
            let ice_servers = load_ice_servers(&self.state).await?;
            ensure_active(&self.state, &call_id)?;
            let sdp = rtc_async(
                &self.state,
                "create_offer",
                &[
                    JsValue::from_str(&call_id),
                    ice_servers,
                    JsValue::from_bool(with_video),
                ],
            )
            .await?
            .as_string()
            .filter(|sdp| !sdp.is_empty())
            .ok_or_else(|| call_error("rtc", "create_offer returned an empty SDP"))?;
            ensure_active(&self.state, &call_id)?;
            let payload = signal_payload(&call_id, SignalKind::Offer, Some(&sdp), None, None)?;
            let send = enqueue_signal(&self.state, call.clone(), SignalKind::Offer, payload, true)?;
            JsFuture::from(send).await.map_err(|error| error)?;
            open_local_signals(&self.state, &call_id)?;
            Ok::<(), JsValue>(())
        }
        .await;

        if let Err(error) = setup {
            mark_recoverable_failure(&self.state, &call_id, error.clone());
            return Err(error);
        }
        Ok(call_id)
    }

    /// Accepts the active incoming offer, creates a local answer, and sends it.
    /// ICE gathered before the answer is sent remains held and is released in order.
    pub async fn accept_call(&self) -> JsResult<()> {
        let call = self.require_incoming()?;
        let sdp = call
            .pending_offer_sdp
            .as_deref()
            .filter(|sdp| !sdp.is_empty())
            .ok_or_else(|| call_error("invalid_state", "incoming offer has no SDP"))?
            .to_owned();
        cancel_answer_timeout(&self.state);
        set_phase(&self.state, &call.call_id, Phase::Active)?;

        let result = async {
            let ice_servers = load_ice_servers(&self.state).await?;
            ensure_active(&self.state, &call.call_id)?;
            let answer = rtc_async(
                &self.state,
                "accept_offer",
                &[
                    JsValue::from_str(&call.call_id),
                    ice_servers,
                    JsValue::from_str(&sdp),
                ],
            )
            .await?
            .as_string()
            .filter(|answer| !answer.is_empty())
            .ok_or_else(|| call_error("rtc", "accept_offer returned an empty SDP"))?;
            ensure_active(&self.state, &call.call_id)?;
            let payload =
                signal_payload(&call.call_id, SignalKind::Answer, Some(&answer), None, None)?;
            let send =
                enqueue_signal(&self.state, call.clone(), SignalKind::Answer, payload, true)?;
            JsFuture::from(send).await.map_err(|error| error)?;
            open_local_signals(&self.state, &call.call_id)?;
            Ok::<(), JsValue>(())
        }
        .await;
        if let Err(error) = result {
            mark_recoverable_failure(&self.state, &call.call_id, error.clone());
            return Err(error);
        }
        Ok(())
    }

    /// Declines the active incoming call and sends `reject` with reason `declined`.
    pub fn decline_call(&self) -> JsResult<bool> {
        let Some(call) = self.current_active_call() else {
            return Ok(false);
        };
        if call.phase != Phase::Incoming {
            return Ok(false);
        }
        cancel_answer_timeout(&self.state);
        queue_best_effort(
            &self.state,
            call.clone(),
            SignalKind::Reject,
            None,
            None,
            Some("declined"),
        );
        finish_call(&self.state, &call.call_id, "rejected");
        Ok(true)
    }

    /// Ends either half of the active call. An unanswered incoming call is rejected.
    pub fn hang_up(&self) -> JsResult<bool> {
        let Some(call) = self.current_active_call() else {
            return Ok(false);
        };
        cancel_answer_timeout(&self.state);
        let (kind, reason) = if call.phase == Phase::Incoming {
            (SignalKind::Reject, Some("declined"))
        } else {
            (SignalKind::Hangup, None)
        };
        queue_best_effort(&self.state, call.clone(), kind, None, None, reason);
        let status = local_end_status(&call);
        finish_call(&self.state, &call.call_id, status);
        Ok(true)
    }

    /// Toggles local camera tracks for an active video call.
    pub fn set_video_enabled(&self, enabled: bool) -> JsResult<bool> {
        let call = self
            .current_active_call()
            .ok_or_else(|| call_error("invalid_state", "no active call"))?;
        if !call.with_video {
            return Ok(false);
        }
        let result = rtc_sync(
            &self.state,
            "set_video_enabled",
            &[
                JsValue::from_str(&call.call_id),
                JsValue::from_bool(enabled),
            ],
        )?;
        Ok(result.as_bool().unwrap_or(false))
    }

    /// Switches to the next browser camera, preserving the active call.
    pub async fn switch_camera(&self) -> JsResult<bool> {
        let call = self
            .current_active_call()
            .ok_or_else(|| call_error("invalid_state", "no active call"))?;
        let result = rtc_async(
            &self.state,
            "switch_camera",
            &[JsValue::from_str(&call.call_id)],
        )
        .await?;
        Ok(result.as_bool().unwrap_or(false))
    }

    /// Applies a decrypted call payload received from an envelope delivery.
    ///
    /// The push/Signal layer should call this only for envelope types 10–14,
    /// after pairwise decryption and JSON parsing. Returns `true` when the
    /// payload was valid and handled or intentionally ignored as stale/duplicate.
    pub async fn handle_signal(
        &self,
        sender_account_id: String,
        conversation_id: Option<String>,
        payload: JsValue,
    ) -> JsResult<bool> {
        let Some(signal) = parse_signal(&payload)? else {
            return Ok(false);
        };
        match signal.kind {
            SignalKind::Offer => {
                self.handle_offer(sender_account_id, conversation_id, signal)
                    .await
            }
            SignalKind::Answer => self.handle_answer(signal).await,
            SignalKind::Ice => self.handle_ice(signal).await,
            SignalKind::Hangup => {
                self.handle_hangup(signal);
                Ok(true)
            }
            SignalKind::Reject => {
                self.handle_reject(signal);
                Ok(true)
            }
        }
    }

    /// Returns the active call descriptor, or `null` when idle.
    pub fn active_call(&self) -> JsValue {
        self.state
            .borrow()
            .call
            .as_ref()
            .map(call_descriptor)
            .unwrap_or(JsValue::NULL)
    }

    /// Clears the call state and closes any owned peer connection.
    pub fn close(&self) {
        let Some(call) = self.current_active_call() else {
            return;
        };
        cancel_answer_timeout(&self.state);
        finish_call(&self.state, &call.call_id, local_end_status(&call));
    }
}

impl BrowserCallManager {
    fn current_active_call(&self) -> Option<ActiveCall> {
        self.state.borrow().call.clone()
    }

    fn require_incoming(&self) -> JsResult<ActiveCall> {
        let call = self
            .current_active_call()
            .ok_or_else(|| call_error("invalid_state", "no incoming call"))?;
        if call.direction != Direction::Incoming || call.phase != Phase::Incoming {
            return Err(call_error(
                "invalid_state",
                "the active call is not ringing",
            ));
        }
        Ok(call)
    }

    async fn handle_offer(
        &self,
        sender_account_id: String,
        conversation_id: Option<String>,
        signal: ParsedSignal,
    ) -> JsResult<bool> {
        let Some(sdp) = signal.sdp.filter(|sdp| !sdp.is_empty()) else {
            return Ok(false);
        };
        if sender_account_id.trim().is_empty() {
            return Ok(false);
        }
        prune_finished_incoming(&self.state);
        if is_finished_incoming(&self.state, &signal.call_id).await {
            return Ok(true);
        }
        {
            let state = self.state.borrow();
            if let Some(active) = state.call.as_ref() {
                if active.call_id == signal.call_id {
                    return Ok(true);
                }
                let busy_reject = ActiveCall {
                    call_id: signal.call_id.clone(),
                    peer_account_id: sender_account_id,
                    conversation_id,
                    direction: Direction::Incoming,
                    phase: Phase::Incoming,
                    with_video: false,
                    pending_offer_sdp: None,
                    started_at: now_seconds(),
                    connected: false,
                    connected_at: None,
                    failed: false,
                    signals_open: true,
                    held_candidates: VecDeque::new(),
                };
                drop(state);
                queue_best_effort(
                    &self.state,
                    busy_reject,
                    SignalKind::Reject,
                    None,
                    None,
                    Some("busy"),
                );
                return Ok(true);
            }
        }

        let call = ActiveCall {
            call_id: signal.call_id,
            peer_account_id: sender_account_id,
            conversation_id,
            direction: Direction::Incoming,
            phase: Phase::Incoming,
            with_video: offer_has_video(&sdp),
            pending_offer_sdp: Some(sdp),
            started_at: now_seconds(),
            connected: false,
            connected_at: None,
            failed: false,
            signals_open: false,
            held_candidates: VecDeque::new(),
        };
        self.state.borrow_mut().call = Some(call.clone());
        emit_call_callback(&self.state, false, &call);
        install_answer_timeout(&self.state, &call.call_id)?;
        Ok(true)
    }

    async fn handle_answer(&self, signal: ParsedSignal) -> JsResult<bool> {
        let Some(sdp) = signal.sdp.filter(|sdp| !sdp.is_empty()) else {
            return Ok(false);
        };
        let Some(call) = self.current_active_call() else {
            return Ok(true);
        };
        if call.call_id != signal.call_id
            || call.direction != Direction::Outgoing
            || call.phase != Phase::Outgoing
        {
            return Ok(true);
        }
        set_phase(&self.state, &call.call_id, Phase::Active)?;
        if let Err(error) = rtc_async(
            &self.state,
            "accept_answer",
            &[JsValue::from_str(&call.call_id), JsValue::from_str(&sdp)],
        )
        .await
        {
            mark_recoverable_failure(&self.state, &call.call_id, error.clone());
            return Err(error);
        }
        Ok(true)
    }

    async fn handle_ice(&self, signal: ParsedSignal) -> JsResult<bool> {
        let Some(call) = self.current_active_call() else {
            return Ok(true);
        };
        if call.call_id != signal.call_id {
            return Ok(true);
        }
        let Some(candidate) = signal.candidate else {
            return Ok(false);
        };
        if !candidate_is_valid(&candidate) {
            return Ok(false);
        }
        rtc_async(
            &self.state,
            "add_remote_candidate",
            &[JsValue::from_str(&call.call_id), candidate],
        )
        .await?;
        Ok(true)
    }

    fn handle_hangup(&self, signal: ParsedSignal) {
        let Some(call) = self.current_active_call() else {
            return;
        };
        if call.call_id != signal.call_id {
            return;
        }
        let status = if call.failed {
            "failed"
        } else if call.connected {
            "completed"
        } else if call.phase == Phase::Incoming {
            "missed"
        } else {
            "cancelled"
        };
        finish_call(&self.state, &call.call_id, status);
    }

    fn handle_reject(&self, signal: ParsedSignal) {
        let Some(call) = self.current_active_call() else {
            return;
        };
        if call.call_id != signal.call_id {
            return;
        }
        if call.direction == Direction::Outgoing {
            let callbacks = self.state.borrow().callbacks.clone();
            call_callback2(
                &callbacks.call_rejected,
                call_descriptor(&call),
                signal
                    .reason
                    .as_deref()
                    .map(JsValue::from_str)
                    .unwrap_or(JsValue::NULL),
            );
        }
        finish_call(
            &self.state,
            &call.call_id,
            if call.failed { "failed" } else { "rejected" },
        );
    }
}

impl Drop for BrowserCallManager {
    fn drop(&mut self) {
        let active_call = { self.state.borrow().call.clone() };
        if let Some(call) = active_call {
            cancel_answer_timeout(&self.state);
            finish_call(&self.state, &call.call_id, local_end_status(&call));
        }
        let rtc = self.state.borrow().rtc_manager.clone();
        for name in [
            "set_on_ice_candidate",
            "set_on_connected",
            "set_on_failed",
            "set_on_local_stream",
            "set_on_remote_stream",
            "set_on_remote_video",
        ] {
            if let Ok(setter) = get_function(&rtc, name) {
                let _ = setter.call1(&rtc, &JsValue::NULL);
            }
        }
        // A user callback can drop this manager reentrantly from an RTC event.
        // Let the active Rust trampoline return before dropping its Closure.
        let handlers = std::mem::take(&mut self.rtc_event_handlers);
        spawn_local(async move {
            let _ = JsFuture::from(Promise::resolve(&JsValue::UNDEFINED)).await;
            drop(handlers);
        });
    }
}

struct ParsedSignal {
    call_id: String,
    kind: SignalKind,
    sdp: Option<String>,
    candidate: Option<JsValue>,
    reason: Option<String>,
}

fn parse_signal(value: &JsValue) -> JsResult<Option<ParsedSignal>> {
    if !value.is_object() || value.is_null() {
        return Ok(None);
    }
    let Some(call_id) = get_property(value, "call_id")?.as_string() else {
        return Ok(None);
    };
    if call_id.is_empty() {
        return Ok(None);
    }
    let kind = match get_property(value, "kind")?.as_string().as_deref() {
        Some("offer") => SignalKind::Offer,
        Some("answer") => SignalKind::Answer,
        Some("ice") => SignalKind::Ice,
        Some("hangup") => SignalKind::Hangup,
        Some("reject") => SignalKind::Reject,
        _ => return Ok(None),
    };
    let sdp = get_property(value, "sdp")?.as_string();
    let candidate_value = get_property(value, "candidate")?;
    let candidate = if candidate_value.is_null() || candidate_value.is_undefined() {
        None
    } else {
        Some(candidate_value)
    };
    let reason = get_property(value, "reason")?.as_string();
    Ok(Some(ParsedSignal {
        call_id,
        kind,
        sdp,
        candidate,
        reason,
    }))
}

fn install_rtc_handler(
    state: &Rc<RefCell<OrchestratorState>>,
    handlers: &mut Vec<EventClosure>,
    method_name: &str,
    mut handler: impl FnMut(&Rc<RefCell<OrchestratorState>>, JsValue, JsValue) + 'static,
) -> JsResult<()> {
    let weak: Weak<RefCell<OrchestratorState>> = Rc::downgrade(state);
    let closure = Closure::<dyn FnMut(JsValue, JsValue)>::new(move |first, second| {
        if let Some(state) = weak.upgrade() {
            handler(&state, first, second);
        }
    });
    let rtc = state.borrow().rtc_manager.clone();
    let setter = get_function(&rtc, method_name)?;
    setter.call1(&rtc, closure.as_ref().unchecked_ref())?;
    handlers.push(closure);
    Ok(())
}

fn on_local_ice(
    state: &Rc<RefCell<OrchestratorState>>,
    call_id_value: JsValue,
    candidate: JsValue,
) {
    let Some(call_id) = call_id_value.as_string() else {
        return;
    };
    if !candidate_is_valid(&candidate) {
        let callbacks = state.borrow().callbacks.clone();
        call_callback3(
            &callbacks.signal_failed,
            JsValue::from_str(&call_id),
            JsValue::from_str("ice"),
            call_error(
                "invalid_candidate",
                "browser produced an invalid ICE candidate",
            ),
        );
        return;
    }
    let (call, overflow_callbacks) = {
        let mut inner = state.borrow_mut();
        let callbacks = inner.callbacks.clone();
        let Some(call) = inner.call.as_mut().filter(|call| call.call_id == call_id) else {
            return;
        };
        if !call.signals_open {
            if call.held_candidates.len() >= MAX_HELD_LOCAL_CANDIDATES {
                (None, Some(callbacks))
            } else {
                call.held_candidates.push_back(candidate);
                return;
            }
        } else {
            (Some(call.clone()), None)
        }
    };
    if let Some(callbacks) = overflow_callbacks {
        call_callback3(
            &callbacks.signal_failed,
            JsValue::from_str(&call_id),
            JsValue::from_str("ice"),
            call_error(
                "candidate_queue_full",
                "too many local ICE candidates before SDP delivery",
            ),
        );
        return;
    }
    let Some(call) = call else {
        return;
    };
    let Ok(payload) = signal_payload(&call.call_id, SignalKind::Ice, None, Some(candidate), None)
    else {
        return;
    };
    let _ = enqueue_signal(state, call, SignalKind::Ice, payload, false);
}

fn on_rtc_connected(state: &Rc<RefCell<OrchestratorState>>, call_id_value: JsValue) {
    let Some(call_id) = call_id_value.as_string() else {
        return;
    };
    let call = {
        let mut inner = state.borrow_mut();
        let Some(call) = inner.call.as_mut().filter(|call| call.call_id == call_id) else {
            return;
        };
        if call.connected {
            return;
        }
        call.connected = true;
        call.connected_at = Some(now_seconds());
        call.clone()
    };
    let callbacks = state.borrow().callbacks.clone();
    call_callback1(&callbacks.call_connected, call_descriptor(&call));
}

fn on_rtc_failed(state: &Rc<RefCell<OrchestratorState>>, call_id_value: JsValue, detail: JsValue) {
    let Some(call_id) = call_id_value.as_string() else {
        return;
    };
    if let Some(call) = current_call(state, &call_id) {
        let callbacks = state.borrow().callbacks.clone();
        call_callback2(
            &callbacks.call_failed,
            call_descriptor(&call),
            if detail.is_undefined() {
                JsValue::NULL
            } else {
                detail
            },
        );
        finish_call(state, &call_id, "failed");
    }
}

fn forward_stream(
    state: &Rc<RefCell<OrchestratorState>>,
    local: bool,
    call_id: JsValue,
    stream: JsValue,
) {
    let callbacks = state.borrow().callbacks.clone();
    let callback = if local {
        callbacks.local_stream
    } else {
        callbacks.remote_stream
    };
    call_callback2(&callback, call_id, stream);
}

async fn load_ice_servers(state: &Rc<RefCell<OrchestratorState>>) -> JsResult<JsValue> {
    let provider = state.borrow().get_ice_servers.clone();
    let value = provider.call0(&JsValue::UNDEFINED)?;
    let promise = value
        .dyn_into::<Promise>()
        .map_err(|_| call_error("callback_contract", "get_ice_servers must return a Promise"))?;
    let response = JsFuture::from(promise).await?;
    let servers = get_property(&response, "iceServers")?;
    if !Array::is_array(&servers) {
        return Err(call_error(
            "invalid_ice_servers",
            "GET /webrtc/ice-servers response must contain an iceServers array",
        ));
    }
    Ok(servers)
}

async fn rtc_async(
    state: &Rc<RefCell<OrchestratorState>>,
    method_name: &str,
    arguments: &[JsValue],
) -> JsResult<JsValue> {
    let rtc = state.borrow().rtc_manager.clone();
    let method = get_function(&rtc, method_name)?;
    let args = Array::new();
    for value in arguments {
        args.push(value);
    }
    let returned = method.apply(&rtc, &args)?;
    let promise = returned.dyn_into::<Promise>().map_err(|_| {
        call_error(
            "rtc_contract",
            format!("BrowserRtcManager.{method_name} must return a Promise"),
        )
    })?;
    JsFuture::from(promise).await
}

fn rtc_sync(
    state: &Rc<RefCell<OrchestratorState>>,
    method_name: &str,
    arguments: &[JsValue],
) -> JsResult<JsValue> {
    let rtc = state.borrow().rtc_manager.clone();
    let method = get_function(&rtc, method_name)?;
    let args = Array::new();
    for value in arguments {
        args.push(value);
    }
    method.apply(&rtc, &args)
}

fn enqueue_signal(
    state: &Rc<RefCell<OrchestratorState>>,
    call: ActiveCall,
    kind: SignalKind,
    payload: JsValue,
    await_completion: bool,
) -> JsResult<Promise> {
    let request = signal_request(&call, kind, payload)?;
    let completion = if await_completion {
        let mut resolve = None;
        let mut reject = None;
        let mut executor = |resolve_fn: Function, reject_fn: Function| {
            resolve = Some(resolve_fn);
            reject = Some(reject_fn);
        };
        let promise = Promise::new(&mut executor);
        state.borrow_mut().signals.push_back(SignalRequest {
            call_id: call.call_id,
            kind,
            request,
            completion: Some((
                resolve.expect("Promise executor provides resolve"),
                reject.expect("Promise executor provides reject"),
            )),
        });
        pump_signal_queue(state);
        Ok(promise)
    } else {
        state.borrow_mut().signals.push_back(SignalRequest {
            call_id: call.call_id,
            kind,
            request,
            completion: None,
        });
        pump_signal_queue(state);
        Ok(Promise::resolve(&JsValue::UNDEFINED))
    };
    completion
}

fn queue_best_effort(
    state: &Rc<RefCell<OrchestratorState>>,
    call: ActiveCall,
    kind: SignalKind,
    sdp: Option<&str>,
    candidate: Option<JsValue>,
    reason: Option<&str>,
) {
    let Ok(payload) = signal_payload(&call.call_id, kind, sdp, candidate, reason) else {
        return;
    };
    let _ = enqueue_signal(state, call, kind, payload, false);
}

fn pump_signal_queue(state: &Rc<RefCell<OrchestratorState>>) {
    let start = {
        let mut inner = state.borrow_mut();
        if inner.sending_signals || inner.signals.is_empty() {
            false
        } else {
            inner.sending_signals = true;
            true
        }
    };
    if start {
        let state = Rc::clone(state);
        spawn_local(async move { pump_signal_queue_async(state).await });
    }
}

async fn pump_signal_queue_async(state: Rc<RefCell<OrchestratorState>>) {
    loop {
        let (entry, sender) = {
            let mut inner = state.borrow_mut();
            match inner.signals.pop_front() {
                Some(entry) => (entry, inner.send_signal.clone()),
                None => {
                    inner.sending_signals = false;
                    return;
                }
            }
        };
        let outcome = match sender.call1(&JsValue::UNDEFINED, &entry.request) {
            Ok(value) => match value.dyn_into::<Promise>() {
                Ok(promise) => JsFuture::from(promise).await,
                Err(_) => Err(call_error(
                    "callback_contract",
                    "send_signal(request) must return a Promise",
                )),
            },
            Err(error) => Err(error),
        };
        match outcome {
            Ok(_) => {
                if let Some((resolve, _)) = entry.completion {
                    let _ = resolve.call0(&JsValue::UNDEFINED);
                }
            }
            Err(error) => {
                if let Some((_, reject)) = entry.completion {
                    let _ = reject.call1(&JsValue::UNDEFINED, &error);
                }
                let callbacks = state.borrow().callbacks.clone();
                call_callback3(
                    &callbacks.signal_failed,
                    JsValue::from_str(&entry.call_id),
                    JsValue::from_str(entry.kind.as_str()),
                    error,
                );
            }
        }
    }
}

fn signal_request(call: &ActiveCall, kind: SignalKind, payload: JsValue) -> JsResult<JsValue> {
    let request = Object::new();
    set_property(
        &request,
        "peer_account_id",
        &JsValue::from_str(&call.peer_account_id),
    )?;
    set_property(
        &request,
        "conversation_id",
        &call
            .conversation_id
            .as_deref()
            .map(JsValue::from_str)
            .unwrap_or(JsValue::NULL),
    )?;
    set_property(
        &request,
        "envelope_type",
        &JsValue::from_f64(kind.envelope_type() as f64),
    )?;
    set_property(&request, "payload", &payload)?;
    Ok(request.into())
}

fn signal_payload(
    call_id: &str,
    kind: SignalKind,
    sdp: Option<&str>,
    candidate: Option<JsValue>,
    reason: Option<&str>,
) -> JsResult<JsValue> {
    let payload = Object::new();
    set_property(&payload, "call_id", &JsValue::from_str(call_id))?;
    set_property(&payload, "kind", &JsValue::from_str(kind.as_str()))?;
    set_property(
        &payload,
        "sdp",
        &sdp.map(JsValue::from_str).unwrap_or(JsValue::NULL),
    )?;
    set_property(&payload, "candidate", &candidate.unwrap_or(JsValue::NULL))?;
    set_property(
        &payload,
        "reason",
        &reason.map(JsValue::from_str).unwrap_or(JsValue::NULL),
    )?;
    Ok(payload.into())
}

fn open_local_signals(state: &Rc<RefCell<OrchestratorState>>, call_id: &str) -> JsResult<()> {
    let (call, candidates) = {
        let mut inner = state.borrow_mut();
        let Some(call) = inner.call.as_mut().filter(|call| call.call_id == call_id) else {
            return Err(call_error(
                "call_closed",
                "call ended before SDP signal was sent",
            ));
        };
        call.signals_open = true;
        let call = call.clone();
        let candidates = inner
            .call
            .as_mut()
            .map(|active| std::mem::take(&mut active.held_candidates))
            .unwrap_or_default();
        (call, candidates)
    };
    for candidate in candidates {
        let payload = signal_payload(&call.call_id, SignalKind::Ice, None, Some(candidate), None)?;
        let _ = enqueue_signal(state, call.clone(), SignalKind::Ice, payload, false)?;
    }
    Ok(())
}

fn set_phase(state: &Rc<RefCell<OrchestratorState>>, call_id: &str, phase: Phase) -> JsResult<()> {
    let (call, previous) = {
        let mut inner = state.borrow_mut();
        let Some(call) = inner.call.as_mut().filter(|call| call.call_id == call_id) else {
            return Err(call_error("call_closed", "no matching active call"));
        };
        let previous = call.phase;
        if previous == phase {
            return Ok(());
        }
        call.phase = phase;
        (call.clone(), previous)
    };
    let callbacks = state.borrow().callbacks.clone();
    call_callback2(
        &callbacks.phase_changed,
        call_descriptor(&call),
        JsValue::from_str(previous.as_str()),
    );
    Ok(())
}

fn emit_call_callback(state: &Rc<RefCell<OrchestratorState>>, outgoing: bool, call: &ActiveCall) {
    let callbacks = state.borrow().callbacks.clone();
    call_callback1(
        if outgoing {
            &callbacks.outgoing_call
        } else {
            &callbacks.incoming_call
        },
        call_descriptor(call),
    );
}

fn mark_recoverable_failure(state: &Rc<RefCell<OrchestratorState>>, call_id: &str, error: JsValue) {
    let call = {
        let mut inner = state.borrow_mut();
        let Some(call) = inner.call.as_mut().filter(|call| call.call_id == call_id) else {
            return;
        };
        call.failed = true;
        call.clone()
    };
    let callbacks = state.borrow().callbacks.clone();
    call_callback2(&callbacks.call_failed, call_descriptor(&call), error);
}

fn finish_call(state: &Rc<RefCell<OrchestratorState>>, call_id: &str, status: &str) {
    let (call, rtc) = {
        let mut inner = state.borrow_mut();
        if inner
            .call
            .as_ref()
            .is_none_or(|call| call.call_id != call_id)
        {
            return;
        }
        let call = inner.call.take().expect("active call checked above");
        if call.direction == Direction::Incoming {
            inner
                .finished_incoming
                .insert(call.call_id.clone(), Date::now());
            while inner.finished_incoming.len() > MAX_FINISHED_INCOMING {
                if let Some(oldest) = inner
                    .finished_incoming
                    .iter()
                    .min_by(|left, right| left.1.total_cmp(right.1))
                    .map(|(id, _)| id.clone())
                {
                    inner.finished_incoming.remove(&oldest);
                }
            }
        }
        (call, inner.rtc_manager.clone())
    };
    cancel_answer_timeout(state);
    let _ = rtc_call_sync(&rtc, "close_call", &[JsValue::from_str(call_id)]);
    let callbacks = state.borrow().callbacks.clone();
    call_callback2(
        &callbacks.call_ended,
        call_descriptor(&call),
        JsValue::from_str(status),
    );
}

fn local_end_status(call: &ActiveCall) -> &'static str {
    if call.failed {
        "failed"
    } else if call.connected {
        "completed"
    } else if call.phase == Phase::Incoming {
        "rejected"
    } else {
        "cancelled"
    }
}

fn current_call(state: &Rc<RefCell<OrchestratorState>>, call_id: &str) -> Option<ActiveCall> {
    state
        .borrow()
        .call
        .as_ref()
        .filter(|call| call.call_id == call_id)
        .cloned()
}

fn ensure_active(state: &Rc<RefCell<OrchestratorState>>, call_id: &str) -> JsResult<()> {
    if current_call(state, call_id).is_some() {
        Ok(())
    } else {
        Err(call_error(
            "call_closed",
            "call ended while an asynchronous operation was pending",
        ))
    }
}

fn install_answer_timeout(state: &Rc<RefCell<OrchestratorState>>, call_id: &str) -> JsResult<()> {
    let id = {
        let mut inner = state.borrow_mut();
        inner.next_timer_id = inner
            .next_timer_id
            .checked_add(1)
            .ok_or_else(|| call_error("runtime", "call timer id space exhausted"))?;
        inner.next_timer_id
    };
    let weak = Rc::downgrade(state);
    let call_id_owned = call_id.to_owned();
    let callback = Closure::<dyn FnMut()>::new(move || {
        if let Some(state) = weak.upgrade() {
            on_answer_timeout(&state, &call_id_owned, id);
        }
    });
    let window =
        web_sys::window().ok_or_else(|| call_error("runtime", "browser window is unavailable"))?;
    let handle = window
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            callback.as_ref().unchecked_ref(),
            INCOMING_TIMEOUT_MS,
        )
        .map_err(|error| js_error("runtime", "failed to schedule incoming call timeout", error))?;
    let mut inner = state.borrow_mut();
    inner.timer_callbacks.insert(id, callback);
    inner.active_timeout = Some(ActiveTimeout { id, handle });
    Ok(())
}

fn on_answer_timeout(state: &Rc<RefCell<OrchestratorState>>, call_id: &str, timer_id: u64) {
    let call = {
        let mut inner = state.borrow_mut();
        if inner
            .active_timeout
            .is_none_or(|timer| timer.id != timer_id)
        {
            return;
        }
        inner.active_timeout = None;
        inner
            .call
            .as_ref()
            .filter(|call| call.call_id == call_id && call.phase == Phase::Incoming)
            .cloned()
    };
    if let Some(call) = call {
        queue_best_effort(
            state,
            call.clone(),
            SignalKind::Reject,
            None,
            None,
            Some("timeout"),
        );
        finish_call(state, call_id, "missed");
    }
    release_timer_later(state, timer_id);
}

fn cancel_answer_timeout(state: &Rc<RefCell<OrchestratorState>>) {
    let timer = state.borrow_mut().active_timeout.take();
    if let Some(timer) = timer {
        if let Some(window) = web_sys::window() {
            window.clear_timeout_with_handle(timer.handle);
        }
        release_timer_later(state, timer.id);
    }
}

fn release_timer_later(state: &Rc<RefCell<OrchestratorState>>, timer_id: u64) {
    let state = Rc::clone(state);
    spawn_local(async move {
        let _ = JsFuture::from(Promise::resolve(&JsValue::UNDEFINED)).await;
        state.borrow_mut().timer_callbacks.remove(&timer_id);
    });
}

fn prune_finished_incoming(state: &Rc<RefCell<OrchestratorState>>) {
    let cutoff = Date::now() - FINISHED_INCOMING_RETENTION_MS;
    state
        .borrow_mut()
        .finished_incoming
        .retain(|_, finished_at| *finished_at >= cutoff);
}

async fn is_finished_incoming(state: &Rc<RefCell<OrchestratorState>>, call_id: &str) -> bool {
    let callback = {
        let inner = state.borrow();
        if inner.finished_incoming.contains_key(call_id) {
            return true;
        }
        inner.has_finished_incoming.clone()
    };
    let Some(callback) = callback else {
        return false;
    };
    let result = match callback.call1(&JsValue::UNDEFINED, &JsValue::from_str(call_id)) {
        Ok(value) => JsFuture::from(Promise::resolve(&value)).await,
        Err(_) => return false,
    };
    result
        .ok()
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

fn call_descriptor(call: &ActiveCall) -> JsValue {
    let value = Object::new();
    let _ = set_property(&value, "call_id", &JsValue::from_str(&call.call_id));
    let _ = set_property(
        &value,
        "peer_account_id",
        &JsValue::from_str(&call.peer_account_id),
    );
    let _ = set_property(
        &value,
        "conversation_id",
        &call
            .conversation_id
            .as_deref()
            .map(JsValue::from_str)
            .unwrap_or(JsValue::NULL),
    );
    let _ = set_property(
        &value,
        "direction",
        &JsValue::from_str(call.direction.as_str()),
    );
    let _ = set_property(&value, "phase", &JsValue::from_str(call.phase.as_str()));
    let _ = set_property(&value, "with_video", &JsValue::from_bool(call.with_video));
    let _ = set_property(
        &value,
        "started_at",
        &JsValue::from_f64(call.started_at as f64),
    );
    let _ = set_property(&value, "connected", &JsValue::from_bool(call.connected));
    let _ = set_property(
        &value,
        "connected_at",
        &call
            .connected_at
            .map(|value| JsValue::from_f64(value as f64))
            .unwrap_or(JsValue::NULL),
    );
    let _ = set_property(&value, "failed", &JsValue::from_bool(call.failed));
    let _ = set_property(
        &value,
        "pending_offer_sdp",
        &call
            .pending_offer_sdp
            .as_deref()
            .map(JsValue::from_str)
            .unwrap_or(JsValue::NULL),
    );
    value.into()
}

fn offer_has_video(sdp: &str) -> bool {
    sdp.lines().any(|line| line.starts_with("m=video "))
}

fn candidate_is_valid(candidate: &JsValue) -> bool {
    if !candidate.is_object() || candidate.is_null() {
        return false;
    }
    get_property(candidate, "candidate")
        .ok()
        .and_then(|value| value.as_string())
        .is_some_and(|candidate| !candidate.is_empty())
}

fn uuid_v7() -> String {
    let mut bytes = [0_u8; 16];
    let mut random = rand::rng();
    random.fill_bytes(&mut bytes);
    let timestamp = Date::now().max(0.0) as u64;
    for (index, shift) in (0..6).rev().enumerate() {
        bytes[index] = ((timestamp >> (shift * 8)) & 0xff) as u8;
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn now_seconds() -> u64 {
    (Date::now().max(0.0) / 1_000.0) as u64
}

fn get_function(target: &JsValue, name: &str) -> JsResult<Function> {
    get_property(target, name)?
        .dyn_into::<Function>()
        .map_err(|_| {
            call_error(
                "integration",
                format!("required function {name} is missing"),
            )
        })
}

fn get_property(target: &JsValue, name: &str) -> JsResult<JsValue> {
    Reflect::get(target, &JsValue::from_str(name))
}

fn set_property(target: &Object, name: &str, value: &JsValue) -> JsResult<()> {
    Reflect::set(target, &JsValue::from_str(name), value).map(|_| ())
}

fn call_callback1(callback: &Option<Function>, arg: JsValue) {
    if let Some(callback) = callback {
        let _ = callback.call1(&JsValue::UNDEFINED, &arg);
    }
}

fn call_callback2(callback: &Option<Function>, first: JsValue, second: JsValue) {
    if let Some(callback) = callback {
        let _ = callback.call2(&JsValue::UNDEFINED, &first, &second);
    }
}

fn call_callback3(callback: &Option<Function>, first: JsValue, second: JsValue, third: JsValue) {
    if let Some(callback) = callback {
        let _ = callback.call3(&JsValue::UNDEFINED, &first, &second, &third);
    }
}

fn call_error(code: &str, message: impl AsRef<str>) -> JsValue {
    let error = JsError::new(message.as_ref());
    let _ = Reflect::set(
        error.as_ref(),
        &JsValue::from_str("code"),
        &JsValue::from_str(code),
    );
    error.into()
}

fn js_error(code: &str, prefix: &str, cause: JsValue) -> JsValue {
    let message = cause
        .as_string()
        .or_else(|| {
            get_property(&cause, "message")
                .ok()
                .and_then(|value| value.as_string())
        })
        .unwrap_or_else(|| "unknown browser error".to_owned());
    call_error(code, format!("{prefix}: {message}"))
}

fn rtc_call_sync(rtc: &JsValue, method_name: &str, arguments: &[JsValue]) -> JsResult<JsValue> {
    let method = get_function(rtc, method_name)?;
    let args = Array::new();
    for value in arguments {
        args.push(value);
    }
    method.apply(rtc, &args)
}

#[cfg(test)]
mod tests {
    use super::SignalKind;

    #[test]
    fn signal_kinds_keep_the_web_envelope_mapping() {
        assert_eq!(SignalKind::Offer.envelope_type(), 10);
        assert_eq!(SignalKind::Answer.envelope_type(), 11);
        assert_eq!(SignalKind::Ice.envelope_type(), 12);
        assert_eq!(SignalKind::Hangup.envelope_type(), 13);
        assert_eq!(SignalKind::Reject.envelope_type(), 14);
    }

    #[test]
    fn video_offer_detection_matches_the_web_sdp_rule() {
        assert!(super::offer_has_video(
            "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
        ));
        assert!(!super::offer_has_video(
            "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
        ));
    }
}
