//! Browser WebRTC sessions used by the FriendsHub web client.
//!
//! This module intentionally drives the browser's own `RTCPeerConnection` and
//! `MediaStream` objects. The native `webrtc` crate is not available in a
//! browser build, and sending manually encoded frames would not match the web
//! client's `getUserMedia`/`MediaStreamTrack` contract.
//!
//! Signalling remains outside this module: callers send returned SDP and ICE
//! candidates through the existing Signal-encrypted envelope path. This module
//! never emits or consumes the protobuf `CallSignal` frame.

use js_sys::{Array, Function, Object, Promise, Reflect};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

const MAX_PRE_SESSION_CANDIDATES: usize = 256;
const MAX_PRE_SESSION_CALLS: usize = 16;
const MAX_PRE_SESSION_CANDIDATE_TOTAL: usize = 256;
const MAX_CANDIDATE_BYTES: usize = 16 * 1024;

type CallRef = Rc<RefCell<ManagedCall>>;
type EventClosure = Closure<dyn FnMut(JsValue)>;

#[derive(Clone, Default)]
struct BrowserRtcCallbacks {
    local_stream: Option<Function>,
    remote_stream: Option<Function>,
    ice_candidate: Option<Function>,
    connected: Option<Function>,
    failed: Option<Function>,
    remote_video: Option<Function>,
}

#[derive(Default)]
struct ManagerState {
    calls: HashMap<String, CallRef>,
    candidates_before_call: CandidateQueues<JsValue>,
    starting: StartRegistry,
}

struct ManagedCall {
    call_id: String,
    peer_connection: JsValue,
    local_stream: JsValue,
    remote_stream: JsValue,
    pending_candidates: CandidateQueue<JsValue>,
    remote_description_set: bool,
    closed: bool,
    switching_camera: bool,
    connected_emitted: bool,
    failed_emitted: bool,
    event_handlers: Vec<EventClosure>,
}

/// FIFO for candidates that must wait until a remote description exists.
/// Kept generic so its ordering and bounds can be tested without a JS runtime.
struct CandidateQueue<T> {
    values: VecDeque<T>,
}

impl<T> Default for CandidateQueue<T> {
    fn default() -> Self {
        Self {
            values: VecDeque::new(),
        }
    }
}

impl<T> CandidateQueue<T> {
    fn push(&mut self, value: T) -> Result<(), QueueFull> {
        if self.values.len() >= MAX_PRE_SESSION_CANDIDATES {
            return Err(QueueFull);
        }
        self.values.push_back(value);
        Ok(())
    }

    fn pop(&mut self) -> Option<T> {
        self.values.pop_front()
    }

    fn len(&self) -> usize {
        self.values.len()
    }

    fn extend(&mut self, other: Self) -> Result<(), QueueFull> {
        if self.values.len().saturating_add(other.values.len()) > MAX_PRE_SESSION_CANDIDATES {
            return Err(QueueFull);
        }
        self.values.extend(other.values);
        Ok(())
    }

    fn clear(&mut self) {
        self.values.clear();
    }
}

#[derive(Clone, Copy, Debug)]
struct QueueFull;

/// Bounded map for ICE that arrives before the offer/answer creates a call.
#[derive(Default)]
struct CandidateQueues<T> {
    by_call: HashMap<String, CandidateQueue<T>>,
    total_candidates: usize,
}

impl<T> CandidateQueues<T> {
    fn push(&mut self, call_id: &str, value: T) -> Result<(), QueueFull> {
        if self.total_candidates >= MAX_PRE_SESSION_CANDIDATE_TOTAL {
            return Err(QueueFull);
        }
        if !self.by_call.contains_key(call_id) && self.by_call.len() >= MAX_PRE_SESSION_CALLS {
            return Err(QueueFull);
        }
        self.by_call
            .entry(call_id.to_owned())
            .or_default()
            .push(value)?;
        self.total_candidates += 1;
        Ok(())
    }

    fn take(&mut self, call_id: &str) -> Option<CandidateQueue<T>> {
        let queue = self.by_call.remove(call_id)?;
        self.total_candidates = self.total_candidates.saturating_sub(queue.len());
        Some(queue)
    }

    fn remove(&mut self, call_id: &str) {
        if let Some(queue) = self.by_call.remove(call_id) {
            self.total_candidates = self.total_candidates.saturating_sub(queue.len());
        }
    }

    fn clear(&mut self) {
        self.by_call.clear();
        self.total_candidates = 0;
    }
}

/// Tracks async media-permission requests so a late permission result cannot
/// resurrect a call that was closed while the browser prompt was open.
#[derive(Default)]
struct StartRegistry {
    generations: HashMap<String, u64>,
    next_generation: u64,
}

impl StartRegistry {
    fn reserve(&mut self, call_id: &str) -> Result<u64, StartRegistryError> {
        if self.generations.contains_key(call_id) {
            return Err(StartRegistryError::AlreadyStarting);
        }
        let generation = self
            .next_generation
            .checked_add(1)
            .ok_or(StartRegistryError::GenerationOverflow)?;
        self.next_generation = generation;
        self.generations.insert(call_id.to_owned(), generation);
        Ok(generation)
    }

    fn is_current(&self, call_id: &str, generation: u64) -> bool {
        self.generations.get(call_id) == Some(&generation)
    }

    fn finish(&mut self, call_id: &str, generation: u64) -> bool {
        if self.is_current(call_id, generation) {
            self.generations.remove(call_id);
            true
        } else {
            false
        }
    }

    fn cancel(&mut self, call_id: &str) {
        self.generations.remove(call_id);
    }

    fn clear(&mut self) {
        self.generations.clear();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartRegistryError {
    AlreadyStarting,
    GenerationOverflow,
}

/// Owns browser peer connections and their media tracks.
///
/// Keep one manager for the browser runtime. Calls are looked up by `call_id`,
/// so the application does not own peer-connection or track cleanup. The only
/// browser objects exposed to the application are stream references needed to
/// attach previews and remote audio/video to HTML media elements.
#[wasm_bindgen]
pub struct BrowserRtcManager {
    state: Rc<RefCell<ManagerState>>,
    callbacks: Rc<RefCell<BrowserRtcCallbacks>>,
}

#[wasm_bindgen]
impl BrowserRtcManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> BrowserRtcManager {
        Self {
            state: Rc::new(RefCell::new(ManagerState::default())),
            callbacks: Rc::new(RefCell::new(BrowserRtcCallbacks::default())),
        }
    }

    /// Registers the callback for a newly acquired local `MediaStream`.
    /// The callback receives `(call_id, stream)`.
    pub fn set_on_local_stream(&self, callback: Option<Function>) {
        self.callbacks.borrow_mut().local_stream = callback;
    }

    /// Registers the callback for the accumulated remote `MediaStream`.
    /// The callback receives `(call_id, stream)`.
    pub fn set_on_remote_stream(&self, callback: Option<Function>) {
        self.callbacks.borrow_mut().remote_stream = callback;
    }

    /// Registers the callback for each locally gathered ICE candidate.
    /// The candidate is the browser's `RTCIceCandidateInit` JSON object.
    pub fn set_on_ice_candidate(&self, callback: Option<Function>) {
        self.callbacks.borrow_mut().ice_candidate = callback;
    }

    /// Registers the callback fired when the media connection reaches
    /// `connectionState == "connected"`. It receives `call_id`.
    pub fn set_on_connected(&self, callback: Option<Function>) {
        self.callbacks.borrow_mut().connected = callback;
    }

    /// Registers the callback fired once when ICE or connection state fails.
    /// It receives `(call_id, detail)`.
    pub fn set_on_failed(&self, callback: Option<Function>) {
        self.callbacks.borrow_mut().failed = callback;
    }

    /// Registers the callback fired when a remote video track arrives.
    /// It receives `call_id`.
    pub fn set_on_remote_video(&self, callback: Option<Function>) {
        self.callbacks.borrow_mut().remote_video = callback;
    }

    /// Acquires local audio and optional front-camera video, adds every track
    /// before creating the offer, and returns the local SDP. Local ICE
    /// candidates are emitted separately through `set_on_ice_candidate`.
    pub async fn create_offer(
        &self,
        call_id: String,
        ice_servers: JsValue,
        with_video: bool,
    ) -> Result<String, JsValue> {
        let generation = self.reserve_call(&call_id)?;
        let local_stream = match acquire_local_media(with_video).await {
            Ok(stream) => stream,
            Err(error) => {
                self.cancel_start(&call_id, generation);
                return Err(error);
            }
        };
        if !self.is_starting(&call_id, generation) {
            stop_stream(&local_stream);
            return Err(rtc_error(
                "call_closed",
                "Call ended during media permission request",
            ));
        }

        let call = match self.make_call(&call_id, &ice_servers, local_stream.clone()) {
            Ok(call) => call,
            Err(error) => {
                stop_stream(&local_stream);
                self.cancel_start(&call_id, generation);
                return Err(error);
            }
        };
        if !self.activate_call(&call_id, generation, call.clone()) {
            close_call_state(&call);
            stop_stream(&local_stream);
            return Err(rtc_error(
                "call_closed",
                "Call was closed before negotiation started",
            ));
        }

        emit_stream(
            &self.callbacks,
            CallbackKind::LocalStream,
            &call_id,
            &local_stream,
        );

        let result = async {
            let peer_connection = call.borrow().peer_connection.clone();
            let offer = await_method(&peer_connection, "createOffer", &[]).await?;
            await_method(&peer_connection, "setLocalDescription", &[offer]).await?;
            ensure_call_open(&call)?;
            local_sdp(&peer_connection)
        }
        .await;

        if result.is_err() {
            self.remove_call_if_same(&call_id, &call);
            close_call_state(&call);
        }
        result
    }

    /// Acquires media matching the incoming offer, installs the offer, drains
    /// any queued ICE candidates, creates an answer, and returns its local SDP.
    /// Video is acquired only when the remote SDP contains a video m-line.
    pub async fn accept_offer(
        &self,
        call_id: String,
        ice_servers: JsValue,
        remote_sdp: String,
    ) -> Result<String, JsValue> {
        validate_sdp(&remote_sdp)?;
        let generation = self.reserve_call(&call_id)?;
        let with_video = offer_has_video(&remote_sdp);
        let local_stream = match acquire_local_media(with_video).await {
            Ok(stream) => stream,
            Err(error) => {
                self.cancel_start(&call_id, generation);
                return Err(error);
            }
        };
        if !self.is_starting(&call_id, generation) {
            stop_stream(&local_stream);
            return Err(rtc_error(
                "call_closed",
                "Call ended during media permission request",
            ));
        }

        let call = match self.make_call(&call_id, &ice_servers, local_stream.clone()) {
            Ok(call) => call,
            Err(error) => {
                stop_stream(&local_stream);
                self.cancel_start(&call_id, generation);
                return Err(error);
            }
        };
        if !self.activate_call(&call_id, generation, call.clone()) {
            close_call_state(&call);
            stop_stream(&local_stream);
            return Err(rtc_error(
                "call_closed",
                "Call was closed before negotiation started",
            ));
        }

        emit_stream(
            &self.callbacks,
            CallbackKind::LocalStream,
            &call_id,
            &local_stream,
        );

        let result = async {
            let peer_connection = call.borrow().peer_connection.clone();
            let description = session_description("offer", &remote_sdp)?;
            await_method(&peer_connection, "setRemoteDescription", &[description]).await?;
            mark_remote_description_set(&call)?;
            drain_remote_candidates(&call).await?;

            let answer = await_method(&peer_connection, "createAnswer", &[]).await?;
            await_method(&peer_connection, "setLocalDescription", &[answer]).await?;
            ensure_call_open(&call)?;
            local_sdp(&peer_connection)
        }
        .await;

        if result.is_err() {
            self.remove_call_if_same(&call_id, &call);
            close_call_state(&call);
        }
        result
    }

    /// Applies the peer's answer and then applies queued remote ICE candidates.
    pub async fn accept_answer(&self, call_id: String, remote_sdp: String) -> Result<(), JsValue> {
        validate_sdp(&remote_sdp)?;
        let call = self.get_call(&call_id)?;
        let peer_connection = call.borrow().peer_connection.clone();
        let description = session_description("answer", &remote_sdp)?;
        await_method(&peer_connection, "setRemoteDescription", &[description]).await?;
        mark_remote_description_set(&call)?;
        drain_remote_candidates(&call).await
    }

    /// Adds a remote ICE candidate. Candidates received before the call object
    /// exists, or before its remote SDP is installed, are queued and drained in
    /// arrival order after `accept_offer`/`accept_answer`.
    pub async fn add_remote_candidate(
        &self,
        call_id: String,
        candidate: JsValue,
    ) -> Result<(), JsValue> {
        validate_call_id(&call_id)?;
        validate_candidate(&candidate)?;
        let call = self.state.borrow().calls.get(&call_id).cloned();
        let Some(call) = call else {
            let mut state = self.state.borrow_mut();
            if state
                .candidates_before_call
                .push(&call_id, candidate)
                .is_err()
            {
                return Err(rtc_error(
                    "candidate_queue_full",
                    "Too many ICE candidates or calls arrived before a peer connection was created",
                ));
            }
            return Ok(());
        };

        let (peer_connection, remote_is_set, closed) = {
            let mut state = call.borrow_mut();
            if state.closed {
                return Ok(());
            }
            if !state.remote_description_set {
                if state.pending_candidates.push(candidate).is_err() {
                    return Err(rtc_error(
                        "candidate_queue_full",
                        "Too many ICE candidates arrived before the remote description",
                    ));
                }
                return Ok(());
            }
            (
                state.peer_connection.clone(),
                state.remote_description_set,
                state.closed,
            )
        };
        if closed || !remote_is_set {
            return Ok(());
        }
        await_method(&peer_connection, "addIceCandidate", &[candidate]).await?;
        Ok(())
    }

    /// Mutes or unmutes every local microphone track. Returns whether at least
    /// one local audio track was present.
    pub fn set_audio_enabled(&self, call_id: String, enabled: bool) -> Result<bool, JsValue> {
        self.set_local_track_enabled(&call_id, "audio", enabled)
    }

    /// Enables or disables every local camera track without stopping capture.
    pub fn set_video_enabled(&self, call_id: String, enabled: bool) -> Result<bool, JsValue> {
        self.set_local_track_enabled(&call_id, "video", enabled)
    }

    /// Switches to the next enumerated camera, replaces the sender track without
    /// renegotiation, updates the preview stream, and releases the previous
    /// camera track. Returns `false` when there is no second usable camera.
    pub async fn switch_camera(&self, call_id: String) -> Result<bool, JsValue> {
        let call = self.get_call(&call_id)?;
        let (local_stream, peer_connection, old_track) = {
            let mut state = call.borrow_mut();
            ensure_call_open_ref(&state)?;
            if state.switching_camera {
                return Ok(false);
            }
            let tracks = stream_tracks(&state.local_stream, Some("video"))?;
            let Some(track) = tracks.first() else {
                return Ok(false);
            };
            state.switching_camera = true;
            (
                state.local_stream.clone(),
                state.peer_connection.clone(),
                track.clone(),
            )
        };
        let _switch_guard = CameraSwitchGuard { call: call.clone() };

        let devices_api = media_devices()?;
        let devices = await_method(&devices_api, "enumerateDevices", &[]).await?;
        let devices = devices
            .dyn_into::<Array>()
            .map_err(|_| rtc_error("runtime", "enumerateDevices returned a non-array value"))?;
        let mut cameras = Vec::new();
        for index in 0..devices.length() {
            let device = devices.get(index);
            if get_property(&device, "kind")?.as_string().as_deref() == Some("videoinput") {
                cameras.push(device);
            }
        }
        if cameras.len() <= 1 {
            return Ok(false);
        }

        let current_device_id = get_property(&old_track, "getSettings")
            .and_then(|method| {
                method.dyn_into::<Function>().map_err(|_| {
                    rtc_error("runtime", "MediaStreamTrack.getSettings is not callable")
                })
            })?
            .call0(&old_track)
            .and_then(|settings| get_property(&settings, "deviceId"))
            .ok()
            .and_then(|value| value.as_string());
        let current_index = cameras.iter().position(|camera| {
            get_property(camera, "deviceId")
                .ok()
                .and_then(|value| value.as_string())
                == current_device_id
        });
        let next_index = current_index.map_or(0, |index| (index + 1) % cameras.len());
        let Some(next_device) = cameras.get(next_index) else {
            return Ok(false);
        };
        let Some(device_id) = get_property(next_device, "deviceId")?.as_string() else {
            return Ok(false);
        };

        let constraints = Object::new();
        let video = Object::new();
        let exact_device = Object::new();
        set_property(&exact_device, "exact", &JsValue::from_str(&device_id))?;
        set_property(&video, "deviceId", exact_device.as_ref())?;
        set_property(&constraints, "video", video.as_ref())?;
        let devices_api = media_devices()?;
        let replacement_stream =
            await_method(&devices_api, "getUserMedia", &[constraints.into()]).await?;
        let mut replacement_stream = StopStreamOnDrop::new(replacement_stream);
        let replacement_tracks = stream_tracks(replacement_stream.stream(), Some("video"))?;
        let Some(replacement_track) = replacement_tracks.first().cloned() else {
            return Ok(false);
        };

        let enabled = match get_property(&old_track, "enabled") {
            Ok(value) => value.as_bool().unwrap_or(true),
            Err(error) => return Err(error),
        };
        set_property(&replacement_track, "enabled", &JsValue::from_bool(enabled))?;
        let sender = match video_sender(&peer_connection) {
            Ok(Some(sender)) => sender,
            Ok(None) => return Ok(false),
            Err(error) => return Err(error),
        };
        if let Err(error) =
            await_method(&sender, "replaceTrack", &[replacement_track.clone()]).await
        {
            return Err(error);
        }
        if call.borrow().closed {
            return Ok(false);
        }

        let audio_tracks = match stream_tracks(&local_stream, Some("audio")) {
            Ok(tracks) => tracks,
            Err(error) => {
                let _ = await_method(&sender, "replaceTrack", &[old_track.clone()]).await;
                return Err(error);
            }
        };
        let mut new_tracks = audio_tracks;
        new_tracks.push(replacement_track.clone());
        let new_local_stream = match new_media_stream(&new_tracks) {
            Ok(stream) => stream,
            Err(error) => {
                let _ = await_method(&sender, "replaceTrack", &[old_track.clone()]).await;
                return Err(error);
            }
        };

        let closed_during_switch = {
            let mut state = call.borrow_mut();
            if state.closed {
                true
            } else {
                state.local_stream = new_local_stream.clone();
                false
            }
        };
        if closed_during_switch {
            let _ = await_method(&sender, "replaceTrack", &[old_track.clone()]).await;
            return Ok(false);
        }
        replacement_stream.disarm();
        let _ = call_method(&old_track, "stop", &[]);
        emit_stream(
            &self.callbacks,
            CallbackKind::LocalStream,
            &call_id,
            &new_local_stream,
        );
        Ok(true)
    }

    /// Returns the current local stream reference for a preview element.
    pub fn local_stream(&self, call_id: String) -> Result<JsValue, JsValue> {
        Ok(self.get_call(&call_id)?.borrow().local_stream.clone())
    }

    /// Returns the current accumulated remote stream reference for a media
    /// element. It is empty until the peer sends its first track.
    pub fn remote_stream(&self, call_id: String) -> Result<JsValue, JsValue> {
        Ok(self.get_call(&call_id)?.borrow().remote_stream.clone())
    }

    /// Closes the peer connection, stops local and remote tracks, clears queued
    /// candidates, and detaches the registered browser event closures. Their
    /// Rust storage is released after any callback currently on the stack exits.
    pub fn close_call(&self, call_id: String) -> Result<(), JsValue> {
        validate_call_id(&call_id)?;
        let call = {
            let mut state = self.state.borrow_mut();
            state.starting.cancel(&call_id);
            state.candidates_before_call.remove(&call_id);
            state.calls.remove(&call_id)
        };
        if let Some(call) = call {
            close_call_state(&call);
        }
        Ok(())
    }
}

impl Drop for BrowserRtcManager {
    fn drop(&mut self) {
        let calls = {
            let mut state = self.state.borrow_mut();
            state.starting.clear();
            state.candidates_before_call.clear();
            std::mem::take(&mut state.calls)
        };
        for call in calls.into_values() {
            close_call_state(&call);
        }
    }
}

impl BrowserRtcManager {
    fn reserve_call(&self, call_id: &str) -> Result<u64, JsValue> {
        validate_call_id(call_id)?;
        let mut state = self.state.borrow_mut();
        if state.calls.contains_key(call_id) || state.starting.generations.contains_key(call_id) {
            return Err(rtc_error(
                "call_exists",
                "A peer connection already exists for this call_id",
            ));
        }
        state
            .starting
            .reserve(call_id)
            .map_err(|error| match error {
                StartRegistryError::AlreadyStarting => rtc_error(
                    "call_exists",
                    "A peer connection is already starting for this call_id",
                ),
                StartRegistryError::GenerationOverflow => {
                    rtc_error("runtime", "Call generation counter overflowed")
                }
            })
    }

    fn is_starting(&self, call_id: &str, generation: u64) -> bool {
        self.state.borrow().starting.is_current(call_id, generation)
    }

    fn cancel_start(&self, call_id: &str, generation: u64) {
        let mut state = self.state.borrow_mut();
        state.starting.finish(call_id, generation);
    }

    fn activate_call(&self, call_id: &str, generation: u64, call: CallRef) -> bool {
        let mut state = self.state.borrow_mut();
        if !state.starting.finish(call_id, generation) {
            return false;
        }
        if let Some(candidates) = state.candidates_before_call.take(call_id)
            && call
                .borrow_mut()
                .pending_candidates
                .extend(candidates)
                .is_err()
        {
            return false;
        }
        state.calls.insert(call_id.to_string(), call);
        true
    }

    fn get_call(&self, call_id: &str) -> Result<CallRef, JsValue> {
        validate_call_id(call_id)?;
        self.state
            .borrow()
            .calls
            .get(call_id)
            .cloned()
            .ok_or_else(|| rtc_error("unknown_call", "No active peer connection for call_id"))
    }

    fn remove_call_if_same(&self, call_id: &str, expected: &CallRef) {
        let mut state = self.state.borrow_mut();
        if state
            .calls
            .get(call_id)
            .is_some_and(|actual| Rc::ptr_eq(actual, expected))
        {
            state.calls.remove(call_id);
            state.candidates_before_call.remove(call_id);
        }
    }

    fn set_local_track_enabled(
        &self,
        call_id: &str,
        kind: &str,
        enabled: bool,
    ) -> Result<bool, JsValue> {
        let call = self.get_call(call_id)?;
        ensure_call_open_ref(&call.borrow())?;
        let local_stream = call.borrow().local_stream.clone();
        let tracks = stream_tracks(&local_stream, Some(kind))?;
        for track in &tracks {
            set_property(track, "enabled", &JsValue::from_bool(enabled))?;
        }
        Ok(!tracks.is_empty())
    }

    fn make_call(
        &self,
        call_id: &str,
        ice_servers: &JsValue,
        local_stream: JsValue,
    ) -> Result<CallRef, JsValue> {
        if !Array::is_array(ice_servers) {
            return Err(rtc_error(
                "invalid_ice_servers",
                "ice_servers must be an array",
            ));
        }
        let configuration = Object::new();
        set_property(&configuration, "iceServers", ice_servers)?;
        set_property(
            &configuration,
            "bundlePolicy",
            &JsValue::from_str("max-bundle"),
        )?;
        let peer_connection = construct_global("RTCPeerConnection", &[configuration.into()])?;
        let local_tracks = match stream_tracks(&local_stream, None) {
            Ok(tracks) => tracks,
            Err(error) => {
                let _ = call_method(&peer_connection, "close", &[]);
                return Err(error);
            }
        };
        for track in &local_tracks {
            if let Err(error) = call_method(
                &peer_connection,
                "addTrack",
                &[track.clone(), local_stream.clone()],
            ) {
                let _ = call_method(&peer_connection, "close", &[]);
                return Err(error);
            }
        }
        let remote_stream = match construct_global("MediaStream", &[]) {
            Ok(stream) => stream,
            Err(error) => {
                let _ = call_method(&peer_connection, "close", &[]);
                return Err(error);
            }
        };
        let call = Rc::new(RefCell::new(ManagedCall {
            call_id: call_id.to_string(),
            peer_connection,
            local_stream,
            remote_stream,
            pending_candidates: CandidateQueue::default(),
            remote_description_set: false,
            closed: false,
            switching_camera: false,
            connected_emitted: false,
            failed_emitted: false,
            event_handlers: Vec::new(),
        }));
        if let Err(error) = install_event_handlers(&call, &self.callbacks) {
            close_call_state(&call);
            return Err(error);
        }
        Ok(call)
    }
}

enum CallbackKind {
    LocalStream,
    RemoteStream,
}

fn emit_stream(
    callbacks: &Rc<RefCell<BrowserRtcCallbacks>>,
    kind: CallbackKind,
    call_id: &str,
    stream: &JsValue,
) {
    let callback = {
        let callbacks = callbacks.borrow();
        match kind {
            CallbackKind::LocalStream => callbacks.local_stream.clone(),
            CallbackKind::RemoteStream => callbacks.remote_stream.clone(),
        }
    };
    if let Some(callback) = callback {
        let _ = callback.call2(&JsValue::NULL, &JsValue::from_str(call_id), stream);
    }
}

fn emit_simple(callback: Option<Function>, call_id: &str) {
    if let Some(callback) = callback {
        let _ = callback.call1(&JsValue::NULL, &JsValue::from_str(call_id));
    }
}

fn emit_failed(callbacks: &Rc<RefCell<BrowserRtcCallbacks>>, call_id: &str, detail: &str) {
    let callback = callbacks.borrow().failed.clone();
    if let Some(callback) = callback {
        let _ = callback.call2(
            &JsValue::NULL,
            &JsValue::from_str(call_id),
            &JsValue::from_str(detail),
        );
    }
}

fn install_event_handlers(
    call: &CallRef,
    callbacks: &Rc<RefCell<BrowserRtcCallbacks>>,
) -> Result<(), JsValue> {
    let weak_call = Rc::downgrade(call);
    let callback_set = Rc::clone(callbacks);
    let call_id = call.borrow().call_id.clone();
    let ice_handler = Closure::wrap(Box::new(move |event: JsValue| {
        let Some(call) = weak_call.upgrade() else {
            return;
        };
        if call.borrow().closed {
            return;
        }
        let Ok(candidate) = get_property(&event, "candidate") else {
            return;
        };
        if candidate.is_null() || candidate.is_undefined() {
            return;
        }
        let Some(candidate_json) = candidate_init(&candidate) else {
            return;
        };
        let callback = callback_set.borrow().ice_candidate.clone();
        if let Some(callback) = callback {
            let _ = callback.call2(
                &JsValue::NULL,
                &JsValue::from_str(&call_id),
                &candidate_json,
            );
        }
    }) as Box<dyn FnMut(JsValue)>);

    let weak_call = Rc::downgrade(call);
    let callback_set = Rc::clone(callbacks);
    let call_id = call.borrow().call_id.clone();
    let track_handler = Closure::wrap(Box::new(move |event: JsValue| {
        let Some(call) = weak_call.upgrade() else {
            return;
        };
        let (stream, track, closed) = {
            let state = call.borrow();
            (
                state.remote_stream.clone(),
                get_property(&event, "track").ok(),
                state.closed,
            )
        };
        let Some(track) = track else { return };
        if closed {
            return;
        }
        let Ok(tracks) = call_method(&stream, "getTracks", &[]).and_then(|value| {
            value.dyn_into::<Array>().map_err(|_| {
                rtc_error(
                    "runtime",
                    "MediaStream.getTracks returned a non-array value",
                )
            })
        }) else {
            return;
        };
        let present = get_property(&tracks.clone().into(), "includes")
            .ok()
            .and_then(|method| method.dyn_into::<Function>().ok())
            .and_then(|method| method.call1(&tracks, &track).ok())
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        if !present && call_method(&stream, "addTrack", &[track.clone()]).is_err() {
            return;
        }

        emit_stream(&callback_set, CallbackKind::RemoteStream, &call_id, &stream);
        if get_property(&track, "kind")
            .ok()
            .and_then(|value| value.as_string())
            .as_deref()
            == Some("video")
        {
            emit_simple(callback_set.borrow().remote_video.clone(), &call_id);
        }
    }) as Box<dyn FnMut(JsValue)>);

    let weak_call = Rc::downgrade(call);
    let callback_set = Rc::clone(callbacks);
    let call_id = call.borrow().call_id.clone();
    let connection_handler = Closure::wrap(Box::new(move |_event: JsValue| {
        let Some(call) = weak_call.upgrade() else {
            return;
        };
        let (state, closed, emit_connected, should_emit_failed) = {
            let mut state = call.borrow_mut();
            let connection_state = get_property(&state.peer_connection, "connectionState")
                .ok()
                .and_then(|value| value.as_string())
                .unwrap_or_default();
            let connected = connection_state == "connected" && !state.connected_emitted;
            let failed = connection_state == "failed" && !state.failed_emitted;
            if connected {
                state.connected_emitted = true;
            }
            if failed {
                state.failed_emitted = true;
            }
            (connection_state, state.closed, connected, failed)
        };
        if closed {
            return;
        }
        if emit_connected {
            emit_simple(callback_set.borrow().connected.clone(), &call_id);
        }
        if should_emit_failed {
            emit_failed(
                &callback_set,
                &call_id,
                &format!("connection_state_{state}"),
            );
        }
    }) as Box<dyn FnMut(JsValue)>);

    let weak_call = Rc::downgrade(call);
    let callback_set = Rc::clone(callbacks);
    let call_id = call.borrow().call_id.clone();
    let ice_state_handler = Closure::wrap(Box::new(move |_event: JsValue| {
        let Some(call) = weak_call.upgrade() else {
            return;
        };
        let should_emit = {
            let mut state = call.borrow_mut();
            let ice_state = get_property(&state.peer_connection, "iceConnectionState")
                .ok()
                .and_then(|value| value.as_string())
                .unwrap_or_default();
            let failed = ice_state == "failed" && !state.failed_emitted && !state.closed;
            if failed {
                state.failed_emitted = true;
            }
            failed
        };
        if should_emit {
            emit_failed(&callback_set, &call_id, "ice_connection_failed");
        }
    }) as Box<dyn FnMut(JsValue)>);

    let peer_connection = call.borrow().peer_connection.clone();
    call.borrow_mut().event_handlers.extend([
        ice_handler,
        track_handler,
        connection_handler,
        ice_state_handler,
    ]);
    let handlers = call.borrow();
    set_property(
        &peer_connection,
        "onicecandidate",
        handlers.event_handlers[0].as_ref(),
    )?;
    set_property(
        &peer_connection,
        "ontrack",
        handlers.event_handlers[1].as_ref(),
    )?;
    set_property(
        &peer_connection,
        "onconnectionstatechange",
        handlers.event_handlers[2].as_ref(),
    )?;
    set_property(
        &peer_connection,
        "oniceconnectionstatechange",
        handlers.event_handlers[3].as_ref(),
    )?;
    Ok(())
}

struct CameraSwitchGuard {
    call: CallRef,
}

impl Drop for CameraSwitchGuard {
    fn drop(&mut self) {
        self.call.borrow_mut().switching_camera = false;
    }
}

struct StopStreamOnDrop {
    stream: JsValue,
    should_stop: bool,
}

impl StopStreamOnDrop {
    fn new(stream: JsValue) -> Self {
        Self {
            stream,
            should_stop: true,
        }
    }

    fn stream(&self) -> &JsValue {
        &self.stream
    }

    fn disarm(&mut self) {
        self.should_stop = false;
    }
}

impl Drop for StopStreamOnDrop {
    fn drop(&mut self) {
        if self.should_stop {
            stop_stream(&self.stream);
        }
    }
}

async fn acquire_local_media(with_video: bool) -> Result<JsValue, JsValue> {
    let constraints = Object::new();
    set_property(&constraints, "audio", &JsValue::TRUE)?;
    if with_video {
        let video = Object::new();
        let width = Object::new();
        let height = Object::new();
        set_property(&video, "facingMode", &JsValue::from_str("user"))?;
        set_property(&width, "ideal", &JsValue::from_f64(1280.0))?;
        set_property(&height, "ideal", &JsValue::from_f64(720.0))?;
        set_property(&video, "width", width.as_ref())?;
        set_property(&video, "height", height.as_ref())?;
        set_property(&constraints, "video", video.as_ref())?;
    }
    let devices_api = media_devices()?;
    await_method(&devices_api, "getUserMedia", &[constraints.into()]).await
}

fn media_devices() -> Result<JsValue, JsValue> {
    let global = js_sys::global();
    let navigator = get_property(&global, "navigator")
        .map_err(|_| rtc_error("media_unavailable", "Browser navigator is unavailable"))?;
    let media_devices = get_property(&navigator, "mediaDevices")
        .map_err(|_| rtc_error("media_unavailable", "Browser mediaDevices is unavailable"))?;
    if media_devices.is_null() || media_devices.is_undefined() {
        return Err(rtc_error(
            "media_unavailable",
            "Media capture requires navigator.mediaDevices in a secure context",
        ));
    }
    Ok(media_devices)
}

fn construct_global(name: &str, args: &[JsValue]) -> Result<JsValue, JsValue> {
    let constructor = get_property(&js_sys::global(), name)?
        .dyn_into::<Function>()
        .map_err(|_| {
            rtc_error(
                "runtime",
                &format!("Browser constructor {name} is unavailable"),
            )
        })?;
    let arguments = Array::new();
    for arg in args {
        arguments.push(arg);
    }
    Reflect::construct(&constructor, &arguments)
}

fn call_method(object: &JsValue, name: &str, args: &[JsValue]) -> Result<JsValue, JsValue> {
    let method = get_property(object, name)?
        .dyn_into::<Function>()
        .map_err(|_| rtc_error("runtime", &format!("Browser method {name} is unavailable")))?;
    let arguments = Array::new();
    for arg in args {
        arguments.push(arg);
    }
    method.apply(object, &arguments)
}

async fn await_method(object: &JsValue, name: &str, args: &[JsValue]) -> Result<JsValue, JsValue> {
    let value = call_method(object, name, args)?;
    let promise = value.dyn_into::<Promise>().map_err(|_| {
        rtc_error(
            "runtime",
            &format!("Browser method {name} did not return a Promise"),
        )
    })?;
    JsFuture::from(promise).await
}

fn get_property(object: &JsValue, name: &str) -> Result<JsValue, JsValue> {
    Reflect::get(object, &JsValue::from_str(name))
}

fn set_property(object: &JsValue, name: &str, value: &JsValue) -> Result<(), JsValue> {
    match Reflect::set(object, &JsValue::from_str(name), value) {
        Ok(true) => Ok(()),
        Ok(false) => Err(rtc_error(
            "runtime",
            &format!("Could not set browser property {name}"),
        )),
        Err(error) => Err(error),
    }
}

fn stream_tracks(stream: &JsValue, kind: Option<&str>) -> Result<Vec<JsValue>, JsValue> {
    let value = call_method(stream, "getTracks", &[])?;
    let tracks = value.dyn_into::<Array>().map_err(|_| {
        rtc_error(
            "runtime",
            "MediaStream.getTracks returned a non-array value",
        )
    })?;
    let mut selected = Vec::new();
    for index in 0..tracks.length() {
        let track = tracks.get(index);
        if kind.is_none_or(|expected| {
            get_property(&track, "kind")
                .ok()
                .and_then(|value| value.as_string())
                .as_deref()
                == Some(expected)
        }) {
            selected.push(track);
        }
    }
    Ok(selected)
}

fn new_media_stream(tracks: &[JsValue]) -> Result<JsValue, JsValue> {
    let stream = construct_global("MediaStream", &[])?;
    for track in tracks {
        call_method(&stream, "addTrack", &[track.clone()])?;
    }
    Ok(stream)
}

fn candidate_init(candidate: &JsValue) -> Option<JsValue> {
    if let Ok(method) = get_property(candidate, "toJSON")
        && let Ok(method) = method.dyn_into::<Function>()
        && let Ok(value) = method.call0(candidate)
        && value.is_object()
    {
        return Some(value);
    }

    // Older browser implementations may not expose RTCIceCandidate.toJSON.
    // Copy the Web API init fields into an ordinary object before the web
    // layer serializes/encrypts the Signal envelope.
    let value = Object::new();
    let mut has_candidate = false;
    for name in ["candidate", "sdpMid", "sdpMLineIndex", "usernameFragment"] {
        let Ok(field) = get_property(candidate, name) else {
            continue;
        };
        if name == "candidate" && field.as_string().is_some() {
            has_candidate = true;
        }
        if !field.is_undefined() && set_property(&value, name, &field).is_err() {
            return None;
        }
    }
    has_candidate.then(|| value.into())
}

fn stop_stream(stream: &JsValue) {
    let Ok(tracks) = stream_tracks(stream, None) else {
        return;
    };
    for track in tracks {
        let _ = call_method(&track, "stop", &[]);
    }
}

fn video_sender(peer_connection: &JsValue) -> Result<Option<JsValue>, JsValue> {
    let senders = call_method(peer_connection, "getSenders", &[])?
        .dyn_into::<Array>()
        .map_err(|_| {
            rtc_error(
                "runtime",
                "RTCPeerConnection.getSenders returned a non-array value",
            )
        })?;
    for index in 0..senders.length() {
        let sender = senders.get(index);
        let track = get_property(&sender, "track")?;
        if !track.is_null()
            && !track.is_undefined()
            && get_property(&track, "kind")?.as_string().as_deref() == Some("video")
        {
            return Ok(Some(sender));
        }
    }
    Ok(None)
}

fn session_description(kind: &str, sdp: &str) -> Result<JsValue, JsValue> {
    let description = Object::new();
    set_property(&description, "type", &JsValue::from_str(kind))?;
    set_property(&description, "sdp", &JsValue::from_str(sdp))?;
    Ok(description.into())
}

fn local_sdp(peer_connection: &JsValue) -> Result<String, JsValue> {
    let description = get_property(peer_connection, "localDescription")?;
    let sdp = get_property(&description, "sdp")?
        .as_string()
        .filter(|sdp| !sdp.is_empty())
        .ok_or_else(|| {
            rtc_error(
                "empty_sdp",
                "The browser peer connection produced no local SDP",
            )
        })?;
    Ok(sdp)
}

fn validate_call_id(call_id: &str) -> Result<(), JsValue> {
    validate_call_id_text(call_id).map_err(|message| rtc_error("invalid_call_id", message))
}

fn validate_call_id_text(call_id: &str) -> Result<(), &'static str> {
    let bytes = call_id.as_bytes();
    if bytes.len() != 36 {
        return Err("call_id must be a canonical UUID string");
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return Err("call_id must be a canonical UUID string");
            }
        } else if !byte.is_ascii_hexdigit() {
            return Err("call_id must be a canonical UUID string");
        }
    }
    Ok(())
}

fn validate_sdp(sdp: &str) -> Result<(), JsValue> {
    if sdp.is_empty() {
        return Err(rtc_error("invalid_sdp", "remote_sdp must not be empty"));
    }
    Ok(())
}

fn validate_candidate(candidate: &JsValue) -> Result<(), JsValue> {
    if candidate.is_null() || candidate.is_undefined() || !candidate.is_object() {
        return Err(rtc_error(
            "invalid_candidate",
            "ICE candidate must be an object",
        ));
    }
    let raw = get_property(candidate, "candidate")?
        .as_string()
        .ok_or_else(|| {
            rtc_error(
                "invalid_candidate",
                "ICE candidate must contain a non-empty candidate string",
            )
        })?;
    validate_candidate_text(&raw).map_err(|message| rtc_error("invalid_candidate", message))
}

fn validate_candidate_text(candidate: &str) -> Result<(), &'static str> {
    if candidate.is_empty() {
        return Err("ICE candidate must contain a non-empty candidate string");
    }
    if candidate.len() > MAX_CANDIDATE_BYTES {
        return Err("ICE candidate exceeds the 16384-byte limit");
    }
    Ok(())
}

fn offer_has_video(sdp: &str) -> bool {
    sdp.lines().any(|line| line.starts_with("m=video "))
}

fn ensure_call_open(call: &CallRef) -> Result<(), JsValue> {
    ensure_call_open_ref(&call.borrow())
}

fn ensure_call_open_ref(call: &ManagedCall) -> Result<(), JsValue> {
    if call.closed {
        Err(rtc_error(
            "call_closed",
            "The peer connection has already been closed",
        ))
    } else {
        Ok(())
    }
}

fn mark_remote_description_set(call: &CallRef) -> Result<(), JsValue> {
    let mut state = call.borrow_mut();
    ensure_call_open_ref(&state)?;
    state.remote_description_set = true;
    Ok(())
}

async fn drain_remote_candidates(call: &CallRef) -> Result<(), JsValue> {
    loop {
        let (peer_connection, candidate) = {
            let mut state = call.borrow_mut();
            ensure_call_open_ref(&state)?;
            let Some(candidate) = state.pending_candidates.pop() else {
                return Ok(());
            };
            (state.peer_connection.clone(), candidate)
        };
        await_method(&peer_connection, "addIceCandidate", &[candidate]).await?;
    }
}

fn close_call_state(call: &CallRef) {
    let (peer_connection, local_stream, remote_stream) = {
        let mut state = call.borrow_mut();
        if state.closed {
            return;
        }
        state.closed = true;
        state.pending_candidates.clear();
        (
            state.peer_connection.clone(),
            state.local_stream.clone(),
            state.remote_stream.clone(),
        )
    };
    for name in [
        "onicecandidate",
        "ontrack",
        "onconnectionstatechange",
        "oniceconnectionstatechange",
    ] {
        let _ = set_property(&peer_connection, name, &JsValue::NULL);
    }
    let _ = call_method(&peer_connection, "close", &[]);
    stop_stream(&local_stream);
    stop_stream(&remote_stream);
}

fn rtc_error(code: &str, message: &str) -> JsValue {
    let error = js_sys::Error::new(message);
    let _ = set_property(&error, "name", &JsValue::from_str("BrowserRtcError"));
    let _ = set_property(&error, "code", &JsValue::from_str(code));
    error.into()
}

#[cfg(test)]
mod tests {
    use super::{
        CandidateQueue, CandidateQueues, MAX_CANDIDATE_BYTES, MAX_PRE_SESSION_CALLS,
        MAX_PRE_SESSION_CANDIDATE_TOTAL, StartRegistry, StartRegistryError, validate_call_id_text,
        validate_candidate_text,
    };

    const CALL_ID: &str = "00112233-4455-6677-8899-aabbccddeeff";

    #[test]
    fn call_id_validation_requires_canonical_uuid_shape() {
        assert!(validate_call_id_text(CALL_ID).is_ok());
        assert!(validate_call_id_text("00112233-4455-6677-8899-AABBCCDDEEFF").is_ok());
        for invalid in [
            "",
            "not-a-uuid",
            "00112233445566778899aabbccddeeff",
            "{00112233-4455-6677-8899-aabbccddeeff}",
            "00112233-4455-6677-8899-aabbccddeefg",
            "00112233_4455-6677-8899-aabbccddeeff",
        ] {
            assert!(
                validate_call_id_text(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn candidate_validation_rejects_empty_and_oversized_strings() {
        assert!(validate_candidate_text("candidate:1 1 UDP 1 192.0.2.1 1234 typ host").is_ok());
        assert!(validate_candidate_text("").is_err());
        assert!(validate_candidate_text(&"x".repeat(MAX_CANDIDATE_BYTES + 1)).is_err());
    }

    #[test]
    fn pending_candidate_queue_preserves_fifo_and_enforces_limit() {
        let mut queue = CandidateQueue::default();
        for value in 0..super::MAX_PRE_SESSION_CANDIDATES {
            queue.push(value).unwrap();
        }
        assert!(queue.push(super::MAX_PRE_SESSION_CANDIDATES).is_err());
        for value in 0..super::MAX_PRE_SESSION_CANDIDATES {
            assert_eq!(queue.pop(), Some(value));
        }
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn pre_call_candidate_queues_have_global_and_call_count_limits() {
        let mut queues = CandidateQueues::default();
        for index in 0..MAX_PRE_SESSION_CALLS {
            queues.push(&format!("call-{index}"), index).unwrap();
        }
        assert!(queues.push("too-many-call-ids", 0).is_err());

        queues.remove("call-0");
        queues.push("replacement-call", 99).unwrap();
        queues.take("call-1").unwrap();
        assert_eq!(queues.total_candidates, MAX_PRE_SESSION_CALLS - 1);

        queues.clear();
        let entries_per_call = MAX_PRE_SESSION_CANDIDATE_TOTAL / MAX_PRE_SESSION_CALLS;
        for call_index in 0..MAX_PRE_SESSION_CALLS {
            for candidate_index in 0..entries_per_call {
                queues
                    .push(&format!("bounded-call-{call_index}"), candidate_index)
                    .unwrap();
            }
        }
        assert_eq!(queues.total_candidates, MAX_PRE_SESSION_CANDIDATE_TOTAL);
        assert!(queues.push("bounded-call-0", usize::MAX).is_err());
        assert_eq!(queues.total_candidates, MAX_PRE_SESSION_CANDIDATE_TOTAL);
    }

    #[test]
    fn start_registry_prevents_late_permission_results_from_reactivating_calls() {
        let mut starts = StartRegistry::default();
        let first = starts.reserve(CALL_ID).unwrap();
        assert_eq!(
            starts.reserve(CALL_ID),
            Err(StartRegistryError::AlreadyStarting)
        );
        assert!(starts.is_current(CALL_ID, first));
        starts.cancel(CALL_ID);

        let second = starts.reserve(CALL_ID).unwrap();
        assert_ne!(first, second);
        assert!(!starts.finish(CALL_ID, first));
        assert!(starts.is_current(CALL_ID, second));
        assert!(starts.finish(CALL_ID, second));
        assert!(!starts.is_current(CALL_ID, second));
    }
}
