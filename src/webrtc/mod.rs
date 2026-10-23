//! WebRTC layer. Owns peer connections, data channels, ICE negotiation, and
//! media tracks.
//!
//! The signaling channel is the existing websocket: SDP offers and answers
//! and ICE candidates travel as envelopes with `envelope_type` in the
//! CALL_* range, exactly the way any other message does. Media itself does
//! not go through the websocket; RTP/RTCP flow over the peer connection.

use std::collections::HashMap;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use bytes::BytesMut;
use serde::Serialize;
use tokio::sync::Mutex;
#[cfg(test)]
use tokio::sync::Semaphore;
use tokio::sync::mpsc;

use webrtc::data_channel::{DataChannel, DataChannelEvent, RTCDataChannelMessage};
use webrtc::peer_connection::{
    MediaEngine, PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler,
    RTCConfigurationBuilder, RTCIceConnectionState, RTCIceGatheringState, RTCIceServer,
    RTCPeerConnectionIceEvent, RTCPeerConnectionState, RTCSessionDescription, RTCSignalingState,
};

use crate::error::{Error, Result};
use crate::webrtc::audio::AudioTracks;
use crate::webrtc::video::VideoTracks;

pub mod audio;
pub mod signal;
pub mod video;
pub mod vp8;

/// Events emitted by a peer connection.
#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum WebRtcEvent {
    IceCandidate {
        call_id: String,
        candidate: serde_json::Value,
    },
    SignalingStateChanged {
        call_id: String,
        state: String,
    },
    IceConnectionStateChanged {
        call_id: String,
        state: String,
    },
    IceGatheringStateChanged {
        call_id: String,
        state: String,
    },
    ConnectionStateChanged {
        call_id: String,
        state: String,
    },
    DataChannelOpened {
        call_id: String,
        label: String,
    },
    DataChannelClosed {
        call_id: String,
        label: String,
    },
    DataChannelMessage {
        call_id: String,
        label: String,
        data_base64: String,
        is_text: bool,
    },
    TrackReceived {
        call_id: String,
        track_id: String,
        kind: String,
    },
    Closed {
        call_id: String,
    },
}

enum InternalEvent {
    User(WebRtcEvent),
    ChannelOpened {
        call_id: String,
        label: String,
        channel: Arc<dyn DataChannel>,
    },
    ChannelClosed {
        call_id: String,
        label: String,
    },
    TrackOpened {
        call_id: String,
        track_id: String,
        kind: String,
        track: Arc<dyn webrtc::media_stream::track_remote::TrackRemote>,
    },
}

#[derive(Clone)]
struct Handler {
    call_id: String,
    tx: mpsc::UnboundedSender<InternalEvent>,
}

fn candidate_to_sdp(c: &webrtc::peer_connection::RTCIceCandidate) -> String {
    let proto = format!("{:?}", c.protocol).to_lowercase();
    let typ = format!("{:?}", c.typ).to_lowercase();
    let mut s = format!(
        "candidate:{} {} {} {} {} {} typ {}",
        c.foundation, c.component, proto, c.priority, c.address, c.port, typ
    );
    if !c.related_address.is_empty() {
        s.push_str(&format!(
            " raddr {} rport {}",
            c.related_address, c.related_port
        ));
    }
    s
}

#[async_trait]
impl PeerConnectionEventHandler for Handler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        let candidate_sdp = candidate_to_sdp(&event.candidate);
        let candidate =
            serde_json::json!({ "candidate": candidate_sdp, "sdpMid": "0", "sdpMLineIndex": 0 });
        let _ = self.tx.send(InternalEvent::User(WebRtcEvent::IceCandidate {
            call_id: self.call_id.clone(),
            candidate,
        }));
    }

    async fn on_signaling_state_change(&self, state: RTCSignalingState) {
        let _ = self
            .tx
            .send(InternalEvent::User(WebRtcEvent::SignalingStateChanged {
                call_id: self.call_id.clone(),
                state: format!("{state:?}"),
            }));
    }

    async fn on_ice_connection_state_change(&self, state: RTCIceConnectionState) {
        let _ = self.tx.send(InternalEvent::User(
            WebRtcEvent::IceConnectionStateChanged {
                call_id: self.call_id.clone(),
                state: format!("{state:?}"),
            },
        ));
    }

    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        let _ = self
            .tx
            .send(InternalEvent::User(WebRtcEvent::IceGatheringStateChanged {
                call_id: self.call_id.clone(),
                state: format!("{state:?}"),
            }));
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        let _ = self
            .tx
            .send(InternalEvent::User(WebRtcEvent::ConnectionStateChanged {
                call_id: self.call_id.clone(),
                state: format!("{state:?}"),
            }));
    }

    async fn on_data_channel(&self, channel: Arc<dyn DataChannel>) {
        let label = match channel.label().await {
            Ok(l) => l,
            Err(_) => return,
        };
        let _ = self.tx.send(InternalEvent::ChannelOpened {
            call_id: self.call_id.clone(),
            label,
            channel,
        });
    }

    async fn on_track(&self, track: Arc<dyn webrtc::media_stream::track_remote::TrackRemote>) {
        // TrackRemote exposes track_id, stream_id and kind, all async. There
        // is no mid here: the m-line identifier lives on the transceiver, and
        // a consumer that needs it reads it from its own SDP bookkeeping.
        let kind = format!("{:?}", track.kind().await);
        let track_id = format!("{:?}", track.track_id().await);
        let _ = self.tx.send(InternalEvent::TrackOpened {
            call_id: self.call_id.clone(),
            track_id: track_id.clone(),
            kind: kind.clone(),
            track: track.clone(),
        });
        let _ = self
            .tx
            .send(InternalEvent::User(WebRtcEvent::TrackReceived {
                call_id: self.call_id.clone(),
                track_id,
                kind,
            }));
    }
}

pub struct WebRtcManager {
    peers: Mutex<HashMap<String, Arc<dyn PeerConnection>>>,
    call_locks: Mutex<HashMap<String, Weak<Mutex<()>>>>,
    channels: Mutex<HashMap<(String, String), Arc<dyn DataChannel>>>,
    pub video: Arc<VideoTracks>,
    pub audio: Arc<AudioTracks>,
    event_tx: mpsc::UnboundedSender<InternalEvent>,
    event_rx: Mutex<mpsc::UnboundedReceiver<InternalEvent>>,
    #[cfg(test)]
    offer_test_hooks: Option<Arc<OfferTestHooks>>,
}

impl WebRtcManager {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            peers: Mutex::new(HashMap::new()),
            call_locks: Mutex::new(HashMap::new()),
            channels: Mutex::new(HashMap::new()),
            video: Arc::new(VideoTracks::new()),
            audio: Arc::new(AudioTracks::new()),
            event_tx: tx,
            event_rx: Mutex::new(rx),
            #[cfg(test)]
            offer_test_hooks: None,
        }
    }

    pub async fn run_event_loop(self: Arc<Self>, state: Arc<crate::runtime::ActorState>) {
        loop {
            let ev = {
                let mut rx = self.event_rx.lock().await;
                rx.recv().await
            };
            let Some(ev) = ev else { return };
            match ev {
                InternalEvent::User(user) => {
                    state.events.push(crate::events::types::Event::ephemeral(
                        "webrtc_event",
                        serde_json::to_value(&user).unwrap_or(serde_json::Value::Null),
                    ));
                }
                InternalEvent::ChannelOpened {
                    call_id,
                    label,
                    channel,
                } => {
                    self.channels
                        .lock()
                        .await
                        .insert((call_id.clone(), label.clone()), channel.clone());

                    let call_id2 = call_id.clone();
                    let label2 = label.clone();
                    state.events.push(crate::events::types::Event::ephemeral(
                        "webrtc_event",
                        serde_json::json!({
                            "event": "data_channel_opened",
                            "call_id": call_id,
                            "label": label,
                        }),
                    ));
                    let state2 = state.clone();
                    let manager = self.clone();
                    tokio::task::spawn_local(async move {
                        poll_data_channel(state2, manager, call_id2, label2, channel).await;
                    });
                }
                InternalEvent::ChannelClosed { call_id, label } => {
                    self.channels.lock().await.remove(&(call_id, label));
                }
                InternalEvent::TrackOpened {
                    call_id,
                    track_id,
                    kind,
                    track,
                } => {
                    // Video and audio arrive on the same callback. Route by the
                    // codec kind so each ends up in its own frame queue; a
                    // consumer then reads whichever stream it cares about.
                    if kind.to_ascii_lowercase().contains("audio") {
                        self.audio.register_remote(&call_id, track_id, track).await;
                    } else {
                        self.video.register_remote(&call_id, track_id, track).await;
                    }
                }
            }
        }
    }

    pub async fn send_data(
        &self,
        call_id: &str,
        label: &str,
        data: Vec<u8>,
        is_text: bool,
    ) -> Result<()> {
        let channel = {
            let channels = self.channels.lock().await;
            channels
                .get(&(call_id.to_string(), label.to_string()))
                .cloned()
        };
        let channel = channel.ok_or_else(|| {
            Error::InvalidPayload(format!(
                "no open data channel {label:?} on call {call_id:?}"
            ))
        })?;
        if is_text {
            let text = String::from_utf8(data)
                .map_err(|e| Error::InvalidPayload(format!("text payload is not utf-8: {e}")))?;
            channel
                .send_text(&text)
                .await
                .map_err(|e| Error::Internal(format!("send_text: {e}")))?;
        } else {
            channel
                .send(BytesMut::from(&data[..]))
                .await
                .map_err(|e| Error::Internal(format!("send: {e}")))?;
        }
        Ok(())
    }

    /// Adds a VP8 video track to a call and returns the payload type the
    /// caller must use when writing frames. Actually the underlying track
    /// owns that; the return is informational only.
    pub async fn add_video_track(&self, call_id: &str, label: &str) -> Result<()> {
        let pc = self.get(call_id).await?;
        let track = self.video.register_local(call_id, label).await?;
        pc.add_track(track)
            .await
            .map_err(|e| Error::Internal(format!("add_track: {e}")))?;
        Ok(())
    }

    /// Adds an Opus audio track to a call. The caller produces encoded Opus
    /// frames and hands them to `write_audio_frame`; the library only routes
    /// them through RTP.
    pub async fn add_audio_track(&self, call_id: &str, label: &str) -> Result<()> {
        let pc = self.get(call_id).await?;
        let track = self.audio.register_local(call_id, label).await?;
        pc.add_track(track)
            .await
            .map_err(|e| Error::Internal(format!("add_track: {e}")))?;
        Ok(())
    }

    pub async fn write_audio_frame(
        &self,
        call_id: &str,
        data: Vec<u8>,
        duration_ms: u64,
    ) -> Result<()> {
        self.audio.write_frame(call_id, data, duration_ms).await
    }

    pub async fn write_video_frame(
        &self,
        call_id: &str,
        data: Vec<u8>,
        duration_ms: u64,
    ) -> Result<()> {
        self.video.write_frame(call_id, data, duration_ms).await
    }

    pub async fn create_offer(
        &self,
        call_id: &str,
        ice_servers: Vec<serde_json::Value>,
    ) -> Result<String> {
        #[cfg(test)]
        if let Some(hooks) = &self.offer_test_hooks {
            hooks.offers_started.add_permits(1);
        }
        let call_lock = self.call_operation_lock(call_id).await;
        let _call_guard = call_lock.lock().await;

        // The first call creates the connection. Later calls create a new
        // offer on that same connection, which is required after the caller
        // adds a track or data channel.
        let existing = self.peers.lock().await.get(call_id).cloned();
        let pc = match existing {
            Some(pc) => pc,
            None => self.build_peer(call_id, ice_servers).await?,
        };
        let offer = pc
            .create_offer(None)
            .await
            .map_err(|e| Error::Internal(format!("create_offer: {e}")))?;
        pc.set_local_description(offer.clone())
            .await
            .map_err(|e| Error::Internal(format!("set_local_description: {e}")))?;
        self.peers
            .lock()
            .await
            .entry(call_id.to_string())
            .or_insert(pc);
        Ok(offer.sdp)
    }

    pub async fn accept_offer(
        &self,
        call_id: &str,
        remote_sdp: &str,
        ice_servers: Vec<serde_json::Value>,
    ) -> Result<String> {
        let call_lock = self.call_operation_lock(call_id).await;
        let _call_guard = call_lock.lock().await;
        let existing = self.peers.lock().await.get(call_id).cloned();
        let pc = match existing {
            Some(pc) => pc,
            None => self.build_peer(call_id, ice_servers).await?,
        };
        let remote = RTCSessionDescription::offer(remote_sdp.to_string())
            .map_err(|e| Error::Internal(format!("bad offer: {e}")))?;
        pc.set_remote_description(remote)
            .await
            .map_err(|e| Error::Internal(format!("set_remote_description: {e}")))?;
        let answer = pc
            .create_answer(None)
            .await
            .map_err(|e| Error::Internal(format!("create_answer: {e}")))?;
        pc.set_local_description(answer.clone())
            .await
            .map_err(|e| Error::Internal(format!("set_local_description: {e}")))?;
        self.peers.lock().await.insert(call_id.to_string(), pc);
        Ok(answer.sdp)
    }

    pub async fn apply_answer(&self, call_id: &str, remote_sdp: &str) -> Result<()> {
        let pc = self.get(call_id).await?;
        let remote = RTCSessionDescription::answer(remote_sdp.to_string())
            .map_err(|e| Error::Internal(format!("bad answer: {e}")))?;
        pc.set_remote_description(remote)
            .await
            .map_err(|e| Error::Internal(format!("set_remote_description: {e}")))?;
        Ok(())
    }

    pub async fn add_ice_candidate(
        &self,
        call_id: &str,
        candidate: serde_json::Value,
    ) -> Result<()> {
        let pc = self.get(call_id).await?;
        let init: webrtc::peer_connection::RTCIceCandidateInit = serde_json::from_value(candidate)
            .map_err(|e| Error::InvalidPayload(format!("ice candidate: {e}")))?;
        pc.add_ice_candidate(init)
            .await
            .map_err(|e| Error::Internal(format!("add_ice_candidate: {e}")))?;
        Ok(())
    }

    pub async fn create_data_channel(&self, call_id: &str, label: &str) -> Result<()> {
        let pc = self.get(call_id).await?;
        let dc = pc
            .create_data_channel(label, None)
            .await
            .map_err(|e| Error::Internal(format!("create_data_channel: {e}")))?;
        let label_owned = label.to_string();
        let call_id_owned = call_id.to_string();
        let tx = self.event_tx.clone();
        let _ = tx.send(InternalEvent::ChannelOpened {
            call_id: call_id_owned,
            label: label_owned,
            channel: dc,
        });
        Ok(())
    }

    pub async fn close(&self, call_id: &str) -> Result<()> {
        let call_lock = self.call_operation_lock(call_id).await;
        let _call_guard = call_lock.lock().await;
        let pc = {
            let mut peers = self.peers.lock().await;
            peers.remove(call_id)
        };
        {
            let mut channels = self.channels.lock().await;
            channels.retain(|(cid, _), _| cid != call_id);
        }
        self.video.drop_call(call_id).await;
        self.audio.drop_call(call_id).await;
        if let Some(pc) = pc {
            let _ = pc.close().await;
        }
        let _ = self.event_tx.send(InternalEvent::User(WebRtcEvent::Closed {
            call_id: call_id.to_string(),
        }));
        Ok(())
    }

    pub async fn list_active(&self) -> Vec<String> {
        self.peers.lock().await.keys().cloned().collect()
    }

    async fn call_operation_lock(&self, call_id: &str) -> Arc<Mutex<()>> {
        let mut locks = self.call_locks.lock().await;
        // Weak entries do not keep idle call locks alive. Remove finished
        // entries opportunistically so this map does not grow with call IDs.
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(call_id).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        locks.insert(call_id.to_owned(), Arc::downgrade(&lock));
        lock
    }

    async fn get(&self, call_id: &str) -> Result<Arc<dyn PeerConnection>> {
        self.peers
            .lock()
            .await
            .get(call_id)
            .cloned()
            .ok_or_else(|| Error::InvalidPayload(format!("unknown call_id: {call_id}")))
    }

    async fn build_peer(
        &self,
        call_id: &str,
        ice_servers: Vec<serde_json::Value>,
    ) -> Result<Arc<dyn PeerConnection>> {
        #[cfg(test)]
        if let Some(hooks) = &self.offer_test_hooks {
            hooks.builds_started.add_permits(1);
            hooks.build_count.fetch_add(1, Ordering::SeqCst);
            hooks
                .release_build
                .acquire()
                .await
                .expect("test must release gated peer build")
                .forget();
        }
        let servers = parse_ice_servers(ice_servers)?;
        let config = RTCConfigurationBuilder::default()
            .with_ice_servers(servers)
            .build();
        let handler = Arc::new(Handler {
            call_id: call_id.to_string(),
            tx: self.event_tx.clone(),
        });
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .map_err(|e| Error::Internal(format!("register WebRTC codecs: {e}")))?;
        let pc_impl = PeerConnectionBuilder::new()
            .with_configuration(config)
            .with_media_engine(media_engine)
            .with_handler(handler)
            .with_udp_addrs(vec!["0.0.0.0:0"])
            .build()
            .await
            .map_err(|e| Error::Internal(format!("peer build: {e}")))?;
        Ok(Arc::new(pc_impl))
    }
}

impl Default for WebRtcManager {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_ice_servers(input: Vec<serde_json::Value>) -> Result<Vec<RTCIceServer>> {
    let mut out = Vec::with_capacity(input.len());
    for item in input {
        let urls: Vec<String> = item
            .get("urls")
            .and_then(|u| serde_json::from_value(u.clone()).ok())
            .ok_or_else(|| Error::InvalidPayload("ice server urls missing".into()))?;
        let username = item
            .get("username")
            .and_then(|u| u.as_str())
            .map(String::from);
        let credential = item
            .get("credential")
            .and_then(|u| u.as_str())
            .map(String::from);
        out.push(RTCIceServer {
            urls,
            username: username.unwrap_or_default(),
            credential: credential.unwrap_or_default(),
        });
    }
    Ok(out)
}

async fn poll_data_channel(
    state: Arc<crate::runtime::ActorState>,
    manager: Arc<WebRtcManager>,
    call_id: String,
    label: String,
    dc: Arc<dyn DataChannel>,
) {
    loop {
        let Some(event) = dc.poll().await else { break };
        match event {
            DataChannelEvent::OnMessage(msg) => {
                let is_text = data_channel_message_is_text(&msg);
                state.events.push(crate::events::types::Event::ephemeral(
                    "webrtc_event",
                    serde_json::json!({
                        "event": "data_channel_message",
                        "call_id": call_id,
                        "label": label,
                        "data_base64": base64_standard(&msg.data),
                        "is_text": is_text,
                    }),
                ));
            }
            DataChannelEvent::OnClose => {
                let _ = manager.event_tx.send(InternalEvent::ChannelClosed {
                    call_id: call_id.clone(),
                    label: label.clone(),
                });
                state.events.push(crate::events::types::Event::ephemeral(
                    "webrtc_event",
                    serde_json::json!({
                        "event": "data_channel_closed",
                        "call_id": call_id,
                        "label": label,
                    }),
                ));
                break;
            }
            _ => {}
        }
    }
}

fn data_channel_message_is_text(message: &RTCDataChannelMessage) -> bool {
    message.is_string
}

fn base64_standard(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[cfg(test)]
struct OfferTestHooks {
    offers_started: Semaphore,
    builds_started: Semaphore,
    release_build: Semaphore,
    build_count: AtomicUsize,
}

#[cfg(test)]
impl OfferTestHooks {
    fn new() -> Self {
        Self {
            offers_started: Semaphore::new(0),
            builds_started: Semaphore::new(0),
            release_build: Semaphore::new(0),
            build_count: AtomicUsize::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sdp_peer_identity(sdp: &str) -> (String, String) {
        let origin = sdp
            .lines()
            .find(|line| line.starts_with("o="))
            .expect("SDP should have an origin line");
        let session_id = origin
            .split_whitespace()
            .nth(1)
            .expect("SDP origin should have a session ID")
            .to_owned();
        let fingerprint = sdp
            .lines()
            .find(|line| line.starts_with("a=fingerprint:"))
            .expect("SDP should have a DTLS fingerprint")
            .to_owned();
        (session_id, fingerprint)
    }

    #[tokio::test]
    async fn idle_call_operation_locks_are_pruned_on_the_next_call() {
        let manager = WebRtcManager::new();
        drop(manager.call_operation_lock("closed-call").await);

        let current_lock = manager.call_operation_lock("new-call").await;
        let locks = manager.call_locks.lock().await;
        assert_eq!(locks.len(), 1);
        assert!(locks.contains_key("new-call"));
        drop(locks);
        drop(current_lock);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_first_offers_share_the_retained_peer_connection() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let hooks = Arc::new(OfferTestHooks::new());
                let mut manager = WebRtcManager::new();
                manager.offer_test_hooks = Some(hooks.clone());
                let manager = Arc::new(manager);

                let first_manager = manager.clone();
                let first = tokio::task::spawn_local(async move {
                    first_manager
                        .create_offer("concurrent-offer", Vec::new())
                        .await
                });
                hooks
                    .offers_started
                    .acquire()
                    .await
                    .expect("first offer should start")
                    .forget();
                hooks
                    .builds_started
                    .acquire()
                    .await
                    .expect("first offer should start building a peer")
                    .forget();

                let second_manager = manager.clone();
                let second = tokio::task::spawn_local(async move {
                    second_manager
                        .create_offer("concurrent-offer", Vec::new())
                        .await
                });
                hooks
                    .offers_started
                    .acquire()
                    .await
                    .expect("second offer should start")
                    .forget();

                // The first build remains suspended until after the second
                // call has reached its first await. Without per-call
                // serialization, both calls observe the empty peer map and
                // start separate builds here.
                let builds_before_release = hooks.build_count.load(Ordering::SeqCst);
                hooks.release_build.add_permits(2);

                let first_offer = first.await.expect("first task should finish").unwrap();
                let second_offer = second.await.expect("second task should finish").unwrap();
                let retained = manager
                    .get("concurrent-offer")
                    .await
                    .expect("a peer should be retained");
                let retained_offer = retained
                    .local_description()
                    .await
                    .expect("retained peer should have a local offer")
                    .sdp;

                assert_eq!(builds_before_release, 1, "only one peer may be built");
                let retained_identity = sdp_peer_identity(&retained_offer);
                assert_eq!(sdp_peer_identity(&first_offer), retained_identity);
                assert_eq!(sdp_peer_identity(&second_offer), retained_identity);
                assert_eq!(second_offer, retained_offer);
                manager.close("concurrent-offer").await.unwrap();
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn creating_an_offer_after_adding_audio_reuses_the_peer_connection() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let manager = WebRtcManager::new();
                let first_offer = manager
                    .create_offer("renegotiate", Vec::new())
                    .await
                    .expect("create initial offer");
                assert!(!first_offer.contains("m=audio"));

                manager
                    .add_audio_track("renegotiate", "microphone")
                    .await
                    .expect("add local audio track");
                manager
                    .create_data_channel("renegotiate", "chat")
                    .await
                    .expect("add data channel");
                let renegotiated_offer = manager
                    .create_offer("renegotiate", Vec::new())
                    .await
                    .expect("create renegotiation offer on existing peer");
                assert!(
                    renegotiated_offer.contains("m=audio"),
                    "offer must describe the track added to this call"
                );
                assert!(
                    renegotiated_offer.contains("m=application"),
                    "offer must describe the data channel added to this call"
                );

                manager.close("renegotiate").await.expect("close peer");
            })
            .await;
    }

    #[test]
    fn binary_data_channel_message_is_not_reclassified_by_utf8_validity() {
        let message = RTCDataChannelMessage {
            is_string: false,
            data: bytes::BytesMut::from(&b"valid utf8 text"[..]),
        };

        assert!(std::str::from_utf8(&message.data).is_ok());
        assert!(!data_channel_message_is_text(&message));
    }
}
