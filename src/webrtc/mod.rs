//! WebRTC layer. Owns peer connections, data channels, ICE negotiation.
//!
//! The signaling channel is the existing websocket: SDP offers and answers
//! and ICE candidates travel as envelopes with `envelope_type` in the
//! CALL_* range, exactly the way any other message does.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
    RTCIceConnectionState, RTCIceGatheringState, RTCIceServer, RTCPeerConnectionIceEvent,
    RTCPeerConnectionState, RTCSessionDescription, RTCSignalingState,
};

use crate::error::{Error, Result};

pub mod signal;

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
    },
    Closed {
        call_id: String,
    },
}

/// Events delivered from the callback context into the actor's local loop.
///
/// The handler runs inside webrtc's own dispatch, where the current runtime
/// context is not the actor's LocalSet, so it cannot touch the DataChannel
/// poll machinery directly. Opening a channel is therefore forwarded here and
/// the actor loop spawns the poller on the right context.
enum InternalEvent {
    User(WebRtcEvent),
    ChannelOpened {
        call_id: String,
        label: String,
        channel: Arc<dyn DataChannel>,
    },
}

#[derive(Clone)]
struct Handler {
    call_id: String,
    tx: mpsc::UnboundedSender<InternalEvent>,
}

/// Rebuilds an RFC 8839 candidate-attribute line from a parsed candidate.
///
/// The remote side of the signal channel expects the W3C `RTCIceCandidateInit`
/// shape, whose `candidate` field is the SDP line, not the structured form.
fn candidate_to_sdp(c: &webrtc::peer_connection::RTCIceCandidate) -> String {
    let proto = format!("{:?}", c.protocol).to_lowercase();
    let typ = format!("{:?}", c.typ).to_lowercase();

    let mut s = format!(
        "candidate:{} {} {} {} {} {} typ {}",
        c.foundation, c.component, proto, c.priority, c.address, c.port, typ
    );

    if !c.related_address.is_empty() {
        s.push_str(&format!(" raddr {} rport {}", c.related_address, c.related_port));
    }

    s
}

#[async_trait]
impl PeerConnectionEventHandler for Handler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        let candidate_sdp = candidate_to_sdp(&event.candidate);
        let candidate = serde_json::json!({
            "candidate": candidate_sdp,
            "sdpMid": "0",
            "sdpMLineIndex": 0,
        });
        let _ = self.tx.send(InternalEvent::User(WebRtcEvent::IceCandidate {
            call_id: self.call_id.clone(),
            candidate,
        }));
    }

    async fn on_signaling_state_change(&self, state: RTCSignalingState) {
        let _ = self.tx.send(InternalEvent::User(WebRtcEvent::SignalingStateChanged {
            call_id: self.call_id.clone(),
            state: format!("{state:?}"),
        }));
    }

    async fn on_ice_connection_state_change(&self, state: RTCIceConnectionState) {
        let _ = self
            .tx
            .send(InternalEvent::User(WebRtcEvent::IceConnectionStateChanged {
                call_id: self.call_id.clone(),
                state: format!("{state:?}"),
            }));
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
        let _ = self.tx.send(InternalEvent::User(WebRtcEvent::ConnectionStateChanged {
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

    async fn on_track(&self, _track: Arc<dyn webrtc::media_stream::track_remote::TrackRemote>) {
        let _ = self.tx.send(InternalEvent::User(WebRtcEvent::TrackReceived {
            call_id: self.call_id.clone(),
        }));
    }
}

pub struct WebRtcManager {
    peers: Mutex<HashMap<String, Arc<dyn PeerConnection>>>,
    event_tx: mpsc::UnboundedSender<InternalEvent>,
    event_rx: Mutex<mpsc::UnboundedReceiver<InternalEvent>>,
}

impl WebRtcManager {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            peers: Mutex::new(HashMap::new()),
            event_tx: tx,
            event_rx: Mutex::new(rx),
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
                InternalEvent::ChannelOpened { call_id, label, channel } => {
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
                    tokio::task::spawn_local(async move {
                        poll_data_channel(state2, call_id2, label2, channel).await;
                    });
                }
            }
        }
    }

    pub async fn create_offer(
        &self,
        call_id: &str,
        ice_servers: Vec<serde_json::Value>,
    ) -> Result<String> {
        let pc = self.build_peer(call_id, ice_servers).await?;
        let offer = pc
            .create_offer(None)
            .await
            .map_err(|e| Error::Internal(format!("create_offer: {e}")))?;
        pc.set_local_description(offer.clone())
            .await
            .map_err(|e| Error::Internal(format!("set_local_description: {e}")))?;
        self.peers.lock().await.insert(call_id.to_string(), pc);
        Ok(offer.sdp)
    }

    pub async fn accept_offer(
        &self,
        call_id: &str,
        remote_sdp: &str,
        ice_servers: Vec<serde_json::Value>,
    ) -> Result<String> {
        let pc = self.build_peer(call_id, ice_servers).await?;
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
        let init: webrtc::peer_connection::RTCIceCandidateInit =
            serde_json::from_value(candidate)
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
        let pc = {
            let mut peers = self.peers.lock().await;
            peers.remove(call_id)
        };
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
        let servers = parse_ice_servers(ice_servers)?;
        let config = RTCConfigurationBuilder::default()
            .with_ice_servers(servers)
            .build();

        let handler = Arc::new(Handler {
            call_id: call_id.to_string(),
            tx: self.event_tx.clone(),
        });

        let pc_impl = PeerConnectionBuilder::new()
            .with_configuration(config)
            .with_handler(handler)
            .with_udp_addrs(vec!["0.0.0.0:0"])
            .build()
            .await
            .map_err(|e| Error::Internal(format!("peer build: {e}")))?;

        let pc: Arc<dyn PeerConnection> = Arc::new(pc_impl);
        Ok(pc)
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
            ..Default::default()
        });
    }
    Ok(out)
}

async fn poll_data_channel(
    state: Arc<crate::runtime::ActorState>,
    call_id: String,
    label: String,
    dc: Arc<dyn DataChannel>,
) {
    loop {
        let Some(event) = dc.poll().await else { break };
        match event {
            DataChannelEvent::OnMessage(msg) => {
                let is_text = std::str::from_utf8(&msg.data).is_ok();
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

fn base64_standard(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[derive(Debug, Deserialize)]
pub struct DataChannelSendParams {
    pub call_id: String,
    pub label: String,
    pub data_base64: String,
    pub is_text: bool,
}

pub async fn send_data(
    manager: &Arc<WebRtcManager>,
    _state: &Arc<crate::runtime::ActorState>,
    params: DataChannelSendParams,
) -> Result<()> {
    let _ = (manager, params);
    Err(Error::NotImplemented)
}
