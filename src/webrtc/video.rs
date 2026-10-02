//! Video track management for WebRTC calls.
//!
//! Sending: a TrackLocalStaticSample registered with a VP8 codec, written
//! to via write_sample. The sample is an encoded frame; the library does not
//! encode, the caller does.
//!
//! Receiving: when a remote peer attaches a video track, on_track fires with
//! a TrackRemote. A poller is spawned for it; the poller reassembles RTP
//! packets into frames and pushes them into a bounded channel. Frames are
//! read out through read_frame.
//!
//! The channel is small on purpose. If the consumer falls behind, the right
//! behaviour for video is to drop frames, not to queue them and drift
//! further behind real time.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rtc::media_stream::MediaStreamTrack as RtcMediaStreamTrack;
use rtc::media_stream::{MediaStreamId, MediaStreamTrackId};
use rtc::rtp_transceiver::rtp_sender::RtpCodecKind;
use rtc_media::Sample;
use tokio::sync::{mpsc, Mutex};
use webrtc::media_stream::track_local::static_sample::TrackLocalStaticSample;
use webrtc::media_stream::track_remote::{TrackRemote, TrackRemoteEvent};

use crate::error::{Error, Result};
use crate::webrtc::vp8::Vp8Depacketizer;

/// MIME type for VP8. Every WebRTC implementation supports it without
/// negotiation tricks.
pub const MIME_VP8: &str = "video/VP8";

/// Maximum number of frames waiting to be read. Small: video does not want
/// a backlog, it wants the newest frame.
const FRAME_BUFFER_DEPTH: usize = 5;

pub struct InboundVideoTrack {
    pub call_id: String,
    pub track_id: String,
    pub track: Arc<dyn TrackRemote>,
}

#[derive(Default)]
pub struct VideoTracks {
    pub local: Mutex<HashMap<String, Arc<TrackLocalStaticSample>>>,
    pub remote: Mutex<HashMap<String, Arc<InboundVideoTrack>>>,
    frames: Mutex<HashMap<String, Arc<Mutex<mpsc::Receiver<Vec<u8>>>>>>,
}

impl VideoTracks {
    pub fn new() -> Self { Self::default() }

    pub async fn register_local(&self, call_id: &str, label: &str) -> Result<Arc<TrackLocalStaticSample>> {
        let stream_track = RtcMediaStreamTrack::new(MediaStreamTrackId::new(), MediaStreamId::new(), label.to_string(), RtpCodecKind::Video, vec![]);
        let local = TrackLocalStaticSample::new(Instant::now(), stream_track).map_err(|e| Error::Internal(format!("video track: {e}")))?;
        let local = Arc::new(local);
        self.local.lock().await.insert(call_id.to_string(), local.clone());
        Ok(local)
    }

    pub async fn write_frame(&self, call_id: &str, data: Vec<u8>, duration_ms: u64) -> Result<()> {
        let track = {
            let map = self.local.lock().await;
            map.get(call_id).cloned()
        };
        let track = track.ok_or_else(|| Error::InvalidPayload(format!("no local video track on call {call_id}")))?;
        let sample = Sample {
            data: Bytes::from(data),
            timestamp: Instant::now(),
            duration: Duration::from_millis(duration_ms),
            packet_timestamp: 0,
            prev_dropped_packets: 0,
            prev_padding_packets: 0,
        };
        track.write_sample(0, 0, &sample, &[]).await.map_err(|e| Error::Internal(format!("video write: {e}")))?;
        Ok(())
    }

    pub async fn register_remote(&self, call_id: &str, track_id: String, track: Arc<dyn TrackRemote>) {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(FRAME_BUFFER_DEPTH);

        self.frames.lock().await.insert(call_id.to_string(), Arc::new(Mutex::new(rx)));
        self.remote.lock().await.insert(
            call_id.to_string(),
            Arc::new(InboundVideoTrack { call_id: call_id.to_string(), track_id, track: track.clone() }),
        );

        let call = call_id.to_string();
        tokio::task::spawn_local(async move {
            let mut depack = Vp8Depacketizer::new();
            while let Some(event) = track.poll().await {
                match event {
                    TrackRemoteEvent::OnRtpPacket(pkt) => {
                        if let Some(frame) = depack.push(&pkt) {
                            if tx.try_send(frame).is_err() {
                                tracing::trace!(call_id = %call, "video frame dropped: buffer full or closed");
                            }
                        }
                    }
                    TrackRemoteEvent::OnEnding | TrackRemoteEvent::OnEnded => {
                        tracing::debug!(call_id = %call, "remote video track ended");
                        break;
                    }
                    _ => {}
                }
            }
        });
    }

    pub async fn read_frame(&self, call_id: &str, timeout: Duration) -> Option<Vec<u8>> {
        // Clone the Arc while the outer map lock is held, then release it. The
        // receiver itself sits behind its own Mutex: its guard lives across the
        // await, which is what keeps the borrow valid for the duration of the
        // future. Holding the outer map lock across the await would serialize
        // every read for every call on one mutex.
        let rx_arc = {
            let map = self.frames.lock().await;
            map.get(call_id).cloned()
        };
        let rx_arc = rx_arc?;

        let mut rx = rx_arc.lock().await;
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(frame)) => Some(frame),
            Ok(None) => None,
            Err(_) => None,
        }
    }

    pub async fn has_local(&self, call_id: &str) -> bool { self.local.lock().await.contains_key(call_id) }
    pub async fn has_remote(&self, call_id: &str) -> bool { self.remote.lock().await.contains_key(call_id) }

    pub async fn drop_call(&self, call_id: &str) {
        self.local.lock().await.remove(call_id);
        self.remote.lock().await.remove(call_id);
        self.frames.lock().await.remove(call_id);
    }

    pub fn outgoing_mime() -> &'static str { MIME_VP8 }
}
