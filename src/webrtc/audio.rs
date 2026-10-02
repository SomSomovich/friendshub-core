//! Audio track management for WebRTC calls.
//!
//! Sending: a TrackLocalStaticSample registered with an Opus codec, written
//! to via write_sample. The caller produces encoded Opus frames; the library
//! only routes them.
//!
//! Receiving: an Opus RTP stream arrives as a sequence of packets, one Opus
//! frame per packet for the common case of 20 ms frames. A frame that spans
//! more than one packet is reassembled by concatenating payloads until the
//! RTP marker bit, which is the same rule VP8 uses but without the codec-
//! specific descriptor.
//!
//! The frame channel is deeper than video's: audio glitches are worse than a
//! dropped video frame, and the audio stream is a fifth of the bitrate.

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

/// MIME type for Opus.
pub const MIME_OPUS: &str = "audio/opus";

/// Depth of the inbound frame queue. Larger than the video one: a skipped
/// 20 ms of audio is more noticeable than a skipped video frame, and the
/// queue stays cheap because the frames are small.
const FRAME_BUFFER_DEPTH: usize = 20;

type FrameReceiverMap = Mutex<HashMap<String, Arc<Mutex<mpsc::Receiver<Vec<u8>>>>>>;

pub struct InboundAudioTrack {
    pub call_id: String,
    pub track_id: String,
    pub track: Arc<dyn TrackRemote>,
}

#[derive(Default)]
pub struct AudioTracks {
    pub local: Mutex<HashMap<String, Arc<TrackLocalStaticSample>>>,
    pub remote: Mutex<HashMap<String, Arc<InboundAudioTrack>>>,
    frames: FrameReceiverMap,
}

impl AudioTracks {
    pub fn new() -> Self { Self::default() }

    pub async fn register_local(&self, call_id: &str, label: &str) -> Result<Arc<TrackLocalStaticSample>> {
        let stream_track = RtcMediaStreamTrack::new(MediaStreamTrackId::new(), MediaStreamId::new(), label.to_string(), RtpCodecKind::Audio, vec![]);
        let local = TrackLocalStaticSample::new(Instant::now(), stream_track).map_err(|e| Error::Internal(format!("audio track: {e}")))?;
        let local = Arc::new(local);
        self.local.lock().await.insert(call_id.to_string(), local.clone());
        Ok(local)
    }

    pub async fn write_frame(&self, call_id: &str, data: Vec<u8>, duration_ms: u64) -> Result<()> {
        let track = {
            let map = self.local.lock().await;
            map.get(call_id).cloned()
        };
        let track = track.ok_or_else(|| Error::InvalidPayload(format!("no local audio track on call {call_id}")))?;
        let sample = Sample {
            data: Bytes::from(data),
            timestamp: Instant::now(),
            duration: Duration::from_millis(duration_ms),
            packet_timestamp: 0,
            prev_dropped_packets: 0,
            prev_padding_packets: 0,
        };
        track.write_sample(0, 0, &sample, &[]).await.map_err(|e| Error::Internal(format!("audio write: {e}")))?;
        Ok(())
    }

    pub async fn register_remote(&self, call_id: &str, track_id: String, track: Arc<dyn TrackRemote>) {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(FRAME_BUFFER_DEPTH);

        self.frames.lock().await.insert(call_id.to_string(), Arc::new(Mutex::new(rx)));
        self.remote.lock().await.insert(
            call_id.to_string(),
            Arc::new(InboundAudioTrack { call_id: call_id.to_string(), track_id, track: track.clone() }),
        );

        let call = call_id.to_string();
        tokio::task::spawn_local(async move {
            let mut pending: Vec<u8> = Vec::new();
            let mut have_frame = false;
            while let Some(event) = track.poll().await {
                match event {
                    TrackRemoteEvent::OnRtpPacket(pkt) => {
                        // Opus has no codec-specific RTP descriptor: the entire
                        // payload is the compressed frame (or the next slice of
                        // one). A frame ends at the RTP marker bit.
                        if !pkt.payload.is_empty() {
                            pending.extend_from_slice(&pkt.payload);
                            have_frame = true;
                        }

                        if have_frame && pkt.header.marker {
                            let frame = std::mem::take(&mut pending);
                            have_frame = false;
                            if tx.try_send(frame).is_err() {
                                tracing::trace!(call_id = %call, "audio frame dropped: buffer full or closed");
                            }
                        }
                    }
                    TrackRemoteEvent::OnEnding | TrackRemoteEvent::OnEnded => {
                        tracing::debug!(call_id = %call, "remote audio track ended");
                        break;
                    }
                    _ => {}
                }
            }
        });
    }

    pub async fn read_frame(&self, call_id: &str, timeout: Duration) -> Option<Vec<u8>> {
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

    pub fn outgoing_mime() -> &'static str { MIME_OPUS }
}
