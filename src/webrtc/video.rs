//! Video track management for WebRTC calls.
//!
//! Sending: a TrackLocalStaticSample registered with a VP8 codec, written
//! to via write_sample. The sample is an encoded frame; the library does not
//! encode, the caller does.
//!
//! Receiving: when a remote peer attaches a video track, on_track fires with
//! a TrackRemote. A poller is spawned for it; the poller reassembles RTP
//! packets into frames and stores only the newest frame. Frames are read out
//! through read_frame; a slow consumer never builds a stale playback backlog.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rtc::media_stream::MediaStreamTrack as RtcMediaStreamTrack;
use rtc::media_stream::{MediaStreamId, MediaStreamTrackId};
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpEncodingParameters, RtpCodecKind};
use rtc_media::Sample;
use tokio::sync::{Mutex, watch};
use webrtc::media_stream::track_local::static_sample::TrackLocalStaticSample;
use webrtc::media_stream::track_remote::{TrackRemote, TrackRemoteEvent};

use crate::error::{Error, Result};
use crate::webrtc::vp8::Vp8Depacketizer;

/// MIME type for VP8. Every WebRTC implementation supports it without
/// negotiation tricks.
pub const MIME_VP8: &str = "video/VP8";

/// Per-call latest-frame receiver. Readers hold a separate mutex while
/// waiting, so reads on different calls do not serialize on one lock.
type FrameReceiverMap = Mutex<HashMap<String, Arc<Mutex<watch::Receiver<Option<Vec<u8>>>>>>>;

pub struct InboundVideoTrack {
    pub call_id: String,
    pub track_id: String,
    pub track: Arc<dyn TrackRemote>,
}

#[derive(Default)]
pub struct VideoTracks {
    pub local: Mutex<HashMap<String, Arc<TrackLocalStaticSample>>>,
    pub remote: Mutex<HashMap<String, Arc<InboundVideoTrack>>>,
    frames: FrameReceiverMap,
}

impl VideoTracks {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register_local(
        &self,
        call_id: &str,
        label: &str,
    ) -> Result<Arc<TrackLocalStaticSample>> {
        let stream_track = RtcMediaStreamTrack::new(
            MediaStreamTrackId::new(),
            MediaStreamId::new(),
            label.to_string(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                codec: RTCRtpCodec {
                    mime_type: MIME_VP8.to_owned(),
                    clock_rate: 90_000,
                    channels: 0,
                    sdp_fmtp_line: String::new(),
                    rtcp_feedback: vec![],
                },
                ..Default::default()
            }],
        );
        let local = TrackLocalStaticSample::new(Instant::now(), stream_track)
            .map_err(|e| Error::Internal(format!("video track: {e}")))?;
        let local = Arc::new(local);
        self.local
            .lock()
            .await
            .insert(call_id.to_string(), local.clone());
        Ok(local)
    }

    pub async fn write_frame(&self, call_id: &str, data: Vec<u8>, duration_ms: u64) -> Result<()> {
        let track = {
            let map = self.local.lock().await;
            map.get(call_id).cloned()
        };
        let track = track.ok_or_else(|| {
            Error::InvalidPayload(format!("no local video track on call {call_id}"))
        })?;
        let sample = Sample {
            data: Bytes::from(data),
            timestamp: Instant::now(),
            duration: Duration::from_millis(duration_ms),
            packet_timestamp: 0,
            prev_dropped_packets: 0,
            prev_padding_packets: 0,
        };
        track
            .write_sample(0, 0, &sample, &[])
            .await
            .map_err(|e| Error::Internal(format!("video write: {e}")))?;
        Ok(())
    }

    pub async fn register_remote(
        &self,
        call_id: &str,
        track_id: String,
        track: Arc<dyn TrackRemote>,
    ) {
        let (tx, rx) = watch::channel::<Option<Vec<u8>>>(None);

        self.frames
            .lock()
            .await
            .insert(call_id.to_string(), Arc::new(Mutex::new(rx)));
        self.remote.lock().await.insert(
            call_id.to_string(),
            Arc::new(InboundVideoTrack {
                call_id: call_id.to_string(),
                track_id,
                track: track.clone(),
            }),
        );

        let call = call_id.to_string();
        tokio::task::spawn_local(async move {
            let mut depack = Vp8Depacketizer::new();
            while let Some(event) = track.poll().await {
                match event {
                    TrackRemoteEvent::OnRtpPacket(pkt) => {
                        if let Some(frame) = depack.push(&pkt) {
                            // A watch channel stores only the newest frame;
                            // a slow reader never has to drain stale backlog.
                            tx.send_replace(Some(frame));
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
        match tokio::time::timeout(timeout, rx.changed()).await {
            Ok(Ok(())) => rx.borrow_and_update().clone(),
            Ok(Err(_)) | Err(_) => None,
        }
    }

    pub async fn has_local(&self, call_id: &str) -> bool {
        self.local.lock().await.contains_key(call_id)
    }
    pub async fn has_remote(&self, call_id: &str) -> bool {
        self.remote.lock().await.contains_key(call_id)
    }

    pub async fn drop_call(&self, call_id: &str) {
        self.local.lock().await.remove(call_id);
        self.remote.lock().await.remove(call_id);
        self.frames.lock().await.remove(call_id);
    }

    pub fn outgoing_mime() -> &'static str {
        MIME_VP8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unread_video_frames_are_coalesced_to_the_newest_frame() {
        let (tx, mut rx) = watch::channel::<Option<Vec<u8>>>(None);
        tx.send_replace(Some(vec![1]));
        tx.send_replace(Some(vec![2]));
        tx.send_replace(Some(vec![3]));

        rx.changed().await.expect("a frame should be available");
        assert_eq!(rx.borrow_and_update().as_deref(), Some([3].as_slice()));
    }
}
