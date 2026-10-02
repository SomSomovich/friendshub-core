//! Minimal VP8 RTP depacketizer.
//!
//! One video frame travels as a sequence of RTP packets. The first carries
//! the S bit set in its VP8 payload descriptor; the last carries the RTP
//! marker bit. Everything in between belongs to the same frame.
//!
//! Only the base partition is reassembled. Encoders that split a frame into
//! multiple VP8 partitions exist but are rare in practice; when one appears,
//! the extra partitions are concatenated into the same buffer, which produces
//! a frame the decoder can still read as long as the partitions are in order.
//!
//! Reference: RFC 7741 section 4.2.

use rtc::rtp;

pub struct Vp8Depacketizer {
    buffer: Vec<u8>,
    in_frame: bool,
    /// Set when a frame was started but never finished, so a later packet
    /// from a fresh frame does not silently glue onto the leftovers.
    last_sequence: Option<u16>,
}

impl Vp8Depacketizer {
    pub fn new() -> Self {
        Self { buffer: Vec::new(), in_frame: false, last_sequence: None }
    }

    /// Feeds one RTP packet. Returns a complete frame when the packet
    /// terminates one, otherwise `None`.
    pub fn push(&mut self, packet: &rtp::Packet) -> Option<Vec<u8>> {
        let payload = packet.payload.as_ref();
        if payload.is_empty() {
            return None;
        }

        // Sequence gap: anything pending belongs to a frame that lost a
        // packet. Dropping it is correct: a VP8 decoder cannot use a partial
        // frame, and keeping it would make the next frame start with garbage.
        if let Some(prev) = self.last_sequence
            && packet.header.sequence_number != prev.wrapping_add(1) {
                self.buffer.clear();
                self.in_frame = false;
            }
        self.last_sequence = Some(packet.header.sequence_number);

        let descriptor_len = parse_descriptor_len(payload)?;

        let first = payload[0];
        let s_bit = (first & 0x10) != 0;

        if s_bit {
            // New frame starts. Discard anything pending: the sender would
            // not begin a new frame without having marked the previous one.
            self.buffer.clear();
            self.in_frame = true;
        } else if !self.in_frame {
            // Continuation of a frame we never saw start (we joined late, or
            // lost the opening packet). Ignore.
            return None;
        }

        if descriptor_len <= payload.len() {
            self.buffer.extend_from_slice(&payload[descriptor_len..]);
        }

        if packet.header.marker && self.in_frame {
            self.in_frame = false;
            return Some(std::mem::take(&mut self.buffer));
        }

        None
    }
}

impl Default for Vp8Depacketizer {
    fn default() -> Self { Self::new() }
}

/// Returns the number of descriptor bytes before the actual VP8 payload,
/// or `None` when the packet is too short to hold the descriptor it claims.
fn parse_descriptor_len(payload: &[u8]) -> Option<usize> {
    let first = payload[0];
    let x_bit = (first & 0x80) != 0;
    let mut offset = 1usize;

    if !x_bit {
        return Some(offset);
    }

    if payload.len() < offset + 1 {
        return None;
    }
    let x = payload[offset];
    offset += 1;

    if (x & 0x80) != 0 {
        // PictureID present. The first byte's high bit says whether it is
        // one byte or two.
        if payload.len() < offset + 1 {
            return None;
        }
        let extended = (payload[offset] & 0x80) != 0;
        offset += if extended { 2 } else { 1 };
    }
    if (x & 0x40) != 0 {
        // TL0PICIDX
        offset += 1;
    }
    if (x & 0x20) != 0 || (x & 0x10) != 0 {
        // TID and/or KEYIDX share one byte.
        offset += 1;
    }

    if offset > payload.len() {
        return None;
    }
    Some(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use rtc::rtp::{Header, Packet};

    fn packet(seq: u16, marker: bool, payload: Vec<u8>) -> Packet {
        let header = Header {
            sequence_number: seq,
            marker,
            ..Default::default()
        };
        Packet { header, payload: Bytes::from(payload) }
    }

    #[test]
    fn single_packet_frame() {
        let mut d = Vp8Depacketizer::new();
        // S bit set (0x10), marker set, payload "abc"
        let p = packet(1, true, vec![0x10, b'a', b'b', b'c']);
        let frame = d.push(&p);
        assert_eq!(frame, Some(b"abc".to_vec()));
    }

    #[test]
    fn multi_packet_frame_is_reassembled() {
        let mut d = Vp8Depacketizer::new();
        let first = packet(1, false, vec![0x10, b'a', b'b']);
        let mid = packet(2, false, vec![0x00, b'c']);
        let last = packet(3, true, vec![0x00, b'd']);
        assert_eq!(d.push(&first), None);
        assert_eq!(d.push(&mid), None);
        assert_eq!(d.push(&last), Some(b"abcd".to_vec()));
    }

    #[test]
    fn sequence_gap_drops_pending_frame() {
        let mut d = Vp8Depacketizer::new();
        d.push(&packet(1, false, vec![0x10, b'a']));
        // Skip sequence 2; jump to 3.
        let frame = d.push(&packet(3, true, vec![0x10, b'b']));
        assert_eq!(frame, Some(b"b".to_vec()));
    }

    #[test]
    fn continuation_without_start_is_ignored() {
        let mut d = Vp8Depacketizer::new();
        // S bit clear, no frame in progress.
        assert_eq!(d.push(&packet(1, false, vec![0x00, b'a'])), None);
    }

    #[test]
    fn empty_payload_is_ignored() {
        let mut d = Vp8Depacketizer::new();
        assert_eq!(d.push(&packet(1, true, vec![])), None);
    }
}
