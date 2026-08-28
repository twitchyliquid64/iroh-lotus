//! Length-prefixed canonical CBOR framing, as a [`tokio_util::codec`]
//! pair.
//!
//! A frame is a four-byte big-endian length followed by that many bytes
//! of canonical CBOR. The prefix bounds what a peer can make us allocate:
//! a frame claiming more than [`MAX_FRAME_LEN`] is a protocol error, not
//! a large read. The codec traits are pure `BytesMut` transforms — no
//! runtime, no socket — which is what keeps this layer sans-io; pairing
//! the codec with a stream via `Framed` is the driver's business.

use tokio_util::{
    bytes::{Buf, BufMut, BytesMut},
    codec::{Decoder, Encoder},
};

use crate::{Error, proto::Message};

/// The largest frame body either side will read or write.
///
/// Comfortably above any sane envelope: an envelope bigger than a frame
/// cannot be synced at all, so until the ledger bounds envelope size
/// itself, this is the bound.
pub const MAX_FRAME_LEN: u32 = 1 << 24;

/// Frames [`Message`]s on and off a byte stream.
#[derive(Debug, Default)]
pub struct Codec;

impl Decoder for Codec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Message>, Error> {
        let Some(prefix) = src.get(..4) else {
            return Ok(None);
        };
        let len = u32::from_be_bytes(prefix.try_into().expect("the slice is four bytes"));
        if len > MAX_FRAME_LEN {
            return Err(Error::FrameTooLarge(len.into()));
        }

        let frame = 4 + len as usize;
        if src.len() < frame {
            src.reserve(frame - src.len());
            return Ok(None);
        }

        src.advance(4);
        let body = src.split_to(len as usize);
        wire::decode(&body).map(Some).map_err(Error::Wire)
    }
}

impl Encoder<Message> for Codec {
    type Error = Error;

    fn encode(&mut self, message: Message, dst: &mut BytesMut) -> Result<(), Error> {
        let body = wire::encode(&message).map_err(Error::Wire)?;
        let len = u32::try_from(body.len())
            .ok()
            .filter(|&len| len <= MAX_FRAME_LEN)
            .ok_or(Error::FrameTooLarge(body.len() as u64))?;

        dst.reserve(4 + body.len());
        dst.put_u32(len);
        dst.put_slice(&body);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proto::{CaughtUp, Envelopes, NoSplit, Split},
        testutil::set,
    };
    use wire::EnvelopeDigest;

    fn d(byte: u8) -> EnvelopeDigest {
        EnvelopeDigest::from_bytes([byte; 32])
    }

    fn encode(message: Message) -> BytesMut {
        let mut buffer = BytesMut::new();
        Codec.encode(message, &mut buffer).unwrap();
        buffer
    }

    #[test]
    fn a_frame_round_trips() {
        let sent = Message::Envelopes(Envelopes {
            batch: vec![set(d(0xab), "a", "1"), set(d(0xcd), "b", "2")],
        });

        let mut buffer = encode(sent.clone());
        assert_eq!(Codec.decode(&mut buffer).unwrap(), Some(sent));
        assert!(buffer.is_empty(), "the frame is consumed exactly");
    }

    /// The decoder is incremental: it answers `None` on a partial prefix
    /// and a partial body, then yields once the frame completes.
    #[test]
    fn decoding_waits_for_a_full_frame() {
        let sent = Message::Split(Split { at: d(0x11) });
        let frame = encode(sent.clone());

        let mut buffer = BytesMut::new();
        for &byte in &frame[..frame.len() - 1] {
            buffer.put_u8(byte);
            assert_eq!(Codec.decode(&mut buffer).unwrap(), None);
        }
        buffer.put_u8(frame[frame.len() - 1]);
        assert_eq!(Codec.decode(&mut buffer).unwrap(), Some(sent));
    }

    /// Back-to-back frames in one buffer decode one call at a time — the
    /// remainder stays for the next call, as `Framed` expects.
    #[test]
    fn frames_decode_back_to_back() {
        let first = Message::NoSplit(NoSplit {});
        let second = Message::CaughtUp(CaughtUp {});

        let mut buffer = encode(first.clone());
        buffer.extend_from_slice(&encode(second.clone()));

        assert_eq!(Codec.decode(&mut buffer).unwrap(), Some(first));
        assert_eq!(Codec.decode(&mut buffer).unwrap(), Some(second));
        assert_eq!(Codec.decode(&mut buffer).unwrap(), None);
    }

    /// The length prefix is judged before any body is read, so an
    /// oversized claim costs nothing to refuse.
    #[test]
    fn an_oversized_length_prefix_is_refused() {
        let mut buffer = BytesMut::new();
        buffer.put_u32(MAX_FRAME_LEN + 1);
        assert!(matches!(
            Codec.decode(&mut buffer),
            Err(Error::FrameTooLarge(len)) if len == u64::from(MAX_FRAME_LEN) + 1
        ));
    }

    #[test]
    fn a_garbage_body_is_a_codec_error() {
        let mut buffer = BytesMut::new();
        buffer.put_u32(1);
        buffer.put_u8(0xff);
        assert!(matches!(Codec.decode(&mut buffer), Err(Error::Wire(_))));
    }

    /// A message too large to frame is refused at encode time rather than
    /// written truncated or oversize.
    #[test]
    fn an_oversized_message_is_refused_at_encode() {
        let huge = "x".repeat(MAX_FRAME_LEN as usize + 1);
        let message = Message::Envelopes(Envelopes {
            batch: vec![set(d(0xab), "a", &huge)],
        });

        let mut buffer = BytesMut::new();
        assert!(matches!(
            Codec.encode(message, &mut buffer),
            Err(Error::FrameTooLarge(_))
        ));
        assert!(buffer.is_empty(), "nothing may be written on refusal");
    }
}
