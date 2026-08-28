//! The messages peers exchange, in the order a pull session speaks them.
//!
//! Everything here is canonical CBOR with integer keys, moved through
//! [`wire::encode`] and [`wire::decode`] like the ledger wire itself.
//! Envelopes travel as their canonical encoding and nothing else: a
//! receiver re-derives digests and re-verifies signatures, and neither
//! the verification status (`#[serde(skip)]` in [`wire`]) nor a node's
//! `StoredAt` ever crosses the wire.

use core::fmt;

use cbor2::Cbor;
use wire::{Envelope, EnvelopeDigest};

/// Each side's first frame: protocol version and the current HEAD.
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq)]
pub struct Hello {
    /// Must equal [`PROTOCOL_VERSION`](crate::PROTOCOL_VERSION) exactly.
    #[cbor(key = 1)]
    pub version: u32,
    /// The canonical head this node stands at.
    #[cbor(key = 2)]
    pub head: EnvelopeDigest,
}

/// The puller's canonical path sampled newest-first — see
/// [`locator::sample`](crate::locator::sample) — asking the server where
/// the paths part.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct FindSplit {
    #[cbor(key = 1)]
    pub locator: Vec<EnvelopeDigest>,
}

/// The newest locator entry on the server's canonical path; the stream
/// that follows starts just after it.
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq)]
pub struct Split {
    #[cbor(key = 1)]
    pub at: EnvelopeDigest,
}

/// No locator entry is in the server's log: the chains share nothing,
/// and only checkpoint sync (unbuilt) could go further.
#[derive(Debug, Copy, Clone, Default, Cbor, PartialEq, Eq)]
pub struct NoSplit {}

/// One parent-first run of the server's canonical path. Never empty,
/// never more than [`MAX_BATCH_ENVELOPES`](crate::MAX_BATCH_ENVELOPES).
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Envelopes {
    #[cbor(key = 1)]
    pub batch: Vec<Envelope>,
}

/// Ends the stream cleanly. Carries nothing: the puller computed every
/// digest it ingested, so it already knows the head it was caught up
/// to — this marker's whole job is distinguishing a finished stream from
/// a connection that died mid-way.
#[derive(Debug, Copy, Clone, Default, Cbor, PartialEq, Eq)]
pub struct CaughtUp {}

/// A frame on the peer wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Hello(Hello),
    FindSplit(FindSplit),
    Split(Split),
    NoSplit(NoSplit),
    Envelopes(Envelopes),
    CaughtUp(CaughtUp),
}

/// Implements the wire representation of an all-newtype-variant enum: a
/// one-pair map under an integer tag (`{1: …}`), the shape [`wire`] gives
/// its message enums. Unlike `wire`'s `dual_repr!` there is no
/// human-readable dual — these messages exist only on the peer wire.
macro_rules! wire_tags {
    ($name:ident { $($variant:ident($ty:ty) = $tag:literal),+ $(,)? }) => {
        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::core::result::Result<S::Ok, S::Error> {
                use ::serde::ser::SerializeMap as _;
                let mut map = serializer.serialize_map(Some(1))?;
                match self {
                    $($name::$variant(v) => map.serialize_entry::<u64, $ty>(&$tag, v)?,)+
                }
                map.end()
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> ::core::result::Result<Self, D::Error> {
                struct WireVisitor;

                impl<'de> ::serde::de::Visitor<'de> for WireVisitor {
                    type Value = $name;

                    fn expecting(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                        f.write_str(concat!("a one-pair map tagging a ", stringify!($name)))
                    }

                    fn visit_map<A: ::serde::de::MapAccess<'de>>(
                        self,
                        mut map: A,
                    ) -> ::core::result::Result<Self::Value, A::Error> {
                        let tag = map
                            .next_key::<u64>()?
                            .ok_or_else(|| ::serde::de::Error::invalid_length(0, &self))?;
                        let value = match tag {
                            $($tag => $name::$variant(map.next_value()?),)+
                            _ => {
                                return Err(::serde::de::Error::invalid_value(
                                    ::serde::de::Unexpected::Unsigned(tag),
                                    &self,
                                ));
                            }
                        };
                        match map.next_key::<::serde::de::IgnoredAny>()? {
                            None => Ok(value),
                            Some(_) => Err(::serde::de::Error::invalid_length(2, &self)),
                        }
                    }
                }

                deserializer.deserialize_map(WireVisitor)
            }
        }
    };
}

wire_tags! {
    Message {
        Hello(Hello) = 1,
        FindSplit(FindSplit) = 2,
        Split(Split) = 3,
        NoSplit(NoSplit) = 4,
        Envelopes(Envelopes) = 5,
        CaughtUp(CaughtUp) = 6,
    }
}

impl Message {
    /// Which message this is, for breach diagnostics.
    pub fn kind(&self) -> MessageKind {
        match self {
            Message::Hello(_) => MessageKind::Hello,
            Message::FindSplit(_) => MessageKind::FindSplit,
            Message::Split(_) => MessageKind::Split,
            Message::NoSplit(_) => MessageKind::NoSplit,
            Message::Envelopes(_) => MessageKind::Envelopes,
            Message::CaughtUp(_) => MessageKind::CaughtUp,
        }
    }
}

/// A [`Message`]'s name without its payload.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MessageKind {
    Hello,
    FindSplit,
    Split,
    NoSplit,
    Envelopes,
    CaughtUp,
}

impl fmt::Display for MessageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MessageKind::Hello => "Hello",
            MessageKind::FindSplit => "FindSplit",
            MessageKind::Split => "Split",
            MessageKind::NoSplit => "NoSplit",
            MessageKind::Envelopes => "Envelopes",
            MessageKind::CaughtUp => "CaughtUp",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{assert_wire, digest_of, hex_digest, set, unhex};

    fn d(byte: u8) -> EnvelopeDigest {
        EnvelopeDigest::from_bytes([byte; 32])
    }

    /// `a2` (map, 2 pairs): version, then the head as a bare byte string,
    /// exactly as `wire` encodes digests.
    #[test]
    fn hello_pins_its_encoding() {
        let hello = Hello {
            version: 1,
            head: d(0xcd),
        };
        assert_wire(&hello, &format!("a20101025820{}", "cd".repeat(32)));
        assert_wire(
            &Message::Hello(hello),
            &format!("a101a20101025820{}", "cd".repeat(32)),
        );
    }

    /// Every variant wraps as a one-pair map under its integer tag.
    #[test]
    fn message_variants_pin_their_tags() {
        assert_wire(
            &Message::FindSplit(FindSplit {
                locator: vec![d(0x11), d(0x22)],
            }),
            &format!("a102a101825820{}5820{}", "11".repeat(32), "22".repeat(32)),
        );
        assert_wire(
            &Message::Split(Split { at: d(0x33) }),
            &format!("a103a1015820{}", "33".repeat(32)),
        );
        assert_wire(&Message::NoSplit(NoSplit {}), "a104a0");
        assert_wire(&Message::CaughtUp(CaughtUp {}), "a106a0");
    }

    /// An envelope inside a batch is byte-for-byte the ledger-wire
    /// envelope encoding — nothing sync-specific wraps it.
    #[test]
    fn envelopes_carry_ledger_wire_encodings() {
        let envelope = set(d(0xab), "a", "1");
        let message = Message::Envelopes(Envelopes {
            batch: vec![envelope.clone()],
        });
        assert_wire(
            &message,
            &format!(
                "a105a10181{}",
                crate::testutil::hex(&wire::encode(&envelope).unwrap())
            ),
        );
    }

    /// The batch round-trip is what strips local state: a decoded copy is
    /// `Unchecked` however its sender had verified it.
    #[test]
    fn a_round_tripped_envelope_arrives_unchecked() {
        let mut envelope = set(d(0xab), "a", "1");
        envelope.set_verification_status(wire::VerificationStatus::AllMatched { total_weight: 7 });
        let sent = Message::Envelopes(Envelopes {
            batch: vec![envelope],
        });

        let received: Message = wire::decode(&wire::encode(&sent).unwrap()).unwrap();
        let Message::Envelopes(Envelopes { batch }) = received else {
            panic!("the tag must round-trip");
        };
        assert_eq!(
            batch[0].verification_status(),
            &wire::VerificationStatus::Unchecked
        );
    }

    #[test]
    fn unknown_tags_and_padded_maps_are_rejected() {
        // Tag 7 names no message.
        assert!(wire::decode::<Message>(&unhex("a107a0")).is_err());
        // A two-pair map is not a tagged message, even with a valid first
        // pair: {4: {}, 4: {}}.
        assert!(wire::decode::<Message>(&unhex("a204a004a0")).is_err());
        // The empty map carries no tag at all.
        assert!(wire::decode::<Message>(&unhex("a0")).is_err());
    }

    /// `MessageKind` names every variant, which breach diagnostics print.
    #[test]
    fn message_kinds_name_their_variants() {
        assert_eq!(Message::NoSplit(NoSplit {}).kind(), MessageKind::NoSplit);
        assert_eq!(MessageKind::FindSplit.to_string(), "FindSplit");
        assert_eq!(
            Message::CaughtUp(CaughtUp {}).kind().to_string(),
            "CaughtUp"
        );
    }

    /// Guards the helper the other tests lean on: `digest_of` matches
    /// `Envelope::digest`.
    #[test]
    fn testutil_digest_matches_wire() {
        let envelope = set(d(0xab), "a", "1");
        assert_eq!(digest_of(&envelope), envelope.digest().unwrap());
        assert_eq!(
            hex_digest(&digest_of(&envelope)),
            envelope.digest().unwrap().to_hex().as_ref()
        );
    }
}
