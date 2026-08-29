//! The out-of-band half of joining a cluster: one string an operator
//! carries from a running node to a blank one.
//!
//! An invite names the sponsor — its node id and the endpoint to dial —
//! pins the root the joiner will build on, and carries the bearer token
//! the sponsor admits it by. The endpoint id is what iroh authenticates
//! the connection against and the root digest is what the joiner checks
//! the first envelope against, so between them the joiner knows it has
//! reached the cluster it was invited to before it trusts a single key
//! the chain installs.
//!
//! The text form is a fixed prefix over the invite's canonical CBOR in
//! unpadded base32, lower case: one word that survives a chat message, a
//! terminal, and a double-click.

use core::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cbor2::Cbor;
use data_encoding::BASE32_NOPAD;
use iroh::EndpointAddr;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use wire::{EnvelopeDigest, KeyId};

/// What every invite text starts with. The digit is the format version:
/// a text this build cannot read fails on the prefix, not on the CBOR.
pub const PREFIX: &str = "lotus1";

/// The invite format spoken by this build. Exact match required.
pub const VERSION: u32 = 1;

/// The bearer token a sponsor admits a joiner by: 32 random bytes, drawn
/// once per invite and forgotten once redeemed.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Token([u8; 32]);

impl Token {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether `other` is this token, taking the same time whichever byte
    /// differs first: a redeem is an attacker's one chance to compare
    /// against a token it never saw, and must learn nothing from it.
    pub fn matches(&self, other: &Token) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

impl fmt::Debug for Token {
    /// Never the bytes: a token in a log is a token leaked.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(..)")
    }
}

impl Serialize for Token {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Token {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BytesVisitor;

        impl serde::de::Visitor<'_> for BytesVisitor {
            type Value = Token;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 32-byte token")
            }

            fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Token, E> {
                <[u8; 32]>::try_from(bytes)
                    .map(Token)
                    .map_err(|_| E::invalid_length(bytes.len(), &self))
            }
        }

        deserializer.deserialize_bytes(BytesVisitor)
    }
}

/// Everything a blank node needs to join: who to dial, what to expect
/// from them, and the token that gets it admitted.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Invite {
    /// Must equal [`VERSION`] exactly.
    #[cbor(key = 1)]
    pub version: u32,
    /// The node id of the sponsor — the key that will sign the admission.
    /// The joiner checks it is among the keys the chain it pulled trusts.
    #[cbor(key = 2)]
    pub sponsor: KeyId,
    /// Where to reach the sponsor. The endpoint id in it is the trust
    /// anchor: iroh refuses a connection to anyone else under it.
    #[cbor(key = 3)]
    pub endpoint: EndpointAddr,
    /// The oldest envelope the sponsor holds, which the joiner roots its
    /// chain at. Pinned here so the sponsor cannot hand over a different
    /// one than the operator saw invited.
    #[cbor(key = 4)]
    pub root: EnvelopeDigest,
    #[cbor(key = 5)]
    pub token: Token,
    /// When the sponsor stops honouring the token, in milliseconds since
    /// the unix epoch on the sponsor's clock. Informational: the sponsor
    /// enforces it, this only lets a joiner say why it was refused.
    #[cbor(key = 6)]
    pub expires_at_millis: i64,
}

impl Invite {
    /// The invite as one word: [`PREFIX`] over the canonical CBOR in
    /// lower-case unpadded base32.
    pub fn encode(&self) -> Result<String, wire::Error> {
        let body = wire::encode(self)?;
        Ok(format!(
            "{PREFIX}{}",
            BASE32_NOPAD.encode(&body).to_ascii_lowercase()
        ))
    }

    /// Reads back what [`encode`](Self::encode) wrote. Whitespace around
    /// the word is forgiven; nothing inside it is.
    pub fn decode(text: &str) -> Result<Self, DecodeError> {
        let body = text
            .trim()
            .strip_prefix(PREFIX)
            .ok_or(DecodeError::Prefix)?;
        let bytes = BASE32_NOPAD
            .decode(body.to_ascii_uppercase().as_bytes())
            .map_err(|_| DecodeError::Base32)?;
        let invite: Invite = wire::decode(&bytes).map_err(DecodeError::Wire)?;
        if invite.version != VERSION {
            return Err(DecodeError::Version(invite.version));
        }
        Ok(invite)
    }

    /// How long until the invite expires, by this clock; zero once it has.
    pub fn expires_in(&self, now: SystemTime) -> Duration {
        let now = now.duration_since(UNIX_EPOCH).map_or(0, |since| {
            i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
        });
        Duration::from_millis(u64::try_from(self.expires_at_millis - now).unwrap_or(0))
    }
}

/// Why a text is not an invite.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("not an invite: expected it to start with `{PREFIX}`")]
    Prefix,
    #[error("not an invite: the text after `{PREFIX}` is not base32")]
    Base32,
    #[error("not an invite: the encoded invite does not decode")]
    Wire(#[source] wire::Error),
    #[error("the invite is format version {0}; this build speaks version {VERSION}")]
    Version(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite() -> Invite {
        Invite {
            version: VERSION,
            sponsor: KeyId::from_bytes([7; 32]),
            endpoint: EndpointAddr::new(iroh::SecretKey::from_bytes(&[9; 32]).public()),
            root: EnvelopeDigest::from_bytes([3; 32]),
            token: Token::from_bytes([5; 32]),
            expires_at_millis: 1_700_000_000_000,
        }
    }

    #[test]
    fn an_invite_round_trips_as_one_lower_case_word() {
        let text = invite().encode().unwrap();
        assert!(text.starts_with(PREFIX));
        assert!(
            text.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "{text}"
        );
        assert_eq!(Invite::decode(&text).unwrap(), invite());
        assert_eq!(Invite::decode(&format!("  {text}\n")).unwrap(), invite());
    }

    #[test]
    fn a_token_travels_as_a_byte_string() {
        let text = invite().encode().unwrap();
        let bytes = BASE32_NOPAD
            .decode(text[PREFIX.len()..].to_ascii_uppercase().as_bytes())
            .unwrap();
        // `58 20` is a 32-byte string; the token would be 32 ints without
        // the custom impl.
        let needle: Vec<u8> = [0x58, 0x20].into_iter().chain([5u8; 32]).collect();
        assert!(bytes.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn a_wrong_prefix_or_body_is_refused() {
        assert!(matches!(
            Invite::decode("lotus2abc"),
            Err(DecodeError::Prefix)
        ));
        assert!(matches!(Invite::decode("abc"), Err(DecodeError::Prefix)));
        assert!(matches!(
            Invite::decode("lotus1!!!"),
            Err(DecodeError::Base32)
        ));
        assert!(matches!(
            Invite::decode("lotus1aaaa"),
            Err(DecodeError::Wire(_))
        ));
    }

    #[test]
    fn a_future_version_is_refused_by_number() {
        let mut future = invite();
        future.version = VERSION + 1;
        let text = future.encode().unwrap();
        assert!(matches!(
            Invite::decode(&text),
            Err(DecodeError::Version(v)) if v == VERSION + 1
        ));
    }

    #[test]
    fn tokens_compare_whole() {
        let a = Token::from_bytes([1; 32]);
        let mut b = [1; 32];
        b[31] = 2;
        assert!(a.matches(&a));
        assert!(!a.matches(&Token::from_bytes(b)));
        assert_eq!(format!("{a:?}"), "Token(..)");
    }

    #[test]
    fn expiry_counts_down_to_zero() {
        let invite = invite();
        let at = |millis: u64| UNIX_EPOCH + Duration::from_millis(millis);
        assert_eq!(
            invite.expires_in(at(1_700_000_000_000 - 1_500)),
            Duration::from_millis(1_500)
        );
        assert_eq!(invite.expires_in(at(1_700_000_000_000)), Duration::ZERO);
        assert_eq!(invite.expires_in(at(1_800_000_000_000)), Duration::ZERO);
    }
}
