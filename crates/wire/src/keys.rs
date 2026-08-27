//! The signing primitives an envelope carries.
//!
//! Verification follows ZIP 215 through `ed25519-zebra`; the "Signature
//! verification" section of AGENTS.md covers why that rule set and not
//! another.

use core::fmt;
use std::collections::BTreeMap;

use cbor2::Cbor;
use ed25519_zebra::{Signature as ZebraSignature, VerificationKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{codec::byte_array, envelope::EnvelopeSignatureDigest};

/// An entry in the ledger's trusted key set: the key material, what its
/// signatures are worth, and whatever the operator wants to record
/// alongside it.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct Key {
    /// The key material signatures are checked against.
    #[cbor(key = 1)]
    public_key: PublicKey,
    /// What a signature by this key contributes to an envelope's weight.
    #[cbor(key = 2)]
    weight: u32,
    /// Free-form annotations — an operator name, a rotation date, a
    /// hardware token serial. Never interpreted here.
    #[cbor(key = 3)]
    metadata: BTreeMap<String, String>,
}

impl Key {
    /// A key of `weight`, carrying no metadata.
    pub fn new(public_key: PublicKey, weight: u32) -> Self {
        Self {
            public_key,
            weight,
            metadata: BTreeMap::new(),
        }
    }

    /// This key with `metadata` recorded against it.
    pub fn with_metadata(mut self, metadata: BTreeMap<String, String>) -> Self {
        self.metadata = metadata;
        self
    }

    /// The key material signatures are checked against.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// What a signature by this key contributes to an envelope's weight.
    pub fn weight(&self) -> u32 {
        self.weight
    }

    /// The annotations recorded against this key.
    pub fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }

    /// The id this key is referred to by — see [`PublicKey::id`].
    pub fn id(&self) -> KeyId {
        self.public_key.id()
    }

    /// Verifies `signature` over `digest` against this key's material.
    pub fn verify(
        &self,
        signature: &Signature,
        digest: &EnvelopeSignatureDigest,
    ) -> Result<(), SignatureError> {
        self.public_key.verify(signature, digest)
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (weight {})", self.public_key, self.weight)
    }
}

/// The key material itself, in whichever scheme produced it.
///
/// Variants are renamed to single letters to shorten their wire encoding.
#[derive(Debug, Copy, Clone, Cbor, Hash, PartialEq, Eq)]
pub enum PublicKey {
    #[serde(rename = "e")]
    Ed25519(Ed25519PublicKey),
}

impl PublicKey {
    /// The id a key is referred to by: blake3 over the *public key's*
    /// canonical encoding, which covers the scheme tag, so two schemes can
    /// never share an id however their bytes line up.
    ///
    /// Deliberately not over the whole [`Key`]: re-weighting a key or
    /// editing its metadata would otherwise change its id and orphan every
    /// signature already naming it.
    ///
    /// Consensus-critical — nodes that derive different ids resolve
    /// different keys for the same signature.
    pub fn id(&self) -> KeyId {
        let mut hasher = blake3::Hasher::new();
        crate::encode_into(self, &mut hasher).expect(
            "a PublicKey is a fixed-width byte string under a scheme tag; encoding cannot fail",
        );
        KeyId(hasher.finalize())
    }

    /// Verifies `signature` over `digest`.
    ///
    /// A key and a signature of differing schemes cannot be paired while
    /// each has one variant; a second scheme makes this match
    /// non-exhaustive, which is where that decision belongs.
    pub fn verify(
        &self,
        signature: &Signature,
        digest: &EnvelopeSignatureDigest,
    ) -> Result<(), SignatureError> {
        match (self, signature) {
            (Self::Ed25519(key), Signature::Ed25519(signature)) => key.verify(signature, digest),
        }
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519(key) => write!(f, "ed25519:{key}"),
        }
    }
}

/// A short, stable reference to a [`Key`].
///
/// Envelopes name the key that signed them by id rather than carrying it.
/// For Ed25519 that saves nothing — key and id are both 32 bytes — but a
/// post-quantum public key runs to kilobytes and would otherwise be
/// repeated in every envelope it signs. Resolving an id back to a key is
/// the ledger's business: the trusted key set is ordinary ledger state,
/// which a verifier must already consult to learn the key's weight.
///
/// Serialized as a CBOR byte string (major type 2), *not* a sequence of
/// integers.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct KeyId(blake3::Hash);

impl KeyId {
    /// The bytes representation of a key id.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Encodes a key id as a lowercase-hex string.
    pub fn to_hex(&self) -> impl AsRef<str> {
        self.0.to_hex()
    }

    /// Decodes a key id from a bytes representation. Real ones come from
    /// [`Key::id`]; this is for tooling and decoding.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(blake3::Hash::from_bytes(bytes))
    }
}

/// Ordered bytewise, so a key set can be a `BTreeMap` keyed by id.
impl Ord for KeyId {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl PartialOrd for KeyId {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_hex().as_ref())
    }
}

impl Serialize for KeyId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.as_bytes())
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        byte_array(deserializer, "a 32-byte key id").map(Self::from_bytes)
    }
}

/// A signature over an [`EnvelopeSignatureDigest`].
///
/// Variants are renamed to single letters to shorten their wire encoding.
#[derive(Debug, Copy, Clone, Cbor, Hash, PartialEq, Eq)]
pub enum Signature {
    #[serde(rename = "e")]
    Ed25519(Ed25519Signature),
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519(signature) => write!(f, "ed25519:{signature}"),
        }
    }
}

/// An Ed25519 public key, held as the 32 bytes it arrived as.
///
/// Serialized as a CBOR byte string (major type 2), *not* a sequence of
/// integers.
///
/// Decoding does not check the bytes against the curve. Under ZIP 215 a
/// key that fails to decompress makes the *signature* invalid, so
/// rejecting it here would turn an envelope every node scores at zero
/// into one some nodes cannot decode at all — the same disagreement the
/// rule set exists to prevent.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ed25519PublicKey([u8; 32]);

impl Ed25519PublicKey {
    /// Wraps the 32 bytes of an Ed25519 public key.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The bytes representation of the key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Verifies `signature` over `digest` under the ZIP 215 rules.
    pub fn verify(
        &self,
        signature: &Ed25519Signature,
        digest: &EnvelopeSignatureDigest,
    ) -> Result<(), SignatureError> {
        VerificationKey::try_from(self.0)
            .map_err(SignatureError::Ed25519)?
            .verify(
                &ZebraSignature::from_bytes(signature.as_bytes()),
                digest.as_bytes(),
            )
            .map_err(SignatureError::Ed25519)
    }
}

impl fmt::Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl Serialize for Ed25519PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Ed25519PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        byte_array(deserializer, "a 32-byte ed25519 public key").map(Self)
    }
}

/// An Ed25519 signature, held as the 64 bytes it arrived as.
///
/// Serialized as a CBOR byte string (major type 2), *not* a sequence of
/// integers.
#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub struct Ed25519Signature([u8; 64]);

impl Ed25519Signature {
    /// Wraps the 64 bytes of an Ed25519 signature.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// The bytes representation of the signature.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Hand-written because `[u8; 64]` would print as 64 separate integers.
impl fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Signature({self})")
    }
}

impl fmt::Display for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl Serialize for Ed25519Signature {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Ed25519Signature {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        byte_array(deserializer, "a 64-byte ed25519 signature").map(Self)
    }
}

/// Why a signature did not verify.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureError {
    /// Ed25519 verification failed under the ZIP 215 rules — a malformed
    /// key and a signature that simply doesn't match are both this.
    Ed25519(ed25519_zebra::Error),
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureError::Ed25519(_) => f.write_str("ed25519 signature did not verify"),
        }
    }
}

impl core::error::Error for SignatureError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            SignatureError::Ed25519(err) => Some(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_zebra::SigningKey;

    use super::*;
    use crate::testutil::assert_wire;

    fn signing_key() -> SigningKey {
        SigningKey::from([7u8; 32])
    }

    fn digest() -> EnvelopeSignatureDigest {
        EnvelopeSignatureDigest::from_bytes([0x5a; 32])
    }

    fn sign(key: &SigningKey, digest: &EnvelopeSignatureDigest) -> Signature {
        Signature::Ed25519(Ed25519Signature::from_bytes(
            key.sign(digest.as_bytes()).to_bytes(),
        ))
    }

    fn public_key(key: &SigningKey) -> PublicKey {
        PublicKey::Ed25519(Ed25519PublicKey::from_bytes(key.verification_key().into()))
    }

    /// `a1 61 65` is the one-pair map naming the `e` variant; `5820` and
    /// `5840` are the byte strings, not arrays of integers.
    #[test]
    fn keys_and_signatures_encode_as_byte_strings() {
        assert_wire(
            &PublicKey::Ed25519(Ed25519PublicKey::from_bytes([0xab; 32])),
            &format!("a161655820{}", "ab".repeat(32)),
        );
        assert_wire(
            &Signature::Ed25519(Ed25519Signature::from_bytes([0xcd; 64])),
            &format!("a161655840{}", "cd".repeat(64)),
        );
    }

    #[test]
    fn key_ids_encode_as_byte_strings() {
        assert_wire(
            &KeyId::from_bytes([0xef; 32]),
            &format!("5820{}", "ef".repeat(32)),
        );
    }

    /// Ids are derived, never assigned: the same key always yields the
    /// same id, and different keys never share one.
    #[test]
    fn key_ids_are_derived_from_the_public_key() {
        let public_key = PublicKey::Ed25519(Ed25519PublicKey::from_bytes([0xab; 32]));

        assert_eq!(public_key.id(), public_key.id());
        assert_ne!(
            public_key.id(),
            PublicKey::Ed25519(Ed25519PublicKey::from_bytes([0xac; 32])).id()
        );

        // Pinned against the rule itself — blake3 over the canonical
        // encoding — rather than a captured constant.
        assert_eq!(
            public_key.id().as_bytes(),
            blake3::hash(&crate::encode(&public_key).unwrap()).as_bytes(),
        );
    }

    /// Weight and metadata sit outside the id, so a key can be re-weighted
    /// or annotated without orphaning signatures that already name it.
    #[test]
    fn re_weighting_a_key_does_not_change_its_id() {
        let public_key = PublicKey::Ed25519(Ed25519PublicKey::from_bytes([0xab; 32]));
        let key = Key::new(public_key, 1);

        let heavier = Key::new(public_key, 9).with_metadata(BTreeMap::from([(
            "operator".to_string(),
            "alice".to_string(),
        )]));

        assert_ne!(key, heavier);
        assert_eq!(key.id(), heavier.id());
        assert_eq!(key.id(), public_key.id());
    }

    /// The key material under `01`, the weight under `02`, the metadata
    /// map under `03`.
    #[test]
    fn a_key_encodes_its_weight_and_metadata() {
        assert_wire(
            &Key::new(
                PublicKey::Ed25519(Ed25519PublicKey::from_bytes([0xab; 32])),
                7,
            ),
            &format!("a301a161655820{}020703a0", "ab".repeat(32)),
        );
    }

    #[test]
    fn decoding_rejects_the_wrong_length() {
        let short = format!("a16165581f{}", "ab".repeat(31));
        assert!(crate::decode::<PublicKey>(&crate::testutil::unhex(&short)).is_err());
    }

    #[test]
    fn a_signature_verifies_under_its_own_key() {
        let key = signing_key();
        assert_eq!(
            public_key(&key).verify(&sign(&key, &digest()), &digest()),
            Ok(())
        );
    }

    #[test]
    fn a_signature_over_another_digest_does_not_verify() {
        let key = signing_key();
        let signature = sign(&key, &EnvelopeSignatureDigest::from_bytes([0x01; 32]));
        assert!(public_key(&key).verify(&signature, &digest()).is_err());
    }

    /// A key that isn't a curve point decodes fine and fails verification;
    /// it must never be a decode error. See [`Ed25519PublicKey`].
    /// `[0xab; 32]` does not decompress, which is also what the wire test
    /// above encodes.
    #[test]
    fn a_malformed_key_decodes_and_fails_verification() {
        let encoded = format!("a161655820{}", "ab".repeat(32));
        let key: PublicKey = crate::decode(&crate::testutil::unhex(&encoded)).unwrap();

        let signature = sign(&signing_key(), &digest());
        assert_eq!(
            key.verify(&signature, &digest()),
            Err(SignatureError::Ed25519(
                ed25519_zebra::Error::MalformedPublicKey
            ))
        );
    }
}
