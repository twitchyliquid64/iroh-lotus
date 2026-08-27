use cbor2::Cbor;

use crate::{
    Error,
    codec::byte_array,
    keys::{Key, KeyId, Signature, SignatureError},
};

/// The cached state of signature verification for an envelope.
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
pub enum VerificationStatus {
    #[default]
    Unchecked,
    Failed,
    AllMatched {
        total_weight: u32,
    },
}

impl VerificationStatus {
    /// The verified signature weight of this envelope; zero until
    /// verification has succeeded.
    pub fn signature_weight(&self) -> u32 {
        match self {
            Self::Unchecked | Self::Failed => 0,
            Self::AllMatched { total_weight } => *total_weight,
        }
    }
}

/// Container type for a message in the ledger.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct Envelope {
    /// The message contained within the envelope.
    #[cbor(key = 1)]
    payload: super::Msg,

    /// Signatures over the entire envelope. Digest which is signed
    /// is computed with an empty signatures vector.
    #[cbor(key = 2)]
    signatures: Vec<EnvelopeSignature>,
    /// Assertions of the time this envelope was created, signed by
    /// a TSA.
    #[cbor(key = 3)]
    timestamps: Vec<SignedTimestamp>,

    /// Never on the wire and excluded from the digest, but storage
    /// backends must persist it — see `Storage::put_envelope`'s contract
    /// in the storage crate.
    #[serde(skip)]
    verification_status: VerificationStatus,
}

impl Envelope {
    /// A new envelope carrying `payload`, with nothing attested over it yet.
    pub fn new(payload: super::Msg) -> Self {
        Self {
            payload,
            signatures: Vec::new(),
            timestamps: Vec::new(),
            verification_status: VerificationStatus::Unchecked,
        }
    }

    /// The message this envelope carries.
    pub fn payload(&self) -> &super::Msg {
        &self.payload
    }

    /// The signatures attached to this envelope.
    pub fn signatures(&self) -> &[EnvelopeSignature] {
        &self.signatures
    }

    /// The timestamps attested over this envelope.
    pub fn timestamps(&self) -> &[SignedTimestamp] {
        &self.timestamps
    }

    /// The verification status of this envelope.
    pub fn verification_status(&self) -> &VerificationStatus {
        &self.verification_status
    }

    /// Records the outcome of signature verification. The status lives
    /// outside the canonical encoding, so this never changes the
    /// envelope's digest.
    pub fn set_verification_status(&mut self, status: VerificationStatus) {
        self.verification_status = status;
    }

    /// The digest of this envelope, taken over its canonical CBOR encoding.
    ///
    /// The digest covers the whole envelope, signatures and timestamps
    /// included, so it changes as they are attached.
    pub fn digest(&self) -> Result<EnvelopeDigest, Error> {
        let mut hasher = blake3::Hasher::new();
        crate::encode_into(self, &mut hasher)?;
        Ok(EnvelopeDigest(hasher.finalize()))
    }

    /// The digest this envelope's signatures are taken over: the same
    /// encoding as [`digest`](Self::digest) but with an empty signatures
    /// array, so attaching one signature doesn't invalidate the next.
    ///
    /// Timestamps are *not* stripped, so every timestamp must be attached
    /// before the envelope is signed.
    pub fn signature_digest(&self) -> Result<EnvelopeSignatureDigest, Error> {
        let mut hasher = blake3::Hasher::new();
        crate::encode_into(
            &SignedPortion {
                payload: &self.payload,
                signatures: [],
                timestamps: &self.timestamps,
            },
            &mut hasher,
        )?;
        Ok(EnvelopeSignatureDigest(hasher.finalize()))
    }

    /// This envelope with `signature` attached.
    pub fn with_signature(mut self, signature: EnvelopeSignature) -> Self {
        self.signatures.push(signature);
        self
    }
}

/// What [`Envelope::signature_digest`] hashes: [`Envelope`]'s own CBOR keys
/// with nothing at the signatures key. Generic so the fields can be
/// borrowed — the `Deserialize` the derive also emits is unreachable for
/// the reference types this is used with, and unused.
#[derive(Cbor)]
struct SignedPortion<P, T> {
    #[cbor(key = 1)]
    payload: P,
    #[cbor(key = 2)]
    signatures: [EnvelopeSignature; 0],
    #[cbor(key = 3)]
    timestamps: T,
}

/// A signature over an envelope, naming the key that produced it.
///
/// The key is named by [`KeyId`], not carried: resolving it is the
/// ledger's business, and a verifier must consult the key set for the
/// key's weight regardless.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct EnvelopeSignature {
    /// The key the signature is weighed under.
    #[cbor(key = 1)]
    key_id: KeyId,
    /// The signature over the envelope's [`EnvelopeSignatureDigest`].
    #[cbor(key = 2)]
    signature: Signature,
}

impl EnvelopeSignature {
    /// A signature naming the key that produced it. Nothing is checked
    /// here; [`verify`](Self::verify) is the only thing that decides.
    pub fn new(key_id: KeyId, signature: Signature) -> Self {
        Self { key_id, signature }
    }

    /// The id of the key the signature is weighed under.
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The signature itself.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Verifies this signature against `digest`, which must come from
    /// [`Envelope::signature_digest`] on the envelope carrying it.
    ///
    /// `key` is the resolved [`Self::key_id`]; handing over a different
    /// key is a [`SignatureError::KeyMismatch`] rather than a silent
    /// verification failure.
    pub fn verify(
        &self,
        key: &Key,
        digest: &EnvelopeSignatureDigest,
    ) -> Result<(), SignatureError> {
        let given = key.id();
        if given != self.key_id {
            return Err(SignatureError::KeyMismatch {
                named: self.key_id,
                given,
            });
        }
        key.verify(&self.signature, digest)
    }
}

/// A timestamp over an envelope, attested by a signature.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct SignedTimestamp {}

/// A digest over the entire envelope, i.e. a message in the ledger.
///
/// Serialized as a CBOR byte string (major type 2), *not* a sequence
/// of integers.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct EnvelopeDigest(blake3::Hash);

/// Ordered by the digest's numeric value: bytewise over the 32 bytes,
/// ala big-endian number. Used as the final tie-breaker for fork resolution.
impl Ord for EnvelopeDigest {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl PartialOrd for EnvelopeDigest {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl serde::Serialize for EnvelopeDigest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0.as_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for EnvelopeDigest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        byte_array(deserializer, "a 32-byte envelope digest").map(Self::from_bytes)
    }
}

/// The digest an envelope's signatures are taken over.
///
/// Distinct from [`EnvelopeDigest`] on purpose: an envelope's own digest
/// covers its signatures, so signing it would be circular. Never on the
/// wire — it is derived from the envelope by both signer and verifier.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct EnvelopeSignatureDigest(blake3::Hash);

impl EnvelopeSignatureDigest {
    /// Returns the bytes representation of a signature digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Encodes a signature digest as a lowercase-hex string.
    pub fn to_hex(&self) -> impl AsRef<str> {
        self.0.to_hex()
    }

    /// Decodes a signature digest from a bytes representation. For tests
    /// and tooling; real ones come from [`Envelope::signature_digest`].
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(blake3::Hash::from_bytes(bytes))
    }
}

impl EnvelopeDigest {
    /// Returns the bytes representation of an envelope digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Returns a slice representation of an envelope digest.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Decodes an envelope digest from a lowercase-hex representation.
    pub fn from_hex(hex: impl AsRef<[u8]>) -> Result<Self, blake3::HexError> {
        Ok(EnvelopeDigest(blake3::Hash::from_hex(hex)?))
    }

    /// Encodes an envelope digest as a lowercase-hex string.
    pub fn to_hex(&self) -> impl AsRef<str> {
        self.0.to_hex()
    }

    /// Decodes an envelope digest from a bytes representation.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        EnvelopeDigest(blake3::Hash::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        keys::{Ed25519PublicKey, Ed25519Signature, PublicKey, SignatureError},
        testutil::{assert_wire, hex, unhex},
    };

    /// The canonical encoding of an `Init` envelope carrying no signatures
    /// and no timestamps.
    //  a3                     map(3)
    //    01                   payload
    //      a1 61 69           Msg::Init
    //        a1 01            InitMsg.state
    //          a1 01 a0       FullCheckpoint { namespaces: {} }
    //    02 80                signatures = []
    //    03 80                timestamps = []
    const INIT_ENVELOPE: &str = "a301a16169a101a101a002800380";

    /// Round-trips the bytes rather than constructing a `Msg`, whose fields
    /// are private to its module.
    fn init_envelope() -> Envelope {
        crate::decode(&unhex(INIT_ENVELOPE)).unwrap()
    }

    #[test]
    fn envelope_wraps_payload_under_integer_key() {
        assert_eq!(
            hex(&crate::encode(&init_envelope()).unwrap()),
            INIT_ENVELOPE
        );
    }

    /// A signature: the key id under `01` as a bare byte string, the
    /// signature under `02` as a one-pair map naming its scheme.
    fn signature() -> EnvelopeSignature {
        EnvelopeSignature::new(
            KeyId::from_bytes([0xef; 32]),
            Signature::Ed25519(Ed25519Signature::from_bytes([0xcd; 64])),
        )
    }

    fn signature_hex() -> String {
        format!("a2015820{}02a161655840{}", "ef".repeat(32), "cd".repeat(64))
    }

    /// `SignedTimestamp` is still an empty map (`a0`), so a populated list
    /// is `81 a0`. Adding fields to it grows that map rather than changing
    /// its major type.
    #[test]
    fn signatures_and_timestamps_encode_as_arrays() {
        assert_wire(&signature(), &signature_hex());
        assert_wire(&SignedTimestamp {}, "a0");

        let signed = init_envelope().with_signature(signature());
        assert_wire(
            &signed,
            &format!("a301a16169a101a101a00281{}0380", signature_hex()),
        );

        let stamped = Envelope {
            timestamps: vec![SignedTimestamp {}],
            ..init_envelope()
        };
        assert_wire(&stamped, "a301a16169a101a101a002800381a0");
    }

    /// The whole point of the second digest: a signer signs what the next
    /// signer will also sign, however many are already attached.
    #[test]
    fn signature_digest_ignores_attached_signatures() {
        let envelope = init_envelope();
        let unsigned = envelope.signature_digest().unwrap();

        let signed = envelope
            .with_signature(signature())
            .with_signature(signature());
        assert_eq!(signed.signature_digest().unwrap(), unsigned);
        assert_ne!(signed.digest().unwrap(), init_envelope().digest().unwrap());
    }

    /// With no signatures attached there is nothing to strip, so the two
    /// digests must agree — which is what pins `SignedPortion` to
    /// `Envelope`'s own encoding.
    #[test]
    fn signature_digest_matches_the_digest_of_an_unsigned_envelope() {
        let envelope = init_envelope();
        assert_eq!(
            envelope.signature_digest().unwrap().as_bytes(),
            envelope.digest().unwrap().as_bytes(),
        );
    }

    /// End to end: sign an envelope's signature digest, name the key by
    /// id, and verify against the resolved key. A different key is refused
    /// outright rather than failing as a bad signature.
    #[test]
    fn a_signature_verifies_against_the_key_it_names() {
        let signing = ed25519_zebra::SigningKey::from([7u8; 32]);
        let key = Key::new(
            PublicKey::Ed25519(Ed25519PublicKey::from_bytes(
                signing.verification_key().into(),
            )),
            1,
        );

        let envelope = init_envelope();
        let digest = envelope.signature_digest().unwrap();
        let attached = EnvelopeSignature::new(
            key.id(),
            Signature::Ed25519(Ed25519Signature::from_bytes(
                signing.sign(digest.as_bytes()).to_bytes(),
            )),
        );

        assert_eq!(attached.verify(&key, &digest), Ok(()));

        let other = Key::new(
            PublicKey::Ed25519(Ed25519PublicKey::from_bytes([0x01; 32])),
            1,
        );
        assert_eq!(
            attached.verify(&other, &digest),
            Err(SignatureError::KeyMismatch {
                named: key.id(),
                given: other.id(),
            })
        );
    }

    /// Only signatures are stripped, so a timestamp attached after signing
    /// invalidates every signature already there.
    #[test]
    fn signature_digest_covers_timestamps() {
        let stamped = Envelope {
            timestamps: vec![SignedTimestamp {}],
            ..init_envelope()
        };
        assert_ne!(
            stamped.signature_digest().unwrap(),
            init_envelope().signature_digest().unwrap(),
        );
    }

    /// The digest is blake3 over the envelope's canonical encoding — not
    /// over the payload alone, and not over whatever order the fields
    /// happened to be written in.
    #[test]
    fn digest_hashes_the_canonical_encoding() {
        let envelope = init_envelope();

        assert_eq!(
            envelope.digest().unwrap().as_bytes(),
            blake3::hash(&unhex(INIT_ENVELOPE)).as_bytes(),
        );

        // Pinned so the hashed input can't drift silently. Unlike the CBOR
        // above this is captured, not hand-derived: blake3 is not
        // reproducible by inspection.
        assert_eq!(
            envelope.digest().unwrap().to_hex().as_ref(),
            "c3cac0124e2d1b64457f8879766d3b10b1fe468887587222819351048e5de3ca",
        );
    }

    /// Streaming into the hasher must produce the same bytes as collecting
    /// them, or the digest silently depends on which path was taken.
    #[test]
    fn encode_into_matches_encode() {
        let envelope = init_envelope();

        let mut streamed = Vec::new();
        crate::encode_into(&envelope, &mut streamed).unwrap();

        assert_eq!(streamed, crate::encode(&envelope).unwrap());
        assert_eq!(hex(&streamed), INIT_ENVELOPE);
    }

    /// Signatures are inside the digest, so attaching one changes it.
    #[test]
    fn digest_covers_signatures() {
        let unsigned = init_envelope();
        let signed = init_envelope().with_signature(signature());

        assert_eq!(unsigned.digest().unwrap(), unsigned.digest().unwrap());
        assert_ne!(unsigned.digest().unwrap(), signed.digest().unwrap());

        // Pinned to the hand-derived encoding rather than a captured hash.
        assert_eq!(
            signed.digest().unwrap().as_bytes(),
            blake3::hash(&unhex(&format!(
                "a301a16169a101a101a00281{}0380",
                signature_hex()
            )))
            .as_bytes(),
        );
    }

    /// A digest is a fixed 34 bytes: `58 20` (byte string, 32 long) then
    /// the digest itself, byte for byte.
    #[test]
    fn digest_encodes_as_a_byte_string() {
        assert_wire(
            &EnvelopeDigest::from_bytes([0xab; 32]),
            &format!("5820{}", "ab".repeat(32)),
        );
        assert_wire(
            &EnvelopeDigest::from_bytes([1; 32]),
            &format!("5820{}", "01".repeat(32)),
        );
        assert_wire(
            &EnvelopeDigest::from_bytes([0; 32]),
            &format!("5820{}", "00".repeat(32)),
        );

        // Fixed width regardless of content, unlike the array encoding.
        for probe in [[0u8; 32], [0x17; 32], [0x18; 32], [0xff; 32]] {
            let encoded = crate::encode(&EnvelopeDigest::from_bytes(probe)).unwrap();
            assert_eq!(encoded.len(), 34);
        }
    }

    /// The array-of-integers shape the derived impl used to produce is no
    /// longer accepted; only a byte string decodes.
    #[test]
    fn digest_rejects_wrong_shape_or_length() {
        let bad = [
            format!("9820{}", "18ab".repeat(32)), // array of 32 integers
            format!("5821{}", "ab".repeat(33)),   // 33-byte string
            "4100".to_string(),                   // 1-byte string
            "40".to_string(),                     // empty byte string
            "6161".to_string(),                   // text string
        ];
        for bad in bad {
            assert!(
                crate::decode::<EnvelopeDigest>(&unhex(&bad)).is_err(),
                "expected {bad} to be rejected",
            );
        }
    }

    /// Fork choice reads a digest as one big-endian number, so `Ord` must
    /// let the leading byte dominate whatever follows it.
    #[test]
    fn digest_orders_as_a_big_endian_number() {
        let zero = EnvelopeDigest::from_bytes([0x00; 32]);
        let low = EnvelopeDigest::from_bytes({
            let mut bytes = [0xff; 32];
            bytes[0] = 0x00;
            bytes
        });
        let high = EnvelopeDigest::from_bytes({
            let mut bytes = [0x00; 32];
            bytes[0] = 0x01;
            bytes
        });

        assert!(low < high, "0x00ff… must order below 0x0100…");
        assert!(zero < low);

        let mut sorted = vec![high, low, zero];
        sorted.sort();
        assert_eq!(sorted, [zero, low, high]);
    }

    #[test]
    fn digest_hex_roundtrips() {
        let digest = EnvelopeDigest::from_bytes([0xab; 32]);
        let round = EnvelopeDigest::from_hex(digest.to_hex().as_ref()).unwrap();
        assert_eq!(round, digest);
        assert_eq!(round.as_slice(), &[0xab; 32]);
    }
}
