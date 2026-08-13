use cbor2::Cbor;

use crate::Error;

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
}

impl Envelope {
    /// A new envelope carrying `payload`, with nothing attested over it yet.
    pub fn new(payload: super::Msg) -> Self {
        Self {
            payload,
            signatures: Vec::new(),
            timestamps: Vec::new(),
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

    /// The digest of this envelope, taken over its canonical CBOR encoding.
    ///
    /// The digest covers the whole envelope, signatures and timestamps
    /// included, so it changes as they are attached.
    pub fn digest(&self) -> Result<EnvelopeDigest, Error> {
        let mut hasher = blake3::Hasher::new();
        crate::encode_into(self, &mut hasher)?;
        Ok(EnvelopeDigest(hasher.finalize()))
    }
}

/// A signature over an envelope.
#[derive(Debug, Clone, Cbor, Hash, PartialEq, Eq)]
pub struct EnvelopeSignature {}

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
        deserializer.deserialize_bytes(EnvelopeDigestVisitor)
    }
}

struct EnvelopeDigestVisitor;

impl<'de> serde::de::Visitor<'de> for EnvelopeDigestVisitor {
    type Value = EnvelopeDigest;

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a 32-byte envelope digest")
    }

    fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| E::invalid_length(bytes.len(), &self))?;
        Ok(EnvelopeDigest::from_bytes(bytes))
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
    use crate::testutil::{assert_wire, hex, unhex};

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

    /// Both are empty maps (`a0`) today, so a populated list is `81 a0`.
    /// Adding fields to either grows that map rather than changing its
    /// major type.
    #[test]
    fn signatures_and_timestamps_encode_as_arrays() {
        assert_wire(&EnvelopeSignature {}, "a0");
        assert_wire(&SignedTimestamp {}, "a0");

        let signed = Envelope {
            signatures: vec![EnvelopeSignature {}],
            ..init_envelope()
        };
        assert_wire(&signed, "a301a16169a101a101a00281a00380");

        let stamped = Envelope {
            timestamps: vec![SignedTimestamp {}],
            ..init_envelope()
        };
        assert_wire(&stamped, "a301a16169a101a101a002800381a0");
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
        let signed = Envelope {
            signatures: vec![EnvelopeSignature {}],
            ..init_envelope()
        };

        assert_eq!(unsigned.digest().unwrap(), unsigned.digest().unwrap());
        assert_ne!(unsigned.digest().unwrap(), signed.digest().unwrap());
        assert_eq!(
            signed.digest().unwrap().to_hex().as_ref(),
            "f80ace62eb8d898403f3c3f06f107962099347dbedee78448478834a70220708",
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
