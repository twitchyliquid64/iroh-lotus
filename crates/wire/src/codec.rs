//! The crate's sanctioned CBOR entry points.
//!
//! Everything that crosses the wire or reaches the ledger goes through
//! [`encode`] and [`decode`] rather than calling `cbor2` directly.

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::Error;

/// Encodes a wire value as deterministic CBOR, satisfying the core
/// deterministic encoding requirements of RFC 8949 §4.2.1. Use this
/// rather than [`cbor2::to_vec`].
pub fn encode<T: ?Sized + Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    Ok(cbor2::to_canonical_vec(value)?)
}

/// Encodes a wire value as deterministic CBOR straight into `writer`.
///
/// Byte-for-byte identical to [`encode`], without collecting the output
/// into a `Vec` first.
pub fn encode_into<T, W>(value: &T, writer: W) -> Result<(), Error>
where
    T: ?Sized + Serialize,
    W: std::io::Write,
{
    Ok(cbor2::to_canonical_writer(value, writer)?)
}

/// Decodes a wire value from CBOR.
///
/// Does not require the input to be canonically encoded — only [`encode`]
/// guarantees that on the way out.
pub fn decode<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, Error> {
    Ok(cbor2::from_slice(bytes)?)
}

/// Implements both serde representations of an all-newtype-variant enum:
/// on the wire a one-pair map under an integer tag (`{1: …}`), in
/// human-readable formats (JSON) an adjacently tagged object under the
/// full name (`{"type": "string", "value": …}`).
///
/// The enum itself must derive neither `Cbor` nor serde's traits. Every
/// variant is restated here with its payload type; drift from the enum
/// fails to compile — except a renumbered tag, which only the pinned
/// wire-byte tests catch.
macro_rules! dual_repr {
    ($name:ident { $($variant:ident($ty:ty) = $wire:literal | $json:literal),+ $(,)? }) => {
        const _: () = {
            // Variant idents double as the type parameters, so one shadow
            // serves borrowed serialization and owned deserialization.
            #[derive(::serde::Serialize, ::serde::Deserialize)]
            #[serde(tag = "type", content = "value")]
            enum Json<$($variant),+> {
                $(#[serde(rename = $json)] $variant($variant),)+
            }

            impl ::serde::Serialize for $name {
                fn serialize<S: ::serde::Serializer>(
                    &self,
                    serializer: S,
                ) -> ::core::result::Result<S::Ok, S::Error> {
                    type JsonRef<'a> = Json<$(&'a $ty),+>;
                    if serializer.is_human_readable() {
                        match self {
                            $($name::$variant(v) => JsonRef::$variant(v).serialize(serializer),)+
                        }
                    } else {
                        use ::serde::ser::SerializeMap as _;
                        let mut map = serializer.serialize_map(Some(1))?;
                        match self {
                            $($name::$variant(v) => map.serialize_entry::<u64, $ty>(&$wire, v)?,)+
                        }
                        map.end()
                    }
                }
            }

            impl<'de> ::serde::Deserialize<'de> for $name {
                fn deserialize<D: ::serde::Deserializer<'de>>(
                    deserializer: D,
                ) -> ::core::result::Result<Self, D::Error> {
                    if deserializer.is_human_readable() {
                        return <Json<$($ty),+> as ::serde::Deserialize>::deserialize(deserializer)
                            .map(|value| match value {
                                $(Json::$variant(v) => $name::$variant(v),)+
                            });
                    }

                    struct WireVisitor;

                    impl<'de> ::serde::de::Visitor<'de> for WireVisitor {
                        type Value = $name;

                        fn expecting(
                            &self,
                            f: &mut ::core::fmt::Formatter<'_>,
                        ) -> ::core::fmt::Result {
                            f.write_str(concat!(
                                "a one-pair map tagging a ",
                                stringify!($name),
                            ))
                        }

                        fn visit_map<A: ::serde::de::MapAccess<'de>>(
                            self,
                            mut map: A,
                        ) -> ::core::result::Result<Self::Value, A::Error> {
                            let tag = map
                                .next_key::<u64>()?
                                .ok_or_else(|| ::serde::de::Error::invalid_length(0, &self))?;
                            let value = match tag {
                                $($wire => $name::$variant(map.next_value()?),)+
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
    };
}
pub(crate) use dual_repr;

/// Serializes a fixed-width byte newtype — digests, keys, signatures — as
/// a CBOR byte string, or in human-readable formats (JSON) as `prefix`
/// followed by lowercase hex. The prefix names the digest's type (`ed:`
/// for an envelope digest; `sd:` is reserved for the signature digest,
/// which is never serialized) so one kind pasted where another belongs
/// fails to parse; empty for the types that carry no prefix.
pub(crate) fn serialize_byte_array<S: Serializer>(
    bytes: &[u8],
    serializer: S,
    prefix: &'static str,
) -> Result<S::Ok, S::Error> {
    if serializer.is_human_readable() {
        serializer.collect_str(&Hex { prefix, bytes })
    } else {
        serializer.serialize_bytes(bytes)
    }
}

struct Hex<'a> {
    prefix: &'static str,
    bytes: &'a [u8],
}

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.prefix)?;
        self.bytes
            .iter()
            .try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// Deserializes what [`serialize_byte_array`] produced back into exactly
/// `N` bytes: a CBOR byte string — never a sequence of integers — or, in
/// human-readable formats, `prefix` verbatim followed by hex of either
/// case.
pub(crate) fn byte_array<'de, D, const N: usize>(
    deserializer: D,
    expecting: &'static str,
    prefix: &'static str,
) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    let visitor = ByteArrayVisitor::<N> { expecting, prefix };
    if deserializer.is_human_readable() {
        deserializer.deserialize_str(visitor)
    } else {
        deserializer.deserialize_bytes(visitor)
    }
}

struct ByteArrayVisitor<const N: usize> {
    expecting: &'static str,
    prefix: &'static str,
}

impl<'de, const N: usize> de::Visitor<'de> for ByteArrayVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.expecting)
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
        bytes
            .try_into()
            .map_err(|_| E::invalid_length(bytes.len(), &self))
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
        fn nibble(b: u8) -> Option<u8> {
            match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            }
        }

        let hex = s
            .strip_prefix(self.prefix)
            .ok_or_else(|| E::invalid_value(de::Unexpected::Str(s), &self))?;
        if hex.len() != 2 * N {
            return Err(E::invalid_length(hex.len(), &self));
        }
        let mut bytes = [0u8; N];
        // The length check above leaves no remainder.
        let (pairs, _) = hex.as_bytes().as_chunks::<2>();
        bytes
            .iter_mut()
            .zip(pairs)
            .try_for_each(|(byte, [hi, lo])| {
                *byte = (nibble(*hi)? << 4) | nibble(*lo)?;
                Some(())
            })
            .ok_or_else(|| E::invalid_value(de::Unexpected::Str(s), &self))?;
        Ok(bytes)
    }
}
