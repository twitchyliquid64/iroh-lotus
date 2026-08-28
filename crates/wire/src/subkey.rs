//! Paths into the value a namespace holds.
//!
//! A namespace's value can be a whole tree of maps and arrays; a
//! [`SubkeyPath`] addresses one value inside it, so an update can amend a
//! branch without republishing the trunk.

use core::{fmt, str::FromStr};

use nutype::nutype;

use crate::codec::dual_repr;

/// One step of a path into a namespace's value.
///
/// `dual_repr!` below defines the serde representations: integer wire
/// tags, adjacently tagged full names in JSON.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Subkey {
    /// A key of a [`Value::Map`](crate::msg::Value::Map).
    Key(String),
    /// An index into a [`Value::Array`](crate::msg::Value::Array).
    Index(u32),
}

dual_repr! {
    Subkey {
        Key(String) = 1 | "key",
        Index(u32) = 2 | "index",
    }
}

impl fmt::Display for Subkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Subkey::Key(key) => f.write_str(key),
            Subkey::Index(index) => write!(f, "[{index}]"),
        }
    }
}

/// A path to a value nested inside a namespace.
///
/// Never empty: the empty path addresses the namespace's value as a whole,
/// which is [`SetNamespace`](crate::msg::SetNamespace)'s job.
#[nutype(
    validate(predicate = |path| !path.is_empty()),
    derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, AsRef, Serialize, Deserialize)
)]
pub struct SubkeyPath(Vec<Subkey>);

impl fmt::Display for SubkeyPath {
    /// Keys are dotted and indices bracketed, e.g. `servers[0].host`. A
    /// leading dot is never emitted, so a path opening on an index reads
    /// `[0].host`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_ref()
            .iter()
            .enumerate()
            .try_for_each(|(i, segment)| {
                if i > 0 && matches!(segment, Subkey::Key(_)) {
                    f.write_str(".")?;
                }
                write!(f, "{segment}")
            })
    }
}

impl FromStr for SubkeyPath {
    type Err = PathParseError;

    /// Reads back what [`Display`](SubkeyPath::fmt) writes: dotted keys and
    /// bracketed indices, `servers[0].host`.
    ///
    /// The textual form cannot express a key containing `.`, `[` or `]` —
    /// such a key parses as several segments. It is an input format for
    /// people to type, not a round trip for arbitrary paths.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut segments = Vec::new();
        let mut rest = text;

        while !rest.is_empty() {
            rest = match rest.strip_prefix('[') {
                Some(after) => {
                    let (index, after) = after
                        .split_once(']')
                        .ok_or_else(|| PathParseError::UnclosedIndex(text.to_string()))?;
                    segments.push(Subkey::Index(
                        index
                            .parse()
                            .map_err(|_| PathParseError::BadIndex(index.to_string()))?,
                    ));
                    after
                }
                None => {
                    let end = rest.find(['.', '[']).unwrap_or(rest.len());
                    let (key, after) = rest.split_at(end);
                    if key.is_empty() {
                        return Err(PathParseError::EmptyKey(text.to_string()));
                    }
                    segments.push(Subkey::Key(key.to_string()));
                    after
                }
            };
            // A dot only ever separates; anything else carries on as its
            // own segment, and a trailing one leaves an empty key behind.
            if let Some(after) = rest.strip_prefix('.') {
                if after.is_empty() {
                    return Err(PathParseError::EmptyKey(text.to_string()));
                }
                rest = after;
            }
        }

        Self::try_new(segments).map_err(|_| PathParseError::Empty)
    }
}

/// Why a path could not be read from text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathParseError {
    /// The text was empty; a path addresses at least one segment.
    Empty,
    /// A key was empty — a leading, doubled, or trailing dot. Holds the
    /// text it was read from.
    EmptyKey(String),
    /// An index was opened and never closed. Holds the text.
    UnclosedIndex(String),
    /// An index was not a `u32`. Holds what stood between the brackets.
    BadIndex(String),
}

impl fmt::Display for PathParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathParseError::Empty => f.write_str("a path needs at least one segment"),
            PathParseError::EmptyKey(text) => write!(f, "{text} has an empty key"),
            PathParseError::UnclosedIndex(text) => write!(f, "{text} has an unclosed ["),
            PathParseError::BadIndex(index) => {
                write!(f, "[{index}] is not a whole number under 2^32")
            }
        }
    }
}

impl core::error::Error for PathParseError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{assert_wire, unhex};

    fn path(segments: impl IntoIterator<Item = Subkey>) -> SubkeyPath {
        SubkeyPath::try_new(segments.into_iter().collect()).unwrap()
    }

    fn key(k: &str) -> Subkey {
        Subkey::Key(k.to_string())
    }

    /// Same one-pair integer-tag shape as `Value`: `a1` (map, 1 pair),
    /// the tag, then the payload.
    #[test]
    fn subkey_variants() {
        assert_wire(&key("a"), "a1016161");
        assert_wire(&Subkey::Key(String::new()), "a10160");
        assert_wire(&Subkey::Index(0), "a10200");
        assert_wire(&Subkey::Index(23), "a10217");
        assert_wire(&Subkey::Index(300), "a10219012c");
        assert_wire(&Subkey::Index(u32::MAX), "a1021affffffff");
    }

    /// An index wider than `u32` is refused rather than truncated.
    #[test]
    fn subkey_index_is_bounded_at_u32() {
        assert!(crate::decode::<Subkey>(&unhex("a1021b0000000100000000")).is_err());
    }

    /// The path is transparent — a bare CBOR array, no wrapper map.
    #[test]
    fn subkey_path_encodes_as_an_array() {
        assert_wire(&path([key("a")]), "81a1016161");
        assert_wire(&path([key("a"), Subkey::Index(2)]), "82a1016161a10202");
    }

    /// The empty path addresses the whole namespace value, which is what
    /// `SetNamespace` is for — so it is refused, on the wire too.
    #[test]
    fn subkey_path_rejects_empty() {
        assert!(SubkeyPath::try_new(vec![]).is_err());
        assert!(crate::decode::<SubkeyPath>(&unhex("80")).is_err());
    }

    #[test]
    fn subkey_displays_keys_bare_and_indices_bracketed() {
        assert_eq!(key("host").to_string(), "host");
        assert_eq!(Subkey::Index(0).to_string(), "[0]");
    }

    /// What `Display` writes, `FromStr` reads back.
    #[test]
    fn a_path_round_trips_through_its_text() {
        for original in [
            path([key("a")]),
            path([key("a"), key("b")]),
            path([key("servers"), Subkey::Index(0), key("host")]),
            path([Subkey::Index(7)]),
            path([Subkey::Index(1), Subkey::Index(2)]),
            path([key("a"), Subkey::Index(0)]),
        ] {
            let text = original.to_string();
            assert_eq!(text.parse::<SubkeyPath>(), Ok(original), "{text}");
        }
    }

    #[test]
    fn a_path_is_read_from_its_written_form() {
        assert_eq!(
            "servers[0].host".parse::<SubkeyPath>(),
            Ok(path([key("servers"), Subkey::Index(0), key("host")])),
        );
        assert_eq!("[12]".parse::<SubkeyPath>(), Ok(path([Subkey::Index(12)])));
    }

    #[test]
    fn a_malformed_path_is_refused() {
        assert_eq!("".parse::<SubkeyPath>(), Err(PathParseError::Empty));
        for text in [".a", "a..b", "a."] {
            assert_eq!(
                text.parse::<SubkeyPath>(),
                Err(PathParseError::EmptyKey(text.to_string())),
                "{text}",
            );
        }
        assert_eq!(
            "a[0".parse::<SubkeyPath>(),
            Err(PathParseError::UnclosedIndex("a[0".to_string())),
        );
        assert_eq!(
            "a[-1]".parse::<SubkeyPath>(),
            Err(PathParseError::BadIndex("-1".to_string())),
        );
        assert_eq!(
            "a[4294967296]".parse::<SubkeyPath>(),
            Err(PathParseError::BadIndex("4294967296".to_string())),
        );
    }

    /// The documented limit of the textual form: a key with a separator in
    /// it comes back as several segments.
    #[test]
    fn a_key_containing_a_separator_does_not_round_trip() {
        assert_eq!("a.b".parse::<SubkeyPath>(), Ok(path([key("a"), key("b")])),);
        assert_ne!("a.b".parse::<SubkeyPath>(), Ok(path([key("a.b")])),);
    }

    #[test]
    fn subkey_path_displays_as_a_dotted_path() {
        assert_eq!(path([key("a")]).to_string(), "a");
        assert_eq!(path([key("a"), key("b")]).to_string(), "a.b");
        assert_eq!(
            path([key("servers"), Subkey::Index(0), key("host")]).to_string(),
            "servers[0].host",
        );

        // No leading dot, and adjacent indices don't grow one either.
        assert_eq!(path([Subkey::Index(7)]).to_string(), "[7]");
        assert_eq!(
            path([Subkey::Index(1), Subkey::Index(2)]).to_string(),
            "[1][2]",
        );
    }
}
