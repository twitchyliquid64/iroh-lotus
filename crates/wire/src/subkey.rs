//! Paths into the value a namespace holds.
//!
//! A namespace's value can be a whole tree of maps and arrays; a
//! [`SubkeyPath`] addresses one value inside it, so an update can amend a
//! branch without republishing the trunk.

use core::{
    fmt::{self, Write as _},
    str::FromStr,
};

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

impl Subkey {
    /// Whether a key reads unambiguously bare, as `host` in
    /// `servers[0].host`. Anything else is written bracket-quoted.
    ///
    /// Wider than RFC 9535's member-name shorthand — `my-key` and hex key
    /// ids are bare here — but never a key the parser could misread: the
    /// structural characters, quotes, a backslash, a control character,
    /// the empty key, or a leading `$`.
    fn is_bare(key: &str) -> bool {
        !key.is_empty()
            && !key.starts_with('$')
            && !key
                .chars()
                .any(|c| matches!(c, '.' | '[' | ']' | '\'' | '"' | '\\') || c.is_control())
    }

    /// Whether this segment is written after a dot.
    fn is_dotted(&self) -> bool {
        matches!(self, Subkey::Key(key) if Self::is_bare(key))
    }
}

impl fmt::Display for Subkey {
    /// Keys are bare, or single-quoted in brackets when they must be
    /// (`['my.key']`); indices are bracketed. The quoted form escapes as
    /// JSONPath (RFC 9535) does.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Subkey::Key(key) if Self::is_bare(key) => f.write_str(key),
            Subkey::Key(key) => {
                f.write_str("['")?;
                key.chars().try_for_each(|c| match c {
                    '\'' => f.write_str("\\'"),
                    '\\' => f.write_str("\\\\"),
                    '\u{8}' => f.write_str("\\b"),
                    '\u{c}' => f.write_str("\\f"),
                    '\n' => f.write_str("\\n"),
                    '\r' => f.write_str("\\r"),
                    '\t' => f.write_str("\\t"),
                    c if c.is_control() => write!(f, "\\u{:04x}", u32::from(c)),
                    c => f.write_char(c),
                })?;
                f.write_str("']")
            }
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
    /// Keys are dotted and indices bracketed, e.g. `servers[0].host`, in
    /// the shape of a JSONPath without its leading `$`. A key that can't
    /// be written bare is bracket-quoted instead: `servers['my.key']`.
    /// A leading dot is never emitted, so a path opening on an index or
    /// a quoted key reads `[0].host`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_ref()
            .iter()
            .enumerate()
            .try_for_each(|(i, segment)| {
                if i > 0 && segment.is_dotted() {
                    f.write_str(".")?;
                }
                write!(f, "{segment}")
            })
    }
}

impl FromStr for SubkeyPath {
    type Err = PathParseError;

    /// Reads a path the way JSONPath (RFC 9535) writes one, minus the
    /// need for the leading `$`: dotted keys, bracketed indices, and
    /// bracket-quoted keys for anything a bare key can't spell —
    /// `servers[0].host`, `$.servers[0].host`, `servers['my.key']`,
    /// `["it's"]`. Quoted keys take JSON's escapes: `\'`, `\"`, `\\`,
    /// `\/`, `\b`, `\f`, `\n`, `\r`, `\t` and `\uXXXX`, surrogate pairs
    /// included.
    ///
    /// Bare keys are read more leniently than the RFC's shorthand: only
    /// `.` and `[` end one, so `my-key` and `3fa9` need no quotes. What
    /// [`Display`](fmt::Display) writes always reads back as the same
    /// path.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut segments = Vec::new();
        // A `$` is the root only where JSONPath puts one: alone, or
        // before a `.` or `[`. Anywhere else it opens a bare key.
        let (mut rest, rooted) = match text.strip_prefix('$') {
            Some(after) if after.is_empty() || after.starts_with(['.', '[']) => (after, true),
            _ => (text, false),
        };
        let mut first = true;

        while !rest.is_empty() {
            rest = match rest.strip_prefix('[') {
                Some(inner) => {
                    let (segment, after) = parse_bracket(inner, text)?;
                    segments.push(segment);
                    after
                }
                None => {
                    // A dot introduces every key but the first — and the
                    // first too, once a `$` stands before it.
                    let body = match rest.strip_prefix('.') {
                        Some(_) if first && !rooted => {
                            return Err(PathParseError::EmptyKey(text.to_string()));
                        }
                        Some(after) => after,
                        None => rest,
                    };
                    let end = body.find(['.', '[']).unwrap_or(body.len());
                    let (key, after) = body.split_at(end);
                    if key.is_empty() {
                        return Err(PathParseError::EmptyKey(text.to_string()));
                    }
                    segments.push(Subkey::Key(key.to_string()));
                    after
                }
            };
            first = false;
        }

        Self::try_new(segments).map_err(|_| PathParseError::Empty)
    }
}

/// Reads what follows an opening `[` — an index or a quoted key, with
/// blanks allowed around it — through the closing `]`, yielding the
/// segment and the text after the bracket.
fn parse_bracket<'a>(inner: &'a str, text: &str) -> Result<(Subkey, &'a str), PathParseError> {
    let inner = inner.trim_start_matches(BLANK);
    let unclosed = || PathParseError::UnclosedBracket(text.to_string());

    if let Some(quote) = inner.chars().next().filter(|c| matches!(c, '\'' | '"')) {
        let (key, after) = unquote(&inner[quote.len_utf8()..], quote, text)?;
        let after = after
            .trim_start_matches(BLANK)
            .strip_prefix(']')
            .ok_or_else(unclosed)?;
        return Ok((Subkey::Key(key), after));
    }

    let (selector, after) = inner.split_once(']').ok_or_else(unclosed)?;
    let selector = selector.trim_matches(BLANK);
    // A `u32` never carries a sign or blanks; `parse` would take a `+`.
    let index = selector
        .bytes()
        .all(|b| b.is_ascii_digit())
        .then(|| selector.parse().ok())
        .flatten()
        .ok_or_else(|| PathParseError::BadIndex(selector.to_string()))?;
    Ok((Subkey::Index(index), after))
}

/// The blanks RFC 9535 allows inside brackets.
const BLANK: [char; 4] = [' ', '\t', '\n', '\r'];

/// Reads a quoted key up to its closing `quote`, resolving escapes, and
/// yields it with the text after the quote.
fn unquote<'a>(
    body: &'a str,
    quote: char,
    text: &str,
) -> Result<(String, &'a str), PathParseError> {
    let mut key = String::new();
    let mut chars = body.char_indices();
    let unclosed = || PathParseError::UnclosedString(text.to_string());

    while let Some((at, c)) = chars.next() {
        match c {
            c if c == quote => return Ok((key, &body[at + c.len_utf8()..])),
            '\\' => {
                let (_, escaped) = chars.next().ok_or_else(unclosed)?;
                let bad = |seq: &str| PathParseError::BadEscape(format!("\\{seq}"));
                key.push(match escaped {
                    '\'' | '"' | '\\' | '/' => escaped,
                    'b' => '\u{8}',
                    'f' => '\u{c}',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'u' => {
                        let rest = &body[at + 2..];
                        let (c, consumed) = unescape_unicode(rest).ok_or_else(|| {
                            bad(&format!("u{}", rest.chars().take(4).collect::<String>()))
                        })?;
                        // Advance past what the escape spanned.
                        chars.by_ref().take(consumed).for_each(drop);
                        c
                    }
                    other => return Err(bad(&other.to_string())),
                });
            }
            c => key.push(c),
        }
    }
    Err(unclosed())
}

/// Reads the `XXXX` of a `\uXXXX` escape — and, for a high surrogate, the
/// `\uXXXX` low surrogate it must be followed by — from the front of
/// `rest`, yielding the character and how many characters were consumed.
fn unescape_unicode(rest: &str) -> Option<(char, usize)> {
    let unit = |at: usize| {
        rest.get(at..at + 4)
            .filter(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
            .and_then(|hex| u16::from_str_radix(hex, 16).ok())
    };
    let high = unit(0)?;
    match high {
        0xD800..=0xDBFF => {
            let low = rest[4..]
                .strip_prefix("\\u")
                .and_then(|_| unit(6))
                .filter(|low| (0xDC00..=0xDFFF).contains(low))?;
            let code = 0x10000 + ((u32::from(high) - 0xD800) << 10) + (u32::from(low) - 0xDC00);
            char::from_u32(code).map(|c| (c, 10))
        }
        0xDC00..=0xDFFF => None,
        _ => char::from_u32(u32::from(high)).map(|c| (c, 4)),
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
    /// A bracket was opened and never closed. Holds the text.
    UnclosedBracket(String),
    /// What stood unquoted between brackets was not a `u32`. Holds it.
    BadIndex(String),
    /// A quoted key was opened and never closed. Holds the text.
    UnclosedString(String),
    /// A backslash in a quoted key began no escape this form has. Holds
    /// the sequence.
    BadEscape(String),
}

impl fmt::Display for PathParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathParseError::Empty => f.write_str("a path needs at least one segment"),
            PathParseError::EmptyKey(text) => write!(f, "{text} has an empty key"),
            PathParseError::UnclosedBracket(text) => write!(f, "{text} has an unclosed ["),
            PathParseError::BadIndex(index) => write!(
                f,
                "[{index}] is not a whole number under 2^32; a key in brackets is quoted, ['{index}']"
            ),
            PathParseError::UnclosedString(text) => write!(f, "{text} has an unclosed quote"),
            PathParseError::BadEscape(seq) => write!(f, "{seq} is not an escape"),
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

    /// What `Display` writes, `FromStr` reads back — whatever the key.
    #[test]
    fn a_path_round_trips_through_its_text() {
        for original in [
            path([key("a")]),
            path([key("a"), key("b")]),
            path([key("servers"), Subkey::Index(0), key("host")]),
            path([Subkey::Index(7)]),
            path([Subkey::Index(1), Subkey::Index(2)]),
            path([key("a"), Subkey::Index(0)]),
            path([key("my-key"), key("3fa9"), key("a b"), key("a$")]),
            path([key("a.b"), key("c")]),
            path([key("a"), key("x[0]"), key("]")]),
            path([key("it's"), key("say \"hi\""), key("back\\slash")]),
            path([key(""), key("a")]),
            path([key("$"), key("$root")]),
            path([
                key("tab\there"),
                key("new\nline"),
                key("\u{0}\u{7f}\u{8}\u{c}\r"),
            ]),
            path([key("ünïcödé"), key("😀"), key("a.😀")]),
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

    /// The JSONPath spellings of the same path all read as it: with or
    /// without the `$`, keys dotted or bracket-quoted with either quote,
    /// blanks inside the brackets.
    #[test]
    fn a_path_is_read_in_every_jsonpath_spelling() {
        let expected = path([key("servers"), Subkey::Index(0), key("host")]);
        for text in [
            "servers[0].host",
            "$.servers[0].host",
            "$['servers'][0]['host']",
            "$[\"servers\"][0][\"host\"]",
            "servers[0]['host']",
            "['servers'][0].host",
            "$[ 'servers' ][ 0 ].host",
            "servers[\t0\n]['host']",
        ] {
            assert_eq!(text.parse::<SubkeyPath>(), Ok(expected.clone()), "{text}");
        }
    }

    /// Only `.` and `[` end a bare key; what JSONPath would make you
    /// quote reads bare here too.
    #[test]
    fn a_bare_key_is_read_leniently() {
        assert_eq!(
            "my-key.3fa9.a b.a$".parse::<SubkeyPath>(),
            Ok(path([key("my-key"), key("3fa9"), key("a b"), key("a$")])),
        );
        // `$` is the root only where JSONPath puts it.
        assert_eq!("$root".parse::<SubkeyPath>(), Ok(path([key("$root")])));
        assert_eq!(
            "a$.b".parse::<SubkeyPath>(),
            Ok(path([key("a$"), key("b")]))
        );
    }

    /// Quoted keys spell what bare ones can't, with JSON's escapes.
    #[test]
    fn a_quoted_key_resolves_its_escapes() {
        let read = |text: &str| {
            text.parse::<SubkeyPath>()
                .unwrap_or_else(|e| panic!("{text}: {e}"))
        };

        assert_eq!(read("['a.b']"), path([key("a.b")]));
        assert_eq!(read("['x[0]']"), path([key("x[0]")]));
        assert_eq!(read("['']"), path([key("")]));
        // The other quote needs no escape inside; its own does.
        assert_eq!(read("['say \"hi\"']"), path([key("say \"hi\"")]));
        assert_eq!(read("[\"it's\"]"), path([key("it's")]));
        assert_eq!(read("['it\\'s']"), path([key("it's")]));
        assert_eq!(read("[\"say \\\"hi\\\"\"]"), path([key("say \"hi\"")]));
        assert_eq!(
            read("['\\\\ \\/ \\b \\f \\n \\r \\t']"),
            path([key("\\ / \u{8} \u{c} \n \r \t")]),
        );
        assert_eq!(read("['\\u0041\\u00e9']"), path([key("Aé")]));
        assert_eq!(read("['\\uD83D\\uDE00']"), path([key("😀")]));
        assert_eq!(read("['\\ud83d\\ude00x']"), path([key("😀x")]));
        // Raw non-ASCII needs no escaping either.
        assert_eq!(read("['😀'].ünïcödé"), path([key("😀"), key("ünïcödé")]));
    }

    #[test]
    fn a_malformed_path_is_refused() {
        assert_eq!("".parse::<SubkeyPath>(), Err(PathParseError::Empty));
        assert_eq!("$".parse::<SubkeyPath>(), Err(PathParseError::Empty));
        for text in [".a", "a..b", "a.", "$.", "$.[0]", "a.[0]"] {
            assert_eq!(
                text.parse::<SubkeyPath>(),
                Err(PathParseError::EmptyKey(text.to_string())),
                "{text}",
            );
        }
        for text in ["a[0", "a[", "['a'", "['a' x]"] {
            assert_eq!(
                text.parse::<SubkeyPath>(),
                Err(PathParseError::UnclosedBracket(text.to_string())),
                "{text}",
            );
        }
        for (text, index) in [
            ("a[-1]", "-1"),
            ("a[+1]", "+1"),
            ("a[4294967296]", "4294967296"),
            ("a[host]", "host"),
            ("a[]", ""),
        ] {
            assert_eq!(
                text.parse::<SubkeyPath>(),
                Err(PathParseError::BadIndex(index.to_string())),
                "{text}",
            );
        }
        for text in ["['a", "['a\\']", "[\"a']", "['a]"] {
            assert_eq!(
                text.parse::<SubkeyPath>(),
                Err(PathParseError::UnclosedString(text.to_string())),
                "{text}",
            );
        }
        for (text, seq) in [
            ("['\\x']", "\\x"),
            ("['\\u12']", "\\u12']"),
            ("['\\u12g4']", "\\u12g4"),
            // A lone surrogate, either half.
            ("['\\uD83D']", "\\uD83D"),
            ("['\\uDE00']", "\\uDE00"),
            ("['\\uD83Dx']", "\\uD83D"),
        ] {
            assert_eq!(
                text.parse::<SubkeyPath>(),
                Err(PathParseError::BadEscape(seq.to_string())),
                "{text}",
            );
        }
    }

    /// A key is written bare when it reads back bare, and bracket-quoted
    /// — single quotes, JSON escapes — when it wouldn't.
    #[test]
    fn a_key_is_quoted_only_when_it_must_be() {
        assert_eq!(key("host").to_string(), "host");
        assert_eq!(key("my-key").to_string(), "my-key");
        assert_eq!(key("3fa9").to_string(), "3fa9");
        assert_eq!(key("a b").to_string(), "a b");
        assert_eq!(key("a$").to_string(), "a$");
        assert_eq!(key("ünïcödé").to_string(), "ünïcödé");

        assert_eq!(key("a.b").to_string(), "['a.b']");
        assert_eq!(key("x[0]").to_string(), "['x[0]']");
        assert_eq!(key("]").to_string(), "[']']");
        assert_eq!(key("").to_string(), "['']");
        assert_eq!(key("$").to_string(), "['$']");
        assert_eq!(key("$root").to_string(), "['$root']");
        assert_eq!(key("it's").to_string(), "['it\\'s']");
        assert_eq!(key("say \"hi\"").to_string(), "['say \"hi\"']");
        assert_eq!(key("back\\slash").to_string(), "['back\\\\slash']");
        assert_eq!(
            key("\u{8}\u{c}\n\r\t\u{0}\u{7f}").to_string(),
            "['\\b\\f\\n\\r\\t\\u0000\\u007f']",
        );
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
        // Nor does a quoted key, in any position.
        assert_eq!(
            path([key("a.b"), key("c"), key("d.e"), Subkey::Index(0)]).to_string(),
            "['a.b'].c['d.e'][0]",
        );
    }
}
