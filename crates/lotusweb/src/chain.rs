//! The chain page: the canonical chain the daemon holds, one stanza per
//! envelope, as `lotusctl chain` prints it.
//!
//! Newest first, since the page is opened to see what has been happening:
//! the head at the top, the oldest envelope shown at the bottom, marked
//! `root` when it is the oldest the node still holds. The walk is bounded
//! as `lotusctl chain` bounds it — at most so many envelopes, or only what
//! the node stored within a window — and both bounds ride in the query
//! string, so a bounded view is a URL like any other.

use std::{collections::HashSet, time::Duration};

use chrono::{DateTime, SecondsFormat, Utc};
use lotus_sdk::{
    ChainRange, ChainWalk, EnvelopeDigest, EnvelopeFrame, Match, NamespaceKey, SubkeyPath, Value,
    wire::{
        Msg, VerificationStatus,
        msg::{AmendOp, IncrementDecrement},
    },
};
use maud::{Markup, html};

use crate::{Error, Location, json, view};

/// Where the chain is shown.
pub const CHAIN_URL: &str = "/chain";

/// How many envelopes the page shows when the URL does not say.
const DEFAULT_LIMIT: u32 = 100;

/// How many characters of a written value a stanza shows.
const PREVIEW_WIDTH: usize = 96;

/// How much of the chain the page asks for: the two bounds of a
/// [`ChainWalk`], as the query string spells them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Walk {
    /// At most this many envelopes back from the head; `None` for all the
    /// node holds.
    limit: Option<u32>,
    /// Only what the node stored within this window.
    since: Option<Duration>,
}

impl Walk {
    /// Reads the bounds off the query string. A `limit` key left out shows
    /// the newest [`DEFAULT_LIMIT`]; present and empty, it means all.
    pub fn parse(limit: Option<&str>, since: Option<&str>) -> Result<Self, Error> {
        let limit = match limit.map(str::trim) {
            None => Some(DEFAULT_LIMIT),
            Some("") => None,
            Some(text) => Some(text.parse().map_err(|_| {
                Error::BadRequest(format!("`{text}` is not a number of envelopes"))
            })?),
        };
        let since = match since.map(str::trim) {
            None | Some("") => None,
            Some(text) => Some(parse_window(text).map_err(Error::BadRequest)?),
        };
        Ok(Self { limit, since })
    }

    /// What to ask the daemon for.
    pub fn request(&self) -> ChainWalk {
        let walk = self.limit.map_or_else(ChainWalk::default, |limit| {
            ChainWalk::default().with_limit(limit)
        });
        self.since.map_or(walk, |since| walk.with_since(since))
    }
}

/// Reads a window like `90s`, `15m`, `2h` or `7d`, as `lotusctl` does. A
/// bare number is seconds.
fn parse_window(text: &str) -> Result<Duration, String> {
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (count, unit) = text.split_at(split);
    let count: u64 = count
        .parse()
        .map_err(|_| format!("`{text}` is not a window; write one like 90s, 15m, 2h or 7d"))?;
    let millis = match unit {
        "ms" => 1,
        "" | "s" => 1_000,
        "m" => 60 * 1_000,
        "h" => 60 * 60 * 1_000,
        "d" => 24 * 60 * 60 * 1_000,
        unit => return Err(format!("`{unit}` is not a unit; use ms, s, m, h or d")),
    };
    count
        .checked_mul(millis)
        .map(Duration::from_millis)
        .ok_or_else(|| format!("`{text}` is a longer window than any log covers"))
}

/// A window in its largest whole unit, for the form to show back.
fn window(duration: Duration) -> String {
    let secs = duration.as_secs();
    [(86_400, "d"), (3_600, "h"), (60, "m")]
        .into_iter()
        .find(|(unit, _)| secs > 0 && secs.is_multiple_of(*unit))
        .map_or_else(
            || format!("{secs}s"),
            |(unit, suffix)| format!("{}{suffix}", secs / unit),
        )
}

/// The chain page: `frames`, as the daemon sent them for `walk`, head
/// first, between the ends `range` names.
pub fn pane(walk: &Walk, range: &ChainRange, frames: &[EnvelopeFrame]) -> Markup {
    let shown: HashSet<_> = frames.iter().map(|frame| frame.digest).collect();
    let count = frames.len();
    html! {
        header.pane-head {
            h1 { "Chain" }
            span.badge { (count) " " (if count == 1 { "envelope" } else { "envelopes" }) }
            span.head title=(range.head.to_hex().as_ref()) { "head " code { (view::short(&range.head)) } }
        }
        (bounds(walk))
        @if frames.is_empty() {
            p.empty { "Nothing in this window." }
        } @else if !shown.contains(&range.root) {
            p.note { "Older envelopes are held but not shown; widen the bounds to see back to the root." }
        }
        section.chain {
            @for frame in frames.iter().rev() {
                (stanza(frame, range, &shown))
            }
        }
    }
}

/// The form that bounds the walk, showing the bounds in force.
fn bounds(walk: &Walk) -> Markup {
    html! {
        form.bounds hx-get=(CHAIN_URL) hx-push-url="true" action=(CHAIN_URL) method="get" {
            label {
                "Newest"
                input type="number" name="limit" min="1" step="1" placeholder="all"
                    value=[walk.limit];
            }
            label {
                "Stored within"
                input name="since" placeholder="e.g. 15m, 2h, 7d" value=[walk.since.map(window)];
            }
            button { "Show" }
        }
    }
}

/// One envelope: digest and marks, what it does, then a field per line.
fn stanza(frame: &EnvelopeFrame, range: &ChainRange, shown: &HashSet<EnvelopeDigest>) -> Markup {
    let envelope = &frame.envelope;
    let msg = envelope.payload();
    let hex = frame.digest.to_hex();
    html! {
        article.envelope #(anchor(&frame.digest)) {
            header {
                code.digest { (hex.as_ref()) }
                @if frame.digest == range.head { span.mark { "head" } }
                @if frame.digest == range.root { span.mark { "root" } }
            }
            p.summary { (describe(msg)) }
            dl {
                dt { "prev" }
                dd {
                    @match msg.prev_digest() {
                        None => span.absent { "— (genesis)" },
                        Some(prev) => (digest(prev, shown)),
                    }
                }
                (detail(msg))
                dt { "verification" }
                dd { (status(&frame.verification.clone().into())) }
                dt { "signed by" }
                dd {
                    @if envelope.signatures().is_empty() { span.absent { "—" } }
                    @for id in envelope.signatures().keys() {
                        code.key { (id.to_hex().as_ref()) }
                    }
                }
                dt { "timestamps" }
                dd { (envelope.timestamps().len()) }
                dt { "stored" }
                dd { (stored(frame.stored_at())) }
            }
        }
    }
}

/// The id an envelope's stanza sits under, so a `prev` can point at it.
fn anchor(digest: &EnvelopeDigest) -> String {
    format!("e-{}", view::short(digest))
}

/// A digest in short, the whole a hover away, linking to its stanza when
/// the page shows one.
fn digest(digest: &EnvelopeDigest, shown: &HashSet<EnvelopeDigest>) -> Markup {
    let full = digest.to_hex();
    html! {
        @if shown.contains(digest) {
            a href=(format!("#{}", anchor(digest))) title=(full.as_ref()) {
                code { (view::short(digest)) }
            }
        } @else {
            code title=(full.as_ref()) { (view::short(digest)) }
        }
    }
}

/// When the log first saw the envelope, on the daemon's clock, in UTC.
fn stored(at: Option<DateTime<Utc>>) -> Markup {
    html! {
        @match at {
            Some(at) => time datetime=(at.to_rfc3339_opts(SecondsFormat::Millis, true)) {
                (at.format("%Y-%m-%d %H:%M:%S%.3f UTC"))
            },
            None => span.absent { "—" },
        }
    }
}

/// How the daemon scored the signatures.
fn status(status: &VerificationStatus) -> Markup {
    html! {
        @match status {
            VerificationStatus::Unchecked => span.unknown { "unchecked" },
            VerificationStatus::Failed { failing_key_ids } => span.bad {
                "failed, " (plural(failing_key_ids.len(), "bad signature", "bad signatures"))
            },
            VerificationStatus::AllMatched { total_weight } => span.good {
                "all matched, weight " (total_weight)
            },
        }
    }
}

/// A one-line summary of what the message does, the namespace and path
/// each a link to where it is browsed.
fn describe(msg: &Msg) -> Markup {
    html! {
        @match msg {
            Msg::Init(init) => {
                "init, " (plural(init.state.namespaces.len(), "namespace", "namespaces"))
            }
            Msg::SetNamespace(set) => { "set " (namespace(&set.key)) }
            Msg::SetNamespaceKey(set) => {
                (if set.value.is_some() { "set " } else { "clear " })
                (inside(&set.key, &set.path))
            }
            Msg::AmendNamespaceKey(amend) => {
                @let target = match &amend.path {
                    Some(path) => inside(&amend.key, path),
                    None => namespace(&amend.key),
                };
                @match &amend.op {
                    AmendOp::AppendEntry(_) => { "append an entry to " (target) }
                    AmendOp::IncrementDecrement(op) => { "add " (op.delta) " to " (target) }
                    AmendOp::DeleteMatching(predicate) => {
                        "delete entries of " (target) " matching "
                        (plural(predicate.as_ref().len(), "condition", "conditions"))
                    }
                }
            }
            Msg::DeleteNamespace(delete) => { "delete " (namespace(&delete.key)) }
        }
    }
}

fn namespace(key: &NamespaceKey) -> Markup {
    let to = Location::namespace(key.clone());
    html! { "namespace " (view::link(&to, key.as_ref())) }
}

fn inside(key: &NamespaceKey, path: &SubkeyPath) -> Markup {
    let to = Location::new(key.clone(), Some(path.clone()));
    html! { (view::link(&to, &path.to_string())) " in " (namespace(key)) }
}

/// What the message carries beyond its summary: the value it writes, or
/// the shape of what it removes. Nothing for messages the summary says
/// all of.
fn detail(msg: &Msg) -> Markup {
    html! {
        @match msg {
            Msg::Init(init) => {
                dt { "namespaces" }
                dd {
                    @if init.state.namespaces.is_empty() { span.absent { "—" } }
                    @for (key, namespace) in &init.state.namespaces {
                        div { code { (key) " = " (json::preview(&namespace.value, PREVIEW_WIDTH)) } }
                    }
                }
            }
            Msg::SetNamespace(set) => (value("value", &set.namespace.value)),
            Msg::SetNamespaceKey(set) => {
                @if let Some(written) = &set.value { (value("value", written)) }
            }
            Msg::AmendNamespaceKey(amend) => {
                @match &amend.op {
                    AmendOp::AppendEntry(entry) => (value("entry", entry)),
                    AmendOp::IncrementDecrement(op) => (clamp(op)),
                    AmendOp::DeleteMatching(predicate) => {
                        dt { "matching" }
                        dd {
                            @for matches in predicate.as_ref() { div { (condition(matches)) } }
                        }
                    }
                }
            }
            Msg::DeleteNamespace(_) => {}
        }
    }
}

fn value(label: &str, value: &Value) -> Markup {
    html! {
        dt { (label) }
        dd { code { (json::preview(value, PREVIEW_WIDTH)) } }
    }
}

/// The bounds an increment clamps to, where it has any.
fn clamp(op: &IncrementDecrement) -> Markup {
    let bounds: Vec<_> = [
        op.min.map(|min| format!("at least {min}")),
        op.max.map(|max| format!("at most {max}")),
    ]
    .into_iter()
    .flatten()
    .collect();
    html! {
        @if !bounds.is_empty() {
            dt { "clamped" }
            dd { (bounds.join(", ")) }
        }
    }
}

/// One condition of a delete predicate: where it looks, and what it must
/// find there.
fn condition(matches: &Match) -> Markup {
    let at = matches
        .path
        .as_ref()
        .map_or_else(|| "entry".to_string(), ToString::to_string);
    html! { code { (at) " = " (json::preview(&matches.value, PREVIEW_WIDTH)) } }
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_limit_shows_the_newest_and_an_empty_one_shows_all() {
        assert_eq!(Walk::parse(None, None).unwrap().limit, Some(DEFAULT_LIMIT));
        assert_eq!(Walk::parse(Some(""), None).unwrap().limit, None);
        assert_eq!(Walk::parse(Some(" 7 "), None).unwrap().limit, Some(7));
        assert!(Walk::parse(Some("seven"), None).is_err());
        assert!(Walk::parse(Some("-1"), None).is_err());
    }

    #[test]
    fn a_window_reads_as_lotusctl_reads_it() {
        let walk = Walk::parse(None, Some("15m")).unwrap();
        assert_eq!(walk.since, Some(Duration::from_secs(900)));
        assert_eq!(walk.request().since(), Some(Duration::from_secs(900)));
        assert_eq!(Walk::parse(None, Some("")).unwrap().since, None);
        for bad in ["", "m5", "5x", "1.5h"] {
            assert!(parse_window(bad).is_err(), "`{bad}` should not parse");
        }
    }

    #[test]
    fn a_window_shows_back_in_its_largest_whole_unit() {
        assert_eq!(window(Duration::from_secs(600)), "10m");
        assert_eq!(window(Duration::from_secs(7200)), "2h");
        assert_eq!(window(Duration::from_secs(172_800)), "2d");
        assert_eq!(window(Duration::from_secs(90)), "90s");
    }
}
