//! Showing the value an envelope writes.
//!
//! A preview, never a serialization: a value runs from an integer to a
//! whole checkpoint, so what fits is written out JSON-shaped and what
//! does not is elided. A reader who needs the value itself asks for JSON.

use core::fmt::Write as _;

use wire::msg::Value;

/// Columns a preview line may fill, past the label a stanza pads to.
const WIDTH: usize = 60;

/// Lines one preview may run to, its elisions counted.
const LINES: usize = 8;

/// Spaces one level of nesting indents by.
const INDENT: usize = 2;

/// Columns a leaf is never elided below, however deep it sits: a value
/// cut to nothing says less than a line that runs long.
const MIN_LEAF: usize = 16;

/// The lines `value` previews as, `prefix` opening the first: one line
/// where the whole of it fits, broken and elided where it does not.
pub(crate) fn preview(prefix: &str, value: &Value) -> Vec<String> {
    let mut lines = lines(value, width(prefix), 0, LINES);
    if let Some(first) = lines.first_mut() {
        *first = format!("{prefix}{first}");
    }
    lines
}

/// The lines a labelled list of values previews as, the whole list under
/// one budget and each value under an equal share of it.
///
/// A genesis names every namespace in the ledger, and a stanza has no
/// more room for all of them together than it has for one large value.
/// The share is what keeps the first namespace from spending the lines
/// the rest of them are shown in.
pub(crate) fn previews<'a>(
    values: impl ExactSizeIterator<Item = (String, &'a Value)>,
) -> Vec<String> {
    let share = LINES.div_ceil(values.len().max(1));
    entries(values, 0, LINES, share, Separated::No)
}

/// Whether a list carries JSON's separator between its entries.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Separated {
    Yes,
    No,
}

/// The lines `value` renders to: the first starting at column `start`,
/// the rest indented to `indent`, `budget` of them at most.
fn lines(value: &Value, start: usize, indent: usize, budget: usize) -> Vec<String> {
    let room = WIDTH.saturating_sub(start);

    let mut one_line = String::new();
    if write_compact(&mut one_line, value, room) {
        return vec![one_line];
    }

    match value {
        // An array of leaves is a list rather than a record: broken over
        // lines it spends one a value and so shows fewer of them than the
        // single elided line does.
        Value::Array(items) if items.iter().all(is_leaf) => vec![elide(&one_line, room)],
        Value::Map(fields) if breakable(fields.len(), budget) => container(
            ('{', '}'),
            fields
                .iter()
                .map(|(key, value)| (format!("{}: ", quoted(key)), value)),
            indent,
            budget,
        ),
        Value::Array(items) if breakable(items.len(), budget) => container(
            ('[', ']'),
            items.iter().map(|value| (String::new(), value)),
            indent,
            budget,
        ),
        // Elided inside its quotes rather than after them: a string that
        // ends mid-escape reads as a broken value rather than a cut one.
        Value::String(text) => vec![quoted(&elide(text, room.saturating_sub(2)))],
        // Whatever is left has no room to be broken up: what a container
        // holds says more than a count of how much it holds, so the one
        // line it gets carries as much of the value as fits.
        _ => vec![elide(&one_line, room)],
    }
}

/// Whether a container of `total` entries is worth breaking over
/// `budget` lines: an opener and a closer, a line for something real
/// inside them, and — where more than one entry is in play — a line for
/// the count of what was left out. Three lines carrying only that count
/// say less than the one line an elided value gets.
fn breakable(total: usize, budget: usize) -> bool {
    budget >= 3 + usize::from(total > 1)
}

/// Whether `value` is one a path stops at — the containers are the two a
/// preview can break over lines.
fn is_leaf(value: &Value) -> bool {
    !matches!(value, Value::Array(_) | Value::Map(_))
}

/// Breaks a container over its entries, one line each where they fit,
/// between an opener and a closer that hold a line back each.
fn container<'a>(
    (open, close): (char, char),
    values: impl ExactSizeIterator<Item = (String, &'a Value)>,
    indent: usize,
    budget: usize,
) -> Vec<String> {
    let inside = budget - 2;
    // No share inside a container: what it holds is one value, and the
    // lines belong to whichever part of it needs them first.
    let mut out = vec![open.to_string()];
    out.extend(entries(
        values,
        indent + INDENT,
        inside,
        inside,
        Separated::Yes,
    ));
    out.push(format!("{}{close}", " ".repeat(indent)));
    out
}

/// Writes each of `values` at `indent`, its label opening it, within
/// `budget` lines for the list and `share` for any one of them. Whatever
/// is left over when the budget runs out becomes a count of it.
fn entries<'a>(
    values: impl ExactSizeIterator<Item = (String, &'a Value)>,
    indent: usize,
    budget: usize,
    share: usize,
    separated: Separated,
) -> Vec<String> {
    let pad = " ".repeat(indent);
    let total = values.len();
    let mut out: Vec<String> = Vec::new();

    for (index, (label, value)) in values.enumerate() {
        // Whatever follows this entry holds a line back, be it written
        // out or elided into a count.
        let left = budget - out.len();
        let rest = total - index;
        let held = usize::from(rest > 1);
        if left <= held {
            out.push(format!("{pad}… {rest} more"));
            break;
        }

        let mut sub = lines(
            value,
            indent + width(&label),
            indent,
            (left - held).min(share.max(1)),
        )
        .into_iter();
        out.push(format!("{pad}{label}{}", sub.next().unwrap_or_default()));
        out.extend(sub);
        // Every entry but the last carries a separator — the `… more`
        // that stands in for a tail included, since the list does go on.
        // An entry that was itself elided has said so already.
        let last = out.last_mut().expect("a line was just pushed");
        if separated == Separated::Yes && rest > 1 && !last.ends_with('…') {
            last.push(',');
        }
    }

    out
}

/// Writes `value` on one line, giving up the moment it passes `room`
/// columns: a value can be a whole checkpoint, and no preview needs the
/// string for one.
fn write_compact(out: &mut String, value: &Value, room: usize) -> bool {
    if width(out) > room {
        return false;
    }
    match value {
        Value::String(text) => out.push_str(&quoted(text)),
        Value::Int(int) => {
            let _ = write!(out, "{int}");
        }
        Value::Bool(flag) => {
            let _ = write!(out, "{flag}");
        }
        // Angle brackets, because a trusted key is not a value JSON has a
        // shape for. Its metadata is not a preview's business.
        Value::Key(key) => {
            let _ = write!(out, "<{key}>");
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                if !write_compact(out, item, room) {
                    return false;
                }
            }
            out.push(']');
        }
        Value::Map(fields) => {
            out.push('{');
            for (index, (key, field)) in fields.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                let _ = write!(out, "{}: ", quoted(key));
                if !write_compact(out, field, room) {
                    return false;
                }
            }
            out.push('}');
        }
    }
    width(out) <= room
}

/// `text` as a JSON string literal.
fn quoted(text: &str) -> String {
    let escaped = text
        .chars()
        .map(|c| match c {
            '"' => "\\\"".to_string(),
            '\\' => "\\\\".to_string(),
            '\u{8}' => "\\b".to_string(),
            '\u{c}' => "\\f".to_string(),
            '\n' => "\\n".to_string(),
            '\r' => "\\r".to_string(),
            '\t' => "\\t".to_string(),
            c if c.is_control() => format!("\\u{:04x}", u32::from(c)),
            c => c.to_string(),
        })
        .collect::<String>();
    format!("\"{escaped}\"")
}

/// `text` cut to `width` columns, ending in an ellipsis where it was cut.
fn elide(text: &str, width: usize) -> String {
    let width = width.max(MIN_LEAF);
    match text.chars().count() <= width {
        true => text.to_string(),
        false => text.chars().take(width - 1).chain(['…']).collect(),
    }
}

/// The columns `text` occupies. Close enough: nothing here is painted,
/// and a value wide enough for the difference to matter is elided.
fn width(text: &str) -> usize {
    text.chars().count()
}
