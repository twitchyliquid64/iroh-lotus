//! Ledger values as the JSON a person types and reads.
//!
//! Plain JSON, as `lotusctl` speaks it: objects are maps, numbers must be
//! whole, and a trusted key — which plain JSON has no shape for — is shown
//! in the ledger's tagged form and never read back from it. So text typed
//! into a form can create every kind of value but a key, which keeps the
//! trusted key set out of reach of a stray edit.

use lotus_sdk::Value;

/// Why text could not be read as a ledger value.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("not JSON: {0}")]
    Syntax(#[from] serde_json::Error),
    #[error("{0} is not a whole number an i64 holds")]
    NotInteger(serde_json::Number),
    #[error("null is not a value the ledger holds")]
    Null,
}

/// Reads `text` as a JSON literal — a string is quoted — and that as a
/// ledger value.
pub fn parse(text: &str) -> Result<Value, ParseError> {
    serde_json::from_str(text.trim())
        .map_err(ParseError::Syntax)
        .and_then(from_json)
}

fn from_json(json: serde_json::Value) -> Result<Value, ParseError> {
    match json {
        serde_json::Value::String(text) => Ok(Value::String(text)),
        serde_json::Value::Bool(flag) => Ok(Value::Bool(flag)),
        serde_json::Value::Number(number) => number
            .as_i64()
            .map(Value::Int)
            .ok_or(ParseError::NotInteger(number)),
        serde_json::Value::Array(items) => items
            .into_iter()
            .map(from_json)
            .collect::<Result<_, _>>()
            .map(Value::Array),
        serde_json::Value::Object(fields) => fields
            .into_iter()
            .map(|(key, value)| from_json(value).map(|value| (key, value)))
            .collect::<Result<_, _>>()
            .map(Value::Map),
        serde_json::Value::Null => Err(ParseError::Null),
    }
}

/// Writes a ledger value as plain JSON, a trusted key in the tagged form.
pub fn to_json(value: &Value) -> serde_json::Value {
    match value {
        Value::String(text) => serde_json::Value::String(text.clone()),
        Value::Int(n) => serde_json::Value::from(*n),
        Value::Bool(flag) => serde_json::Value::Bool(*flag),
        Value::Array(items) => serde_json::Value::Array(items.iter().map(to_json).collect()),
        Value::Map(fields) => serde_json::Value::Object(
            fields
                .iter()
                .map(|(key, value)| (key.clone(), to_json(value)))
                .collect(),
        ),
        Value::Key(_) => {
            serde_json::to_value(value).expect("a ledger value serializes as tagged JSON")
        }
    }
}

/// The value over lines, as an editor shows it.
pub fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(&to_json(value)).expect("JSON with string keys serializes")
}

/// The value on one line, cut to about `width` characters.
pub fn preview(value: &Value, width: usize) -> String {
    let text = to_json(value).to_string();
    match text.char_indices().nth(width) {
        Some((cut, _)) => format!("{}…", &text[..cut]),
        None => text,
    }
}

/// Whether a trusted key sits anywhere inside `value`. Such a value can
/// not be edited as plain JSON: written back, the key would come out a map.
pub fn holds_key(value: &Value) -> bool {
    match value {
        Value::Key(_) => true,
        Value::Array(items) => items.iter().any(holds_key),
        Value::Map(fields) => fields.values().any(holds_key),
        Value::String(_) | Value::Int(_) | Value::Bool(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_json_reads_as_a_value() {
        assert_eq!(parse("\"hi\"").unwrap(), Value::from("hi"));
        assert_eq!(parse(" 7 ").unwrap(), Value::Int(7));
        assert_eq!(parse("true").unwrap(), Value::Bool(true));
        assert_eq!(
            parse("{\"a\": [1, \"b\"]}").unwrap(),
            Value::from_iter([("a", Value::from_iter([Value::Int(1), Value::from("b")]))])
        );
    }

    #[test]
    fn what_the_ledger_cannot_hold_is_refused() {
        assert!(matches!(parse("null"), Err(ParseError::Null)));
        assert!(matches!(parse("1.5"), Err(ParseError::NotInteger(_))));
        assert!(matches!(parse("hello"), Err(ParseError::Syntax(_))));
    }

    #[test]
    fn a_preview_is_cut_on_a_character_boundary() {
        let value = Value::from("ünïcödé text that runs on");
        assert_eq!(preview(&value, 6), "\"ünïcö…");
        assert_eq!(preview(&Value::Int(7), 6), "7");
    }

    #[test]
    fn a_value_round_trips_through_its_text() {
        let value = Value::from_iter([("host", Value::from("a")), ("port", Value::Int(443))]);
        assert_eq!(parse(&pretty(&value)).unwrap(), value);
    }
}
