//! Forms shaped by a schema: an input per value, typed as the schema
//! types it, and the submission read back by the same schema.
//!
//! A string, an integer and a bool each get the input that fits them, an
//! array of strings or integers a line each, and a struct an input per
//! field, nested structs nesting. What is left — maps, arrays of
//! containers, `any` — is typed as JSON inside the form, and has no typed
//! form of its own.
//!
//! An optional field left blank is left out, so a blank cannot spell the
//! empty string there; a required one left blank is the empty value of its
//! type where there is one, for the ledger to judge.

use std::collections::{BTreeMap, BTreeSet};

use lotus_sdk::{
    Schema, Value,
    schema::{Bounds, Kind},
};
use maud::{Markup, html};
use serde::Deserialize;

use crate::{Error, json, known};

/// The field a form types its value into as JSON.
pub const JSON: &str = "value";
/// The field naming the key a map's new entry goes under.
pub const KEY: &str = "key";
/// The field a typed form's value is under; a struct's fields are below
/// it, `f.<field>`.
const ROOT: &str = "f";

/// What a number input can bound: past it a browser compares doubles
/// that no longer tell neighbouring integers apart.
const EXACT: i64 = 1 << 53;

/// What a form submitted, by field.
#[derive(Debug, Deserialize)]
#[serde(transparent)]
pub struct Fields(BTreeMap<String, String>);

impl Fields {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    /// What was typed into `name`; `None` when nothing was.
    fn typed(&self, name: &str) -> Option<&str> {
        self.get(name).filter(|text| !text.is_empty())
    }
}

/// The input a schema's value is typed into.
enum Widget<'a> {
    Text {
        len: &'a Bounds<u64>,
        allowed: Option<&'a BTreeSet<String>>,
    },
    Number {
        range: &'a Bounds<i64>,
        allowed: Option<&'a BTreeSet<i64>>,
    },
    Flag,
    /// An array, an item to a line.
    Lines(Line),
    Group {
        fields: &'a BTreeMap<String, Schema>,
        required: &'a BTreeSet<String>,
    },
    Json,
}

/// What one line of a [`Widget::Lines`] holds.
#[derive(Clone, Copy)]
enum Line {
    Text,
    Number,
}

fn widget(schema: &Schema) -> Widget<'_> {
    match schema.kind() {
        Kind::String { len, allowed } => Widget::Text {
            len,
            allowed: allowed.as_ref(),
        },
        Kind::Int { range, allowed } => Widget::Number {
            range,
            allowed: allowed.as_ref(),
        },
        Kind::Bool => Widget::Flag,
        Kind::Struct { fields, required } => Widget::Group { fields, required },
        Kind::Array { items, .. } => match items.kind() {
            Kind::String { .. } => Widget::Lines(Line::Text),
            Kind::Int { .. } => Widget::Lines(Line::Number),
            _ => Widget::Json,
        },
        Kind::Any | Kind::Key | Kind::Map { .. } => Widget::Json,
    }
}

/// Whether a value held to `schema` has a typed form.
pub fn typed(schema: &Schema) -> bool {
    !matches!(widget(schema), Widget::Json)
}

/// Whether `value`, a leaf, can be edited in the typed form for `schema`
/// and come back as it went in.
pub fn edits(schema: &Schema, value: &Value) -> bool {
    match (widget(schema), value) {
        // A form posts every line break as CRLF, read back as LF: a
        // string holding a CR would not survive the trip.
        (Widget::Text { .. }, Value::String(text)) => !text.contains('\r'),
        (Widget::Number { .. }, Value::Int(_)) | (Widget::Flag, Value::Bool(_)) => true,
        _ => false,
    }
}

/// The name of `field`'s input, below the struct's at `parent`.
fn below(parent: &str, field: &str) -> String {
    // A dot inside a field's name must not read as a step down.
    let field = field.replace('%', "%25").replace('.', "%2E");
    format!("{parent}.{field}")
}

/// How an input's name reads in a failure.
fn label(name: &str) -> String {
    match name.strip_prefix(ROOT).and_then(|at| at.strip_prefix('.')) {
        Some(path) => format!("`{}`", path.replace("%2E", ".").replace("%25", "%")),
        None => "the value".to_string(),
    }
}

/// The inputs for a value held to `schema`, prefilled with `current`.
pub fn inputs(schema: &Schema, current: Option<&Value>) -> Markup {
    match widget(schema) {
        Widget::Group { fields, required } => group(ROOT, fields, required, true),
        // What the value is held to is said once, above the form.
        _ => html! {
            label.field {
                span.field-head { span.field-name { "Value" } span.field-type { (hint(schema)) } }
                (control(ROOT, schema, true, current))
            }
        },
    }
}

/// The inputs of a struct's fields. `firm` says the struct itself must
/// be there: only then must its required fields be filled, an optional
/// struct being left out by leaving all of it blank.
fn group(
    name: &str,
    fields: &BTreeMap<String, Schema>,
    required: &BTreeSet<String>,
    firm: bool,
) -> Markup {
    html! {
        @for (title, schema) in fields {
            @let required = required.contains(title);
            (field(title, &below(name, title), schema, required, firm && required))
        }
    }
}

/// One labelled input: what it is called, what the schema says of it,
/// and the control itself.
fn field(title: &str, name: &str, schema: &Schema, required: bool, firm: bool) -> Markup {
    let head = html! {
        span.field-name { (title) }
        @if required { span.required { "required" } }
        span.field-type { (known::summary(schema)) (hint(schema)) }
    };
    let description = html! {
        @if let Some(description) = schema.description() { span.description { (description) } }
    };
    match widget(schema) {
        Widget::Group { fields, required } => html! {
            fieldset.group {
                legend { (head) }
                (description)
                (group(name, fields, required, firm))
            }
        },
        _ => html! {
            label.field {
                span.field-head { (head) }
                (description)
                (control(name, schema, firm, None))
            }
        },
    }
}

/// How the control wants its value typed, where the type does not say.
fn hint(schema: &Schema) -> &'static str {
    match widget(schema) {
        Widget::Lines(_) => " · one per line",
        Widget::Json => " · as JSON",
        _ => "",
    }
}

/// The control alone. `firm` says the form cannot go without a value
/// here, which the browser then holds it to.
fn control(name: &str, schema: &Schema, firm: bool, current: Option<&Value>) -> Markup {
    match widget(schema) {
        Widget::Text {
            allowed: Some(allowed),
            ..
        } => {
            let current = match current {
                Some(Value::String(text)) => Some(text),
                _ => None,
            };
            choice(
                name,
                firm,
                allowed
                    .iter()
                    .map(|one| (one.as_str(), Some(one) == current)),
            )
        }
        Widget::Text { len, allowed: None } => {
            let text = match current {
                Some(Value::String(text)) => text.as_str(),
                _ => "",
            };
            // Only the minimum: HTML counts UTF-16 units where the schema
            // counts scalar values, so its maximum would refuse strings
            // the schema admits.
            let min = len.min().filter(|min| *min > 0);
            let needed = firm && min.is_some();
            html! {
                @if name == ROOT {
                    // The parser drops a textarea's first line break, so
                    // one is spent ahead of text that may begin with its own.
                    textarea name=(name) rows=(text.lines().count().clamp(1, 24))
                        minlength=[min] required[needed] spellcheck="false" { "\n" (text) }
                } @else {
                    input type="text" name=(name) value=(text) minlength=[min] required[needed]
                        spellcheck="false";
                }
            }
        }
        Widget::Number {
            allowed: Some(allowed),
            ..
        } => {
            let current = match current {
                Some(Value::Int(n)) => Some(n),
                _ => None,
            };
            let options: Vec<_> = allowed
                .iter()
                .map(|one| (one.to_string(), Some(one) == current))
                .collect();
            choice(
                name,
                firm,
                options.iter().map(|(one, picked)| (one.as_str(), *picked)),
            )
        }
        Widget::Number {
            range,
            allowed: None,
        } => {
            let value = match current {
                Some(Value::Int(n)) => Some(*n),
                _ => None,
            };
            let exact = |bound: Option<i64>| bound.filter(|n| (-EXACT..=EXACT).contains(n));
            html! {
                input type="number" name=(name) step="1" value=[value] min=[exact(range.min())]
                    max=[exact(range.max())] required[firm];
            }
        }
        Widget::Flag => {
            let current = match current {
                Some(Value::Bool(flag)) => Some(*flag),
                _ => None,
            };
            choice(
                name,
                firm,
                [
                    ("true", current == Some(true)),
                    ("false", current == Some(false)),
                ],
            )
        }
        Widget::Lines(_) => html! {
            textarea name=(name) rows="3" spellcheck="false" {}
        },
        Widget::Group { .. } | Widget::Json => {
            let placeholder = match schema.kind() {
                Kind::Array { .. } => "[ … ]",
                Kind::Any => "\"text\", 7, true, [ … ] or { … }",
                _ => "{ … }",
            };
            html! {
                textarea name=(name) rows="3" placeholder=(placeholder) spellcheck="false" {}
            }
        }
    }
}

/// A pick of one of `options`, each with whether it is the current one.
/// Nothing is picked until the person picks: a firm choice starts on a
/// blank the browser will not submit, never on whichever option is first.
fn choice<'a>(
    name: &str,
    firm: bool,
    options: impl IntoIterator<Item = (&'a str, bool)>,
) -> Markup {
    let options: Vec<_> = options.into_iter().collect();
    let unpicked = !options.iter().any(|(_, picked)| *picked);
    html! {
        select name=(name) required[firm] {
            @if unpicked || !firm {
                option value="" selected[unpicked] { @if firm { "— choose —" } @else { "— not set —" } }
            }
            @for (option, picked) in options {
                option value=(option) selected[picked] { (option) }
            }
        }
    }
}

/// Reads the value a typed form submitted, as `schema` types it. Whether
/// it conforms is the ledger's to say.
pub fn decode(schema: &Schema, fields: &Fields) -> Result<Value, Error> {
    filled(schema, ROOT, fields)
}

/// The value at `name`, which must have one.
fn filled(schema: &Schema, name: &str, fields: &Fields) -> Result<Value, Error> {
    entered(schema, name, fields)?.map_or_else(|| blank(schema, name), Ok)
}

/// The value typed in at `name`; `None` when nothing was.
fn entered(schema: &Schema, name: &str, fields: &Fields) -> Result<Option<Value>, Error> {
    let text = fields.typed(name);
    match widget(schema) {
        Widget::Text { .. } => Ok(text.map(|text| Value::String(text.replace("\r\n", "\n")))),
        Widget::Number { .. } => text.map(|text| int(text, name)).transpose(),
        Widget::Flag => text
            .map(|text| match text {
                "true" => Ok(Value::Bool(true)),
                "false" => Ok(Value::Bool(false)),
                _ => Err(Error::Invalid(format!(
                    "{} must be true or false",
                    label(name)
                ))),
            })
            .transpose(),
        Widget::Lines(line) => {
            let items = text
                .into_iter()
                .flat_map(str::lines)
                .filter_map(|item| match line {
                    Line::Text => (!item.is_empty()).then(|| Ok(Value::String(item.to_string()))),
                    Line::Number => (!item.trim().is_empty()).then(|| int(item, name)),
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok((!items.is_empty()).then_some(Value::Array(items)))
        }
        Widget::Json => text
            .filter(|text| !text.trim().is_empty())
            .map(|text| {
                json::parse(text).map_err(|e| Error::Invalid(format!("{}: {e}", label(name))))
            })
            .transpose(),
        Widget::Group {
            fields: declared,
            required,
        } => {
            let members = declared
                .iter()
                .map(|(field, schema)| {
                    let at = below(name, field);
                    entered(schema, &at, fields).map(|value| (field, schema, at, value))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if members.iter().all(|(.., value)| value.is_none()) {
                return Ok(None);
            }
            members
                .into_iter()
                .filter_map(|(field, schema, at, value)| match value {
                    Some(value) => Some(Ok((field.clone(), value))),
                    None if required.contains(field) => {
                        Some(blank(schema, &at).map(|value| (field.clone(), value)))
                    }
                    None => None,
                })
                .collect::<Result<_, _>>()
                .map(|members| Some(Value::Map(members)))
        }
    }
}

/// What a required value left blank at `name` stands for: the empty
/// value of its type, where the type has one.
fn blank(schema: &Schema, name: &str) -> Result<Value, Error> {
    let needed = || Error::Invalid(format!("{} needs a value", label(name)));
    match widget(schema) {
        Widget::Text { .. } => Ok(Value::String(String::new())),
        Widget::Lines(_) => Ok(Value::Array(Vec::new())),
        Widget::Number { .. } | Widget::Flag => Err(needed()),
        Widget::Json => match schema.kind() {
            Kind::Map { .. } => Ok(Value::Map(BTreeMap::new())),
            Kind::Array { .. } => Ok(Value::Array(Vec::new())),
            _ => Err(needed()),
        },
        Widget::Group { fields, required } => required
            .iter()
            .filter_map(|field| fields.get_key_value(field))
            .map(|(field, schema)| {
                blank(schema, &below(name, field)).map(|value| (field.clone(), value))
            })
            .collect::<Result<_, _>>()
            .map(Value::Map),
    }
}

fn int(text: &str, name: &str) -> Result<Value, Error> {
    text.trim().parse().map(Value::Int).map_err(|_| {
        Error::Invalid(format!(
            "{}: `{text}` is not a whole number an i64 holds",
            label(name)
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema(text: &str) -> Schema {
        Schema::parse(&json::parse(text).unwrap()).unwrap()
    }

    fn fields(pairs: &[(&str, &str)]) -> Fields {
        Fields(
            pairs
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
        )
    }

    fn decoded(schema: &Schema, pairs: &[(&str, &str)]) -> Result<Value, String> {
        decode(schema, &fields(pairs)).map_err(|error| error.describe())
    }

    fn value(text: &str) -> Value {
        json::parse(text).unwrap()
    }

    /// A route, as a site's schema might hold one.
    fn route() -> Schema {
        schema(
            r#"{"type": "struct", "required": ["kind"], "fields": {
                "kind": {"type": "string", "enum": ["files", "proxy"]},
                "to": {"type": "string"},
                "status": {"type": "int", "min": 0, "max": 65535},
                "strip_prefix": {"type": "bool"},
                "aliases": {"type": "array", "items": {"type": "string"}},
                "headers": {"type": "map", "values": {"type": "string"}},
                "auth": {"type": "struct", "required": ["users"], "fields": {
                    "users": {"type": "array", "items": {"type": "string"}, "min_len": 1},
                    "realm": {"type": "string"}
                }}
            }}"#,
        )
    }

    #[test]
    fn a_leaf_is_read_as_its_type() {
        assert_eq!(
            decoded(&schema(r#"{"type": "string"}"#), &[("f", "7")]),
            Ok(Value::from("7"))
        );
        assert_eq!(
            decoded(&schema(r#"{"type": "int"}"#), &[("f", " 7 ")]),
            Ok(Value::Int(7))
        );
        assert_eq!(
            decoded(&schema(r#"{"type": "bool"}"#), &[("f", "false")]),
            Ok(Value::Bool(false))
        );
    }

    #[test]
    fn a_leaf_that_is_not_its_type_is_refused() {
        assert_eq!(
            decoded(&schema(r#"{"type": "int"}"#), &[("f", "seven")]),
            Err("the value: `seven` is not a whole number an i64 holds".into())
        );
        assert_eq!(
            decoded(&schema(r#"{"type": "bool"}"#), &[("f", "yes")]),
            Err("the value must be true or false".into())
        );
        assert_eq!(
            decoded(&schema(r#"{"type": "int"}"#), &[("f", "")]),
            Err("the value needs a value".into())
        );
    }

    #[test]
    fn a_blank_string_at_the_root_is_the_empty_string() {
        assert_eq!(
            decoded(&schema(r#"{"type": "string"}"#), &[("f", "")]),
            Ok(Value::from(""))
        );
    }

    #[test]
    fn line_breaks_come_back_as_they_were_shown() {
        assert_eq!(
            decoded(&schema(r#"{"type": "string"}"#), &[("f", "a\r\nb")]),
            Ok(Value::from("a\nb"))
        );
    }

    #[test]
    fn a_struct_takes_what_was_typed_and_leaves_out_the_rest() {
        assert_eq!(
            decoded(
                &route(),
                &[
                    ("f.kind", "proxy"),
                    ("f.to", "http://127.0.0.1:8080"),
                    ("f.status", ""),
                    ("f.strip_prefix", "true"),
                    ("f.aliases", "a.example\r\n\r\nb.example\r\n"),
                    ("f.headers", r#"{"x-via": "lotus"}"#),
                    ("f.auth.users", ""),
                    ("f.auth.realm", ""),
                ]
            ),
            Ok(value(
                r#"{"kind": "proxy", "to": "http://127.0.0.1:8080", "strip_prefix": true,
                    "aliases": ["a.example", "b.example"], "headers": {"x-via": "lotus"}}"#
            ))
        );
    }

    #[test]
    fn a_nested_struct_appears_once_any_of_it_is_typed() {
        assert_eq!(
            decoded(&route(), &[("f.kind", "files"), ("f.auth.realm", "staff")]),
            Ok(value(
                r#"{"kind": "files", "auth": {"realm": "staff", "users": []}}"#
            ))
        );
        assert_eq!(
            decoded(
                &route(),
                &[("f.kind", "files"), ("f.auth.users", "alice\nbob")]
            ),
            Ok(value(
                r#"{"kind": "files", "auth": {"users": ["alice", "bob"]}}"#
            ))
        );
    }

    #[test]
    fn a_required_field_left_blank_is_the_empty_value_of_its_type() {
        let zone = schema(
            r#"{"type": "struct", "required": ["name", "records", "soa"], "fields": {
                "name": {"type": "string"},
                "records": {"type": "map"},
                "soa": {"type": "struct", "required": ["primary"], "fields": {
                    "primary": {"type": "string"}, "serial": {"type": "int"}
                }},
                "ttl": {"type": "int"}
            }}"#,
        );
        assert_eq!(
            decoded(&zone, &[]),
            Ok(value(
                r#"{"name": "", "records": {}, "soa": {"primary": ""}}"#
            ))
        );
    }

    #[test]
    fn a_required_number_left_blank_is_refused_by_name() {
        let mx = schema(
            r#"{"type": "struct", "required": ["preference"], "fields": {
                "preference": {"type": "int"}, "exchange": {"type": "string"}
            }}"#,
        );
        assert_eq!(
            decoded(&mx, &[("f.exchange", "mx.example")]),
            Err("`preference` needs a value".into())
        );
    }

    #[test]
    fn json_typed_inside_a_form_must_be_json() {
        let error = decoded(&route(), &[("f.kind", "files"), ("f.headers", "{nope")]).unwrap_err();
        assert!(error.starts_with("`headers`: not JSON"), "{error}");
    }

    #[test]
    fn a_dot_in_a_field_name_is_not_a_step_down() {
        let dotted = schema(
            r#"{"type": "struct", "fields": {
                "a.b": {"type": "string"},
                "a": {"type": "struct", "fields": {"b": {"type": "string"}}}
            }}"#,
        );
        assert_eq!(
            decoded(&dotted, &[("f.a%2Eb", "flat"), ("f.a.b", "nested")]),
            Ok(value(r#"{"a.b": "flat", "a": {"b": "nested"}}"#))
        );
        assert_eq!(label("f.a%2Eb"), "`a.b`");
    }

    #[test]
    fn what_has_no_typed_form_is_told_apart() {
        assert!(typed(&route()));
        assert!(typed(&schema(
            r#"{"type": "array", "items": {"type": "int"}}"#
        )));
        assert!(!typed(&schema(r#"{"type": "any"}"#)));
        assert!(!typed(&schema(r#"{"type": "map"}"#)));
        assert!(!typed(&schema(r#"{"type": "array"}"#)));
    }

    #[test]
    fn a_leaf_is_edited_typed_only_when_it_survives_the_trip() {
        let string = schema(r#"{"type": "string"}"#);
        assert!(edits(&string, &Value::from("a\nb")));
        assert!(!edits(&string, &Value::from("a\r\nb")));
        assert!(!edits(&string, &Value::Int(1)));
        assert!(edits(&schema(r#"{"type": "int"}"#), &Value::Int(1)));
    }

    #[test]
    fn inputs_carry_what_the_schema_restricts() {
        let page = inputs(&route(), None).into_string();
        // A required pick starts unpicked, and the browser holds it there.
        assert!(
            page.contains(
                r#"<select name="f.kind" required><option value="" selected>— choose —</option>"#
            ),
            "{page}"
        );
        assert!(
            page.contains(r#"<select name="f.strip_prefix"><option value="" selected>— not set —"#),
            "{page}"
        );
        assert!(
            page.contains(r#"<input type="number" name="f.status" step="1" min="0" max="65535">"#),
            "{page}"
        );
        assert!(page.contains(r#"<textarea name="f.auth.users""#), "{page}");

        let port = schema(r#"{"type": "int", "min": 1, "description": "Where it listens."}"#);
        let page = inputs(&port, Some(&Value::Int(443))).into_string();
        assert!(page.contains(r#"value="443" min="1" required"#), "{page}");
    }

    #[test]
    fn an_optional_struct_can_be_left_blank_whatever_it_requires() {
        let site = schema(
            r#"{"type": "struct", "required": ["name"], "fields": {
                "name": {"type": "string", "min_len": 1},
                "owner": {"type": "struct", "required": ["id", "role"], "fields": {
                    "id": {"type": "int"},
                    "role": {"type": "string", "enum": ["admin", "guest"]}
                }}
            }}"#,
        );
        let page = inputs(&site, None).into_string();
        assert!(
            page.contains(r#"<input type="text" name="f.name" value="" minlength="1" required"#),
            "{page}"
        );
        assert!(
            page.contains(r#"<input type="number" name="f.owner.id" step="1">"#),
            "{page}"
        );
        assert!(
            page.contains(r#"<select name="f.owner.role"><option value="" selected>— not set —"#),
            "{page}"
        );
        assert_eq!(
            decoded(
                &site,
                &[("f.name", "blog"), ("f.owner.id", ""), ("f.owner.role", "")]
            ),
            Ok(value(r#"{"name": "blog"}"#))
        );
    }
}
