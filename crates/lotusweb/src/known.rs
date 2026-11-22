//! What a namespace's schema says of a location, and how that reads.

use core::fmt;

use lotus_sdk::{
    Schema, Subkey,
    schema::{Bounds, Kind},
};

use crate::Location;

/// A location the namespace's schema speaks of.
#[derive(Debug, Clone, Copy)]
pub struct Known<'a> {
    /// What the value there is held to.
    pub schema: &'a Schema,
    /// How the location sits in what holds it.
    pub place: Place,
}

/// How a location sits in the container it is an entry of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// Under a key or index the schema leaves free, or at the root.
    Free,
    /// A declared field of a struct: its name is fixed.
    Field { required: bool },
}

impl<'a> Known<'a> {
    /// What `namespace`, the schema of the namespace `location` is in,
    /// says of it; `None` where no conforming value reaches.
    pub fn locate(namespace: &'a Schema, location: &Location) -> Option<Self> {
        let segments = location.segments();
        let schema = namespace.at(segments)?;
        let place = match segments.split_last() {
            Some((Subkey::Key(name), parents)) => match namespace.at(parents).map(Schema::kind) {
                Some(Kind::Struct { required, .. }) => Place::Field {
                    required: required.contains(name),
                },
                _ => Place::Free,
            },
            _ => Place::Free,
        };
        Some(Self { schema, place })
    }

    /// Whether the schema refuses the value's removal.
    pub fn required(&self) -> bool {
        self.place == Place::Field { required: true }
    }

    /// Whether the value can move to another key.
    pub fn renamable(&self) -> bool {
        self.place == Place::Free
    }
}

/// What each entry of the container `schema` describes is held to, when
/// its keys or indices are free.
pub fn entry(schema: &Schema) -> Option<&Schema> {
    match schema.kind() {
        Kind::Map { values, .. } => Some(values),
        Kind::Array { items, .. } => Some(items),
        _ => None,
    }
}

/// The schema's type alone.
fn name(schema: &Schema) -> &'static str {
    match schema.kind() {
        Kind::Any => "any",
        Kind::Bool => "bool",
        Kind::Key => "trusted key",
        Kind::String { .. } => "string",
        Kind::Int { .. } => "int",
        Kind::Array { .. } => "array",
        Kind::Map { .. } => "map",
        Kind::Struct { .. } => "struct",
    }
}

/// The schema's type and what it restricts, on one line.
pub fn summary(schema: &Schema) -> String {
    let parts: Vec<String> = match schema.kind() {
        Kind::Any | Kind::Bool | Kind::Key | Kind::Struct { .. } => vec![],
        Kind::String { len, allowed } => allowed
            .as_ref()
            .map(one_of)
            .into_iter()
            .chain(length(len))
            .collect(),
        Kind::Int { range, allowed } => allowed
            .as_ref()
            .map(one_of)
            .into_iter()
            .chain(span(range))
            .collect(),
        Kind::Array { len, .. } | Kind::Map { len, .. } => length(len).into_iter().collect(),
    };
    let head = match entry(schema) {
        Some(entry) => format!("{} of {}", name(schema), name(entry)),
        None => name(schema).to_string(),
    };
    std::iter::once(head)
        .chain(parts)
        .collect::<Vec<_>>()
        .join(" · ")
}

fn one_of<T: fmt::Display>(allowed: impl IntoIterator<Item = T>) -> String {
    let listed: Vec<_> = allowed.into_iter().map(|one| one.to_string()).collect();
    format!("one of {}", listed.join(", "))
}

/// The range in words; `None` when it admits everything.
fn span<T: fmt::Display + PartialEq + Copy>(bounds: &Bounds<T>) -> Option<String> {
    match (bounds.min(), bounds.max()) {
        (None, None) => None,
        (Some(min), Some(max)) if min == max => Some(format!("exactly {min}")),
        (Some(min), Some(max)) => Some(format!("{min} to {max}")),
        (Some(min), None) => Some(format!("at least {min}")),
        (None, Some(max)) => Some(format!("at most {max}")),
    }
}

/// A length's range in words; `None` when any length does.
fn length(bounds: &Bounds<u64>) -> Option<String> {
    match (bounds.min(), bounds.max()) {
        (None | Some(0), None) => None,
        _ => span(bounds).map(|span| format!("length {span}")),
    }
}

#[cfg(test)]
mod tests {
    use lotus_sdk::NamespaceKey;

    use super::*;
    use crate::json;

    fn schema(text: &str) -> Schema {
        Schema::parse(&json::parse(text).unwrap()).unwrap()
    }

    fn at(path: &str) -> Location {
        Location::new(
            NamespaceKey::try_new("cfg").unwrap(),
            Some(path.parse().unwrap()),
        )
    }

    #[test]
    fn a_summary_names_the_type_and_what_it_restricts() {
        let cases = [
            (r#"{"type": "any"}"#, "any"),
            (r#"{"type": "string"}"#, "string"),
            (r#"{"type": "string", "min_len": 0}"#, "string"),
            (
                r#"{"type": "string", "min_len": 1}"#,
                "string · length at least 1",
            ),
            (
                r#"{"type": "string", "min_len": 64, "max_len": 64}"#,
                "string · length exactly 64",
            ),
            (
                r#"{"type": "string", "enum": ["b", "a"]}"#,
                "string · one of a, b",
            ),
            (
                r#"{"type": "int", "min": 0, "max": 65535}"#,
                "int · 0 to 65535",
            ),
            (r#"{"type": "int", "max": 9}"#, "int · at most 9"),
            (
                r#"{"type": "array", "items": {"type": "string"}, "min_len": 1}"#,
                "array of string · length at least 1",
            ),
            (r#"{"type": "map"}"#, "map of any"),
            (r#"{"type": "struct", "fields": {}}"#, "struct"),
        ];
        for (text, expected) in cases {
            assert_eq!(summary(&schema(text)), expected, "{text}");
        }
    }

    #[test]
    fn a_struct_field_is_placed_and_everything_else_is_free() {
        let namespace = schema(
            r#"{"type": "struct", "required": ["sites"], "fields": {
                "sites": {"type": "map", "values": {"type": "string"}},
                "port": {"type": "int"}
            }}"#,
        );
        let place = |path| Known::locate(&namespace, &at(path)).map(|known| known.place);
        assert_eq!(place("sites"), Some(Place::Field { required: true }));
        assert_eq!(place("port"), Some(Place::Field { required: false }));
        assert_eq!(place("sites.blog"), Some(Place::Free));
        assert_eq!(place("colour"), None);
        assert_eq!(place("port.deeper"), None);
        // A value that is not there yet is still spoken of.
        assert!(Known::locate(&namespace, &at("sites.new")).is_some());
    }
}
