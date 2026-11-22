//! Schemas: what an operator declares a namespace's value may hold.
//!
//! A schema is itself a [`Value`] — a map naming a `type` and that type's
//! keywords — so it is written, read and browsed like any other state.
//! The language is closed and small on purpose: every node must judge a
//! value the same way forever, and anything looser (a regex engine, a
//! float comparison) is somewhere two builds can disagree.
//!
//! | `type`   | keywords                         |
//! |----------|----------------------------------|
//! | `any`    |                                  |
//! | `bool`   |                                  |
//! | `key`    |                                  |
//! | `string` | `min_len`, `max_len`, `enum`     |
//! | `int`    | `min`, `max`, `enum`             |
//! | `array`  | `items`, `min_len`, `max_len`    |
//! | `map`    | `values`, `min_len`, `max_len`   |
//! | `struct` | `fields` (required), `required`  |
//!
//! A string's length counts Unicode scalar values. `items` and `values`
//! default to `any`. A `struct` is closed: a field its `fields` does not
//! name is refused.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use wire::{
    msg::{AmendOp, NamespaceKey, Value},
    subkey::{Subkey, SubkeyPath},
};

/// The prefix of the namespaces the ledger reserves for itself. Their
/// rules are baked in, so a schema may not name one.
pub(crate) const RESERVED_PREFIX: &str = "_lotus_";

/// What a value must look like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schema(Node);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Any,
    Bool,
    Key,
    String {
        len: Bounds<u64>,
        allowed: Option<BTreeSet<String>>,
    },
    Int {
        range: Bounds<i64>,
        allowed: Option<BTreeSet<i64>>,
    },
    Array {
        items: Box<Node>,
        len: Bounds<u64>,
    },
    Map {
        values: Box<Node>,
        len: Bounds<u64>,
    },
    Struct {
        fields: BTreeMap<String, Node>,
        required: BTreeSet<String>,
    },
}

/// An inclusive range, open on any side left unset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds<T> {
    min: Option<T>,
    max: Option<T>,
}

impl<T: Ord + Copy> Bounds<T> {
    fn contains(&self, n: T) -> bool {
        self.min.is_none_or(|min| n >= min) && self.max.is_none_or(|max| n <= max)
    }
}

impl<T: fmt::Display> fmt::Display for Bounds<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.min, &self.max) {
            (Some(min), Some(max)) => write!(f, "{min} to {max}"),
            (Some(min), None) => write!(f, "at least {min}"),
            (None, Some(max)) => write!(f, "at most {max}"),
            (None, None) => f.write_str("anything"),
        }
    }
}

impl Schema {
    /// Parses a schema from the value that spells it.
    ///
    /// Strict: an unknown type or keyword is an error, never ignored. A
    /// keyword one node enforced and another skipped would have them
    /// accept different envelopes.
    pub fn parse(value: &Value) -> Result<Self, SchemaError> {
        Node::parse(value).map(Self)
    }

    /// Checks `value` against the schema, reporting the first violation.
    pub fn check(&self, value: &Value) -> Result<(), Violation> {
        self.0.check(value)
    }
}

/// What a path-local check may ask about the value a write lands on, as
/// it stands before the write. Every answer is O(what the path addresses),
/// never O(namespace).
pub(crate) trait Standing {
    type Error;

    /// How many entries the array or map at `path` holds; `None` when
    /// nothing is there, or a leaf is.
    fn len(&self, path: &[Subkey]) -> Result<Option<u64>, Self::Error>;

    /// Whether `path` addresses anything.
    fn contains(&self, path: &[Subkey]) -> Result<bool, Self::Error>;

    /// The value at `path`, materialized.
    fn value(&self, path: &[Subkey]) -> Result<Option<Value>, Self::Error>;
}

/// The outcome of judging a write by the path it lands on.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Local {
    /// The verdict a check of the whole resulting value would reach.
    Judged(Result<(), Violation>),
    /// The write cannot be judged from its path: check the whole value.
    Whole,
}

/// Why a local check stopped short of `Ok`.
enum Stop<E> {
    Violation(Violation),
    Whole,
    Standing(E),
}

impl<E> From<Violation> for Stop<E> {
    fn from(violation: Violation) -> Self {
        Stop::Violation(violation)
    }
}

fn local<E>(judged: Result<(), Stop<E>>) -> Result<Local, E> {
    match judged {
        Ok(()) => Ok(Local::Judged(Ok(()))),
        Err(Stop::Violation(violation)) => Ok(Local::Judged(Err(violation))),
        Err(Stop::Whole) => Ok(Local::Whole),
        Err(Stop::Standing(err)) => Err(err),
    }
}

/// Local checks: a nested write judged from the path it lands on.
///
/// Sound only because a governed namespace conforms at every head: what
/// the write does not touch already satisfies the schema, so the one
/// place a violation can appear is what the write changes — the value it
/// puts down, and the container whose entries it adds to or takes from.
/// Each check reports exactly what [`Schema::check`] would report on the
/// whole result, or [`Local::Whole`] when the standing value is not the
/// shape the schema says it must be and that promise is off.
impl Schema {
    /// Judges setting (`Some`) or clearing (`None`) the value at `path`.
    /// The write is pre-validated, as a
    /// [`NamespaceOp::SetAt`](storage::NamespaceOp::SetAt) is.
    pub(crate) fn check_set<T: Standing>(
        &self,
        path: &SubkeyPath,
        value: Option<&Value>,
        standing: &T,
    ) -> Result<Local, T::Error> {
        local(self.0.check_set(path.as_ref(), value, standing))
    }

    /// Judges amending the value at `path` — the whole value when `None`
    /// — by `op`. The write is pre-validated, as a
    /// [`NamespaceOp::AmendAt`](storage::NamespaceOp::AmendAt) is.
    pub(crate) fn check_amend<T: Standing>(
        &self,
        path: Option<&SubkeyPath>,
        op: &AmendOp,
        standing: &T,
    ) -> Result<Local, T::Error> {
        let path = path.map_or(&[][..], |path| path.as_ref());
        local(self.0.check_amend(path, op, standing))
    }
}

/// What every step below an `any` is held to.
static ANY: Node = Node::Any;

impl Node {
    /// The schema one step down, when the step fits this one.
    fn descend(&self, segment: &Subkey) -> Option<&Node> {
        match (self, segment) {
            (Node::Any, _) => Some(&ANY),
            (Node::Struct { fields, .. }, Subkey::Key(name)) => fields.get(name),
            (Node::Map { values, .. }, Subkey::Key(_)) => Some(values),
            (Node::Array { items, .. }, Subkey::Index(_)) => Some(items),
            _ => None,
        }
    }

    /// The schema `path` leads to.
    fn locate<E>(&self, path: &[Subkey]) -> Result<&Node, Stop<E>> {
        path.iter()
            .try_fold(self, |node, segment| node.descend(segment))
            .ok_or(Stop::Whole)
    }

    fn check_set<T: Standing>(
        &self,
        path: &[Subkey],
        value: Option<&Value>,
        standing: &T,
    ) -> Result<(), Stop<T::Error>> {
        let (last, parents) = path.split_last().ok_or(Stop::Whole)?;
        let len = || {
            standing
                .len(parents)
                .map_err(Stop::Standing)?
                .ok_or(Stop::Whole)
        };
        // The container's own faults are found at the container; the
        // value's, under the path it is written to.
        let at_container = |kind: ViolationKind| Stop::from(Violation::from(kind).within(parents));
        let judge = |node: &Node, value: &Value| {
            node.check(value)
                .map_err(|violation| Stop::from(violation.within(path)))
        };

        match (self.locate(parents)?, last, value) {
            (Node::Any, _, _) => Ok(()),
            (Node::Struct { fields, .. }, Subkey::Key(name), Some(value)) => {
                let field = fields
                    .get(name)
                    .ok_or_else(|| at_container(ViolationKind::UnknownField(name.clone())))?;
                judge(field, value)
            }
            (Node::Struct { required, .. }, Subkey::Key(name), None) => {
                if required.contains(name) {
                    return Err(at_container(ViolationKind::MissingField(name.clone())));
                }
                Ok(())
            }
            (
                Node::Map {
                    values,
                    len: bounds,
                },
                Subkey::Key(_),
                Some(value),
            ) => {
                // Only a fresh key grows the map, and only a maximum can
                // mind: neither read happens otherwise.
                if bounds.max.is_some() && !standing.contains(path).map_err(Stop::Standing)? {
                    let grown = len()?.checked_add(1).ok_or(Stop::Whole)?;
                    check_len(bounds, grown).map_err(|v| v.within(parents))?;
                }
                judge(values, value)
            }
            (Node::Array { items, .. }, Subkey::Index(_), Some(value)) => judge(items, value),
            (Node::Map { len: bounds, .. }, Subkey::Key(_), None)
            | (Node::Array { len: bounds, .. }, Subkey::Index(_), None) => {
                if bounds.min.is_some_and(|min| min > 0) {
                    let shrunk = len()?.checked_sub(1).ok_or(Stop::Whole)?;
                    check_len(bounds, shrunk).map_err(|v| v.within(parents))?;
                }
                Ok(())
            }
            _ => Err(Stop::Whole),
        }
    }

    fn check_amend<T: Standing>(
        &self,
        path: &[Subkey],
        op: &AmendOp,
        standing: &T,
    ) -> Result<(), Stop<T::Error>> {
        match op {
            AmendOp::AppendEntry(entry) => {
                let Some(len) = standing.len(path).map_err(Stop::Standing)? else {
                    // Nothing there: the append creates a one-entry array
                    // as a fresh key, which is a set by another name.
                    let created = Value::Array(vec![entry.clone()]);
                    return self.check_set(path, Some(&created), standing);
                };
                match self.locate(path)? {
                    Node::Any => Ok(()),
                    Node::Array { items, len: bounds } => {
                        let grown = len.checked_add(1).ok_or(Stop::Whole)?;
                        check_len(bounds, grown).map_err(|v| v.within(path))?;
                        let index = u32::try_from(len).map_err(|_| Stop::Whole)?;
                        items.check(entry).map_err(|violation| {
                            Stop::from(violation.under(Subkey::Index(index)).within(path))
                        })
                    }
                    _ => Err(Stop::Whole),
                }
            }
            AmendOp::IncrementDecrement(increment) => match self.locate(path)? {
                Node::Any => Ok(()),
                node => {
                    let Some(Value::Int(n)) = standing.value(path).map_err(Stop::Standing)? else {
                        return Err(Stop::Whole);
                    };
                    let sum = increment.apply(n).ok_or(Stop::Whole)?;
                    node.check(&Value::Int(sum))
                        .map_err(|violation| Stop::from(violation.within(path)))
                }
            },
            AmendOp::DeleteMatching(_) => {
                let node = self.locate(path)?;
                // Removing entries can only break a floor: a minimum
                // length, or a struct's required fields. Without one
                // there is nothing to read.
                let has_floor = match node {
                    Node::Any => false,
                    Node::Array { len, .. } | Node::Map { len, .. } => {
                        len.min.is_some_and(|min| min > 0)
                    }
                    Node::Struct { required, .. } => !required.is_empty(),
                    _ => return Err(Stop::Whole),
                };
                if !has_floor {
                    return Ok(());
                }
                // Which entries match is a question about the entries, so
                // the container is read — it, not the namespace around it.
                let mut container = standing
                    .value(path)
                    .map_err(Stop::Standing)?
                    .ok_or(Stop::Whole)?;
                storage::value::amend_at(&mut container, None, op.clone());
                node.check(&container)
                    .map_err(|violation| Stop::from(violation.within(path)))
            }
        }
    }
}

type Keywords = BTreeMap<String, Value>;

impl Node {
    fn parse(value: &Value) -> Result<Self, SchemaError> {
        let Value::Map(keywords) = value else {
            return Err(SchemaErrorKind::NotAMap.into());
        };
        let kind = match keywords.get("type") {
            Some(Value::String(kind)) => kind.as_str(),
            Some(_) => return Err(SchemaErrorKind::BadKeyword("type").into()),
            None => return Err(SchemaErrorKind::MissingKeyword("type").into()),
        };
        let only = |allowed: &[&str]| {
            keywords
                .keys()
                .find(|keyword| *keyword != "type" && !allowed.contains(&keyword.as_str()))
                .map_or(Ok(()), |keyword| {
                    Err(SchemaError::from(SchemaErrorKind::UnknownKeyword(
                        keyword.clone(),
                    )))
                })
        };

        match kind {
            "any" => only(&[]).map(|()| Node::Any),
            "bool" => only(&[]).map(|()| Node::Bool),
            "key" => only(&[]).map(|()| Node::Key),
            "string" => {
                only(&["min_len", "max_len", "enum"])?;
                Ok(Node::String {
                    len: len_bounds(keywords)?,
                    allowed: allowed(keywords, |entry| match entry {
                        Value::String(s) => Some(s.clone()),
                        _ => None,
                    })?,
                })
            }
            "int" => {
                only(&["min", "max", "enum"])?;
                Ok(Node::Int {
                    range: bounds(int(keywords, "min")?, int(keywords, "max")?)?,
                    allowed: allowed(keywords, |entry| match entry {
                        Value::Int(n) => Some(*n),
                        _ => None,
                    })?,
                })
            }
            "array" => {
                only(&["items", "min_len", "max_len"])?;
                Ok(Node::Array {
                    items: Box::new(nested(keywords, "items")?),
                    len: len_bounds(keywords)?,
                })
            }
            "map" => {
                only(&["values", "min_len", "max_len"])?;
                Ok(Node::Map {
                    values: Box::new(nested(keywords, "values")?),
                    len: len_bounds(keywords)?,
                })
            }
            "struct" => {
                only(&["fields", "required"])?;
                let fields = match keywords.get("fields") {
                    Some(Value::Map(fields)) => fields
                        .iter()
                        .map(|(name, schema)| {
                            Node::parse(schema)
                                .map(|node| (name.clone(), node))
                                .map_err(|err| err.under(name).under("fields"))
                        })
                        .collect::<Result<BTreeMap<_, _>, _>>()?,
                    Some(_) => return Err(SchemaErrorKind::BadKeyword("fields").into()),
                    None => return Err(SchemaErrorKind::MissingKeyword("fields").into()),
                };
                let required = match keywords.get("required") {
                    None => BTreeSet::new(),
                    Some(Value::Array(names)) => names
                        .iter()
                        .map(|name| match name {
                            Value::String(name) if fields.contains_key(name) => Ok(name.clone()),
                            Value::String(name) => {
                                Err(SchemaErrorKind::UnknownRequired(name.clone()).into())
                            }
                            _ => Err(SchemaErrorKind::BadKeyword("required").into()),
                        })
                        .collect::<Result<_, SchemaError>>()?,
                    Some(_) => return Err(SchemaErrorKind::BadKeyword("required").into()),
                };
                Ok(Node::Struct { fields, required })
            }
            other => Err(SchemaErrorKind::UnknownType(other.to_string()).into()),
        }
    }

    fn check(&self, value: &Value) -> Result<(), Violation> {
        let wrong = |expected| {
            Err(Violation::from(ViolationKind::WrongType {
                expected,
                found: type_name(value),
            }))
        };
        match (self, value) {
            (Node::Any, _) | (Node::Bool, Value::Bool(_)) | (Node::Key, Value::Key(_)) => Ok(()),
            (Node::String { len, allowed }, Value::String(s)) => {
                // Scalar values, not bytes or graphemes: the one count
                // that needs no Unicode tables, so it cannot move under
                // a dependency bump.
                check_len(len, len_of(s.chars().count()))?;
                check_allowed(allowed, s)
            }
            (Node::Int { range, allowed }, Value::Int(n)) => {
                if !range.contains(*n) {
                    return Err(ViolationKind::OutOfRange {
                        value: *n,
                        range: *range,
                    }
                    .into());
                }
                check_allowed(allowed, n)
            }
            (Node::Array { items, len }, Value::Array(entries)) => {
                check_len(len, len_of(entries.len()))?;
                entries.iter().zip(0u32..).try_for_each(|(entry, index)| {
                    items
                        .check(entry)
                        .map_err(|violation| violation.under(Subkey::Index(index)))
                })
            }
            (Node::Map { values, len }, Value::Map(entries)) => {
                check_len(len, len_of(entries.len()))?;
                entries.iter().try_for_each(|(key, entry)| {
                    values
                        .check(entry)
                        .map_err(|violation| violation.under(Subkey::Key(key.clone())))
                })
            }
            (Node::Struct { fields, required }, Value::Map(entries)) => {
                if let Some(missing) = required.iter().find(|name| !entries.contains_key(*name)) {
                    return Err(ViolationKind::MissingField(missing.clone()).into());
                }
                entries.iter().try_for_each(|(name, entry)| {
                    fields
                        .get(name)
                        .ok_or_else(|| Violation::from(ViolationKind::UnknownField(name.clone())))?
                        .check(entry)
                        .map_err(|violation| violation.under(Subkey::Key(name.clone())))
                })
            }
            (Node::Bool, _) => wrong("bool"),
            (Node::Key, _) => wrong("key"),
            (Node::String { .. }, _) => wrong("string"),
            (Node::Int { .. }, _) => wrong("int"),
            (Node::Array { .. }, _) => wrong("array"),
            (Node::Map { .. } | Node::Struct { .. }, _) => wrong("map"),
        }
    }
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::String(_) => "string",
        Value::Int(_) => "int",
        Value::Bool(_) => "bool",
        Value::Array(_) => "array",
        Value::Map(_) => "map",
        Value::Key(_) => "key",
    }
}

/// A container's length as the schema counts it.
fn len_of(len: usize) -> u64 {
    // A length past u64 cannot exist; saturating keeps the cast total.
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn check_len(bounds: &Bounds<u64>, len: u64) -> Result<(), Violation> {
    bounds.contains(len).then_some(()).ok_or_else(|| {
        ViolationKind::BadLength {
            len,
            len_range: *bounds,
        }
        .into()
    })
}

fn check_allowed<T: Ord>(allowed: &Option<BTreeSet<T>>, value: &T) -> Result<(), Violation> {
    allowed
        .as_ref()
        .is_none_or(|allowed| allowed.contains(value))
        .then_some(())
        .ok_or_else(|| ViolationKind::NotAllowed.into())
}

fn int(keywords: &Keywords, name: &'static str) -> Result<Option<i64>, SchemaError> {
    match keywords.get(name) {
        None => Ok(None),
        Some(Value::Int(n)) => Ok(Some(*n)),
        Some(_) => Err(SchemaErrorKind::BadKeyword(name).into()),
    }
}

fn len(keywords: &Keywords, name: &'static str) -> Result<Option<u64>, SchemaError> {
    int(keywords, name)?
        .map(|n| u64::try_from(n).map_err(|_| SchemaErrorKind::BadKeyword(name).into()))
        .transpose()
}

fn bounds<T: Ord>(min: Option<T>, max: Option<T>) -> Result<Bounds<T>, SchemaError> {
    match (&min, &max) {
        (Some(min), Some(max)) if min > max => Err(SchemaErrorKind::InvertedBounds.into()),
        _ => Ok(Bounds { min, max }),
    }
}

fn len_bounds(keywords: &Keywords) -> Result<Bounds<u64>, SchemaError> {
    bounds(len(keywords, "min_len")?, len(keywords, "max_len")?)
}

/// Reads `enum`: a non-empty array of one kind of leaf.
fn allowed<T: Ord>(
    keywords: &Keywords,
    leaf: impl Fn(&Value) -> Option<T>,
) -> Result<Option<BTreeSet<T>>, SchemaError> {
    let bad = || SchemaError::from(SchemaErrorKind::BadKeyword("enum"));
    match keywords.get("enum") {
        None => Ok(None),
        Some(Value::Array(entries)) if !entries.is_empty() => entries
            .iter()
            .map(|entry| leaf(entry).ok_or_else(bad))
            .collect::<Result<_, _>>()
            .map(Some),
        Some(_) => Err(bad()),
    }
}

fn nested(keywords: &Keywords, name: &'static str) -> Result<Node, SchemaError> {
    keywords.get(name).map_or(Ok(Node::Any), |schema| {
        Node::parse(schema).map_err(|err| err.under(name))
    })
}

/// Parses the value of the schema namespace: a map from the name of a
/// namespace to the schema its value must satisfy.
pub(crate) fn parse_set(value: &Value) -> Result<BTreeMap<NamespaceKey, Schema>, SchemaSetError> {
    let Value::Map(entries) = value else {
        return Err(SchemaSetError::NotAMap);
    };
    entries
        .iter()
        .map(|(namespace, schema)| {
            if namespace.starts_with(RESERVED_PREFIX) {
                return Err(SchemaSetError::Reserved(namespace.clone()));
            }
            let key = NamespaceKey::try_new(namespace.as_str())
                .map_err(|_| SchemaSetError::BadName(namespace.clone()))?;
            Schema::parse(schema)
                .map(|schema| (key, schema))
                .map_err(|error| SchemaSetError::Invalid {
                    namespace: namespace.clone(),
                    error,
                })
        })
        .collect()
}

/// Why the schema namespace refused the value a write would leave it
/// holding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SchemaSetError {
    /// The namespace holds something other than a map of schemas.
    NotAMap,
    /// An entry is filed under a name no namespace can have.
    BadName(String),
    /// An entry names a namespace the ledger reserves for itself.
    Reserved(String),
    /// The entry for `namespace` is not a schema.
    Invalid {
        /// The namespace the entry is filed under.
        namespace: String,
        /// What is wrong with it.
        error: SchemaError,
    },
}

impl fmt::Display for SchemaSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchemaSetError::NotAMap => {
                f.write_str("the schema set must be a map of namespace name to schema")
            }
            SchemaSetError::BadName(name) => write!(f, "{name:?} cannot name a namespace"),
            SchemaSetError::Reserved(name) => {
                write!(f, "{name} is reserved and cannot be given a schema")
            }
            SchemaSetError::Invalid { namespace, error } => {
                write!(f, "the schema for {namespace} is invalid: {error}")
            }
        }
    }
}

impl core::error::Error for SchemaSetError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            SchemaSetError::Invalid { error, .. } => Some(error),
            SchemaSetError::NotAMap | SchemaSetError::BadName(_) | SchemaSetError::Reserved(_) => {
                None
            }
        }
    }
}

/// Why a value is not a schema, and where inside it the fault lies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError {
    path: Vec<Subkey>,
    kind: SchemaErrorKind,
}

impl SchemaError {
    /// The path from the schema's root to the faulty part of it; empty
    /// when that is the root itself.
    pub fn path(&self) -> &[Subkey] {
        &self.path
    }

    /// What is wrong there.
    pub fn kind(&self) -> &SchemaErrorKind {
        &self.kind
    }

    fn under(mut self, segment: &str) -> Self {
        self.path.insert(0, Subkey::Key(segment.to_string()));
        self
    }
}

impl From<SchemaErrorKind> for SchemaError {
    fn from(kind: SchemaErrorKind) -> Self {
        Self {
            path: Vec::new(),
            kind,
        }
    }
}

/// What is wrong with one part of a schema.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SchemaErrorKind {
    /// A schema must be a map.
    NotAMap,
    /// A keyword the type requires is absent.
    MissingKeyword(&'static str),
    /// A keyword holds a value it cannot.
    BadKeyword(&'static str),
    /// The type has no such keyword.
    UnknownKeyword(String),
    /// There is no such type.
    UnknownType(String),
    /// A minimum exceeds its maximum.
    InvertedBounds,
    /// A struct requires a field it does not declare.
    UnknownRequired(String),
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            SchemaErrorKind::NotAMap => f.write_str("a schema must be a map"),
            SchemaErrorKind::MissingKeyword(keyword) => write!(f, "`{keyword}` is missing"),
            SchemaErrorKind::BadKeyword(keyword) => write!(f, "`{keyword}` holds a bad value"),
            SchemaErrorKind::UnknownKeyword(keyword) => write!(f, "unknown keyword `{keyword}`"),
            SchemaErrorKind::UnknownType(kind) => write!(f, "unknown type `{kind}`"),
            SchemaErrorKind::InvertedBounds => f.write_str("the minimum exceeds the maximum"),
            SchemaErrorKind::UnknownRequired(field) => {
                write!(f, "required field `{field}` is not declared in `fields`")
            }
        }?;
        write!(f, "{}", At(&self.path))
    }
}

impl core::error::Error for SchemaError {}

/// Where a value breaks its schema, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    path: Vec<Subkey>,
    kind: ViolationKind,
}

impl Violation {
    /// The path from the namespace's value to the offending part of it;
    /// empty when that is the value itself.
    pub fn path(&self) -> &[Subkey] {
        &self.path
    }

    /// How the value there breaks the schema.
    pub fn kind(&self) -> &ViolationKind {
        &self.kind
    }

    fn under(mut self, segment: Subkey) -> Self {
        self.path.insert(0, segment);
        self
    }

    /// Relocates a violation found under `prefix` to where it lies from
    /// the root.
    fn within(mut self, prefix: &[Subkey]) -> Self {
        self.path.splice(0..0, prefix.iter().cloned());
        self
    }
}

impl From<ViolationKind> for Violation {
    fn from(kind: ViolationKind) -> Self {
        Self {
            path: Vec::new(),
            kind,
        }
    }
}

/// How a value breaks its schema.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ViolationKind {
    /// The value is of another type than the schema names.
    WrongType {
        /// The type the schema names.
        expected: &'static str,
        /// The type the value is.
        found: &'static str,
    },
    /// An integer lies outside its range.
    OutOfRange {
        /// The integer.
        value: i64,
        /// The range it must lie in.
        range: Bounds<i64>,
    },
    /// A string, array or map is too short or too long.
    BadLength {
        /// The length it has.
        len: u64,
        /// The lengths it may have.
        len_range: Bounds<u64>,
    },
    /// The value is not one its `enum` lists.
    NotAllowed,
    /// A struct lacks a field it requires.
    MissingField(String),
    /// A struct holds a field it does not declare.
    UnknownField(String),
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ViolationKind::WrongType { expected, found } => {
                write!(f, "expected {expected}, found {found}")
            }
            ViolationKind::OutOfRange { value, range } => {
                write!(f, "{value} is out of range, must be {range}")
            }
            ViolationKind::BadLength { len, len_range } => {
                write!(f, "length {len} is out of range, must be {len_range}")
            }
            ViolationKind::NotAllowed => f.write_str("not one of the allowed values"),
            ViolationKind::MissingField(field) => write!(f, "required field `{field}` is missing"),
            ViolationKind::UnknownField(field) => write!(f, "unknown field `{field}`"),
        }?;
        write!(f, "{}", At(&self.path))
    }
}

impl core::error::Error for Violation {}

/// Displays where a fault lies: ` at <path>`, or nothing at the root.
struct At<'a>(&'a [Subkey]);

impl fmt::Display for At<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        SubkeyPath::try_new(self.0.to_vec()).map_or(Ok(()), |path| write!(f, " at {path}"))
    }
}

#[cfg(test)]
mod tests {
    use core::{cell::RefCell, convert::Infallible};

    use wire::{
        keys::{Ed25519PublicKey, Key, PublicKey},
        msg::{IncrementDecrement, Match, Predicate},
    };

    use super::*;

    fn map(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
        entries.into_iter().collect()
    }

    fn of(kind: &str) -> Value {
        map([("type", kind.into())])
    }

    fn strings(entries: impl IntoIterator<Item = &'static str>) -> Value {
        entries.into_iter().collect()
    }

    /// `{servers: [{host: string(1..), port?: int(1..=65535)}] (..=2)}`.
    fn servers() -> Schema {
        let server = map([
            ("type", "struct".into()),
            ("required", strings(["host"])),
            (
                "fields",
                map([
                    (
                        "host",
                        map([("type", "string".into()), ("min_len", 1.into())]),
                    ),
                    (
                        "port",
                        map([
                            ("type", "int".into()),
                            ("min", 1.into()),
                            ("max", 65535.into()),
                        ]),
                    ),
                ]),
            ),
        ]);
        Schema::parse(&map([
            ("type", "struct".into()),
            ("required", strings(["servers"])),
            (
                "fields",
                map([(
                    "servers",
                    map([
                        ("type", "array".into()),
                        ("max_len", 2.into()),
                        ("items", server),
                    ]),
                )]),
            ),
        ]))
        .unwrap()
    }

    fn server(host: &str, port: i64) -> Value {
        map([("host", host.into()), ("port", port.into())])
    }

    fn config(servers: impl IntoIterator<Item = Value>) -> Value {
        map([("servers", servers.into_iter().collect())])
    }

    fn violation(schema: &Schema, value: &Value) -> String {
        schema.check(value).unwrap_err().to_string()
    }

    fn parse_error(value: &Value) -> String {
        Schema::parse(value).unwrap_err().to_string()
    }

    #[test]
    fn a_conforming_value_passes() {
        let value = config([server("a", 80), map([("host", "b".into())])]);
        assert_eq!(servers().check(&value), Ok(()));
    }

    #[test]
    fn a_violation_names_where_it_lies() {
        assert_eq!(
            violation(&servers(), &config([server("a", 80), server("b", 70000)])),
            "70000 is out of range, must be 1 to 65535 at servers[1].port"
        );
    }

    #[test]
    fn a_wrong_type_is_refused() {
        assert_eq!(
            violation(&servers(), &map([("servers", "none".into())])),
            "expected array, found string at servers"
        );
    }

    #[test]
    fn a_struct_requires_its_required_fields() {
        assert_eq!(
            violation(&servers(), &config([map([("port", 80.into())])])),
            "required field `host` is missing at servers[0]"
        );
    }

    #[test]
    fn a_struct_refuses_undeclared_fields() {
        assert_eq!(
            violation(
                &servers(),
                &map([("servers", Value::Array(Vec::new())), ("extra", 1.into())])
            ),
            "unknown field `extra`"
        );
    }

    #[test]
    fn lengths_are_bounded() {
        let three = config([server("a", 1), server("b", 2), server("c", 3)]);
        assert_eq!(
            violation(&servers(), &three),
            "length 3 is out of range, must be at most 2 at servers"
        );
        assert_eq!(
            violation(&servers(), &config([server("", 1)])),
            "length 0 is out of range, must be at least 1 at servers[0].host"
        );
    }

    #[test]
    fn a_string_length_counts_scalar_values() {
        let schema =
            Schema::parse(&map([("type", "string".into()), ("max_len", 2.into())])).unwrap();
        assert_eq!(schema.check(&"éé".into()), Ok(()));
        assert!(schema.check(&"ééé".into()).is_err());
    }

    #[test]
    fn an_enum_admits_only_what_it_lists() {
        let schema = Schema::parse(&map([
            ("type", "string".into()),
            ("enum", strings(["blue", "green"])),
        ]))
        .unwrap();
        assert_eq!(schema.check(&"green".into()), Ok(()));
        assert_eq!(
            violation(&schema, &"red".into()),
            "not one of the allowed values"
        );
    }

    #[test]
    fn a_map_judges_every_entry() {
        let schema = Schema::parse(&map([("type", "map".into()), ("values", of("bool"))])).unwrap();
        assert_eq!(schema.check(&map([("a", true.into())])), Ok(()));
        assert_eq!(
            violation(&schema, &map([("a", true.into()), ("b", 1.into())])),
            "expected bool, found int at b"
        );
    }

    #[test]
    fn any_admits_everything() {
        let schema = Schema::parse(&of("any")).unwrap();
        assert_eq!(schema.check(&config([])), Ok(()));
    }

    #[test]
    fn an_unknown_keyword_is_refused() {
        assert_eq!(
            parse_error(&map([("type", "int".into()), ("pattern", "x".into())])),
            "unknown keyword `pattern`"
        );
        // A keyword of another type is as unknown as one of none.
        assert_eq!(
            parse_error(&map([("type", "bool".into()), ("min", 1.into())])),
            "unknown keyword `min`"
        );
    }

    #[test]
    fn an_unknown_type_is_refused() {
        assert_eq!(parse_error(&of("float")), "unknown type `float`");
    }

    #[test]
    fn a_schema_error_names_where_it_lies() {
        let schema = map([
            ("type", "struct".into()),
            (
                "fields",
                map([(
                    "tags",
                    map([("type", "array".into()), ("items", of("uuid"))]),
                )]),
            ),
        ]);
        assert_eq!(
            parse_error(&schema),
            "unknown type `uuid` at fields.tags.items"
        );
    }

    #[test]
    fn malformed_schemas_are_refused() {
        assert_eq!(parse_error(&"int".into()), "a schema must be a map");
        assert_eq!(parse_error(&map([])), "`type` is missing");
        assert_eq!(parse_error(&of("struct")), "`fields` is missing");
        assert_eq!(
            parse_error(&map([
                ("type", "int".into()),
                ("min", 2.into()),
                ("max", 1.into())
            ])),
            "the minimum exceeds the maximum"
        );
        assert_eq!(
            parse_error(&map([("type", "string".into()), ("min_len", (-1).into())])),
            "`min_len` holds a bad value"
        );
        assert_eq!(
            parse_error(&map([("type", "int".into()), ("enum", strings(["a"]))])),
            "`enum` holds a bad value"
        );
        assert_eq!(
            parse_error(&map([("type", "int".into()), ("enum", strings([]))])),
            "`enum` holds a bad value"
        );
        assert_eq!(
            parse_error(&map([
                ("type", "struct".into()),
                ("fields", map([])),
                ("required", strings(["ghost"])),
            ])),
            "required field `ghost` is not declared in `fields`"
        );
    }

    #[test]
    fn a_schema_set_refuses_reserved_and_unnameable_namespaces() {
        assert_eq!(parse_set(&"x".into()), Err(SchemaSetError::NotAMap));
        assert_eq!(
            parse_set(&map([("_lotus_nodes", of("any"))])),
            Err(SchemaSetError::Reserved("_lotus_nodes".to_string()))
        );
        assert_eq!(
            parse_set(&map([("", of("any"))])),
            Err(SchemaSetError::BadName(String::new()))
        );
        assert!(matches!(
            parse_set(&map([("app", of("float"))])),
            Err(SchemaSetError::Invalid { namespace, .. }) if namespace == "app"
        ));
    }

    fn schema(keywords: impl IntoIterator<Item = (&'static str, Value)>) -> Schema {
        Schema::parse(&map(keywords)).unwrap()
    }

    fn kind_of_error(keywords: impl IntoIterator<Item = (&'static str, Value)>) -> SchemaErrorKind {
        Schema::parse(&map(keywords)).unwrap_err().kind
    }

    fn a_key() -> Value {
        Value::Key(Key::new(
            PublicKey::Ed25519(Ed25519PublicKey::from_bytes([7; 32])),
            1,
        ))
    }

    /// One value of every kind a ledger can hold, by the name its type
    /// goes by.
    fn one_of_each() -> [(&'static str, Value); 6] {
        [
            ("string", "s".into()),
            ("int", 1.into()),
            ("bool", true.into()),
            ("array", Value::Array(Vec::new())),
            ("map", map([])),
            ("key", a_key()),
        ]
    }

    /// Every type, minimally spelled, with the kind of value it admits.
    fn every_type() -> [(Schema, &'static str); 7] {
        [
            (schema([("type", "string".into())]), "string"),
            (schema([("type", "int".into())]), "int"),
            (schema([("type", "bool".into())]), "bool"),
            (schema([("type", "key".into())]), "key"),
            (schema([("type", "array".into())]), "array"),
            (schema([("type", "map".into())]), "map"),
            (
                schema([("type", "struct".into()), ("fields", map([]))]),
                "map",
            ),
        ]
    }

    #[test]
    fn every_type_admits_only_its_own_kind_of_value() {
        for (schema, admits) in every_type() {
            for (kind, value) in one_of_each() {
                let expected = if kind == admits {
                    Ok(())
                } else {
                    Err(Violation::from(ViolationKind::WrongType {
                        expected: admits,
                        found: kind,
                    }))
                };
                assert_eq!(schema.check(&value), expected, "{schema:?} on a {kind}");
            }
        }
    }

    #[test]
    fn any_admits_every_kind_of_value() {
        let any = schema([("type", "any".into())]);
        for (kind, value) in one_of_each() {
            assert_eq!(any.check(&value), Ok(()), "{kind}");
        }
    }

    /// A keyword means something under one type only; under another it is
    /// as unknown as a misspelling, whatever it holds.
    #[test]
    fn every_type_refuses_the_keywords_of_the_others() {
        const KEYWORDS: [&str; 9] = [
            "min", "max", "min_len", "max_len", "enum", "items", "values", "fields", "required",
        ];
        let types: [(&str, &[&str]); 8] = [
            ("any", &[]),
            ("bool", &[]),
            ("key", &[]),
            ("string", &["min_len", "max_len", "enum"]),
            ("int", &["min", "max", "enum"]),
            ("array", &["items", "min_len", "max_len"]),
            ("map", &["values", "min_len", "max_len"]),
            ("struct", &["fields", "required"]),
        ];
        for (kind, allowed) in types {
            for keyword in KEYWORDS.iter().filter(|k| !allowed.contains(k)) {
                assert_eq!(
                    kind_of_error([("type", kind.into()), (keyword, 1.into())]),
                    SchemaErrorKind::UnknownKeyword((*keyword).to_string()),
                    "`{keyword}` under {kind}"
                );
            }
        }
    }

    #[test]
    fn a_keyword_holding_the_wrong_kind_of_value_is_refused() {
        let ints = |ns: &[i64]| ns.iter().copied().collect::<Value>();
        let cases: [(&str, &str, Value); 16] = [
            ("int", "min", "1".into()),
            ("int", "max", true.into()),
            ("int", "enum", 1.into()),
            ("int", "enum", strings(["a"])),
            ("int", "enum", Value::Array(vec![1.into(), "a".into()])),
            ("string", "min_len", "1".into()),
            ("string", "max_len", (-1).into()),
            ("string", "enum", "a".into()),
            ("string", "enum", ints(&[1])),
            ("string", "enum", map([])),
            ("array", "min_len", (-1).into()),
            ("array", "max_len", true.into()),
            ("map", "min_len", i64::MIN.into()),
            ("map", "max_len", "x".into()),
            ("struct", "fields", strings(["host"])),
            ("struct", "fields", "host".into()),
        ];
        for (kind, keyword, bad) in cases {
            assert_eq!(
                kind_of_error([("type", kind.into()), (keyword, bad.clone())]),
                SchemaErrorKind::BadKeyword(keyword),
                "{kind}.{keyword} = {bad:?}"
            );
        }

        for bad in ["host".into(), ints(&[1]), map([])] {
            assert_eq!(
                kind_of_error([
                    ("type", "struct".into()),
                    ("fields", map([("host", of("string"))])),
                    ("required", bad),
                ]),
                SchemaErrorKind::BadKeyword("required")
            );
        }
    }

    #[test]
    fn the_type_must_be_a_string() {
        assert_eq!(
            kind_of_error([("type", 1.into())]),
            SchemaErrorKind::BadKeyword("type")
        );
        assert_eq!(
            kind_of_error([("type", strings(["int"]))]),
            SchemaErrorKind::BadKeyword("type")
        );
        // Types are spelled one way.
        assert_eq!(
            kind_of_error([("type", "Int".into())]),
            SchemaErrorKind::UnknownType("Int".to_string())
        );
        assert_eq!(
            kind_of_error([("type", "".into())]),
            SchemaErrorKind::UnknownType(String::new())
        );
    }

    #[test]
    fn a_nested_schema_must_be_a_schema() {
        for (kind, keyword) in [("array", "items"), ("map", "values")] {
            let err = Schema::parse(&map([("type", kind.into()), (keyword, "string".into())]))
                .unwrap_err();
            assert_eq!(err.kind(), &SchemaErrorKind::NotAMap);
            assert_eq!(err.path(), [Subkey::Key(keyword.to_string())]);
        }
        let err = Schema::parse(&map([
            ("type", "struct".into()),
            ("fields", map([("host", "string".into())])),
        ]))
        .unwrap_err();
        assert_eq!(err.kind(), &SchemaErrorKind::NotAMap);
        assert_eq!(err.to_string(), "a schema must be a map at fields.host");
    }

    #[test]
    fn int_bounds_are_inclusive() {
        let exact = schema([("type", "int".into()), ("min", 3.into()), ("max", 3.into())]);
        assert!(exact.check(&2.into()).is_err());
        assert_eq!(exact.check(&3.into()), Ok(()));
        assert!(exact.check(&4.into()).is_err());

        let floor = schema([("type", "int".into()), ("min", (-2).into())]);
        assert!(floor.check(&(-3).into()).is_err());
        assert_eq!(floor.check(&(-2).into()), Ok(()));
        assert_eq!(floor.check(&i64::MAX.into()), Ok(()));

        let ceiling = schema([("type", "int".into()), ("max", (-2).into())]);
        assert_eq!(ceiling.check(&i64::MIN.into()), Ok(()));
        assert_eq!(ceiling.check(&(-2).into()), Ok(()));
        assert!(ceiling.check(&(-1).into()).is_err());
    }

    #[test]
    fn int_bounds_reach_the_ends_of_i64() {
        let whole = schema([
            ("type", "int".into()),
            ("min", i64::MIN.into()),
            ("max", i64::MAX.into()),
        ]);
        assert_eq!(whole.check(&i64::MIN.into()), Ok(()));
        assert_eq!(whole.check(&i64::MAX.into()), Ok(()));

        let lowest = schema([("type", "int".into()), ("max", i64::MIN.into())]);
        assert_eq!(lowest.check(&i64::MIN.into()), Ok(()));
        assert!(lowest.check(&(i64::MIN + 1).into()).is_err());
    }

    #[test]
    fn length_bounds_are_inclusive_for_every_container() {
        let bounded = |kind: &str| {
            schema([
                ("type", kind.to_string().into()),
                ("min_len", 1.into()),
                ("max_len", 2.into()),
            ])
        };
        let strings = ["", "a", "ab", "abc"].map(Value::from);
        let arrays = [0, 1, 2, 3].map(|n| (0..n).map(Value::Int).collect::<Value>());
        let maps = [0, 1, 2, 3]
            .map(|n| Value::Map((0..n).map(|i| (i.to_string(), Value::Int(i))).collect()));

        for (kind, values) in [("string", strings), ("array", arrays), ("map", maps)] {
            let verdicts = values
                .each_ref()
                .map(|value| bounded(kind).check(value).is_ok());
            assert_eq!(verdicts, [false, true, true, false], "{kind}");
        }
    }

    #[test]
    fn a_maximum_length_of_zero_admits_only_the_empty() {
        let empty = schema([("type", "array".into()), ("max_len", 0.into())]);
        assert_eq!(empty.check(&Value::Array(Vec::new())), Ok(()));
        assert_eq!(
            violation(&empty, &strings(["a"])),
            "length 1 is out of range, must be at most 0"
        );
    }

    #[test]
    fn equal_bounds_are_not_inverted() {
        schema([("type", "int".into()), ("min", 5.into()), ("max", 5.into())]);
        schema([
            ("type", "string".into()),
            ("min_len", 0.into()),
            ("max_len", 0.into()),
        ]);
        for kind in ["string", "array", "map"] {
            assert_eq!(
                kind_of_error([
                    ("type", kind.into()),
                    ("min_len", 2.into()),
                    ("max_len", 1.into()),
                ]),
                SchemaErrorKind::InvertedBounds,
                "{kind}"
            );
        }
    }

    /// Scalar values: not the bytes of the encoding, and not what a
    /// reader would call characters.
    #[test]
    fn a_string_length_counts_neither_bytes_nor_graphemes() {
        let two = schema([
            ("type", "string".into()),
            ("min_len", 2.into()),
            ("max_len", 2.into()),
        ]);
        assert_eq!(two.check(&"日本".into()), Ok(()), "six bytes, two scalars");
        assert_eq!(
            two.check(&"e\u{301}".into()),
            Ok(()),
            "one grapheme, two scalars"
        );
        assert!(two.check(&"é".into()).is_err(), "two bytes, one scalar");
    }

    #[test]
    fn an_int_enum_admits_only_what_it_lists() {
        let schema = schema([
            ("type", "int".into()),
            ("enum", [80i64, 443].into_iter().collect()),
        ]);
        assert_eq!(schema.check(&443.into()), Ok(()));
        assert_eq!(
            violation(&schema, &8080.into()),
            "not one of the allowed values"
        );
        assert_eq!(
            violation(&schema, &"443".into()),
            "expected int, found string"
        );
    }

    /// An enum narrows; it does not widen the bounds beside it.
    #[test]
    fn an_enum_and_bounds_both_apply() {
        let ints = schema([
            ("type", "int".into()),
            ("min", 1.into()),
            ("max", 5.into()),
            ("enum", [3i64, 9].into_iter().collect()),
        ]);
        assert_eq!(ints.check(&3.into()), Ok(()));
        assert_eq!(
            ints.check(&9.into()).unwrap_err().kind(),
            &ViolationKind::OutOfRange {
                value: 9,
                range: Bounds {
                    min: Some(1),
                    max: Some(5)
                }
            }
        );
        assert_eq!(
            ints.check(&4.into()).unwrap_err().kind(),
            &ViolationKind::NotAllowed
        );

        let text = schema([
            ("type", "string".into()),
            ("max_len", 2.into()),
            ("enum", strings(["ok", "long"])),
        ]);
        assert_eq!(text.check(&"ok".into()), Ok(()));
        assert!(matches!(
            text.check(&"long".into()).unwrap_err().kind(),
            ViolationKind::BadLength { len: 4, .. }
        ));
    }

    #[test]
    fn an_enum_matches_exactly() {
        let schema = schema([("type", "string".into()), ("enum", strings(["blue"]))]);
        for near in ["Blue", "blue ", "", "blu"] {
            assert!(schema.check(&near.into()).is_err(), "{near:?}");
        }
    }

    /// Two spellings of one schema are one schema: what is compared when
    /// a write to the schema set is asked what it changed.
    #[test]
    fn spelling_does_not_distinguish_equal_schemas() {
        assert_eq!(
            schema([
                ("type", "string".into()),
                ("enum", strings(["a", "b", "a"]))
            ]),
            schema([("type", "string".into()), ("enum", strings(["b", "a"]))]),
        );
        assert_eq!(
            schema([("type", "array".into()), ("items", of("any"))]),
            schema([("type", "array".into())]),
        );
        assert_eq!(
            schema([("type", "map".into()), ("values", of("any"))]),
            schema([("type", "map".into())]),
        );
        let fields = || map([("a", of("int")), ("b", of("int"))]);
        assert_eq!(
            schema([
                ("type", "struct".into()),
                ("fields", fields()),
                ("required", strings(["b", "a", "b"])),
            ]),
            schema([
                ("type", "struct".into()),
                ("fields", fields()),
                ("required", strings(["a", "b"])),
            ]),
        );
        assert_eq!(
            schema([
                ("type", "struct".into()),
                ("fields", fields()),
                ("required", strings([])),
            ]),
            schema([("type", "struct".into()), ("fields", fields())]),
        );
        assert_ne!(
            schema([("type", "int".into()), ("max", 1.into())]),
            schema([("type", "int".into()), ("max", 2.into())]),
        );
    }

    #[test]
    fn items_and_values_default_to_any() {
        let array = schema([("type", "array".into())]);
        let mixed = Value::Array(one_of_each().into_iter().map(|(_, v)| v).collect());
        assert_eq!(array.check(&mixed), Ok(()));

        let entries = Value::Map(
            one_of_each()
                .into_iter()
                .map(|(kind, v)| (kind.to_string(), v))
                .collect(),
        );
        assert_eq!(schema([("type", "map".into())]).check(&entries), Ok(()));
    }

    #[test]
    fn an_optional_field_may_be_absent_but_not_wrong() {
        let schema = schema([
            ("type", "struct".into()),
            ("fields", map([("port", of("int"))])),
        ]);
        assert_eq!(schema.check(&map([])), Ok(()));
        assert_eq!(schema.check(&map([("port", 1.into())])), Ok(()));
        assert_eq!(
            violation(&schema, &map([("port", "1".into())])),
            "expected int, found string at port"
        );
    }

    #[test]
    fn an_empty_struct_admits_only_an_empty_map() {
        let schema = schema([("type", "struct".into()), ("fields", map([]))]);
        assert_eq!(schema.check(&map([])), Ok(()));
        assert_eq!(
            violation(&schema, &map([("a", 1.into())])),
            "unknown field `a`"
        );
    }

    /// Field names are data, not keywords: a struct can have a field
    /// called `type`.
    #[test]
    fn a_field_may_be_named_like_a_keyword() {
        let schema = schema([
            ("type", "struct".into()),
            ("required", strings(["type", "required"])),
            (
                "fields",
                map([
                    ("type", of("string")),
                    ("fields", of("int")),
                    ("required", of("bool")),
                ]),
            ),
        ]);
        assert_eq!(
            schema.check(&map([("type", "t".into()), ("required", true.into())])),
            Ok(())
        );
        assert_eq!(
            violation(&schema, &map([("type", "t".into())])),
            "required field `required` is missing"
        );
    }

    #[test]
    fn a_required_field_must_be_declared() {
        assert_eq!(
            kind_of_error([
                ("type", "struct".into()),
                ("fields", map([("host", of("string"))])),
                ("required", strings(["host", "port"])),
            ]),
            SchemaErrorKind::UnknownRequired("port".to_string())
        );
    }

    /// Which violation is reported cannot depend on anything but the
    /// value: a missing field first, then entries in key or index order.
    #[test]
    fn the_violation_reported_is_the_first_in_order() {
        let ints = schema([("type", "map".into()), ("values", of("int"))]);
        let value = map([("b", "x".into()), ("a", "x".into()), ("c", 1.into())]);
        assert_eq!(
            ints.check(&value).unwrap_err().path(),
            [Subkey::Key("a".into())]
        );

        let array = schema([("type", "array".into()), ("items", of("int"))]);
        let value = Value::Array(vec![1.into(), "x".into(), "y".into()]);
        assert_eq!(array.check(&value).unwrap_err().path(), [Subkey::Index(1)]);

        let record = schema([
            ("type", "struct".into()),
            ("required", strings(["z"])),
            ("fields", map([("a", of("int")), ("z", of("int"))])),
        ]);
        assert_eq!(
            record.check(&map([("a", "x".into())])).unwrap_err().kind(),
            &ViolationKind::MissingField("z".to_string())
        );

        // A container's own length is judged before what it holds.
        let short = schema([
            ("type", "array".into()),
            ("items", of("int")),
            ("max_len", 1.into()),
        ]);
        assert!(matches!(
            short.check(&strings(["x", "y"])).unwrap_err().kind(),
            ViolationKind::BadLength { len: 2, .. }
        ));
    }

    #[test]
    fn a_violation_deep_inside_is_located() {
        let schema = schema([
            ("type", "array".into()),
            (
                "items",
                map([
                    ("type", "map".into()),
                    (
                        "values",
                        map([
                            ("type", "struct".into()),
                            ("fields", map([("on", of("bool"))])),
                        ]),
                    ),
                ]),
            ),
        ]);
        let good = map([("k", map([("on", true.into())]))]);
        let bad = map([
            ("k", map([("on", true.into())])),
            ("m", map([("on", 0.into())])),
        ]);
        let err = schema.check(&Value::Array(vec![good, bad])).unwrap_err();
        assert_eq!(
            err.path(),
            [
                Subkey::Index(1),
                Subkey::Key("m".into()),
                Subkey::Key("on".into())
            ]
        );
        assert_eq!(err.to_string(), "expected bool, found int at [1].m.on");
    }

    #[test]
    fn a_violation_quotes_a_key_that_cannot_be_written_bare() {
        let schema = schema([("type", "map".into()), ("values", of("int"))]);
        assert_eq!(
            violation(&schema, &map([("a.b", "x".into())])),
            "expected int, found string at ['a.b']"
        );
    }

    /// A key is a leaf: only `key` (and `any`) admits one, and nothing
    /// reaches inside it.
    #[test]
    fn a_key_is_admitted_as_a_key_only() {
        let trusted = schema([("type", "map".into()), ("values", of("key"))]);
        assert_eq!(trusted.check(&map([("alice", a_key())])), Ok(()));
        assert_eq!(
            violation(&trusted, &map([("alice", "ed25519:…".into())])),
            "expected key, found string at alice"
        );
        let record = schema([("type", "struct".into()), ("fields", map([]))]);
        assert_eq!(violation(&record, &a_key()), "expected map, found key");
    }

    /// A schema is state like any other: it must mean the same after the
    /// trip through the canonical encoding that every node reads it from.
    #[test]
    fn a_schema_means_the_same_after_the_wire() {
        let spelled = map([
            ("type", "struct".into()),
            ("required", strings(["name"])),
            (
                "fields",
                map([
                    (
                        "name",
                        map([
                            ("type", "string".into()),
                            ("min_len", 1.into()),
                            ("enum", strings(["a", "b"])),
                        ]),
                    ),
                    (
                        "n",
                        map([
                            ("type", "int".into()),
                            ("min", i64::MIN.into()),
                            ("max", i64::MAX.into()),
                        ]),
                    ),
                    ("xs", map([("type", "array".into()), ("items", of("key"))])),
                ]),
            ),
        ]);
        let decoded: Value = wire::decode(&wire::encode(&spelled).unwrap()).unwrap();
        assert_eq!(Schema::parse(&decoded), Schema::parse(&spelled));
        assert!(Schema::parse(&decoded).is_ok());
    }

    #[test]
    fn an_empty_schema_set_governs_nothing() {
        assert_eq!(parse_set(&map([])), Ok(BTreeMap::new()));
    }

    #[test]
    fn a_schema_set_is_keyed_by_namespace() {
        let set = parse_set(&map([("b", of("int")), ("a.b", of("bool"))])).unwrap();
        assert_eq!(
            set.keys().map(AsRef::as_ref).collect::<Vec<&str>>(),
            ["a.b", "b"]
        );
        assert_eq!(set["b"], schema([("type", "int".into())]));
    }

    /// Reserved is the `_lotus_` prefix, exactly: every such name, known
    /// to this build or not, and nothing that merely resembles one.
    #[test]
    fn only_the_reserved_prefix_is_reserved() {
        for reserved in [
            "_lotus_",
            "_lotus_schema",
            "_lotus_trusted_keys",
            "_lotus_future",
        ] {
            assert_eq!(
                parse_set(&map([(reserved, of("any"))])),
                Err(SchemaSetError::Reserved(reserved.to_string())),
            );
        }
        for free in ["_lotus", "lotus_x", "x_lotus_", "_Lotus_x", " _lotus_x"] {
            assert!(parse_set(&map([(free, of("any"))])).is_ok(), "{free:?}");
        }
    }

    #[test]
    fn one_bad_entry_fails_the_whole_schema_set() {
        assert_eq!(
            parse_set(&map([("a", of("int")), ("b", "int".into())])),
            Err(SchemaSetError::Invalid {
                namespace: "b".to_string(),
                error: SchemaErrorKind::NotAMap.into(),
            })
        );
        for not_a_map in [Value::Array(Vec::new()), 1.into(), true.into(), a_key()] {
            assert_eq!(parse_set(&not_a_map), Err(SchemaSetError::NotAMap));
        }
    }

    #[test]
    fn errors_read_as_sentences() {
        assert_eq!(
            SchemaSetError::Invalid {
                namespace: "app".to_string(),
                error: SchemaError::from(SchemaErrorKind::InvertedBounds).under("items"),
            }
            .to_string(),
            "the schema for app is invalid: the minimum exceeds the maximum at items"
        );
        assert_eq!(
            SchemaSetError::BadName(String::new()).to_string(),
            "\"\" cannot name a namespace"
        );
        assert_eq!(
            Bounds::<i64> {
                min: None,
                max: None
            }
            .to_string(),
            "anything"
        );
    }

    /// Something a local check asked of the standing value: which
    /// [`Standing`] method, of which path.
    type Question = (&'static str, Vec<Subkey>);

    /// A value standing in for a namespace, noting every question a
    /// local check asks of it.
    struct Recorded<'a> {
        value: &'a Value,
        asked: RefCell<Vec<Question>>,
    }

    impl<'a> Recorded<'a> {
        fn new(value: &'a Value) -> Self {
            Self {
                value,
                asked: RefCell::new(Vec::new()),
            }
        }

        fn note(&self, question: &'static str, path: &[Subkey]) -> Option<&'a Value> {
            self.asked.borrow_mut().push((question, path.to_vec()));
            storage::value::walk(self.value, path)
        }

        /// The paths whose values were materialized.
        fn materialized(&self) -> Vec<Vec<Subkey>> {
            self.asked
                .borrow()
                .iter()
                .filter(|(question, _)| *question == "value")
                .map(|(_, path)| path.clone())
                .collect()
        }
    }

    impl Standing for Recorded<'_> {
        type Error = Infallible;

        fn len(&self, path: &[Subkey]) -> Result<Option<u64>, Infallible> {
            Ok(match self.note("len", path) {
                Some(Value::Array(entries)) => Some(len_of(entries.len())),
                Some(Value::Map(entries)) => Some(len_of(entries.len())),
                _ => None,
            })
        }

        fn contains(&self, path: &[Subkey]) -> Result<bool, Infallible> {
            Ok(self.note("contains", path).is_some())
        }

        fn value(&self, path: &[Subkey]) -> Result<Option<Value>, Infallible> {
            Ok(self.note("value", path).cloned())
        }
    }

    /// A nested write, as the ledger hands one to a local check.
    #[derive(Debug, Clone)]
    enum Op {
        Set(SubkeyPath, Option<Value>),
        Amend(Option<SubkeyPath>, AmendOp),
    }

    impl Op {
        fn target(&self) -> &[Subkey] {
            match self {
                Op::Set(path, _) | Op::Amend(Some(path), _) => path.as_ref(),
                Op::Amend(None, _) => &[],
            }
        }

        /// The value the write leaves, as the stores compute it.
        fn applied_to(&self, standing: &Value) -> Value {
            let mut result = standing.clone();
            match self {
                Op::Set(path, value) => storage::value::set_at(&mut result, path, value.clone()),
                Op::Amend(path, op) => {
                    storage::value::amend_at(&mut result, path.as_ref(), op.clone());
                }
            }
            result
        }

        fn judged_locally(&self, schema: &Schema, standing: &Recorded<'_>) -> Local {
            let Ok(judged) = match self {
                Op::Set(path, value) => schema.check_set(path, value.as_ref(), standing),
                Op::Amend(path, op) => schema.check_amend(path.as_ref(), op, standing),
            };
            judged
        }
    }

    fn at(text: &str) -> SubkeyPath {
        text.parse().unwrap()
    }

    fn set_op(path: &str, value: impl Into<Value>) -> Op {
        Op::Set(at(path), Some(value.into()))
    }

    fn clear_op(path: &str) -> Op {
        Op::Set(at(path), None)
    }

    fn append_op(path: &str, entry: impl Into<Value>) -> Op {
        Op::Amend(Some(at(path)), AmendOp::AppendEntry(entry.into()))
    }

    fn add_op(path: &str, delta: i64) -> Op {
        Op::Amend(
            Some(at(path)),
            AmendOp::IncrementDecrement(IncrementDecrement::new(delta)),
        )
    }

    fn remove_op(path: Option<&str>, entry: impl Into<Value>) -> Op {
        Op::Amend(
            path.map(at),
            AmendOp::DeleteMatching(Predicate::try_new(vec![Match::entry(entry.into())]).unwrap()),
        )
    }

    /// Judges `op` locally and wholly, demands they agree, and yields
    /// the verdict with what the local check asked of the standing value.
    fn judged(
        schema: &Schema,
        standing: &Value,
        op: &Op,
    ) -> (Result<(), Violation>, Vec<Question>) {
        assert_eq!(
            schema.check(standing),
            Ok(()),
            "the standing value conforms"
        );
        let recorded = Recorded::new(standing);
        let whole = schema.check(&op.applied_to(standing));
        assert_eq!(
            op.judged_locally(schema, &recorded),
            Local::Judged(whole.clone()),
            "{op:?} on {standing:?}"
        );
        (whole, recorded.asked.into_inner())
    }

    fn verdict(schema: &Schema, standing: &Value, op: &Op) -> String {
        judged(schema, standing, op)
            .0
            .map_or_else(|violation| violation.to_string(), |()| "ok".to_string())
    }

    /// `{name, count, tags: [..], limits: {..}, nested: {on}}`, bounded
    /// on every side a write can push against.
    fn local_schema() -> Schema {
        schema([
            ("type", "struct".into()),
            ("required", strings(["name", "nested"])),
            (
                "fields",
                map([
                    (
                        "name",
                        map([("type", "string".into()), ("max_len", 3.into())]),
                    ),
                    ("count", map([("type", "int".into()), ("max", 5.into())])),
                    (
                        "tags",
                        map([
                            ("type", "array".into()),
                            ("items", of("string")),
                            ("min_len", 1.into()),
                            ("max_len", 3.into()),
                        ]),
                    ),
                    (
                        "limits",
                        map([
                            ("type", "map".into()),
                            ("values", of("int")),
                            ("min_len", 1.into()),
                            ("max_len", 2.into()),
                        ]),
                    ),
                    (
                        "nested",
                        map([
                            ("type", "struct".into()),
                            ("required", strings(["on"])),
                            ("fields", map([("on", of("bool")), ("why", of("string"))])),
                        ]),
                    ),
                    ("free", of("any")),
                    (
                        "loose",
                        map([("type", "map".into()), ("values", of("int"))]),
                    ),
                ]),
            ),
        ])
    }

    fn local_value() -> Value {
        map([
            ("name", "web".into()),
            ("count", 3.into()),
            ("tags", strings(["a", "b"])),
            ("limits", map([("cpu", 1.into())])),
            ("nested", map([("on", true.into())])),
            ("free", map([("anything", strings(["goes"]))])),
            ("loose", map([("x", 1.into())])),
        ])
    }

    /// Every kind of nested write, judged from its path, reaches the
    /// verdict — and the wording — a check of the whole result reaches.
    #[test]
    fn a_local_check_agrees_with_the_whole_one() {
        let (schema, value) = (local_schema(), local_value());
        let cases = [
            (set_op("name", "api"), "ok"),
            (
                set_op("name", "toolong"),
                "length 7 is out of range, must be at most 3 at name",
            ),
            (set_op("name", 1), "expected string, found int at name"),
            (set_op("colour", "red"), "unknown field `colour`"),
            (set_op("nested.why", "because"), "ok"),
            (set_op("nested.who", "me"), "unknown field `who` at nested"),
            (
                set_op("nested.on", "yes"),
                "expected bool, found string at nested.on",
            ),
            (
                set_op("nested", map([])),
                "required field `on` is missing at nested",
            ),
            (set_op("tags[1]", "z"), "ok"),
            (
                set_op("tags[1]", 1),
                "expected string, found int at tags[1]",
            ),
            (set_op("limits.cpu", 9), "ok"),
            (set_op("limits.mem", 9), "ok"),
            (
                set_op("limits.mem", "9"),
                "expected int, found string at limits.mem",
            ),
            (set_op("free.anything[0]", 1), "ok"),
            (set_op("free.more", a_key()), "ok"),
            (clear_op("count"), "ok"),
            (clear_op("name"), "required field `name` is missing"),
            (
                clear_op("nested.on"),
                "required field `on` is missing at nested",
            ),
            (clear_op("tags[0]"), "ok"),
            (
                clear_op("limits.cpu"),
                "length 0 is out of range, must be 1 to 2 at limits",
            ),
            (clear_op("free.anything"), "ok"),
            (clear_op("loose.x"), "ok"),
            (append_op("tags", "c"), "ok"),
            (
                append_op("tags", 1),
                "expected string, found int at tags[2]",
            ),
            (append_op("free.anything", 1), "ok"),
            (append_op("free.fresh", 1), "ok"),
            (append_op("fresh", 1), "unknown field `fresh`"),
            (
                append_op("loose.fresh", 1),
                "expected int, found array at loose.fresh",
            ),
            (add_op("count", 2), "ok"),
            (
                add_op("count", 3),
                "6 is out of range, must be at most 5 at count",
            ),
            (add_op("limits.cpu", i64::MAX - 1), "ok"),
            (remove_op(Some("tags"), "a"), "ok"),
            (remove_op(Some("tags"), "nope"), "ok"),
            (
                remove_op(Some("limits"), 1),
                "length 0 is out of range, must be 1 to 2 at limits",
            ),
            (remove_op(Some("loose"), 1), "ok"),
            (remove_op(Some("free"), strings(["goes"])), "ok"),
            (remove_op(None, 3), "ok"),
            (remove_op(None, "web"), "required field `name` is missing"),
            (
                remove_op(Some("nested"), true),
                "required field `on` is missing at nested",
            ),
        ];
        for (op, expected) in cases {
            assert_eq!(verdict(&schema, &value, &op), expected, "{op:?}");
        }
    }

    #[test]
    fn a_local_check_minds_a_container_that_is_already_full() {
        let schema = local_schema();
        let mut value = local_value();
        storage::value::set_at(&mut value, &at("tags"), Some(strings(["a", "b", "c"])));
        storage::value::set_at(&mut value, &at("limits.mem"), Some(2.into()));

        assert_eq!(
            verdict(&schema, &value, &append_op("tags", "d")),
            "length 4 is out of range, must be 1 to 3 at tags"
        );
        // The length is judged before the entry, as the whole check does.
        assert_eq!(
            verdict(&schema, &value, &append_op("tags", 1)),
            "length 4 is out of range, must be 1 to 3 at tags"
        );
        assert_eq!(
            verdict(&schema, &value, &set_op("limits.disk", "x")),
            "length 3 is out of range, must be 1 to 2 at limits"
        );
        // Replacing an entry of a full map grows nothing.
        assert_eq!(verdict(&schema, &value, &set_op("limits.mem", 7)), "ok");
        assert_eq!(verdict(&schema, &value, &clear_op("limits.mem")), "ok");
    }

    /// The point of judging locally: a write under a path asks only about
    /// that path, and materializes nothing it does not have to.
    #[test]
    fn a_local_check_reads_no_more_than_the_write_touches() {
        let (schema, value) = (local_schema(), local_value());
        let asked = |op: &Op| judged(&schema, &value, op).1;
        let paths = |text: &[&str]| -> Vec<Vec<Subkey>> {
            text.iter().map(|path| at(path).as_ref().to_vec()).collect()
        };
        let materialized = |op: &Op| -> Vec<Vec<Subkey>> {
            asked(op)
                .into_iter()
                .filter(|(question, _)| *question == "value")
                .map(|(_, path)| path)
                .collect()
        };

        // A set judges what it writes: nothing standing is read at all
        // unless a length bound makes the container's size matter.
        for op in [
            set_op("name", "api"),
            set_op("nested.why", "x"),
            set_op("tags[0]", "z"),
            set_op("loose.fresh", 1),
            set_op("free.more", 1),
            clear_op("count"),
            clear_op("loose.x"),
            clear_op("free.anything"),
        ] {
            assert_eq!(asked(&op), [], "{op:?}");
        }
        assert_eq!(
            asked(&set_op("limits.mem", 1)),
            [
                ("contains", at("limits.mem").as_ref().to_vec()),
                ("len", at("limits").as_ref().to_vec())
            ]
        );
        assert_eq!(
            asked(&clear_op("tags[0]")),
            [("len", at("tags").as_ref().to_vec())]
        );

        // An amend reads the one thing it amends, and only when the
        // schema could mind the result.
        assert_eq!(materialized(&add_op("count", 1)), paths(&["count"]));
        assert_eq!(materialized(&append_op("tags", "c")), paths(&[]));
        assert_eq!(
            materialized(&remove_op(Some("tags"), "a")),
            paths(&["tags"])
        );
        assert_eq!(materialized(&remove_op(Some("loose"), 1)), paths(&[]));
        assert_eq!(materialized(&remove_op(Some("free"), 1)), paths(&[]));
        assert_eq!(materialized(&append_op("free.anything", 1)), paths(&[]));
    }

    /// The promise a local check rests on is that the standing value
    /// conforms. Where it visibly does not, the check does not guess: it
    /// hands the write back to be judged whole.
    #[test]
    fn a_local_check_defers_when_the_standing_value_is_not_what_the_schema_says() {
        let schema = schema([
            ("type", "struct".into()),
            ("fields", map([("n", of("int")), ("xs", of("string"))])),
        ]);
        let standing = map([
            ("n", map([("deep", 1.into())])),
            ("undeclared", map([("deep", 1.into())])),
            ("xs", strings(["a"])),
        ]);
        assert!(schema.check(&standing).is_err());

        for op in [
            set_op("n.deep", 2),
            set_op("undeclared.deep", 2),
            clear_op("undeclared.deep"),
            add_op("undeclared.deep", 1),
            append_op("xs", "b"),
            remove_op(Some("xs"), "a"),
            add_op("xs[0]", 1),
        ] {
            assert_eq!(
                op.judged_locally(&schema, &Recorded::new(&standing)),
                Local::Whole,
                "{op:?}"
            );
        }
    }

    /// splitmix64: enough randomness to wander the space of schemas,
    /// values and writes, the same way on every run.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let z = (self.0 ^ (self.0 >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            let z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
        }

        /// Inclusive on both ends.
        fn between(&mut self, lo: i64, hi: i64) -> i64 {
            lo + i64::try_from(self.next() % u64::try_from(hi - lo + 1).unwrap()).unwrap()
        }

        fn chance(&mut self, percent: u64) -> bool {
            self.next() % 100 < percent
        }

        fn pick<T: Clone>(&mut self, from: &[T]) -> T {
            from[self.below(from.len())].clone()
        }

        fn some_of<T: Clone>(&mut self, from: &[T]) -> Vec<T> {
            from.iter().filter(|_| self.chance(50)).cloned().collect()
        }
    }

    const NAMES: [&str; 4] = ["a", "b", "c", "d"];
    const WORDS: [&str; 5] = ["", "a", "b", "cc", "ddd"];

    /// A random schema, spelled as the value that would be written.
    fn random_schema(rng: &mut Rng, depth: u32) -> Value {
        let lengths = |rng: &mut Rng| {
            let min = rng.between(0, 2);
            [
                rng.chance(40).then_some(("min_len", Value::Int(min))),
                rng.chance(40)
                    .then(|| ("max_len", Value::Int(rng.between(min.max(1), 3)))),
            ]
        };
        let kind = rng.below(if depth == 0 { 4 } else { 7 });
        let keywords: Vec<(&'static str, Value)> = match kind {
            0 => vec![("type", "any".into())],
            1 => vec![("type", "bool".into())],
            2 => {
                let allowed = rng.some_of(&WORDS);
                [Some(("type", "string".into()))]
                    .into_iter()
                    .chain(lengths(rng))
                    .chain([(rng.chance(25) && !allowed.is_empty())
                        .then(|| ("enum", allowed.into_iter().collect()))])
                    .flatten()
                    .collect()
            }
            3 => {
                let min = rng.between(-2, 1);
                let allowed = rng.some_of(&[-1i64, 0, 1, 2]);
                [
                    Some(("type", "int".into())),
                    rng.chance(40).then_some(("min", Value::Int(min))),
                    rng.chance(40)
                        .then(|| ("max", Value::Int(rng.between(min, 3)))),
                    (rng.chance(25) && !allowed.is_empty())
                        .then(|| ("enum", allowed.into_iter().collect())),
                ]
                .into_iter()
                .flatten()
                .collect()
            }
            4 | 5 => {
                let (kind, inner) = if kind == 4 {
                    ("array", "items")
                } else {
                    ("map", "values")
                };
                [Some(("type", kind.into()))]
                    .into_iter()
                    .chain(lengths(rng))
                    .chain([rng
                        .chance(80)
                        .then(|| (inner, random_schema(rng, depth - 1)))])
                    .flatten()
                    .collect()
            }
            _ => {
                let fields = rng.some_of(&NAMES);
                let required = rng.some_of(&fields);
                vec![
                    ("type", "struct".into()),
                    ("required", required.into_iter().collect()),
                    (
                        "fields",
                        fields
                            .into_iter()
                            .map(|name| (name, random_schema(rng, depth - 1)))
                            .collect(),
                    ),
                ]
            }
        };
        map(keywords)
    }

    /// A random value of no schema in particular.
    fn random_value(rng: &mut Rng, depth: u32) -> Value {
        match rng.below(if depth == 0 { 4 } else { 6 }) {
            0 => rng.pick(&WORDS).into(),
            1 => rng.between(-3, 4).into(),
            2 => rng.chance(50).into(),
            3 => a_key(),
            4 => (0..rng.below(4))
                .map(|_| random_value(rng, depth - 1))
                .collect(),
            _ => rng
                .some_of(&NAMES)
                .into_iter()
                .map(|name| (name, random_value(rng, depth - 1)))
                .collect(),
        }
    }

    /// A random value built to fit `node` — though an enum at odds with
    /// its bounds can still leave it short, which the caller checks.
    fn random_fit(rng: &mut Rng, node: &Node) -> Value {
        let count = |rng: &mut Rng, len: &Bounds<u64>| {
            let min = i64::try_from(len.min.unwrap_or(0)).unwrap();
            let max = len.max.map_or(min + 2, |max| i64::try_from(max).unwrap());
            usize::try_from(rng.between(min, max.max(min))).unwrap()
        };
        match node {
            Node::Any => random_value(rng, 2),
            Node::Bool => rng.chance(50).into(),
            Node::Key => a_key(),
            Node::String {
                allowed: Some(allowed),
                ..
            } => rng
                .pick(&allowed.iter().cloned().collect::<Vec<_>>())
                .into(),
            Node::String { len, allowed: None } => "xyz"
                .chars()
                .cycle()
                .skip(rng.below(3))
                .take(count(rng, len))
                .collect::<String>()
                .into(),
            Node::Int {
                allowed: Some(allowed),
                ..
            } => rng
                .pick(&allowed.iter().copied().collect::<Vec<_>>())
                .into(),
            Node::Int {
                range,
                allowed: None,
            } => {
                let lo = range.min.unwrap_or_else(|| range.max.unwrap_or(0) - 3);
                rng.between(lo, range.max.unwrap_or(lo + 3)).into()
            }
            Node::Array { items, len } => (0..count(rng, len))
                .map(|_| random_fit(rng, items))
                .collect(),
            Node::Map { values, len } => Value::Map(
                (0..count(rng, len))
                    .map(|i| (format!("k{i}"), random_fit(rng, values)))
                    .collect(),
            ),
            Node::Struct { fields, required } => Value::Map(
                fields
                    .iter()
                    .filter(|(name, _)| required.contains(*name) || rng.chance(60))
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|(name, field)| (name.clone(), random_fit(rng, field)))
                    .collect(),
            ),
        }
    }

    /// Every path into `value`, the empty one — the value itself — first.
    fn paths_into(value: &Value) -> Vec<Vec<Subkey>> {
        let below: Vec<(Subkey, &Value)> = match value {
            Value::Map(entries) => entries
                .iter()
                .map(|(key, entry)| (Subkey::Key(key.clone()), entry))
                .collect(),
            Value::Array(entries) => entries
                .iter()
                .zip(0u32..)
                .map(|(entry, index)| (Subkey::Index(index), entry))
                .collect(),
            _ => Vec::new(),
        };
        core::iter::once(Vec::new())
            .chain(below.into_iter().flat_map(|(segment, entry)| {
                paths_into(entry)
                    .into_iter()
                    .map(move |rest| core::iter::once(segment.clone()).chain(rest).collect())
            }))
            .collect()
    }

    /// A random write the ledger's pre-validation would let through to
    /// the schema: its path resolves, and its op fits what is there.
    fn random_op(rng: &mut Rng, schema: &Schema, standing: &Value) -> Option<Op> {
        let target = rng.pick(&paths_into(standing));
        let there = storage::value::walk(standing, &target).expect("the path was just walked");
        let extended =
            |segment: Subkey| -> Vec<Subkey> { target.iter().cloned().chain([segment]).collect() };
        let path = |segments: Vec<Subkey>| SubkeyPath::try_new(segments).ok();
        // What to write at a path: something that fits the schema there,
        // or something that most likely does not.
        let candidate = |rng: &mut Rng, at: &[Subkey]| match schema.0.locate::<Infallible>(at) {
            Ok(node) if rng.chance(60) => random_fit(rng, node),
            _ => random_value(rng, 2),
        };
        let fresh = |rng: &mut Rng, entries: &BTreeMap<String, Value>| {
            let free: Vec<&str> = NAMES
                .into_iter()
                .chain(["k0", "k1", "k2", "k3", "new"])
                .filter(|name| !entries.contains_key(*name))
                .collect();
            Subkey::Key(rng.pick(&free).to_string())
        };

        match (rng.below(7), there) {
            (0, _) => Some(Op::Set(
                path(target.clone())?,
                Some(candidate(rng, &target)),
            )),
            (1, _) => Some(Op::Set(path(target.clone())?, None)),
            (2, Value::Map(entries)) => {
                let at = extended(fresh(rng, entries));
                let value = candidate(rng, &at);
                Some(Op::Set(path(at)?, Some(value)))
            }
            (3, Value::Array(entries)) => {
                let index = u32::try_from(entries.len()).unwrap();
                let entry = candidate(rng, &extended(Subkey::Index(index)));
                Some(Op::Amend(path(target.clone()), AmendOp::AppendEntry(entry)))
            }
            (3, Value::Map(entries)) => {
                let at = extended(fresh(rng, entries));
                let entry = random_value(rng, 1);
                Some(Op::Amend(path(at), AmendOp::AppendEntry(entry)))
            }
            (4, Value::Int(_)) => {
                let op = IncrementDecrement::new(rng.between(-3, 3));
                let min = rng.between(-2, 2);
                let op = if rng.chance(25) { op.with_min(min) } else { op };
                let op = if rng.chance(25) {
                    op.with_max(rng.between(min, 4))
                } else {
                    op
                };
                Some(Op::Amend(
                    path(target.clone()),
                    AmendOp::IncrementDecrement(op),
                ))
            }
            (5 | 6, Value::Map(_) | Value::Array(_)) => {
                let entries: Vec<&Value> = match there {
                    Value::Map(entries) => entries.values().collect(),
                    Value::Array(entries) => entries.iter().collect(),
                    _ => Vec::new(),
                };
                let entry = if entries.is_empty() || rng.chance(20) {
                    random_value(rng, 1)
                } else {
                    rng.pick(&entries).clone()
                };
                let predicate = Predicate::try_new(vec![Match::entry(entry)]).unwrap();
                Some(Op::Amend(
                    path(target.clone()),
                    AmendOp::DeleteMatching(predicate),
                ))
            }
            _ => None,
        }
    }

    /// The local check against its oracle, over schemas, conforming
    /// values and writes nobody thought to write down: whatever the
    /// write, judging it from its path must reach exactly the verdict
    /// that applying it and checking the whole result reaches — and must
    /// never need the whole value to get there.
    #[test]
    fn a_local_check_agrees_with_the_whole_one_on_random_writes() {
        let mut rng = Rng(0x10705);
        let (mut refused, mut admitted) = (0u32, 0u32);

        for _ in 0..4000 {
            let schema = Schema::parse(&random_schema(&mut rng, 3))
                .expect("the generator spells only valid schemas");
            let standing = random_fit(&mut rng, &schema.0);
            if schema.check(&standing).is_err() {
                continue;
            }
            for _ in 0..12 {
                let Some(op) = random_op(&mut rng, &schema, &standing) else {
                    continue;
                };
                let recorded = Recorded::new(&standing);
                let whole = schema.check(&op.applied_to(&standing));
                assert_eq!(
                    op.judged_locally(&schema, &recorded),
                    Local::Judged(whole.clone()),
                    "\nschema: {schema:?}\nstanding: {standing:?}\nop: {op:?}"
                );
                // Whatever was materialized was the write's own target,
                // never anything above it.
                for read in recorded.materialized() {
                    assert_eq!(read, op.target(), "\nschema: {schema:?}\nop: {op:?}");
                }
                if matches!(op, Op::Set(..)) {
                    assert_eq!(recorded.materialized(), Vec::<Vec<Subkey>>::new());
                }
                match whole {
                    Ok(()) => admitted += 1,
                    Err(_) => refused += 1,
                }
            }
        }

        // A generator that drifted into producing only one verdict would
        // leave this test agreeing about nothing.
        assert!(admitted > 2000, "only {admitted} writes were admitted");
        assert!(refused > 2000, "only {refused} writes were refused");
    }
}
