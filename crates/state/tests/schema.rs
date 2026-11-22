//! Schemas, as a ledger and a chain enforce them: every way a write can
//! reach a governed namespace or the schema set itself, on every storage
//! backend — the lookups a schema check makes are the backend's own.

use std::{cell::RefCell, collections::BTreeMap};

use state::{
    ApplyError, Chain, Error, Insert, Ledger, MIN_KEEP_MINUTES_KEY, SCHEMA_KEY, Schema,
    SchemaSetError, ValueError,
};
use storage::{LogEntry, MemStorage, NamespaceOp, Resolution, SqliteStorage, Storage, ValueMeta};
use wire::{
    Envelope, EnvelopeDigest, Msg,
    keys::{Ed25519PublicKey, Key, PublicKey},
    msg::{
        AmendNamespaceKey, AmendOp, DeleteNamespace, FullCheckpoint, IncrementDecrement, InitMsg,
        Match, Namespace, NamespaceKey, Predicate, SetNamespace, SetNamespaceKey, Value,
    },
    subkey::{Subkey, SubkeyPath},
};

/// Runs each named case on every storage backend.
macro_rules! on_every_backend {
    ($($name:ident)*) => {
        mod mem {
            $(#[test] fn $name() { super::$name(storage::MemStorage::default) })*
        }
        mod sqlite {
            $(#[test] fn $name() {
                super::$name(|| storage::SqliteStorage::open_in_memory().unwrap())
            })*
        }
    };
}

on_every_backend! {
    conforming_writes_of_every_kind_are_admitted
    a_whole_value_that_breaks_the_schema_is_refused
    a_nested_set_is_judged_where_it_lands
    an_undeclared_field_cannot_be_added
    a_required_field_cannot_be_cleared
    an_increment_is_judged_by_where_it_lands
    an_append_is_judged_by_what_it_leaves
    an_array_cannot_shrink_below_its_minimum
    a_delete_matching_cannot_remove_a_required_field
    a_map_cannot_outgrow_its_maximum
    an_append_that_creates_its_array_is_judged
    root_values_are_held_to_root_schemas
    a_key_field_admits_only_a_key
    namespaces_without_a_schema_are_left_alone
    a_namespace_whose_name_needs_quoting_is_governed
    a_missing_namespace_is_reported_before_its_schema
    a_path_fault_is_reported_before_the_schema
    a_schema_its_namespace_breaks_is_refused
    a_whole_schema_set_is_judged_entry_by_entry
    tightening_in_place_is_judged_and_loosening_is_free
    amends_to_a_schema_are_judged
    a_malformed_schema_is_refused_however_it_is_written
    an_empty_schema_set_governs_nothing
    a_reserved_namespace_cannot_be_given_a_schema
    reserved_namespaces_keep_their_own_rules
    removing_an_entry_lifts_its_schema
    deleting_the_schema_set_lifts_every_schema
    a_schema_can_precede_and_outlive_its_namespace
    an_incompatible_change_goes_through_removal
    resetting_the_same_schema_is_accepted
    the_schema_is_readable_from_the_ledger
    the_schema_in_force_is_the_parents
    an_unreadable_entry_refuses_writes_to_its_namespace
    an_unreadable_entry_is_repaired_by_overwriting_it
    a_schema_set_that_is_not_a_map_refuses_every_governable_write
    genesis_is_held_to_the_schemas_it_carries
    an_adopted_checkpoint_is_held_to_its_schemas
    replay_enforces_schemas_along_the_way
    a_checkpoint_carries_its_schemas
    the_chain_refuses_a_violating_envelope_at_the_door
    a_fork_never_leaves_canonical_state_breaking_its_schema
    a_batch_stops_at_the_envelope_that_breaks_a_schema
    the_walk_drops_a_stored_envelope_that_breaks_a_schema
    a_schema_survives_compaction
    a_joiner_adopting_a_cut_inherits_its_schemas
    a_nested_write_never_materializes_its_namespace
    a_whole_write_reads_nothing_of_what_it_replaces
    a_schema_change_reads_only_the_namespaces_it_changes
}

fn key(k: &str) -> NamespaceKey {
    NamespaceKey::try_new(k).unwrap()
}

fn path(text: &str) -> SubkeyPath {
    text.parse().unwrap()
}

fn map(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    entries.into_iter().collect()
}

fn strings(entries: impl IntoIterator<Item = &'static str>) -> Value {
    entries.into_iter().collect()
}

fn of(kind: &str) -> Value {
    map([("type", kind.into())])
}

fn a_key() -> Value {
    Value::Key(Key::new(
        PublicKey::Ed25519(Ed25519PublicKey::from_bytes([7; 32])),
        1,
    ))
}

/// A message, short of the envelope it chains onto.
type Write = Box<dyn Fn(EnvelopeDigest) -> Msg>;

fn set(k: &str, value: Value) -> Write {
    let key = key(k);
    Box::new(move |prev| {
        Msg::SetNamespace(SetNamespace {
            prev,
            key: key.clone(),
            namespace: Namespace {
                value: value.clone(),
            },
        })
    })
}

fn set_at(k: &str, at: &str, value: impl Into<Option<Value>>) -> Write {
    let (key, path, value) = (key(k), path(at), value.into());
    Box::new(move |prev| {
        Msg::SetNamespaceKey(SetNamespaceKey {
            prev,
            key: key.clone(),
            path: path.clone(),
            value: value.clone(),
        })
    })
}

fn clear(k: &str, at: &str) -> Write {
    set_at(k, at, None)
}

fn amend(k: &str, at: Option<&str>, op: AmendOp) -> Write {
    let (key, path) = (key(k), at.map(path));
    Box::new(move |prev| {
        Msg::AmendNamespaceKey(AmendNamespaceKey {
            prev,
            key: key.clone(),
            path: path.clone(),
            op: op.clone(),
        })
    })
}

fn append(k: &str, at: &str, value: impl Into<Value>) -> Write {
    amend(k, Some(at), AmendOp::AppendEntry(value.into()))
}

fn add(k: &str, at: &str, delta: i64) -> Write {
    amend(
        k,
        Some(at),
        AmendOp::IncrementDecrement(IncrementDecrement::new(delta)),
    )
}

/// Removes the entries of the container at `at` that equal `entry`.
fn remove(k: &str, at: Option<&str>, entry: impl Into<Value>) -> Write {
    let predicate = Predicate::try_new(vec![Match::entry(entry.into())]).unwrap();
    amend(k, at, AmendOp::DeleteMatching(predicate))
}

fn delete(k: &str) -> Write {
    let key = key(k);
    Box::new(move |prev| {
        Msg::DeleteNamespace(DeleteNamespace {
            prev,
            key: key.clone(),
        })
    })
}

fn init(namespaces: impl IntoIterator<Item = (&'static str, Value)>) -> Envelope {
    Envelope::new(Msg::Init(InitMsg {
        state: checkpoint(namespaces),
    }))
}

fn checkpoint(namespaces: impl IntoIterator<Item = (&'static str, Value)>) -> FullCheckpoint {
    FullCheckpoint {
        namespaces: namespaces
            .into_iter()
            .map(|(k, value)| (key(k), Namespace { value }))
            .collect(),
    }
}

/// A ledger and the store it stands in.
struct World<S> {
    store: S,
    ledger: Ledger,
}

impl<S: Storage> World<S> {
    fn genesis(mut store: S, namespaces: impl IntoIterator<Item = (&'static str, Value)>) -> Self {
        let ledger = Ledger::init(&mut store, &init(namespaces)).unwrap();
        Self { store, ledger }
    }

    /// A ledger holding [`app`] under `app`, with [`app_schema`] in force.
    fn governed(store: S) -> Self {
        let mut world = Self::genesis(store, [("app", app())]);
        world.ok(set(SCHEMA_KEY, map([("app", app_schema())])));
        world
    }

    fn try_apply(&mut self, write: &Write) -> Result<(), ApplyError<S::Error>> {
        let envelope = Envelope::new(write(self.ledger.head()));
        self.ledger.apply(&mut self.store, &envelope)
    }

    fn ok(&mut self, write: Write) {
        self.try_apply(&write).unwrap();
    }

    /// Applies a write that must be refused, checking it moved nothing.
    fn refused(&mut self, write: Write) -> ApplyError<S::Error> {
        let (head, state) = (self.ledger.head(), self.state());
        let err = self
            .try_apply(&write)
            .expect_err("the write should have been refused");
        assert_eq!(self.ledger.head(), head, "a refused write moves no head");
        assert_eq!(self.state(), state, "a refused write changes no state");
        err
    }

    /// The namespace a refused write would have left breaking its schema,
    /// and how.
    fn violation(&mut self, write: Write) -> String {
        match self.refused(write) {
            ApplyError::SchemaViolation { key, violation } => format!("{key}: {violation}"),
            other => panic!("expected a schema violation, got {other:?}"),
        }
    }

    /// Why the schema set refused a write, or could not be read for one.
    fn unreadable(&mut self, write: Write) -> String {
        match self.refused(write) {
            ApplyError::InvalidValue {
                key,
                reason: ValueError::Schema(reason),
            } if key.as_ref() == SCHEMA_KEY => reason.to_string(),
            other => panic!("expected the schema set to refuse, got {other:?}"),
        }
    }

    fn state(&self) -> FullCheckpoint {
        self.ledger.checkpoint(&self.store).unwrap()
    }

    fn value(&self, k: &str) -> Option<Value> {
        self.ledger
            .namespace(&self.store, &key(k))
            .unwrap()
            .map(|namespace| namespace.value)
    }
}

/// `{name: "web", replicas: 3, tags: ["a", "b"], limits: {cpu: 2, mem: 4},
/// mode: "blue"}`.
fn app() -> Value {
    map([
        ("name", "web".into()),
        ("replicas", 3.into()),
        ("tags", strings(["a", "b"])),
        ("limits", map([("cpu", 2.into()), ("mem", 4.into())])),
        ("mode", "blue".into()),
    ])
}

/// The schema [`app`] conforms to, with a constraint of every kind:
///
/// - `name` (required): a string of 1 to 8
/// - `replicas` (required): an int from 1 to 5
/// - `tags`: 1 to 3 strings of at most 4
/// - `limits`: at most 3 non-negative ints
/// - `mode`: `blue` or `green`
/// - `owner`: a key
fn app_schema() -> Value {
    map([
        ("type", "struct".into()),
        ("required", strings(["name", "replicas"])),
        (
            "fields",
            map([
                (
                    "name",
                    map([
                        ("type", "string".into()),
                        ("min_len", 1.into()),
                        ("max_len", 8.into()),
                    ]),
                ),
                (
                    "replicas",
                    map([("type", "int".into()), ("min", 1.into()), ("max", 5.into())]),
                ),
                (
                    "tags",
                    map([
                        ("type", "array".into()),
                        (
                            "items",
                            map([("type", "string".into()), ("max_len", 4.into())]),
                        ),
                        ("min_len", 1.into()),
                        ("max_len", 3.into()),
                    ]),
                ),
                (
                    "limits",
                    map([
                        ("type", "map".into()),
                        ("values", map([("type", "int".into()), ("min", 0.into())])),
                        ("max_len", 3.into()),
                    ]),
                ),
                (
                    "mode",
                    map([
                        ("type", "string".into()),
                        ("enum", strings(["blue", "green"])),
                    ]),
                ),
                ("owner", of("key")),
            ]),
        ),
    ])
}

fn conforming_writes_of_every_kind_are_admitted<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());

    world.ok(set("app", app()));
    world.ok(set_at("app", "replicas", Value::Int(5)));
    world.ok(set_at("app", "limits.disk", Value::Int(9)));
    world.ok(set_at("app", "tags[0]", Value::from("z")));
    world.ok(append("app", "tags", "c"));
    world.ok(add("app", "replicas", -4));
    world.ok(remove("app", Some("tags"), "c"));
    world.ok(remove("app", Some("limits"), 9));
    world.ok(clear("app", "mode"));
    world.ok(set_at("app", "owner", a_key()));

    assert_eq!(
        world.value("app"),
        Some(map([
            ("name", "web".into()),
            ("replicas", 1.into()),
            ("tags", strings(["z", "b"])),
            ("limits", map([("cpu", 2.into()), ("mem", 4.into())])),
            ("owner", a_key()),
        ]))
    );

    world.ok(delete("app"));
    assert_eq!(world.value("app"), None);
}

fn a_whole_value_that_breaks_the_schema_is_refused<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());

    assert_eq!(
        world.violation(set("app", "flat".into())),
        "app: expected map, found string"
    );
    assert_eq!(
        world.violation(set("app", map([("name", "web".into())]))),
        "app: required field `replicas` is missing"
    );
    assert_eq!(
        world.violation(set("app", map([]))),
        "app: required field `name` is missing"
    );
}

fn a_nested_set_is_judged_where_it_lands<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());

    assert_eq!(
        world.violation(set_at("app", "name", Value::Int(7))),
        "app: expected string, found int at name"
    );
    assert_eq!(
        world.violation(set_at("app", "name", Value::from(""))),
        "app: length 0 is out of range, must be 1 to 8 at name"
    );
    assert_eq!(
        world.violation(set_at("app", "limits.cpu", Value::Int(-1))),
        "app: -1 is out of range, must be at least 0 at limits.cpu"
    );
    assert_eq!(
        world.violation(set_at("app", "tags[1]", Value::from("too long"))),
        "app: length 8 is out of range, must be at most 4 at tags[1]"
    );
    assert_eq!(
        world.violation(set_at("app", "mode", Value::from("red"))),
        "app: not one of the allowed values at mode"
    );
    assert_eq!(
        world.violation(set_at("app", "tags", strings([]))),
        "app: length 0 is out of range, must be 1 to 3 at tags"
    );
    assert_eq!(
        world.violation(set_at("app", "limits", strings(["cpu"]))),
        "app: expected map, found array at limits"
    );
}

fn an_undeclared_field_cannot_be_added<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());
    assert_eq!(
        world.violation(set_at("app", "colour", Value::from("red"))),
        "app: unknown field `colour`"
    );
}

fn a_required_field_cannot_be_cleared<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());

    assert_eq!(
        world.violation(clear("app", "name")),
        "app: required field `name` is missing"
    );
    assert_eq!(
        world.violation(clear("app", "replicas")),
        "app: required field `replicas` is missing"
    );
    // What the schema does not require is free to go.
    world.ok(clear("app", "tags"));
    world.ok(clear("app", "limits.cpu"));
}

fn an_increment_is_judged_by_where_it_lands<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());
    let clamped = |delta: i64, min: Option<i64>, max: Option<i64>| {
        let op = IncrementDecrement::new(delta);
        let op = min.map_or(op.clone(), |min| op.clone().with_min(min));
        let op = max.map_or(op.clone(), |max| op.clone().with_max(max));
        amend("app", Some("replicas"), AmendOp::IncrementDecrement(op))
    };

    assert_eq!(
        world.violation(add("app", "replicas", 3)),
        "app: 6 is out of range, must be 1 to 5 at replicas"
    );
    assert_eq!(
        world.violation(add("app", "replicas", -3)),
        "app: 0 is out of range, must be 1 to 5 at replicas"
    );
    // The op's own clamp runs first; the schema judges the clamped sum.
    assert_eq!(
        world.violation(clamped(100, None, Some(6))),
        "app: 6 is out of range, must be 1 to 5 at replicas"
    );
    world.ok(clamped(100, None, Some(5)));
    assert_eq!(
        world.value("app").unwrap(),
        map([
            ("name", "web".into()),
            ("replicas", 5.into()),
            ("tags", strings(["a", "b"])),
            ("limits", map([("cpu", 2.into()), ("mem", 4.into())])),
            ("mode", "blue".into()),
        ])
    );
    world.ok(clamped(-100, Some(1), None));
    world.ok(add("app", "replicas", 0));
}

fn an_append_is_judged_by_what_it_leaves<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());

    assert_eq!(
        world.violation(append("app", "tags", 7)),
        "app: expected string, found int at tags[2]"
    );
    assert_eq!(
        world.violation(append("app", "tags", "too long")),
        "app: length 8 is out of range, must be at most 4 at tags[2]"
    );
    world.ok(append("app", "tags", "c"));
    assert_eq!(
        world.violation(append("app", "tags", "d")),
        "app: length 4 is out of range, must be 1 to 3 at tags"
    );
}

fn an_array_cannot_shrink_below_its_minimum<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());

    world.ok(clear("app", "tags[0]"));
    assert_eq!(
        world.violation(clear("app", "tags[0]")),
        "app: length 0 is out of range, must be 1 to 3 at tags"
    );
    assert_eq!(
        world.violation(remove("app", Some("tags"), "b")),
        "app: length 0 is out of range, must be 1 to 3 at tags"
    );
    // Matching nothing removes nothing.
    world.ok(remove("app", Some("tags"), "nope"));
}

fn a_delete_matching_cannot_remove_a_required_field<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());

    assert_eq!(
        world.violation(remove("app", None, "web")),
        "app: required field `name` is missing"
    );
    assert_eq!(
        world.violation(remove("app", None, 3)),
        "app: required field `replicas` is missing"
    );
    world.ok(remove("app", None, "blue"));
    assert_eq!(world.value("app").unwrap(), {
        let Value::Map(mut entries) = app() else {
            unreachable!()
        };
        entries.remove("mode");
        Value::Map(entries)
    });
}

fn a_map_cannot_outgrow_its_maximum<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());

    world.ok(set_at("app", "limits.disk", Value::Int(1)));
    assert_eq!(
        world.violation(set_at("app", "limits.net", Value::Int(1))),
        "app: length 4 is out of range, must be at most 3 at limits"
    );
    // Replacing an entry is not growth.
    world.ok(set_at("app", "limits.disk", Value::Int(2)));
    assert_eq!(
        world.violation(set_at("app", "limits.disk", Value::from("2"))),
        "app: expected int, found string at limits.disk"
    );
}

fn an_append_that_creates_its_array_is_judged<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());
    world.ok(clear("app", "tags"));

    assert_eq!(
        world.violation(append("app", "tags", 7)),
        "app: expected string, found int at tags[0]"
    );
    assert_eq!(
        world.violation(append("app", "labels", "x")),
        "app: unknown field `labels`"
    );
    world.ok(append("app", "tags", "ok"));
}

/// A namespace whose value is a leaf or an array has no path to write
/// under: its amends carry none, and are judged all the same.
fn root_values_are_held_to_root_schemas<S: Storage>(new: fn() -> S) {
    let mut world = World::genesis(new(), [("count", 3.into()), ("list", strings(["a"]))]);
    world.ok(set(
        SCHEMA_KEY,
        map([
            ("count", map([("type", "int".into()), ("max", 3.into())])),
            (
                "list",
                map([
                    ("type", "array".into()),
                    ("items", of("string")),
                    ("max_len", 2.into()),
                ]),
            ),
        ]),
    ));
    let bump = |delta| {
        amend(
            "count",
            None,
            AmendOp::IncrementDecrement(IncrementDecrement::new(delta)),
        )
    };
    let push = |value: Value| amend("list", None, AmendOp::AppendEntry(value));

    assert_eq!(
        world.violation(bump(1)),
        "count: 4 is out of range, must be at most 3"
    );
    world.ok(bump(-1));

    assert_eq!(
        world.violation(push(1.into())),
        "list: expected string, found int at [1]"
    );
    world.ok(push("b".into()));
    assert_eq!(
        world.violation(push("c".into())),
        "list: length 3 is out of range, must be at most 2"
    );
    world.ok(remove("list", None, "a"));
    assert_eq!(world.value("list"), Some(strings(["b"])));
}

fn a_key_field_admits_only_a_key<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());

    assert_eq!(
        world.violation(set_at("app", "owner", Value::from("alice"))),
        "app: expected key, found string at owner"
    );
    world.ok(set_at("app", "owner", a_key()));
    assert_eq!(
        world.violation(set_at("app", "name", a_key())),
        "app: expected string, found key at name"
    );
}

fn namespaces_without_a_schema_are_left_alone<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());

    world.ok(set("other", "anything".into()));
    world.ok(set("other", map([("list", strings([]))])));
    world.ok(set_at("other", "extra", Value::Int(1)));
    world.ok(append("other", "list", 1));
    world.ok(add("other", "extra", i64::MAX - 1));
    world.ok(delete("other"));
}

fn a_namespace_whose_name_needs_quoting_is_governed<S: Storage>(new: fn() -> S) {
    for name in ["my.app", "it's[0]", "with space", "ünï"] {
        let mut world = World::genesis(new(), []);
        world.ok(set(SCHEMA_KEY, map([(name, of("int"))])));

        world.ok(set(name, 1.into()));
        assert_eq!(
            world.violation(set(name, "one".into())),
            format!("{name}: expected int, found string")
        );
        assert_eq!(
            world.ledger.schema(&world.store, &key(name)).unwrap(),
            Some(Schema::parse(&of("int")).unwrap())
        );
    }
}

fn a_missing_namespace_is_reported_before_its_schema<S: Storage>(new: fn() -> S) {
    let mut world = World::genesis(new(), []);
    world.ok(set(SCHEMA_KEY, map([("ghost", app_schema())])));

    for write in [
        set_at("ghost", "name", Value::from("x")),
        append("ghost", "tags", "x"),
        delete("ghost"),
    ] {
        assert!(matches!(
            world.refused(write),
            ApplyError::UnknownNamespace(k) if k == key("ghost")
        ));
    }
}

fn a_path_fault_is_reported_before_the_schema<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());

    assert!(matches!(
        world.refused(set_at("app", "nope.deeper", Value::Int(1))),
        ApplyError::UnknownPath { .. }
    ));
    assert!(matches!(
        world.refused(set_at("app", "name.inside", Value::Int(1))),
        ApplyError::PathTypeMismatch { .. }
    ));
    assert!(matches!(
        world.refused(add("app", "name", 1)),
        ApplyError::AmendTypeMismatch { .. }
    ));
}

fn a_schema_its_namespace_breaks_is_refused<S: Storage>(new: fn() -> S) {
    let mut world = World::genesis(new(), [("app", app())]);

    assert_eq!(
        world.violation(set(SCHEMA_KEY, map([("app", of("int"))]))),
        "app: expected int, found map"
    );
    assert_eq!(world.value(SCHEMA_KEY), None);

    // One keyword off is as refused as the wrong type.
    let mut tight = app_schema();
    let at = path("fields.replicas.max");
    storage::value::set_at(&mut tight, &at, Some(2.into()));
    assert_eq!(
        world.violation(set(SCHEMA_KEY, map([("app", tight)]))),
        "app: 3 is out of range, must be 1 to 2 at replicas"
    );
}

fn a_whole_schema_set_is_judged_entry_by_entry<S: Storage>(new: fn() -> S) {
    let mut world = World::genesis(new(), [("a", 1.into()), ("b", "x".into())]);
    world.ok(set(
        SCHEMA_KEY,
        map([("a", of("int")), ("b", of("string"))]),
    ));

    let narrow = map([("type", "int".into()), ("max", 0.into())]);
    assert_eq!(
        world.violation(set(SCHEMA_KEY, map([("a", narrow), ("b", of("string"))]))),
        "a: 1 is out of range, must be at most 0"
    );
    assert_eq!(
        world.violation(set(SCHEMA_KEY, map([("a", of("int")), ("b", of("int"))]))),
        "b: expected int, found string"
    );
    // An entry is added for a namespace that conforms, changed for one
    // that still does, and dropped for one that no longer needs it.
    let wide = map([("type", "int".into()), ("max", 5.into())]);
    world.ok(set(SCHEMA_KEY, map([("a", wide), ("c", of("bool"))])));
    world.ok(set("b", 7.into()));
    assert_eq!(
        world.violation(set("a", 6.into())),
        "a: 6 is out of range, must be at most 5"
    );
    assert_eq!(
        world.violation(set("c", 1.into())),
        "c: expected bool, found int"
    );
}

fn tightening_in_place_is_judged_and_loosening_is_free<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());
    let max = "app.fields.replicas.max";

    assert_eq!(
        world.violation(set_at(SCHEMA_KEY, max, Value::Int(2))),
        "app: 3 is out of range, must be 1 to 2 at replicas"
    );
    world.ok(set_at(SCHEMA_KEY, max, Value::Int(3)));
    assert_eq!(
        world.violation(set_at("app", "replicas", Value::Int(4))),
        "app: 4 is out of range, must be 1 to 3 at replicas"
    );

    world.ok(set_at(SCHEMA_KEY, max, Value::Int(9)));
    world.ok(set_at("app", "replicas", Value::Int(9)));

    // Dropping a bound loosens too; dropping the field the value holds
    // does not.
    world.ok(clear(SCHEMA_KEY, max));
    world.ok(set_at("app", "replicas", Value::Int(i64::MAX)));
    assert_eq!(
        world.violation(clear(SCHEMA_KEY, "app.fields.mode")),
        "app: unknown field `mode`"
    );
}

fn amends_to_a_schema_are_judged<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());
    let required = "app.required";

    // Requiring a field the value has is fine; one it lacks is not, and
    // one the schema does not declare is no schema at all.
    world.ok(append(SCHEMA_KEY, required, "mode"));
    assert_eq!(
        world.violation(clear("app", "mode")),
        "app: required field `mode` is missing"
    );
    assert_eq!(
        world.violation(append(SCHEMA_KEY, required, "owner")),
        "app: required field `owner` is missing"
    );
    assert_eq!(
        world.unreadable(append(SCHEMA_KEY, required, "ghost")),
        "the schema for app is invalid: required field `ghost` is not declared in `fields`"
    );
    assert_eq!(
        world.unreadable(append(SCHEMA_KEY, required, 7)),
        "the schema for app is invalid: `required` holds a bad value"
    );

    let max = "app.fields.replicas.max";
    assert_eq!(
        world.violation(add(SCHEMA_KEY, max, -3)),
        "app: 3 is out of range, must be 1 to 2 at replicas"
    );
    world.ok(add(SCHEMA_KEY, max, -2));
    assert_eq!(
        world.unreadable(add(SCHEMA_KEY, max, -3)),
        "the schema for app is invalid: the minimum exceeds the maximum at fields.replicas"
    );

    world.ok(append(SCHEMA_KEY, "app.fields.mode.enum", "red"));
    world.ok(set_at("app", "mode", Value::from("red")));
    assert_eq!(
        world.violation(remove(SCHEMA_KEY, Some("app.fields.mode.enum"), "red")),
        "app: not one of the allowed values at mode"
    );

    // Removing the whole entry by what it holds lifts the schema.
    let structs = Predicate::try_new(vec![Match::at(path("type"), "struct".into())]).unwrap();
    world.ok(amend(SCHEMA_KEY, None, AmendOp::DeleteMatching(structs)));
    world.ok(set("app", "flat".into()));
}

fn a_malformed_schema_is_refused_however_it_is_written<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());

    assert_eq!(
        world.unreadable(set(SCHEMA_KEY, map([("app", of("float"))]))),
        "the schema for app is invalid: unknown type `float`"
    );
    assert_eq!(
        world.unreadable(set(SCHEMA_KEY, map([("app", "struct".into())]))),
        "the schema for app is invalid: a schema must be a map"
    );
    for not_a_map in [strings(["app"]), "app".into(), 1.into(), true.into()] {
        assert_eq!(
            world.unreadable(set(SCHEMA_KEY, not_a_map)),
            "the schema set must be a map of namespace name to schema"
        );
    }
    assert_eq!(
        world.unreadable(set_at(
            SCHEMA_KEY,
            "app.fields.name.pattern",
            Value::from(".*")
        )),
        "the schema for app is invalid: unknown keyword `pattern` at fields.name"
    );
    assert_eq!(
        world.unreadable(clear(SCHEMA_KEY, "app.type")),
        "the schema for app is invalid: `type` is missing"
    );
    assert_eq!(
        world.unreadable(clear(SCHEMA_KEY, "app.fields")),
        "the schema for app is invalid: `fields` is missing"
    );
    assert_eq!(
        world.unreadable(set_at(SCHEMA_KEY, "other", Value::from("int"))),
        "the schema for other is invalid: a schema must be a map"
    );
    assert_eq!(
        world.unreadable(set_at(SCHEMA_KEY, "app.fields.tags.min_len", Value::Int(4))),
        "the schema for app is invalid: the minimum exceeds the maximum at fields.tags"
    );

    assert_eq!(world.value(SCHEMA_KEY), Some(map([("app", app_schema())])));
}

fn an_empty_schema_set_governs_nothing<S: Storage>(new: fn() -> S) {
    let mut world = World::genesis(new(), [("app", app())]);
    world.ok(set(SCHEMA_KEY, map([])));
    world.ok(set("app", "flat".into()));
    world.ok(set("fresh", 1.into()));
}

fn a_reserved_namespace_cannot_be_given_a_schema<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());

    for reserved in ["_lotus_nodes", "_lotus_schema", "_lotus_not_yet_invented"] {
        let expected = format!("{reserved} is reserved and cannot be given a schema");
        assert_eq!(
            world.unreadable(set(SCHEMA_KEY, map([(reserved, of("any"))]))),
            expected
        );
        assert_eq!(
            world.unreadable(set_at(SCHEMA_KEY, reserved, of("any"))),
            expected
        );
    }
}

/// The schema set is one more reserved namespace; the others answer to
/// the rules they always had, whatever it holds.
fn reserved_namespaces_keep_their_own_rules<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());

    assert!(matches!(
        world.refused(set(MIN_KEEP_MINUTES_KEY, "soon".into())),
        ApplyError::InvalidValue { key: k, reason: ValueError::MinKeepMinutes }
            if k == key(MIN_KEEP_MINUTES_KEY)
    ));
    world.ok(set(MIN_KEEP_MINUTES_KEY, 5.into()));
    let bump = amend(
        MIN_KEEP_MINUTES_KEY,
        None,
        AmendOp::IncrementDecrement(IncrementDecrement::new(-5)),
    );
    assert!(matches!(
        world.refused(bump),
        ApplyError::InvalidValue {
            reason: ValueError::MinKeepMinutes,
            ..
        }
    ));
}

fn removing_an_entry_lifts_its_schema<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());
    world.ok(clear(SCHEMA_KEY, "app"));
    world.ok(set("app", "flat".into()));
    assert_eq!(world.value(SCHEMA_KEY), Some(map([])));
}

fn deleting_the_schema_set_lifts_every_schema<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());
    world.ok(delete(SCHEMA_KEY));
    world.ok(set("app", "flat".into()));
    assert_eq!(
        world.ledger.schema(&world.store, &key("app")).unwrap(),
        None
    );
}

/// Absent satisfies any schema: the namespace can go, and what comes back
/// under its name is held to the schema that waited for it.
fn a_schema_can_precede_and_outlive_its_namespace<S: Storage>(new: fn() -> S) {
    let mut world = World::genesis(new(), []);
    world.ok(set(SCHEMA_KEY, map([("app", app_schema())])));

    assert_eq!(
        world.violation(set("app", "flat".into())),
        "app: expected map, found string"
    );
    world.ok(set("app", app()));
    world.ok(delete("app"));
    assert_eq!(
        world.violation(set("app", "flat".into())),
        "app: expected map, found string"
    );
    world.ok(set("app", app()));
}

/// No one envelope can change both a value and its schema, so a change
/// neither side survives goes through having no schema.
fn an_incompatible_change_goes_through_removal<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());

    assert_eq!(
        world.violation(set_at(SCHEMA_KEY, "app", of("int"))),
        "app: expected int, found map"
    );
    assert_eq!(
        world.violation(set("app", 1.into())),
        "app: expected map, found int"
    );

    world.ok(clear(SCHEMA_KEY, "app"));
    world.ok(set("app", 1.into()));
    world.ok(set_at(SCHEMA_KEY, "app", of("int")));
    assert_eq!(
        world.violation(set("app", app())),
        "app: expected int, found map"
    );
}

fn resetting_the_same_schema_is_accepted<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());
    world.ok(set(SCHEMA_KEY, map([("app", app_schema())])));
    world.ok(set_at(SCHEMA_KEY, "app", app_schema()));
    assert_eq!(
        world.violation(set("app", "flat".into())),
        "app: expected map, found string"
    );
}

fn the_schema_is_readable_from_the_ledger<S: Storage>(new: fn() -> S) {
    let mut world = World::genesis(new(), [("app", app())]);
    let schema = |world: &World<S>, k: &str| world.ledger.schema(&world.store, &key(k)).unwrap();
    assert_eq!(schema(&world, "app"), None);

    world.ok(set(SCHEMA_KEY, map([("app", app_schema())])));
    assert_eq!(
        schema(&world, "app"),
        Some(Schema::parse(&app_schema()).unwrap())
    );
    assert_eq!(schema(&world, "other"), None);
    assert_eq!(schema(&world, SCHEMA_KEY), None);

    world.ok(clear(SCHEMA_KEY, "app"));
    assert_eq!(schema(&world, "app"), None);
}

/// An envelope answers to the schema at its parent — fixed by its `prev`,
/// so every node judges it alike wherever its own head stands.
fn the_schema_in_force_is_the_parents<S: Storage>(new: fn() -> S) {
    let mut world = World::genesis(new(), [("app", app())]);
    let mut before = world.ledger;
    world.ok(set(SCHEMA_KEY, map([("app", app_schema())])));

    let flat = |prev| Envelope::new(set("app", "flat".into())(prev));
    before
        .apply(&mut world.store, &flat(before.head()))
        .unwrap();
    assert_eq!(
        world.violation(set("app", "flat".into())),
        "app: expected map, found string"
    );

    // And the fork that never took the schema is still free of it.
    before
        .apply(&mut world.store, &flat(before.head()))
        .unwrap();
}

/// A head installed without passing through validation: state a build
/// from before schemas, or a foreign one, could have left behind.
fn unvalidated<S: Storage>(
    mut store: S,
    namespaces: impl IntoIterator<Item = (&'static str, Value)>,
) -> World<S> {
    let head = EnvelopeDigest::from_bytes([9; 32]);
    store
        .install(head, checkpoint(namespaces).namespaces)
        .unwrap();
    let ledger = Ledger::open(&store, head).unwrap();
    World { store, ledger }
}

/// A guard that disarms itself when its own value is corrupt is not a
/// guard: an entry that cannot be read refuses, it does not wave through.
fn an_unreadable_entry_refuses_writes_to_its_namespace<S: Storage>(new: fn() -> S) {
    let mut world = unvalidated(
        new(),
        [
            ("app", app()),
            ("other", "x".into()),
            (SCHEMA_KEY, map([("app", of("float"))])),
        ],
    );
    let unreadable = "the schema for app is invalid: unknown type `float`";

    assert_eq!(world.unreadable(set("app", app())), unreadable);
    assert_eq!(
        world.unreadable(set_at("app", "replicas", Value::Int(4))),
        unreadable
    );
    assert_eq!(world.unreadable(add("app", "replicas", 1)), unreadable);
    assert!(matches!(
        world.ledger.schema(&world.store, &key("app")),
        Err(ApplyError::InvalidValue {
            reason: ValueError::Schema(SchemaSetError::Invalid { .. }),
            ..
        })
    ));

    // Its neighbours have nothing to do with it.
    world.ok(set("other", "y".into()));
    world.ok(set("fresh", 1.into()));
}

fn an_unreadable_entry_is_repaired_by_overwriting_it<S: Storage>(new: fn() -> S) {
    let junk = || [("app", app()), (SCHEMA_KEY, map([("app", of("float"))]))];

    // What replaces it is judged as a new schema would be.
    let mut world = unvalidated(new(), junk());
    assert_eq!(
        world.violation(set_at(SCHEMA_KEY, "app", of("int"))),
        "app: expected int, found map"
    );
    world.ok(set_at(SCHEMA_KEY, "app", app_schema()));
    assert_eq!(
        world.violation(set("app", "flat".into())),
        "app: expected map, found string"
    );

    let mut world = unvalidated(new(), junk());
    world.ok(clear(SCHEMA_KEY, "app"));
    world.ok(set("app", "flat".into()));

    let mut world = unvalidated(new(), junk());
    world.ok(delete(SCHEMA_KEY));
    world.ok(set("app", "flat".into()));
}

fn a_schema_set_that_is_not_a_map_refuses_every_governable_write<S: Storage>(new: fn() -> S) {
    for junk in [Value::from("junk"), strings(["app"]), 7.into()] {
        let mut world = unvalidated(new(), [("app", app()), (SCHEMA_KEY, junk)]);
        let not_a_map = "the schema set must be a map of namespace name to schema";

        assert_eq!(world.unreadable(set("app", app())), not_a_map);
        assert_eq!(world.unreadable(set("fresh", 1.into())), not_a_map);
        assert_eq!(world.unreadable(add("app", "replicas", 1)), not_a_map);

        // The ledger's own config is not the schema set's to hold up, and
        // a delete leaves nothing to judge.
        world.ok(set(MIN_KEEP_MINUTES_KEY, 5.into()));
        world.ok(delete("app"));

        world.ok(set(SCHEMA_KEY, map([])));
        world.ok(set("fresh", 1.into()));
    }
}

fn genesis_is_held_to_the_schemas_it_carries<S: Storage>(new: fn() -> S) {
    let open = |namespaces: Vec<(&'static str, Value)>| {
        let mut store = new();
        Ledger::init(&mut store, &init(namespaces)).map(|ledger| World { store, ledger })
    };
    let governed = |app: Value| vec![("app", app), (SCHEMA_KEY, map([("app", app_schema())]))];

    assert!(matches!(
        open(governed("flat".into())),
        Err(Error::Apply(ApplyError::SchemaViolation { key: k, .. })) if k == key("app")
    ));
    assert!(matches!(
        open(vec![(SCHEMA_KEY, map([("app", of("float"))]))]),
        Err(Error::Apply(ApplyError::InvalidValue {
            reason: ValueError::Schema(SchemaSetError::Invalid { .. }),
            ..
        }))
    ));
    assert!(matches!(
        open(vec![(SCHEMA_KEY, map([("_lotus_nodes", of("any"))]))]),
        Err(Error::Apply(ApplyError::InvalidValue {
            reason: ValueError::Schema(SchemaSetError::Reserved(_)),
            ..
        }))
    ));
    assert!(matches!(
        open(vec![(SCHEMA_KEY, "junk".into())]),
        Err(Error::Apply(ApplyError::InvalidValue {
            reason: ValueError::Schema(SchemaSetError::NotAMap),
            ..
        }))
    ));

    // A schema may wait for a namespace genesis does not carry.
    let mut world = open(vec![(SCHEMA_KEY, map([("app", app_schema())]))]).unwrap();
    assert_eq!(
        world.violation(set("app", "flat".into())),
        "app: expected map, found string"
    );

    let mut world = open(governed(app())).unwrap();
    assert_eq!(
        world.violation(set_at("app", "replicas", Value::Int(0))),
        "app: 0 is out of range, must be 1 to 5 at replicas"
    );
}

fn an_adopted_checkpoint_is_held_to_its_schemas<S: Storage>(new: fn() -> S) {
    let cut = Envelope::new(set("x", 1.into())(EnvelopeDigest::from_bytes([1; 32])));
    let state = |app: Value| checkpoint([("app", app), (SCHEMA_KEY, map([("app", app_schema())]))]);

    let mut store = new();
    assert!(matches!(
        Ledger::adopt(&mut store, &cut, &state("flat".into())),
        Err(Error::Apply(ApplyError::SchemaViolation { key: k, .. })) if k == key("app")
    ));
    assert!(matches!(
        Ledger::adopt(&mut store, &cut, &checkpoint([(SCHEMA_KEY, "junk".into())])),
        Err(Error::Apply(ApplyError::InvalidValue { .. }))
    ));

    let ledger = Ledger::adopt(&mut store, &cut, &state(app())).unwrap();
    let mut world = World { store, ledger };
    assert_eq!(
        world.violation(set("app", "flat".into())),
        "app: expected map, found string"
    );
    world.ok(set_at("app", "replicas", Value::Int(4)));
}

/// Three envelopes that govern `app`, chained from `root`, and a fourth
/// that breaks the schema they leave in force.
fn governing_run(root: EnvelopeDigest) -> (Vec<Envelope>, Envelope) {
    let writes = [
        set("app", app()),
        set(SCHEMA_KEY, map([("app", app_schema())])),
        set_at("app", "replicas", Value::Int(4)),
    ];
    let (envelopes, head) = writes
        .iter()
        .fold((Vec::new(), root), |(mut run, prev), write| {
            let envelope = Envelope::new(write(prev));
            let head = envelope.digest().unwrap();
            run.push(envelope);
            (run, head)
        });
    (envelopes, Envelope::new(set("app", "flat".into())(head)))
}

fn replay_enforces_schemas_along_the_way<S: Storage>(new: fn() -> S) {
    let genesis = init([]);
    let (run, breaking) = governing_run(genesis.digest().unwrap());
    let chain: Vec<Envelope> = core::iter::once(genesis).chain(run).collect();

    let mut store = new();
    let ledger = Ledger::replay(&mut store, &chain).unwrap();
    assert_eq!(
        ledger.schema(&store, &key("app")).unwrap(),
        Some(Schema::parse(&app_schema()).unwrap())
    );

    let mut store = new();
    assert!(matches!(
        Ledger::replay(&mut store, chain.iter().chain([&breaking])),
        Err(Error::Apply(ApplyError::SchemaViolation { key: k, .. })) if k == key("app")
    ));
}

/// A rewritten chain opens from a checkpoint of the old one's state, and
/// the schemas are part of that state.
fn a_checkpoint_carries_its_schemas<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(new());
    let rewritten = Envelope::new(Msg::Init(InitMsg {
        state: world.state(),
    }));

    world.ledger = Ledger::init(&mut world.store, &rewritten).unwrap();
    assert_eq!(
        world.violation(set("app", "flat".into())),
        "app: expected map, found string"
    );
    world.ok(set_at("app", "replicas", Value::Int(4)));
}

/// A chain on `store` holding [`governing_run`] above an empty genesis,
/// with the envelope that would break it.
fn governed_chain<S: Storage>(store: &mut S) -> (Chain, Vec<EnvelopeDigest>, Envelope) {
    let mut chain = Chain::init(store, init([])).unwrap();
    let (run, breaking) = governing_run(chain.root());
    let digests = run.iter().map(|e| e.digest().unwrap()).collect();
    assert_eq!(chain.insert_batch(store, run).unwrap(), Insert::Extended);
    (chain, digests, breaking)
}

fn is_violation<E>(err: &Error<E>, namespace: &str) -> bool {
    matches!(err, Error::Apply(ApplyError::SchemaViolation { key: k, .. }) if *k == key(namespace))
}

fn the_chain_refuses_a_violating_envelope_at_the_door<S: Storage>(new: fn() -> S) {
    let mut store = new();
    let (mut chain, _, breaking) = governed_chain(&mut store);
    let head = chain.head();

    let err = chain.insert(&mut store, breaking.clone()).unwrap_err();
    assert!(is_violation(&err, "app"), "{err:?}");
    assert_eq!(
        store.envelope(breaking.digest().unwrap()).unwrap(),
        None,
        "never stored"
    );
    assert_eq!(chain.head(), head, "head must not move");
}

/// A schema and a write that would break it, as siblings: each is valid
/// where it stands, so both are stored — and whichever wins the fork, the
/// canonical state conforms to whatever schema it holds, on every node,
/// in whatever order the two arrived.
fn a_fork_never_leaves_canonical_state_breaking_its_schema<S: Storage>(new: fn() -> S) {
    let genesis = || init([("app", app())]);
    let root = genesis().digest().unwrap();
    let schema = Envelope::new(set(SCHEMA_KEY, map([("app", app_schema())]))(root));
    let flat = Envelope::new(set("app", "flat".into())(root));
    let under_schema = Envelope::new(set("app", "flat".into())(schema.digest().unwrap()));

    let heads: Vec<EnvelopeDigest> = [[&schema, &flat], [&flat, &schema]]
        .into_iter()
        .map(|order| {
            let mut store = new();
            let mut chain = Chain::init(&mut store, genesis()).unwrap();
            for envelope in order {
                chain.insert(&mut store, envelope.clone()).unwrap();
            }

            let ledger = chain.ledger();
            let value = ledger
                .namespace(&store, &key("app"))
                .unwrap()
                .unwrap()
                .value;
            if let Some(schema) = ledger.schema(&store, &key("app")).unwrap() {
                assert_eq!(schema.check(&value), Ok(()));
            } else {
                assert_eq!(value, Value::from("flat"));
            }

            // Canonical or not, the schema's branch refuses what breaks it.
            let err = chain.insert(&mut store, under_schema.clone()).unwrap_err();
            assert!(is_violation(&err, "app"), "{err:?}");
            chain.head()
        })
        .collect();

    assert_eq!(heads[0], heads[1], "arrival order must not matter");
}

fn a_batch_stops_at_the_envelope_that_breaks_a_schema<S: Storage>(new: fn() -> S) {
    let mut store = new();
    let mut chain = Chain::init(&mut store, init([])).unwrap();
    let (run, breaking) = governing_run(chain.root());
    let last_valid = run.last().unwrap().digest().unwrap();
    let after = Envelope::new(set("other", 1.into())(breaking.digest().unwrap()));

    let batch = run.into_iter().chain([breaking, after.clone()]);
    let err = chain.insert_batch(&mut store, batch).unwrap_err();

    assert!(is_violation(&err, "app"), "{err:?}");
    assert_eq!(chain.head(), last_valid, "the valid prefix is kept");
    assert_eq!(store.envelope(after.digest().unwrap()).unwrap(), None);
}

/// `insert` stores only what applies, but the walk stays defensive: a
/// violating envelope that reached the log some other way — a node that
/// ran without schemas — is dropped when it wins its fork, never adopted.
fn the_walk_drops_a_stored_envelope_that_breaks_a_schema<S: Storage>(new: fn() -> S) {
    let mut store = new();
    let (mut chain, _, breaking) = governed_chain(&mut store);
    let head = chain.head();
    let bad = breaking.digest().unwrap();
    store.put_envelope(bad, breaking).unwrap();

    // Grind until the valid sibling loses the digest race, so the walk
    // must adjudicate the violation before reaching it.
    let good = (1..)
        .map(|n| Envelope::new(set("other", Value::Int(n))(head)))
        .find(|envelope| envelope.digest().unwrap() < bad)
        .expect("some value hashes below the violation");

    let err = chain.insert(&mut store, good.clone()).unwrap_err();
    assert!(is_violation(&err, "app"), "{err:?}");
    assert_eq!(store.envelope(bad).unwrap(), None, "dropped");
    assert_eq!(chain.head(), head, "the walk aborted at the fault");

    assert_eq!(
        chain.insert_batch(&mut store, core::iter::empty()).unwrap(),
        Insert::Extended
    );
    assert_eq!(chain.head(), good.digest().unwrap());
}

/// The envelope that set a schema can be pruned; the schema is state, and
/// stands in the cut's version like everything else below it.
fn a_schema_survives_compaction<S: Storage>(new: fn() -> S) {
    let mut store = new();
    let (mut chain, digests, breaking) = governed_chain(&mut store);
    let cut = *digests.last().unwrap();

    assert_eq!(chain.compact(&mut store, cut).unwrap(), 3);
    assert_eq!(
        store.envelope(digests[1]).unwrap(),
        None,
        "the schema's envelope is gone"
    );

    let mut reopened = Chain::open(&mut store, cut).unwrap();
    let err = reopened.insert(&mut store, breaking).unwrap_err();
    assert!(is_violation(&err, "app"), "{err:?}");
    reopened
        .insert(
            &mut store,
            Envelope::new(set_at("app", "replicas", Value::Int(5))(cut)),
        )
        .unwrap();
}

fn a_joiner_adopting_a_cut_inherits_its_schemas<S: Storage>(new: fn() -> S) {
    let mut store = new();
    let (chain, digests, breaking) = governed_chain(&mut store);
    let cut = *digests.last().unwrap();
    let handed_over = store.envelope(cut).unwrap().unwrap();
    let state = chain.checkpoint(&store).unwrap();

    let mut fresh = new();
    let mut joined = Chain::adopt(&mut fresh, handed_over.clone(), &state).unwrap();
    let err = joined.insert(&mut fresh, breaking).unwrap_err();
    assert!(is_violation(&err, "app"), "{err:?}");

    // A sponsor cannot hand over state its own schemas refuse.
    let tampered = FullCheckpoint {
        namespaces: state
            .namespaces
            .into_iter()
            .chain([(
                key("app"),
                Namespace {
                    value: "flat".into(),
                },
            )])
            .collect::<BTreeMap<_, _>>(),
    };
    let mut fresh = new();
    let err = Chain::adopt(&mut fresh, handed_over, &tampered).unwrap_err();
    assert!(is_violation(&err, "app"), "{err:?}");
}

/// A read of namespace state the ledger asked a store for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Asked {
    /// A whole namespace, materialized.
    Namespace(String),
    /// Every namespace, materialized.
    Everything,
    /// The value under a path, materialized.
    Value(String, Vec<Subkey>),
    /// The shape or size of what a path addresses; nothing below it.
    Shape(String, Vec<Subkey>),
}

/// A store that notes what the ledger reads of namespace state, to hold
/// the ledger to reading no more than a write touches.
struct Spy<S> {
    inner: S,
    asked: RefCell<Vec<Asked>>,
}

impl<S> Spy<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            asked: RefCell::new(Vec::new()),
        }
    }

    fn note(&self, asked: Asked) {
        self.asked.borrow_mut().push(asked);
    }
}

impl<S: Storage> Storage for Spy<S> {
    type Error = S::Error;

    fn contains_version(&self, head: EnvelopeDigest) -> Result<bool, S::Error> {
        self.inner.contains_version(head)
    }

    fn resolve(
        &self,
        head: EnvelopeDigest,
        key: &NamespaceKey,
        path: &[Subkey],
    ) -> Result<Option<Resolution>, S::Error> {
        self.note(Asked::Shape(key.to_string(), path.to_vec()));
        self.inner.resolve(head, key, path)
    }

    fn value_at(
        &self,
        head: EnvelopeDigest,
        key: &NamespaceKey,
        path: &[Subkey],
    ) -> Result<Option<Value>, S::Error> {
        self.note(Asked::Value(key.to_string(), path.to_vec()));
        self.inner.value_at(head, key, path)
    }

    fn meta_at(
        &self,
        head: EnvelopeDigest,
        key: &NamespaceKey,
        path: &[Subkey],
    ) -> Result<Option<ValueMeta>, S::Error> {
        self.note(Asked::Shape(key.to_string(), path.to_vec()));
        self.inner.meta_at(head, key, path)
    }

    fn namespace(
        &self,
        head: EnvelopeDigest,
        key: &NamespaceKey,
    ) -> Result<Option<Namespace>, S::Error> {
        self.note(Asked::Namespace(key.to_string()));
        self.inner.namespace(head, key)
    }

    fn namespaces(
        &self,
        head: EnvelopeDigest,
    ) -> impl Iterator<Item = Result<(NamespaceKey, Namespace), S::Error>> {
        self.note(Asked::Everything);
        self.inner.namespaces(head)
    }

    fn commit(
        &mut self,
        parent: EnvelopeDigest,
        head: EnvelopeDigest,
        op: NamespaceOp,
    ) -> Result<(), S::Error> {
        self.inner.commit(parent, head, op)
    }

    fn install(
        &mut self,
        head: EnvelopeDigest,
        namespaces: impl IntoIterator<Item = (NamespaceKey, Namespace)>,
    ) -> Result<(), S::Error> {
        self.inner.install(head, namespaces)
    }

    fn retain(&mut self, keep: &[EnvelopeDigest]) -> Result<(), S::Error> {
        self.inner.retain(keep)
    }

    fn put_envelope(&mut self, digest: EnvelopeDigest, envelope: Envelope) -> Result<(), S::Error> {
        self.inner.put_envelope(digest, envelope)
    }

    fn logged_envelope(&self, digest: EnvelopeDigest) -> Result<Option<LogEntry>, S::Error> {
        self.inner.logged_envelope(digest)
    }

    fn remove_envelope(&mut self, digest: EnvelopeDigest) -> Result<(), S::Error> {
        self.inner.remove_envelope(digest)
    }

    fn children(
        &self,
        parent: EnvelopeDigest,
    ) -> impl Iterator<Item = Result<EnvelopeDigest, S::Error>> {
        self.inner.children(parent)
    }
}

impl<S: Storage> World<Spy<S>> {
    /// Applies `write` — admitted or refused, the reads are the same
    /// question — and yields what it had the store materialize.
    fn materialized_by(&mut self, write: Write) -> (bool, Vec<Asked>) {
        self.store.asked.borrow_mut().clear();
        let admitted = self.try_apply(&write).is_ok();
        let asked = self.store.asked.borrow().clone();
        (
            admitted,
            asked
                .into_iter()
                // Shapes materialize nothing, and the signature thresholds
                // every envelope answers to are no part of this question.
                .filter(|asked| match asked {
                    Asked::Shape(..) => false,
                    Asked::Namespace(k) => !k.starts_with("_lotus_min_envelope_"),
                    Asked::Everything | Asked::Value(..) => true,
                })
                .collect(),
        )
    }
}

fn value_read(k: &str, at: &str) -> Asked {
    Asked::Value(k.to_string(), path(at).as_ref().to_vec())
}

/// A governed namespace may be far larger than any one write to it, so a
/// write under a path is judged by that path: the namespace is never
/// materialized, and the only values read are the schema's own entry and
/// — for an amend whose outcome depends on it — the thing amended.
fn a_nested_write_never_materializes_its_namespace<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(Spy::new(new()));
    let schema_read = value_read(SCHEMA_KEY, "app");
    let just = |reads: &[Asked]| -> Vec<Asked> {
        core::iter::once(schema_read.clone())
            .chain(reads.iter().cloned())
            .collect()
    };

    // Sets and clears, admitted and refused: nothing standing is read.
    for (write, admitted) in [
        (set_at("app", "replicas", Value::Int(4)), true),
        (set_at("app", "replicas", Value::Int(9)), false),
        (set_at("app", "name", Value::from("api")), true),
        (set_at("app", "colour", Value::from("red")), false),
        (set_at("app", "tags[0]", Value::from("z")), true),
        (set_at("app", "tags[0]", Value::Int(1)), false),
        (set_at("app", "limits.disk", Value::Int(1)), true),
        (set_at("app", "limits.net", Value::Int(1)), false),
        (set_at("app", "limits.cpu", Value::from("x")), false),
        (clear("app", "name"), false),
        (clear("app", "mode"), true),
        (clear("app", "limits.disk"), true),
        (clear("app", "tags[0]"), true),
        (clear("app", "tags[0]"), false),
    ] {
        assert_eq!(world.materialized_by(write), (admitted, just(&[])));
    }

    // An append reads nothing either: its entry is in the envelope.
    for (write, admitted) in [
        (append("app", "tags", "c"), true),
        (append("app", "tags", 7), false),
        (append("app", "labels", "x"), false),
    ] {
        assert_eq!(world.materialized_by(write), (admitted, just(&[])));
    }

    // An increment reads the integer it adds to — once to add, once to
    // judge the sum.
    let replicas = value_read("app", "replicas");
    assert_eq!(
        world.materialized_by(add("app", "replicas", 1)),
        (
            true,
            vec![replicas.clone(), schema_read.clone(), replicas.clone()]
        )
    );
    assert_eq!(
        world.materialized_by(add("app", "replicas", 9)),
        (false, vec![replicas.clone(), schema_read.clone(), replicas])
    );

    // A delete-matching reads the container it removes from only where
    // the schema sets a floor under it: `tags` has a minimum length,
    // `limits` has none.
    assert_eq!(
        world.materialized_by(remove("app", Some("tags"), "c")),
        (true, just(&[value_read("app", "tags")]))
    );
    assert_eq!(
        world.materialized_by(remove("app", Some("limits"), 2)),
        (true, just(&[]))
    );
}

/// A whole set carries its value: there is nothing standing to read.
fn a_whole_write_reads_nothing_of_what_it_replaces<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(Spy::new(new()));
    let schema_read = value_read(SCHEMA_KEY, "app");

    assert_eq!(
        world.materialized_by(set("app", app())),
        (true, vec![schema_read.clone()])
    );
    assert_eq!(
        world.materialized_by(set("app", "flat".into())),
        (false, vec![schema_read])
    );
    // And a namespace with no schema is not read at all.
    world.ok(set("other", map([("n", 1.into())])));
    assert_eq!(
        world.materialized_by(set_at("other", "m", Value::Int(2))),
        (true, vec![])
    );
}

/// A change to the schema set must judge whole namespaces — there is no
/// path to judge them by — but only the ones whose entries it changes.
fn a_schema_change_reads_only_the_namespaces_it_changes<S: Storage>(new: fn() -> S) {
    let mut world = World::governed(Spy::new(new()));
    world.ok(set("big", "left alone".into()));
    world.ok(set_at(SCHEMA_KEY, "big", of("string")));

    let (admitted, asked) =
        world.materialized_by(set_at(SCHEMA_KEY, "app.fields.replicas.max", Value::Int(9)));
    assert!(admitted);
    assert!(asked.contains(&Asked::Namespace("app".to_string())));
    assert!(
        !asked.iter().any(|asked| matches!(
            asked,
            Asked::Namespace(k) | Asked::Value(k, _) if k == "big"
        )),
        "{asked:?}"
    );
    assert!(!asked.contains(&Asked::Everything));
}

// The macro names every case; these keep the backends it runs them on
// from drifting out of the imports unnoticed.
const _: fn() -> MemStorage = MemStorage::default;
const _: fn() -> Result<SqliteStorage, storage::sqlite::Error> = SqliteStorage::open_in_memory;
