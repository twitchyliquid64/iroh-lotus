//! The behavioral contract every backend must satisfy.
//!
//! Two backends that both pass this suite cannot disagree about what a
//! commit does — which is what lets validation live above [`Storage`] and
//! trust the op to apply identically everywhere.
//!
//! Instantiate it in a backend's test module; the expression is evaluated
//! once per test and must yield a fresh, empty store:
//!
//! ```ignore
//! #[cfg(test)]
//! mod tests {
//!     storage::storage_conformance!(MyStore::open_temp());
//! }
//! ```

use std::collections::BTreeMap;

use wire::{
    Envelope, EnvelopeDigest, Msg, VerificationStatus,
    keys::KeyId,
    msg::{
        AmendOp, IncrementDecrement, Match, Namespace, NamespaceKey, Predicate, SetNamespace, Value,
    },
    subkey::{Subkey, SubkeyPath},
};

use crate::{NamespaceOp, NodeKind, Resolution, Storage, StoredAt, ValueMeta};

/// Instantiates the conformance suite as `#[test]` functions.
#[macro_export]
macro_rules! storage_conformance {
    ($make:expr) => {
        #[test]
        fn conformance_unknown_heads_are_absent() {
            $crate::conformance::unknown_heads_are_absent($make);
        }
        #[test]
        fn conformance_install_creates_a_version() {
            $crate::conformance::install_creates_a_version($make);
        }
        #[test]
        fn conformance_install_keeps_other_chains() {
            $crate::conformance::install_keeps_other_chains($make);
        }
        #[test]
        fn conformance_commit_keeps_the_parent_intact() {
            $crate::conformance::commit_keeps_the_parent_intact($make);
        }
        #[test]
        fn conformance_put_creates_and_overwrites() {
            $crate::conformance::put_creates_and_overwrites($make);
        }
        #[test]
        fn conformance_delete_removes_the_namespace() {
            $crate::conformance::delete_removes_the_namespace($make);
        }
        #[test]
        fn conformance_set_at_writes_and_creates_leaves() {
            $crate::conformance::set_at_writes_and_creates_leaves($make);
        }
        #[test]
        fn conformance_set_at_replaces_array_elements() {
            $crate::conformance::set_at_replaces_array_elements($make);
        }
        #[test]
        fn conformance_set_at_clears_values() {
            $crate::conformance::set_at_clears_values($make);
        }
        #[test]
        fn conformance_amend_at_appends_and_creates_arrays() {
            $crate::conformance::amend_at_appends_and_creates_arrays($make);
        }
        #[test]
        fn conformance_amend_at_increments_integers() {
            $crate::conformance::amend_at_increments_integers($make);
        }
        #[test]
        fn conformance_amend_at_without_a_path_amends_the_root() {
            $crate::conformance::amend_at_without_a_path_amends_the_root($make);
        }
        #[test]
        fn conformance_amend_at_deletes_matching_entries() {
            $crate::conformance::amend_at_deletes_matching_entries($make);
        }
        #[test]
        fn conformance_value_at_reads_the_addressed_value() {
            $crate::conformance::value_at_reads_the_addressed_value($make);
        }
        #[test]
        fn conformance_meta_at_counts_and_names_entries() {
            $crate::conformance::meta_at_counts_and_names_entries($make);
        }
        #[test]
        fn conformance_set_at_does_not_bleed_into_other_versions() {
            $crate::conformance::set_at_does_not_bleed_into_other_versions($make);
        }
        #[test]
        fn conformance_reads_at_a_head_are_stable_across_updates() {
            $crate::conformance::reads_at_a_head_are_stable_across_updates($make);
        }
        #[test]
        fn conformance_forks_diverge_independently() {
            $crate::conformance::forks_diverge_independently($make);
        }
        #[test]
        fn conformance_resolve_reports_the_walk() {
            $crate::conformance::resolve_reports_the_walk($make);
        }
        #[test]
        fn conformance_namespace_keys_name_the_versions_namespaces() {
            $crate::conformance::namespace_keys_name_the_versions_namespaces($make);
        }
        #[test]
        fn conformance_namespaces_reencode_to_identical_bytes() {
            $crate::conformance::namespaces_reencode_to_identical_bytes($make);
        }
        #[test]
        fn conformance_retain_prunes_unkept_versions() {
            $crate::conformance::retain_prunes_unkept_versions($make);
        }
        #[test]
        fn conformance_envelopes_store_and_read_back() {
            $crate::conformance::envelopes_store_and_read_back($make);
        }
        #[test]
        fn conformance_envelopes_round_trip_the_verification_status() {
            $crate::conformance::envelopes_round_trip_the_verification_status($make);
        }
        #[test]
        fn conformance_envelopes_record_when_they_were_stored() {
            $crate::conformance::envelopes_record_when_they_were_stored($make);
        }
        #[test]
        fn conformance_re_storing_keeps_the_time_first_seen() {
            $crate::conformance::re_storing_keeps_the_time_first_seen($make);
        }
        #[test]
        fn conformance_children_come_back_in_digest_order() {
            $crate::conformance::children_come_back_in_digest_order($make);
        }
        #[test]
        fn conformance_retain_leaves_the_envelope_log_alone() {
            $crate::conformance::retain_leaves_the_envelope_log_alone($make);
        }
        #[test]
        fn conformance_remove_envelope_unstores_and_unindexes() {
            $crate::conformance::remove_envelope_unstores_and_unindexes($make);
        }
        #[test]
        fn conformance_parent_follows_prev() {
            $crate::conformance::parent_follows_prev($make);
        }
    };
}

fn digest(byte: u8) -> EnvelopeDigest {
    EnvelopeDigest::from_bytes([byte; 32])
}

fn key(k: &str) -> NamespaceKey {
    NamespaceKey::try_new(k).expect("suite keys are non-empty")
}

fn leaf(v: &str) -> Namespace {
    Namespace {
        value: Value::String(v.to_string()),
    }
}

fn map(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

fn path(segments: impl IntoIterator<Item = Subkey>) -> SubkeyPath {
    SubkeyPath::try_new(segments.into_iter().collect()).expect("suite paths are non-empty")
}

fn sub(k: &str) -> Subkey {
    Subkey::Key(k.to_string())
}

fn namespaces(
    entries: impl IntoIterator<Item = (&'static str, Namespace)>,
) -> BTreeMap<NamespaceKey, Namespace> {
    entries.into_iter().map(|(k, ns)| (key(k), ns)).collect()
}

/// A namespace whose value is `{"a": {"b": "1"}, "list": ["x", "y"]}` —
/// one of each container kind.
fn nested() -> Namespace {
    Namespace {
        value: map([
            ("a", map([("b", Value::String("1".into()))])),
            (
                "list",
                Value::Array(vec![Value::String("x".into()), Value::String("y".into())]),
            ),
        ]),
    }
}

/// A `SetAt` against the `n` namespace the nested fixtures install.
fn set_at(p: SubkeyPath, value: Option<Value>) -> NamespaceOp {
    NamespaceOp::SetAt {
        key: key("n"),
        path: p,
        value,
    }
}

fn fetch<S: Storage>(store: &S, head: u8, k: &str) -> Option<Namespace> {
    store
        .namespace(digest(head), &key(k))
        .expect("namespace read must not fail")
}

pub fn unknown_heads_are_absent<S: Storage>(store: S) {
    assert!(!store.contains_version(digest(9)).expect("contains_version"));
}

pub fn install_creates_a_version<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("a", leaf("1")), ("b", leaf("2"))]))
        .expect("install");

    assert!(store.contains_version(digest(1)).expect("contains_version"));
    assert_eq!(fetch(&store, 1, "a"), Some(leaf("1")));
    assert_eq!(fetch(&store, 1, "missing"), None);

    let all: Vec<_> = store
        .namespaces(digest(1))
        .collect::<Result<_, _>>()
        .expect("namespaces");
    assert_eq!(all, vec![(key("a"), leaf("1")), (key("b"), leaf("2"))]);
}

pub fn install_keeps_other_chains<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("a", leaf("1"))]))
        .expect("install");
    store
        .install(digest(2), namespaces([("b", leaf("2"))]))
        .expect("install");

    assert_eq!(
        fetch(&store, 1, "a"),
        Some(leaf("1")),
        "an install must not wipe other versions"
    );
    assert_eq!(fetch(&store, 1, "b"), None);
    assert_eq!(fetch(&store, 2, "b"), Some(leaf("2")));
    assert_eq!(fetch(&store, 2, "a"), None);
}

pub fn commit_keeps_the_parent_intact<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("a", leaf("1"))]))
        .expect("install");
    store
        .commit(digest(1), digest(2), NamespaceOp::Put(key("a"), leaf("9")))
        .expect("commit");

    assert_eq!(fetch(&store, 2, "a"), Some(leaf("9")));
    assert_eq!(
        fetch(&store, 1, "a"),
        Some(leaf("1")),
        "the parent version must not move"
    );
}

pub fn put_creates_and_overwrites<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("a", leaf("1"))]))
        .expect("install");
    store
        .commit(digest(1), digest(2), NamespaceOp::Put(key("b"), leaf("2")))
        .expect("commit");
    store
        .commit(digest(2), digest(3), NamespaceOp::Put(key("a"), leaf("9")))
        .expect("commit");

    assert_eq!(fetch(&store, 3, "a"), Some(leaf("9")));
    assert_eq!(fetch(&store, 3, "b"), Some(leaf("2")));
}

pub fn delete_removes_the_namespace<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("a", leaf("1")), ("b", leaf("2"))]))
        .expect("install");
    store
        .commit(digest(1), digest(2), NamespaceOp::Delete(key("a")))
        .expect("commit");

    assert_eq!(fetch(&store, 2, "a"), None);
    assert_eq!(
        fetch(&store, 2, "b"),
        Some(leaf("2")),
        "siblings must survive"
    );
    assert_eq!(
        fetch(&store, 1, "a"),
        Some(leaf("1")),
        "the parent still holds it"
    );
}

pub fn set_at_writes_and_creates_leaves<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("n", nested())]))
        .expect("install");

    // Overwrite an existing leaf, then create a fresh one under a map.
    store
        .commit(
            digest(1),
            digest(2),
            set_at(path([sub("a"), sub("b")]), Some(Value::String("2".into()))),
        )
        .expect("commit");
    store
        .commit(
            digest(2),
            digest(3),
            set_at(path([sub("a"), sub("new")]), Some(Value::Bool(true))),
        )
        .expect("commit");

    let expected = map([
        (
            "a",
            map([("b", Value::String("2".into())), ("new", Value::Bool(true))]),
        ),
        (
            "list",
            Value::Array(vec![Value::String("x".into()), Value::String("y".into())]),
        ),
    ]);
    assert_eq!(fetch(&store, 3, "n").expect("n exists").value, expected);
}

pub fn set_at_replaces_array_elements<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("n", nested())]))
        .expect("install");

    store
        .commit(
            digest(1),
            digest(2),
            set_at(
                path([sub("list"), Subkey::Index(1)]),
                Some(Value::String("z".into())),
            ),
        )
        .expect("commit");

    let expected = map([
        ("a", map([("b", Value::String("1".into()))])),
        (
            "list",
            Value::Array(vec![Value::String("x".into()), Value::String("z".into())]),
        ),
    ]);
    assert_eq!(fetch(&store, 2, "n").expect("n exists").value, expected);
}

pub fn set_at_clears_values<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("n", nested())]))
        .expect("install");

    // Clear a map entry, then remove an array element — later indices
    // shift down.
    store
        .commit(
            digest(1),
            digest(2),
            set_at(path([sub("a"), sub("b")]), None),
        )
        .expect("commit");
    store
        .commit(
            digest(2),
            digest(3),
            set_at(path([sub("list"), Subkey::Index(0)]), None),
        )
        .expect("commit");

    let expected = map([
        ("a", Value::Map(BTreeMap::new())),
        ("list", Value::Array(vec![Value::String("y".into())])),
    ]);
    assert_eq!(fetch(&store, 3, "n").expect("n exists").value, expected);
}

/// An `AmendAt` against the `n` namespace the nested fixtures install.
fn amend_at(p: SubkeyPath, op: AmendOp) -> NamespaceOp {
    NamespaceOp::AmendAt {
        key: key("n"),
        path: Some(p),
        op,
    }
}

/// An `AmendAt` of a namespace's whole value.
fn amend_root(k: &'static str, op: AmendOp) -> NamespaceOp {
    NamespaceOp::AmendAt {
        key: key(k),
        path: None,
        op,
    }
}

pub fn amend_at_appends_and_creates_arrays<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("n", nested())]))
        .expect("install");

    // Append to the array that's there, then create a fresh one-entry
    // array under the map.
    store
        .commit(
            digest(1),
            digest(2),
            amend_at(
                path([sub("list")]),
                AmendOp::AppendEntry(Value::String("z".into())),
            ),
        )
        .expect("commit");
    store
        .commit(
            digest(2),
            digest(3),
            amend_at(
                path([sub("a"), sub("fresh")]),
                AmendOp::AppendEntry(Value::Int(1)),
            ),
        )
        .expect("commit");

    let expected = map([
        (
            "a",
            map([
                ("b", Value::String("1".into())),
                ("fresh", Value::Array(vec![Value::Int(1)])),
            ]),
        ),
        (
            "list",
            Value::Array(vec![
                Value::String("x".into()),
                Value::String("y".into()),
                Value::String("z".into()),
            ]),
        ),
    ]);
    assert_eq!(fetch(&store, 3, "n").expect("n exists").value, expected);
    assert_eq!(
        fetch(&store, 1, "n"),
        Some(nested()),
        "the parent version must not move"
    );
}

pub fn amend_at_increments_integers<S: Storage>(mut store: S) {
    store
        .install(
            digest(1),
            namespaces([(
                "n",
                Namespace {
                    value: map([("count", Value::Int(5))]),
                },
            )]),
        )
        .expect("install");

    let at_count = || path([sub("count")]);
    store
        .commit(
            digest(1),
            digest(2),
            amend_at(
                at_count(),
                AmendOp::IncrementDecrement(IncrementDecrement::new(3)),
            ),
        )
        .expect("commit");
    store
        .commit(
            digest(2),
            digest(3),
            amend_at(
                at_count(),
                AmendOp::IncrementDecrement(IncrementDecrement::new(-10)),
            ),
        )
        .expect("commit");
    // Clamped on both sides: the ceiling catches this sum...
    store
        .commit(
            digest(3),
            digest(4),
            amend_at(
                at_count(),
                AmendOp::IncrementDecrement(IncrementDecrement::new(100).with_min(0).with_max(10)),
            ),
        )
        .expect("commit");
    // ...the floor catches the next, even when the sum leaves i64.
    store
        .commit(
            digest(4),
            digest(5),
            amend_at(
                at_count(),
                AmendOp::IncrementDecrement(IncrementDecrement::new(i64::MIN).with_min(-1)),
            ),
        )
        .expect("commit");

    let count_of = |head: u8| match fetch(&store, head, "n").expect("n exists").value {
        Value::Map(top) => top.get("count").cloned(),
        _ => None,
    };
    assert_eq!(count_of(1), Some(Value::Int(5)), "parent must not move");
    assert_eq!(count_of(2), Some(Value::Int(8)));
    assert_eq!(count_of(3), Some(Value::Int(-2)));
    assert_eq!(count_of(4), Some(Value::Int(10)));
    assert_eq!(count_of(5), Some(Value::Int(-1)));
}

fn predicate(matches: impl IntoIterator<Item = Match>) -> Predicate {
    Predicate::try_new(matches.into_iter().collect()).expect("suite predicates are non-empty")
}

/// A delete-matching drops the entries its predicate matches — from an
/// array with later indices shifted down, from a map, or from the
/// namespace's root container with no path — and nothing when none match.
pub fn amend_at_deletes_matching_entries<S: Storage>(mut store: S) {
    let server =
        |id: &str, up: bool| map([("id", Value::String(id.into())), ("up", Value::Bool(up))]);
    store
        .install(
            digest(1),
            namespaces([(
                "n",
                Namespace {
                    value: map([
                        (
                            "servers",
                            Value::Array(vec![
                                server("a", true),
                                server("b", false),
                                server("c", false),
                            ]),
                        ),
                        (
                            "flags",
                            map([("x", Value::Bool(true)), ("y", Value::Bool(false))]),
                        ),
                    ]),
                },
            )]),
        )
        .expect("install");
    let id_is = |id: &str| Match::at(path([sub("id")]), Value::String(id.into()));

    // Two conditions, one entry meets both.
    store
        .commit(
            digest(1),
            digest(2),
            amend_at(
                path([sub("servers")]),
                AmendOp::DeleteMatching(predicate([
                    id_is("b"),
                    Match::at(path([sub("up")]), Value::Bool(false)),
                ])),
            ),
        )
        .expect("commit");
    // Nothing matches: a new version that is the same.
    store
        .commit(
            digest(2),
            digest(3),
            amend_at(
                path([sub("servers")]),
                AmendOp::DeleteMatching(predicate([id_is("zzz")])),
            ),
        )
        .expect("commit");
    // A map's entries are judged by value too.
    store
        .commit(
            digest(3),
            digest(4),
            amend_at(
                path([sub("flags")]),
                AmendOp::DeleteMatching(predicate([Match::entry(Value::Bool(false))])),
            ),
        )
        .expect("commit");
    // No path: the root map's entries.
    store
        .commit(
            digest(4),
            digest(5),
            amend_root(
                "n",
                AmendOp::DeleteMatching(predicate([Match::entry(map([("x", Value::Bool(true))]))])),
            ),
        )
        .expect("commit");

    let after_first = map([
        (
            "servers",
            Value::Array(vec![server("a", true), server("c", false)]),
        ),
        (
            "flags",
            map([("x", Value::Bool(true)), ("y", Value::Bool(false))]),
        ),
    ]);
    assert_eq!(fetch(&store, 2, "n").expect("n exists").value, after_first);
    assert_eq!(fetch(&store, 3, "n").expect("n exists").value, after_first);
    assert_eq!(
        fetch(&store, 4, "n").expect("n exists").value,
        map([
            (
                "servers",
                Value::Array(vec![server("a", true), server("c", false)]),
            ),
            ("flags", map([("x", Value::Bool(true))])),
        ])
    );
    assert_eq!(
        fetch(&store, 5, "n").expect("n exists").value,
        map([(
            "servers",
            Value::Array(vec![server("a", true), server("c", false)]),
        )])
    );
    assert_eq!(
        fetch(&store, 1, "n").expect("n exists").value,
        map([
            (
                "servers",
                Value::Array(vec![
                    server("a", true),
                    server("b", false),
                    server("c", false),
                ]),
            ),
            (
                "flags",
                map([("x", Value::Bool(true)), ("y", Value::Bool(false))]),
            ),
        ]),
        "the parent version must not move"
    );
}

/// A `path` of `None` amends the namespace's value itself — a namespace
/// that is one bare array or one bare integer.
pub fn amend_at_without_a_path_amends_the_root<S: Storage>(mut store: S) {
    store
        .install(
            digest(1),
            namespaces([
                (
                    "tags",
                    Namespace {
                        value: Value::Array(vec![Value::String("x".into())]),
                    },
                ),
                (
                    "total",
                    Namespace {
                        value: Value::Int(5),
                    },
                ),
            ]),
        )
        .expect("install");

    store
        .commit(
            digest(1),
            digest(2),
            amend_root("tags", AmendOp::AppendEntry(Value::String("y".into()))),
        )
        .expect("commit");
    store
        .commit(
            digest(2),
            digest(3),
            amend_root(
                "total",
                AmendOp::IncrementDecrement(IncrementDecrement::new(-100).with_min(0)),
            ),
        )
        .expect("commit");

    assert_eq!(
        fetch(&store, 3, "tags").expect("tags exists").value,
        Value::Array(vec![Value::String("x".into()), Value::String("y".into())])
    );
    assert_eq!(
        fetch(&store, 3, "total").expect("total exists").value,
        Value::Int(0)
    );
    assert_eq!(
        fetch(&store, 1, "total").expect("total exists").value,
        Value::Int(5),
        "the parent version must not move"
    );
}

pub fn value_at_reads_the_addressed_value<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("n", nested())]))
        .expect("install");

    let value_at = |p: &[Subkey]| store.value_at(digest(1), &key("n"), p).expect("value_at");

    assert_eq!(value_at(&[]), Some(nested().value));
    assert_eq!(
        value_at(&[sub("a"), sub("b")]),
        Some(Value::String("1".into()))
    );
    assert_eq!(
        value_at(&[sub("list"), Subkey::Index(1)]),
        Some(Value::String("y".into()))
    );

    // A path that stops short — absent, out of bounds, or the wrong
    // shape — is `None`, like the namespace that isn't there at all.
    assert_eq!(value_at(&[sub("nope")]), None);
    assert_eq!(value_at(&[sub("list"), Subkey::Index(9)]), None);
    assert_eq!(value_at(&[sub("a"), Subkey::Index(0)]), None);
    assert_eq!(
        store
            .value_at(digest(1), &key("absent"), &[])
            .expect("value_at"),
        None
    );
}

/// Two siblings write through the same shared parent; each must see only
/// its own write, and the parent neither. Catches copy-on-write slips
/// where structural sharing lets a write leak across versions.
pub fn meta_at_counts_and_names_entries<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("n", nested())]))
        .expect("install");

    let meta = |p: &[Subkey]| store.meta_at(digest(1), &key("n"), p).expect("meta_at");

    assert_eq!(
        meta(&[]),
        Some(ValueMeta::Map {
            keys: vec!["a".to_string(), "list".to_string()],
        })
    );
    assert_eq!(meta(&[sub("list")]), Some(ValueMeta::Array { len: 2 }));
    assert_eq!(meta(&[sub("a"), sub("b")]), Some(ValueMeta::Leaf));
    // Nothing there, and nowhere to walk: both are absent, not empty.
    assert_eq!(meta(&[sub("missing")]), None);
    assert_eq!(meta(&[sub("a"), sub("b"), sub("c")]), None);
    assert_eq!(
        store
            .meta_at(digest(1), &key("missing"), &[])
            .expect("meta_at"),
        None
    );
}

pub fn set_at_does_not_bleed_into_other_versions<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("n", nested())]))
        .expect("install");

    let at_b = || path([sub("a"), sub("b")]);
    store
        .commit(
            digest(1),
            digest(2),
            set_at(at_b(), Some(Value::String("2".into()))),
        )
        .expect("commit");
    store
        .commit(
            digest(1),
            digest(3),
            set_at(at_b(), Some(Value::String("3".into()))),
        )
        .expect("commit");

    let b_of = |head: u8| match fetch(&store, head, "n").expect("n exists").value {
        Value::Map(top) => match top.get("a") {
            Some(Value::Map(a)) => a.get("b").cloned(),
            _ => None,
        },
        _ => None,
    };
    assert_eq!(
        b_of(1),
        Some(Value::String("1".into())),
        "parent must not move"
    );
    assert_eq!(b_of(2), Some(Value::String("2".into())));
    assert_eq!(b_of(3), Some(Value::String("3".into())));
}

/// Reads are snapshots, not handles: everything read at a head must read
/// back identically after later commits touch the same keys and paths.
/// Returned values are owned and cannot change in the caller's hands —
/// what this pins is the store itself, where structural sharing or a
/// path-indexed `resolve` override could serve a newer version's write
/// through an old head.
pub fn reads_at_a_head_are_stable_across_updates<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("a", leaf("1")), ("n", nested())]))
        .expect("install");

    let before_n = fetch(&store, 1, "n").expect("n exists");
    let before_all: Vec<_> = store
        .namespaces(digest(1))
        .collect::<Result<_, _>>()
        .expect("namespaces");
    let at_b = || [sub("a"), sub("b")];
    let before_resolved = store
        .resolve(digest(1), &key("n"), &at_b())
        .expect("resolve");

    // Touch everything the snapshot read: a nested write, a wholesale
    // overwrite, and a delete of the sibling.
    store
        .commit(
            digest(1),
            digest(2),
            set_at(path(at_b()), Some(Value::String("9".into()))),
        )
        .expect("commit");
    store
        .commit(digest(2), digest(3), NamespaceOp::Put(key("n"), leaf("x")))
        .expect("commit");
    store
        .commit(digest(3), digest(4), NamespaceOp::Delete(key("a")))
        .expect("commit");

    assert_eq!(fetch(&store, 1, "n"), Some(before_n));
    assert_eq!(fetch(&store, 1, "a"), Some(leaf("1")));
    assert_eq!(
        store
            .namespaces(digest(1))
            .collect::<Result<Vec<_>, _>>()
            .expect("namespaces"),
        before_all
    );
    assert_eq!(
        store
            .resolve(digest(1), &key("n"), &at_b())
            .expect("resolve"),
        before_resolved,
        "resolve must walk the addressed version, not the newest"
    );
}

pub fn forks_diverge_independently<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("a", leaf("1"))]))
        .expect("install");
    store
        .commit(digest(1), digest(2), NamespaceOp::Put(key("b"), leaf("2")))
        .expect("commit");
    store
        .commit(digest(1), digest(3), NamespaceOp::Put(key("c"), leaf("3")))
        .expect("commit");

    assert_eq!(fetch(&store, 2, "a"), Some(leaf("1")));
    assert_eq!(fetch(&store, 2, "b"), Some(leaf("2")));
    assert_eq!(fetch(&store, 2, "c"), None);

    assert_eq!(fetch(&store, 3, "a"), Some(leaf("1")));
    assert_eq!(fetch(&store, 3, "b"), None);
    assert_eq!(fetch(&store, 3, "c"), Some(leaf("3")));

    assert_eq!(fetch(&store, 1, "b"), None);
    assert_eq!(fetch(&store, 1, "c"), None);
}

pub fn resolve_reports_the_walk<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("n", nested())]))
        .expect("install");

    let resolve = |p: &[Subkey]| {
        store
            .resolve(digest(1), &key("n"), p)
            .expect("resolve")
            .expect("namespace exists")
    };

    // Everything that exists, by kind.
    assert_eq!(resolve(&[]), Resolution::Node(NodeKind::Map));
    assert_eq!(resolve(&[sub("a")]), Resolution::Node(NodeKind::Map));
    assert_eq!(
        resolve(&[sub("a"), sub("b")]),
        Resolution::Node(NodeKind::Leaf)
    );
    assert_eq!(resolve(&[sub("list")]), Resolution::Node(NodeKind::Array));
    assert_eq!(
        resolve(&[sub("list"), Subkey::Index(1)]),
        Resolution::Node(NodeKind::Leaf)
    );

    // Absences report where the walk stopped, and in what.
    assert_eq!(
        resolve(&[sub("nope")]),
        Resolution::Missing {
            depth: 0,
            at: NodeKind::Map
        }
    );
    assert_eq!(
        resolve(&[sub("nope"), sub("deeper")]),
        Resolution::Missing {
            depth: 0,
            at: NodeKind::Map
        },
        "the walk stops at the first absent segment"
    );
    assert_eq!(
        resolve(&[sub("a"), sub("nope")]),
        Resolution::Missing {
            depth: 1,
            at: NodeKind::Map
        }
    );
    assert_eq!(
        resolve(&[sub("list"), Subkey::Index(9)]),
        Resolution::Missing {
            depth: 1,
            at: NodeKind::Array
        }
    );

    // Shape disagreements are mismatches, not absences.
    assert_eq!(
        resolve(&[sub("a"), Subkey::Index(0)]),
        Resolution::Mismatch { depth: 1 },
        "an index into a map"
    );
    assert_eq!(
        resolve(&[sub("list"), sub("x")]),
        Resolution::Mismatch { depth: 1 },
        "a key into an array"
    );
    assert_eq!(
        resolve(&[sub("a"), sub("b"), sub("deeper")]),
        Resolution::Mismatch { depth: 2 },
        "a step through a leaf"
    );

    // No namespace at all is `None`, not a `Resolution`.
    assert_eq!(
        store
            .resolve(digest(1), &key("absent"), &[])
            .expect("resolve"),
        None
    );
}

/// The key listing names every namespace of the version, in key order,
/// and no namespace of any other version.
pub fn namespace_keys_name_the_versions_namespaces<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("b", leaf("2")), ("a", nested())]))
        .expect("install");
    store
        .install(digest(2), namespaces([("c", leaf("3"))]))
        .expect("install");

    assert_eq!(keys_at(&store, 1), vec![key("a"), key("b")]);
    assert_eq!(keys_at(&store, 2), vec![key("c")]);

    store
        .commit(digest(2), digest(3), NamespaceOp::Delete(key("c")))
        .expect("commit");
    assert_eq!(keys_at(&store, 3), Vec::<NamespaceKey>::new());
    assert_eq!(
        keys_at(&store, 2),
        vec![key("c")],
        "the parent version must not move"
    );
}

fn keys_at<S: Storage>(store: &S, head: u8) -> Vec<NamespaceKey> {
    store
        .namespace_keys(digest(head))
        .collect::<Result<_, _>>()
        .expect("namespace_keys")
}

/// A namespace read back re-encodes to the exact bytes it went in as.
/// Digests are computed over canonical CBOR, so a backend that decomposes
/// the tree must reassemble it losslessly.
pub fn namespaces_reencode_to_identical_bytes<S: Storage>(mut store: S) {
    let before = wire::encode(&nested()).expect("encode");

    store
        .install(digest(1), namespaces([("n", nested())]))
        .expect("install");

    let after = fetch(&store, 1, "n").expect("n exists");
    assert_eq!(wire::encode(&after).expect("encode"), before);
}

/// An envelope chaining onto `prev`, distinguished by its value.
fn envelope(prev: EnvelopeDigest, v: &str) -> Envelope {
    Envelope::new(Msg::SetNamespace(SetNamespace {
        prev,
        key: key("a"),
        namespace: leaf(v),
    }))
}

fn digest_of(envelope: &Envelope) -> EnvelopeDigest {
    envelope.digest().expect("suite envelopes encode")
}

fn put<S: Storage>(store: &mut S, envelope: &Envelope) -> EnvelopeDigest {
    let digest = digest_of(envelope);
    store
        .put_envelope(digest, envelope.clone())
        .expect("put_envelope");
    digest
}

fn children_of<S: Storage>(store: &S, parent: EnvelopeDigest) -> Vec<EnvelopeDigest> {
    store
        .children(parent)
        .collect::<Result<_, _>>()
        .expect("children")
}

pub fn envelopes_store_and_read_back<S: Storage>(mut store: S) {
    let stored = envelope(digest(1), "1");
    let d = digest_of(&stored);

    assert_eq!(store.envelope(d).expect("envelope"), None);
    put(&mut store, &stored);
    assert_eq!(store.envelope(d).expect("envelope"), Some(stored.clone()));

    // The log is content-addressed: re-storing changes nothing, and the
    // parent doesn't grow a second child.
    put(&mut store, &stored);
    assert_eq!(store.envelope(d).expect("envelope"), Some(stored));
    assert_eq!(children_of(&store, digest(1)), vec![d]);
}

/// A stored envelope is stamped with when the log took it, and the plain
/// `envelope` read is the same envelope the stamped one carries.
pub fn envelopes_record_when_they_were_stored<S: Storage>(mut store: S) {
    let stored = envelope(digest(1), "1");
    let d = digest_of(&stored);

    let before = StoredAt::now();
    put(&mut store, &stored);
    let after = StoredAt::now();

    let entry = store
        .logged_envelope(d)
        .expect("logged_envelope")
        .expect("stored");
    let at = entry.stored_at;

    assert!(
        before <= at && at <= after,
        "{at} is outside {before}..{after}"
    );
    assert_eq!(entry.envelope, stored);
    // The two reads are the same envelope, whichever a caller reaches for.
    assert_eq!(store.envelope(d).expect("envelope"), Some(stored));

    // Nothing is stamped until something is stored.
    assert_eq!(
        store.logged_envelope(digest(9)).expect("logged_envelope"),
        None,
    );
}

/// Verification lands after an envelope did, and re-storing it is how the
/// status is upgraded. The stamp says when this node first saw the
/// envelope, so that upgrade must not make it look newer than it is.
pub fn re_storing_keeps_the_time_first_seen<S: Storage>(mut store: S) {
    let stored = envelope(digest(1), "1");
    let d = digest_of(&stored);
    put(&mut store, &stored);

    let first = store
        .logged_envelope(d)
        .expect("logged_envelope")
        .expect("stored")
        .stored_at;

    // Long enough that a clock reading a millisecond at a time has moved.
    std::thread::sleep(std::time::Duration::from_millis(5));

    let mut verified = stored.clone();
    verified.set_verification_status(VerificationStatus::AllMatched { total_weight: 3 });
    put(&mut store, &verified);

    let entry = store
        .logged_envelope(d)
        .expect("logged_envelope")
        .expect("stored");
    assert_eq!(entry.stored_at, first, "the stamp was rewritten");
    assert_eq!(
        entry.envelope.verification_status(),
        &VerificationStatus::AllMatched { total_weight: 3 },
        "the rest of the record must still be replaced",
    );

    // An envelope genuinely stored later is stamped later, which is what
    // makes the assertion above mean anything.
    let later = put(&mut store, &envelope(digest(1), "2"));
    let later = store
        .logged_envelope(later)
        .expect("logged_envelope")
        .expect("stored")
        .stored_at;
    assert!(first < later, "{first} should precede {later}");
}

/// The verification status rides outside the envelope's canonical CBOR:
/// a backend keeping envelopes as encoded bytes must persist the status
/// beside them, or fork resolution forgets every verification on restart.
pub fn envelopes_round_trip_the_verification_status<S: Storage>(mut store: S) {
    let unverified = envelope(digest(1), "1");
    let mut verified = unverified.clone();
    verified.set_verification_status(VerificationStatus::AllMatched { total_weight: 7 });
    assert_eq!(
        digest_of(&verified),
        digest_of(&unverified),
        "the status must not change the digest"
    );

    let d = put(&mut store, &verified);
    assert_eq!(
        store.envelope(d).expect("envelope").expect("stored"),
        verified,
        "the status is not in the encoding and must be stored beside it"
    );

    // A failed status names the keys that failed, and a backend that
    // dropped them would hand back a forged envelope as one that merely
    // failed for reasons nobody recorded.
    let mut failed = unverified.clone();
    failed.set_verification_status(VerificationStatus::Failed {
        failing_key_ids: [KeyId::from_bytes([7u8; 32]), KeyId::from_bytes([9u8; 32])].into(),
    });
    put(&mut store, &failed);
    assert_eq!(
        store.envelope(d).expect("envelope").expect("stored"),
        failed,
        "the keys a failed status names must be stored beside it"
    );

    // Verification usually lands after the envelope did: re-storing under
    // the same digest replaces the record, status included.
    put(&mut store, &unverified);
    assert_eq!(
        store.envelope(d).expect("envelope").expect("stored"),
        unverified
    );
}

pub fn children_come_back_in_digest_order<S: Storage>(mut store: S) {
    let siblings: Vec<_> = ["1", "2", "3", "4"]
        .iter()
        .map(|v| put(&mut store, &envelope(digest(1), v)))
        .collect();
    let elsewhere = put(&mut store, &envelope(digest(2), "1"));

    let expected = siblings
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        children_of(&store, digest(1)),
        expected.into_iter().collect::<Vec<_>>(),
        "siblings must come back ascending — the fork rule reads them in order"
    );

    assert_eq!(children_of(&store, digest(2)), vec![elsewhere]);
    assert_eq!(children_of(&store, digest(9)), Vec::new());
}

pub fn remove_envelope_unstores_and_unindexes<S: Storage>(mut store: S) {
    let kept_envelope = envelope(digest(1), "1");
    let kept = put(&mut store, &kept_envelope);
    let removed = put(&mut store, &envelope(digest(1), "2"));

    store.remove_envelope(removed).expect("remove");

    assert_eq!(store.envelope(removed).expect("envelope"), None);
    assert_eq!(
        store.envelope(kept).expect("envelope"),
        Some(kept_envelope),
        "siblings must survive"
    );
    assert_eq!(children_of(&store, digest(1)), vec![kept]);

    // Removing what isn't stored is a no-op.
    store.remove_envelope(digest(9)).expect("remove");
    assert_eq!(children_of(&store, digest(1)), vec![kept]);
}

/// `parent` answers what the stored envelope's own `prev` says — the hop
/// chain walks take without materializing envelopes — and `None` for
/// both an absent envelope and one with no parent.
pub fn parent_follows_prev<S: Storage>(mut store: S) {
    let first = envelope(digest(1), "1");
    let second = envelope(digest_of(&first), "2");
    put(&mut store, &first);
    put(&mut store, &second);

    assert_eq!(
        store.parent(digest_of(&second)).expect("parent"),
        Some(digest_of(&first))
    );
    assert_eq!(
        store.parent(digest_of(&first)).expect("parent"),
        Some(digest(1))
    );
    assert_eq!(store.parent(digest(9)).expect("parent"), None, "not stored");

    // An `Init` has no parent: stored, but the walk ends on it.
    let root = Envelope::new(Msg::Init(wire::msg::InitMsg {
        state: wire::msg::FullCheckpoint::default(),
    }));
    put(&mut store, &root);
    assert_eq!(store.parent(digest_of(&root)).expect("parent"), None);

    // Removal takes the answer with it.
    store.remove_envelope(digest_of(&second)).expect("remove");
    assert_eq!(store.parent(digest_of(&second)).expect("parent"), None);
}

/// Versions are what the log folds down to; pruning them must not touch
/// the log itself.
pub fn retain_leaves_the_envelope_log_alone<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("a", leaf("1"))]))
        .expect("install");
    let stored = envelope(digest(1), "2");
    let d = put(&mut store, &stored);

    store.retain(&[]).expect("retain");

    assert!(!store.contains_version(digest(1)).expect("contains_version"));
    assert_eq!(store.envelope(d).expect("envelope"), Some(stored));
    assert_eq!(children_of(&store, digest(1)), vec![d]);
}

pub fn retain_prunes_unkept_versions<S: Storage>(mut store: S) {
    store
        .install(digest(1), namespaces([("n", nested())]))
        .expect("install");
    store
        .commit(
            digest(1),
            digest(2),
            set_at(path([sub("a"), sub("b")]), Some(Value::String("2".into()))),
        )
        .expect("commit");

    store.retain(&[digest(2)]).expect("retain");

    assert!(!store.contains_version(digest(1)).expect("contains_version"));
    assert!(store.contains_version(digest(2)).expect("contains_version"));

    // The untouched subtree was shared with the pruned parent; pruning
    // must not tear it out from under the survivor.
    let expected = map([
        ("a", map([("b", Value::String("2".into()))])),
        (
            "list",
            Value::Array(vec![Value::String("x".into()), Value::String("y".into())]),
        ),
    ]);
    assert_eq!(fetch(&store, 2, "n").expect("n exists").value, expected);
}
