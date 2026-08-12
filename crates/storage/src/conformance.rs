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
    EnvelopeDigest,
    msg::{FullCheckpoint, Namespace, NamespaceKey, Value},
    subkey::{Subkey, SubkeyPath},
};

use crate::{NamespaceOp, NodeKind, Resolution, Storage};

/// Instantiates the conformance suite as `#[test]` functions.
#[macro_export]
macro_rules! storage_conformance {
    ($make:expr) => {
        #[test]
        fn conformance_unknown_heads_have_no_config() {
            $crate::conformance::unknown_heads_have_no_config($make);
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
        fn conformance_set_at_does_not_bleed_into_other_versions() {
            $crate::conformance::set_at_does_not_bleed_into_other_versions($make);
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
        fn conformance_namespaces_reencode_to_identical_bytes() {
            $crate::conformance::namespaces_reencode_to_identical_bytes($make);
        }
        #[test]
        fn conformance_retain_prunes_unkept_versions() {
            $crate::conformance::retain_prunes_unkept_versions($make);
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

fn checkpoint(entries: impl IntoIterator<Item = (&'static str, Namespace)>) -> FullCheckpoint {
    FullCheckpoint {
        namespaces: entries.into_iter().map(|(k, ns)| (key(k), ns)).collect(),
        ..Default::default()
    }
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

pub fn unknown_heads_have_no_config<S: Storage>(store: S) {
    assert_eq!(store.config(digest(9)).expect("config"), None);
}

pub fn install_creates_a_version<S: Storage>(mut store: S) {
    let checkpoint = checkpoint([("a", leaf("1")), ("b", leaf("2"))]);
    store
        .install(digest(1), checkpoint.clone())
        .expect("install");

    assert_eq!(
        store.config(digest(1)).expect("config"),
        Some(checkpoint.config)
    );
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
        .install(digest(1), checkpoint([("a", leaf("1"))]))
        .expect("install");
    store
        .install(digest(2), checkpoint([("b", leaf("2"))]))
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
        .install(digest(1), checkpoint([("a", leaf("1"))]))
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
        .install(digest(1), checkpoint([("a", leaf("1"))]))
        .expect("install");
    store
        .commit(digest(1), digest(2), NamespaceOp::Put(key("b"), leaf("2")))
        .expect("commit");
    store
        .commit(digest(2), digest(3), NamespaceOp::Put(key("a"), leaf("9")))
        .expect("commit");

    assert_eq!(fetch(&store, 3, "a"), Some(leaf("9")));
    assert_eq!(fetch(&store, 3, "b"), Some(leaf("2")));
    assert_eq!(
        store.config(digest(3)).expect("config"),
        store.config(digest(1)).expect("config"),
        "config rides along the chain"
    );
}

pub fn delete_removes_the_namespace<S: Storage>(mut store: S) {
    store
        .install(digest(1), checkpoint([("a", leaf("1")), ("b", leaf("2"))]))
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
        .install(digest(1), checkpoint([("n", nested())]))
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
        .install(digest(1), checkpoint([("n", nested())]))
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
        .install(digest(1), checkpoint([("n", nested())]))
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

/// Two siblings write through the same shared parent; each must see only
/// its own write, and the parent neither. Catches copy-on-write slips
/// where structural sharing lets a write leak across versions.
pub fn set_at_does_not_bleed_into_other_versions<S: Storage>(mut store: S) {
    store
        .install(digest(1), checkpoint([("n", nested())]))
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

pub fn forks_diverge_independently<S: Storage>(mut store: S) {
    store
        .install(digest(1), checkpoint([("a", leaf("1"))]))
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
        .install(digest(1), checkpoint([("n", nested())]))
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

/// A namespace read back re-encodes to the exact bytes it went in as.
/// Digests are computed over canonical CBOR, so a backend that decomposes
/// the tree must reassemble it losslessly.
pub fn namespaces_reencode_to_identical_bytes<S: Storage>(mut store: S) {
    let before = wire::encode(&nested()).expect("encode");

    store
        .install(digest(1), checkpoint([("n", nested())]))
        .expect("install");

    let after = fetch(&store, 1, "n").expect("n exists");
    assert_eq!(wire::encode(&after).expect("encode"), before);
}

pub fn retain_prunes_unkept_versions<S: Storage>(mut store: S) {
    store
        .install(digest(1), checkpoint([("n", nested())]))
        .expect("install");
    store
        .commit(
            digest(1),
            digest(2),
            set_at(path([sub("a"), sub("b")]), Some(Value::String("2".into()))),
        )
        .expect("commit");

    store.retain(&[digest(2)]).expect("retain");

    assert_eq!(store.config(digest(1)).expect("config"), None);
    assert!(store.config(digest(2)).expect("config").is_some());

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
