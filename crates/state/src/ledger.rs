//! The state a chain of envelopes folds down to.

use wire::{
    Envelope, EnvelopeDigest, Msg,
    msg::{FullCheckpoint, LedgerConfig, Namespace, NamespaceKey, SetNamespaceKey, Value},
    subkey::{Subkey, SubkeyPath},
};

use crate::{ApplyError, Error};

/// The ledger, as of some position in the chain.
///
/// Opened from the `Init` envelope that starts a chain and advanced by
/// [`apply`](Ledger::apply). A ledger always has a head, so there is no
/// such thing as one that has yet to see its first envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ledger {
    head: EnvelopeDigest,
    state: FullCheckpoint,
}

impl Ledger {
    /// Opens a ledger from the `Init` envelope that starts a chain.
    pub fn init(envelope: &Envelope) -> Result<Self, Error> {
        match envelope.payload() {
            Msg::Init(init) => Ok(Self {
                head: envelope.digest()?,
                state: init.state.clone(),
            }),
            _ => Err(Error::NotInit),
        }
    }

    /// Replays a whole chain, `Init` envelope first.
    pub fn replay<'a>(envelopes: impl IntoIterator<Item = &'a Envelope>) -> Result<Self, Error> {
        let mut envelopes = envelopes.into_iter();
        let ledger = envelopes
            .next()
            .ok_or(Error::EmptyChain)
            .and_then(Self::init)?;

        envelopes.try_fold(ledger, |mut ledger, envelope| {
            ledger.apply(envelope)?;
            Ok(ledger)
        })
    }

    /// Advances the ledger by one envelope.
    ///
    /// The envelope must chain onto the current [`head`](Ledger::head).
    /// State is left untouched when this returns an error, so a rejected
    /// envelope cannot half-apply.
    pub fn apply(&mut self, envelope: &Envelope) -> Result<(), ApplyError> {
        let msg = envelope.payload();
        let prev = msg.prev_digest().ok_or(ApplyError::UnexpectedInit)?;

        if prev != &self.head {
            return Err(ApplyError::ChainMismatch {
                expected: self.head,
                found: *prev,
            });
        }
        let head = envelope.digest()?;

        match msg {
            // Unreachable: Init is the only variant without a prev digest,
            // so the check above has already rejected it.
            Msg::Init(_) => return Err(ApplyError::UnexpectedInit),
            Msg::SetNamespace(set) => {
                self.state
                    .namespaces
                    .insert(set.key.clone(), set.namespace.clone());
            }
            Msg::SetNamespaceKey(set) => self.set_key(set)?,
            Msg::DeleteNamespace(del) => {
                self.state
                    .namespaces
                    .remove(&del.key)
                    .ok_or_else(|| ApplyError::UnknownNamespace(del.key.clone()))?;
            }
        }

        self.head = head;
        Ok(())
    }

    /// Writes or clears one value nested inside a namespace.
    ///
    /// Every step of the path must already exist — nothing is created along
    /// the way, so a typo'd path is refused rather than quietly building a
    /// second copy of the data beside the real one.
    fn set_key(&mut self, set: &SetNamespaceKey) -> Result<(), ApplyError> {
        let miss = |miss: Miss| miss.into_error(&set.key, &set.path);

        let root = &mut self
            .state
            .namespaces
            .get_mut(&set.key)
            .ok_or_else(|| ApplyError::UnknownNamespace(set.key.clone()))?
            .value;

        let (last, parents) = set
            .path
            .as_ref()
            .split_last()
            .expect("SubkeyPath is validated non-empty");

        let parent = walk_mut(root, parents).map_err(miss)?;

        match (parent, last, &set.value) {
            (Value::Map(map), Subkey::Key(key), Some(value)) => {
                map.insert(key.clone(), value.clone());
            }
            (Value::Map(map), Subkey::Key(key), None) => {
                map.remove(key).ok_or_else(|| miss(Miss::NotFound))?;
            }
            (Value::Array(array), Subkey::Index(index), Some(value)) => {
                *array
                    .get_mut(*index as usize)
                    .ok_or_else(|| miss(Miss::NotFound))? = value.clone();
            }
            (Value::Array(array), Subkey::Index(index), None) => {
                let index = *index as usize;
                if index >= array.len() {
                    return Err(miss(Miss::NotFound));
                }
                array.remove(index);
            }
            _ => return Err(miss(Miss::TypeMismatch)),
        }

        Ok(())
    }

    /// The digest of the most recently applied envelope.
    pub fn head(&self) -> EnvelopeDigest {
        self.head
    }

    /// The ledger's configuration.
    pub fn config(&self) -> &LedgerConfig {
        &self.state.config
    }

    /// The namespace filed under `key`, if the ledger holds one.
    pub fn namespace(&self, key: &str) -> Option<&Namespace> {
        self.state.namespaces.get(key)
    }

    /// Every namespace the ledger holds, in key order.
    pub fn namespaces(&self) -> impl Iterator<Item = (&NamespaceKey, &Namespace)> {
        self.state.namespaces.iter()
    }

    /// The ledger's state as a checkpoint, ready to open a rewritten chain.
    pub fn checkpoint(&self) -> &FullCheckpoint {
        &self.state
    }
}

/// Why a path stopped short. Carries no context of its own; the caller
/// pins the namespace and path onto it.
enum Miss {
    NotFound,
    TypeMismatch,
}

impl Miss {
    fn into_error(self, key: &NamespaceKey, path: &SubkeyPath) -> ApplyError {
        let (key, path) = (key.clone(), path.clone());
        match self {
            Miss::NotFound => ApplyError::UnknownPath { key, path },
            Miss::TypeMismatch => ApplyError::PathTypeMismatch { key, path },
        }
    }
}

/// Walks `path` from `root`, yielding the value it addresses.
fn walk_mut<'a>(root: &'a mut Value, path: &[Subkey]) -> Result<&'a mut Value, Miss> {
    path.iter().try_fold(root, |value, segment| {
        match (value, segment) {
            (Value::Map(map), Subkey::Key(key)) => map.get_mut(key),
            (Value::Array(array), Subkey::Index(index)) => array.get_mut(*index as usize),
            _ => return Err(Miss::TypeMismatch),
        }
        .ok_or(Miss::NotFound)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wire::msg::{DeleteNamespace, InitMsg, SetNamespace};

    fn key(k: &str) -> NamespaceKey {
        NamespaceKey::try_new(k).unwrap()
    }

    fn ns(v: &str) -> Namespace {
        Namespace {
            value: Value::String(v.to_string()),
        }
    }

    fn init() -> Envelope {
        Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint::default(),
        }))
    }

    fn set(prev: EnvelopeDigest, k: &str, v: &str) -> Envelope {
        Envelope::new(Msg::SetNamespace(SetNamespace {
            prev,
            key: key(k),
            namespace: ns(v),
        }))
    }

    fn delete(prev: EnvelopeDigest, k: &str) -> Envelope {
        Envelope::new(Msg::DeleteNamespace(DeleteNamespace { prev, key: key(k) }))
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
        SubkeyPath::try_new(segments.into_iter().collect()).unwrap()
    }

    fn sub(k: &str) -> Subkey {
        Subkey::Key(k.to_string())
    }

    /// A namespace whose value is `{"a": {"b": "1"}, "list": ["x", "y"]}`.
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

    /// A ledger holding [`nested`] under namespace `n`.
    fn nested_ledger() -> Ledger {
        let envelope = Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: [(key("n"), nested())].into_iter().collect(),
                ..Default::default()
            },
        }));
        Ledger::init(&envelope).unwrap()
    }

    fn set_key(prev: EnvelopeDigest, p: SubkeyPath, value: Option<Value>) -> Envelope {
        Envelope::new(Msg::SetNamespaceKey(SetNamespaceKey {
            prev,
            key: key("n"),
            path: p,
            value,
        }))
    }

    /// Reads back what a path addresses, for asserting on.
    fn at(ledger: &Ledger, p: &[Subkey]) -> Option<Value> {
        let mut root = ledger.namespace("n")?.value.clone();
        walk_mut(&mut root, p).ok().cloned()
    }

    #[test]
    fn init_opens_at_the_checkpoint() {
        let envelope = init();
        let ledger = Ledger::init(&envelope).unwrap();

        assert_eq!(ledger.head(), envelope.digest().unwrap());
        assert_eq!(ledger.namespaces().count(), 0);
        assert_eq!(ledger.config(), &LedgerConfig::default());
    }

    /// An `Init` carrying state opens the ledger already populated, which is
    /// what makes a compacted or rewritten chain resumable.
    #[test]
    fn init_carries_its_state_across() {
        let envelope = Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: [(key("a"), ns("1"))].into_iter().collect(),
                ..Default::default()
            },
        }));

        let ledger = Ledger::init(&envelope).unwrap();
        assert_eq!(ledger.namespace("a"), Some(&ns("1")));
    }

    #[test]
    fn init_rejects_a_non_init_envelope() {
        let envelope = set(EnvelopeDigest::from_bytes([0xab; 32]), "a", "1");
        assert!(matches!(Ledger::init(&envelope), Err(Error::NotInit)));
    }

    #[test]
    fn apply_sets_a_namespace_and_advances_the_head() {
        let init = init();
        let mut ledger = Ledger::init(&init).unwrap();

        let set = set(ledger.head(), "a", "1");
        ledger.apply(&set).unwrap();

        assert_eq!(ledger.namespace("a"), Some(&ns("1")));
        assert_eq!(ledger.head(), set.digest().unwrap());
        assert_ne!(ledger.head(), init.digest().unwrap());
    }

    #[test]
    fn set_overwrites_a_namespace_wholesale() {
        let init = init();
        let mut ledger = Ledger::init(&init).unwrap();

        let first = set(ledger.head(), "a", "1");
        ledger.apply(&first).unwrap();
        let second = set(ledger.head(), "a", "2");
        ledger.apply(&second).unwrap();

        assert_eq!(ledger.namespace("a"), Some(&ns("2")));
        assert_eq!(ledger.namespaces().count(), 1);
    }

    #[test]
    fn apply_deletes_a_namespace() {
        let init = init();
        let mut ledger = Ledger::init(&init).unwrap();

        let set = set(ledger.head(), "a", "1");
        ledger.apply(&set).unwrap();
        let delete = delete(ledger.head(), "a");
        ledger.apply(&delete).unwrap();

        assert_eq!(ledger.namespace("a"), None);
        assert_eq!(ledger.head(), delete.digest().unwrap());
    }

    /// The point of the chain: an envelope that doesn't point at the head is
    /// refused, so a gap or a fork can't be folded in unnoticed.
    #[test]
    fn apply_rejects_an_envelope_that_skips_the_head() {
        let init = init();
        let mut ledger = Ledger::init(&init).unwrap();
        let head = ledger.head();

        let orphan = set(EnvelopeDigest::from_bytes([0xab; 32]), "a", "1");
        let err = ledger.apply(&orphan).unwrap_err();

        assert!(matches!(
            err,
            ApplyError::ChainMismatch { expected, found }
                if expected == head && found == EnvelopeDigest::from_bytes([0xab; 32])
        ));
        assert_eq!(ledger.head(), head, "head must not move");
        assert_eq!(ledger.namespaces().count(), 0, "state must not change");
    }

    /// Replaying the same envelope twice fails the second time: its `prev`
    /// points at what is now the previous head, not the current one.
    #[test]
    fn apply_is_not_idempotent() {
        let init = init();
        let mut ledger = Ledger::init(&init).unwrap();

        let set = set(ledger.head(), "a", "1");
        ledger.apply(&set).unwrap();
        assert!(matches!(
            ledger.apply(&set),
            Err(ApplyError::ChainMismatch { .. })
        ));
    }

    #[test]
    fn apply_rejects_a_second_init() {
        let opening = init();
        let mut ledger = Ledger::init(&opening).unwrap();

        assert!(matches!(
            ledger.apply(&init()),
            Err(ApplyError::UnexpectedInit)
        ));
        assert_eq!(ledger.head(), opening.digest().unwrap());
    }

    /// Deleting what isn't there is a malformed message rather than a no-op:
    /// two nodes must never disagree about whether an envelope applied.
    #[test]
    fn delete_rejects_an_unknown_namespace() {
        let init = init();
        let mut ledger = Ledger::init(&init).unwrap();
        let head = ledger.head();

        let delete = delete(head, "nope");
        let err = ledger.apply(&delete).unwrap_err();

        assert!(matches!(err, ApplyError::UnknownNamespace(k) if k == key("nope")));
        assert_eq!(ledger.head(), head, "head must not move");
    }

    #[test]
    fn replay_folds_a_whole_chain() {
        let init = init();
        let a = set(init.digest().unwrap(), "a", "1");
        let b = set(a.digest().unwrap(), "b", "2");
        let delete_a = delete(b.digest().unwrap(), "a");
        let chain = [init, a, b, delete_a];

        let replayed = Ledger::replay(&chain).unwrap();

        assert_eq!(replayed.namespace("a"), None);
        assert_eq!(replayed.namespace("b"), Some(&ns("2")));
        assert_eq!(replayed.head(), chain.last().unwrap().digest().unwrap());

        // Same result as advancing one envelope at a time.
        let stepwise = chain.iter().skip(1).try_fold(
            Ledger::init(&chain[0]).unwrap(),
            |mut ledger, envelope| ledger.apply(envelope).map(|()| ledger),
        );
        assert_eq!(stepwise.unwrap(), replayed);
    }

    #[test]
    fn set_key_writes_a_nested_value() {
        let mut ledger = nested_ledger();
        let envelope = set_key(
            ledger.head(),
            path([sub("a"), sub("b")]),
            Some(Value::String("2".into())),
        );
        ledger.apply(&envelope).unwrap();

        assert_eq!(
            at(&ledger, &[sub("a"), sub("b")]),
            Some(Value::String("2".into()))
        );
        assert_eq!(ledger.head(), envelope.digest().unwrap());
    }

    /// Only the addressed value moves; its siblings are left alone. That's
    /// the whole point of the message over republishing the namespace.
    #[test]
    fn set_key_leaves_the_rest_of_the_namespace_alone() {
        let mut ledger = nested_ledger();
        let before = at(&ledger, &[sub("list")]);

        ledger
            .apply(&set_key(
                ledger.head(),
                path([sub("a"), sub("b")]),
                Some(Value::Int(9)),
            ))
            .unwrap();

        assert_eq!(at(&ledger, &[sub("list")]), before);
    }

    /// A key that isn't there yet is created, as long as its parent map is.
    #[test]
    fn set_key_adds_a_new_leaf_to_an_existing_map() {
        let mut ledger = nested_ledger();
        ledger
            .apply(&set_key(
                ledger.head(),
                path([sub("a"), sub("new")]),
                Some(Value::Bool(true)),
            ))
            .unwrap();

        assert_eq!(at(&ledger, &[sub("a"), sub("new")]), Some(Value::Bool(true)));
    }

    #[test]
    fn set_key_clears_a_value_when_given_none() {
        let mut ledger = nested_ledger();
        ledger
            .apply(&set_key(ledger.head(), path([sub("a"), sub("b")]), None))
            .unwrap();

        assert_eq!(at(&ledger, &[sub("a"), sub("b")]), None);
        assert_eq!(at(&ledger, &[sub("a")]), Some(map([])));
    }

    #[test]
    fn set_key_replaces_an_array_element_by_index() {
        let mut ledger = nested_ledger();
        ledger
            .apply(&set_key(
                ledger.head(),
                path([sub("list"), Subkey::Index(1)]),
                Some(Value::String("z".into())),
            ))
            .unwrap();

        assert_eq!(
            at(&ledger, &[sub("list")]),
            Some(Value::Array(vec![
                Value::String("x".into()),
                Value::String("z".into()),
            ]))
        );
    }

    /// Clearing an element shortens the array — later indices shift down.
    #[test]
    fn set_key_removes_an_array_element_when_given_none() {
        let mut ledger = nested_ledger();
        ledger
            .apply(&set_key(
                ledger.head(),
                path([sub("list"), Subkey::Index(0)]),
                None,
            ))
            .unwrap();

        assert_eq!(
            at(&ledger, &[sub("list")]),
            Some(Value::Array(vec![Value::String("y".into())]))
        );
    }

    /// Nothing is created along the way: an intermediate that doesn't exist
    /// is refused rather than conjured, so a typo can't build a shadow copy
    /// of the data next to the real one.
    #[test]
    fn set_key_refuses_to_create_intermediates() {
        let mut ledger = nested_ledger();
        let head = ledger.head();
        let before = ledger.namespace("n").cloned();

        let err = ledger
            .apply(&set_key(
                head,
                path([sub("nope"), sub("b")]),
                Some(Value::Int(1)),
            ))
            .unwrap_err();

        assert!(matches!(err, ApplyError::UnknownPath { key: k, path: p }
            if k == key("n") && p == path([sub("nope"), sub("b")])));
        assert_eq!(ledger.namespace("n").cloned(), before);
        assert_eq!(ledger.head(), head);
    }

    #[test]
    fn set_key_rejects_a_path_of_the_wrong_shape() {
        let mut ledger = nested_ledger();
        let head = ledger.head();

        // A key into an array.
        let err = ledger
            .apply(&set_key(
                head,
                path([sub("list"), sub("x")]),
                Some(Value::Int(1)),
            ))
            .unwrap_err();
        assert!(matches!(err, ApplyError::PathTypeMismatch { .. }));

        // An index into a map.
        let err = ledger
            .apply(&set_key(
                head,
                path([sub("a"), Subkey::Index(0)]),
                Some(Value::Int(1)),
            ))
            .unwrap_err();
        assert!(matches!(err, ApplyError::PathTypeMismatch { .. }));

        // A step through a leaf.
        let err = ledger
            .apply(&set_key(
                head,
                path([sub("a"), sub("b"), sub("deeper")]),
                Some(Value::Int(1)),
            ))
            .unwrap_err();
        assert!(matches!(err, ApplyError::PathTypeMismatch { .. }));
    }

    #[test]
    fn set_key_rejects_clearing_what_is_not_there() {
        let mut ledger = nested_ledger();
        let head = ledger.head();

        let err = ledger
            .apply(&set_key(head, path([sub("a"), sub("gone")]), None))
            .unwrap_err();
        assert!(matches!(err, ApplyError::UnknownPath { .. }));

        let err = ledger
            .apply(&set_key(head, path([sub("list"), Subkey::Index(9)]), None))
            .unwrap_err();
        assert!(matches!(err, ApplyError::UnknownPath { .. }));

        assert_eq!(ledger.head(), head, "head must not move");
    }

    #[test]
    fn set_key_rejects_an_unknown_namespace() {
        let mut ledger = nested_ledger();
        let envelope = Envelope::new(Msg::SetNamespaceKey(SetNamespaceKey {
            prev: ledger.head(),
            key: key("absent"),
            path: path([sub("a")]),
            value: Some(Value::Int(1)),
        }));

        assert!(matches!(
            ledger.apply(&envelope),
            Err(ApplyError::UnknownNamespace(k)) if k == key("absent")
        ));
    }

    /// `replay` speaks the crate error, but a mid-chain failure keeps the
    /// specific `ApplyError` underneath rather than flattening it.
    #[test]
    fn replay_wraps_apply_errors() {
        let init = init();
        let orphan = set(EnvelopeDigest::from_bytes([0xab; 32]), "a", "1");

        let err = Ledger::replay(&[init, orphan]).unwrap_err();
        assert!(matches!(
            err,
            Error::Apply(ApplyError::ChainMismatch { .. })
        ));

        // The chain is reachable through `source()`, not just the variant.
        let source = core::error::Error::source(&err).unwrap();
        assert!(source.downcast_ref::<ApplyError>().is_some());
    }

    #[test]
    fn replay_rejects_an_empty_chain() {
        assert!(matches!(Ledger::replay(&[]), Err(Error::EmptyChain)));
    }

    /// The checkpoint a ledger hands back reopens to exactly the same state
    /// — that's what lets a chain be compacted or rewritten.
    #[test]
    fn checkpoint_reopens_to_the_same_state() {
        let init = init();
        let mut ledger = Ledger::init(&init).unwrap();
        ledger.apply(&set(ledger.head(), "a", "1")).unwrap();

        let reopened = Envelope::new(Msg::Init(InitMsg {
            state: ledger.checkpoint().clone(),
        }));
        let reopened = Ledger::init(&reopened).unwrap();

        assert_eq!(reopened.checkpoint(), ledger.checkpoint());
        assert_ne!(reopened.head(), ledger.head(), "new chain, new head");
    }
}
