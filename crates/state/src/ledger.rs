//! The state a chain of envelopes folds down to.

use storage::{NamespaceOp, NodeKind, Resolution, Storage};
use wire::{
    Envelope, EnvelopeDigest, Msg,
    msg::{FullCheckpoint, LedgerConfig, Namespace, NamespaceKey, SetNamespaceKey},
    subkey::{Subkey, SubkeyPath},
};

use crate::{ApplyError, Error};

/// The ledger, as of some position in the chain.
///
/// A ledger is a cursor: the head it stands at and the config of its
/// chain. State lives in the [`Storage`] each operation is handed, where
/// it is addressed by head — so any number of ledgers can drive one store
/// at once, and cloning a ledger is how a chain forks in place. Applying
/// an envelope touches only what the envelope addresses, never the whole
/// state.
///
/// A ledger must only be used with the store it was opened from; a store
/// treats an unknown head as a broken invariant, not an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ledger {
    head: EnvelopeDigest,
    config: LedgerConfig,
}

impl Ledger {
    /// Opens a ledger from the `Init` envelope that starts a chain,
    /// installing its checkpoint in `storage`. Chains already in the
    /// store are left alone.
    pub fn init<S: Storage>(storage: &mut S, envelope: &Envelope) -> Result<Self, Error<S::Error>> {
        match envelope.payload() {
            Msg::Init(init) => {
                let head = envelope.digest()?;
                let config = init.state.config.clone();
                storage
                    .install(head, init.state.clone())
                    .map_err(Error::Storage)?;
                Ok(Self { head, config })
            }
            _ => Err(Error::NotInit),
        }
    }

    /// Reopens a ledger standing at `head`. Any version the store still
    /// holds works, so an old head opens a historical view — readable,
    /// and appendable as a fork.
    pub fn open<S: Storage>(storage: &S, head: EnvelopeDigest) -> Result<Self, Error<S::Error>> {
        storage
            .config(head)
            .map_err(Error::Storage)?
            .ok_or(Error::UnknownHead(head))
            .map(|config| Self { head, config })
    }

    /// Replays a whole chain into `storage`, `Init` envelope first.
    pub fn replay<'a, S: Storage>(
        storage: &mut S,
        envelopes: impl IntoIterator<Item = &'a Envelope>,
    ) -> Result<Self, Error<S::Error>> {
        let mut envelopes = envelopes.into_iter();
        let mut ledger = envelopes
            .next()
            .ok_or(Error::EmptyChain)
            .and_then(|envelope| Self::init(storage, envelope))?;

        envelopes.try_for_each(|envelope| ledger.apply(storage, envelope))?;
        Ok(ledger)
    }

    /// Advances the ledger by one envelope.
    ///
    /// The envelope must chain onto the current [`head`](Ledger::head).
    /// Everything is validated before the one commit, so a rejected
    /// envelope cannot half-apply. The version at the previous head is
    /// kept — other ledgers may be standing on it.
    pub fn apply<S: Storage>(
        &mut self,
        storage: &mut S,
        envelope: &Envelope,
    ) -> Result<(), ApplyError<S::Error>> {
        let msg = envelope.payload();
        let prev = msg.prev_digest().ok_or(ApplyError::UnexpectedInit)?;

        if prev != &self.head {
            return Err(ApplyError::ChainMismatch {
                expected: self.head,
                found: *prev,
            });
        }
        let head = envelope.digest()?;

        let op = match msg {
            // Unreachable: Init is the only variant without a prev digest,
            // so the check above has already rejected it.
            Msg::Init(_) => return Err(ApplyError::UnexpectedInit),
            Msg::SetNamespace(set) => NamespaceOp::Put(set.key.clone(), set.namespace.clone()),
            Msg::SetNamespaceKey(set) => self.validate_set_key(storage, set)?,
            Msg::DeleteNamespace(del) => {
                self.resolve(storage, &del.key, &[])?
                    .ok_or_else(|| ApplyError::UnknownNamespace(del.key.clone()))?;
                NamespaceOp::Delete(del.key.clone())
            }
        };

        storage
            .commit(self.head, head, op)
            .map_err(ApplyError::Storage)?;
        self.head = head;
        Ok(())
    }

    /// Checks a `SetNamespaceKey` against the store, yielding the op that
    /// commits it. Nothing is written here.
    ///
    /// Every step of the path must already exist — nothing is created
    /// along the way except a fresh leaf under an existing map, so a
    /// typo'd path is refused rather than quietly building a second copy
    /// of the data beside the real one.
    fn validate_set_key<S: Storage>(
        &self,
        storage: &S,
        set: &SetNamespaceKey,
    ) -> Result<NamespaceOp, ApplyError<S::Error>> {
        let miss = |miss: Miss| miss.into_error(&set.key, &set.path);
        let last = set.path.as_ref().len() - 1;

        let resolution = self
            .resolve(storage, &set.key, set.path.as_ref())?
            .ok_or_else(|| ApplyError::UnknownNamespace(set.key.clone()))?;

        match resolution {
            // The path addresses an existing value: a set overwrites it,
            // a clear removes it.
            Resolution::Node(_) => {}
            // The only legal absence: a fresh key set into a map. The
            // segment's shape matched the map, or this would be Mismatch.
            Resolution::Missing {
                depth,
                at: NodeKind::Map,
            } if depth == last && set.value.is_some() => {}
            Resolution::Missing { .. } => return Err(miss(Miss::NotFound)),
            Resolution::Mismatch { .. } => return Err(miss(Miss::TypeMismatch)),
        }

        Ok(NamespaceOp::SetAt {
            key: set.key.clone(),
            path: set.path.clone(),
            value: set.value.clone(),
        })
    }

    fn resolve<S: Storage>(
        &self,
        storage: &S,
        key: &NamespaceKey,
        path: &[Subkey],
    ) -> Result<Option<Resolution>, ApplyError<S::Error>> {
        storage
            .resolve(self.head, key, path)
            .map_err(ApplyError::Storage)
    }

    /// The digest of the most recently applied envelope.
    pub fn head(&self) -> EnvelopeDigest {
        self.head
    }

    /// The ledger's configuration.
    pub fn config(&self) -> &LedgerConfig {
        &self.config
    }

    /// The namespace filed under `key`, if the ledger holds one.
    ///
    /// Materializes the whole namespace.
    pub fn namespace<S: Storage>(
        &self,
        storage: &S,
        key: &NamespaceKey,
    ) -> Result<Option<Namespace>, S::Error> {
        storage.namespace(self.head, key)
    }

    /// Every namespace the ledger holds, in key order.
    pub fn namespaces<S: Storage>(
        &self,
        storage: &S,
    ) -> impl Iterator<Item = Result<(NamespaceKey, Namespace), S::Error>> {
        storage.namespaces(self.head)
    }

    /// The ledger's state as a checkpoint, ready to open a rewritten
    /// chain. The one read that is O(state): every namespace streams
    /// through memory to build it.
    pub fn checkpoint<S: Storage>(&self, storage: &S) -> Result<FullCheckpoint, S::Error> {
        Ok(FullCheckpoint {
            namespaces: storage.namespaces(self.head).collect::<Result<_, _>>()?,
            config: self.config.clone(),
        })
    }
}

/// Why a path stopped short. Carries no context of its own; the caller
/// pins the namespace and path onto it.
enum Miss {
    NotFound,
    TypeMismatch,
}

impl Miss {
    fn into_error<E>(self, key: &NamespaceKey, path: &SubkeyPath) -> ApplyError<E> {
        let (key, path) = (key.clone(), path.clone());
        match self {
            Miss::NotFound => ApplyError::UnknownPath { key, path },
            Miss::TypeMismatch => ApplyError::PathTypeMismatch { key, path },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use storage::MemStorage;
    use wire::msg::{DeleteNamespace, InitMsg, SetNamespace, Value};

    use super::*;

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

    fn setup(envelope: &Envelope) -> (MemStorage, Ledger) {
        let mut store = MemStorage::default();
        let ledger = Ledger::init(&mut store, envelope).unwrap();
        (store, ledger)
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

    /// A store and ledger holding [`nested`] under namespace `n`.
    fn nested_ledger() -> (MemStorage, Ledger) {
        setup(&Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: [(key("n"), nested())].into_iter().collect(),
                ..Default::default()
            },
        })))
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
    fn at(store: &MemStorage, ledger: &Ledger, p: &[Subkey]) -> Option<Value> {
        let namespace = ledger.namespace(store, &key("n")).unwrap()?;
        p.iter()
            .try_fold(&namespace.value, |value, segment| match (value, segment) {
                (Value::Map(map), Subkey::Key(k)) => map.get(k),
                (Value::Array(array), Subkey::Index(index)) => array.get(*index as usize),
                _ => None,
            })
            .cloned()
    }

    #[test]
    fn init_opens_at_the_checkpoint() {
        let envelope = init();
        let (store, ledger) = setup(&envelope);

        assert_eq!(ledger.head(), envelope.digest().unwrap());
        assert_eq!(ledger.namespaces(&store).count(), 0);
        assert_eq!(ledger.config(), &LedgerConfig::default());
    }

    /// An `Init` carrying state opens the ledger already populated, which is
    /// what makes a compacted or rewritten chain resumable.
    #[test]
    fn init_carries_its_state_across() {
        let (store, ledger) = setup(&Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: [(key("a"), ns("1"))].into_iter().collect(),
                ..Default::default()
            },
        })));

        assert_eq!(ledger.namespace(&store, &key("a")).unwrap(), Some(ns("1")));
    }

    #[test]
    fn init_rejects_a_non_init_envelope() {
        let mut store = MemStorage::default();
        let envelope = set(EnvelopeDigest::from_bytes([0xab; 32]), "a", "1");
        assert!(matches!(
            Ledger::init(&mut store, &envelope),
            Err(Error::NotInit)
        ));
    }

    /// Opening a second chain in the same store must not disturb the
    /// first — that's the point of the store not owning a head.
    #[test]
    fn init_leaves_other_chains_alone() {
        let (mut store, first) = setup(&Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: [(key("old"), ns("1"))].into_iter().collect(),
                ..Default::default()
            },
        })));

        let second = Ledger::init(&mut store, &init()).unwrap();

        assert_eq!(first.namespace(&store, &key("old")).unwrap(), Some(ns("1")));
        assert_eq!(second.namespace(&store, &key("old")).unwrap(), None);
    }

    #[test]
    fn open_resumes_at_a_head() {
        let (mut store, mut ledger) = setup(&init());
        ledger
            .apply(&mut store, &set(ledger.head(), "a", "1"))
            .unwrap();

        let reopened = Ledger::open(&store, ledger.head()).unwrap();
        assert_eq!(reopened, ledger);
        assert_eq!(reopened.config(), &LedgerConfig::default());
        assert_eq!(
            reopened.namespace(&store, &key("a")).unwrap(),
            Some(ns("1"))
        );
    }

    #[test]
    fn open_rejects_an_unknown_head() {
        let store = MemStorage::default();
        let head = EnvelopeDigest::from_bytes([0xab; 32]);

        assert!(matches!(
            Ledger::open(&store, head),
            Err(Error::UnknownHead(h)) if h == head
        ));
    }

    /// Advancing a ledger doesn't consume the version it stood on: the
    /// old head still opens, as a historical view of the chain.
    #[test]
    fn an_old_head_stays_readable() {
        let opening = init();
        let (mut store, mut ledger) = setup(&opening);
        ledger
            .apply(&mut store, &set(ledger.head(), "a", "1"))
            .unwrap();

        let past = Ledger::open(&store, opening.digest().unwrap()).unwrap();
        assert_eq!(past.namespace(&store, &key("a")).unwrap(), None);
        assert_eq!(ledger.namespace(&store, &key("a")).unwrap(), Some(ns("1")));
    }

    /// Cloning a ledger forks the chain: both cursors advance from the
    /// same head, in one store, without treading on each other.
    #[test]
    fn forked_ledgers_share_one_store() {
        let (mut store, mut left) = setup(&init());
        let mut right = left.clone();

        left.apply(&mut store, &set(left.head(), "a", "1")).unwrap();
        right
            .apply(&mut store, &set(right.head(), "b", "2"))
            .unwrap();

        assert_eq!(left.namespace(&store, &key("a")).unwrap(), Some(ns("1")));
        assert_eq!(left.namespace(&store, &key("b")).unwrap(), None);
        assert_eq!(right.namespace(&store, &key("b")).unwrap(), Some(ns("2")));
        assert_eq!(right.namespace(&store, &key("a")).unwrap(), None);
    }

    #[test]
    fn apply_sets_a_namespace_and_advances_the_head() {
        let init = init();
        let (mut store, mut ledger) = setup(&init);

        let set = set(ledger.head(), "a", "1");
        ledger.apply(&mut store, &set).unwrap();

        assert_eq!(ledger.namespace(&store, &key("a")).unwrap(), Some(ns("1")));
        assert_eq!(ledger.head(), set.digest().unwrap());
        assert_ne!(ledger.head(), init.digest().unwrap());
    }

    #[test]
    fn set_overwrites_a_namespace_wholesale() {
        let (mut store, mut ledger) = setup(&init());

        let first = set(ledger.head(), "a", "1");
        ledger.apply(&mut store, &first).unwrap();
        let second = set(ledger.head(), "a", "2");
        ledger.apply(&mut store, &second).unwrap();

        assert_eq!(ledger.namespace(&store, &key("a")).unwrap(), Some(ns("2")));
        assert_eq!(ledger.namespaces(&store).count(), 1);
    }

    #[test]
    fn apply_deletes_a_namespace() {
        let (mut store, mut ledger) = setup(&init());

        let set = set(ledger.head(), "a", "1");
        ledger.apply(&mut store, &set).unwrap();
        let delete = delete(ledger.head(), "a");
        ledger.apply(&mut store, &delete).unwrap();

        assert_eq!(ledger.namespace(&store, &key("a")).unwrap(), None);
        assert_eq!(ledger.head(), delete.digest().unwrap());
    }

    /// The point of the chain: an envelope that doesn't point at the head is
    /// refused, so a gap or a fork can't be folded in unnoticed.
    #[test]
    fn apply_rejects_an_envelope_that_skips_the_head() {
        let (mut store, mut ledger) = setup(&init());
        let head = ledger.head();

        let orphan = set(EnvelopeDigest::from_bytes([0xab; 32]), "a", "1");
        let err = ledger.apply(&mut store, &orphan).unwrap_err();

        assert!(matches!(
            err,
            ApplyError::ChainMismatch { expected, found }
                if expected == head && found == EnvelopeDigest::from_bytes([0xab; 32])
        ));
        assert_eq!(ledger.head(), head, "head must not move");
        assert_eq!(
            ledger.namespaces(&store).count(),
            0,
            "state must not change"
        );
    }

    /// Replaying the same envelope twice fails the second time: its `prev`
    /// points at what is now the previous head, not the current one.
    #[test]
    fn apply_is_not_idempotent() {
        let (mut store, mut ledger) = setup(&init());

        let set = set(ledger.head(), "a", "1");
        ledger.apply(&mut store, &set).unwrap();
        assert!(matches!(
            ledger.apply(&mut store, &set),
            Err(ApplyError::ChainMismatch { .. })
        ));
    }

    #[test]
    fn apply_rejects_a_second_init() {
        let opening = init();
        let (mut store, mut ledger) = setup(&opening);

        assert!(matches!(
            ledger.apply(&mut store, &init()),
            Err(ApplyError::UnexpectedInit)
        ));
        assert_eq!(ledger.head(), opening.digest().unwrap());
    }

    /// Deleting what isn't there is a malformed message rather than a no-op:
    /// two nodes must never disagree about whether an envelope applied.
    #[test]
    fn delete_rejects_an_unknown_namespace() {
        let (mut store, mut ledger) = setup(&init());
        let head = ledger.head();

        let delete = delete(head, "nope");
        let err = ledger.apply(&mut store, &delete).unwrap_err();

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

        let mut store = MemStorage::default();
        let replayed = Ledger::replay(&mut store, &chain).unwrap();

        assert_eq!(replayed.namespace(&store, &key("a")).unwrap(), None);
        assert_eq!(
            replayed.namespace(&store, &key("b")).unwrap(),
            Some(ns("2"))
        );
        assert_eq!(replayed.head(), chain.last().unwrap().digest().unwrap());

        // Same result as advancing one envelope at a time.
        let mut stepwise_store = MemStorage::default();
        let stepwise = chain
            .iter()
            .skip(1)
            .try_fold(
                Ledger::init(&mut stepwise_store, &chain[0]).unwrap(),
                |mut ledger, envelope| ledger.apply(&mut stepwise_store, envelope).map(|()| ledger),
            )
            .unwrap();
        assert_eq!(stepwise, replayed);
        assert_eq!(
            stepwise.checkpoint(&stepwise_store).unwrap(),
            replayed.checkpoint(&store).unwrap()
        );
    }

    #[test]
    fn set_key_writes_a_nested_value() {
        let (mut store, mut ledger) = nested_ledger();
        let envelope = set_key(
            ledger.head(),
            path([sub("a"), sub("b")]),
            Some(Value::String("2".into())),
        );
        ledger.apply(&mut store, &envelope).unwrap();

        assert_eq!(
            at(&store, &ledger, &[sub("a"), sub("b")]),
            Some(Value::String("2".into()))
        );
        assert_eq!(ledger.head(), envelope.digest().unwrap());
    }

    /// Only the addressed value moves; its siblings are left alone. That's
    /// the whole point of the message over republishing the namespace.
    #[test]
    fn set_key_leaves_the_rest_of_the_namespace_alone() {
        let (mut store, mut ledger) = nested_ledger();
        let before = at(&store, &ledger, &[sub("list")]);

        ledger
            .apply(
                &mut store,
                &set_key(
                    ledger.head(),
                    path([sub("a"), sub("b")]),
                    Some(Value::Int(9)),
                ),
            )
            .unwrap();

        assert_eq!(at(&store, &ledger, &[sub("list")]), before);
    }

    /// A key that isn't there yet is created, as long as its parent map is.
    #[test]
    fn set_key_adds_a_new_leaf_to_an_existing_map() {
        let (mut store, mut ledger) = nested_ledger();
        ledger
            .apply(
                &mut store,
                &set_key(
                    ledger.head(),
                    path([sub("a"), sub("new")]),
                    Some(Value::Bool(true)),
                ),
            )
            .unwrap();

        assert_eq!(
            at(&store, &ledger, &[sub("a"), sub("new")]),
            Some(Value::Bool(true))
        );
    }

    #[test]
    fn set_key_clears_a_value_when_given_none() {
        let (mut store, mut ledger) = nested_ledger();
        ledger
            .apply(
                &mut store,
                &set_key(ledger.head(), path([sub("a"), sub("b")]), None),
            )
            .unwrap();

        assert_eq!(at(&store, &ledger, &[sub("a"), sub("b")]), None);
        assert_eq!(at(&store, &ledger, &[sub("a")]), Some(map([])));
    }

    #[test]
    fn set_key_replaces_an_array_element_by_index() {
        let (mut store, mut ledger) = nested_ledger();
        ledger
            .apply(
                &mut store,
                &set_key(
                    ledger.head(),
                    path([sub("list"), Subkey::Index(1)]),
                    Some(Value::String("z".into())),
                ),
            )
            .unwrap();

        assert_eq!(
            at(&store, &ledger, &[sub("list")]),
            Some(Value::Array(vec![
                Value::String("x".into()),
                Value::String("z".into()),
            ]))
        );
    }

    /// Clearing an element shortens the array — later indices shift down.
    #[test]
    fn set_key_removes_an_array_element_when_given_none() {
        let (mut store, mut ledger) = nested_ledger();
        ledger
            .apply(
                &mut store,
                &set_key(ledger.head(), path([sub("list"), Subkey::Index(0)]), None),
            )
            .unwrap();

        assert_eq!(
            at(&store, &ledger, &[sub("list")]),
            Some(Value::Array(vec![Value::String("y".into())]))
        );
    }

    /// Nothing is created along the way: an intermediate that doesn't exist
    /// is refused rather than conjured, so a typo can't build a shadow copy
    /// of the data next to the real one.
    #[test]
    fn set_key_refuses_to_create_intermediates() {
        let (mut store, mut ledger) = nested_ledger();
        let head = ledger.head();
        let before = ledger.namespace(&store, &key("n")).unwrap();

        let err = ledger
            .apply(
                &mut store,
                &set_key(head, path([sub("nope"), sub("b")]), Some(Value::Int(1))),
            )
            .unwrap_err();

        assert!(matches!(err, ApplyError::UnknownPath { key: k, path: p }
            if k == key("n") && p == path([sub("nope"), sub("b")])));
        assert_eq!(ledger.namespace(&store, &key("n")).unwrap(), before);
        assert_eq!(ledger.head(), head);
    }

    #[test]
    fn set_key_rejects_a_path_of_the_wrong_shape() {
        let (mut store, mut ledger) = nested_ledger();
        let head = ledger.head();

        // A key into an array.
        let err = ledger
            .apply(
                &mut store,
                &set_key(head, path([sub("list"), sub("x")]), Some(Value::Int(1))),
            )
            .unwrap_err();
        assert!(matches!(err, ApplyError::PathTypeMismatch { .. }));

        // An index into a map.
        let err = ledger
            .apply(
                &mut store,
                &set_key(
                    head,
                    path([sub("a"), Subkey::Index(0)]),
                    Some(Value::Int(1)),
                ),
            )
            .unwrap_err();
        assert!(matches!(err, ApplyError::PathTypeMismatch { .. }));

        // A step through a leaf.
        let err = ledger
            .apply(
                &mut store,
                &set_key(
                    head,
                    path([sub("a"), sub("b"), sub("deeper")]),
                    Some(Value::Int(1)),
                ),
            )
            .unwrap_err();
        assert!(matches!(err, ApplyError::PathTypeMismatch { .. }));
    }

    #[test]
    fn set_key_rejects_clearing_what_is_not_there() {
        let (mut store, mut ledger) = nested_ledger();
        let head = ledger.head();

        let err = ledger
            .apply(
                &mut store,
                &set_key(head, path([sub("a"), sub("gone")]), None),
            )
            .unwrap_err();
        assert!(matches!(err, ApplyError::UnknownPath { .. }));

        let err = ledger
            .apply(
                &mut store,
                &set_key(head, path([sub("list"), Subkey::Index(9)]), None),
            )
            .unwrap_err();
        assert!(matches!(err, ApplyError::UnknownPath { .. }));

        assert_eq!(ledger.head(), head, "head must not move");
    }

    #[test]
    fn set_key_rejects_an_unknown_namespace() {
        let (mut store, mut ledger) = nested_ledger();
        let envelope = Envelope::new(Msg::SetNamespaceKey(SetNamespaceKey {
            prev: ledger.head(),
            key: key("absent"),
            path: path([sub("a")]),
            value: Some(Value::Int(1)),
        }));

        assert!(matches!(
            ledger.apply(&mut store, &envelope),
            Err(ApplyError::UnknownNamespace(k)) if k == key("absent")
        ));
    }

    /// A rejected envelope leaves the *store* untouched, not just the
    /// ledger's caches — reopening at the same head must agree.
    #[test]
    fn a_rejected_envelope_leaves_the_store_untouched() {
        let (mut store, mut ledger) = nested_ledger();
        let head = ledger.head();

        ledger
            .apply(&mut store, &set_key(head, path([sub("nope")]), None))
            .unwrap_err();

        let reopened = Ledger::open(&store, head).unwrap();
        assert_eq!(reopened.head(), head);
        assert_eq!(
            reopened.namespace(&store, &key("n")).unwrap(),
            Some(nested())
        );
    }

    /// `replay` speaks the crate error, but a mid-chain failure keeps the
    /// specific `ApplyError` underneath rather than flattening it.
    #[test]
    fn replay_wraps_apply_errors() {
        let init = init();
        let orphan = set(EnvelopeDigest::from_bytes([0xab; 32]), "a", "1");

        let mut store = MemStorage::default();
        let err = Ledger::replay(&mut store, &[init, orphan]).unwrap_err();
        assert!(matches!(
            err,
            Error::Apply(ApplyError::ChainMismatch { .. })
        ));

        // The chain is reachable through `source()`, not just the variant.
        let source = core::error::Error::source(&err).unwrap();
        assert!(source.downcast_ref::<ApplyError<Infallible>>().is_some());
    }

    #[test]
    fn replay_rejects_an_empty_chain() {
        let mut store = MemStorage::default();
        assert!(matches!(
            Ledger::replay(&mut store, &[]),
            Err(Error::EmptyChain)
        ));
    }

    /// The checkpoint a ledger hands back reopens to exactly the same state
    /// — that's what lets a chain be compacted or rewritten, in the same
    /// store, alongside the chain it came from.
    #[test]
    fn checkpoint_reopens_to_the_same_state() {
        let (mut store, mut ledger) = setup(&init());
        ledger
            .apply(&mut store, &set(ledger.head(), "a", "1"))
            .unwrap();

        let rewritten = Envelope::new(Msg::Init(InitMsg {
            state: ledger.checkpoint(&store).unwrap(),
        }));
        let reopened = Ledger::init(&mut store, &rewritten).unwrap();

        assert_eq!(
            reopened.checkpoint(&store).unwrap(),
            ledger.checkpoint(&store).unwrap()
        );
        assert_ne!(reopened.head(), ledger.head(), "new chain, new head");
    }
}
