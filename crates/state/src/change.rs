//! What a head movement changed.
//!
//! A [`ChangeSet`] summarises the namespaces and paths a run of envelopes
//! touched; a [`ChangeDiffer`] derives one from the log, reorgs included.
//! Callers use the summary to decide what to go and re-read — it is
//! deliberately not a diff of values.

use std::collections::{BTreeMap, BTreeSet};

use storage::Storage;
use wire::{Envelope, EnvelopeDigest, Msg, msg::NamespaceKey, subkey::SubkeyPath};

use crate::Error;

/// What changed inside one namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The namespace was written, removed, or amended at its root, so
    /// anything under it may differ.
    Whole,
    /// Only these paths were touched. Never empty: a namespace nothing
    /// touched is absent from the [`ChangeSet`] instead. No path here is a
    /// prefix of another — the shallowest description of the change is kept
    /// and the deeper paths it already covers are dropped.
    Paths(BTreeSet<SubkeyPath>),
}

/// The namespaces and paths a run of envelopes touched.
///
/// An over-approximation, and meant to stay one: a value written back to
/// what it already was still appears here, and an append records the array
/// it landed in rather than the index it created. Reorgs are summarised the
/// same way — the branch left behind contributes its changes alongside the
/// branch taken, since both are things a reader must look at again.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeSet(BTreeMap<NamespaceKey, Change>);

impl ChangeSet {
    /// Whether nothing was touched.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// What changed in `key`, if anything.
    pub fn get(&self, key: &NamespaceKey) -> Option<&Change> {
        self.0.get(key)
    }

    /// Every namespace touched and what changed in it, in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&NamespaceKey, &Change)> {
        self.0.iter()
    }

    /// Whether what `path` addresses in `key` may have changed; `None` asks
    /// about the namespace as a whole.
    ///
    /// Paths match in both directions: writing `servers[0].host` is a
    /// change to a watcher of `servers`, and replacing the whole of
    /// `servers` is a change to a watcher of `servers[0].host`. Only a
    /// path that diverges from every recorded one — the same namespace,
    /// but a sibling — is left out.
    pub fn touches(&self, key: &NamespaceKey, path: Option<&SubkeyPath>) -> bool {
        match (self.0.get(key), path) {
            (None, _) => false,
            (Some(Change::Whole), _) | (Some(Change::Paths(_)), None) => true,
            (Some(Change::Paths(paths)), Some(path)) => {
                paths.iter().any(|touched| overlaps(touched, path))
            }
        }
    }

    /// Records everything `msg` touches.
    pub fn record(&mut self, msg: &Msg) {
        match msg {
            Msg::Init(init) => init
                .state
                .namespaces
                .keys()
                .for_each(|key| self.touch(key, None)),
            Msg::SetNamespace(set) => self.touch(&set.key, None),
            Msg::DeleteNamespace(del) => self.touch(&del.key, None),
            Msg::SetNamespaceKey(set) => self.touch(&set.key, Some(&set.path)),
            // A pathless amend transforms the namespace's whole value.
            Msg::AmendNamespaceKey(amend) => self.touch(&amend.key, amend.path.as_ref()),
        }
    }

    /// Folds `other` into this set.
    pub fn merge(&mut self, other: &ChangeSet) {
        other.0.iter().for_each(|(key, change)| match change {
            Change::Whole => self.touch(key, None),
            Change::Paths(paths) => paths.iter().for_each(|path| self.touch(key, Some(path))),
        });
    }

    /// Records a change to `path` in `key`; `None` for the whole namespace,
    /// which absorbs any paths already recorded under it.
    fn touch(&mut self, key: &NamespaceKey, path: Option<&SubkeyPath>) {
        let Some(path) = path else {
            self.0.insert(key.clone(), Change::Whole);
            return;
        };
        // Seeded with the path rather than empty so `Paths` is never
        // momentarily the empty set its contract forbids; the arm below
        // then finds it already covered and leaves it alone.
        match self
            .0
            .entry(key.clone())
            .or_insert_with(|| Change::Paths([path.clone()].into()))
        {
            Change::Whole => {}
            Change::Paths(paths) if paths.iter().any(|touched| covers(touched, path)) => {}
            Change::Paths(paths) => {
                paths.retain(|touched| !covers(path, touched));
                paths.insert(path.clone());
            }
        }
    }
}

/// Whether two paths address overlapping state: one is a prefix of the
/// other, equal paths included.
fn overlaps(a: &SubkeyPath, b: &SubkeyPath) -> bool {
    a.as_ref().iter().zip(b.as_ref()).all(|(a, b)| a == b)
}

/// Whether `a` covers `b`: everything `b` addresses lies under `a`, equal
/// paths included. Recording `b` beside `a` would add nothing.
fn covers(a: &SubkeyPath, b: &SubkeyPath) -> bool {
    a.as_ref().len() <= b.as_ref().len() && overlaps(a, b)
}

/// What one movement of the canonical head did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Movement {
    /// The envelopes that were on the canonical path and are not any more,
    /// left there by a reorg. Empty when the head merely moved forward.
    ///
    /// An envelope here is off the chain for good. Fork resolution ranks
    /// siblings by `(weight, digest)`, both fixed once an envelope is
    /// stored, and the sibling that beat this one is still in the log — so
    /// the contest it lost can never come out differently, and neither can
    /// any contest its descendants hang off.
    pub orphaned: BTreeSet<EnvelopeDigest>,
    /// What the movement changed, counting the branch left behind as much
    /// as the one taken.
    pub changes: ChangeSet,
}

impl Movement {
    /// Folds a movement that followed this one into it, describing both as
    /// one — how a reader that was not looking catches up in a single step.
    ///
    /// Orphans simply accumulate. That is exact rather than approximate
    /// because an envelope never returns to the chain, which in turn rests
    /// on a stored envelope's verification status never being raised in
    /// place — something [`Storage::put_envelope`] contemplates a caller
    /// doing. Were that ever done, a loser could come to out-weigh the
    /// sibling that beat it, and an envelope orphaned by one movement could
    /// be canonical again by the end of the next.
    ///
    /// [`Storage::put_envelope`]: storage::Storage::put_envelope
    pub fn merge(&mut self, next: &Movement) {
        self.changes.merge(&next.changes);
        self.orphaned.extend(&next.orphaned);
    }

    /// Whether the movement neither changed nor orphaned anything.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty() && self.orphaned.is_empty()
    }
}

/// Derives the [`Movement`] between two canonical heads.
///
/// Opened at the head standing before a run of envelopes is ingested, then
/// asked to diff against the head that run left behind — so a caller holds
/// one across [`Chain::insert_batch`](crate::Chain::insert_batch) and asks
/// afterwards.
///
/// The two heads are walked back through the log in step until they reach
/// the envelope they last agreed on, and everything above it on either side
/// is recorded: the changes undone by leaving the old branch as well as
/// those made by taking the new one. Walking both sides at once costs the
/// distance to that meeting point rather than the length of the chain, so
/// the ordinary case — a head that simply moved forward — stops as soon as
/// the new branch reaches the old head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeDiffer {
    from: EnvelopeDigest,
}

impl ChangeDiffer {
    /// Opens a differ at `from`, the head standing before the ingest.
    pub fn opened_at(from: EnvelopeDigest) -> Self {
        Self { from }
    }

    /// The head this differ opened at.
    pub fn from(&self) -> EnvelopeDigest {
        self.from
    }

    /// What moving from the head this differ opened at to `to` did.
    ///
    /// Both heads must sit on the same chain: two heads whose branches
    /// share no ancestor the log still holds are [`Error::Diverged`],
    /// since nothing can be said about what lies between them.
    pub fn diff<S: Storage>(
        &self,
        storage: &S,
        to: EnvelopeDigest,
    ) -> Result<Movement, Error<S::Error>> {
        let mut undone = Branch::opened(self.from);
        let mut made = Branch::opened(to);

        let meet = loop {
            if let Some(meet) = undone.meet(&made) {
                break meet;
            }
            // Both sides step every round; neither able to is the end of
            // the log on both branches with nothing in common found.
            let undone_moved = undone.step(storage)?;
            let made_moved = made.step(storage)?;
            if !undone_moved && !made_moved {
                return Err(Error::Diverged {
                    from: self.from,
                    to,
                });
            }
        };

        // The undone walk is the orphan list: those envelopes were on the
        // canonical path and the new one does not pass through them.
        let mut movement = Movement::default();
        undone.above(meet).for_each(|(digest, envelope)| {
            movement.orphaned.insert(digest);
            movement.changes.record(envelope.payload());
        });
        made.above(meet)
            .for_each(|(_, envelope)| movement.changes.record(envelope.payload()));
        Ok(movement)
    }
}

/// Where a branch's walk down the log has got to.
#[derive(Debug, Clone, Copy)]
enum Cursor {
    /// The digest to read next.
    At(EnvelopeDigest),
    /// The walk can go no further, holding where it stopped: `None` at the
    /// root, or the digest the log turned out not to hold.
    End(Option<EnvelopeDigest>),
}

/// One side of the walk: the envelopes from a head down to wherever the
/// walk has reached, head first.
#[derive(Debug)]
struct Branch {
    walked: Vec<(EnvelopeDigest, Envelope)>,
    cursor: Cursor,
    reached: BTreeSet<EnvelopeDigest>,
}

impl Branch {
    fn opened(head: EnvelopeDigest) -> Self {
        Self {
            walked: Vec::new(),
            cursor: Cursor::At(head),
            reached: BTreeSet::from([head]),
        }
    }

    /// The digests this branch has reached, head first — read or not.
    fn reached(&self) -> impl Iterator<Item = EnvelopeDigest> {
        self.walked
            .iter()
            .map(|(digest, _)| *digest)
            .chain(match self.cursor {
                Cursor::At(digest) | Cursor::End(Some(digest)) => Some(digest),
                Cursor::End(None) => None,
            })
    }

    /// The nearest digest both branches have reached, once they have met.
    ///
    /// Every digest they share is a common ancestor, and ancestors form one
    /// path, so the first this branch reached is the nearest for the other
    /// branch too.
    fn meet(&self, other: &Self) -> Option<EnvelopeDigest> {
        self.reached().find(|digest| other.reached.contains(digest))
    }

    /// Reads the envelope at the cursor and moves to its parent. `false`
    /// once the walk can go no further.
    fn step<S: Storage>(&mut self, storage: &S) -> Result<bool, Error<S::Error>> {
        let Cursor::At(digest) = self.cursor else {
            return Ok(false);
        };
        // A digest the log no longer holds ends the walk where it stands,
        // rather than dropping it: the other branch may yet reach the same
        // envelope and make it the meeting point.
        let Some(envelope) = storage.envelope(digest).map_err(Error::Storage)? else {
            self.cursor = Cursor::End(Some(digest));
            return Ok(false);
        };

        self.cursor = match envelope.payload().prev_digest() {
            Some(prev) => {
                self.reached.insert(*prev);
                Cursor::At(*prev)
            }
            None => Cursor::End(None),
        };
        self.walked.push((digest, envelope));
        Ok(matches!(self.cursor, Cursor::At(_)))
    }

    /// The envelopes this branch walked above `meet` — everything it
    /// contributes to the change set.
    fn above(&self, meet: EnvelopeDigest) -> impl Iterator<Item = (EnvelopeDigest, &Envelope)> {
        self.walked
            .iter()
            .take_while(move |(digest, _)| *digest != meet)
            .map(|(digest, envelope)| (*digest, envelope))
    }
}

#[cfg(test)]
mod tests {
    use storage::MemStorage;
    use wire::{
        Msg,
        msg::{
            AmendNamespaceKey, AmendOp, DeleteNamespace, FullCheckpoint, IncrementDecrement,
            InitMsg, Namespace, SetNamespace, SetNamespaceKey, Value,
        },
        subkey::Subkey,
    };

    use super::*;
    use crate::Chain;

    fn key(k: &str) -> NamespaceKey {
        NamespaceKey::try_new(k).unwrap()
    }

    fn path(segments: impl IntoIterator<Item = Subkey>) -> SubkeyPath {
        SubkeyPath::try_new(segments.into_iter().collect()).unwrap()
    }

    /// A path of map keys, the common case in these tests.
    fn keys(segments: &[&str]) -> SubkeyPath {
        path(segments.iter().map(|k| Subkey::Key((*k).to_string())))
    }

    fn digest(envelope: &Envelope) -> EnvelopeDigest {
        envelope.digest().unwrap()
    }

    /// A namespace deep enough for paths to resolve inside it.
    fn tree() -> Namespace {
        Namespace {
            value: Value::Map(BTreeMap::from([
                ("host".to_string(), Value::String("one".to_string())),
                ("port".to_string(), Value::Int(1)),
                (
                    "tags".to_string(),
                    Value::Array(vec![Value::String("x".to_string())]),
                ),
            ])),
        }
    }

    /// A namespace nested two levels deep, so `b.c` and `b` are both
    /// writable paths inside it.
    fn nested() -> Namespace {
        Namespace {
            value: Value::Map(BTreeMap::from([(
                "b".to_string(),
                Value::Map(BTreeMap::from([
                    ("c".to_string(), Value::Int(1)),
                    ("d".to_string(), Value::Int(2)),
                ])),
            )])),
        }
    }

    fn set_ns(prev: EnvelopeDigest, k: &str, namespace: Namespace) -> Envelope {
        Envelope::new(Msg::SetNamespace(SetNamespace {
            prev,
            key: key(k),
            namespace,
        }))
    }

    /// A namespace holding one string, for the fork tests where only the
    /// key written matters.
    fn set_str(prev: EnvelopeDigest, k: &str, v: &str) -> Envelope {
        set_ns(
            prev,
            k,
            Namespace {
                value: Value::String(v.to_string()),
            },
        )
    }

    fn set_key(prev: EnvelopeDigest, k: &str, path: SubkeyPath, value: Option<Value>) -> Envelope {
        Envelope::new(Msg::SetNamespaceKey(SetNamespaceKey {
            prev,
            key: key(k),
            path,
            value,
        }))
    }

    fn amend(prev: EnvelopeDigest, k: &str, path: Option<SubkeyPath>, op: AmendOp) -> Envelope {
        Envelope::new(Msg::AmendNamespaceKey(AmendNamespaceKey {
            prev,
            key: key(k),
            path,
            op,
        }))
    }

    fn delete(prev: EnvelopeDigest, k: &str) -> Envelope {
        Envelope::new(Msg::DeleteNamespace(DeleteNamespace { prev, key: key(k) }))
    }

    fn genesis(namespaces: impl IntoIterator<Item = (NamespaceKey, Namespace)>) -> Envelope {
        Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: namespaces.into_iter().collect(),
            },
        }))
    }

    fn setup() -> (MemStorage, Chain) {
        let mut store = MemStorage::default();
        let chain = Chain::init(&mut store, genesis([])).unwrap();
        (store, chain)
    }

    /// Splits two sibling envelopes into (winner, loser) by the fork rule:
    /// equal (zero) signature weight, so the higher digest wins.
    fn ranked(a: Envelope, b: Envelope) -> (Envelope, Envelope) {
        if digest(&a) > digest(&b) {
            (a, b)
        } else {
            (b, a)
        }
    }

    /// Ingests a run of envelopes and reports what the head movement
    /// changed — the way a caller holds a differ across an insert.
    fn ingest(
        store: &mut MemStorage,
        chain: &mut Chain,
        envelopes: impl IntoIterator<Item = Envelope>,
    ) -> ChangeSet {
        movement(store, chain, envelopes).changes
    }

    /// The same, kept whole for the tests that weigh what was orphaned.
    fn movement(
        store: &mut MemStorage,
        chain: &mut Chain,
        envelopes: impl IntoIterator<Item = Envelope>,
    ) -> Movement {
        let differ = ChangeDiffer::opened_at(chain.head());
        chain.insert_batch(store, envelopes).unwrap();
        differ.diff(store, chain.head()).unwrap()
    }

    /// The change set for a namespace written whole.
    fn whole(k: &str) -> (NamespaceKey, Change) {
        (key(k), Change::Whole)
    }

    fn paths(k: &str, paths: impl IntoIterator<Item = SubkeyPath>) -> (NamespaceKey, Change) {
        (key(k), Change::Paths(paths.into_iter().collect()))
    }

    fn expect(entries: impl IntoIterator<Item = (NamespaceKey, Change)>) -> ChangeSet {
        ChangeSet(entries.into_iter().collect())
    }

    #[test]
    fn a_head_that_did_not_move_changed_nothing() {
        let (store, chain) = setup();
        let differ = ChangeDiffer::opened_at(chain.head());

        assert_eq!(
            differ.diff(&store, chain.head()).unwrap(),
            Movement::default()
        );
    }

    #[test]
    fn writing_a_namespace_changes_the_whole_of_it() {
        let (mut store, mut chain) = setup();
        let envelope = set_ns(chain.head(), "a", tree());

        let changes = ingest(&mut store, &mut chain, [envelope]);

        assert_eq!(changes, expect([whole("a")]));
        // Written whole, so every path inside it is suspect.
        assert!(changes.touches(&key("a"), None));
        assert!(changes.touches(&key("a"), Some(&keys(&["host"]))));
        assert!(!changes.touches(&key("b"), None));
    }

    #[test]
    fn deleting_a_namespace_changes_the_whole_of_it() {
        let (mut store, mut chain) = setup();
        let write = set_ns(chain.head(), "a", tree());
        chain.insert(&mut store, write).unwrap();
        let envelope = delete(chain.head(), "a");

        assert_eq!(
            ingest(&mut store, &mut chain, [envelope]),
            expect([whole("a")])
        );
    }

    /// The case that makes paths worth recording at all: a write inside a
    /// namespace is not a change to its siblings.
    #[test]
    fn writing_a_key_changes_only_the_path_it_addresses() {
        let (mut store, mut chain) = setup();
        let write = set_ns(chain.head(), "a", tree());
        chain.insert(&mut store, write).unwrap();
        let envelope = set_key(
            chain.head(),
            "a",
            keys(&["host"]),
            Some(Value::String("two".to_string())),
        );

        let changes = ingest(&mut store, &mut chain, [envelope]);

        assert_eq!(changes, expect([paths("a", [keys(&["host"])])]));
        assert!(changes.touches(&key("a"), Some(&keys(&["host"]))));
        // Same namespace, a sibling path: untouched.
        assert!(!changes.touches(&key("a"), Some(&keys(&["port"]))));
        // Paths match in both directions: above the write, and below it.
        assert!(changes.touches(&key("a"), None));
        assert!(changes.touches(&key("a"), Some(&keys(&["host", "inner"]))));
    }

    #[test]
    fn clearing_a_key_changes_its_path() {
        let (mut store, mut chain) = setup();
        let write = set_ns(chain.head(), "a", tree());
        chain.insert(&mut store, write).unwrap();
        let envelope = set_key(chain.head(), "a", keys(&["host"]), None);

        assert_eq!(
            ingest(&mut store, &mut chain, [envelope]),
            expect([paths("a", [keys(&["host"])])])
        );
    }

    /// Array indices separate paths the same way map keys do.
    #[test]
    fn writing_an_index_leaves_its_siblings_untouched() {
        let (mut store, mut chain) = setup();
        let write = set_ns(chain.head(), "a", tree());
        chain.insert(&mut store, write).unwrap();
        let envelope = set_key(
            chain.head(),
            "a",
            path([Subkey::Key("tags".to_string()), Subkey::Index(0)]),
            Some(Value::String("y".to_string())),
        );

        let changes = ingest(&mut store, &mut chain, [envelope]);

        assert!(changes.touches(
            &key("a"),
            Some(&path([Subkey::Key("tags".to_string()), Subkey::Index(0)]))
        ));
        assert!(!changes.touches(
            &key("a"),
            Some(&path([Subkey::Key("tags".to_string()), Subkey::Index(1)]))
        ));
        // The array the write landed in is above it, so it matches.
        assert!(changes.touches(&key("a"), Some(&keys(&["tags"]))));
    }

    #[test]
    fn an_amend_changes_the_path_it_amends() {
        let (mut store, mut chain) = setup();
        let write = set_ns(chain.head(), "a", tree());
        chain.insert(&mut store, write).unwrap();
        let envelope = amend(
            chain.head(),
            "a",
            Some(keys(&["tags"])),
            AmendOp::AppendEntry(Value::String("y".to_string())),
        );

        let changes = ingest(&mut store, &mut chain, [envelope]);

        assert_eq!(changes, expect([paths("a", [keys(&["tags"])])]));
        assert!(!changes.touches(&key("a"), Some(&keys(&["host"]))));
    }

    /// A pathless amend transforms the namespace's own value, so there is
    /// no path to record.
    #[test]
    fn a_pathless_amend_changes_the_whole_namespace() {
        let (mut store, mut chain) = setup();
        let write = set_ns(
            chain.head(),
            "n",
            Namespace {
                value: Value::Int(1),
            },
        );
        chain.insert(&mut store, write).unwrap();
        let envelope = amend(
            chain.head(),
            "n",
            None,
            AmendOp::IncrementDecrement(IncrementDecrement::new(1)),
        );

        assert_eq!(
            ingest(&mut store, &mut chain, [envelope]),
            expect([whole("n")])
        );
    }

    #[test]
    fn a_batch_unions_what_every_envelope_touched() {
        let (mut store, mut chain) = setup();
        let write = set_ns(chain.head(), "a", tree());
        chain.insert(&mut store, write).unwrap();

        let first = set_key(
            chain.head(),
            "a",
            keys(&["host"]),
            Some(Value::String("two".to_string())),
        );
        let second = set_key(digest(&first), "a", keys(&["port"]), Some(Value::Int(2)));
        let third = set_str(digest(&second), "b", "1");

        assert_eq!(
            ingest(&mut store, &mut chain, [first, second, third]),
            expect([paths("a", [keys(&["host"]), keys(&["port"])]), whole("b"),])
        );
    }

    /// Two envelopes in one run, each writing a different namespace: both
    /// are changes, neither shadows the other.
    #[test]
    fn two_envelopes_touching_different_namespaces_both_count() {
        let (mut store, mut chain) = setup();
        let first = set_str(chain.head(), "a", "1");
        let second = set_str(digest(&first), "b", "2");

        let changes = ingest(&mut store, &mut chain, [first, second]);

        assert_eq!(changes, expect([whole("a"), whole("b")]));
        assert!(changes.touches(&key("a"), None));
        assert!(changes.touches(&key("b"), None));
    }

    /// A write over a path already recorded absorbs it: `n.b` covers
    /// everything `n.b.c` addresses, so recording both would say nothing
    /// the shallower path does not.
    #[test]
    fn a_shallower_path_absorbs_the_deeper_one_recorded_before_it() {
        let (mut store, mut chain) = setup();
        let write = set_ns(chain.head(), "n", nested());
        chain.insert(&mut store, write).unwrap();

        let first = set_key(chain.head(), "n", keys(&["b", "c"]), Some(Value::Int(9)));
        let second = set_key(
            digest(&first),
            "n",
            keys(&["b"]),
            Some(Value::Map(BTreeMap::new())),
        );

        let changes = ingest(&mut store, &mut chain, [first, second]);

        assert_eq!(changes, expect([paths("n", [keys(&["b"])])]));
        // Absorbing loses nothing: the deeper path still reads as changed.
        assert!(changes.touches(&key("n"), Some(&keys(&["b", "c"]))));
        assert!(changes.touches(&key("n"), Some(&keys(&["b", "d"]))));
    }

    /// The same, arriving the other way round: a path already covered by a
    /// shallower one is not recorded beside it.
    #[test]
    fn a_deeper_path_recorded_after_a_shallower_one_adds_nothing() {
        let (mut store, mut chain) = setup();
        let write = set_ns(chain.head(), "n", nested());
        chain.insert(&mut store, write).unwrap();

        let first = set_key(
            chain.head(),
            "n",
            keys(&["b"]),
            Some(Value::Map(BTreeMap::from([(
                "c".to_string(),
                Value::Int(1),
            )]))),
        );
        let second = set_key(digest(&first), "n", keys(&["b", "c"]), Some(Value::Int(9)));

        assert_eq!(
            ingest(&mut store, &mut chain, [first, second]),
            expect([paths("n", [keys(&["b"])])])
        );
    }

    /// A namespace written whole swallows the paths recorded beside it:
    /// nothing under it can be ruled out any more.
    #[test]
    fn a_whole_write_absorbs_the_paths_recorded_beside_it() {
        let (mut store, mut chain) = setup();
        let write = set_ns(chain.head(), "a", tree());
        chain.insert(&mut store, write).unwrap();

        let first = set_key(
            chain.head(),
            "a",
            keys(&["host"]),
            Some(Value::String("two".to_string())),
        );
        let second = set_ns(digest(&first), "a", tree());

        let changes = ingest(&mut store, &mut chain, [first, second]);

        assert_eq!(changes, expect([whole("a")]));
        assert!(changes.touches(&key("a"), Some(&keys(&["port"]))));
    }

    /// A fork that loses leaves the head where it stood, so nothing an
    /// existing reader holds has changed.
    #[test]
    fn a_losing_fork_changes_nothing() {
        let (mut store, mut chain) = setup();
        let (winner, loser) = ranked(
            set_str(chain.head(), "a", "1"),
            set_str(chain.head(), "b", "2"),
        );
        chain.insert(&mut store, winner).unwrap();

        assert!(ingest(&mut store, &mut chain, [loser]).is_empty());
    }

    /// A reorg covers the branch left behind as well as the one taken: the
    /// loser's write is rolled back, which is a change to anyone reading it.
    #[test]
    fn a_reorg_covers_both_the_branch_left_and_the_branch_taken() {
        let (mut store, mut chain) = setup();
        let (winner, loser) = ranked(
            set_str(chain.head(), "a", "1"),
            set_str(chain.head(), "b", "2"),
        );
        chain.insert(&mut store, loser).unwrap();

        assert_eq!(
            ingest(&mut store, &mut chain, [winner]),
            expect([whole("a"), whole("b")])
        );
    }

    /// A fork below the head undoes every envelope above it. The envelope
    /// the branches share is not a change — only what sits above it is.
    #[test]
    fn a_deep_reorg_undoes_every_envelope_above_the_fork() {
        let (mut store, mut chain) = setup();
        let base = set_str(chain.head(), "base", "0");
        chain.insert(&mut store, base.clone()).unwrap();

        let (winner, loser) = ranked(
            set_str(digest(&base), "a", "1"),
            set_str(digest(&base), "b", "2"),
        );
        let tail = set_str(digest(&loser), "c", "3");
        chain.insert_batch(&mut store, [loser, tail]).unwrap();

        let changes = ingest(&mut store, &mut chain, [winner.clone()]);

        assert_eq!(chain.head(), digest(&winner));
        assert_eq!(changes, expect([whole("a"), whole("b"), whole("c")]));
        // The fork point is common to both branches, so it never moved.
        assert!(!changes.touches(&key("base"), None));
    }

    /// A deep fork that loses still moves nothing, however many envelopes
    /// hang off it.
    #[test]
    fn a_deep_losing_fork_changes_nothing() {
        let (mut store, mut chain) = setup();
        let base = set_str(chain.head(), "base", "0");
        chain.insert(&mut store, base.clone()).unwrap();

        let (winner, loser) = ranked(
            set_str(digest(&base), "a", "1"),
            set_str(digest(&base), "b", "2"),
        );
        chain.insert(&mut store, winner).unwrap();
        let tail = set_str(digest(&loser), "c", "3");

        assert!(ingest(&mut store, &mut chain, [loser, tail]).is_empty());
    }

    /// Moving forward takes nothing off the chain.
    #[test]
    fn a_fast_forward_orphans_nothing() {
        let (mut store, mut chain) = setup();
        let first = set_str(chain.head(), "a", "1");
        let second = set_str(digest(&first), "b", "2");

        let movement = movement(&mut store, &mut chain, [first, second]);

        assert!(movement.orphaned.is_empty());
        assert!(!movement.changes.is_empty());
    }

    #[test]
    fn a_reorg_orphans_the_branch_left_behind() {
        let (mut store, mut chain) = setup();
        let (winner, loser) = ranked(
            set_str(chain.head(), "a", "1"),
            set_str(chain.head(), "b", "2"),
        );
        chain.insert(&mut store, loser.clone()).unwrap();

        let movement = movement(&mut store, &mut chain, [winner.clone()]);

        assert_eq!(movement.orphaned, BTreeSet::from([digest(&loser)]));
        // The winner joined the chain; it did not leave it.
        assert!(!movement.orphaned.contains(&digest(&winner)));
    }

    /// Everything above the fork goes, not just the tip that was the head.
    #[test]
    fn a_deep_reorg_orphans_every_envelope_above_the_fork() {
        let (mut store, mut chain) = setup();
        let base = set_str(chain.head(), "base", "0");
        chain.insert(&mut store, base.clone()).unwrap();

        let (winner, loser) = ranked(
            set_str(digest(&base), "a", "1"),
            set_str(digest(&base), "b", "2"),
        );
        let tail = set_str(digest(&loser), "c", "3");
        chain
            .insert_batch(&mut store, [loser.clone(), tail.clone()])
            .unwrap();

        let movement = movement(&mut store, &mut chain, [winner]);

        assert_eq!(
            movement.orphaned,
            BTreeSet::from([digest(&loser), digest(&tail)])
        );
        // The fork point stayed canonical throughout.
        assert!(!movement.orphaned.contains(&digest(&base)));
    }

    /// A fork that never won was never on the chain, so it leaves nothing.
    #[test]
    fn a_losing_fork_orphans_nothing() {
        let (mut store, mut chain) = setup();
        let (winner, loser) = ranked(
            set_str(chain.head(), "a", "1"),
            set_str(chain.head(), "b", "2"),
        );
        chain.insert(&mut store, winner).unwrap();

        assert_eq!(
            movement(&mut store, &mut chain, [loser]),
            Movement::default()
        );
    }

    /// Two chains sharing a store share no ancestor, so nothing can be said
    /// about the distance between their heads.
    #[test]
    fn heads_of_different_chains_diverge() {
        let mut store = MemStorage::default();
        let one = Chain::init(&mut store, genesis([])).unwrap();
        let two = Chain::init(&mut store, genesis([(key("a"), tree())])).unwrap();

        let err = ChangeDiffer::opened_at(one.head())
            .diff(&store, two.head())
            .unwrap_err();

        assert!(matches!(
            err,
            Error::Diverged { from, to } if from == one.head() && to == two.head()
        ));
    }
}
