//! Fork resolution over the envelopes a node has seen.

use storage::Storage;
use wire::{Envelope, EnvelopeDigest, Msg, msg::FullCheckpoint};

use crate::{ApplyError, Error, Ledger};

/// The canonical path through the envelopes to the latest state.
///
/// Unlike [`Ledger`] which faithfully replays a sequence of envelopes (i.e.
/// log messages) to arrive at a state, [`Chain`] can handle when there
/// are multiple descendant envelopes for a parent envelope, AKA a fork
/// in the chain.
///
/// The winner is decided per fork, by applying some deterministic rules.
/// An envelope that fails to apply is discarded, along with its children.
///
/// Switching branches is cheap because the store keeps the versions of
/// both: the ledger reopens at the fork point and only envelopes never
/// applied before are applied. Everything durable lives in the store —
/// the chain itself is just a cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    root: EnvelopeDigest,
    ledger: Ledger,
}

/// What [`Chain::insert`] did to the canonical head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insert {
    /// The head moved forward; the old head is an ancestor of the new.
    Extended,
    /// The canonical chain switched branches, abandoning `from`.
    Reorged {
        /// The head that was abandoned.
        from: EnvelopeDigest,
    },
    /// The head did not move: a losing fork, or an envelope the walk
    /// adjudicated against.
    Unchanged,
    /// The envelope was already in the store's log *and* the head did
    /// not move. A duplicate this cursor had not folded in yet — filed
    /// through another chain sharing the store — reports the movement
    /// instead.
    Duplicate,
}

impl Chain {
    /// Opens a chain from the `Init` envelope that starts it, filing the
    /// envelope and installing its checkpoint.
    pub fn init<S: Storage>(storage: &mut S, envelope: Envelope) -> Result<Self, Error<S::Error>> {
        let ledger = Ledger::init(storage, &envelope)?;
        let root = ledger.head();
        storage
            .put_envelope(root, envelope)
            .map_err(Error::Storage)?;
        Ok(Self { root, ledger })
    }

    /// Reopens the chain rooted at `root`, re-deriving the canonical head
    /// from the envelopes the store's log already holds — how a node
    /// resumes after a restart.
    pub fn open<S: Storage>(
        storage: &mut S,
        root: EnvelopeDigest,
    ) -> Result<Self, Error<S::Error>> {
        match storage
            .envelope(root)
            .map_err(Error::Storage)?
            .ok_or(Error::UnknownHead(root))?
            .payload()
        {
            Msg::Init(_) => {}
            _ => return Err(Error::NotInit),
        }
        let mut chain = Self {
            root,
            ledger: Ledger::open(storage, root)?,
        };
        chain.ledger = chain.canonicalize(storage)?;
        Ok(chain)
    }

    /// Files `envelope` into the store's log and re-derives the canonical
    /// head.
    ///
    /// The parent's version must be in the store: sync transmits
    /// parent-first, so an unknown — or pruned — parent is refused as
    /// [`Error::UnknownParent`], not buffered. Validation happens at the
    /// boundary: the envelope is applied on probation against its
    /// parent's version, and a failure refuses it — never filed — with
    /// the failure as the error. Losing a fork is no error, merely
    /// [`Insert::Unchanged`].
    ///
    /// Inserting always leaves the chain standing at the canonical head
    /// of everything the log holds — an envelope already filed still
    /// triggers the walk, so a cursor lagging behind a shared store
    /// catches up rather than reporting [`Insert::Duplicate`] forever.
    pub fn insert<S: Storage>(
        &mut self,
        storage: &mut S,
        envelope: Envelope,
    ) -> Result<Insert, Error<S::Error>> {
        let Some(prev) = envelope.payload().prev_digest().copied() else {
            return Err(Error::Apply(ApplyError::UnexpectedInit));
        };
        let digest = envelope.digest()?;

        // Already in the log — perhaps through another chain sharing the
        // store. Nothing to file, but the walk below still runs: this
        // cursor may not have folded it in yet.
        let already_stored = storage.envelope(digest).map_err(Error::Storage)?.is_some();

        if !already_stored {
            if !storage.contains_version(prev).map_err(Error::Storage)? {
                return Err(Error::UnknownParent(prev));
            }

            // Store the new envelope if it applies successfully.
            let mut prev_state = Ledger::open(storage, prev)?;
            prev_state.apply(storage, &envelope)?;

            storage
                .put_envelope(digest, envelope)
                .map_err(Error::Storage)?;
        }

        let from = self.ledger.head();
        self.ledger = self.canonicalize(storage)?;

        let head = self.ledger.head();
        Ok(if head != from {
            if descends(storage, head, from)? {
                Insert::Extended
            } else {
                Insert::Reorged { from }
            }
        } else if already_stored {
            Insert::Duplicate
        } else {
            Insert::Unchanged
        })
    }

    /// The canonical head — the tip fork resolution currently agrees on.
    pub fn head(&self) -> EnvelopeDigest {
        self.ledger.head()
    }

    /// The ledger standing at the canonical head.
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// The digest of the `Init` envelope this chain grew from.
    pub fn root(&self) -> EnvelopeDigest {
        self.root
    }

    /// The compaction floor in force at the canonical head. Config is
    /// namespace data, so it follows the canonical branch like the rest
    /// of the state.
    pub fn min_keep_minutes<S: Storage>(&self, storage: &S) -> Result<u32, S::Error> {
        self.ledger.min_keep_minutes(storage)
    }

    /// The canonical state as a checkpoint, ready to open a rewritten
    /// chain. The one read that is O(state): every namespace streams
    /// through memory to build it.
    pub fn checkpoint<S: Storage>(&self, storage: &S) -> Result<FullCheckpoint, S::Error> {
        self.ledger.checkpoint(storage)
    }

    /// Walks the canonical path down from the root, one [`step`](Self::step)
    /// at a time.
    fn canonicalize<S: Storage>(&self, storage: &mut S) -> Result<Ledger, Error<S::Error>> {
        let mut ledger = Ledger::open(storage, self.root)?;
        while let Some(next) = self.step(storage, &ledger)? {
            ledger = next;
        }
        Ok(ledger)
    }

    /// One canonical step down from `ledger`: the lowest-digest child that
    /// is valid, or `None` at a tip.
    fn step<S: Storage>(
        &self,
        storage: &mut S,
        ledger: &Ledger,
    ) -> Result<Option<Ledger>, Error<S::Error>> {
        // Collected because applying below needs the store mutably.
        let children: Vec<EnvelopeDigest> = storage
            .children(ledger.head())
            .collect::<Result<_, _>>()
            .map_err(Error::Storage)?;

        for child in children {
            // A version at the child means it applied before — digests pin
            // content, so it can only be this envelope's result.
            if storage.contains_version(child).map_err(Error::Storage)? {
                return Ok(Some(Ledger::open(storage, child)?));
            }
            let envelope = storage
                .envelope(child)
                .map_err(Error::Storage)?
                .expect("children indexes only filed envelopes");
            let mut candidate = *ledger;
            match candidate.apply(storage, &envelope) {
                Ok(()) => return Ok(Some(candidate)),
                Err(ApplyError::Storage(err)) => return Err(Error::Storage(err)),
                // Deterministic rejection: this envelope can never be
                // canonical, so drop it rather than re-refuse it on every
                // future walk. The fork falls to the next sibling.
                Err(_) => storage.remove_envelope(child).map_err(Error::Storage)?,
            }
        }
        Ok(None)
    }
}

/// Whether `ancestor` lies on the path from `digest` back to the root.
fn descends<S: Storage>(
    storage: &S,
    digest: EnvelopeDigest,
    ancestor: EnvelopeDigest,
) -> Result<bool, Error<S::Error>> {
    let mut cursor = Some(digest);
    while let Some(current) = cursor {
        if current == ancestor {
            return Ok(true);
        }
        cursor = storage
            .envelope(current)
            .map_err(Error::Storage)?
            .and_then(|envelope| envelope.payload().prev_digest().copied());
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use storage::MemStorage;
    use wire::{
        Msg,
        msg::{
            DeleteNamespace, FullCheckpoint, InitMsg, Namespace, NamespaceKey, SetNamespace, Value,
        },
    };

    use super::*;
    use crate::MIN_KEEP_MINUTES_KEY;

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

    fn setup() -> (MemStorage, Chain) {
        let mut store = MemStorage::default();
        let chain = Chain::init(&mut store, init()).unwrap();
        (store, chain)
    }

    fn digest(envelope: &Envelope) -> EnvelopeDigest {
        envelope.digest().unwrap()
    }

    /// Splits two sibling envelopes into (winner, loser) by the fork rule.
    fn ranked(a: Envelope, b: Envelope) -> (Envelope, Envelope) {
        if digest(&a) < digest(&b) {
            (a, b)
        } else {
            (b, a)
        }
    }

    /// The namespace key a `SetNamespace` envelope writes.
    fn key_of(envelope: &Envelope) -> NamespaceKey {
        match envelope.payload() {
            Msg::SetNamespace(set) => set.key.clone(),
            _ => unreachable!("test envelopes are SetNamespace"),
        }
    }

    fn has(store: &MemStorage, chain: &Chain, k: &NamespaceKey) -> bool {
        chain.ledger().namespace(store, k).unwrap().is_some()
    }

    #[test]
    fn insert_extends_the_chain() {
        let (mut store, mut chain) = setup();
        let envelope = set(chain.head(), "a", "1");

        assert_eq!(
            chain.insert(&mut store, envelope.clone()).unwrap(),
            Insert::Extended
        );
        assert_eq!(chain.head(), digest(&envelope));
        assert!(has(&store, &chain, &key("a")));
    }

    /// Of two children contesting one parent, the lower digest wins; the
    /// loser arriving second changes nothing.
    #[test]
    fn a_losing_fork_leaves_the_head_alone() {
        let (mut store, mut chain) = setup();
        let (winner, loser) = ranked(set(chain.head(), "a", "1"), set(chain.head(), "b", "2"));

        chain.insert(&mut store, winner.clone()).unwrap();
        assert_eq!(
            chain.insert(&mut store, loser.clone()).unwrap(),
            Insert::Unchanged
        );

        assert_eq!(chain.head(), digest(&winner));
        assert!(has(&store, &chain, &key_of(&winner)));
        assert!(!has(&store, &chain, &key_of(&loser)));
    }

    /// The winner arriving second reorgs the head: the loser's write is
    /// rolled back, the winner's takes its place.
    #[test]
    fn a_winning_fork_reorgs_the_head() {
        let (mut store, mut chain) = setup();
        let (winner, loser) = ranked(set(chain.head(), "a", "1"), set(chain.head(), "b", "2"));

        chain.insert(&mut store, loser.clone()).unwrap();
        assert_eq!(
            chain.insert(&mut store, winner.clone()).unwrap(),
            Insert::Reorged {
                from: digest(&loser)
            }
        );

        assert_eq!(chain.head(), digest(&winner));
        assert!(has(&store, &chain, &key_of(&winner)));
        assert!(!has(&store, &chain, &key_of(&loser)));
    }

    /// One low digest at the fork beats any number of descendants on the
    /// other side — there is no notion of chain length or weight.
    #[test]
    fn a_longer_losing_branch_stays_losing() {
        let (mut store, mut chain) = setup();
        let (winner, loser) = ranked(set(chain.head(), "a", "1"), set(chain.head(), "b", "2"));

        chain.insert(&mut store, loser.clone()).unwrap();
        let tail = set(digest(&loser), "c", "3");
        assert_eq!(
            chain.insert(&mut store, tail.clone()).unwrap(),
            Insert::Extended
        );

        assert_eq!(
            chain.insert(&mut store, winner.clone()).unwrap(),
            Insert::Reorged {
                from: digest(&tail)
            }
        );
        assert_eq!(chain.head(), digest(&winner));

        // Growing the losing branch further changes nothing…
        let more = set(digest(&tail), "d", "4");
        assert_eq!(chain.insert(&mut store, more).unwrap(), Insert::Unchanged);

        // …while the winning branch extends normally.
        let next = set(chain.head(), "e", "5");
        assert_eq!(
            chain.insert(&mut store, next.clone()).unwrap(),
            Insert::Extended
        );
        assert_eq!(chain.head(), digest(&next));
    }

    /// Sync transmits parent-first from the intersection point, so a
    /// parent the log doesn't hold is a protocol breach, not a gap to
    /// buffer around.
    #[test]
    fn an_unknown_parent_is_rejected() {
        let (mut store, mut chain) = setup();
        let parent = set(chain.head(), "a", "1");
        let child = set(digest(&parent), "b", "2");

        let err = chain.insert(&mut store, child.clone()).unwrap_err();
        assert!(matches!(err, Error::UnknownParent(p) if p == digest(&parent)));
        assert_eq!(store.envelope(digest(&child)).unwrap(), None, "never filed");
        assert_eq!(chain.head(), chain.root(), "head must not move");

        // Delivered in order, both land.
        chain.insert(&mut store, parent).unwrap();
        assert_eq!(
            chain.insert(&mut store, child.clone()).unwrap(),
            Insert::Extended
        );
        assert_eq!(chain.head(), digest(&child));
    }

    /// When the parent's state is at hand, an envelope that fails to apply
    /// is refused with the failure itself — and never filed.
    #[test]
    fn an_invalid_envelope_is_refused_at_the_door() {
        let (mut store, mut chain) = setup();
        // Deleting a namespace that doesn't exist fails validation.
        let bad = delete(chain.head(), "nope");

        let err = chain.insert(&mut store, bad.clone()).unwrap_err();
        assert!(matches!(
            err,
            Error::Apply(ApplyError::UnknownNamespace(k)) if k == key("nope")
        ));

        assert_eq!(store.envelope(digest(&bad)).unwrap(), None, "never filed");
        assert_eq!(chain.head(), chain.root(), "head must not move");
    }

    /// A parent whose version was pruned can't back a probation, so its
    /// children are refused rather than filed unvalidated.
    #[test]
    fn a_pruned_parent_refuses_new_children() {
        let (mut store, mut chain) = setup();
        let parent = set(chain.head(), "a", "1");
        chain.insert(&mut store, parent.clone()).unwrap();

        // Prune every version but the root; the parent survives only in
        // the log.
        store.retain(&[chain.root()]).unwrap();

        let child = set(digest(&parent), "b", "2");
        assert!(matches!(
            chain.insert(&mut store, child.clone()).unwrap_err(),
            Error::UnknownParent(p) if p == digest(&parent)
        ));
        assert_eq!(store.envelope(digest(&child)).unwrap(), None, "never filed");
        assert_eq!(chain.head(), digest(&parent), "head must not move");
    }

    /// `insert` files only validated envelopes, but the walk stays
    /// defensive: an invalid envelope that reached the log some other
    /// way is dropped the moment the walk finds it out.
    #[test]
    fn the_walk_drops_an_invalid_envelope_from_the_log() {
        let (mut store, mut chain) = setup();
        let bad = delete(chain.head(), "nope");
        store.put_envelope(digest(&bad), bad.clone()).unwrap();

        // Grind until the valid sibling loses the digest race, so the
        // walk must adjudicate `bad` before reaching it.
        let good = (0..)
            .map(|i| set(chain.head(), "a", &format!("v{i}")))
            .find(|e| digest(e) > digest(&bad))
            .expect("some value hashes above bad");
        chain.insert(&mut store, good.clone()).unwrap();

        assert_eq!(chain.head(), digest(&good));
        assert_eq!(store.envelope(digest(&bad)).unwrap(), None, "dropped");
    }

    #[test]
    fn a_duplicate_is_reported_and_ignored() {
        let (mut store, mut chain) = setup();
        let envelope = set(chain.head(), "a", "1");

        chain.insert(&mut store, envelope.clone()).unwrap();
        assert_eq!(
            chain.insert(&mut store, envelope.clone()).unwrap(),
            Insert::Duplicate
        );
        assert_eq!(chain.head(), digest(&envelope));

        // Even the chain's own Init is refused rather than deduped —
        // Init envelopes never travel through insert.
        assert!(matches!(
            chain.insert(&mut store, init()),
            Err(Error::Apply(ApplyError::UnexpectedInit))
        ));
    }

    /// Chains share a store: an envelope filed by one is a duplicate to
    /// the other's log, but a lagging cursor must still fold it in
    /// rather than staying stale behind [`Insert::Duplicate`].
    #[test]
    fn a_duplicate_still_advances_a_lagging_chain() {
        let mut store = MemStorage::default();
        let mut leader = Chain::init(&mut store, init()).unwrap();
        let mut follower = Chain::init(&mut store, init()).unwrap();

        let envelope = set(leader.head(), "a", "1");
        leader.insert(&mut store, envelope.clone()).unwrap();
        assert_eq!(follower.head(), follower.root(), "not folded in yet");

        assert_eq!(
            follower.insert(&mut store, envelope.clone()).unwrap(),
            Insert::Extended
        );
        assert_eq!(follower.head(), leader.head());

        // Caught up, the same envelope is a true duplicate.
        assert_eq!(
            follower.insert(&mut store, envelope).unwrap(),
            Insert::Duplicate
        );
    }

    /// A *different* `Init` starts a different chain; it cannot be folded
    /// into this one.
    #[test]
    fn a_second_init_is_rejected() {
        let (mut store, mut chain) = setup();
        let foreign = Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: [(key("x"), ns("1"))].into_iter().collect(),
            },
        }));

        assert!(matches!(
            chain.insert(&mut store, foreign),
            Err(Error::Apply(ApplyError::UnexpectedInit))
        ));
    }

    fn set_minutes(prev: EnvelopeDigest, minutes: i64) -> Envelope {
        Envelope::new(Msg::SetNamespace(SetNamespace {
            prev,
            key: key(MIN_KEEP_MINUTES_KEY),
            namespace: Namespace {
                value: Value::Int(minutes),
            },
        }))
    }

    /// Config is namespace data like any other: it follows the canonical
    /// branch, so a reorg can change what's in force.
    #[test]
    fn config_follows_the_canonical_branch() {
        let (mut store, mut chain) = setup();
        let (winner, loser) = ranked(
            set_minutes(chain.head(), 100),
            set_minutes(chain.head(), 200),
        );
        let minutes = |envelope: &Envelope| match envelope.payload() {
            Msg::SetNamespace(set) => match set.namespace.value {
                Value::Int(minutes) => u32::try_from(minutes).unwrap(),
                _ => unreachable!("both envelopes set an integer"),
            },
            _ => unreachable!("both envelopes are SetNamespace"),
        };

        chain.insert(&mut store, loser.clone()).unwrap();
        assert_eq!(chain.min_keep_minutes(&store).unwrap(), minutes(&loser));

        chain.insert(&mut store, winner.clone()).unwrap();
        assert_eq!(chain.head(), digest(&winner));
        assert_eq!(chain.min_keep_minutes(&store).unwrap(), minutes(&winner));
    }

    /// Everything durable lives in the store, so a chain reopened from
    /// its root digest alone stands exactly where the original did.
    #[test]
    fn open_rederives_the_canonical_head() {
        let (mut store, mut chain) = setup();
        let (winner, loser) = ranked(set(chain.head(), "a", "1"), set(chain.head(), "b", "2"));
        chain.insert(&mut store, loser).unwrap();
        chain.insert(&mut store, winner).unwrap();
        chain
            .insert(&mut store, set_minutes(chain.head(), 42))
            .unwrap();

        let reopened = Chain::open(&mut store, chain.root()).unwrap();
        assert_eq!(reopened.head(), chain.head());
        assert_eq!(reopened.ledger(), chain.ledger());
        assert_eq!(reopened.min_keep_minutes(&store).unwrap(), 42);
    }

    /// Reopening survives pruned mid-chain versions: what `retain` drops
    /// is re-derived from the envelope log.
    #[test]
    fn open_rebuilds_pruned_versions_from_the_log() {
        let (mut store, mut chain) = setup();
        let first = set(chain.head(), "a", "1");
        chain.insert(&mut store, first.clone()).unwrap();
        let second = set(chain.head(), "b", "2");
        chain.insert(&mut store, second).unwrap();

        // Keep only the root; the two applied versions are re-derived.
        storage::Storage::retain(&mut store, &[chain.root()]).unwrap();

        let reopened = Chain::open(&mut store, chain.root()).unwrap();
        assert_eq!(reopened.head(), chain.head());
        assert!(has(&store, &reopened, &key("a")));
        assert!(has(&store, &reopened, &key("b")));
    }

    /// Convergence: every parent-first arrival order of the same
    /// envelopes ends at the same head with the same state — the
    /// property sync depends on.
    #[test]
    fn arrival_order_does_not_matter() {
        let root = digest(&init());
        let a = set(root, "a", "1");
        let b = set(root, "b", "2");
        let c = set(digest(&a), "c", "3");
        let envelopes = [a, b, c];

        // Every order that delivers `a` before its child `c`.
        let outcomes: Vec<_> = [[0, 1, 2], [0, 2, 1], [1, 0, 2]]
            .iter()
            .map(|order| {
                let (mut store, mut chain) = setup();
                order.iter().for_each(|&i| {
                    chain.insert(&mut store, envelopes[i].clone()).unwrap();
                });
                (chain.head(), chain.checkpoint(&store).unwrap())
            })
            .collect();

        assert!(outcomes.windows(2).all(|pair| pair[0] == pair[1]));
    }
}
