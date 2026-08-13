//! Fork resolution over the envelopes a node has seen.

use storage::Storage;
use wire::{
    Envelope, EnvelopeDigest, Msg,
    msg::{FullCheckpoint, LedgerConfig},
};

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
    /// The envelope was already in the store's log.
    Duplicate,
}

impl Chain {
    /// Opens a chain from the `Init` envelope that starts it, filing the
    /// envelope and installing its checkpoint.
    pub fn init<S: Storage>(storage: &mut S, envelope: Envelope) -> Result<Self, Error<S::Error>> {
        let ledger = Ledger::init(storage, &envelope)?;
        Ok(Self {
            root: ledger.head(),
            ledger,
        })
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
    /// The parent must already be in the log — sync transmits parent-first
    /// from the intersection point, so an unknown parent is refused as
    /// [`Error::UnknownParent`], not buffered. Validation happens at the
    /// boundary: the envelope is applied on probation against its
    /// parent's version, and a failure refuses it — never filed — with
    /// the failure as the error. (A parent whose version was pruned can't
    /// back a probation; then the envelope is filed as-is and checked
    /// when the walk re-derives that branch.) Losing a fork is no error,
    /// merely [`Insert::Unchanged`].
    pub fn insert<S: Storage>(
        &mut self,
        storage: &mut S,
        envelope: Envelope,
    ) -> Result<Insert, Error<S::Error>> {
        let digest = envelope.digest()?;
        if storage.envelope(digest).map_err(Error::Storage)?.is_some() {
            return Ok(Insert::Duplicate);
        }
        let Some(prev) = envelope.payload().prev_digest().copied() else {
            return Err(Error::Apply(ApplyError::UnexpectedInit));
        };

        if storage.contains_version(prev).map_err(Error::Storage)? {
            // Probation: commits the child version on success, which the
            // walk below picks up instead of re-applying.
            Ledger::open(storage, prev)?.apply(storage, &envelope)?;
        } else if storage.envelope(prev).map_err(Error::Storage)?.is_none() {
            return Err(Error::UnknownParent(prev));
        }
        storage
            .put_envelope(digest, envelope)
            .map_err(Error::Storage)?;

        let from = self.ledger.head();
        self.ledger = self.canonicalize(storage)?;

        let head = self.ledger.head();
        Ok(if head == from {
            Insert::Unchanged
        } else if descends(storage, head, from)? {
            Insert::Extended
        } else {
            Insert::Reorged { from }
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

    /// The configuration in force at the canonical head, folded out of
    /// the messages on the canonical path.
    pub fn config(&self) -> &LedgerConfig {
        self.ledger.config()
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
            let envelope = storage
                .envelope(child)
                .map_err(Error::Storage)?
                .expect("children indexes only filed envelopes");
            // A version at the child means it applied before — digests pin
            // content, so it can only be this envelope's result. The
            // cursor still folds over the envelope for the config.
            if storage.contains_version(child).map_err(Error::Storage)? {
                let mut next = ledger.clone();
                next.advance(&envelope)?;
                return Ok(Some(next));
            }
            let mut candidate = ledger.clone();
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
            DeleteNamespace, FullCheckpoint, InitMsg, MinKeepMinutes, Namespace, NamespaceKey,
            SetNamespace, Value,
        },
    };

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

    /// A filed parent whose version was pruned can't back a probation;
    /// the envelope is filed as-is and adjudicated when the walk
    /// re-derives that branch — where an invalid one is dropped from
    /// the log.
    #[test]
    fn a_pruned_parent_defers_validation_to_the_walk() {
        let (mut store, mut chain) = setup();
        let parent = set(chain.head(), "a", "1");
        chain.insert(&mut store, parent.clone()).unwrap();

        // Prune every version but the root; the parent survives only in
        // the log.
        store.retain(&[chain.root()]).unwrap();

        let bad = delete(digest(&parent), "nope");
        assert_eq!(
            chain.insert(&mut store, bad.clone()).unwrap(),
            Insert::Unchanged
        );

        assert_eq!(chain.head(), digest(&parent));
        assert!(has(&store, &chain, &key("a")), "the branch was re-derived");
        assert_eq!(
            store.envelope(digest(&bad)).unwrap(),
            None,
            "dropped when the walk rejected it"
        );

        // Refiling it is now checkable directly — refused at the door.
        assert!(matches!(
            chain.insert(&mut store, bad),
            Err(Error::Apply(ApplyError::UnknownNamespace(k))) if k == key("nope")
        ));
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

        // The chain's own Init counts as already present.
        assert_eq!(chain.insert(&mut store, init()).unwrap(), Insert::Duplicate);
    }

    /// A *different* `Init` starts a different chain; it cannot be folded
    /// into this one.
    #[test]
    fn a_second_init_is_rejected() {
        let (mut store, mut chain) = setup();
        let foreign = Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: [(key("x"), ns("1"))].into_iter().collect(),
                ..Default::default()
            },
        }));

        assert!(matches!(
            chain.insert(&mut store, foreign),
            Err(Error::Apply(ApplyError::UnexpectedInit))
        ));
    }

    fn set_config(prev: EnvelopeDigest, minutes: u32) -> Envelope {
        Envelope::new(Msg::SetConfig(wire::msg::SetConfig {
            prev,
            config: LedgerConfig {
                min_keep_minutes: MinKeepMinutes::new(minutes),
            },
        }))
    }

    /// Config is state like any other: it follows the canonical branch,
    /// so a reorg can change what's in force.
    #[test]
    fn config_follows_the_canonical_branch() {
        let (mut store, mut chain) = setup();
        let (winner, loser) = ranked(set_config(chain.head(), 100), set_config(chain.head(), 200));
        let minutes = |envelope: &Envelope| match envelope.payload() {
            Msg::SetConfig(set) => set.config.min_keep_minutes,
            _ => unreachable!("both envelopes are SetConfig"),
        };

        chain.insert(&mut store, loser.clone()).unwrap();
        assert_eq!(chain.config().min_keep_minutes, minutes(&loser));

        chain.insert(&mut store, winner.clone()).unwrap();
        assert_eq!(chain.head(), digest(&winner));
        assert_eq!(chain.config().min_keep_minutes, minutes(&winner));
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
            .insert(&mut store, set_config(chain.head(), 42))
            .unwrap();

        let reopened = Chain::open(&mut store, chain.root()).unwrap();
        assert_eq!(reopened.head(), chain.head());
        assert_eq!(reopened.ledger(), chain.ledger());
        assert_eq!(reopened.config().min_keep_minutes, MinKeepMinutes::new(42));
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
