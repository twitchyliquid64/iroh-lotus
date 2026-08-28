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
/// The winner is decided per fork, by applying some deterministic rules:
/// highest verified signature weight first, then highest digest. A winning
/// envelope that fails to apply is discarded — along with its children —
/// and the failure surfaces as the walk's error; the losing siblings are
/// never adopted in its place until the next walk.
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
    /// The head did not move: a losing fork.
    Unchanged,
    /// The envelope was already in the store's log *and* the head did
    /// not move. A duplicate this cursor had not folded in yet — stored
    /// through another chain sharing the store — reports the movement
    /// instead.
    Duplicate,
}

impl Chain {
    /// Opens a chain from the `Init` envelope that starts it, storing the
    /// envelope and installing its checkpoint.
    pub fn init<S: Storage>(
        storage: &mut S,
        mut envelope: Envelope,
    ) -> Result<Self, Error<S::Error>> {
        let ledger = Ledger::init(storage, &envelope)?;
        let root = ledger.head();

        // Genesis has no parent, so its signatures are verified against
        // the key set it installs itself. Circular by nature: trusting a
        // root is the operator's decision, not something the chain can
        // attest to.
        let status = ledger.verify_envelope(storage, &envelope)?;
        envelope.set_verification_status(status);

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

    /// Stores `envelope` in the log and re-derives the canonical head.
    ///
    /// The parent's version must be in the store: sync transmits
    /// parent-first, so an unknown — or pruned — parent is refused as
    /// [`Error::UnknownParent`], not buffered. Validation happens at the
    /// boundary: the envelope is applied on a trial ledger against its
    /// parent's version, and a failure refuses it — never stored — with
    /// the failure as the error. Losing a fork is no error, merely
    /// [`Insert::Unchanged`].
    ///
    /// Inserting always leaves the chain standing at the canonical head
    /// of everything the log holds — an envelope already stored still
    /// triggers the walk, so a cursor lagging behind a shared store
    /// catches up rather than reporting [`Insert::Duplicate`] forever.
    pub fn insert<S: Storage>(
        &mut self,
        storage: &mut S,
        envelope: Envelope,
    ) -> Result<Insert, Error<S::Error>> {
        self.insert_batch(storage, [envelope])
    }

    /// Stores a parent-first linear run of envelopes in the log and
    /// re-derives the canonical head once, at the end — one walk per
    /// batch instead of one per envelope, which is what sync should use.
    ///
    /// The run must be continuous: each envelope chains onto the one
    /// before it — a gap is refused as [`ApplyError::ChainMismatch`] —
    /// and the first parent's version must be in the store, as
    /// [`insert`](Self::insert). The run may start anywhere a version
    /// stands, a losing branch included.
    ///
    /// Validation is one trial ledger advanced across the run, so a
    /// refusal keeps the valid prefix: everything before the fault is
    /// stored, nothing at or after it is, and the walk still runs before
    /// the error returns — the head never lags what was stored. The walk
    /// itself can also refuse: a stored envelope that wins its fork but
    /// fails to apply is dropped from the log and its failure is the
    /// error, leaving the head where it stood until the next walk. Envelopes
    /// already in the log are folded in without re-judgment (what's
    /// stored is the walk's to adjudicate); [`Insert::Duplicate`] means a
    /// non-empty run of nothing but duplicates that moved nothing. An
    /// empty run just re-walks.
    pub fn insert_batch<S: Storage>(
        &mut self,
        storage: &mut S,
        envelopes: impl IntoIterator<Item = Envelope>,
    ) -> Result<Insert, Error<S::Error>> {
        let stored = self.store_batch(storage, envelopes);

        let from = self.ledger.head();
        self.ledger = self.canonicalize(storage)?;
        let all_duplicates = stored?;

        let head = self.ledger.head();
        Ok(if head != from {
            if descends(storage, head, from)? {
                Insert::Extended
            } else {
                Insert::Reorged { from }
            }
        } else if all_duplicates {
            Insert::Duplicate
        } else {
            Insert::Unchanged
        })
    }

    /// Validates and stores a linear run of envelopes. Returns whether
    /// the run was non-empty and every envelope was already in the log.
    ///
    /// `trial` drops to `None` at a stored envelope this run can't
    /// stand on — its version pruned with no parent version to re-derive
    /// it from, or one that no longer applies. That is the walk's
    /// business, not a refusal; only a *new* envelope downstream turns
    /// the missing footing into [`Error::UnknownParent`].
    fn store_batch<S: Storage>(
        &self,
        storage: &mut S,
        envelopes: impl IntoIterator<Item = Envelope>,
    ) -> Result<bool, Error<S::Error>> {
        let mut trial: Option<Ledger> = None;
        let mut last: Option<EnvelopeDigest> = None;
        let mut all_duplicates = true;

        for mut envelope in envelopes {
            let Some(prev) = envelope.payload().prev_digest().copied() else {
                return Err(Error::Apply(ApplyError::UnexpectedInit));
            };
            if let Some(expected) = last.filter(|&expected| expected != prev) {
                return Err(Error::Apply(ApplyError::ChainMismatch {
                    expected,
                    found: prev,
                }));
            }
            let digest = envelope.digest()?;
            last = Some(digest);

            let stored = storage.envelope(digest).map_err(Error::Storage)?.is_some();
            all_duplicates &= stored;

            // The ledger standing at `prev`, the parents state. Used to get at
            // the config and trusted key set to verify signatures.
            let parent = match trial.take() {
                Some(ledger) => Some(ledger),
                None => storage
                    .contains_version(prev)
                    .map_err(Error::Storage)?
                    .then(|| Ledger::open(storage, prev))
                    .transpose()?,
            };
            if !stored && let Some(parent) = parent {
                let status = parent.verify_envelope(storage, &envelope)?;
                envelope.set_verification_status(status);
            }

            if storage.contains_version(digest).map_err(Error::Storage)? {
                // A version at the digest means it applied before —
                // digests pin content, so it can only be this envelope's
                // result.
                //
                // Only taken into the log if it could be verified. With
                // the parent's version pruned there is no key set to verify
                // against, and an envelope stored `Unchecked` would rank
                // at zero for good: nothing later can recover a weight
                // whose parent is gone. Leaving the log as it was keeps
                // this a no-op rather than a downgrade.
                if !stored && parent.is_some() {
                    storage
                        .put_envelope(digest, envelope)
                        .map_err(Error::Storage)?;
                }
                trial = Some(Ledger::open(storage, digest)?);
                continue;
            }

            let Some(mut ledger) = parent else {
                if stored {
                    continue;
                }
                return Err(Error::UnknownParent(prev));
            };
            match ledger.apply(storage, &envelope) {
                Ok(()) => {
                    if !stored {
                        storage
                            .put_envelope(digest, envelope)
                            .map_err(Error::Storage)?;
                    }
                    trial = Some(ledger);
                }
                Err(ApplyError::Storage(err)) => return Err(Error::Storage(err)),
                Err(err) if !stored => return Err(err.into()),
                // Swallowed on purpose: a stored envelope that no longer
                // applies is the walk's to adjudicate and drop, exactly
                // as if it had arrived through another chain.
                Err(_) => {}
            }
        }
        Ok(last.is_some() && all_duplicates)
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

    /// Whether `digest` lies on the canonical path — the walk back from
    /// the head to the root, which is O(chain) in envelope reads.
    ///
    /// A digest the log never held answers `false` the same as one that
    /// lost a fork: to a reader, off the chain is off the chain.
    pub fn contains<S: Storage>(
        &self,
        storage: &S,
        digest: EnvelopeDigest,
    ) -> Result<bool, Error<S::Error>> {
        descends(storage, self.head(), digest)
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

    /// One canonical step down from `ledger`: the winning child, or `None`
    /// at a tip.
    ///
    /// The winner is the child with the highest verified signature weight,
    /// ties broken by the numerically higher digest. Siblings are never
    /// consulted: a winner that fails to apply is dropped from the log and
    /// the failure is the walk's error.
    fn step<S: Storage>(
        &self,
        storage: &mut S,
        ledger: &Ledger,
    ) -> Result<Option<Ledger>, Error<S::Error>> {
        // Collected because the envelope reads below need the store again.
        let children: Vec<EnvelopeDigest> = storage
            .children(ledger.head())
            .collect::<Result<_, _>>()
            .map_err(Error::Storage)?;

        let candidates: Vec<(u32, EnvelopeDigest, Envelope)> = children
            .into_iter()
            .map(|child| {
                storage.envelope(child).map_err(Error::Storage).map(|env| {
                    let envelope = env.expect("children indexes only stored envelopes");
                    let weight = envelope.verification_status().signature_weight();
                    (weight, child, envelope)
                })
            })
            .collect::<Result<_, _>>()?;

        let Some((_, child, envelope)) = candidates
            .into_iter()
            .max_by_key(|(weight, digest, _)| (*weight, *digest))
        else {
            return Ok(None);
        };

        // A version at the child means it applied before — digests pin
        // content, so it can only be this envelope's result.
        if storage.contains_version(child).map_err(Error::Storage)? {
            return Ok(Some(Ledger::open(storage, child)?));
        }

        let mut candidate = *ledger;
        match candidate.apply(storage, &envelope) {
            Ok(()) => Ok(Some(candidate)),
            Err(ApplyError::Storage(err)) => Err(Error::Storage(err)),
            // Deterministic rejection: this envelope can never be canonical.
            // Drop it before erroring, or every future walk would wedge on
            // re-refusing it.
            Err(err) => {
                storage.remove_envelope(child).map_err(Error::Storage)?;
                Err(err.into())
            }
        }
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
    use ed25519_zebra::SigningKey;
    use storage::MemStorage;
    use wire::{
        Msg, VerificationStatus,
        keys::{Ed25519PublicKey, Ed25519Signature, Key, PublicKey, Signature},
        msg::{
            DeleteNamespace, FullCheckpoint, InitMsg, Namespace, NamespaceKey, SetNamespace, Value,
        },
    };

    use super::*;
    use crate::{MIN_KEEP_MINUTES_KEY, TRUSTED_KEYS_KEY};

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

    fn public_key(signing: &SigningKey) -> PublicKey {
        PublicKey::Ed25519(Ed25519PublicKey::from_bytes(
            signing.verification_key().into(),
        ))
    }

    /// Signs `envelope`'s signature digest and files it under the signer's
    /// key id. Attaching a signature never changes that digest, so this
    /// composes however many times.
    fn sign(envelope: Envelope, signing: &SigningKey) -> Envelope {
        let digest = envelope.signature_digest().unwrap();
        let signature = Signature::Ed25519(Ed25519Signature::from_bytes(
            signing.sign(digest.as_bytes()).to_bytes(),
        ));
        envelope.with_signature(public_key(signing).id(), signature)
    }

    /// A chain whose genesis already trusts `keys`.
    fn signed_setup(keys: impl IntoIterator<Item = Key>) -> (MemStorage, Chain) {
        let trusted = Value::Map(
            keys.into_iter()
                .map(|key| (key.id().to_hex().as_ref().to_string(), Value::Key(key)))
                .collect(),
        );
        let mut store = MemStorage::default();
        let chain = Chain::init(
            &mut store,
            Envelope::new(Msg::Init(InitMsg {
                state: FullCheckpoint {
                    namespaces: [(key(TRUSTED_KEYS_KEY), Namespace { value: trusted })]
                        .into_iter()
                        .collect(),
                },
            })),
        )
        .unwrap();
        (store, chain)
    }

    /// The status is computed before the envelope is persisted, so the
    /// walk reads a weight rather than an `Unchecked` placeholder.
    #[test]
    fn inserting_persists_the_verification_status() {
        let alice = SigningKey::from([1u8; 32]);
        let (mut store, mut chain) = signed_setup([Key::new(public_key(&alice), 3)]);

        let envelope = set(chain.head(), "a", "1");
        let signed = sign(envelope.clone(), &alice);
        let digest = digest(&signed);
        chain.insert(&mut store, signed).unwrap();

        assert_eq!(
            store
                .envelope(digest)
                .unwrap()
                .unwrap()
                .verification_status(),
            &VerificationStatus::AllMatched { total_weight: 3 }
        );
    }

    /// Genesis is verified against the key set it installs itself.
    #[test]
    fn init_verifies_against_its_own_checkpoint() {
        let (store, chain) = signed_setup([]);
        assert_eq!(
            store
                .envelope(chain.root())
                .unwrap()
                .unwrap()
                .verification_status(),
            &VerificationStatus::AllMatched { total_weight: 0 }
        );
    }

    /// The payoff: at a fork the heavier envelope wins, whichever way the
    /// digests happen to fall — signature weight outranks the tiebreak.
    #[test]
    fn the_heavier_fork_wins_regardless_of_digest() {
        let alice = SigningKey::from([1u8; 32]);
        let (mut store, mut chain) = signed_setup([Key::new(public_key(&alice), 3)]);
        let head = chain.head();

        let heavy_unsigned = set(head, "a", "heavy");
        let heavy = sign(heavy_unsigned.clone(), &alice);

        // Pick the unsigned sibling so that it outranks the signed one on
        // the digest tiebreak — a weightless walk would choose it, so the
        // signed one can only win on weight.
        let light = (0..64)
            .map(|n| set(head, "a", &format!("light{n}")))
            .find(|light| digest(light) > digest(&heavy))
            .expect("some sibling digest exceeds the signed one's");

        chain.insert(&mut store, light).unwrap();
        chain.insert(&mut store, heavy.clone()).unwrap();

        assert_eq!(chain.head(), digest(&heavy));
        assert_eq!(
            chain.ledger().namespace(&store, &key("a")).unwrap(),
            Some(ns("heavy"))
        );
    }

    /// A signature that does not verify is not a refusal: the envelope is
    /// stored, worth nothing, and loses every fork it is in.
    #[test]
    fn a_failed_signature_stores_at_zero_weight() {
        let alice = SigningKey::from([1u8; 32]);
        let mallory = SigningKey::from([9u8; 32]);
        let (mut store, mut chain) = signed_setup([Key::new(public_key(&alice), 3)]);

        let envelope = set(chain.head(), "a", "1");
        let signed = sign(envelope.clone(), &mallory);
        let digest = digest(&signed);

        chain.insert(&mut store, signed).unwrap();

        assert_eq!(chain.head(), digest, "unopposed, it is still canonical");
        assert_eq!(
            store
                .envelope(digest)
                .unwrap()
                .unwrap()
                .verification_status(),
            &VerificationStatus::Failed
        );
    }

    /// Re-offering an envelope the log already holds must not disturb the
    /// status it was stored with — a peer's copy arrives `Unchecked`, and
    /// taking it would silently drop the envelope's weight to zero.
    #[test]
    fn re_inserting_does_not_downgrade_a_stored_status() {
        let alice = SigningKey::from([1u8; 32]);
        let (mut store, mut chain) = signed_setup([Key::new(public_key(&alice), 3)]);

        let envelope = set(chain.head(), "a", "1");
        let signed = sign(envelope.clone(), &alice);
        let d = digest(&signed);
        chain.insert(&mut store, signed.clone()).unwrap();

        let mut peer_copy = signed;
        peer_copy.set_verification_status(VerificationStatus::Unchecked);
        assert_eq!(
            chain.insert(&mut store, peer_copy).unwrap(),
            Insert::Duplicate
        );

        assert_eq!(
            store.envelope(d).unwrap().unwrap().verification_status(),
            &VerificationStatus::AllMatched { total_weight: 3 }
        );
    }

    /// Compaction can prune the version an envelope's weight was taken
    /// from. Re-offered after that, it cannot be verified — so it is not
    /// taken into the log at all, rather than taken in at zero.
    #[test]
    fn an_envelope_that_cannot_be_verified_is_not_stored() {
        let alice = SigningKey::from([1u8; 32]);
        let (mut store, mut chain) = signed_setup([Key::new(public_key(&alice), 3)]);
        let root = chain.head();

        let a = set(root, "a", "1");
        let a = sign(a.clone(), &alice);
        chain.insert(&mut store, a.clone()).unwrap();

        let b = set(digest(&a), "b", "2");
        let b = sign(b.clone(), &alice);
        let bd = digest(&b);
        chain.insert(&mut store, b.clone()).unwrap();

        // Compaction keeps the root and the tip; the middle version goes,
        // and the tip's envelope leaves the log with it.
        store.retain(&[root, bd]).unwrap();
        store.remove_envelope(bd).unwrap();
        assert!(!store.contains_version(digest(&a)).unwrap());

        let mut peer_copy = b;
        peer_copy.set_verification_status(VerificationStatus::Unchecked);
        chain.insert(&mut store, peer_copy).unwrap();

        assert!(
            store.envelope(bd).unwrap().is_none(),
            "an unverifiable envelope must not enter the log"
        );
        // The cost of refusing: with its envelope out of the log, the
        // tip is unreachable to the walk, so the head falls back to the
        // last envelope the log still holds.
        assert_eq!(chain.head(), digest(&a));
    }

    /// A chain replayed from the wire carries no verification statuses,
    /// so `replay` has to verify each envelope itself — otherwise a chain
    /// that satisfied its own thresholds when it was written refuses to
    /// replay, every envelope failing the floor it once cleared.
    #[test]
    fn replay_verifies_envelopes_it_receives_unverified() {
        let alice = SigningKey::from([1u8; 32]);
        let (mut store, mut chain) = signed_setup([Key::new(public_key(&alice), 3)]);

        let floor = Envelope::new(Msg::SetNamespace(SetNamespace {
            prev: chain.head(),
            key: key(crate::MIN_ENVELOPE_WEIGHT_KEY),
            namespace: Namespace {
                value: Value::Int(3),
            },
        }));
        chain.insert(&mut store, floor.clone()).unwrap();

        let next = set(chain.head(), "a", "1");
        let next = sign(next.clone(), &alice);
        chain.insert(&mut store, next.clone()).unwrap();
        assert_eq!(chain.head(), digest(&next));

        // Exactly what a peer receives: decoded from the wire, so every
        // status is back to `Unchecked`.
        let root = store.envelope(chain.root()).unwrap().unwrap();
        let received: Vec<Envelope> = [&root, &floor, &next]
            .into_iter()
            .map(|envelope| wire::decode(&wire::encode(envelope).unwrap()).unwrap())
            .collect();
        assert_eq!(
            received[2].verification_status(),
            &VerificationStatus::Unchecked
        );

        let mut fresh = MemStorage::default();
        let replayed = Ledger::replay(&mut fresh, received.iter()).unwrap();
        assert_eq!(replayed.head(), chain.head());
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

    /// Of two children contesting one parent, the higher digest wins; the
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

    /// One winning digest at the fork beats any number of descendants on
    /// the other side — there is no notion of chain length.
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
        assert_eq!(
            store.envelope(digest(&child)).unwrap(),
            None,
            "never stored"
        );
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
    /// is refused with the failure itself — and never stored.
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

        assert_eq!(store.envelope(digest(&bad)).unwrap(), None, "never stored");
        assert_eq!(chain.head(), chain.root(), "head must not move");
    }

    /// A parent whose version was pruned can't back a trial apply, so its
    /// children are refused rather than stored unvalidated.
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
        assert_eq!(
            store.envelope(digest(&child)).unwrap(),
            None,
            "never stored"
        );
        assert_eq!(chain.head(), digest(&parent), "head must not move");
    }

    /// `insert` stores only validated envelopes, but the walk stays
    /// defensive: an invalid envelope that reached the log some other way
    /// and wins its fork is dropped, its failure surfaces as the error,
    /// and only the next walk adopts the surviving sibling.
    #[test]
    fn the_walk_drops_an_invalid_envelope_from_the_log() {
        let (mut store, mut chain) = setup();
        let bad = delete(chain.head(), "nope");
        store.put_envelope(digest(&bad), bad.clone()).unwrap();

        // Grind until the valid sibling loses the digest race, so the
        // walk must adjudicate `bad` before reaching it.
        let good = (0..)
            .map(|i| set(chain.head(), "a", &format!("v{i}")))
            .find(|e| digest(e) < digest(&bad))
            .expect("some value hashes below bad");

        let err = chain.insert(&mut store, good.clone()).unwrap_err();
        assert!(matches!(
            err,
            Error::Apply(ApplyError::UnknownNamespace(k)) if k == key("nope")
        ));
        assert_eq!(store.envelope(digest(&bad)).unwrap(), None, "dropped");
        assert_eq!(chain.head(), chain.root(), "walk aborted at the fault");

        // `good` was stored before the fault; the next walk reaches it.
        assert_eq!(
            chain.insert_batch(&mut store, core::iter::empty()).unwrap(),
            Insert::Extended
        );
        assert_eq!(chain.head(), digest(&good));
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

    /// Chains share a store: an envelope stored by one is a duplicate to
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

    #[test]
    fn a_batch_extends_the_chain_in_one_call() {
        let (mut store, mut chain) = setup();
        let a = set(chain.head(), "a", "1");
        let b = set(digest(&a), "b", "2");
        let c = set(digest(&b), "c", "3");

        assert_eq!(
            chain.insert_batch(&mut store, [a, b, c.clone()]).unwrap(),
            Insert::Extended
        );
        assert_eq!(chain.head(), digest(&c));
        assert!(has(&store, &chain, &key("a")));
        assert!(has(&store, &chain, &key("c")));
    }

    /// The batch contract is linearity: an envelope that doesn't chain
    /// onto its predecessor is refused — even one that would have been a
    /// legal fork on its own.
    #[test]
    fn a_batch_with_a_gap_is_refused() {
        let (mut store, mut chain) = setup();
        let a = set(chain.head(), "a", "1");
        // Chains onto the root, not onto `a`.
        let stray = set(chain.head(), "x", "9");

        let err = chain
            .insert_batch(&mut store, [a.clone(), stray.clone()])
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Apply(ApplyError::ChainMismatch { expected, found })
                if expected == digest(&a) && found == chain.root()
        ));

        assert_eq!(chain.head(), digest(&a), "prefix is kept and canonical");
        assert_eq!(
            store.envelope(digest(&stray)).unwrap(),
            None,
            "never stored"
        );
    }

    /// A mid-batch refusal keeps the valid prefix: everything before the
    /// fault is stored and canonical, the fault and its descendants never
    /// land.
    #[test]
    fn a_refused_batch_keeps_its_valid_prefix() {
        let (mut store, mut chain) = setup();
        let a = set(chain.head(), "a", "1");
        let bad = delete(digest(&a), "nope");
        let tail = set(digest(&bad), "c", "3");

        let err = chain
            .insert_batch(&mut store, [a.clone(), bad.clone(), tail.clone()])
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Apply(ApplyError::UnknownNamespace(k)) if k == key("nope")
        ));

        assert_eq!(chain.head(), digest(&a), "prefix is canonical");
        assert_eq!(store.envelope(digest(&bad)).unwrap(), None, "never stored");
        assert_eq!(store.envelope(digest(&tail)).unwrap(), None, "never stored");
    }

    /// A batch may grow a losing branch: everything is stored, nothing moves.
    #[test]
    fn a_losing_batch_leaves_the_head_alone() {
        let (mut store, mut chain) = setup();
        let (winner, loser) = ranked(set(chain.head(), "a", "1"), set(chain.head(), "b", "2"));
        chain.insert(&mut store, winner.clone()).unwrap();

        let tail = set(digest(&loser), "c", "3");
        assert_eq!(
            chain
                .insert_batch(&mut store, [loser, tail.clone()])
                .unwrap(),
            Insert::Unchanged
        );
        assert_eq!(chain.head(), digest(&winner));
        assert!(store.envelope(digest(&tail)).unwrap().is_some(), "stored");
    }

    #[test]
    fn a_winning_batch_reorgs_the_head() {
        let (mut store, mut chain) = setup();
        let (winner, loser) = ranked(set(chain.head(), "a", "1"), set(chain.head(), "b", "2"));
        chain.insert(&mut store, loser.clone()).unwrap();

        let next = set(digest(&winner), "c", "3");
        assert_eq!(
            chain
                .insert_batch(&mut store, [winner, next.clone()])
                .unwrap(),
            Insert::Reorged {
                from: digest(&loser)
            }
        );
        assert_eq!(chain.head(), digest(&next));
    }

    /// Duplicates mixed into a run are folded past silently; the new
    /// tail decides the outcome. Only a run of nothing but duplicates
    /// that moved nothing reports [`Insert::Duplicate`].
    #[test]
    fn a_batch_resumes_past_duplicates() {
        let (mut store, mut chain) = setup();
        let a = set(chain.head(), "a", "1");
        chain.insert(&mut store, a.clone()).unwrap();
        let b = set(digest(&a), "b", "2");

        assert_eq!(
            chain
                .insert_batch(&mut store, [a.clone(), b.clone()])
                .unwrap(),
            Insert::Extended
        );
        assert_eq!(chain.head(), digest(&b));

        assert_eq!(
            chain.insert_batch(&mut store, [a, b]).unwrap(),
            Insert::Duplicate
        );
    }

    /// An empty batch is a bare re-walk: nothing to store, but a cursor
    /// lagging a shared store still catches up.
    #[test]
    fn an_empty_batch_just_rewalks() {
        let mut store = MemStorage::default();
        let mut leader = Chain::init(&mut store, init()).unwrap();
        let mut follower = Chain::init(&mut store, init()).unwrap();

        assert_eq!(
            follower
                .insert_batch(&mut store, core::iter::empty())
                .unwrap(),
            Insert::Unchanged
        );

        leader
            .insert(&mut store, set(leader.head(), "a", "1"))
            .unwrap();
        assert_eq!(
            follower
                .insert_batch(&mut store, core::iter::empty())
                .unwrap(),
            Insert::Extended
        );
        assert_eq!(follower.head(), leader.head());
    }

    /// One batch lands exactly where the same envelopes inserted one at
    /// a time do — the batch is an optimization, not new semantics.
    #[test]
    fn a_batch_matches_one_at_a_time_insertion() {
        let root = digest(&init());
        let a = set(root, "a", "1");
        let b = set(digest(&a), "b", "2");
        let c = set(digest(&b), "c", "3");
        let envelopes = [a, b, c];

        let (mut batch_store, mut batched) = setup();
        batched
            .insert_batch(&mut batch_store, envelopes.clone())
            .unwrap();

        let (mut loop_store, mut stepwise) = setup();
        envelopes.into_iter().for_each(|envelope| {
            stepwise.insert(&mut loop_store, envelope).unwrap();
        });

        assert_eq!(batched.head(), stepwise.head());
        assert_eq!(
            batched.checkpoint(&batch_store).unwrap(),
            stepwise.checkpoint(&loop_store).unwrap()
        );
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
