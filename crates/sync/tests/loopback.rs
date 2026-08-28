//! Two session machines wired straight to each other over two real
//! chains — every scenario runs synchronously and deterministically,
//! with no runtime and no sockets, which is the payoff of the sans-io
//! construction.
//!
//! The pump round-trips every message through [`wire::encode`] and
//! [`wire::decode`], exactly as a transport would: local state like the
//! verification status is stripped in flight, so these tests also prove
//! that a receiver re-verifies what it ingests.

use std::{cell::RefCell, collections::VecDeque};

use ed25519_zebra::SigningKey;
use state::{Chain, Insert, MIN_ENVELOPE_WEIGHT_KEY, TRUSTED_KEYS_KEY};
use storage::{MemStorage, Storage};
use sync::{
    Answer, Breach, Effect, Envelopes, Input, Message, PullOutcome, Puller, Query, ServeOutcome,
    Server, Split, locator,
};
use wire::{
    Envelope, EnvelopeDigest, Msg,
    keys::{Ed25519PublicKey, Ed25519Signature, Key, PublicKey, Signature},
    msg::{FullCheckpoint, InitMsg, Namespace, NamespaceKey, SetNamespace, Value},
};

fn key(k: &str) -> NamespaceKey {
    NamespaceKey::try_new(k).unwrap()
}

fn set_value(prev: EnvelopeDigest, k: &str, value: Value) -> Envelope {
    Envelope::new(Msg::SetNamespace(SetNamespace {
        prev,
        key: key(k),
        namespace: Namespace { value },
    }))
}

fn set(prev: EnvelopeDigest, k: &str, v: &str) -> Envelope {
    set_value(prev, k, Value::String(v.to_string()))
}

fn digest(envelope: &Envelope) -> EnvelopeDigest {
    envelope.digest().unwrap()
}

fn public_key(signing: &SigningKey) -> PublicKey {
    PublicKey::Ed25519(Ed25519PublicKey::from_bytes(
        signing.verification_key().into(),
    ))
}

fn sign(envelope: Envelope, signing: &SigningKey) -> Envelope {
    let digest = envelope.signature_digest().unwrap();
    let signature = Signature::Ed25519(Ed25519Signature::from_bytes(
        signing.sign(digest.as_bytes()).to_bytes(),
    ));
    envelope.with_signature(public_key(signing).id(), signature)
}

/// A genesis whose checkpoint already trusts `keys`.
fn genesis_trusting(keys: impl IntoIterator<Item = Key>) -> Envelope {
    let trusted = Value::Map(
        keys.into_iter()
            .map(|key| (key.id().to_hex().as_ref().to_string(), Value::Key(key)))
            .collect(),
    );
    Envelope::new(Msg::Init(InitMsg {
        state: FullCheckpoint {
            namespaces: [(key(TRUSTED_KEYS_KEY), Namespace { value: trusted })]
                .into_iter()
                .collect(),
        },
    }))
}

fn genesis_plain() -> Envelope {
    Envelope::new(Msg::Init(InitMsg {
        state: FullCheckpoint::default(),
    }))
}

/// One node: a real chain over in-memory storage, answering the queries
/// the machines emit — the same semantics the daemon's core will answer
/// with.
struct Node {
    store: MemStorage,
    chain: Chain,
}

impl Node {
    fn new(genesis: Envelope) -> Self {
        let mut store = MemStorage::default();
        let chain = Chain::init(&mut store, genesis).unwrap();
        Self { store, chain }
    }

    fn insert(&mut self, envelope: Envelope) -> Insert {
        self.chain.insert(&mut self.store, envelope).unwrap()
    }

    fn extend(&mut self, envelopes: impl IntoIterator<Item = Envelope>) {
        self.chain.insert_batch(&mut self.store, envelopes).unwrap();
    }

    fn head(&self) -> EnvelopeDigest {
        self.chain.head()
    }

    fn holds(&self, digest: EnvelopeDigest) -> bool {
        self.store.envelope(digest).unwrap().is_some()
    }

    fn checkpoint(&self) -> FullCheckpoint {
        self.chain.checkpoint(&self.store).unwrap()
    }

    /// Walks the canonical path, newest first, down to the root — what
    /// the locator helpers stream over without materializing the path.
    fn walk(&self) -> impl Iterator<Item = EnvelopeDigest> {
        core::iter::successors(Some(self.chain.head()), |&at| {
            self.store
                .envelope(at)
                .unwrap()
                .and_then(|envelope| envelope.payload().prev_digest().copied())
        })
    }

    /// The walk collected, for the reads that need positions.
    fn canonical(&self) -> Vec<EnvelopeDigest> {
        self.walk().collect()
    }

    /// Answers a machine query with the semantics the daemon core will
    /// implement.
    fn answer(&self, query: Query) -> Answer {
        match query {
            Query::ContainsEnvelope(digest) => Answer::Contains(self.holds(digest)),
            Query::Locator => Answer::Locator(locator::sample(self.walk())),
            Query::SplitPoint(entries) => Answer::SplitPoint(locator::split(&entries, self.walk())),
            Query::Segment { after } => {
                let path = self.canonical();
                let Some(position) = path.iter().position(|&digest| digest == after) else {
                    // The cursor left the canonical path: end the stream.
                    return Answer::Segment(Vec::new());
                };

                let mut budget = sync::SEGMENT_BYTE_BUDGET as usize;
                let segment: Vec<Envelope> = path[..position]
                    .iter()
                    .rev()
                    .take(sync::MAX_BATCH_ENVELOPES as usize)
                    .map(|&digest| self.store.envelope(digest).unwrap().unwrap())
                    .enumerate()
                    // The first envelope goes regardless of its size:
                    // excluding it would wedge the stream at this point
                    // for good.
                    .take_while(|(index, envelope)| {
                        let cost = wire::encode(envelope).unwrap().len();
                        let fits = *index == 0 || cost <= budget;
                        budget = budget.saturating_sub(cost);
                        fits
                    })
                    .map(|(_, envelope)| envelope)
                    .collect();
                Answer::Segment(segment)
            }
        }
    }

    fn ingest(&mut self, run: Vec<Envelope>) -> Result<Insert, String> {
        self.chain
            .insert_batch(&mut self.store, run)
            .map_err(|error| format!("{error:?}"))
    }
}

#[derive(Debug)]
enum Fault {
    Puller(Breach),
    // Only read through Debug when a test fails; that's its whole job.
    Server(#[allow(dead_code)] Breach),
    // Only read through Debug when a test fails; that's its whole job.
    Ingest(#[allow(dead_code)] String),
}

#[derive(Debug)]
struct Outcomes {
    pull: Option<PullOutcome>,
    serve: Option<ServeOutcome>,
}

fn roundtrip(message: Message) -> Message {
    wire::decode(&wire::encode(&message).unwrap()).unwrap()
}

fn run_sync(puller_node: &mut Node, server_node: &mut Node) -> Result<Outcomes, Fault> {
    run_sync_tampered(puller_node, server_node, |message| message)
}

/// Pumps one pull session to completion, applying `tamper` to every
/// server→puller frame — identity for honest runs, or a wiretap for
/// observing and corrupting traffic.
fn run_sync_tampered(
    puller_node: &mut Node,
    server_node: &mut Node,
    mut tamper: impl FnMut(Message) -> Message,
) -> Result<Outcomes, Fault> {
    let (mut puller, opening) = Puller::new(puller_node.head());
    let mut server = Server::new(server_node.head());
    let mut pull_effects: VecDeque<Effect<PullOutcome>> = VecDeque::from([opening]);
    let mut serve_effects: VecDeque<Effect<ServeOutcome>> = VecDeque::new();
    let mut outcomes = Outcomes {
        pull: None,
        serve: None,
    };

    loop {
        if let Some(effect) = pull_effects.pop_front() {
            match effect {
                Effect::Send(message) => {
                    serve_effects.extend(server.handle(Input::Message(roundtrip(message))));
                }
                Effect::Ask(query) => {
                    let answer = puller_node.answer(query);
                    pull_effects.extend(puller.handle(Input::Answer(answer)));
                }
                Effect::Ingest(run) => match puller_node.ingest(run) {
                    Ok(_) => pull_effects.extend(puller.handle(Input::Ingested)),
                    Err(error) => return Err(Fault::Ingest(error)),
                },
                Effect::Done(outcome) => outcomes.pull = Some(outcome),
                Effect::Violation(breach) => return Err(Fault::Puller(breach)),
            }
            continue;
        }
        if let Some(effect) = serve_effects.pop_front() {
            match effect {
                Effect::Send(message) => {
                    let message = roundtrip(tamper(message));
                    pull_effects.extend(puller.handle(Input::Message(message)));
                }
                Effect::Ask(query) => {
                    let answer = server_node.answer(query);
                    serve_effects.extend(server.handle(Input::Answer(answer)));
                }
                Effect::Ingest(_) => unreachable!("a server never emits Ingest"),
                Effect::Done(outcome) => outcomes.serve = Some(outcome),
                Effect::Violation(breach) => return Err(Fault::Server(breach)),
            }
            continue;
        }
        return Ok(outcomes);
    }
}

/// A linear run of `n` envelopes chaining onto `prev`.
fn run_of(prev: EnvelopeDigest, label: &str, n: usize) -> Vec<Envelope> {
    let mut cursor = prev;
    (0..n)
        .map(|i| {
            let envelope = set(cursor, &format!("{label}{i}"), "v");
            cursor = digest(&envelope);
            envelope
        })
        .collect()
}

#[test]
fn a_fresh_follower_fast_forwards() {
    let genesis = genesis_plain();
    let mut a = Node::new(genesis.clone());
    let mut b = Node::new(genesis);
    b.extend(run_of(b.head(), "b", 5));

    let outcomes = run_sync(&mut a, &mut b).unwrap();
    assert_eq!(
        outcomes.pull,
        Some(PullOutcome::Synced {
            head: b.head(),
            ingested: 5
        })
    );
    assert_eq!(
        outcomes.serve,
        Some(ServeOutcome::Served {
            head: b.head(),
            sent: 5
        })
    );
    assert_eq!(a.head(), b.head());
    assert_eq!(a.checkpoint(), b.checkpoint());
}

#[test]
fn identical_nodes_are_already_current() {
    let genesis = genesis_plain();
    let common = run_of(digest(&genesis), "c", 3);
    let mut a = Node::new(genesis.clone());
    let mut b = Node::new(genesis);
    a.extend(common.clone());
    b.extend(common);

    let outcomes = run_sync(&mut a, &mut b).unwrap();
    assert_eq!(outcomes.pull, Some(PullOutcome::AlreadyCurrent));
    assert_eq!(outcomes.serve, None, "the server was never asked to serve");
}

/// The puller being *ahead* looks the same: the peer's head is in our
/// log, so there is nothing to pull — the peer's own pull, running the
/// other way, is what moves the data.
#[test]
fn a_node_ahead_of_its_peer_pulls_nothing() {
    let genesis = genesis_plain();
    let mut a = Node::new(genesis.clone());
    let mut b = Node::new(genesis);
    a.extend(run_of(a.head(), "a", 3));
    let ahead = a.head();

    let outcomes = run_sync(&mut a, &mut b).unwrap();
    assert_eq!(outcomes.pull, Some(PullOutcome::AlreadyCurrent));
    assert_eq!(a.head(), ahead, "nothing moved");

    let outcomes = run_sync(&mut b, &mut a).unwrap();
    assert!(matches!(outcomes.pull, Some(PullOutcome::Synced { .. })));
    assert_eq!(b.head(), ahead);
}

/// The fork scenario: both sides extended the same parent while
/// partitioned. After each pulls the other, both hold both branches and
/// the deterministic rules pick the same winner.
#[test]
fn a_two_sided_fork_converges_both_ways() {
    let genesis = genesis_plain();
    let common = run_of(digest(&genesis), "c", 2);
    let mut a = Node::new(genesis.clone());
    let mut b = Node::new(genesis);
    a.extend(common.clone());
    b.extend(common);

    let fork = a.head();
    let ours = set(fork, "a", "ours");
    let theirs = set(fork, "b", "theirs");
    let winner = [&ours, &theirs]
        .into_iter()
        .max_by_key(|envelope| digest(envelope))
        .cloned()
        .unwrap();
    a.insert(ours.clone());
    b.insert(theirs.clone());

    run_sync(&mut a, &mut b).unwrap();
    run_sync(&mut b, &mut a).unwrap();

    assert_eq!(a.head(), digest(&winner));
    assert_eq!(b.head(), a.head());
    assert_eq!(a.checkpoint(), b.checkpoint());
    assert!(a.holds(digest(&ours)) && a.holds(digest(&theirs)));
    assert!(b.holds(digest(&ours)) && b.holds(digest(&theirs)));
}

/// Weight outranks the digest tiebreak across the wire: the signed
/// branch wins even where the unsigned sibling's digest is higher — and
/// the win requires the receiver to re-verify, since verification never
/// travels.
#[test]
fn sync_reorgs_a_lighter_branch_away() {
    let alice = SigningKey::from([1u8; 32]);
    let genesis = genesis_trusting([Key::new(public_key(&alice), 3)]);
    let mut a = Node::new(genesis.clone());
    let mut b = Node::new(genesis);

    let heavy = sign(set(a.head(), "a", "heavy"), &alice);
    // Grind an unsigned sibling that outranks the signed one on digest,
    // so only re-verified weight can decide the fork.
    let light = (0..64)
        .map(|n| set(a.head(), "a", &format!("light{n}")))
        .find(|light| digest(light) > digest(&heavy))
        .expect("some sibling digest exceeds the signed one's");

    a.insert(light);
    b.insert(heavy.clone());

    run_sync(&mut a, &mut b).unwrap();
    assert_eq!(a.head(), digest(&heavy), "weight must beat the digest");
}

/// One heavy envelope beats any number of light ones: there is no notion
/// of chain length, and sync must not invent one.
#[test]
fn a_heavier_fork_beats_a_longer_one() {
    let alice = SigningKey::from([1u8; 32]);
    let genesis = genesis_trusting([Key::new(public_key(&alice), 3)]);
    let mut a = Node::new(genesis.clone());
    let mut b = Node::new(genesis);

    a.extend(run_of(a.head(), "long", 3));
    let heavy = sign(set(b.head(), "a", "heavy"), &alice);
    b.insert(heavy.clone());

    run_sync(&mut a, &mut b).unwrap();
    run_sync(&mut b, &mut a).unwrap();
    assert_eq!(a.head(), digest(&heavy));
    assert_eq!(b.head(), digest(&heavy));
}

/// Signature collection: the same payload carrying more signatures is a
/// sibling fork with a different digest, and sync converges every node
/// onto the heavier variant.
#[test]
fn signature_collection_converges_on_the_heavier_variant() {
    let alice = SigningKey::from([1u8; 32]);
    let genesis = genesis_trusting([Key::new(public_key(&alice), 3)]);
    let mut a = Node::new(genesis.clone());
    let mut b = Node::new(genesis);

    let payload = set(a.head(), "a", "value");
    let signed = sign(payload.clone(), &alice);
    assert_ne!(
        digest(&payload),
        digest(&signed),
        "signatures are inside the digest"
    );

    a.insert(payload);
    b.insert(signed.clone());

    run_sync(&mut a, &mut b).unwrap();
    assert_eq!(a.head(), digest(&signed));
}

/// The locator's exponential spacing can land the split below the true
/// divergence; the stream then re-sends envelopes the puller has, and
/// the chain folds past them. Wiretap the `Split` to prove it really
/// overshot.
#[test]
fn an_overshot_split_streams_duplicates_harmlessly() {
    let genesis = genesis_plain();
    let common = run_of(digest(&genesis), "c", 10);
    let mut a = Node::new(genesis.clone());
    let mut b = Node::new(genesis);
    a.extend(common.clone());
    b.extend(common);

    let fork = a.head();
    let ours = run_of(fork, "a", 3);
    let ours_first = ours[0].clone();
    a.extend(ours);
    let a_tip = a.head();
    let theirs = set(fork, "b", "theirs");
    b.insert(theirs.clone());

    // A's canonical path is 14 long: 3 own + 10 common + genesis. The
    // locator samples offsets 0,1,2 (own branch), then 4 — one past the
    // fork at offset 3 — so the split overshoots by one.
    let expected_split = a.canonical()[4];

    let observed = RefCell::new(None);
    let outcomes = run_sync_tampered(&mut a, &mut b, |message| {
        if let Message::Split(Split { at }) = &message {
            *observed.borrow_mut() = Some(*at);
        }
        message
    })
    .unwrap();

    assert_eq!(observed.into_inner(), Some(expected_split));
    // One duplicate (the common envelope above the split) plus the
    // peer's branch.
    assert_eq!(
        outcomes.pull,
        Some(PullOutcome::Synced {
            head: b.head(),
            ingested: 2
        })
    );

    run_sync(&mut b, &mut a).unwrap();
    assert_eq!(a.head(), b.head());
    // At the fork the higher child digest wins; A's win puts the head at
    // its three-deep tip.
    let expected = if digest(&ours_first) > digest(&theirs) {
        a_tip
    } else {
        digest(&theirs)
    };
    assert_eq!(a.head(), expected);
}

/// Chains that share nothing — a foreign cluster's peer looks exactly
/// like this — say so cleanly on both sides; nothing is streamed and
/// nothing changes. There is deliberately no in-band cluster identity: a
/// claim would be self-asserted, and the envelopes themselves are the
/// identity.
#[test]
fn disjoint_histories_report_no_common_history() {
    let mut a = Node::new(genesis_plain());
    let mut b = Node::new(genesis_trusting([]));
    b.extend(run_of(b.head(), "b", 2));
    let before = a.head();

    let outcomes = run_sync(&mut a, &mut b).unwrap();
    assert_eq!(outcomes.pull, Some(PullOutcome::NoCommonHistory));
    assert_eq!(outcomes.serve, Some(ServeOutcome::NoCommonHistory));
    assert_eq!(a.head(), before, "nothing moved");
}

/// A tampered stream — here, a batch reordered in flight — is pinned on
/// the peer before anything reaches the chain.
#[test]
fn a_reordered_batch_is_a_breach() {
    let genesis = genesis_plain();
    let mut a = Node::new(genesis.clone());
    let mut b = Node::new(genesis);
    b.extend(run_of(b.head(), "b", 3));

    let fault = run_sync_tampered(&mut a, &mut b, |message| match message {
        Message::Envelopes(Envelopes { mut batch }) => {
            batch.reverse();
            Message::Envelopes(Envelopes { batch })
        }
        other => other,
    })
    .unwrap_err();

    assert!(matches!(fault, Fault::Puller(Breach::BrokenRun { .. })));
    assert_eq!(a.head(), a.canonical()[0]);
    assert_eq!(a.canonical().len(), 1, "nothing was ingested");
}

/// Junk injected below the weight floor chains correctly — the machine
/// cannot fault it — but the chain refuses it at the door: never stored,
/// while the valid prefix it rode in on is kept.
#[test]
fn junk_below_the_weight_floor_is_refused_at_the_door() {
    let alice = SigningKey::from([1u8; 32]);
    let genesis = genesis_trusting([Key::new(public_key(&alice), 3)]);
    let mut a = Node::new(genesis.clone());
    let mut b = Node::new(genesis);

    // Common history raises the floor to 3; everything after must carry
    // alice's signature to apply.
    let floor = set_value(a.head(), MIN_ENVELOPE_WEIGHT_KEY, Value::Int(3));
    a.insert(floor.clone());
    b.insert(floor);

    let one = sign(set(b.head(), "a", "1"), &alice);
    let two = sign(set(digest(&one), "b", "2"), &alice);
    b.extend([one, two.clone()]);

    let evil = RefCell::new(None);
    let fault = run_sync_tampered(&mut a, &mut b, |message| match message {
        Message::Envelopes(Envelopes { mut batch }) => {
            let tip = digest(batch.last().unwrap());
            let junk = set(tip, "evil", "1");
            *evil.borrow_mut() = Some(digest(&junk));
            batch.push(junk);
            Message::Envelopes(Envelopes { batch })
        }
        other => other,
    })
    .unwrap_err();

    assert!(matches!(fault, Fault::Ingest(_)));
    let evil = evil.into_inner().expect("the wiretap saw a batch");
    assert!(!a.holds(evil), "junk must never enter the log");
    assert_eq!(a.head(), digest(&two), "the valid prefix is kept");
}

#[test]
fn a_second_pull_is_a_noop() {
    let genesis = genesis_plain();
    let mut a = Node::new(genesis.clone());
    let mut b = Node::new(genesis);
    b.extend(run_of(b.head(), "b", 4));

    run_sync(&mut a, &mut b).unwrap();
    let outcomes = run_sync(&mut a, &mut b).unwrap();
    assert_eq!(outcomes.pull, Some(PullOutcome::AlreadyCurrent));
}

/// A run longer than one batch streams in bounded segments — and the
/// puller counts every envelope of every batch.
#[test]
fn long_streams_arrive_in_bounded_batches() {
    let genesis = genesis_plain();
    let mut a = Node::new(genesis.clone());
    let mut b = Node::new(genesis);
    let n = sync::MAX_BATCH_ENVELOPES as usize + 44;
    b.extend(run_of(b.head(), "b", n));

    let batches = RefCell::new(Vec::new());
    let outcomes = run_sync_tampered(&mut a, &mut b, |message| {
        if let Message::Envelopes(Envelopes { batch }) = &message {
            batches.borrow_mut().push(batch.len());
        }
        message
    })
    .unwrap();

    assert_eq!(
        batches.into_inner(),
        [sync::MAX_BATCH_ENVELOPES as usize, 44]
    );
    assert_eq!(
        outcomes.pull,
        Some(PullOutcome::Synced {
            head: b.head(),
            ingested: n as u64
        })
    );
    assert_eq!(a.head(), b.head());
}

/// Convergence is symmetric under who pulls first.
#[test]
fn pull_order_does_not_matter() {
    let alice = SigningKey::from([1u8; 32]);
    let genesis = genesis_trusting([Key::new(public_key(&alice), 3)]);
    let common = run_of(digest(&genesis), "c", 2);

    let build = || {
        let mut a = Node::new(genesis.clone());
        let mut b = Node::new(genesis.clone());
        a.extend(common.clone());
        b.extend(common.clone());
        a.insert(sign(set(a.head(), "a", "ours"), &alice));
        b.extend(run_of(b.head(), "theirs", 2));
        (a, b)
    };

    let (mut a1, mut b1) = build();
    run_sync(&mut a1, &mut b1).unwrap();
    run_sync(&mut b1, &mut a1).unwrap();

    let (mut a2, mut b2) = build();
    run_sync(&mut b2, &mut a2).unwrap();
    run_sync(&mut a2, &mut b2).unwrap();

    assert_eq!(a1.head(), b1.head());
    assert_eq!(a2.head(), b2.head());
    assert_eq!(a1.head(), a2.head());
    assert_eq!(a1.checkpoint(), a2.checkpoint());
}
