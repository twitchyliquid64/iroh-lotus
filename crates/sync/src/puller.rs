//! The pulling side of a sync session.

use core::mem;

use wire::EnvelopeDigest;

use crate::{
    MAX_BATCH_ENVELOPES, PROTOCOL_VERSION, locator,
    proto::{Envelopes, FindSplit, Hello, Message, Split},
    session::{Answer, Breach, Effect, Input, PullOutcome, Query},
};

/// The machine that catches this node up from one peer.
///
/// Opens with its `Hello`, learns where the paths part, and feeds the
/// peer's canonical path into the chain batch by batch. Everything the
/// peer sends is validated at this boundary — phase, batch shape, run
/// linkage — before an envelope is handed to [`Effect::Ingest`]; the
/// chain then judges content on its own terms.
#[derive(Debug)]
pub struct Puller {
    state: State,
}

#[derive(Debug)]
enum State {
    AwaitHello,
    AwaitContains,
    AwaitLocator,
    AwaitSplit {
        locator: Vec<EnvelopeDigest>,
    },
    AwaitBatch {
        cursor: EnvelopeDigest,
        ingested: u64,
    },
    AwaitIngest {
        cursor: EnvelopeDigest,
        ingested: u64,
        pending: u64,
    },
    Terminal,
}

impl State {
    /// What the protocol admits next, for breach diagnostics.
    fn expecting(&self) -> &'static str {
        match self {
            State::AwaitHello => "Hello",
            State::AwaitSplit { .. } => "Split or NoSplit",
            State::AwaitBatch { .. } => "Envelopes or CaughtUp",
            State::AwaitContains | State::AwaitLocator | State::AwaitIngest { .. } => {
                "no frame while an effect is unresolved"
            }
            State::Terminal => "nothing",
        }
    }
}

impl Puller {
    /// Creates a new Puller for a node at head, also returning the first
    /// message to be sent.
    pub fn new(head: EnvelopeDigest) -> (Self, Effect<PullOutcome>) {
        let hello = Effect::Send(Message::Hello(Hello {
            version: PROTOCOL_VERSION,
            head,
        }));
        (
            Self {
                state: State::AwaitHello,
            },
            hello,
        )
    }

    /// Feeds the machine one input; the returned effects must be resolved
    /// in order before the next frame is fed.
    ///
    /// # Panics
    ///
    /// Panics on a broken driver contract: an [`Input::Answer`] or
    /// [`Input::Ingested`] nothing asked for, a frame fed across an
    /// unresolved effect, or any input after [`Effect::Done`] or
    /// [`Effect::Violation`] ended the session.
    pub fn handle(&mut self, input: Input) -> Vec<Effect<PullOutcome>> {
        // Logged before the step so a contract panic still shows what
        // was fed.
        tracing::debug!(input = %crate::trace::input(&input), "puller");
        let effects = self.step(input);
        tracing::debug!(effects = %crate::trace::effects(&effects), "puller");
        effects
    }

    fn step(&mut self, input: Input) -> Vec<Effect<PullOutcome>> {
        // Every path either installs the next state or ends Terminal.
        let state = mem::replace(&mut self.state, State::Terminal);
        match (state, input) {
            (State::AwaitHello, Input::Message(Message::Hello(peer))) => {
                if peer.version != PROTOCOL_VERSION {
                    return self.breach(Breach::Version {
                        ours: PROTOCOL_VERSION,
                        theirs: peer.version,
                    });
                }
                self.state = State::AwaitContains;
                vec![Effect::Ask(Query::ContainsEnvelope(peer.head))]
            }

            (State::AwaitContains, Input::Answer(Answer::Contains(true))) => {
                vec![Effect::Done(PullOutcome::AlreadyCurrent)]
            }
            (State::AwaitContains, Input::Answer(Answer::Contains(false))) => {
                self.state = State::AwaitLocator;
                vec![Effect::Ask(Query::Locator)]
            }

            (State::AwaitLocator, Input::Answer(Answer::Locator(locator))) => {
                assert!(
                    !locator.is_empty() && locator.len() <= locator::MAX_LOCATOR_LEN,
                    "own core must sample 1..={} locator entries",
                    locator::MAX_LOCATOR_LEN,
                );
                self.state = State::AwaitSplit {
                    locator: locator.clone(),
                };
                vec![Effect::Send(Message::FindSplit(FindSplit { locator }))]
            }

            (State::AwaitSplit { locator }, Input::Message(Message::Split(Split { at }))) => {
                // The server may only point at what we offered: anything
                // else could name an envelope we can't build on.
                if !locator.contains(&at) {
                    return self.breach(Breach::SplitNotInLocator { at });
                }
                self.state = State::AwaitBatch {
                    cursor: at,
                    ingested: 0,
                };
                Vec::new()
            }
            (State::AwaitSplit { .. }, Input::Message(Message::NoSplit(_))) => {
                vec![Effect::Done(PullOutcome::NoCommonHistory)]
            }

            (
                State::AwaitBatch { cursor, ingested },
                Input::Message(Message::Envelopes(Envelopes { batch })),
            ) => {
                if batch.is_empty() {
                    return self.breach(Breach::EmptyBatch);
                }
                if batch.len() > MAX_BATCH_ENVELOPES as usize {
                    return self.breach(Breach::OversizedBatch { got: batch.len() });
                }
                // Linkage is judged here so a violation is attributed to
                // the peer before anything touches the chain; the chain
                // re-judges content (weight, applicability) on ingest.
                let tip = batch.iter().try_fold(cursor, |expected, envelope| {
                    if envelope.payload().prev_digest() != Some(&expected) {
                        return Err(Breach::BrokenRun { expected });
                    }
                    envelope.digest().map_err(Breach::Undigestable)
                });
                match tip {
                    Ok(tip) => {
                        let pending = batch.len() as u64;
                        self.state = State::AwaitIngest {
                            cursor: tip,
                            ingested,
                            pending,
                        };
                        vec![Effect::Ingest(batch)]
                    }
                    Err(breach) => self.breach(breach),
                }
            }
            (State::AwaitBatch { cursor, ingested }, Input::Message(Message::CaughtUp(_))) => {
                vec![Effect::Done(PullOutcome::Synced {
                    head: cursor,
                    ingested,
                })]
            }

            (
                State::AwaitIngest {
                    cursor,
                    ingested,
                    pending,
                },
                Input::Ingested,
            ) => {
                self.state = State::AwaitBatch {
                    cursor,
                    ingested: ingested + pending,
                };
                Vec::new()
            }

            // A frame the phase does not admit is the peer's breach…
            (
                state @ (State::AwaitHello | State::AwaitSplit { .. } | State::AwaitBatch { .. }),
                Input::Message(message),
            ) => {
                let expected = state.expecting();
                self.breach(Breach::Unexpected {
                    got: message.kind(),
                    expected,
                })
            }
            // …while everything below is the driver breaking its contract.
            (
                State::AwaitContains | State::AwaitLocator | State::AwaitIngest { .. },
                Input::Message(_),
            ) => {
                panic!("driver fed a frame while an Ask or Ingest was unresolved")
            }
            (State::Terminal, _) => panic!("driver fed input after the session ended"),
            (_, Input::Answer(_)) => {
                panic!("driver answered a query nothing asked for, or answered in the wrong shape")
            }
            (_, Input::Ingested) => panic!("driver reported an ingest nothing requested"),
        }
    }

    fn breach(&mut self, breach: Breach) -> Vec<Effect<PullOutcome>> {
        self.state = State::Terminal;
        vec![Effect::Violation(breach)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proto::{CaughtUp, MessageKind, NoSplit},
        testutil::{digest_of, set},
    };
    use wire::Envelope;

    fn d(byte: u8) -> EnvelopeDigest {
        EnvelopeDigest::from_bytes([byte; 32])
    }

    fn peer_hello(head: EnvelopeDigest) -> Message {
        Message::Hello(Hello {
            version: PROTOCOL_VERSION,
            head,
        })
    }

    /// One effect out of a handle call, asserted to be the only one.
    fn one(mut effects: Vec<Effect<PullOutcome>>) -> Effect<PullOutcome> {
        assert_eq!(effects.len(), 1, "expected exactly one effect: {effects:?}");
        effects.pop().expect("length checked")
    }

    fn none(effects: Vec<Effect<PullOutcome>>) {
        assert!(effects.is_empty(), "expected no effects: {effects:?}");
    }

    /// Drives a fresh puller to the point of awaiting batches, with the
    /// split at `split`.
    fn streaming(split: EnvelopeDigest) -> Puller {
        let (mut puller, _) = Puller::new(d(0x01));
        puller.handle(Input::Message(peer_hello(d(0x02))));
        puller.handle(Input::Answer(Answer::Contains(false)));
        puller.handle(Input::Answer(Answer::Locator(vec![d(0x01), split])));
        none(puller.handle(Input::Message(Message::Split(Split { at: split }))));
        puller
    }

    /// A run of `n` envelopes chaining onto `prev`; returns the run and
    /// its tip digest.
    fn run(prev: EnvelopeDigest, n: usize) -> (Vec<Envelope>, EnvelopeDigest) {
        let mut cursor = prev;
        let batch: Vec<Envelope> = (0..n)
            .map(|i| {
                let envelope = set(cursor, "k", &format!("v{i}"));
                cursor = digest_of(&envelope);
                envelope
            })
            .collect();
        (batch, cursor)
    }

    #[test]
    fn a_new_puller_opens_with_hello() {
        let (_, effect) = Puller::new(d(0x01));
        assert!(matches!(
            effect,
            Effect::Send(Message::Hello(hello))
                if hello.version == PROTOCOL_VERSION && hello.head == d(0x01)
        ));
    }

    #[test]
    fn a_version_mismatch_is_a_breach() {
        let (mut puller, _) = Puller::new(d(0x01));
        let effect = one(puller.handle(Input::Message(Message::Hello(Hello {
            version: PROTOCOL_VERSION + 1,
            head: d(0x02),
        }))));
        assert!(matches!(
            effect,
            Effect::Violation(Breach::Version { theirs, .. }) if theirs == PROTOCOL_VERSION + 1
        ));
    }

    /// The peer's head is looked up before any negotiation: a known head
    /// means nothing to fetch.
    #[test]
    fn a_known_peer_head_is_already_current() {
        let (mut puller, _) = Puller::new(d(0x01));
        let effect = one(puller.handle(Input::Message(peer_hello(d(0x02)))));
        assert!(matches!(
            effect,
            Effect::Ask(Query::ContainsEnvelope(head)) if head == d(0x02)
        ));

        let effect = one(puller.handle(Input::Answer(Answer::Contains(true))));
        assert!(matches!(effect, Effect::Done(PullOutcome::AlreadyCurrent)));
    }

    #[test]
    fn an_unknown_peer_head_negotiates_a_split() {
        let (mut puller, _) = Puller::new(d(0x01));
        puller.handle(Input::Message(peer_hello(d(0x02))));

        let effect = one(puller.handle(Input::Answer(Answer::Contains(false))));
        assert!(matches!(effect, Effect::Ask(Query::Locator)));

        let locator = vec![d(0x01), d(0x03)];
        let effect = one(puller.handle(Input::Answer(Answer::Locator(locator.clone()))));
        assert!(matches!(
            effect,
            Effect::Send(Message::FindSplit(FindSplit { locator: sent })) if sent == locator
        ));
    }

    /// A split naming a digest we never offered could point anywhere —
    /// including at an envelope we can't build on.
    #[test]
    fn a_split_outside_the_locator_is_a_breach() {
        let (mut puller, _) = Puller::new(d(0x01));
        puller.handle(Input::Message(peer_hello(d(0x02))));
        puller.handle(Input::Answer(Answer::Contains(false)));
        puller.handle(Input::Answer(Answer::Locator(vec![d(0x01)])));

        let effect = one(puller.handle(Input::Message(Message::Split(Split { at: d(0x77) }))));
        assert!(matches!(
            effect,
            Effect::Violation(Breach::SplitNotInLocator { at }) if at == d(0x77)
        ));
    }

    #[test]
    fn no_split_ends_with_no_common_history() {
        let (mut puller, _) = Puller::new(d(0x01));
        puller.handle(Input::Message(peer_hello(d(0x02))));
        puller.handle(Input::Answer(Answer::Contains(false)));
        puller.handle(Input::Answer(Answer::Locator(vec![d(0x01)])));

        let effect = one(puller.handle(Input::Message(Message::NoSplit(NoSplit {}))));
        assert!(matches!(effect, Effect::Done(PullOutcome::NoCommonHistory)));
    }

    /// The happy path: two chained batches ingest, and the caught-up head
    /// closes the session with the count.
    #[test]
    fn chained_batches_ingest_and_complete() {
        let mut puller = streaming(d(0x10));
        let (first, first_tip) = run(d(0x10), 3);
        let (second, tip) = run(first_tip, 2);

        let effect = one(puller.handle(Input::Message(Message::Envelopes(Envelopes {
            batch: first.clone(),
        }))));
        assert!(matches!(effect, Effect::Ingest(batch) if batch == first));
        none(puller.handle(Input::Ingested));

        let effect = one(puller.handle(Input::Message(Message::Envelopes(Envelopes {
            batch: second,
        }))));
        assert!(matches!(effect, Effect::Ingest(_)));
        none(puller.handle(Input::Ingested));

        let effect = one(puller.handle(Input::Message(Message::CaughtUp(CaughtUp {}))));
        assert!(matches!(
            effect,
            // The head is the tip the puller computed itself — `CaughtUp`
            // carries nothing to take the peer's word for.
            Effect::Done(PullOutcome::Synced { head, ingested: 5 }) if head == tip
        ));
    }

    /// A stream may legitimately carry nothing: the server reorged
    /// between its `Hello` and the segment walk.
    #[test]
    fn caught_up_with_nothing_streamed_completes_at_the_split() {
        let mut puller = streaming(d(0x10));
        let effect = one(puller.handle(Input::Message(Message::CaughtUp(CaughtUp {}))));
        assert!(matches!(
            effect,
            Effect::Done(PullOutcome::Synced { head, ingested: 0 }) if head == d(0x10)
        ));
    }

    #[test]
    fn an_empty_batch_is_a_breach() {
        let mut puller = streaming(d(0x10));
        let effect = one(puller.handle(Input::Message(Message::Envelopes(Envelopes {
            batch: Vec::new(),
        }))));
        assert!(matches!(effect, Effect::Violation(Breach::EmptyBatch)));
    }

    #[test]
    fn an_oversized_batch_is_a_breach() {
        let mut puller = streaming(d(0x10));
        let (batch, _) = run(d(0x10), MAX_BATCH_ENVELOPES as usize + 1);
        let effect = one(puller.handle(Input::Message(Message::Envelopes(Envelopes { batch }))));
        assert!(matches!(
            effect,
            Effect::Violation(Breach::OversizedBatch { got }) if got == 257
        ));
    }

    /// The first envelope must chain onto the split point itself.
    #[test]
    fn a_batch_that_skips_the_split_is_a_breach() {
        let mut puller = streaming(d(0x10));
        let (batch, _) = run(d(0x55), 1);
        let effect = one(puller.handle(Input::Message(Message::Envelopes(Envelopes { batch }))));
        assert!(matches!(
            effect,
            Effect::Violation(Breach::BrokenRun { expected }) if expected == d(0x10)
        ));
    }

    #[test]
    fn a_gap_inside_a_batch_is_a_breach() {
        let mut puller = streaming(d(0x10));
        let (mut batch, _) = run(d(0x10), 2);
        let (stray, _) = run(d(0x66), 1);
        batch.extend(stray);

        let effect = one(puller.handle(Input::Message(Message::Envelopes(Envelopes { batch }))));
        assert!(matches!(
            effect,
            Effect::Violation(Breach::BrokenRun { .. })
        ));
    }

    /// The second batch must chain onto the first batch's tip — a server
    /// cannot restart the stream somewhere else mid-session.
    #[test]
    fn a_batch_not_chaining_onto_the_previous_is_a_breach() {
        let mut puller = streaming(d(0x10));
        let (first, _) = run(d(0x10), 2);
        puller.handle(Input::Message(Message::Envelopes(Envelopes {
            batch: first,
        })));
        none(puller.handle(Input::Ingested));

        let (stray, _) = run(d(0x66), 1);
        let effect = one(puller.handle(Input::Message(Message::Envelopes(Envelopes {
            batch: stray,
        }))));
        assert!(matches!(
            effect,
            Effect::Violation(Breach::BrokenRun { .. })
        ));
    }

    /// An `Init` has no `prev`, so it can never satisfy run linkage — a
    /// peer cannot smuggle a new genesis through a pull stream.
    #[test]
    fn an_init_in_the_stream_is_a_breach() {
        let mut puller = streaming(d(0x10));
        let init: Envelope =
            wire::decode(&crate::testutil::unhex("a301a101a101a101a002a00380")).unwrap();
        let effect = one(puller.handle(Input::Message(Message::Envelopes(Envelopes {
            batch: vec![init],
        }))));
        assert!(matches!(
            effect,
            Effect::Violation(Breach::BrokenRun { .. })
        ));
    }

    /// Any frame outside its phase is a breach naming both sides.
    #[test]
    fn an_out_of_phase_frame_is_a_breach() {
        let (mut puller, _) = Puller::new(d(0x01));
        let effect = one(puller.handle(Input::Message(Message::CaughtUp(CaughtUp {}))));
        assert!(matches!(
            effect,
            Effect::Violation(Breach::Unexpected {
                got: MessageKind::CaughtUp,
                expected: "Hello",
            })
        ));
    }

    #[test]
    #[should_panic(expected = "driver answered a query nothing asked for")]
    fn an_unasked_answer_panics() {
        let (mut puller, _) = Puller::new(d(0x01));
        puller.handle(Input::Answer(Answer::Contains(true)));
    }

    #[test]
    #[should_panic(expected = "after the session ended")]
    fn input_after_the_end_panics() {
        let (mut puller, _) = Puller::new(d(0x01));
        puller.handle(Input::Message(peer_hello(d(0x02))));
        puller.handle(Input::Answer(Answer::Contains(true)));
        puller.handle(Input::Message(peer_hello(d(0x02))));
    }
}
