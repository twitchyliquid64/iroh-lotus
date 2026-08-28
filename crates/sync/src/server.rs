//! The serving side of a sync session.

use core::mem;

use wire::EnvelopeDigest;

use crate::{
    MAX_BATCH_ENVELOPES, PROTOCOL_VERSION, locator,
    proto::{CaughtUp, Envelopes, FindSplit, Hello, Message, NoSplit, Split},
    session::{Answer, Breach, Effect, Input, Query, ServeOutcome},
};

/// The machine that serves one peer's pull.
///
/// Answers the peer's `Hello`, finds the split its locator asks about,
/// and streams the canonical path from there in bounded segments. Each
/// segment is read fresh from the core, so a head that advances while the
/// stream runs is simply served too — and a cursor that a reorg detaches
/// from the canonical path ends the stream early at [`CaughtUp`], which
/// the puller accepts; the next anti-entropy round carries the rest.
#[derive(Debug)]
pub struct Server {
    /// The head at session start, for this side's `Hello` alone — a
    /// snapshot; segments always read the current canonical path.
    head: EnvelopeDigest,
    state: State,
}

#[derive(Debug)]
enum State {
    AwaitHello,
    AwaitFindSplit,
    AwaitSplitPoint,
    AwaitSegment { cursor: EnvelopeDigest, sent: u64 },
    Terminal,
}

impl State {
    /// What the protocol admits next, for breach diagnostics.
    fn expecting(&self) -> &'static str {
        match self {
            State::AwaitHello => "Hello",
            State::AwaitFindSplit => "FindSplit",
            State::AwaitSplitPoint | State::AwaitSegment { .. } => {
                "no frame while an effect is unresolved"
            }
            State::Terminal => "nothing",
        }
    }
}

impl Server {
    /// A session about to serve a peer's pull, standing at `head`; says
    /// nothing until the peer's `Hello` arrives.
    pub fn new(head: EnvelopeDigest) -> Self {
        Self {
            head,
            state: State::AwaitHello,
        }
    }

    /// Feeds the machine one input; the returned effects must be resolved
    /// in order before the next frame is fed.
    ///
    /// # Panics
    ///
    /// Panics on a broken driver contract, exactly as
    /// [`Puller::handle`](crate::Puller::handle) — and on a core that
    /// answers a segment over the budget it was asked for.
    pub fn handle(&mut self, input: Input) -> Vec<Effect<ServeOutcome>> {
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
                self.state = State::AwaitFindSplit;
                vec![Effect::Send(Message::Hello(Hello {
                    version: PROTOCOL_VERSION,
                    head: self.head,
                }))]
            }

            (State::AwaitFindSplit, Input::Message(Message::FindSplit(FindSplit { locator }))) => {
                if locator.is_empty() {
                    return self.breach(Breach::EmptyLocator);
                }
                if locator.len() > locator::MAX_LOCATOR_LEN {
                    return self.breach(Breach::OversizedLocator { got: locator.len() });
                }
                self.state = State::AwaitSplitPoint;
                vec![Effect::Ask(Query::SplitPoint(locator))]
            }

            (State::AwaitSplitPoint, Input::Answer(Answer::SplitPoint(None))) => {
                vec![
                    Effect::Send(Message::NoSplit(NoSplit {})),
                    Effect::Done(ServeOutcome::NoCommonHistory),
                ]
            }
            (State::AwaitSplitPoint, Input::Answer(Answer::SplitPoint(Some(at)))) => {
                self.state = State::AwaitSegment {
                    cursor: at,
                    sent: 0,
                };
                vec![
                    Effect::Send(Message::Split(Split { at })),
                    Effect::Ask(Query::Segment { after: at }),
                ]
            }

            (State::AwaitSegment { cursor, sent }, Input::Answer(Answer::Segment(batch))) => {
                if batch.is_empty() {
                    // Caught up — or the cursor left the canonical path
                    // under a reorg; either way the stream ends here.
                    return vec![
                        Effect::Send(Message::CaughtUp(CaughtUp {})),
                        Effect::Done(ServeOutcome::Served { head: cursor, sent }),
                    ];
                }
                assert!(
                    batch.len() <= MAX_BATCH_ENVELOPES as usize,
                    "own core must respect the segment budget"
                );
                debug_assert!(
                    batch
                        .iter()
                        .try_fold(cursor, |expected, envelope| {
                            (envelope.payload().prev_digest() == Some(&expected))
                                .then(|| {
                                    envelope
                                        .digest()
                                        .expect("an envelope out of our own log re-encodes")
                                })
                                .ok_or(())
                        })
                        .is_ok(),
                    "own core must answer segments parent-first from the cursor"
                );

                let tip = batch
                    .last()
                    .expect("the batch is non-empty")
                    .digest()
                    .expect("an envelope out of our own log re-encodes");
                self.state = State::AwaitSegment {
                    cursor: tip,
                    sent: sent + batch.len() as u64,
                };
                vec![
                    Effect::Send(Message::Envelopes(Envelopes { batch })),
                    Effect::Ask(Query::Segment { after: tip }),
                ]
            }

            // A frame the phase does not admit is the peer's breach…
            (state @ (State::AwaitHello | State::AwaitFindSplit), Input::Message(message)) => {
                let expected = state.expecting();
                self.breach(Breach::Unexpected {
                    got: message.kind(),
                    expected,
                })
            }
            // …while everything below is the driver breaking its contract.
            (State::AwaitSplitPoint | State::AwaitSegment { .. }, Input::Message(_)) => {
                panic!("driver fed a frame while an Ask was unresolved")
            }
            (State::Terminal, _) => panic!("driver fed input after the session ended"),
            (_, Input::Answer(_)) => {
                panic!("driver answered a query nothing asked for, or answered in the wrong shape")
            }
            (_, Input::Ingested) => panic!("a server never ingests"),
        }
    }

    fn breach(&mut self, breach: Breach) -> Vec<Effect<ServeOutcome>> {
        self.state = State::Terminal;
        vec![Effect::Violation(breach)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proto::{Hello, MessageKind},
        testutil::{digest_of, set},
    };
    use wire::Envelope;

    fn d(byte: u8) -> EnvelopeDigest {
        EnvelopeDigest::from_bytes([byte; 32])
    }

    fn peer_hello() -> Message {
        Message::Hello(Hello {
            version: PROTOCOL_VERSION,
            head: d(0x01),
        })
    }

    fn one(mut effects: Vec<Effect<ServeOutcome>>) -> Effect<ServeOutcome> {
        assert_eq!(effects.len(), 1, "expected exactly one effect: {effects:?}");
        effects.pop().expect("length checked")
    }

    fn two(mut effects: Vec<Effect<ServeOutcome>>) -> (Effect<ServeOutcome>, Effect<ServeOutcome>) {
        assert_eq!(
            effects.len(),
            2,
            "expected exactly two effects: {effects:?}"
        );
        let second = effects.pop().expect("length checked");
        (effects.pop().expect("length checked"), second)
    }

    /// Drives a fresh server to the point of streaming from `at`.
    fn streaming(at: EnvelopeDigest) -> Server {
        let mut server = Server::new(d(0x02));
        server.handle(Input::Message(peer_hello()));
        server.handle(Input::Message(Message::FindSplit(FindSplit {
            locator: vec![at],
        })));
        let (split, ask) = two(server.handle(Input::Answer(Answer::SplitPoint(Some(at)))));
        assert!(matches!(split, Effect::Send(Message::Split(Split { at: a })) if a == at));
        assert!(matches!(ask, Effect::Ask(Query::Segment { after, .. }) if after == at));
        server
    }

    fn chained(prev: EnvelopeDigest, n: usize) -> (Vec<Envelope>, EnvelopeDigest) {
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
    fn hello_is_answered_with_hello() {
        let mut server = Server::new(d(0x02));
        let effect = one(server.handle(Input::Message(peer_hello())));
        assert!(matches!(
            effect,
            Effect::Send(Message::Hello(hello))
                if hello.version == PROTOCOL_VERSION && hello.head == d(0x02)
        ));
    }

    #[test]
    fn a_version_mismatch_is_a_breach() {
        let mut server = Server::new(d(0x02));
        let effect = one(server.handle(Input::Message(Message::Hello(Hello {
            version: 0,
            head: d(0x01),
        }))));
        assert!(matches!(
            effect,
            Effect::Violation(Breach::Version { theirs: 0, .. })
        ));
    }

    #[test]
    fn find_split_consults_the_core() {
        let mut server = Server::new(d(0x02));
        server.handle(Input::Message(peer_hello()));

        let locator = vec![d(0x01), d(0x03)];
        let effect = one(server.handle(Input::Message(Message::FindSplit(FindSplit {
            locator: locator.clone(),
        }))));
        assert!(matches!(
            effect,
            Effect::Ask(Query::SplitPoint(asked)) if asked == locator
        ));
    }

    #[test]
    fn an_empty_locator_is_a_breach() {
        let mut server = Server::new(d(0x02));
        server.handle(Input::Message(peer_hello()));
        let effect = one(server.handle(Input::Message(Message::FindSplit(FindSplit {
            locator: Vec::new(),
        }))));
        assert!(matches!(effect, Effect::Violation(Breach::EmptyLocator)));
    }

    #[test]
    fn an_oversized_locator_is_a_breach() {
        let mut server = Server::new(d(0x02));
        server.handle(Input::Message(peer_hello()));
        let locator = vec![d(0x01); locator::MAX_LOCATOR_LEN + 1];
        let effect = one(server.handle(Input::Message(Message::FindSplit(FindSplit { locator }))));
        assert!(matches!(
            effect,
            Effect::Violation(Breach::OversizedLocator { got }) if got == 65
        ));
    }

    #[test]
    fn no_split_point_says_so_and_ends() {
        let mut server = Server::new(d(0x02));
        server.handle(Input::Message(peer_hello()));
        server.handle(Input::Message(Message::FindSplit(FindSplit {
            locator: vec![d(0x01)],
        })));

        let (sent, done) = two(server.handle(Input::Answer(Answer::SplitPoint(None))));
        assert!(matches!(sent, Effect::Send(Message::NoSplit(_))));
        assert!(matches!(done, Effect::Done(ServeOutcome::NoCommonHistory)));
    }

    /// The streaming loop: each non-empty segment goes out as a batch and
    /// asks for the next from the new tip; the empty segment closes with
    /// `CaughtUp` at that tip.
    #[test]
    fn segments_stream_until_the_core_runs_dry() {
        let mut server = streaming(d(0x10));
        let (first, first_tip) = chained(d(0x10), 2);
        let (second, tip) = chained(first_tip, 1);

        let (sent, ask) = two(server.handle(Input::Answer(Answer::Segment(first.clone()))));
        assert!(matches!(
            sent,
            Effect::Send(Message::Envelopes(Envelopes { batch })) if batch == first
        ));
        assert!(matches!(
            ask,
            Effect::Ask(Query::Segment { after, .. }) if after == first_tip
        ));

        let (sent, ask) = two(server.handle(Input::Answer(Answer::Segment(second))));
        assert!(matches!(sent, Effect::Send(Message::Envelopes(_))));
        assert!(matches!(
            ask,
            Effect::Ask(Query::Segment { after, .. }) if after == tip
        ));

        let (sent, done) = two(server.handle(Input::Answer(Answer::Segment(Vec::new()))));
        assert!(matches!(sent, Effect::Send(Message::CaughtUp(_))));
        assert!(matches!(
            done,
            Effect::Done(ServeOutcome::Served { head, sent: 3 }) if head == tip
        ));
    }

    /// An immediately-empty segment — the split was the head, or a reorg
    /// detached the cursor — closes at the split point itself.
    #[test]
    fn an_immediately_dry_stream_caught_up_at_the_split() {
        let mut server = streaming(d(0x10));
        let (sent, done) = two(server.handle(Input::Answer(Answer::Segment(Vec::new()))));
        assert!(matches!(sent, Effect::Send(Message::CaughtUp(_))));
        assert!(matches!(
            done,
            Effect::Done(ServeOutcome::Served { head, sent: 0 }) if head == d(0x10)
        ));
    }

    #[test]
    fn a_find_split_before_hello_is_a_breach() {
        let mut server = Server::new(d(0x02));
        let effect = one(server.handle(Input::Message(Message::FindSplit(FindSplit {
            locator: vec![d(0x01)],
        }))));
        assert!(matches!(
            effect,
            Effect::Violation(Breach::Unexpected {
                got: MessageKind::FindSplit,
                expected: "Hello",
            })
        ));
    }

    /// A puller never sends `Envelopes`; one that does is off-script.
    #[test]
    fn an_envelopes_frame_from_the_puller_is_a_breach() {
        let mut server = Server::new(d(0x02));
        server.handle(Input::Message(peer_hello()));
        let (batch, _) = chained(d(0x10), 1);
        let effect = one(server.handle(Input::Message(Message::Envelopes(Envelopes { batch }))));
        assert!(matches!(
            effect,
            Effect::Violation(Breach::Unexpected {
                got: MessageKind::Envelopes,
                expected: "FindSplit",
            })
        ));
    }

    #[test]
    #[should_panic(expected = "a server never ingests")]
    fn an_ingested_input_panics() {
        let mut server = Server::new(d(0x02));
        server.handle(Input::Ingested);
    }

    #[test]
    #[should_panic(expected = "respect the segment budget")]
    fn an_over_budget_segment_panics() {
        let mut server = streaming(d(0x10));
        let (batch, _) = chained(d(0x10), MAX_BATCH_ENVELOPES as usize + 1);
        server.handle(Input::Answer(Answer::Segment(batch)));
    }
}
