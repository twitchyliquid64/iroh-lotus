//! The shape a method has to hold to: one request in, a stream of typed
//! responses out, and a failure the client can tell apart from a hangup.

use std::collections::BTreeMap;

use lotusd_rpc::{
    Call, ChainRange, ChainWalk, Changed, EnvelopeFrame, EnvelopeSelector, Error, Failure,
    FailureKind, GetChainRange, GetEnvelopes, GetVersion, Handler, MAX_FRAME_LEN, NamespaceChange,
    Request, Response, Responses, Verification, Watch, WatchEvent, WatchPath, WatchSelector, call,
    serve,
};
use std::time::Duration;

use tokio::io::{AsyncWriteExt, DuplexStream, duplex};
use wire::{
    Envelope, EnvelopeDigest, Msg, VerificationStatus,
    keys::KeyId,
    msg::{FullCheckpoint, InitMsg, NamespaceKey},
    subkey::SubkeyPath,
};

/// A range to answer `GetChainRange` with, distinct from any real chain's.
fn range() -> ChainRange {
    ChainRange {
        root: EnvelopeDigest::from_bytes([3u8; 32]),
        head: EnvelopeDigest::from_bytes([7u8; 32]),
    }
}

/// A change to answer a watch with, exercising both shapes a namespace
/// change takes.
fn changed() -> Changed {
    Changed {
        from: EnvelopeDigest::from_bytes([3u8; 32]),
        head: EnvelopeDigest::from_bytes([7u8; 32]),
        changes: BTreeMap::from([
            (key("a"), NamespaceChange::Whole),
            (
                key("b"),
                NamespaceChange::Paths([path("servers[0].host"), path("name")].into()),
            ),
        ]),
        orphaned: [EnvelopeDigest::from_bytes([9u8; 32])].into(),
    }
}

/// A fixed reading for the fake's log to claim, well clear of now.
const STORED_AT_MILLIS: i64 = 1_787_000_000_000;

/// A genesis envelope, the one shape that can be built without naming a
/// parent that has to exist.
fn envelope() -> Envelope {
    Envelope::new(Msg::Init(InitMsg {
        state: FullCheckpoint::default(),
    }))
}

fn key(k: &str) -> NamespaceKey {
    NamespaceKey::try_new(k).unwrap()
}

fn path(text: &str) -> SubkeyPath {
    text.parse().unwrap()
}

/// A handler that answers each method the way the daemon does, plus a
/// `GetChainRange` that streams so the multi-response path is exercised.
struct Fake {
    /// How many times `GetChainRange` answers before ending its stream.
    ranges: usize,
    /// The watch selector the last request carried, for a test to read back.
    watched: Option<WatchSelector>,
    /// The envelope selector the last request carried, likewise.
    selected: Option<EnvelopeSelector>,
    /// Fails every request with this, rather than answering.
    fail: Option<Failure>,
}

impl Fake {
    fn new() -> Self {
        Self {
            ranges: 1,
            watched: None,
            selected: None,
            fail: None,
        }
    }
}

impl Handler for Fake {
    async fn handle(
        &mut self,
        request: Request,
        responses: &mut Responses<'_>,
    ) -> Result<(), Error> {
        if let Some(failure) = self.fail.clone() {
            return Err(failure.into());
        }

        match request {
            Request::GetVersion(_) => responses.send(Response::Version("1.2.3".to_owned())).await,
            Request::GetChainRange(_) => {
                for _ in 0..self.ranges {
                    responses.send(Response::ChainRange(range())).await?;
                }
                Ok(())
            }
            Request::GetEnvelopes(get) => {
                self.selected = Some(get.select.clone());

                // One frame each, as the daemon sends them: an envelope
                // per digest asked for, or a two-envelope chain.
                let digests = match get.select {
                    EnvelopeSelector::Digests(digests) => digests,
                    EnvelopeSelector::Chain(walk) => (0..walk.limit.unwrap_or(2))
                        .map(|n| EnvelopeDigest::from_bytes([n as u8; 32]))
                        .collect(),
                };

                for digest in digests {
                    let mut envelope = envelope();
                    envelope.set_verification_status(VerificationStatus::AllMatched {
                        total_weight: 3,
                    });
                    responses
                        .send(Response::Envelope(EnvelopeFrame::new(
                            digest,
                            envelope,
                            STORED_AT_MILLIS,
                        )))
                        .await?;
                }
                Ok(())
            }
            Request::Watch(watch) => {
                self.watched = Some(watch.selector.clone());
                match watch.selector {
                    // The one selector that can answer without waiting.
                    WatchSelector::Orphaned(digest) => {
                        responses
                            .send(Response::Watch(WatchEvent::AlreadyOrphaned(digest)))
                            .await
                    }
                    _ => {
                        responses
                            .send(Response::Watch(WatchEvent::Changed(changed())))
                            .await
                    }
                }
            }
        }
    }
}

/// Serves `handler` on one end of an in-memory pipe, handing back the other.
fn connect(mut handler: Fake) -> DuplexStream {
    let (client, mut server) = duplex(64 * 1024);
    tokio::spawn(async move {
        serve(&mut server, &mut handler).await.unwrap();
    });
    client
}

#[tokio::test]
async fn get_version_answers_with_the_version() {
    let version = call(connect(Fake::new()), GetVersion {}).await.unwrap();

    assert_eq!(version, "1.2.3");
}

#[tokio::test]
async fn get_chain_range_answers_with_both_ends() {
    let answer = call(connect(Fake::new()), GetChainRange {}).await.unwrap();

    assert_eq!(answer, range());
}

#[tokio::test]
async fn a_method_may_answer_more_than_once() {
    let mut stream = Call::send(
        connect(Fake {
            ranges: 3,
            ..Fake::new()
        }),
        GetChainRange {},
    )
    .await
    .unwrap();

    for _ in 0..3 {
        assert_eq!(stream.next().await.unwrap(), Some(range()));
    }
    // The daemon closing is what ends the stream.
    assert_eq!(stream.next().await.unwrap(), None);
}

#[tokio::test]
async fn a_method_that_answers_nothing_closes_the_stream() {
    let mut stream = Call::send(
        connect(Fake {
            ranges: 0,
            ..Fake::new()
        }),
        GetChainRange {},
    )
    .await
    .unwrap();

    assert_eq!(stream.next().await.unwrap(), None);
}

#[tokio::test]
async fn a_stream_that_ends_unanswered_is_not_a_silent_success() {
    assert!(matches!(
        call(
            connect(Fake {
                ranges: 0,
                ..Fake::new()
            }),
            GetChainRange {}
        )
        .await,
        Err(Error::NoResponse)
    ));
}

#[tokio::test]
async fn a_handler_failure_reaches_the_client() {
    let err = call(
        connect(Fake {
            fail: Some(Failure::internal("the disk melted")),
            ..Fake::new()
        }),
        GetChainRange {},
    )
    .await
    .unwrap_err();

    let Error::Failed(failure) = err else {
        panic!("expected a reported failure, got {err:?}");
    };
    assert_eq!(failure.kind, FailureKind::Internal);
    assert_eq!(failure.message, "the disk melted");
}

#[tokio::test]
async fn a_request_the_daemon_cannot_decode_is_unsupported() {
    let mut client = connect(Fake::new());

    // A well-formed frame carrying a method from some future build.
    let body = wire::encode(&"GetTheFuture").unwrap();
    client
        .write_all(&(body.len() as u32).to_be_bytes())
        .await
        .unwrap();
    client.write_all(&body).await.unwrap();

    let mut stream: Call<_, GetChainRange> = Call::send(client, GetChainRange {}).await.unwrap();
    let Err(Error::Failed(failure)) = stream.next().await else {
        panic!("expected an unsupported failure");
    };
    assert_eq!(failure.kind, FailureKind::Unsupported);
}

#[tokio::test]
async fn a_frame_past_the_limit_is_refused_before_it_is_read() {
    let mut client = connect(Fake::new());

    client
        .write_all(&(MAX_FRAME_LEN + 1).to_be_bytes())
        .await
        .unwrap();

    let mut stream: Call<_, GetChainRange> = Call::send(client, GetChainRange {}).await.unwrap();
    // The server tore the connection down rather than allocating the body.
    assert!(stream.next().await.unwrap().is_none());
}

/// Every selector survives the round trip to the daemon and back, the
/// nested path shape included.
#[tokio::test]
async fn a_watch_carries_its_selector_across() {
    for selector in [
        WatchSelector::Head,
        WatchSelector::Namespace(key("a")),
        WatchSelector::Path(WatchPath {
            key: key("a"),
            path: path("servers[0].host"),
        }),
        WatchSelector::Orphaned(EnvelopeDigest::from_bytes([5u8; 32])),
    ] {
        let (client, mut server) = duplex(64 * 1024);
        let served = tokio::spawn(async move {
            let mut handler = Fake::new();
            serve(&mut server, &mut handler).await.unwrap();
            handler.watched
        });

        let mut call = Call::send(
            client,
            Watch {
                selector: selector.clone(),
            },
        )
        .await
        .unwrap();
        call.next().await.unwrap().unwrap();
        drop(call);

        assert_eq!(served.await.unwrap(), Some(selector));
    }
}

/// A change survives the round trip whole: both namespace shapes and the
/// orphan set.
#[tokio::test]
async fn a_watch_event_carries_the_whole_change_across() {
    let event = call(
        connect(Fake::new()),
        Watch {
            selector: WatchSelector::Head,
        },
    )
    .await
    .unwrap();

    assert_eq!(event, WatchEvent::Changed(changed()));
}

/// A watch on an envelope already off the chain is answered and closed
/// rather than left open on an event that can never come.
#[tokio::test]
async fn an_already_orphaned_watch_is_answered_and_ended() {
    let digest = EnvelopeDigest::from_bytes([5u8; 32]);
    let mut call = Call::send(
        connect(Fake::new()),
        Watch {
            selector: WatchSelector::Orphaned(digest),
        },
    )
    .await
    .unwrap();

    assert_eq!(
        call.next().await.unwrap(),
        Some(WatchEvent::AlreadyOrphaned(digest))
    );
    assert_eq!(call.next().await.unwrap(), None);
}

/// One frame per envelope, not one frame carrying all of them: a chain
/// longer than a frame is what the streaming shape is for.
#[tokio::test]
async fn get_envelopes_streams_one_frame_per_envelope() {
    let mut call = Call::send(connect(Fake::new()), GetEnvelopes::newest(3))
        .await
        .unwrap();

    let mut digests = Vec::new();
    while let Some(frame) = call.next().await.unwrap() {
        digests.push(frame.digest);
    }

    assert_eq!(
        digests,
        (0..3)
            .map(|n| EnvelopeDigest::from_bytes([n; 32]))
            .collect::<Vec<_>>()
    );
}

/// The verification status is outside an envelope's canonical encoding, so
/// it has to travel beside it — otherwise every fetched envelope reads as
/// unchecked however the sending node scored it.
#[tokio::test]
async fn an_envelope_frame_carries_the_verification_status_beside_the_envelope() {
    let frame = call(connect(Fake::new()), GetEnvelopes::newest(1))
        .await
        .unwrap();

    assert_eq!(frame.verification, Verification::AllMatched(3));
    // The envelope itself arrived unchecked, as the encoding demands.
    assert_eq!(
        frame.envelope.verification_status(),
        &VerificationStatus::Unchecked
    );

    let (_digest, envelope) = frame.into_parts();
    assert_eq!(
        envelope.verification_status(),
        &VerificationStatus::AllMatched { total_weight: 3 }
    );
}

/// A failed status is not just a verdict: which keys failed travels with
/// it, or a client is told an envelope failed and never which signatures.
#[test]
fn a_failed_verification_carries_the_keys_that_failed() {
    let status = VerificationStatus::Failed {
        failing_key_ids: [KeyId::from_bytes([7u8; 32]), KeyId::from_bytes([9u8; 32])].into(),
    };

    let carried = Verification::from(&status);
    assert_eq!(
        carried,
        Verification::Failed([KeyId::from_bytes([7u8; 32]), KeyId::from_bytes([9u8; 32])].into()),
    );
    assert_eq!(VerificationStatus::from(carried), status);
}

/// Every selector survives the round trip, limit and digest list included.
#[tokio::test]
async fn a_get_envelopes_carries_its_selector_across() {
    for request in [
        GetEnvelopes::chain(),
        GetEnvelopes::newest(2),
        GetEnvelopes::since(Duration::from_secs(900)),
        GetEnvelopes::walk(ChainWalk::default().with_limit(4).with_since(HALF_A_SECOND)),
        GetEnvelopes::digests([EnvelopeDigest::from_bytes([5u8; 32])]),
        GetEnvelopes::digests([]),
    ] {
        let (client, mut server) = duplex(64 * 1024);
        let served = tokio::spawn(async move {
            let mut handler = Fake::new();
            serve(&mut server, &mut handler).await.unwrap();
            handler.selected
        });

        let mut call = Call::send(client, request.clone()).await.unwrap();
        while call.next().await.unwrap().is_some() {}

        assert_eq!(served.await.unwrap(), Some(request.select));
    }
}

/// Asking for nothing is answered with nothing, and the stream simply ends
/// — which is also how a digest the node does not hold reads.
#[tokio::test]
async fn asking_for_no_envelopes_ends_the_stream_at_once() {
    let mut call = Call::send(connect(Fake::new()), GetEnvelopes::digests([]))
        .await
        .unwrap();

    assert_eq!(call.next().await.unwrap(), None);
}

/// Sub-second windows survive the trip: the wire carries milliseconds, so
/// a window shorter than a second must not round down to "everything".
const HALF_A_SECOND: Duration = Duration::from_millis(500);

#[test]
fn a_window_crosses_as_milliseconds() {
    assert_eq!(
        ChainWalk::default().with_since(HALF_A_SECOND).since(),
        Some(HALF_A_SECOND),
    );
    assert_eq!(ChainWalk::default().since(), None);

    // A window past what the field holds saturates rather than wrapping
    // into a short one that would quietly hide most of the chain.
    assert_eq!(
        ChainWalk::default().with_since(Duration::MAX).since_millis,
        Some(u64::MAX),
    );
}

/// The stored-at reading is the node's own clock, and it crosses as a
/// plain number of milliseconds since the epoch that reads back the same.
#[tokio::test]
async fn an_envelope_frame_carries_when_the_node_stored_it() {
    let frame = call(connect(Fake::new()), GetEnvelopes::newest(1))
        .await
        .unwrap();

    assert_eq!(frame.stored_at_millis, STORED_AT_MILLIS);
    assert_eq!(
        frame.stored_at(),
        chrono::DateTime::from_timestamp_millis(STORED_AT_MILLIS),
    );

    // A number no datetime can hold is a peer sending nonsense, not a
    // reading: it reads back as no time rather than as some other one.
    let nonsense = EnvelopeFrame::new(EnvelopeDigest::from_bytes([1u8; 32]), envelope(), i64::MAX);
    assert_eq!(nonsense.stored_at(), None);
}
