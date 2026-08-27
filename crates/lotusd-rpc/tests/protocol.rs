//! The shape a method has to hold to: one request in, a stream of typed
//! responses out, and a failure the client can tell apart from a hangup.

use lotusd_rpc::{
    Call, ChainRange, Error, Failure, FailureKind, GetChainRange, GetVersion, Handler,
    MAX_FRAME_LEN, Request, Response, Responses, call, serve,
};
use tokio::io::{AsyncWriteExt, DuplexStream, duplex};
use wire::EnvelopeDigest;

/// A range to answer `GetChainRange` with, distinct from any real chain's.
fn range() -> ChainRange {
    ChainRange {
        root: EnvelopeDigest::from_bytes([3u8; 32]),
        head: EnvelopeDigest::from_bytes([7u8; 32]),
    }
}

/// A handler that answers each method the way the daemon does, plus a
/// `GetChainRange` that streams so the multi-response path is exercised.
struct Fake {
    /// How many times `GetChainRange` answers before ending its stream.
    ranges: usize,
    /// Fails every request with this, rather than answering.
    fail: Option<Failure>,
}

impl Fake {
    fn new() -> Self {
        Self {
            ranges: 1,
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
