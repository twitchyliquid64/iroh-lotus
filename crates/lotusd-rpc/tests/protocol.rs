//! The shape a method has to hold to: one request in, a stream of typed
//! responses out, and a failure the client can tell apart from a hangup.

use lotusd_rpc::{
    Call, Error, Failure, FailureKind, GetHead, GetVersion, Handler, MAX_FRAME_LEN, Request,
    Response, Responses, call, serve,
};
use tokio::io::{AsyncWriteExt, DuplexStream, duplex};
use wire::EnvelopeDigest;

/// A digest to answer `GetHead` with, distinct from any real chain's.
fn head() -> EnvelopeDigest {
    EnvelopeDigest::from_bytes([7u8; 32])
}

/// A handler that answers each method the way the daemon does, plus a
/// `GetHead` that streams so the multi-response path is exercised.
struct Fake {
    /// How many times `GetHead` answers before ending its stream.
    heads: usize,
    /// Fails every request with this, rather than answering.
    fail: Option<Failure>,
}

impl Fake {
    fn new() -> Self {
        Self {
            heads: 1,
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
            Request::GetHead(_) => {
                for _ in 0..self.heads {
                    responses.send(Response::Head(head())).await?;
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
async fn get_head_answers_with_the_head() {
    let digest = call(connect(Fake::new()), GetHead {}).await.unwrap();

    assert_eq!(digest, head());
}

#[tokio::test]
async fn a_method_may_answer_more_than_once() {
    let mut stream = Call::send(
        connect(Fake {
            heads: 3,
            ..Fake::new()
        }),
        GetHead {},
    )
    .await
    .unwrap();

    for _ in 0..3 {
        assert_eq!(stream.next().await.unwrap(), Some(head()));
    }
    // The daemon closing is what ends the stream.
    assert_eq!(stream.next().await.unwrap(), None);
}

#[tokio::test]
async fn a_method_that_answers_nothing_closes_the_stream() {
    let mut stream = Call::send(
        connect(Fake {
            heads: 0,
            ..Fake::new()
        }),
        GetHead {},
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
                heads: 0,
                ..Fake::new()
            }),
            GetHead {}
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
        GetHead {},
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

    let mut stream: Call<_, GetHead> = Call::send(client, GetHead {}).await.unwrap();
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

    let mut stream: Call<_, GetHead> = Call::send(client, GetHead {}).await.unwrap();
    // The server tore the connection down rather than allocating the body.
    assert!(stream.next().await.unwrap().is_none());
}
