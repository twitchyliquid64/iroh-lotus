//! Issuing a request and reading the answers to it.

use core::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_stream::Stream;

use crate::{AnsweredOnce, Error, Method, Response, frame};

/// Sends `method` on `stream` and reads back the single response to it.
///
/// Only for the methods that answer exactly once. A method whose answer
/// streams needs [`Call`], and does not compile here:
///
/// ```compile_fail
/// use lotusd_rpc::{Watch, WatchSelector, call};
///
/// async fn first_event_only(stream: tokio::io::DuplexStream) {
///     let _ = call(stream, Watch { selector: WatchSelector::Head }).await;
/// }
/// ```
pub async fn call<S, M>(stream: S, method: M) -> Result<M::Response, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    M: AnsweredOnce,
{
    let mut call = Call::send(stream, method).await?;
    call.next().await?.ok_or(Error::NoResponse)
}

/// A request in flight: the connection it went out on, and the responses
/// still arriving.
///
/// The connection carries this one request and nothing after it, so dropping
/// the call is how a client stops listening. Read it with [`next`](Self::next),
/// or as a [`Stream`] of responses.
#[derive(Debug)]
pub struct Call<S, M> {
    stream: S,
    frames: frame::Reader,
    // `fn() -> M` rather than `M`, so a call is `Send` whatever the method is.
    method: PhantomData<fn() -> M>,
}

impl<S, M> Call<S, M>
where
    S: AsyncWrite + Unpin,
    M: Method,
{
    /// Sends `method` on `stream`, returning the call its answers arrive on.
    pub async fn send(mut stream: S, method: M) -> Result<Self, Error> {
        frame::write(&mut stream, &method.into()).await?;
        Ok(Self {
            stream,
            frames: frame::Reader::new(),
            method: PhantomData,
        })
    }
}

impl<S, M> Call<S, M>
where
    S: AsyncRead + Unpin,
    M: Method,
{
    /// The next response, or `None` once the daemon has finished answering.
    pub async fn next(&mut self) -> Result<Option<M::Response>, Error> {
        core::future::poll_fn(|cx| self.poll_response(cx)).await
    }

    /// Polls for the next response: [`next`](Self::next), for a caller
    /// driving the call by hand.
    pub fn poll_response(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<M::Response>, Error>> {
        self.frames
            .poll_read::<Response, _>(cx, Pin::new(&mut self.stream))
            .map(|frame| frame.and_then(|frame| frame.map(M::read).transpose()))
    }
}

impl<S, M> Stream for Call<S, M>
where
    S: AsyncRead + Unpin,
    M: Method,
{
    type Item = Result<M::Response, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.poll_response(cx).map(Result::transpose)
    }
}
