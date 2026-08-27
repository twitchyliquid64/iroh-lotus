//! Issuing a request and reading the answers to it.

use core::marker::PhantomData;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::{Error, Method, frame};

/// Sends `method` on `stream` and reads back the single response to it.
///
/// For the methods that answer exactly once; a method whose answer streams
/// needs [`Call`].
pub async fn call<S, M>(stream: S, method: M) -> Result<M::Response, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    M: Method,
{
    let mut call = Call::send(stream, method).await?;
    call.next().await?.ok_or(Error::NoResponse)
}

/// A request in flight: the connection it went out on, and the responses
/// still arriving.
///
/// The connection carries this one request and nothing after it, so dropping
/// the call is how a client stops listening.
#[derive(Debug)]
pub struct Call<S, M> {
    stream: S,
    // `fn() -> M` rather than `M`, so a call is `Send` whatever the method is.
    method: PhantomData<fn() -> M>,
}

impl<S, M> Call<S, M>
where
    S: AsyncRead + AsyncWrite + Unpin,
    M: Method,
{
    /// Sends `method` on `stream`, returning the call its answers arrive on.
    pub async fn send(mut stream: S, method: M) -> Result<Self, Error> {
        frame::write(&mut stream, &method.into()).await?;
        Ok(Self {
            stream,
            method: PhantomData,
        })
    }

    /// The next response, or `None` once the daemon has finished answering.
    pub async fn next(&mut self) -> Result<Option<M::Response>, Error> {
        frame::read(&mut self.stream)
            .await?
            .map(M::read)
            .transpose()
    }
}
