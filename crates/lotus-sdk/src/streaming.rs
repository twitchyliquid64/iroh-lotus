//! The answers to a request that answers more than once.

use core::{
    pin::Pin,
    task::{Context, Poll},
};

use lotusd_rpc::{Call, Method};
use tokio::net::UnixStream;
use tokio_stream::{Stream, StreamExt};

use crate::Error;

/// The responses to one request, as the daemon sends them.
///
/// Dropping it hangs up the connection, which is how the daemon learns a
/// client has stopped listening: a watch ends the moment its `Streaming`
/// goes away.
#[derive(Debug)]
pub struct Streaming<M: Method> {
    call: Call<UnixStream, M>,
}

impl<M: Method> Streaming<M> {
    pub(crate) fn new(call: Call<UnixStream, M>) -> Self {
        Self { call }
    }

    /// The next response, or `None` once the daemon has finished answering.
    pub async fn next(&mut self) -> Result<Option<M::Response>, Error> {
        self.call.next().await.map_err(Error::Rpc)
    }

    /// Every response still to come, or the first error.
    pub async fn collect(self) -> Result<Vec<M::Response>, Error> {
        StreamExt::collect(self).await
    }
}

impl<M: Method> Stream for Streaming<M> {
    type Item = Result<M::Response, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.call)
            .poll_next(cx)
            .map(|item| item.map(|response| response.map_err(Error::Rpc)))
    }
}
