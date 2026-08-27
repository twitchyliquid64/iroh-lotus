//! The crate's error type.

use crate::{Failure, MAX_FRAME_LEN};

/// An error produced while speaking the local control protocol.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The connection failed.
    #[error("local socket I/O failed")]
    IO(#[source] std::io::Error),
    /// A frame's body was not the CBOR the protocol expects.
    #[error("frame could not be encoded or decoded")]
    Codec(#[source] wire::Error),
    /// A frame declared, or would need, a body past [`MAX_FRAME_LEN`].
    #[error("frame of {0} bytes exceeds the {MAX_FRAME_LEN} byte limit")]
    FrameTooLarge(u64),
    /// The connection ended part way through a frame.
    #[error("connection ended mid-frame")]
    Truncated,
    /// The peer answered a different method than the one asked.
    #[error("{got} is not an answer to a {expected} request")]
    UnexpectedResponse {
        /// The method that was requested.
        expected: &'static str,
        /// The response variant that came back.
        got: &'static str,
    },
    /// The peer reported a failure. Also how a [`Handler`](crate::Handler)
    /// reports one: [`serve`](crate::serve) turns it into the stream's last
    /// frame rather than dropping the connection.
    #[error("request could not be served: {0}")]
    Failed(Failure),
    /// The connection closed before a single response arrived.
    #[error("connection closed without an answer")]
    NoResponse,
}

impl From<Failure> for Error {
    fn from(failure: Failure) -> Self {
        Error::Failed(failure)
    }
}
