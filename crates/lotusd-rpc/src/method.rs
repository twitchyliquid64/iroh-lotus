//! What ties a request to the answers it draws back.

use crate::{ChainRange, Error, GetChainRange, GetVersion, Request, Response, Watch, WatchEvent};

/// One method of the local control protocol.
///
/// Implemented on the request payload itself, so a caller names a method by
/// the value it sends and never has to name the response type: [`call`] and
/// [`Call`] hand back `Self::Response` already unwrapped.
///
/// [`call`]: crate::call
/// [`Call`]: crate::Call
pub trait Method: Into<Request> {
    /// What this method is called in errors.
    const NAME: &'static str;

    /// What one response frame carries.
    type Response;

    /// Reads this method's answer out of a response frame.
    fn read(response: Response) -> Result<Self::Response, Error>;
}

/// Declares the methods of the protocol, pairing each request payload with
/// the [`Response`] variant that answers it.
///
/// Kept in one place so a new method cannot be half-added: a request whose
/// response variant is never named, or the reverse, does not compile.
macro_rules! methods {
    ($($name:literal: $request:ident => $variant:ident($response:ty)),* $(,)?) => {$(
        impl From<$request> for Request {
            fn from(request: $request) -> Self {
                Request::$request(request)
            }
        }

        impl Method for $request {
            const NAME: &'static str = $name;
            type Response = $response;

            fn read(response: Response) -> Result<Self::Response, Error> {
                match response {
                    Response::$variant(value) => Ok(value),
                    // A failure ends any method's stream, so it is this
                    // method's answer rather than a mismatched one.
                    Response::Failed(failure) => Err(Error::Failed(failure)),
                    other => Err(Error::UnexpectedResponse {
                        expected: $name,
                        got: other.name(),
                    }),
                }
            }
        }
    )*};
}

methods! {
    "version": GetVersion => Version(String),
    "chain range": GetChainRange => ChainRange(ChainRange),
    "watch": Watch => Watch(WatchEvent),
}
