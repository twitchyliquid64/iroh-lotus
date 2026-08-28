//! Serving one request per connection.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::{Error, Failure, Request, Response, frame};

/// Serves requests arriving on the local control socket.
///
/// A handler answers with as many responses as the method calls for,
/// including none; the client sees the stream end when the connection
/// closes.
pub trait Handler {
    /// Serves one request, writing each response to `responses`.
    ///
    /// Returning [`Error::Failed`] ends the stream with that failure — the
    /// client is told why. Any other error is the transport itself giving
    /// out, and there is nowhere left to report it.
    fn handle(
        &mut self,
        request: Request,
        responses: &mut Responses<'_>,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}

/// The answers to one request, as a handler writes them.
pub struct Responses<'a> {
    writer: &'a mut (dyn AsyncWrite + Unpin + Send),
}

impl Responses<'_> {
    /// Writes one response frame.
    pub async fn send(&mut self, response: Response) -> Result<(), Error> {
        frame::write(self.writer, &response).await
    }
}

/// Serves one request on `stream`: reads the request frame, hands it to
/// `handler`, and writes back what it answers with.
///
/// The connection carries this one request. Its answer ends where the
/// caller drops `stream`, so a handler that has said all it has to say
/// simply returns.
///
/// A client hanging up ends the answer too, and is watched for rather than
/// discovered on the next write. A handler streaming something long-lived —
/// a subscription that may have nothing to say for hours — would otherwise
/// hold whatever it is streaming from until the client's departure finally
/// broke a send.
pub async fn serve<S, H>(stream: &mut S, handler: &mut H) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    H: Handler,
{
    let request = match frame::read(stream).await {
        // The client hung up before asking for anything.
        Ok(None) => return Ok(()),
        Ok(Some(request)) => request,
        // A request this build cannot decode is one it does not serve.
        // Answered rather than dropped, so a newer client learns why.
        Err(Error::Codec(e)) => {
            return Responses { writer: stream }
                .send(Response::Failed(Failure::unsupported(e.to_string())))
                .await;
        }
        Err(e) => return Err(e),
    };

    let (mut reader, mut writer) = tokio::io::split(stream);

    // Scoped so the handler's borrow of the writer ends with the race, and
    // a failure can still be reported on it below.
    let answered = {
        let mut responses = Responses {
            writer: &mut writer,
        };
        tokio::select! {
            answered = handler.handle(request, &mut responses) => Some(answered),
            () = hung_up(&mut reader) => None,
        }
    };

    match answered {
        // Nobody left to tell.
        None => Ok(()),
        Some(Ok(())) => Ok(()),
        Some(Err(Error::Failed(failure))) => {
            Responses {
                writer: &mut writer,
            }
            .send(Response::Failed(failure))
            .await
        }
        Some(Err(e)) => Err(e),
    }
}

/// Resolves once the client has nothing more to say on this connection:
/// it closed, the connection broke, or — one request per connection — it
/// sent bytes that cannot belong to the request already being served.
async fn hung_up<R: AsyncRead + Unpin>(reader: &mut R) {
    let mut scratch = [0u8; 1];
    // Every outcome ends the answer, so none of them is an error here.
    let _ = reader.read(&mut scratch).await;
}
