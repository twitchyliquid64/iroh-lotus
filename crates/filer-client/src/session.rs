//! A session: one volume on one filer, over a connection that is remade
//! as often as it has to be.
//!
//! The filer keeps nothing per connection, so a session that loses its
//! connection loses nothing with it: the next operation dials again and
//! carries on with the node ids it had. What cannot be papered over is an
//! operation cut off after it was sent — the filer may or may not have
//! carried it out. One that changes nothing is sent again; one that does
//! is reported as failed, for the caller to decide about.

use std::time::Duration;

use filer_proto::{
    ALPN, Close, FrameError, Hello, Mode, Welcome,
    fs::{
        Attr, ByteBuf, DirEntry, DirPage, Errno, Lookup, MAX_DIR_PAGE, Name, NodeId, ReadDir,
        Reply, Request,
    },
    read_frame, write_frame,
};
use iroh::{
    Endpoint,
    endpoint::{Connection, ConnectionError},
};
use tokio::{sync::Mutex, time::timeout};

use crate::Ticket;

/// How long the filer gets to say why it hung up, once it has.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// Why an operation did not come back with what was asked for.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("connecting to the filer")]
    Connect(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The filer hung up on the connection, for the reason it gave.
    #[error("the filer refused: {}", String::from_utf8_lossy(.0.reason()))]
    Refused(Close),
    /// The connection went away for no reason of the protocol's.
    #[error("the connection to the filer was lost")]
    Lost(#[source] ConnectionError),
    #[error("talking to the filer")]
    Frame(#[source] FrameError),
    /// The filer carried the operation out and it failed.
    #[error("the filer answered {0:?}")]
    Op(Errno),
    /// The filer answered with something the operation does not end in.
    #[error("the filer answered out of turn")]
    Unexpected,
}

impl Error {
    /// The failure the filer reported for the operation, when that is
    /// what this is.
    pub fn errno(&self) -> Option<Errno> {
        match self {
            Error::Op(errno) => Some(*errno),
            _ => None,
        }
    }
}

/// How an attempt at an operation failed short of an answer.
struct Cut {
    error: Error,
    /// Whether the request may have reached the filer.
    sent: bool,
}

/// One volume on one filer.
#[derive(Debug)]
pub struct Session {
    endpoint: Endpoint,
    ticket: Ticket,
    /// The connection in use and the mode it was welcomed at; `None`
    /// until first needed and after it is lost.
    link: Mutex<Option<(Connection, Mode)>>,
}

impl Session {
    /// A session for `ticket`'s volume, dialling from `endpoint`. Nothing
    /// is dialled until it is needed; see [`connect`](Self::connect).
    pub fn new(endpoint: Endpoint, ticket: Ticket) -> Self {
        Self {
            endpoint,
            ticket,
            link: Mutex::new(None),
        }
    }

    /// The ticket the session is for.
    pub fn ticket(&self) -> &Ticket {
        &self.ticket
    }

    /// Makes sure there is a connection, and says what the filer permits
    /// on it.
    pub async fn connect(&self) -> Result<Mode, Error> {
        self.link().await.map(|(_, mode)| mode)
    }

    /// The connection in use, dialled and welcomed first where there is
    /// none.
    async fn link(&self) -> Result<(Connection, Mode), Error> {
        let mut link = self.link.lock().await;
        if let Some((conn, mode)) = link.as_ref()
            && conn.close_reason().is_none()
        {
            return Ok((conn.clone(), *mode));
        }
        let conn = self
            .endpoint
            .connect(self.ticket.filer.clone(), ALPN)
            .await
            .map_err(|e| Error::Connect(Box::new(e)))?;
        let mode = Self::greet(&conn, &self.ticket).await?;
        tracing::debug!(volume = %self.ticket.volume, %mode, "connected to the filer");
        *link = Some((conn.clone(), mode));
        Ok((conn, mode))
    }

    /// Names the volume and reads the filer's welcome.
    async fn greet(conn: &Connection, ticket: &Ticket) -> Result<Mode, Error> {
        let greeted = async {
            let (mut send, mut recv) = conn.open_bi().await.map_err(lost)?;
            write_frame(
                &mut send,
                &Hello {
                    volume: ticket.volume.clone(),
                },
            )
            .await
            .map_err(Error::Frame)?;
            read_frame::<Welcome, _>(&mut recv)
                .await
                .map_err(Error::Frame)
        };
        match greeted.await {
            Ok(welcome) => Ok(welcome.mode),
            // A filer that refuses says so by closing, which reads here as
            // a broken stream; the close itself has the reason.
            Err(error) => Err(match timeout(CLOSE_GRACE, conn.closed()).await {
                Ok(closed) => lost(closed),
                Err(_) => error,
            }),
        }
    }

    /// Forgets `conn` as the connection in use, unless another already
    /// took its place.
    async fn drop_link(&self, conn: &Connection) {
        let mut link = self.link.lock().await;
        if link
            .as_ref()
            .is_some_and(|(held, _)| held.stable_id() == conn.stable_id())
        {
            *link = None;
        }
    }

    /// One attempt at `request` over the connection in use.
    async fn attempt(&self, request: &Request) -> Result<Reply, Cut> {
        let unsent = |error| Cut { error, sent: false };
        let (conn, _) = self.link().await.map_err(unsent)?;
        let (mut send, mut recv) = match conn.open_bi().await {
            Ok(stream) => stream,
            Err(e) => {
                self.drop_link(&conn).await;
                return Err(unsent(lost(e)));
            }
        };
        let answered = async {
            write_frame(&mut send, request).await?;
            read_frame::<Reply, _>(&mut recv).await
        };
        match answered.await {
            Ok(reply) => Ok(reply),
            Err(error) => {
                // A stream that broke on its own leaves the connection
                // standing; one that broke because the connection did
                // has the reason there.
                let error = match conn.close_reason() {
                    Some(closed) => {
                        self.drop_link(&conn).await;
                        lost(closed)
                    }
                    None => Error::Frame(error),
                };
                Err(Cut { error, sent: true })
            }
        }
    }

    /// Carries out `request`, whatever the filer answers — an
    /// [`Reply::Error`] included.
    pub async fn call(&self, request: Request) -> Result<Reply, Error> {
        match self.attempt(&request).await {
            Ok(reply) => Ok(reply),
            Err(Cut { sent, error }) if sent && request.mutates() => Err(error),
            Err(Cut { error, .. }) => {
                tracing::debug!(%error, "retrying on a fresh connection");
                self.attempt(&request).await.map_err(|cut| cut.error)
            }
        }
    }

    /// Carries out a request that ends in a node's attributes.
    pub async fn attr(&self, request: Request) -> Result<Attr, Error> {
        match self.call(request).await? {
            Reply::Attr(attr) => Ok(attr),
            other => Err(unexpected(other)),
        }
    }

    /// Carries out a request that ends in nothing.
    pub async fn done(&self, request: Request) -> Result<(), Error> {
        match self.call(request).await? {
            Reply::Done(_) => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    /// Carries out a request that ends in file contents.
    pub async fn data(&self, request: Request) -> Result<ByteBuf, Error> {
        match self.call(request).await? {
            Reply::Data(data) => Ok(data),
            other => Err(unexpected(other)),
        }
    }

    /// Carries out a request that ends in a symlink's target.
    pub async fn link_target(&self, request: Request) -> Result<String, Error> {
        match self.call(request).await? {
            Reply::Link(target) => Ok(target),
            other => Err(unexpected(other)),
        }
    }

    /// Carries out a request that ends in a page of a listing.
    pub async fn dir_page(&self, request: Request) -> Result<DirPage, Error> {
        match self.call(request).await? {
            Reply::Dir(page) => Ok(page),
            other => Err(unexpected(other)),
        }
    }

    /// Every entry of the directory `node`, in name order.
    pub async fn list(&self, node: NodeId) -> Result<Vec<DirEntry>, Error> {
        let mut entries: Vec<DirEntry> = Vec::new();
        loop {
            let page = self
                .dir_page(Request::ReadDir(ReadDir {
                    node,
                    after: entries.last().map(|entry| entry.name.clone()),
                    limit: MAX_DIR_PAGE,
                }))
                .await?;
            // A page that says more follow and brings none would never end.
            let more = page.more && !page.entries.is_empty();
            entries.extend(page.entries);
            if !more {
                return Ok(entries);
            }
        }
    }

    /// Finds the node at `path`, a `/`-separated walk down from the root.
    /// Empty segments are skipped, so `/a//b/` is `a/b`; a segment that is
    /// no name — `..` — is [`Errno::Invalid`].
    pub async fn walk(&self, path: &str) -> Result<Attr, Error> {
        let mut at = self
            .attr(Request::GetAttr(filer_proto::fs::GetAttr {
                node: NodeId::ROOT,
            }))
            .await?;
        for segment in path.split('/').filter(|segment| !segment.is_empty()) {
            let name = Name::try_new(segment).map_err(|_| Error::Op(Errno::Invalid))?;
            at = self
                .attr(Request::Lookup(Lookup {
                    parent: at.node,
                    name,
                }))
                .await?;
        }
        Ok(at)
    }
}

/// What a connection ending is called: the filer's reason where it gave
/// one of the protocol's, the loss itself otherwise.
fn lost(closed: ConnectionError) -> Error {
    match &closed {
        ConnectionError::ApplicationClosed(close) => {
            Close::from_code(close.error_code.into_inner())
                .map_or(Error::Lost(closed), Error::Refused)
        }
        _ => Error::Lost(closed),
    }
}

fn unexpected(reply: Reply) -> Error {
    match reply {
        Reply::Error(errno) => Error::Op(errno),
        _ => Error::Unexpected,
    }
}
