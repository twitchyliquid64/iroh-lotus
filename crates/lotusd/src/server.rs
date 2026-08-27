//! The server actor: one mainloop task owning the [`Core`], reached only by
//! the messages a [`ServerHandle`] sends it.

use std::ops::ControlFlow;

use lotusd_rpc as rpc;
use tokio::{
    net::{UnixListener, UnixStream},
    sync::mpsc,
    task::JoinHandle,
};
use wire::EnvelopeDigest;

use crate::{Core, InitError, Responder, VERSION};

#[derive(Debug)]
enum ServerMsg {
    Shutdown(Responder<(), ()>),
    ChainRange(Responder<rpc::ChainRange, ()>),
}

/// The server actor, encapsulates all running/server state.
#[derive(Debug)]
pub struct Server {
    core: Core,
    local_sock: UnixListener,
}

impl Server {
    pub fn new(core: Core, local_sock: UnixListener) -> Result<Self, InitError> {
        Ok(Self { core, local_sock })
    }

    /// Consumes the initialized server and starts an async task for its mainloop, returning
    /// a handle that can be used to query and control the server.
    pub async fn run(self) -> (ServerHandle, JoinHandle<()>) {
        let Self {
            mut core,
            local_sock,
        } = self;
        let (hnd_tx, mut hnd_recv) = mpsc::channel(8);
        let weak = hnd_tx.downgrade();
        let handle = ServerHandle(hnd_tx);

        let join_hnd = tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Control messages win over new connections, so a shutdown is not held
                    // off by a socket that keeps accepting.
                    biased;

                    msg = hnd_recv.recv() => {
                        // Every handle dropped: nothing can drive us any more.
                        let Some(msg) = msg else { return };
                        if let ControlFlow::Break(r) = Self::handle_message(&mut core, msg).await {
                            // Shutdown, r is to respond when we are done shutting down.
                            r.respond(Ok(()));
                            return;
                        }
                    }
                    conn = local_sock.accept() => match conn {
                        // Served on its own task via own handle to avoid blocking the mainloop
                        Ok((stream, _addr)) => match weak.upgrade() {
                            Some(sender) => {
                                tokio::spawn(Self::handle_connection(ServerHandle(sender), stream));
                            }
                            // Server about to be garbage collected
                            None => drop(stream),
                        },
                        Err(e) => tracing::warn!(error = %e, "accepting local connection"),
                    },
                }
            }
        });

        (handle, join_hnd)
    }

    /// Routes one message to the handler for it, lending each the components it needs.
    ///
    /// Handlers take `&mut Core` rather than `&Core`: the SQLite connection is `Send` but not
    /// `Sync`, so only a unique borrow of the core can be held across an await in the spawned
    /// mainloop.
    async fn handle_message(core: &mut Core, msg: ServerMsg) -> ControlFlow<Responder<(), ()>> {
        match msg {
            ServerMsg::Shutdown(r) => return ControlFlow::Break(r),
            ServerMsg::ChainRange(r) => Self::handle_chain_range(core, r).await,
        }

        ControlFlow::Continue(())
    }

    /// Reads how much of the chain the core holds.
    async fn handle_chain_range(core: &mut Core, r: Responder<rpc::ChainRange, ()>) {
        r.handle(async move {
            Ok(rpc::ChainRange {
                root: core.root(),
                head: core.head(),
            })
        })
        .await
    }

    /// Serves one client on the local control socket.
    ///
    /// One connection, one request: dropping the stream on the way out is
    /// what ends the answer's stream.
    async fn handle_connection(handle: ServerHandle, mut stream: UnixStream) {
        if let Err(e) = rpc::serve(&mut stream, &mut Rpc(handle)).await {
            tracing::warn!(error = %e, "serving local connection");
        }
    }
}

/// Answers local control requests, asking the server for whatever they need.
///
/// Holds a handle rather than the core: it runs off the mainloop, so the
/// state it reports has to come back through the same actor messages any
/// other caller would use.
struct Rpc(ServerHandle);

impl rpc::Handler for Rpc {
    async fn handle(
        &mut self,
        request: rpc::Request,
        responses: &mut rpc::Responses<'_>,
    ) -> Result<(), rpc::Error> {
        match request {
            rpc::Request::GetVersion(_) => {
                responses
                    .send(rpc::Response::Version(VERSION.to_owned()))
                    .await
            }
            rpc::Request::GetChainRange(_) => {
                let range = self
                    .0
                    .chain_range()
                    .await
                    .map_err(|()| rpc::Failure::internal("the server is shutting down"))?;
                responses.send(rpc::Response::ChainRange(range)).await
            }
        }
    }
}

/// A handle to a running lotusd server.
#[derive(Debug, Clone)]
pub struct ServerHandle(mpsc::Sender<ServerMsg>);

#[allow(clippy::result_unit_err)]
impl ServerHandle {
    /// Issues a server shutdown. If the server is running, this future resolves with
    /// and Ok value when shutdown is finished. If the server is not running or otherwise
    /// in a broken state, an Err value is returned immediately.
    pub async fn shutdown(&self) -> Result<(), ()> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::Shutdown(send)).await;
        match recv.await {
            Ok(v) => v,
            Err(_) => Err(()),
        }
    }

    /// Reads how much of the chain this node holds.
    ///
    /// The one read both ends come from: [`head`](Self::head) and
    /// [`root`](Self::root) are conveniences over it, and asking for them
    /// separately can catch the chain mid-move.
    pub async fn chain_range(&self) -> Result<rpc::ChainRange, ()> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::ChainRange(send)).await;
        match recv.await {
            Ok(Ok(v)) => Ok(v),
            _ => Err(()),
        }
    }

    /// Reads the current HEAD.
    pub async fn head(&self) -> Result<EnvelopeDigest, ()> {
        self.chain_range().await.map(|range| range.head)
    }

    /// Reads the oldest envelope this node still holds — the chain's root,
    /// until compaction moves it forward.
    pub async fn root(&self) -> Result<EnvelopeDigest, ()> {
        self.chain_range().await.map(|range| range.root)
    }
}
