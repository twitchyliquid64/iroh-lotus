//! The iroh-lotus daemon.
//!
//! Note that `core` here is this crate's own module, so the standard library
//! core is reached as `::core` inside it.

use tokio::sync::oneshot;

mod core;
pub use crate::core::{
    AdmitError, CannotSignAlone, ChainError, Core, IROH_SECRET_FILENAME, IfInitialized, InitError,
    NodeKeys, OLDEST_ENVELOPE_FILENAME, SIGNING_KEY_FILENAME, SQLITE_DB_FILENAME,
};

mod server;
pub use server::{Identity, Issued, RequestError, Server, ServerHandle, WeakWrite};

mod subscribe;
pub use subscribe::{
    ChangeFilter, ChangeNotification, ChangeSelector, SubscriptionHandle, Subscriptions,
};

pub mod bootstrap;
pub mod invite;
pub mod peer_egress;
pub mod peer_ingress;
pub mod peer_link;
pub mod sync_driver;

/// The version this daemon reports over the control socket.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Encapsulates the return channel for messages back from an actor.
#[derive(Debug)]
pub(crate) struct Responder<T, E>(oneshot::Sender<Result<T, E>>);

impl<T, E> Responder<T, E> {
    /// Constructs both ends of the return channel.
    pub(crate) fn channel() -> (Self, oneshot::Receiver<Result<T, E>>) {
        let (send, recv) = oneshot::channel();
        (Self(send), recv)
    }

    /// Transmits a result to the caller. The caller going away is not an error:
    /// it dropped the receiver because it stopped caring about the answer.
    pub(crate) fn respond(self, res: Result<T, E>) {
        let _ = self.0.send(res);
    }

    /// Awaits the provided future, transmitting its result to the caller.
    pub(crate) async fn handle<F>(self, fut: F)
    where
        F: Future<Output = Result<T, E>>,
    {
        self.respond(fut.await);
    }
}
