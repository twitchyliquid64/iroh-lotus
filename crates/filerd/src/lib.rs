//! The filer daemon: serves volumes of files to clients directly over
//! iroh, and keeps what the cluster needs to know about them in the
//! ledger of the lotusd beside it.
//!
//! Which volumes a filer serves, and from where on disk, is its own
//! configuration ([`Backing`]). The ledger is where it announces them — each volume's
//! entry in the `filers` namespace names the filer's endpoint and where it
//! is reachable — and where an operator says who may connect
//! ([`ledger`]). The filer reaches the ledger only through the local
//! daemon's control socket; clients never touch it at all.
//!
//! Three tasks, sharing one reading of the ledger:
//!
//!  - the view follows the `filers` namespace ([`View`]);
//!  - the publisher claims the filer's volumes and keeps their listed
//!    address current;
//!  - the gate accepts clients, holds each to what the ledger permits its
//!    endpoint id, and carries out the operations they send against the
//!    volume's directory.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use filer_proto::VolumeName;
use iroh::Endpoint;
use lotus_sdk::Client;
use tokio::{sync::watch, task::JoinSet};
use tokio_util::sync::CancellationToken;

pub mod backing;
pub use backing::Backing;

pub mod key;
pub mod ledger;

mod publish;
pub use publish::{DEFAULT_SETTLE, Standing};

mod serve;
pub use serve::DEFAULT_CONNECTION_LIMIT;

mod view;
pub use view::View;

/// A filer, before it is started.
#[derive(Debug)]
pub struct Filer {
    client: Client,
    endpoint: Endpoint,
    volumes: BTreeMap<VolumeName, Arc<Backing>>,
    settle: Duration,
    takeover: bool,
    connection_limit: usize,
}

impl Filer {
    /// A filer announcing itself through the daemon `client` reaches and
    /// serving on `endpoint`, which must have been bound with
    /// [`filer_proto::ALPN`].
    pub fn new(client: Client, endpoint: Endpoint) -> Self {
        Self {
            client,
            endpoint,
            volumes: BTreeMap::new(),
            settle: DEFAULT_SETTLE,
            takeover: false,
            connection_limit: DEFAULT_CONNECTION_LIMIT,
        }
    }

    /// Serves the directory `backing` holds as the volume `name`.
    pub fn with_volume(mut self, name: VolumeName, backing: Backing) -> Self {
        self.volumes.insert(name, Arc::new(backing));
        self
    }

    /// How long the endpoint's address is left to settle before it is
    /// published.
    pub fn with_settle(mut self, settle: Duration) -> Self {
        self.settle = settle;
        self
    }

    /// Claims volumes the ledger gives to another filer, once, at start.
    pub fn with_takeover(mut self, takeover: bool) -> Self {
        self.takeover = takeover;
        self
    }

    /// Caps how many client connections are served at once.
    pub fn with_connection_limit(mut self, limit: usize) -> Self {
        self.connection_limit = limit;
        self
    }

    /// Starts the filer's tasks, returning the handle it is stopped by.
    pub fn spawn(self) -> FilerHandle {
        let volumes: Arc<[VolumeName]> = self.volumes.keys().cloned().collect();
        let cancel = CancellationToken::new();
        let (view_tx, view) = watch::channel(View::Unreadable);
        let (standings_tx, standings) = watch::channel(BTreeMap::new());

        let mut tasks = JoinSet::new();
        tasks.spawn(view::run(
            self.client.clone(),
            Arc::clone(&volumes),
            view_tx,
            cancel.clone(),
        ));
        tasks.spawn(
            publish::Publisher {
                client: self.client,
                volumes,
                addr: self.endpoint.watch_addr(),
                view: view.clone(),
                settle: self.settle,
                takeover: self.takeover,
                standings: standings_tx,
            }
            .run(cancel.clone()),
        );
        tasks.spawn(
            serve::Gate {
                endpoint: self.endpoint,
                volumes: Arc::new(self.volumes),
                view: view.clone(),
                limit: self.connection_limit,
            }
            .run(cancel.clone()),
        );

        FilerHandle {
            cancel,
            tasks,
            view,
            standings,
        }
    }
}

/// A running filer.
#[derive(Debug)]
pub struct FilerHandle {
    cancel: CancellationToken,
    tasks: JoinSet<()>,
    view: watch::Receiver<View>,
    standings: watch::Receiver<BTreeMap<VolumeName, Standing>>,
}

impl FilerHandle {
    /// Where each volume's listing stood at the last reconcile; a volume
    /// not yet reconciled is absent.
    pub fn standings(&self) -> watch::Receiver<BTreeMap<VolumeName, Standing>> {
        self.standings.clone()
    }

    /// The ledger as the filer last read it.
    pub fn view(&self) -> watch::Receiver<View> {
        self.view.clone()
    }

    /// Stops the filer, hanging up on its clients, and waits for its
    /// tasks. The endpoint is the caller's to close.
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        while let Some(res) = self.tasks.join_next().await {
            if let Err(e) = res
                && e.is_panic()
            {
                tracing::error!(error = %e, "filer task panicked");
            }
        }
    }
}
