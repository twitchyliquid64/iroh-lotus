//! The ledger as the filer last read it, kept current by a watch.
//!
//! One task follows the `filers` namespace on the local daemon and
//! publishes what it says about this filer's volumes. Everything else
//! reads that: the gate judges connections by it, and the publisher wakes
//! on it.

use std::{collections::BTreeMap, convert::Infallible, sync::Arc, time::Duration};

use filer_proto::VolumeName;
use lotus_sdk::{Client, WatchEvent, WatchSelector};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::ledger::{self, Entry};

/// How long to wait before following the ledger again after losing it.
const RETRY: Duration = Duration::from_secs(2);

/// What the ledger says about this filer's volumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum View {
    /// The ledger cannot be read right now. Nothing is known, so nothing
    /// new is permitted.
    Unreadable,
    /// The entries of the volumes the ledger lists, as of the last read.
    Read(Arc<BTreeMap<VolumeName, Entry>>),
}

#[derive(Debug, thiserror::Error)]
enum FollowError {
    #[error(transparent)]
    Daemon(#[from] lotus_sdk::Error),
    #[error("the daemon ended the watch")]
    Ended,
}

/// Follows the ledger until cancelled, publishing each reading on `view`.
pub(crate) async fn run(
    client: Client,
    volumes: Arc<[VolumeName]>,
    view: watch::Sender<View>,
    cancel: CancellationToken,
) {
    loop {
        let lost = tokio::select! {
            () = cancel.cancelled() => return,
            followed = follow(&client, &volumes, &view) => match followed {
                Err(lost) => lost,
                Ok(never) => match never {},
            },
        };
        tracing::warn!(error = %lost, "lost the ledger; refusing new connections until it is back");
        view.send_if_modified(|view| {
            let changed = *view != View::Unreadable;
            *view = View::Unreadable;
            changed
        });
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(RETRY) => {}
        }
    }
}

/// Publishes a reading for every movement of the namespace, until the
/// daemon stops answering.
async fn follow(
    client: &Client,
    volumes: &[VolumeName],
    view: &watch::Sender<View>,
) -> Result<Infallible, FollowError> {
    // Opened before the first read, so a change between the two arrives
    // as an event rather than going unseen.
    let mut watch = client
        .watch(WatchSelector::Namespace(ledger::namespace()))
        .await?;
    loop {
        let at = client.read(ledger::namespace(), None).await?;
        let read = View::Read(Arc::new(
            volumes
                .iter()
                .filter_map(|volume| {
                    Entry::find(at.value.as_ref(), volume).map(|entry| (volume.clone(), entry))
                })
                .collect(),
        ));
        view.send_if_modified(|view| {
            let changed = *view != read;
            *view = read;
            changed
        });
        match watch.next().await? {
            Some(WatchEvent::Changed(_)) => {}
            Some(WatchEvent::AlreadyOrphaned(_)) | None => return Err(FollowError::Ended),
        }
    }
}
