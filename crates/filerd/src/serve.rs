//! The gate: accepts client connections on the filer's endpoint and holds
//! each one to what the ledger permits its endpoint id.
//!
//! A client is only ever what its endpoint id says — iroh authenticated
//! that at the handshake — and whether that id may use a volume is ledger
//! state. It is judged when the client says which volume it wants, and
//! again on every change to the ledger for as long as the connection
//! stands: a client removed, or cut back from read-write, is hung up on.
//! A change that leaves its grant alone leaves the connection alone.
//!
//! A ledger that cannot be read admits nobody new. Connections already
//! judged are kept through it — a restart of the local daemon should not
//! unmount every client — and judged again once it reads.

use std::time::Duration;

use filer_proto::{Close, Hello, Mode, VolumeName, Welcome, read_frame, write_frame};
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, Incoming, VarInt},
};
use tokio::{sync::watch, task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::view::View;

/// How many client connections are served at once; further attempts are
/// refused at the handshake.
pub const DEFAULT_CONNECTION_LIMIT: usize = 256;

/// How long a client gets to say which volume it wants.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// How long open connections get to close on shutdown before their tasks
/// are aborted.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

fn close(conn: &Connection, reason: Close) {
    conn.close(VarInt::from_u32(reason.code()), reason.reason());
}

/// What `client` may do on `volume` as the ledger stands in `view`, for
/// the filer with endpoint id `filer`; or the reason to refuse it.
///
/// A volume the ledger does not list and a client it does not permit are
/// refused alike, before whether the volume is this filer's to serve is
/// said: only a permitted client learns that.
fn judge(
    view: &View,
    filer: EndpointId,
    volume: &VolumeName,
    client: EndpointId,
) -> Result<Mode, Close> {
    let View::Read(volumes) = view else {
        return Err(Close::Unavailable);
    };
    let entry = volumes.get(volume).ok_or(Close::NotPermitted)?;
    let grant = entry.allowed.grant(client).ok_or(Close::NotPermitted)?;
    if entry.claim.is(filer) {
        Ok(grant.mode)
    } else {
        Err(Close::Unavailable)
    }
}

/// The reason to hang up on a connection admitted at `held`, as the
/// ledger stands in `view`; `None` while it may stay.
fn revoked(
    view: &View,
    filer: EndpointId,
    volume: &VolumeName,
    client: EndpointId,
    held: Mode,
) -> Option<Close> {
    if *view == View::Unreadable {
        return None;
    }
    match judge(view, filer, volume, client) {
        Ok(mode) if mode >= held => None,
        Ok(_) | Err(Close::NotPermitted) => Some(Close::Revoked),
        Err(reason) => Some(reason),
    }
}

/// The gate, before it is run.
pub(crate) struct Gate {
    pub(crate) endpoint: Endpoint,
    pub(crate) view: watch::Receiver<View>,
    pub(crate) limit: usize,
}

impl Gate {
    pub(crate) async fn run(self, cancel: CancellationToken) {
        let mut conns: JoinSet<()> = JoinSet::new();
        loop {
            tokio::select! {
                biased;

                () = cancel.cancelled() => return Self::stop(conns).await,
                // Reap finished connections so `conns.len()` is the live count.
                Some(res) = conns.join_next() => {
                    if let Err(e) = res && e.is_panic() {
                        tracing::error!(error = %e, "client connection task panicked");
                    }
                }
                incoming = self.endpoint.accept() => {
                    // The endpoint was closed under us.
                    let Some(incoming) = incoming else {
                        return Self::stop(conns).await;
                    };
                    if conns.len() >= self.limit {
                        tracing::debug!(remote = ?incoming.remote_addr(), "refusing client: at connection limit");
                        incoming.refuse();
                        continue;
                    }
                    conns.spawn(connection(
                        incoming,
                        self.endpoint.id(),
                        self.view.clone(),
                        cancel.clone(),
                    ));
                }
            }
        }
    }

    /// Waits for every connection's task, aborting what lingers. The
    /// tasks hold the token that was just cancelled, and close on it.
    async fn stop(mut conns: JoinSet<()>) {
        let drained = timeout(SHUTDOWN_GRACE, async {
            while conns.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            tracing::warn!(
                lingering = conns.len(),
                "aborting client connections that did not close in time"
            );
            conns.shutdown().await;
        }
    }
}

/// Finishes the handshake with one client and serves it until either side
/// hangs up.
///
/// Handshake failures are logged and dropped: the endpoint's UDP socket
/// takes whatever the network sends it, solicited or not.
async fn connection(
    incoming: Incoming,
    filer: EndpointId,
    view: watch::Receiver<View>,
    cancel: CancellationToken,
) {
    let accepting = match incoming.accept() {
        Ok(accepting) => accepting,
        Err(e) => {
            tracing::debug!(error = %e, "accepting client connection");
            return;
        }
    };
    let conn = match accepting.await {
        Ok(conn) => conn,
        Err(e) => {
            tracing::debug!(error = %e, "client handshake failed");
            return;
        }
    };

    let span = tracing::info_span!("client", remote = %conn.remote_id().fmt_short());
    async {
        let reason = tokio::select! {
            reason = serve(&conn, filer, view) => reason,
            () = cancel.cancelled() => Some(Close::ShuttingDown),
        };
        match reason {
            Some(reason) => {
                tracing::debug!(reason = ?reason, "closing client connection");
                close(&conn, reason);
            }
            None => tracing::debug!("client hung up"),
        }
    }
    .instrument(span)
    .await
}

/// Serves one connection. Returns the reason to close it, or `None` when
/// the client already has.
async fn serve(
    conn: &Connection,
    filer: EndpointId,
    mut view: watch::Receiver<View>,
) -> Option<Close> {
    let client = conn.remote_id();
    let (volume, held) = match timeout(HELLO_TIMEOUT, admit(conn, filer, &view)).await {
        Ok(Ok(admitted)) => admitted,
        Ok(Err(reason)) => return reason,
        Err(_) => return Some(Close::Breach),
    };
    tracing::info!(%volume, mode = %held, "client admitted");

    loop {
        tokio::select! {
            _ = conn.closed() => return None,
            changed = view.changed() => {
                // The view's task is gone, and the filer with it.
                if changed.is_err() {
                    return Some(Close::ShuttingDown);
                }
                let reason = revoked(&view.borrow_and_update(), filer, &volume, client, held);
                if let Some(reason) = reason {
                    tracing::info!(%volume, reason = ?reason, "client no longer permitted");
                    return Some(reason);
                }
            }
        }
    }
}

/// Reads the client's [`Hello`] and answers it. Returns the volume and
/// mode it was admitted at, or the reason to close — `None` when the
/// connection is already gone.
async fn admit(
    conn: &Connection,
    filer: EndpointId,
    view: &watch::Receiver<View>,
) -> Result<(VolumeName, Mode), Option<Close>> {
    let (mut send, mut recv) = conn.accept_bi().await.map_err(|_| None)?;
    let hello: Hello = read_frame(&mut recv).await.map_err(|error| {
        tracing::debug!(%error, "reading the client's hello");
        Some(Close::Breach)
    })?;
    let mode = judge(&view.borrow(), filer, &hello.volume, conn.remote_id()).map_err(|reason| {
        tracing::debug!(volume = %hello.volume, reason = ?reason, "refusing client");
        Some(reason)
    })?;
    write_frame(&mut send, &Welcome { mode })
        .await
        .map_err(|_| None)?;
    // Finished rather than dropped: a dropped stream is reset, and a reset
    // may overtake the welcome.
    send.finish().map_err(|_| None)?;
    Ok((hello.volume, mode))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use iroh::EndpointAddr;
    use lotus_sdk::Value;

    use super::*;
    use crate::ledger::{ALLOWED_CLIENTS, ENDPOINT, Entry};

    fn id(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn volume() -> VolumeName {
        VolumeName::try_new("scratch").unwrap()
    }

    /// A view of one volume, `scratch`, claimed by `filer` and permitting
    /// `clients`.
    fn view(filer: EndpointId, clients: &[(EndpointId, &str)]) -> View {
        let allowed: Value = clients
            .iter()
            .map(|(id, mode)| {
                (
                    id.to_z32(),
                    Value::from_iter([("endpoint_id", id.to_z32()), ("mode", (*mode).to_owned())]),
                )
            })
            .collect();
        let namespace = Value::from_iter([(
            "scratch",
            Value::Map(BTreeMap::from([
                (
                    ENDPOINT.to_owned(),
                    Value::try_from(&EndpointAddr::new(filer)).unwrap(),
                ),
                (ALLOWED_CLIENTS.to_owned(), allowed),
            ])),
        )]);
        View::Read(Arc::new(BTreeMap::from([(
            volume(),
            Entry::find(Some(&namespace), &volume()).unwrap(),
        )])))
    }

    #[test]
    fn a_listed_client_is_admitted_at_its_mode() {
        let view = view(id(1), &[(id(2), "rw"), (id(3), "ro")]);
        assert_eq!(judge(&view, id(1), &volume(), id(2)), Ok(Mode::ReadWrite));
        assert_eq!(judge(&view, id(1), &volume(), id(3)), Ok(Mode::ReadOnly));
    }

    #[test]
    fn an_unlisted_client_and_an_unknown_volume_are_refused_alike() {
        let view = view(id(1), &[(id(2), "rw")]);
        let other = VolumeName::try_new("other").unwrap();
        assert_eq!(
            judge(&view, id(1), &volume(), id(9)),
            Err(Close::NotPermitted)
        );
        assert_eq!(judge(&view, id(1), &other, id(2)), Err(Close::NotPermitted));
    }

    #[test]
    fn another_filers_volume_is_unavailable_to_its_clients_only() {
        let view = view(id(7), &[(id(2), "rw")]);
        assert_eq!(
            judge(&view, id(1), &volume(), id(2)),
            Err(Close::Unavailable)
        );
        assert_eq!(
            judge(&view, id(1), &volume(), id(9)),
            Err(Close::NotPermitted)
        );
    }

    #[test]
    fn an_unreadable_ledger_admits_nobody() {
        assert_eq!(
            judge(&View::Unreadable, id(1), &volume(), id(2)),
            Err(Close::Unavailable)
        );
    }

    #[test]
    fn a_connection_stays_while_its_grant_does() {
        let held = Mode::ReadOnly;
        let stays = |view: &View| revoked(view, id(1), &volume(), id(2), held);
        assert_eq!(stays(&view(id(1), &[(id(2), "ro")])), None);
        assert_eq!(stays(&view(id(1), &[(id(2), "ro"), (id(3), "rw")])), None);
        assert_eq!(stays(&view(id(1), &[(id(2), "rw")])), None);
        assert_eq!(stays(&View::Unreadable), None);
    }

    #[test]
    fn a_connection_is_hung_up_on_when_its_grant_goes_or_narrows() {
        let gone = view(id(1), &[(id(3), "rw")]);
        let narrowed = view(id(1), &[(id(2), "ro")]);
        let moved = view(id(7), &[(id(2), "rw")]);
        let held = Mode::ReadWrite;
        assert_eq!(
            revoked(&gone, id(1), &volume(), id(2), held),
            Some(Close::Revoked)
        );
        assert_eq!(
            revoked(&narrowed, id(1), &volume(), id(2), held),
            Some(Close::Revoked)
        );
        assert_eq!(
            revoked(&moved, id(1), &volume(), id(2), held),
            Some(Close::Unavailable)
        );
    }
}
