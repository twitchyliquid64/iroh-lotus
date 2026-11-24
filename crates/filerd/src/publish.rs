//! The publisher: claims this filer's volumes in the ledger and keeps the
//! address listed for them in step with where its endpoint is reachable.
//!
//! The one writer of a volume's `endpoint` field, as
//! `lotusd`'s address publisher is of a node's own listing, and built the
//! same way. Level-triggered: every wake — the ledger moving, the
//! endpoint's address settling — ends in one read of the namespace and
//! whatever writes bring it in line.
//!
//! A volume nobody is named for is claimed. One named for another filer is
//! left alone and not served: which filer serves a volume is settled by
//! whoever wrote first, and changed only by an operator — by clearing the
//! field, or by starting this filer with a takeover, which is spent on the
//! first reconcile so two filers told to take over cannot trade the volume
//! back and forth.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use filer_proto::VolumeName;
use iroh::{EndpointAddr, EndpointId, Watcher};
use lotus_sdk::{
    Client, SubkeyPath, Value,
    schema::SCHEMA_KEY,
    wire::msg::{ADDRS, NamespaceKey},
};
use tokio::{
    sync::watch,
    time::{Sleep, sleep},
};
use tokio_util::sync::CancellationToken;

use crate::{
    ledger::{self, Claim, ENDPOINT, Entry},
    view::View,
};

/// How long the address is left to settle after it moves before it is
/// published: every publish is a signed envelope on a permanent chain.
pub const DEFAULT_SETTLE: Duration = Duration::from_secs(60);

/// Where a volume's listing stands, as of the last reconcile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// The ledger names this filer at the address its endpoint reports.
    Published,
    /// The ledger names another filer.
    Other(EndpointId),
    /// The ledger names something that does not read as a filer.
    Unreadable(String),
    /// The write that would have brought the listing in line failed.
    Failed(String),
}

impl fmt::Display for Standing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Standing::Published => f.write_str("published"),
            Standing::Other(id) => write!(f, "claimed by another filer, {}", id.to_z32()),
            Standing::Unreadable(why) => {
                write!(f, "claimed by an endpoint that does not read: {why}")
            }
            Standing::Failed(why) => write!(f, "failed: {why}"),
        }
    }
}

/// What one reconcile does about one volume.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Leave(Standing),
    Write { path: SubkeyPath, value: Value },
}

/// What brings `volume`'s listing in line with `addr`, given the `entry`
/// the ledger holds for it.
///
/// Writes the narrowest thing that does: nothing is created along a
/// nested write's path, so an entry that is not there is written whole,
/// and one that is has only the field — or only the transports — set.
fn step(
    volume: &VolumeName,
    entry: Option<&Entry>,
    addr: &EndpointAddr,
    listed: &BTreeMap<String, Value>,
    takeover: bool,
) -> Step {
    let claim = || Step::Write {
        path: ledger::entry_path(volume, [ENDPOINT]),
        value: Value::Map(listed.clone()),
    };
    match entry.map(|entry| &entry.claim) {
        None => Step::Write {
            path: ledger::entry_path(volume, []),
            value: Value::from_iter([(ENDPOINT, Value::Map(listed.clone()))]),
        },
        Some(Claim::Unclaimed) => claim(),
        Some(Claim::Endpoint(held)) if held == addr => Step::Leave(Standing::Published),
        Some(Claim::Endpoint(held)) if held.id == addr.id => Step::Write {
            path: ledger::entry_path(volume, [ENDPOINT, ADDRS]),
            value: listed
                .get(ADDRS)
                .cloned()
                .expect("an endpoint address is written with its transports"),
        },
        Some(Claim::Endpoint(_) | Claim::Unreadable(_)) if takeover => claim(),
        Some(Claim::Endpoint(held)) => Step::Leave(Standing::Other(held.id)),
        Some(Claim::Unreadable(why)) => Step::Leave(Standing::Unreadable(why.clone())),
    }
}

/// Whether the `filers` schema still has to be seen to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchemaCheck {
    Due,
    Done,
}

/// The publisher, before it is run.
pub(crate) struct Publisher<W> {
    pub(crate) client: Client,
    pub(crate) volumes: Arc<[VolumeName]>,
    pub(crate) addr: W,
    pub(crate) view: watch::Receiver<View>,
    pub(crate) settle: Duration,
    pub(crate) takeover: bool,
    pub(crate) standings: watch::Sender<BTreeMap<VolumeName, Standing>>,
}

impl<W> Publisher<W>
where
    W: Watcher<Value = EndpointAddr> + Send + Unpin + 'static,
{
    pub(crate) async fn run(mut self, cancel: CancellationToken) {
        let mut timer = Settle::default();
        let mut state = State {
            schema: SchemaCheck::Due,
            takeover: if self.takeover {
                self.volumes.iter().cloned().collect()
            } else {
                BTreeSet::new()
            },
            standings: self.standings.clone(),
        };

        loop {
            tokio::select! {
                biased;

                () = cancel.cancelled() => return,
                () = timer.fired() => {}
                moved = self.addr.updated() => match moved {
                    Ok(_) => {
                        timer.arm(self.settle);
                        continue;
                    }
                    // The endpoint is gone; nothing will move the address again.
                    Err(_) => return,
                },
                changed = self.view.changed() => {
                    // The view's task is gone, and the filer with it.
                    if changed.is_err() {
                        return;
                    }
                    if *self.view.borrow_and_update() == View::Unreadable {
                        continue;
                    }
                }
            }
            tokio::select! {
                () = cancel.cancelled() => return,
                () = self.reconcile(&mut state) => {}
            }
        }
    }

    /// Reads the namespace and writes whatever brings each volume's
    /// listing in line. A failure is logged and left for the next wake.
    async fn reconcile(&mut self, state: &mut State) {
        if state.schema == SchemaCheck::Due {
            state.schema = self.ensure_schema().await;
        }

        let addr = self.addr.get();
        let listed = match Value::try_from(&addr) {
            Ok(Value::Map(listed)) => listed,
            Ok(_) => unreachable!("an endpoint address is written as a map"),
            Err(error) => {
                tracing::warn!(%error, "this endpoint's address has no ledger encoding");
                return;
            }
        };
        let namespace = match self.client.read(ledger::namespace(), None).await {
            Ok(at) => at.value,
            Err(error) => {
                tracing::warn!(%error, "reading the volumes the ledger lists");
                return;
            }
        };

        let Some(namespace) = namespace else {
            // Nothing lists any volume yet: there is no map to write an
            // entry into, so the namespace is written whole.
            let entries = self.volumes.iter().map(|volume| {
                (
                    volume.as_str(),
                    Value::from_iter([(ENDPOINT, Value::Map(listed.clone()))]),
                )
            });
            let outcome = self
                .client
                .set(ledger::namespace(), None, Value::from_iter(entries))
                .await;
            let volumes = Arc::clone(&self.volumes);
            volumes
                .iter()
                .for_each(|volume| state.landed(volume, outcome.as_ref().map(|_| ())));
            return;
        };

        let volumes = Arc::clone(&self.volumes);
        for volume in volumes.iter() {
            let entry = Entry::find(Some(&namespace), volume);
            let takeover = state.takeover.contains(volume);
            match step(volume, entry.as_ref(), &addr, &listed, takeover) {
                Step::Leave(standing) => state.stands(volume, standing),
                Step::Write { path, value } => {
                    let outcome = self.client.set(ledger::namespace(), path, value).await;
                    state.landed(volume, outcome.as_ref().map(|_| ()));
                }
            }
        }
    }

    /// Installs the `filers` schema where the ledger has none for it. One
    /// that is there and differs is left alone: two filer versions would
    /// otherwise rewrite it back and forth.
    async fn ensure_schema(&self) -> SchemaCheck {
        let key = NamespaceKey::try_new(SCHEMA_KEY).expect("the reserved key is static");
        let wanted = ledger::schema();
        let held = match self.client.read(key.clone(), None).await {
            Ok(at) => at.value,
            Err(error) => {
                tracing::warn!(%error, "reading the ledger's schemas");
                return SchemaCheck::Due;
            }
        };
        let installed = match held {
            None => {
                self.client
                    .set(key, None, Value::from_iter([(ledger::NAMESPACE, wanted)]))
                    .await
            }
            Some(Value::Map(schemas)) => match schemas.get(ledger::NAMESPACE) {
                None => {
                    let path = SubkeyPath::try_new(vec![lotus_sdk::Subkey::Key(
                        ledger::NAMESPACE.to_owned(),
                    )])
                    .expect("one segment is not empty");
                    self.client.set(key, path, wanted).await
                }
                Some(held) if *held == wanted => return SchemaCheck::Done,
                Some(_) => {
                    tracing::warn!(
                        namespace = ledger::NAMESPACE,
                        "the ledger holds a different schema for the volumes namespace; leaving it"
                    );
                    return SchemaCheck::Done;
                }
            },
            Some(_) => {
                tracing::warn!("the ledger's schemas are not a map; leaving them");
                return SchemaCheck::Done;
            }
        };
        match installed {
            Ok(_) => {
                tracing::info!(
                    namespace = ledger::NAMESPACE,
                    "installed the volumes schema"
                );
                SchemaCheck::Done
            }
            // Asking again gets the same answer: what the namespace
            // already holds does not conform, and that is an operator's
            // to mend.
            Err(error) if error.is_rejected() => {
                tracing::error!(%error, "the ledger refused the volumes schema; running without it");
                SchemaCheck::Done
            }
            Err(error) => {
                tracing::warn!(%error, "installing the volumes schema");
                SchemaCheck::Due
            }
        }
    }
}

/// What the publisher carries from one reconcile to the next.
struct State {
    schema: SchemaCheck,
    /// The volumes a takeover is still owed for.
    takeover: BTreeSet<VolumeName>,
    /// Where each volume stood last, so a standing is logged when it
    /// changes rather than on every wake.
    standings: watch::Sender<BTreeMap<VolumeName, Standing>>,
}

impl State {
    /// Records the outcome of a write for `volume`.
    fn landed(&mut self, volume: &VolumeName, outcome: Result<(), &lotus_sdk::Error>) {
        self.stands(
            volume,
            match outcome {
                Ok(()) => Standing::Published,
                Err(error) => Standing::Failed(error.to_string()),
            },
        );
    }

    /// Records where `volume` stands, logging it when that is news.
    fn stands(&mut self, volume: &VolumeName, standing: Standing) {
        if standing == Standing::Published {
            self.takeover.remove(volume);
        }
        if self.standings.borrow().get(volume) == Some(&standing) {
            return;
        }
        match &standing {
            Standing::Published => tracing::info!(%volume, "volume listed under this filer"),
            other => tracing::warn!(%volume, standing = %other, "not serving volume"),
        }
        self.standings.send_modify(|standings| {
            standings.insert(volume.clone(), standing);
        });
    }
}

/// The settle timer: unarmed until a wake arms it, and left alone by
/// wakes that find it armed, so an address that never stops moving is
/// published once per window rather than never.
#[derive(Default)]
struct Settle(Option<Pin<Box<Sleep>>>);

impl Settle {
    fn arm(&mut self, after: Duration) {
        if self.0.is_none() {
            self.0 = Some(Box::pin(sleep(after)));
        }
    }

    /// Resolves when the armed timer fires, disarming it; pends forever
    /// while unarmed.
    async fn fired(&mut self) {
        match &mut self.0 {
            Some(timer) => {
                timer.as_mut().await;
                self.0 = None;
            }
            None => std::future::pending().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use iroh::TransportAddr;

    use super::*;
    use crate::ledger::AllowList;

    fn id(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn addr(seed: u8, port: u16) -> EndpointAddr {
        EndpointAddr::from_parts(
            id(seed),
            [TransportAddr::Ip(
                format!("192.0.2.1:{port}").parse().unwrap(),
            )],
        )
    }

    fn listed(addr: &EndpointAddr) -> BTreeMap<String, Value> {
        match Value::try_from(addr).unwrap() {
            Value::Map(listed) => listed,
            other => panic!("expected a map, got {other:?}"),
        }
    }

    fn volume() -> VolumeName {
        VolumeName::try_new("scratch").unwrap()
    }

    fn entry(claim: Claim) -> Entry {
        Entry {
            claim,
            allowed: AllowList::default(),
        }
    }

    fn step_for(entry: Option<&Entry>, ours: &EndpointAddr, takeover: bool) -> Step {
        step(&volume(), entry, ours, &listed(ours), takeover)
    }

    #[test]
    fn an_unlisted_volume_is_written_whole() {
        let ours = addr(1, 1);
        assert_eq!(
            step_for(None, &ours, false),
            Step::Write {
                path: "scratch".parse().unwrap(),
                value: Value::from_iter([(ENDPOINT, Value::Map(listed(&ours)))]),
            }
        );
    }

    #[test]
    fn an_unclaimed_volume_is_claimed_at_its_endpoint_field() {
        let ours = addr(1, 1);
        assert_eq!(
            step_for(Some(&entry(Claim::Unclaimed)), &ours, false),
            Step::Write {
                path: "scratch.endpoint".parse().unwrap(),
                value: Value::Map(listed(&ours)),
            }
        );
    }

    #[test]
    fn a_volume_listed_where_the_endpoint_is_stays() {
        let ours = addr(1, 1);
        assert_eq!(
            step_for(Some(&entry(Claim::Endpoint(ours.clone()))), &ours, false),
            Step::Leave(Standing::Published)
        );
    }

    #[test]
    fn a_moved_address_rewrites_the_transports_alone() {
        let ours = addr(1, 2);
        assert_eq!(
            step_for(Some(&entry(Claim::Endpoint(addr(1, 1)))), &ours, false),
            Step::Write {
                path: "scratch.endpoint.addrs".parse().unwrap(),
                value: listed(&ours).remove(ADDRS).unwrap(),
            }
        );
    }

    #[test]
    fn another_filers_volume_is_left_alone() {
        let ours = addr(1, 1);
        assert_eq!(
            step_for(Some(&entry(Claim::Endpoint(addr(2, 1)))), &ours, false),
            Step::Leave(Standing::Other(id(2)))
        );
        assert!(matches!(
            step_for(
                Some(&entry(Claim::Unreadable("bad".to_owned()))),
                &ours,
                false
            ),
            Step::Leave(Standing::Unreadable(_))
        ));
    }

    #[test]
    fn a_takeover_claims_another_filers_volume() {
        let ours = addr(1, 1);
        assert_eq!(
            step_for(Some(&entry(Claim::Endpoint(addr(2, 1)))), &ours, true),
            Step::Write {
                path: "scratch.endpoint".parse().unwrap(),
                value: Value::Map(listed(&ours)),
            }
        );
    }
}
