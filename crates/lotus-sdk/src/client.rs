//! The client: a socket path, and a request on a fresh connection each time.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use lotusd_rpc::{
    AnsweredOnce, Call, ChainRange, Compact, Compacted, CreateInvite, GetChainRange, GetEnvelopes,
    GetStatus, GetVersion, InviteCode, ListNamespaces, Method, NamespaceList, NodeStatus, Queried,
    Query, QueryKind, Read, ValueAt, Watch, WatchSelector, WeakDelete, WeakDeleteMatching,
    WeakIncrement, WeakPush, WeakSet, Written,
};
use tokio::net::UnixStream;
use wire::{
    msg::{NamespaceKey, Predicate, Value},
    subkey::SubkeyPath,
};

use crate::{Error, Streaming, find_state_dir, socket_in};

/// A lotusd daemon, by its control socket.
///
/// Holds only the path: every request opens its own connection, as the
/// protocol asks, so a client is cheap to make, clone and keep, and is never
/// stale. Nothing is checked until a request is made — see
/// [`Error::is_daemon_unreachable`] for what a daemon that is not there
/// looks like.
#[derive(Debug, Clone)]
pub struct Client {
    socket: PathBuf,
}

impl Client {
    /// The daemon at the control socket `socket`.
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    /// The daemon running with `--state-dir dir`.
    pub fn in_state_dir(dir: impl AsRef<Path>) -> Self {
        Self::new(socket_in(dir.as_ref()))
    }

    /// The daemon this machine runs by default: in `$LOTUS_STATE_DIR`, or
    /// the first of the user's own state directory and the machine's
    /// ([`SYSTEM_STATE_DIR`](crate::SYSTEM_STATE_DIR)) that exists — see
    /// [`find_state_dir`].
    pub fn discover() -> Result<Self, Error> {
        find_state_dir()
            .map(Self::in_state_dir)
            .ok_or(Error::NoStateDir)
    }

    /// The control socket this client connects to.
    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    async fn connect(&self) -> Result<UnixStream, Error> {
        UnixStream::connect(&self.socket)
            .await
            .map_err(|source| Error::Connect {
                path: self.socket.clone(),
                source,
            })
    }

    /// Sends `method` and reads back its one answer.
    ///
    /// For the methods that answer exactly once. One whose answer streams —
    /// [`Watch`], [`GetEnvelopes`] — is not [`AnsweredOnce`] and needs
    /// [`stream`](Self::stream).
    pub async fn call<M: AnsweredOnce>(&self, method: M) -> Result<M::Response, Error> {
        lotusd_rpc::call(self.connect().await?, method)
            .await
            .map_err(Error::Rpc)
    }

    /// Sends `method` and returns its answers as they arrive.
    pub async fn stream<M: Method>(&self, method: M) -> Result<Streaming<M>, Error> {
        Call::send(self.connect().await?, method)
            .await
            .map(Streaming::new)
            .map_err(Error::Rpc)
    }

    /// The daemon's version.
    pub async fn version(&self) -> Result<String, Error> {
        self.call(GetVersion {}).await
    }

    /// Who the daemon is, how much of the chain it holds, and how it stands
    /// with its peers.
    pub async fn status(&self) -> Result<NodeStatus, Error> {
        self.call(GetStatus {}).await
    }

    /// How much of the chain the daemon holds.
    pub async fn chain_range(&self) -> Result<ChainRange, Error> {
        self.call(GetChainRange {}).await
    }

    /// Every namespace the ledger holds and the shape of each.
    pub async fn list_namespaces(&self) -> Result<NamespaceList, Error> {
        self.call(ListNamespaces {}).await
    }

    /// The value `path` addresses in `key` — the whole namespace for
    /// `None` — and the head it was read at.
    pub async fn read(
        &self,
        key: NamespaceKey,
        path: impl Into<Option<SubkeyPath>>,
    ) -> Result<ValueAt, Error> {
        self.call(Read {
            key,
            path: path.into(),
        })
        .await
    }

    /// What `path` holds in `key` — its shape, how many entries, the keys of
    /// a map — without carrying the values back.
    pub async fn query(
        &self,
        key: NamespaceKey,
        path: impl Into<Option<SubkeyPath>>,
        kind: QueryKind,
    ) -> Result<Queried, Error> {
        self.call(Query {
            key,
            path: path.into(),
            kind,
        })
        .await
    }

    /// Writes `value` where `path` addresses in `key`, or as the whole
    /// namespace for `None` — creating it if the ledger does not hold it.
    ///
    /// A weak write, like the rest here: signed by the daemon alone and
    /// chained onto whatever head it stands at, with no precondition. What
    /// the ledger's rules refuse comes back [rejected](Error::is_rejected).
    pub async fn set(
        &self,
        key: NamespaceKey,
        path: impl Into<Option<SubkeyPath>>,
        value: impl Into<Value>,
    ) -> Result<Written, Error> {
        self.call(WeakSet {
            key,
            path: path.into(),
            value: value.into(),
        })
        .await
    }

    /// Appends `value` to the array `path` addresses in `key`.
    pub async fn push(
        &self,
        key: NamespaceKey,
        path: impl Into<Option<SubkeyPath>>,
        value: impl Into<Value>,
    ) -> Result<Written, Error> {
        self.call(WeakPush {
            key,
            path: path.into(),
            value: value.into(),
        })
        .await
    }

    /// Clears what `path` addresses in `key`, or deletes the whole
    /// namespace for `None`. Clearing what is not there is rejected.
    pub async fn delete(
        &self,
        key: NamespaceKey,
        path: impl Into<Option<SubkeyPath>>,
    ) -> Result<Written, Error> {
        self.call(WeakDelete {
            key,
            path: path.into(),
        })
        .await
    }

    /// Adds `delta` to the integer `path` addresses in `key`; negative to
    /// decrement. To clamp the sum, [`call`](Self::call) a [`WeakIncrement`]
    /// with its bounds set.
    pub async fn increment(
        &self,
        key: NamespaceKey,
        path: impl Into<Option<SubkeyPath>>,
        delta: i64,
    ) -> Result<Written, Error> {
        self.call(WeakIncrement {
            key,
            path: path.into(),
            delta,
            min: None,
            max: None,
        })
        .await
    }

    /// Removes every entry of the container `path` addresses in `key` that
    /// `predicate` matches. Matching nothing is fine.
    pub async fn delete_matching(
        &self,
        key: NamespaceKey,
        path: impl Into<Option<SubkeyPath>>,
        predicate: Predicate,
    ) -> Result<Written, Error> {
        self.call(WeakDeleteMatching {
            key,
            path: path.into(),
            predicate,
        })
        .await
    }

    /// An invite a blank node joins the cluster by, trusting its key at
    /// `weight`, good for `ttl` on the daemon's clock — which caps it.
    pub async fn invite(&self, weight: u32, ttl: Duration) -> Result<InviteCode, Error> {
        self.call(CreateInvite {
            weight,
            ttl_millis: u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX),
        })
        .await
    }

    /// Prunes what the daemon's retention policy no longer keeps, now.
    pub async fn compact(&self) -> Result<Compacted, Error> {
        self.call(Compact {}).await
    }

    /// The envelopes `select` picks out, one frame each, oldest first for a
    /// chain walk. Asking for what the daemon does not hold ends the stream
    /// early rather than failing it.
    pub async fn envelopes(&self, select: GetEnvelopes) -> Result<Streaming<GetEnvelopes>, Error> {
        self.stream(select).await
    }

    /// Every movement of the chain `selector` picks out, until the stream
    /// is dropped. See the crate docs for reading alongside a watch.
    pub async fn watch(&self, selector: WatchSelector) -> Result<Streaming<Watch>, Error> {
        self.stream(Watch { selector }).await
    }
}
