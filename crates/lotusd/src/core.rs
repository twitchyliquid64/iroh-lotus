//! The initialized internals for a lotus node.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt,
    path::{Path, PathBuf},
};

use ed25519_zebra::SigningKey;
use iroh::SecretKey;
use rand::{TryRng, rngs::SysRng};
use state::{
    CLUSTER_NODES_KEY, Chain, ChangeDiffer, Insert, MIN_ENVELOPE_SIGNATURES_KEY, TRUSTED_KEYS_KEY,
};
use storage::{LogEntry, SqliteStorage, Storage, StoredAt};
use tokio::{fs, io::AsyncWriteExt};
use wire::{
    Envelope, EnvelopeDigest, Key, KeyId, Msg, Signature,
    keys::{Ed25519PublicKey, Ed25519Signature, PublicKey},
    msg::{
        ADDRS, AmendNamespaceKey, AmendOp, FullCheckpoint, InitMsg, Namespace, NamespaceKey,
        SetNamespaceKey, Value,
    },
    subkey::{Subkey, SubkeyPath},
};

use crate::{ChangeFilter, SubscriptionHandle, Subscriptions};

pub const SQLITE_DB_FILENAME: &str = "db.sqlite";
pub const OLDEST_ENVELOPE_FILENAME: &str = "oldest_envelope";
pub const SIGNING_KEY_FILENAME: &str = "node.ed25519";
pub const IROH_SECRET_FILENAME: &str = "node.iroh";

/// The weight given to the key a new cluster is founded on.
const ROOT_KEY_WEIGHT: u32 = 2;

/// What advancing the chain can fail with, over this node's backend.
pub type ChainError = state::Error<storage::sqlite::Error>;

/// The initialized internals of lotusd.
#[derive(Debug)]
#[allow(dead_code)]
pub struct Core {
    storage: SqliteStorage,
    /// Never handed out mutably: the core owns every advance of the head so
    /// that one place can say what changed.
    chain: Chain,
    oldest: EnvelopeDigest,
    state_dir: PathBuf,
    keys: NodeKeys,
    subscriptions: Subscriptions,
}

impl fmt::Display for Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at head {}",
            self.state_dir.display(),
            self.chain.head().to_hex().as_ref()
        )
    }
}

/// What [`Core::create_in_state_dir`] does when the state directory already
/// holds an initialized cluster.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IfInitialized {
    /// Leave the existing cluster alone and fail.
    Fail,
    /// Initialize over it. Potentially destructive to the existing ledger.
    Overwrite,
}

impl Core {
    pub async fn init_with_state_dir(state_dir: PathBuf) -> Result<Self, InitError> {
        let mut storage =
            SqliteStorage::open(state_dir.join(SQLITE_DB_FILENAME)).map_err(InitError::Storage)?;

        let oldest_envelope = fs::read(state_dir.join(OLDEST_ENVELOPE_FILENAME))
            .await
            .map_err(|e| InitError::IO(e, "reading oldest-envelope"))?;
        let oldest = <[u8; 32]>::try_from(oldest_envelope.as_slice())
            .map(EnvelopeDigest::from_bytes)
            .map_err(|_| InitError::OldestDigestLength(oldest_envelope.len()))?;

        let chain = Chain::open(&mut storage, oldest).map_err(InitError::Chain)?;
        let keys = NodeKeys::load(&state_dir).await?;

        Ok(Self {
            storage,
            chain,
            oldest,
            state_dir,
            keys,
            subscriptions: Subscriptions::default(),
        })
    }

    /// Initializes a new cluster in `state_dir` — generating this node's
    /// keys and committing the genesis envelope — and returns it opened, as
    /// [`Core::init_with_state_dir`] would return it on the next start.
    pub async fn create_in_state_dir(
        state_dir: PathBuf,
        if_initialized: IfInitialized,
    ) -> Result<Self, InitError> {
        fs::create_dir_all(&state_dir)
            .await
            .map_err(|e| InitError::IO(e, "creating state-dir"))?;

        Self::refuse_initialized(&state_dir, if_initialized).await?;

        let keys = NodeKeys::generate(&state_dir).await?;
        let trusted = Key::new(keys.public_key(), ROOT_KEY_WEIGHT);
        let key_id = trusted.id();

        let envelope = Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: BTreeMap::from_iter([
                    (
                        NamespaceKey::try_new(TRUSTED_KEYS_KEY)
                            .expect("the reserved key is static"),
                        Namespace {
                            value: Value::Map(BTreeMap::from_iter([(
                                key_id.to_hex().as_ref().to_owned(),
                                Value::Key(trusted),
                            )])),
                        },
                    ),
                    (
                        NamespaceKey::try_new(CLUSTER_NODES_KEY)
                            .expect("the reserved key is static"),
                        Namespace {
                            value: Value::Map(BTreeMap::from_iter([(
                                key_id.to_hex().as_ref().to_owned(),
                                Value::Map(BTreeMap::from_iter([(
                                    "iroh".to_string(),
                                    Value::try_from(&iroh::EndpointAddr::from_parts(
                                        keys.iroh_secret().public(),
                                        BTreeSet::new(),
                                    ))
                                    .expect("infallible converting a valid EndpointAddr"),
                                )])),
                            )])),
                        },
                    ),
                    (
                        NamespaceKey::try_new(MIN_ENVELOPE_SIGNATURES_KEY)
                            .expect("the reserved key is static"),
                        Namespace {
                            value: Value::Int(1),
                        },
                    ),
                ]),
            },
        }));
        let envelope = keys.sign(envelope).map_err(InitError::Wire)?;

        let mut storage =
            SqliteStorage::open(state_dir.join(SQLITE_DB_FILENAME)).map_err(InitError::Storage)?;
        let chain = Chain::init(&mut storage, envelope).map_err(InitError::Chain)?;
        let oldest = chain.root();

        // Written only once the genesis is durable, so the file never names an
        // envelope the store is missing.
        fs::write(state_dir.join(OLDEST_ENVELOPE_FILENAME), oldest.as_bytes())
            .await
            .map_err(|e| InitError::IO(e, "writing oldest-envelope"))?;

        Ok(Self {
            storage,
            chain,
            oldest,
            state_dir,
            keys,
            subscriptions: Subscriptions::default(),
        })
    }

    /// Lays down a node's keys in `state_dir` without a chain — the first
    /// half of joining an existing cluster, done before the node has
    /// anything to say to it. [`Core::join_in_state_dir`] is the second.
    ///
    /// Leaves the directory uninitialized: a join that fails after this
    /// can be retried, and generates fresh keys when it is.
    pub async fn prepare_join(
        state_dir: PathBuf,
        if_initialized: IfInitialized,
    ) -> Result<NodeKeys, InitError> {
        fs::create_dir_all(&state_dir)
            .await
            .map_err(|e| InitError::IO(e, "creating state-dir"))?;
        Self::refuse_initialized(&state_dir, if_initialized).await?;

        NodeKeys::generate(&state_dir).await
    }

    /// Opens a cluster in `state_dir` from `root`, the oldest envelope a
    /// peer holds, and returns it standing there — the second half of a
    /// join, for the keys [`Core::prepare_join`] left behind. Everything
    /// after the root is pulled from the peer like any other sync.
    ///
    /// The root is taken on trust: whoever handed it over vouched for it,
    /// and its digest is what they vouched by. Checking that the digest is
    /// the one expected is the caller's job.
    pub async fn join_in_state_dir(state_dir: PathBuf, root: Envelope) -> Result<Self, InitError> {
        let keys = NodeKeys::load(&state_dir).await?;
        let mut storage =
            SqliteStorage::open(state_dir.join(SQLITE_DB_FILENAME)).map_err(InitError::Storage)?;
        let chain = Chain::init(&mut storage, root).map_err(InitError::Chain)?;
        let oldest = chain.root();

        // Written only once the root is durable, so the file never names an
        // envelope the store is missing.
        fs::write(state_dir.join(OLDEST_ENVELOPE_FILENAME), oldest.as_bytes())
            .await
            .map_err(|e| InitError::IO(e, "writing oldest-envelope"))?;

        Ok(Self {
            storage,
            chain,
            oldest,
            state_dir,
            keys,
            subscriptions: Subscriptions::default(),
        })
    }

    /// Fails when `state_dir` already holds a cluster and `if_initialized`
    /// says to leave it alone.
    async fn refuse_initialized(
        state_dir: &Path,
        if_initialized: IfInitialized,
    ) -> Result<(), InitError> {
        if if_initialized == IfInitialized::Fail
            && fs::try_exists(state_dir.join(OLDEST_ENVELOPE_FILENAME))
                .await
                .map_err(|e| InitError::IO(e, "reading oldest-envelope"))?
        {
            return Err(InitError::AlreadyInitialized(state_dir.to_path_buf()));
        }
        Ok(())
    }

    /// The canonical head this core stands at.
    pub fn head(&self) -> EnvelopeDigest {
        self.chain.head()
    }

    /// Ingests a parent-first run of envelopes, telling every matching
    /// subscriber what the head movement changed.
    ///
    /// The one path that advances the chain. Everything a subscriber is
    /// promised rests on that: a head that moved anywhere else would move
    /// without anyone being told.
    pub fn insert(
        &mut self,
        envelopes: impl IntoIterator<Item = Envelope>,
    ) -> Result<Insert, ChainError> {
        let differ = ChangeDiffer::opened_at(self.chain.head());
        let insert = self.chain.insert_batch(&mut self.storage, envelopes);

        // Published before the refusal is returned, never instead of it: a
        // run the chain refuses part-way keeps the valid prefix it already
        // stored, so the head can have moved even as this fails.
        let head = self.chain.head();
        if head != differ.from() {
            let movement = differ.diff(&self.storage, head)?;
            self.subscriptions.publish(differ.from(), head, &movement);
        }
        insert
    }

    /// The value `path` addresses in the namespace under `key` — the whole
    /// namespace's value when no path is given — and the head it was read
    /// at. `None` when the ledger holds no such namespace, or the path
    /// stops short of anything inside it.
    ///
    /// One borrow for both, so the value is the one that head holds.
    pub fn read(
        &self,
        key: &NamespaceKey,
        path: Option<&SubkeyPath>,
    ) -> Result<(EnvelopeDigest, Option<Value>), storage::sqlite::Error> {
        let head = self.chain.head();
        let path = path.map_or(&[][..], |path| path.as_ref().as_slice());
        Ok((head, self.storage.value_at(head, key, path)?))
    }

    /// Signs the message `build` makes for the current head with this
    /// node's key and inserts it through [`insert`] — how every local
    /// write reaches the chain.
    ///
    /// Weak: the message chains onto whatever head the core stands at, no
    /// precondition on what was there, and carries one signature. Returns
    /// the envelope's digest alongside what inserting it did.
    ///
    /// [`insert`]: Self::insert
    pub fn sign_write(
        &mut self,
        build: impl FnOnce(EnvelopeDigest) -> Msg,
    ) -> Result<(EnvelopeDigest, Insert), ChainError> {
        let msg = build(self.chain.head());
        let envelope = self
            .keys
            .sign(Envelope::new(msg))
            .map_err(ChainError::Wire)?;
        let digest = envelope.digest().map_err(ChainError::Wire)?;
        let insert = self.insert([envelope])?;
        Ok((digest, insert))
    }

    /// Registers a subscription for the changes `filter` selects.
    ///
    /// The head it opens at is read under the same borrow that registers
    /// it, so nothing can move in between: a subscriber that reads the
    /// state at [`SubscriptionHandle::opened_at`] is certain every later
    /// change reaches it as a notification.
    pub fn subscribe(&self, filter: ChangeFilter) -> SubscriptionHandle {
        self.subscriptions.register(filter, self.chain.head())
    }

    /// Whether `digest` lies on the canonical chain this core stands on.
    ///
    /// O(chain): the walk back from the head, envelope by envelope. What a
    /// woken watcher asks to confirm what it was told.
    pub fn contains(&self, digest: EnvelopeDigest) -> Result<bool, ChainError> {
        self.chain.contains(&self.storage, digest)
    }

    /// Registers a subscription that fires when `digest` leaves the
    /// canonical chain, or `None` when it is not on it to begin with.
    ///
    /// The check and the registration happen under one borrow, which is the
    /// whole point of it living here: checked separately, the envelope
    /// could be orphaned in the gap and the subscription would then wait on
    /// an event that had already passed.
    pub fn watch_orphaned(
        &self,
        digest: EnvelopeDigest,
    ) -> Result<Option<SubscriptionHandle>, ChainError> {
        Ok(self
            .contains(digest)?
            .then(|| self.subscribe(ChangeFilter::orphaned(digest))))
    }

    /// The subscriptions registered against this core.
    pub fn subscriptions(&self) -> &Subscriptions {
        &self.subscriptions
    }

    /// The oldest stored envelope.
    pub fn root(&self) -> EnvelopeDigest {
        self.oldest
    }

    /// The canonical chain, oldest envelope first, of at most `limit`
    /// envelopes counted back from the head and no further back than
    /// `since`.
    ///
    /// Walks back from head by `prev` and stops where the log does, so an
    /// unbounded walk starts as far back as this node can still see — the
    /// chain's root, until compaction has moved it.
    ///
    /// `since` stops the walk rather than filtering it, which is what
    /// makes the answer a contiguous run: envelopes reach the log
    /// parent-first, so along any one chain the times only ever go
    /// forward, and the first envelope stored too long ago has nothing
    /// newer behind it.
    pub fn canonical_chain(
        &self,
        limit: Option<u32>,
        since: Option<StoredAt>,
    ) -> Result<Vec<(EnvelopeDigest, LogEntry)>, storage::sqlite::Error> {
        let limit = limit.map_or(usize::MAX, |limit| limit as usize);
        let mut chain = Vec::new();
        let mut next = Some(self.chain.head());

        // Terminates without a seen-set: a digest covers its parent's, so a
        // cycle would need a hash collision to exist.
        while let Some(digest) = next.filter(|_| chain.len() < limit) {
            let Some(entry) = self.storage.logged_envelope(digest)? else {
                break;
            };
            if since.is_some_and(|since| entry.stored_at < since) {
                break;
            }
            next = entry.envelope.payload().prev_digest().copied();
            chain.push((digest, entry));
        }

        chain.reverse();
        Ok(chain)
    }

    /// The envelopes stored under `digests`, in the order asked for.
    ///
    /// Reads the log, not the canonical chain: an envelope on a losing
    /// fork comes back like any other. Digests the log does not hold are
    /// left out, so the answer can be shorter than the question.
    pub fn envelopes(
        &self,
        digests: impl IntoIterator<Item = EnvelopeDigest>,
    ) -> Result<Vec<(EnvelopeDigest, LogEntry)>, storage::sqlite::Error> {
        digests
            .into_iter()
            .filter_map(|digest| {
                self.storage
                    .logged_envelope(digest)
                    .map(|found| found.map(|entry| (digest, entry)))
                    .transpose()
            })
            .collect()
    }

    /// This node's keys: the one it signs with and the one it is dialled by.
    pub fn keys(&self) -> &NodeKeys {
        &self.keys
    }

    /// The key this node signs ledger envelopes with.
    pub fn signing_key(&self) -> &SigningKey {
        self.keys.signing_key()
    }

    /// The secret key this node's iroh endpoint is identified by.
    pub fn iroh_secret(&self) -> &SecretKey {
        self.keys.iroh_secret()
    }

    /// The id the ledger's trusted key set refers to this node's key by.
    pub fn key_id(&self) -> KeyId {
        self.keys.key_id()
    }

    /// How to reach each node the cluster lists, keyed by node id. Reads
    /// the reserved `cluster-nodes` namespace at the current head.
    pub fn peer_addresses(&self) -> Result<BTreeMap<KeyId, iroh::EndpointAddr>, ChainError> {
        self.chain
            .ledger()
            .peer_addresses(&self.storage)
            .map_err(ChainError::from)
    }

    /// The envelope this node's chain is rooted at — what a joining node
    /// is handed to build on.
    pub fn root_envelope(&self) -> Result<Envelope, storage::sqlite::Error> {
        Ok(self
            .storage
            .envelope(self.oldest)?
            .expect("the oldest-envelope file names an envelope the store holds"))
    }

    /// The keys the ledger trusts at the current head.
    pub fn trusted_keys(&self) -> Result<BTreeMap<KeyId, Key>, ChainError> {
        self.chain
            .ledger()
            .trusted_keys(&self.storage)
            .map_err(ChainError::from)
    }

    /// Returns true if this nodes' key is sufficient to sign an envelope that will
    /// get accepted by the ledger.
    pub fn signs_alone(&self) -> Result<Result<(), CannotSignAlone>, ChainError> {
        let ledger = self.chain.ledger();
        let weight = self
            .trusted_keys()?
            .get(&self.key_id())
            .map_or(0, Key::weight);
        let min_weight = ledger.min_envelope_weight(&self.storage)?;
        let min_signatures = ledger.min_envelope_signatures(&self.storage)?;
        Ok(if weight < min_weight {
            Err(CannotSignAlone::Weight {
                own: weight,
                min: min_weight,
            })
        } else if min_signatures > 1 {
            Err(CannotSignAlone::Signatures {
                min: min_signatures,
            })
        } else {
            Ok(())
        })
    }

    /// Admits a node to the cluster: trusts `key` under its own id, then
    /// lists `addr` under that id in `cluster-nodes`, each as one envelope
    /// signed by this node. Returns the digest of the listing — the one
    /// the joiner watches for, since it lands last.
    ///
    /// Two writes rather than one: a message touches one namespace.
    /// Trusting first, so an envelope the new node signs in between
    /// already verifies.
    pub fn admit(
        &mut self,
        key: Key,
        addr: &iroh::EndpointAddr,
    ) -> Result<EnvelopeDigest, AdmitError> {
        let id = key.id().to_hex().as_ref().to_owned();
        let entry = |namespace: &str, value: Value| {
            let key = NamespaceKey::try_new(namespace).expect("the reserved key is static");
            let path = SubkeyPath::try_new(vec![Subkey::Key(id.clone())])
                .expect("one segment is not empty");
            move |prev| {
                Msg::SetNamespaceKey(SetNamespaceKey {
                    prev,
                    key,
                    path,
                    value: Some(value),
                })
            }
        };
        let listing = Value::Map(BTreeMap::from_iter([(
            "iroh".to_owned(),
            Value::try_from(addr).map_err(AdmitError::Addr)?,
        )]));

        self.sign_write(entry(TRUSTED_KEYS_KEY, Value::Key(key)))
            .map_err(AdmitError::Chain)?;
        let (digest, _) = self
            .sign_write(entry(CLUSTER_NODES_KEY, listing))
            .map_err(AdmitError::Chain)?;
        Ok(digest)
    }

    /// Brings this node's own `cluster-nodes` listing in line with `addr`,
    /// the address its endpoint is reachable at right now.
    ///
    /// Compares and writes under one borrow, so what was compared is what
    /// the write chains onto — and what the indices in an edit were
    /// computed against. Only the transports under the entry's `iroh`
    /// field are written, usually only the ones that moved: see
    /// [`advertise_batch`](Self::advertise_batch). Anything else listed
    /// under this node stays.
    ///
    /// Maintains the transports of the endpoint the ledger already names,
    /// nothing more. A node the ledger does not list is left unlisted, and
    /// one listed under another endpoint id is left alone: which endpoint
    /// a node is, like whether it is listed, is an operator's decision,
    /// and this must not undo it — a daemon started over a copied state
    /// directory on a fresh key would otherwise capture the original's
    /// entry.
    pub fn advertise(&mut self, addr: &iroh::EndpointAddr) -> Result<Advertised, AdvertiseError> {
        let listed = self.peer_addresses().map_err(AdvertiseError::Chain)?;
        let Some(current) = listed.get(&self.key_id()) else {
            return Ok(Advertised::NotListed);
        };
        if current == addr {
            return Ok(Advertised::Unchanged);
        }
        if current.id != addr.id {
            return Ok(Advertised::OtherEndpoint(current.id));
        }
        if let Err(reason) = self.signs_alone().map_err(AdvertiseError::Chain)? {
            return Ok(Advertised::CannotSign(reason));
        }

        let batch = self.advertise_batch(addr)?;
        let digest = batch
            .last()
            .expect("a run carries the whole write at the least")
            .digest()
            .map_err(wire_err)?;
        self.insert(batch).map_err(AdvertiseError::Chain)?;
        Ok(Advertised::Written(digest))
    }

    /// The run of envelopes that takes the transports listed for this
    /// node to `addr`'s: whichever is smaller of writing the array whole
    /// and editing the entries that moved.
    ///
    /// The endpoint id is never written — a listing under another one is
    /// refused above, so the id in the ledger is already the right one,
    /// and a rewrite that carried it would spend those bytes saying so.
    ///
    /// An address usually moves one transport at a time, and an edit
    /// carries the one entry where a rewrite carries every entry there
    /// is. But an edit is a signed envelope of its own, and once enough
    /// of them are needed that costs more than the entries they save. So
    /// both runs are built and the cheaper wins, measured rather than
    /// guessed at.
    fn advertise_batch(&self, addr: &iroh::EndpointAddr) -> Result<Vec<Envelope>, AdvertiseError> {
        let wanted = addr
            .addrs
            .iter()
            .map(Value::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(AdvertiseError::Addr)?;
        let whole = self.sign_updates([Update::Transports(wanted.clone())])?;
        let Some(edits) = self
            .transport_edits(&wanted)?
            .filter(|edits| !edits.is_empty())
        else {
            return Ok(whole);
        };
        let edited = self.sign_updates(edits)?;
        Ok(if batch_bytes(&edited)? < batch_bytes(&whole)? {
            edited
        } else {
            whole
        })
    }

    /// The edits that take the transports listed for this node to
    /// `wanted`: an entry the listing no longer needs is spent on one it
    /// lacks, what is left over is dropped or appended. `None` when the
    /// listing holds no array to edit, leaving a whole write the only way
    /// to mend it.
    ///
    /// Entries are compared as they are stored rather than as they parse,
    /// so an entry naming a transport this build has none for is one to
    /// spend — which is what a whole write does with it too. A duplicate
    /// is spent the same way, for the same reason.
    fn transport_edits(&self, wanted: &[Value]) -> Result<Option<Vec<Update>>, AdvertiseError> {
        let key = NamespaceKey::try_new(CLUSTER_NODES_KEY).expect("the reserved key is static");
        let path = self.listing_path([Subkey::Key(ADDRS.to_owned())]);
        let listed = self
            .storage
            .value_at(self.head(), &key, path.as_ref())
            .map_err(|e| AdvertiseError::Chain(ChainError::Storage(e)))?;
        let Some(Value::Array(listed)) = listed else {
            return Ok(None);
        };

        // The entries the listing keeps hold their indices; every other
        // index is spare, to be written over or dropped.
        let mut kept = HashSet::new();
        let spare = listed
            .iter()
            .enumerate()
            .filter(|(_, entry)| !(wanted.contains(entry) && kept.insert(*entry)))
            .map(|(index, _)| u32::try_from(index))
            .collect::<Result<Vec<_>, _>>();
        // A listing longer than an index can address is not one to edit.
        let Ok(spare) = spare else {
            return Ok(None);
        };
        let missing = wanted
            .iter()
            .filter(|entry| !listed.contains(entry))
            .cloned()
            .collect::<Vec<_>>();

        let paired = spare.len().min(missing.len());
        let appended = missing[paired..].iter().cloned().map(Update::Append);
        let replaced = spare[..paired]
            .iter()
            .zip(&missing[..paired])
            .map(|(&index, entry)| Update::Replace(index, entry.clone()));
        // Highest index first, so a drop never shifts an index a later
        // edit was computed for.
        let dropped = spare[paired..].iter().rev().copied().map(Update::Drop);

        // Gains before losses, so every listing a peer can read between
        // the envelopes names a superset of where this node is reachable:
        // a run cut short leaves it reachable, never unreachable.
        Ok(Some(appended.chain(replaced).chain(dropped).collect()))
    }

    /// Signs `updates` into a parent-first run, each envelope chained onto
    /// the one before it and the first onto the current head.
    ///
    /// Signed rather than described, so a run can be weighed against
    /// another by the bytes it really costs.
    fn sign_updates(
        &self,
        updates: impl IntoIterator<Item = Update>,
    ) -> Result<Vec<Envelope>, AdvertiseError> {
        updates
            .into_iter()
            .try_fold((self.head(), Vec::new()), |(prev, mut batch), update| {
                let envelope = self
                    .keys
                    .sign(Envelope::new(self.advertise_msg(prev, update)))
                    .map_err(wire_err)?;
                let next = envelope.digest().map_err(wire_err)?;
                batch.push(envelope);
                Ok((next, batch))
            })
            .map(|(_, batch)| batch)
    }

    /// The message `update` becomes, chained onto `prev`.
    fn advertise_msg(&self, prev: EnvelopeDigest, update: Update) -> Msg {
        let key = || NamespaceKey::try_new(CLUSTER_NODES_KEY).expect("the reserved key is static");
        let addrs = || Subkey::Key(ADDRS.to_owned());
        let set = |path, value| {
            Msg::SetNamespaceKey(SetNamespaceKey {
                prev,
                key: key(),
                path,
                value,
            })
        };
        match update {
            Update::Transports(entries) => {
                set(self.listing_path([addrs()]), Some(Value::Array(entries)))
            }
            Update::Replace(index, entry) => set(
                self.listing_path([addrs(), Subkey::Index(index)]),
                Some(entry),
            ),
            Update::Drop(index) => set(self.listing_path([addrs(), Subkey::Index(index)]), None),
            Update::Append(entry) => Msg::AmendNamespaceKey(AmendNamespaceKey {
                prev,
                key: key(),
                path: Some(self.listing_path([addrs()])),
                op: AmendOp::AppendEntry(entry),
            }),
        }
    }

    /// The path to the `iroh` field of this node's own `cluster-nodes`
    /// entry, with `below` beneath it.
    fn listing_path(&self, below: impl IntoIterator<Item = Subkey>) -> SubkeyPath {
        SubkeyPath::try_new(
            [
                Subkey::Key(self.key_id().to_hex().as_ref().to_owned()),
                Subkey::Key("iroh".to_owned()),
            ]
            .into_iter()
            .chain(below)
            .collect(),
        )
        .expect("two segments are not empty")
    }

    /// Answers one sync-machine query against this node's chain — the
    /// core-side half of the `sync` crate's `Effect::Ask` contract.
    pub fn sync_answer(&self, query: sync::Query) -> Result<sync::Answer, storage::sqlite::Error> {
        match query {
            sync::Query::ContainsEnvelope(digest) => self
                .storage
                .envelope(digest)
                .map(|stored| sync::Answer::Contains(stored.is_some())),
            sync::Query::Locator => self
                .walk_canonical(|walk| sync::locator::sample(walk))
                .map(sync::Answer::Locator),
            sync::Query::SplitPoint(entries) => self
                .walk_canonical(|walk| sync::locator::split(&entries, walk))
                .map(sync::Answer::SplitPoint),
            sync::Query::Segment { after } => self.segment(after).map(sync::Answer::Segment),
        }
    }

    /// Streams the canonical path, newest first, into `consume` by digest
    /// alone — no path is materialized and no envelope is decoded, each
    /// hop being one [`Storage::parent`] column read. This runs on the
    /// mainloop, so O(chain) hops is the budget; anything heavier here
    /// stalls every other caller. A storage failure ends the walk early
    /// and surfaces as the error, discarding `consume`'s answer.
    fn walk_canonical<T>(
        &self,
        consume: impl FnOnce(&mut dyn Iterator<Item = EnvelopeDigest>) -> T,
    ) -> Result<T, storage::sqlite::Error> {
        let mut failure = None;
        let mut walk = std::iter::successors(Some(self.chain.head()), |&at| {
            match self.storage.parent(at) {
                Ok(parent) => parent,
                Err(err) => {
                    failure = Some(err);
                    None
                }
            }
        });
        let out = consume(&mut walk);
        match failure {
            None => Ok(out),
            Some(err) => Err(err),
        }
    }

    /// The canonical path just after `after`, parent-first, within the
    /// sync segment budgets — empty when `after` is the head, or has left
    /// the canonical path, which is how a mid-session reorg ends a stream
    /// early rather than wrongly.
    fn segment(&self, after: EnvelopeDigest) -> Result<Vec<Envelope>, storage::sqlite::Error> {
        let newer = self.walk_canonical(|walk| {
            let mut newer = Vec::new();
            for digest in walk {
                if digest == after {
                    return Some(newer);
                }
                newer.push(digest);
            }
            None
        })?;
        let Some(newer) = newer else {
            return Ok(Vec::new());
        };

        let mut budget = sync::SEGMENT_BYTE_BUDGET as usize;
        let mut segment = Vec::new();
        for digest in newer
            .into_iter()
            .rev()
            .take(sync::MAX_BATCH_ENVELOPES as usize)
        {
            let envelope = self
                .storage
                .envelope(digest)?
                .expect("the canonical walk visits only stored envelopes");
            let cost = wire::encode(&envelope)
                .expect("a stored envelope re-encodes")
                .len();
            // The first envelope goes regardless of its size: excluding
            // it would end the stream early and wedge sync at this point
            // for good, where an oversize frame at least fails loudly.
            if !segment.is_empty() && cost > budget {
                break;
            }
            budget = budget.saturating_sub(cost);
            segment.push(envelope);
        }
        Ok(segment)
    }
}

/// Loads the node's ledger signing key from `state_dir`.
async fn load_signing_key(state_dir: &Path) -> Result<SigningKey, InitError> {
    load_secret(
        state_dir.join(SIGNING_KEY_FILENAME),
        "reading signing-key",
        InitError::SigningKeyLength,
    )
    .await
    .map(SigningKey::from)
}

/// Loads the node's iroh secret key from `state_dir`.
async fn load_iroh_secret(state_dir: &Path) -> Result<SecretKey, InitError> {
    load_secret(
        state_dir.join(IROH_SECRET_FILENAME),
        "reading iroh-secret",
        InitError::IrohSecretLength,
    )
    .await
    .map(|secret| SecretKey::from_bytes(&secret))
}

/// Reads the 32 bytes of key material at `path`, reporting a file of any
/// other length through `wrong_length`.
async fn load_secret(
    path: PathBuf,
    reading: &'static str,
    wrong_length: impl FnOnce(PathBuf, usize) -> InitError,
) -> Result<[u8; 32], InitError> {
    let bytes = fs::read(&path)
        .await
        .map_err(|e| InitError::IO(e, reading))?;

    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| wrong_length(path, bytes.len()))
}

/// The two keys that make a node: what [`Core`] runs on, and what
/// [`Core::prepare_join`] lays down before there is a chain to run.
#[derive(Debug, Clone)]
pub struct NodeKeys {
    /// The one key this node signs ledger envelopes with.
    signing_key: SigningKey,
    /// The one key this node's iroh endpoint is identified by. Nothing to
    /// do with the ledger: peers dial it, the trusted key set never names
    /// it, and it signs no envelope.
    iroh_secret: SecretKey,
}

impl NodeKeys {
    /// Reads both keys from `state_dir`.
    async fn load(state_dir: &Path) -> Result<Self, InitError> {
        Ok(Self {
            signing_key: load_signing_key(state_dir).await?,
            iroh_secret: load_iroh_secret(state_dir).await?,
        })
    }

    /// Draws both keys fresh and saves them under `state_dir`, replacing
    /// whatever was there: a node has exactly one of each. Returned as
    /// read back from disk, so a core is the same whichever way it was
    /// reached.
    ///
    /// Not `SigningKey::new`: ed25519-zebra takes rand_core 0.6's traits
    /// while the workspace is on rand 0.10, so no RNG here satisfies it.
    /// `new` only fills 32 bytes and calls `from`, which `load` does.
    async fn generate(state_dir: &Path) -> Result<Self, InitError> {
        write_secret(
            &state_dir.join(SIGNING_KEY_FILENAME),
            &draw_secret()?,
            ("creating signing-key", "saving signing-key"),
        )
        .await?;
        write_secret(
            &state_dir.join(IROH_SECRET_FILENAME),
            &draw_secret()?,
            ("creating iroh-secret", "saving iroh-secret"),
        )
        .await?;
        Self::load(state_dir).await
    }

    /// The key this node signs ledger envelopes with.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// The public half of the signing key, in the form the ledger's key
    /// set holds.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::Ed25519(Ed25519PublicKey::from_bytes(
            self.signing_key.verification_key().into(),
        ))
    }

    /// The id the ledger refers to this node by.
    pub fn key_id(&self) -> KeyId {
        self.public_key().id()
    }

    /// The secret the node's iroh endpoint is identified by.
    pub fn iroh_secret(&self) -> &SecretKey {
        &self.iroh_secret
    }

    /// Attaches this node's signature over `envelope` to it.
    ///
    /// Every part of the envelope but its signatures must already be in
    /// place — timestamps included — since the digest signed here covers
    /// them.
    pub fn sign(&self, envelope: Envelope) -> Result<Envelope, wire::Error> {
        let digest = envelope.signature_digest()?;
        let signature = Signature::Ed25519(Ed25519Signature::from_bytes(
            self.signing_key.sign(digest.as_bytes()).to_bytes(),
        ));
        Ok(envelope.with_signature(self.key_id(), signature))
    }
}

/// Why a node could not be admitted.
#[derive(Debug, thiserror::Error)]
pub enum AdmitError {
    #[error("the endpoint address has no ledger encoding")]
    Addr(#[source] wire::msg::AddrError),
    #[error("writing the admission")]
    Chain(#[source] ChainError),
    #[error("the server is shutting down")]
    ServerGone,
}

/// One envelope's worth of change to the transports listed for this node.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Update {
    /// Writes the transport array whole.
    Transports(Vec<Value>),
    /// Writes over the entry at this index.
    Replace(u32, Value),
    /// Drops the entry at this index; the entries after it shift down.
    Drop(u32),
    /// Appends an entry to the transport array.
    Append(Value),
}

/// What a run of envelopes costs stored and gossiped: the canonical
/// encoding of each, signatures included, since that is what a peer
/// receives.
fn batch_bytes(batch: &[Envelope]) -> Result<usize, AdvertiseError> {
    batch.iter().try_fold(0, |total, envelope| {
        Ok(total + wire::encode(envelope).map_err(wire_err)?.len())
    })
}

/// An encoding failure, as the error an advertisement reports.
fn wire_err(e: wire::Error) -> AdvertiseError {
    AdvertiseError::Chain(ChainError::Wire(e))
}

/// What [`Core::advertise`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advertised {
    /// The ledger already listed this address.
    Unchanged,
    /// The listing was brought up to date; holds the digest of the last
    /// envelope it took, which may be one of several.
    Written(EnvelopeDigest),
    /// The ledger does not list this node, so there is nothing to update.
    NotListed,
    /// The ledger lists this node under the endpoint id given, not the
    /// one it serves on, so the listing is not this endpoint's to keep.
    OtherEndpoint(iroh::EndpointId),
    /// The listing is stale, but this node's signature alone would not
    /// carry the update.
    CannotSign(CannotSignAlone),
}

/// Why [`Core::advertise`] could not run.
#[derive(Debug, thiserror::Error)]
pub enum AdvertiseError {
    #[error("the endpoint address has no ledger encoding")]
    Addr(#[source] wire::msg::AddrError),
    #[error("reading or writing the listing")]
    Chain(#[source] ChainError),
    #[error("the server is shutting down")]
    ServerGone,
}

/// Why an envelope signed by this node alone would not apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CannotSignAlone {
    #[error("this node's key weighs {own}, below the ledger's floor of {min}")]
    Weight { own: u32, min: u32 },
    #[error("the ledger requires {min} signatures per envelope")]
    Signatures { min: u32 },
}

/// Draws 32 bytes for an invite token, from the same source as a key.
pub(crate) fn draw_token() -> Result<[u8; 32], rand::rngs::SysError> {
    let mut token = [0u8; 32];
    SysRng.try_fill_bytes(&mut token)?;
    Ok(token)
}

/// Draws 32 bytes of key material.
///
/// Straight from the OS rather than through a userspace generator: this is
/// one 32-byte draw, so ThreadRng's speed buys nothing and it leaves PRNG
/// state that outlives the key.
fn draw_secret() -> Result<[u8; 32], InitError> {
    let mut secret = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut secret)
        .map_err(InitError::Entropy)?;
    Ok(secret)
}

/// Writes key material to `path`, reporting the two ways that fails under
/// the labels given.
async fn write_secret(
    path: &Path,
    secret: &[u8; 32],
    (creating, saving): (&'static str, &'static str),
) -> Result<(), InitError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    // Created 0600 rather than relaxed-then-tightened: a secret key must never
    // exist group- or world-readable, not even for the width of one write.
    // `mode` is tokio's own inherent unix-only method, not `OpenOptionsExt`.
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options
        .open(path)
        .await
        .map_err(|e| InitError::IO(e, creating))?;
    file.write_all(secret)
        .await
        .map_err(|e| InitError::IO(e, saving))?;

    // `write_all` only queues the bytes onto tokio's blocking pool, and a
    // dropped `File` never waits for them: without this the read that
    // follows can find the file still empty — or, on a rewrite, truncated
    // back to nothing. `sync_all` waits, and puts the key somewhere a
    // crash cannot take it: a node that loses this file loses the endpoint
    // peers dial it at.
    file.sync_all().await.map_err(|e| InitError::IO(e, saving))
}

#[derive(Debug)]
pub enum InitError {
    /// An I/O error.
    IO(std::io::Error, &'static str),
    /// The state directory already holds a cluster; holds that directory.
    AlreadyInitialized(PathBuf),
    /// The OS could not supply entropy for a new key.
    Entropy(rand::rngs::SysError),
    /// The genesis envelope could not be encoded to be signed.
    Wire(wire::Error),
    /// The signing key file was not exactly 32 bytes; holds it and the length found.
    SigningKeyLength(PathBuf, usize),
    /// The iroh secret file was not exactly 32 bytes; holds it and the length found.
    IrohSecretLength(PathBuf, usize),
    /// The oldest-envelope file was not exactly 32 bytes; holds the length found.
    OldestDigestLength(usize),
    /// An error occurred initializing the sqlite database.
    Storage(storage::sqlite::Error),
    /// Error when replaying the chain back to head.
    Chain(state::Error<storage::sqlite::Error>),
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InitError::IO(_, what) => write!(f, "{what}"),
            InitError::AlreadyInitialized(dir) => {
                write!(f, "{} already holds a cluster", dir.display())
            }
            InitError::Entropy(_) => f.write_str("the OS could not supply entropy for a key"),
            InitError::Wire(_) => f.write_str("encoding the genesis envelope"),
            InitError::SigningKeyLength(path, len) => {
                write!(f, "{} holds {len} bytes, not a 32-byte key", path.display())
            }
            InitError::IrohSecretLength(path, len) => {
                write!(
                    f,
                    "{} holds {len} bytes, not a 32-byte secret",
                    path.display()
                )
            }
            InitError::OldestDigestLength(len) => {
                write!(
                    f,
                    "the oldest-envelope file holds {len} bytes, not a 32-byte digest"
                )
            }
            InitError::Storage(_) => f.write_str("opening the store"),
            InitError::Chain(_) => f.write_str("opening the chain"),
        }
    }
}

impl core::error::Error for InitError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            InitError::IO(err, _) => Some(err),
            InitError::Entropy(err) => Some(err),
            InitError::Wire(err) => Some(err),
            InitError::Storage(err) => Some(err),
            InitError::Chain(err) => Some(err),
            InitError::AlreadyInitialized(_)
            | InitError::SigningKeyLength(..)
            | InitError::IrohSecretLength(..)
            | InitError::OldestDigestLength(_) => None,
        }
    }
}
