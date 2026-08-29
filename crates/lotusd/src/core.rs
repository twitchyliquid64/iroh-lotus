//! The initialized internals for a lotus node.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::{Path, PathBuf},
};

use ed25519_zebra::SigningKey;
use iroh::SecretKey;
use rand::{TryRng, rngs::SysRng};
use state::{CLUSTER_NODES_KEY, Chain, ChangeDiffer, Insert, TRUSTED_KEYS_KEY};
use storage::{LogEntry, SqliteStorage, Storage, StoredAt};
use tokio::{fs, io::AsyncWriteExt};
use wire::{
    Envelope, EnvelopeDigest, Key, KeyId, Msg, Signature,
    keys::{Ed25519PublicKey, Ed25519Signature, PublicKey},
    msg::{FullCheckpoint, InitMsg, Namespace, NamespaceKey, Value},
    subkey::SubkeyPath,
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
    /// The one key this node signs ledger envelopes with.
    signing_key: SigningKey,
    /// The one key this node's iroh endpoint is identified by. Nothing to
    /// do with the ledger: peers dial it, the trusted key set never names
    /// it, and it signs no envelope.
    iroh_secret: SecretKey,
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
        let signing_key = load_signing_key(&state_dir).await?;
        let iroh_secret = load_iroh_secret(&state_dir).await?;

        Ok(Self {
            storage,
            chain,
            oldest,
            state_dir,
            signing_key,
            iroh_secret,
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

        if if_initialized == IfInitialized::Fail
            && fs::try_exists(state_dir.join(OLDEST_ENVELOPE_FILENAME))
                .await
                .map_err(|e| InitError::IO(e, "reading oldest-envelope"))?
        {
            return Err(InitError::AlreadyInitialized(state_dir));
        }

        let signing_key = gen_signing_key(&state_dir).await?;
        let trusted = Key::new(public_key(&signing_key), ROOT_KEY_WEIGHT);
        let key_id = trusted.id();
        gen_iroh_secret(&state_dir).await?;
        let iroh_secret = load_iroh_secret(&state_dir).await?;

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
                                        iroh_secret.public(),
                                        BTreeSet::new(),
                                    ))
                                    .expect("infallible converting a valid EndpointAddr"),
                                )])),
                            )])),
                        },
                    ),
                ]),
            },
        }));
        let envelope = sign(&signing_key, key_id, envelope).map_err(InitError::Wire)?;

        let mut storage =
            SqliteStorage::open(state_dir.join(SQLITE_DB_FILENAME)).map_err(InitError::Storage)?;
        let chain = Chain::init(&mut storage, envelope).map_err(InitError::Chain)?;
        let oldest = chain.root();

        // Written only once the genesis is durable, so the file never names an
        // envelope the store is missing.
        fs::write(state_dir.join(OLDEST_ENVELOPE_FILENAME), oldest.as_bytes())
            .await
            .map_err(|e| InitError::IO(e, "writing oldest-envelope"))?;

        // Read back rather than assembled from the keys just generated, so a
        // core is the same whichever way it was reached.
        let signing_key = load_signing_key(&state_dir).await?;

        Ok(Self {
            storage,
            chain,
            oldest,
            state_dir,
            signing_key,
            iroh_secret,
            subscriptions: Subscriptions::default(),
        })
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
        let envelope =
            sign(&self.signing_key, self.key_id(), Envelope::new(msg)).map_err(ChainError::Wire)?;
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

    /// The key this node signs ledger envelopes with.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// The secret key this node's iroh endpoint is identified by.
    pub fn iroh_secret(&self) -> &SecretKey {
        &self.iroh_secret
    }

    /// The id the ledger's trusted key set refers to this node's key by.
    pub fn key_id(&self) -> KeyId {
        public_key(&self.signing_key).id()
    }

    /// How to reach each node the cluster lists, keyed by node id. Reads
    /// the reserved `cluster-nodes` namespace at the current head.
    pub fn peer_addresses(&self) -> Result<BTreeMap<KeyId, iroh::EndpointAddr>, ChainError> {
        self.chain
            .ledger()
            .peer_addresses(&self.storage)
            .map_err(ChainError::from)
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

/// The public half of `key`, in the form the ledger's key set holds.
fn public_key(key: &SigningKey) -> PublicKey {
    PublicKey::Ed25519(Ed25519PublicKey::from_bytes(key.verification_key().into()))
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

/// Attaches `key_id`'s signature over `envelope` to it.
///
/// Every part of the envelope but its signatures must already be in place —
/// timestamps included — since the digest signed here covers them.
fn sign(key: &SigningKey, key_id: KeyId, envelope: Envelope) -> Result<Envelope, wire::Error> {
    let digest = envelope.signature_digest()?;
    let signature = Signature::Ed25519(Ed25519Signature::from_bytes(
        key.sign(digest.as_bytes()).to_bytes(),
    ));
    Ok(envelope.with_signature(key_id, signature))
}

/// Generates this node's ledger signing key and saves it under `state_dir`,
/// replacing whatever key was there: a node has exactly one.
async fn gen_signing_key(state_dir: &Path) -> Result<SigningKey, InitError> {
    let secret = draw_secret()?;
    write_secret(
        &state_dir.join(SIGNING_KEY_FILENAME),
        &secret,
        ("creating signing-key", "saving signing-key"),
    )
    .await?;

    // Not `SigningKey::new`: ed25519-zebra takes rand_core 0.6's traits while
    // the workspace is on rand 0.10, so no RNG here satisfies it. `new` only
    // fills 32 bytes and calls `from`, which is what this does.
    Ok(SigningKey::from(secret))
}

/// Generates this node's iroh secret key and saves it under `state_dir`,
/// replacing whatever key was there: a node has exactly one, and its
/// endpoint is that key.
async fn gen_iroh_secret(state_dir: &Path) -> Result<(), InitError> {
    write_secret(
        &state_dir.join(IROH_SECRET_FILENAME),
        &draw_secret()?,
        ("creating iroh-secret", "saving iroh-secret"),
    )
    .await
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
