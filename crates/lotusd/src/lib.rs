use std::{
    collections::BTreeMap,
    fmt,
    ops::ControlFlow,
    path::{Path, PathBuf},
};

use ed25519_zebra::SigningKey;
use rand::{TryRng, rngs::SysRng};
use state::{Chain, TRUSTED_KEYS_KEY};
use storage::{SqliteStorage, Storage};
use tokio::{
    fs,
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use wire::{
    Envelope, EnvelopeDigest, Key, KeyId, Msg, Signature,
    keys::{Ed25519PublicKey, Ed25519Signature, PublicKey},
    msg::{FullCheckpoint, InitMsg, Namespace, NamespaceKey, Value},
};

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

pub const SQLITE_DB_FILENAME: &str = "db.sqlite";
pub const OLDEST_ENVELOPE_FILENAME: &str = "oldest_envelope";
/// Extension of the signing key files in a state directory, each named by
/// the [`KeyId`] of the key it holds.
pub const SIGNING_KEY_EXTENSION: &str = "ed25519";

/// The weight given to the key a new cluster is founded on.
const ROOT_KEY_WEIGHT: u32 = 2;

/// The initialized internals of lotusd.
#[derive(Debug)]
#[allow(dead_code)]
pub struct Core {
    storage: SqliteStorage,
    chain: Chain,
    oldest: EnvelopeDigest,
    state_dir: PathBuf,
    /// Every key this node can sign with, by the id the ledger's trusted
    /// key set refers to it by.
    signing_keys: BTreeMap<KeyId, SigningKey>,
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
        let signing_keys = load_signing_keys(&state_dir).await?;

        Ok(Self {
            storage,
            chain,
            oldest,
            state_dir,
            signing_keys,
        })
    }

    /// Initializes a new cluster in `state_dir` — generating its first signing
    /// key and committing the genesis envelope — and returns it opened, as
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

        let envelope = Envelope::new(Msg::Init(InitMsg {
            state: FullCheckpoint {
                namespaces: BTreeMap::from_iter([(
                    NamespaceKey::try_new(TRUSTED_KEYS_KEY).expect("the reserved key is static"),
                    Namespace {
                        value: Value::Map(BTreeMap::from_iter([(
                            key_id.to_hex().as_ref().to_owned(),
                            Value::Key(trusted),
                        )])),
                    },
                )]),
            },
        }));
        let envelope = sign(&signing_key, key_id, envelope)?;

        let mut storage =
            SqliteStorage::open(state_dir.join(SQLITE_DB_FILENAME)).map_err(InitError::Storage)?;
        let chain = Chain::init(&mut storage, envelope).map_err(InitError::Chain)?;
        let oldest = chain.root();

        // Written only once the genesis is durable, so the file never names an
        // envelope the store is missing.
        fs::write(state_dir.join(OLDEST_ENVELOPE_FILENAME), oldest.as_bytes())
            .await
            .map_err(|e| InitError::IO(e, "writing oldest-envelope"))?;

        // Scanned rather than assembled from the key just generated, so a
        // core is the same whichever way it was reached.
        let signing_keys = load_signing_keys(&state_dir).await?;

        Ok(Self {
            storage,
            chain,
            oldest,
            state_dir,
            signing_keys,
        })
    }

    /// The canonical head this core stands at.
    pub fn head(&self) -> EnvelopeDigest {
        self.chain.head()
    }

    /// The oldest stored envelope.
    pub fn root(&self) -> EnvelopeDigest {
        self.oldest
    }

    /// The canonical chain, oldest envelope first.
    ///
    /// Walks back from head by `prev` and stops where the log does, so the
    /// first entry is as far back as this node can still see — the chain's
    /// root, until compaction has moved it.
    pub fn canonical_chain(
        &self,
    ) -> Result<Vec<(EnvelopeDigest, Envelope)>, storage::sqlite::Error> {
        let mut chain = Vec::new();
        let mut next = Some(self.chain.head());

        // Terminates without a seen-set: a digest covers its parent's, so a
        // cycle would need a hash collision to exist.
        while let Some(digest) = next {
            let Some(envelope) = self.storage.envelope(digest)? else {
                break;
            };
            next = envelope.payload().prev_digest().copied();
            chain.push((digest, envelope));
        }

        chain.reverse();
        Ok(chain)
    }

    /// Every key this node can sign with, by id.
    pub fn signing_keys(&self) -> &BTreeMap<KeyId, SigningKey> {
        &self.signing_keys
    }
}

/// The public half of `key`, in the form the ledger's key set holds.
fn public_key(key: &SigningKey) -> PublicKey {
    PublicKey::Ed25519(Ed25519PublicKey::from_bytes(key.verification_key().into()))
}

/// Loads every signing key saved under `state_dir`.
///
/// Filed under the id derived from the key material, never from the
/// filename: the name is a label for operators to read, and a renamed file
/// must not change which key an id resolves to.
async fn load_signing_keys(state_dir: &Path) -> Result<BTreeMap<KeyId, SigningKey>, InitError> {
    let mut entries = fs::read_dir(state_dir)
        .await
        .map_err(|e| InitError::IO(e, "listing state-dir"))?;
    let mut keys = BTreeMap::new();

    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| InitError::IO(e, "listing state-dir"))?
    {
        let path = entry.path();
        if path
            .extension()
            .is_none_or(|ext| ext != SIGNING_KEY_EXTENSION)
        {
            continue;
        }

        let bytes = fs::read(&path)
            .await
            .map_err(|e| InitError::IO(e, "reading signing-key"))?;
        let seed = <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| InitError::SigningKeyLength(path, bytes.len()))?;

        let key = SigningKey::from(seed);
        keys.insert(public_key(&key).id(), key);
    }

    Ok(keys)
}

/// Attaches `key_id`'s signature over `envelope` to it.
///
/// Every part of the envelope but its signatures must already be in place —
/// timestamps included — since the digest signed here covers them.
fn sign(key: &SigningKey, key_id: KeyId, envelope: Envelope) -> Result<Envelope, InitError> {
    let digest = envelope.signature_digest().map_err(InitError::Wire)?;
    let signature = Signature::Ed25519(Ed25519Signature::from_bytes(
        key.sign(digest.as_bytes()).to_bytes(),
    ));
    Ok(envelope.with_signature(key_id, signature))
}

/// Generates a cluster's first signing key and saves it under `state_dir`,
/// named by the [`wire::KeyId`] the trusted key set refers to it by so an
/// operator can match the file to a key set entry.
async fn gen_signing_key(state_dir: &Path) -> Result<SigningKey, InitError> {
    // Drawn straight from the OS rather than through a userspace generator:
    // this is one 32-byte draw, so ThreadRng's speed buys nothing and it
    // leaves PRNG state that outlives the key.
    //
    // Not `SigningKey::new`: ed25519-zebra takes rand_core 0.6's traits while
    // the workspace is on rand 0.10, so no RNG here satisfies it. `new` only
    // fills 32 bytes and calls `from`, which is what this does.
    let mut seed = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut seed)
        .map_err(InitError::Entropy)?;
    let key = SigningKey::from(seed);

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    // Created 0600 rather than relaxed-then-tightened: a signing key must never
    // exist group- or world-readable, not even for the width of one write.
    // `mode` is tokio's own inherent unix-only method, not `OpenOptionsExt`.
    #[cfg(unix)]
    options.mode(0o600);

    options
        .open(state_dir.join(format!("{}.{SIGNING_KEY_EXTENSION}", public_key(&key).id())))
        .await
        .map_err(|e| InitError::IO(e, "creating signing-key"))?
        .write_all(&key.to_bytes())
        .await
        .map_err(|e| InitError::IO(e, "saving signing-key"))?;
    Ok(key)
}

#[derive(Debug)]
pub enum InitError {
    /// An I/O error.
    IO(std::io::Error, &'static str),
    /// The state directory already holds a cluster; holds that directory.
    AlreadyInitialized(PathBuf),
    /// The OS could not supply entropy for a new signing key.
    Entropy(rand::rngs::SysError),
    /// The genesis envelope could not be encoded to be signed.
    Wire(wire::Error),
    /// A signing key file was not exactly 32 bytes; holds it and the length found.
    SigningKeyLength(PathBuf, usize),
    /// The oldest-envelope file was not exactly 32 bytes; holds the length found.
    OldestDigestLength(usize),
    /// An error occurred initializing the sqlite database.
    Storage(storage::sqlite::Error),
    /// Error when replaying the chain back to head.
    Chain(state::Error<storage::sqlite::Error>),
}

#[derive(Debug)]
enum ServerMsg {
    Shutdown(Responder<(), ()>),
    Head(Responder<EnvelopeDigest, ()>),
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
                        Ok((stream, _addr)) => Self::handle_connection(&mut core, stream).await,
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
            ServerMsg::Head(r) => Self::handle_head(core, r).await,
        }

        ControlFlow::Continue(())
    }

    /// Reads the canonical head the core stands at.
    async fn handle_head(core: &mut Core, r: Responder<EnvelopeDigest, ()>) {
        r.handle(async move { Ok(core.head()) }).await
    }

    /// Serves one client on the local control socket.
    async fn handle_connection(_core: &mut Core, stream: UnixStream) {
        // TODO: speak the control protocol. Dropping the stream closes it.
        tracing::info!("accepted local connection");
        drop(stream);
    }
}

/// A handle to a running lotusd server.
#[derive(Debug, Clone)]
pub struct ServerHandle(mpsc::Sender<ServerMsg>);

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

    /// Reads the current HEAD.
    pub async fn head(&self) -> Result<EnvelopeDigest, ()> {
        let (send, recv) = Responder::channel();
        let _ = self.0.send(ServerMsg::Head(send)).await;
        match recv.await {
            Ok(Ok(v)) => Ok(v),
            _ => Err(()),
        }
    }
}
