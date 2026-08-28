//! What `Core::create_in_state_dir` lays down must be what
//! `Core::init_with_state_dir` picks up on the next start.

use std::{fs::DirEntry, path::Path};

use lotusd::{Core, IfInitialized, InitError};
use state::{Chain, Insert, Ledger};
use storage::{SqliteStorage, Storage};
use tempfile::TempDir;
use wire::{
    Envelope, Msg, Signature, VerificationStatus,
    keys::{Ed25519PublicKey, Ed25519Signature, PublicKey},
    msg::{Namespace, NamespaceKey, SetNamespace, Value},
};

async fn create(dir: &TempDir, if_initialized: IfInitialized) -> Result<Core, InitError> {
    Core::create_in_state_dir(dir.path().to_path_buf(), if_initialized).await
}

/// The one signing key `create_in_state_dir` leaves in `dir`.
fn signing_key_file(dir: &Path) -> DirEntry {
    let mut keys = std::fs::read_dir(dir)
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|ext| ext == lotusd::SIGNING_KEY_EXTENSION)
        });

    let key = keys.next().expect("init writes a signing key");
    assert!(keys.next().is_none(), "init writes only one signing key");
    key
}

#[tokio::test]
async fn created_cluster_reopens_at_the_same_head() {
    let dir = TempDir::new().unwrap();
    let created = create(&dir, IfInitialized::Fail).await.unwrap();
    let (root, head) = (created.root(), created.head());
    drop(created);

    let opened = Core::init_with_state_dir(dir.path().to_path_buf())
        .await
        .unwrap();

    assert_eq!(opened.root(), root);
    assert_eq!(opened.head(), head);
}

#[tokio::test]
async fn create_refuses_an_initialized_state_dir() {
    let dir = TempDir::new().unwrap();
    create(&dir, IfInitialized::Fail).await.unwrap();

    assert!(matches!(
        create(&dir, IfInitialized::Fail).await,
        Err(InitError::AlreadyInitialized(_))
    ));
}

#[tokio::test]
async fn overwrite_reinitializes_an_openable_cluster() {
    let dir = TempDir::new().unwrap();
    create(&dir, IfInitialized::Fail).await.unwrap();
    let recreated = create(&dir, IfInitialized::Overwrite).await.unwrap();
    let head = recreated.head();
    drop(recreated);

    let opened = Core::init_with_state_dir(dir.path().to_path_buf())
        .await
        .unwrap();

    assert_eq!(opened.head(), head);
}

#[cfg(unix)]
#[tokio::test]
async fn the_signing_key_is_written_unreadable_to_anyone_else() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    create(&dir, IfInitialized::Fail).await.unwrap();

    let key = signing_key_file(dir.path());
    assert_eq!(key.metadata().unwrap().permissions().mode() & 0o777, 0o600);
}

/// Genesis is verified against the key set genesis installs itself, so a
/// weight above zero says both halves lined up: the signature checked out,
/// and the key that made it is in the set the same envelope carries.
#[tokio::test]
async fn genesis_is_signed_by_the_key_it_trusts() {
    let dir = TempDir::new().unwrap();
    let core = create(&dir, IfInitialized::Fail).await.unwrap();
    let root = core.root();
    drop(core);

    let storage = SqliteStorage::open(dir.path().join(lotusd::SQLITE_DB_FILENAME)).unwrap();
    let genesis = storage
        .envelope(root)
        .unwrap()
        .expect("the root is in the log");

    let signers: Vec<_> = genesis.signatures().keys().collect();
    assert_eq!(signers.len(), 1);
    assert_eq!(
        signers[0].to_hex().as_ref(),
        signing_key_file(dir.path()).path().file_stem().unwrap(),
        "the key on disk is named by the id that signed genesis",
    );

    assert!(genesis.verification_status().signature_weight() > 0);
}

#[tokio::test]
async fn reopening_loads_the_signing_keys_on_disk() {
    let dir = TempDir::new().unwrap();
    let created = create(&dir, IfInitialized::Fail).await.unwrap();
    let ids: Vec<_> = created.signing_keys().keys().copied().collect();
    drop(created);

    let opened = Core::init_with_state_dir(dir.path().to_path_buf())
        .await
        .unwrap();

    assert_eq!(
        opened.signing_keys().keys().copied().collect::<Vec<_>>(),
        ids
    );
    assert_eq!(
        ids.len(),
        1,
        "a fresh cluster is founded on exactly one key"
    );
    assert_eq!(
        ids[0].to_hex().as_ref(),
        signing_key_file(dir.path()).path().file_stem().unwrap(),
    );
}

/// Every key in the directory loads, not just the one the latest init wrote —
/// an overwritten cluster leaves the previous key behind, and a node that
/// forgot it could not sign under the old id again.
#[tokio::test]
async fn every_key_in_the_state_dir_is_loaded() {
    let dir = TempDir::new().unwrap();
    create(&dir, IfInitialized::Fail).await.unwrap();
    let recreated = create(&dir, IfInitialized::Overwrite).await.unwrap();

    assert_eq!(recreated.signing_keys().len(), 2);
}

#[tokio::test]
async fn a_truncated_signing_key_is_refused() {
    let dir = TempDir::new().unwrap();
    create(&dir, IfInitialized::Fail).await.unwrap();
    let key = signing_key_file(dir.path()).path();
    std::fs::write(&key, [0u8; 31]).unwrap();

    assert!(matches!(
        Core::init_with_state_dir(dir.path().to_path_buf()).await,
        Err(InitError::SigningKeyLength(path, 31)) if path == key
    ));
}

/// The stored verification status is a cache `Chain::init` wrote at creation
/// time; this re-derives it from what actually persisted, so it fails if the
/// trusted key set did not survive the round trip through storage even
/// though the cached status still claims genesis verified.
#[tokio::test]
async fn genesis_reverifies_against_the_state_at_head() {
    let dir = TempDir::new().unwrap();
    create(&dir, IfInitialized::Fail).await.unwrap();

    let core = Core::init_with_state_dir(dir.path().to_path_buf())
        .await
        .unwrap();

    let storage = SqliteStorage::open(dir.path().join(lotusd::SQLITE_DB_FILENAME)).unwrap();
    let genesis = storage
        .envelope(core.root())
        .unwrap()
        .expect("the root is in the log");

    // Genesis is its own parent for verification, so a ledger at head is the
    // position its signatures are scored from.
    let ledger = Ledger::open(&storage, core.head()).unwrap();
    let trusted = ledger.trusted_keys(&storage).unwrap();

    let expected: u32 = genesis
        .signatures()
        .keys()
        .map(|id| {
            let key = trusted.get(id).expect("every signer is trusted at head");
            assert!(
                core.signing_keys().contains_key(id),
                "the node holds the key that signed its own genesis",
            );
            key.weight()
        })
        .sum();
    assert!(expected > 0, "genesis carries a signature worth something");

    assert_eq!(
        ledger.verify_envelope(&storage, &genesis).unwrap(),
        VerificationStatus::AllMatched {
            total_weight: expected
        },
    );
}

/// A fresh cluster's chain is exactly its genesis.
#[tokio::test]
async fn a_fresh_chain_holds_only_genesis() {
    let dir = TempDir::new().unwrap();
    let core = create(&dir, IfInitialized::Fail).await.unwrap();

    let chain = core.canonical_chain(None).unwrap();
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].0, core.root());
    assert_eq!(chain[0].0, core.head());
}

/// Ordering is oldest-first, which a one-envelope chain cannot tell apart
/// from newest-first.
#[tokio::test]
async fn the_chain_is_walked_back_to_the_root_and_returned_oldest_first() {
    let dir = TempDir::new().unwrap();
    let core = create(&dir, IfInitialized::Fail).await.unwrap();
    let (root, signing_key) = (
        core.root(),
        *core.signing_keys().values().next().expect("a founding key"),
    );
    drop(core);

    // Appended behind lotusd's back: nothing but `init` writes envelopes yet.
    let mut storage = SqliteStorage::open(dir.path().join(lotusd::SQLITE_DB_FILENAME)).unwrap();
    let mut chain = Chain::open(&mut storage, root).unwrap();

    let envelope = Envelope::new(Msg::SetNamespace(SetNamespace {
        prev: chain.head(),
        key: NamespaceKey::try_new("greeting").unwrap(),
        namespace: Namespace {
            value: Value::String("hello".to_string()),
        },
    }));
    let signature = Signature::Ed25519(Ed25519Signature::from_bytes(
        signing_key
            .sign(envelope.signature_digest().unwrap().as_bytes())
            .to_bytes(),
    ));
    let envelope = envelope.with_signature(
        PublicKey::Ed25519(Ed25519PublicKey::from_bytes(
            signing_key.verification_key().into(),
        ))
        .id(),
        signature,
    );

    let appended = envelope.digest().unwrap();
    assert_eq!(
        chain.insert(&mut storage, envelope).unwrap(),
        Insert::Extended
    );
    drop(storage);

    let core = Core::init_with_state_dir(dir.path().to_path_buf())
        .await
        .unwrap();

    let walked: Vec<_> = core
        .canonical_chain(None)
        .unwrap()
        .into_iter()
        .map(|(digest, _)| digest)
        .collect();
    assert_eq!(walked, vec![root, appended]);
    assert_eq!(core.head(), appended);
}
