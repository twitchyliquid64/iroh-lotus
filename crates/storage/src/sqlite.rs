//! The rusqlite-backed [`Storage`].
//!
//! # Data model
//!
//! Versioned state lives in three layers, each a pointer into the next:
//!
//! - `versions` is an existence set: one row per snapshot, keyed by the
//!   digest of the envelope that produced it. It carries no data — it is
//!   what lets an empty version be told apart from one never stored.
//! - `version_namespaces` is a version's content: for each namespace key
//!   in the snapshot, a pointer to the root node of that namespace's
//!   value tree. The durable shape of [`MemStorage`]'s map of `Arc`s —
//!   a small pointer map, cheap to copy per commit.
//! - `nodes` plus `map_edges`/`array_edges` hold the [`Value`] trees
//!   decomposed, one row per node. A leaf row carries its value as
//!   canonical CBOR in `leaf`; map and array rows carry nothing, their
//!   entries living as `(parent, key|idx, child)` edge rows pointing at
//!   child nodes.
//!
//! Node ids are meaningless surrogates. A node is never owned by a
//! version and never updated in place: every write only inserts, and
//! ownership is exactly "reachable from a surviving root". Children are
//! inserted before the parents referencing them, so an edge always
//! points at an older row and the graph is acyclic by construction.
//!
//! # Sharing
//!
//! A commit path-copies. Take `n = {"a": {"b": "1"}, "list": ["x", "y"]}`
//! at head `D1`, then a commit setting `n.a.b = "2"` as `D2`: only the
//! nodes on the path root → `a` → `b` are cloned, and the clones point
//! at the existing rows for everything untouched.
//!
//! ```text
//! (D1, "n") → 1: map ─── a ──→ 2: map ── b ──→ 3: leaf "1"
//!                 └─── list ──→ 4: array ─ 0,1 ─→ 5,6: leaves "x","y"
//! (D2, "n") → 9: map ─── a ──→ 8: map ── b ──→ 7: leaf "2"
//!                 └─── list ──→ 4      ← shared with D1
//! ```
//!
//! Three new nodes for a two-segment path: a commit writes O(path) rows,
//! not O(state), however large the untouched siblings are. Forks work the
//! same way, two children path-copying off one parent's subtrees. And
//! because nodes are immutable, reads through an old head are snapshots
//! for free — `D1` can never observe `D2`'s write.
//!
//! Sharing is also why nothing refcounts: liveness is reachability, and
//! [`retain`](Storage::retain) computes it directly — drop the unkept
//! version rows, walk the edges from every surviving root, and sweep
//! whatever the walk never visited.
//!
//! Beside all this sits the envelope log, plain key-value: canonical
//! envelope bytes by digest, with the verification status (which is not
//! part of the encoding) and the parent digest stored as columns beside
//! them — the latter indexed so [`children`](Storage::children) is a
//! range scan in digest order.
//!
//! [`MemStorage`]: crate::MemStorage

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, params};
use wire::{
    Envelope, EnvelopeDigest, VerificationStatus,
    keys::KeyId,
    msg::{AmendOp, IncrementDecrement, Namespace, NamespaceKey, Value},
    subkey::Subkey,
};

use crate::{LogEntry, NamespaceOp, NodeKind, Resolution, Storage, StoredAt};

/// The errors the SQLite backend can produce.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    /// Stored bytes failed to encode or decode as canonical CBOR.
    #[error("codec failure on stored bytes")]
    Codec(#[from] wire::Error),
    /// The database contents violate the schema's invariants.
    #[error("corrupt store: {0}")]
    Corrupt(&'static str),
    /// The file was created by a schema this build doesn't speak.
    #[error("unsupported schema version {0}")]
    SchemaVersion(i64),
    /// The file is a SQLite database, but not one of ours.
    #[error("foreign database (application_id {0:#010x})")]
    ApplicationId(i64),
}

const SCHEMA_VERSION: i64 = 1;

/// "LOTS" in the SQLite header, so `file(1)` and [`SqliteStorage::open`]
/// can tell a ledger from any other SQLite database.
const APPLICATION_ID: i64 = u32::from_be_bytes(*b"LOTS") as i64;

/// Cap on the WAL file's size after a checkpoint; bulk churn (retain)
/// can balloon it well past this transiently.
const JOURNAL_SIZE_LIMIT: i64 = 32 * 1024 * 1024;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS envelopes (
    digest    BLOB PRIMARY KEY,
    bytes     BLOB NOT NULL,
    prev      BLOB,
    status    INTEGER NOT NULL,
    weight    INTEGER,
    -- The ids of the keys whose signatures did not verify, concatenated,
    -- for a failed status and nothing else.
    bad_keys  BLOB,
    -- Unix milliseconds off this node's clock, and nothing but a note to
    -- whoever is reading the log.
    stored_at INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS envelopes_by_prev ON envelopes (prev) WHERE prev IS NOT NULL;

CREATE TABLE IF NOT EXISTS nodes (
    id   INTEGER PRIMARY KEY,
    kind INTEGER NOT NULL,
    leaf BLOB
);
CREATE TABLE IF NOT EXISTS map_edges (
    parent INTEGER NOT NULL,
    key    TEXT    NOT NULL,
    child  INTEGER NOT NULL,
    PRIMARY KEY (parent, key)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS array_edges (
    parent INTEGER NOT NULL,
    idx    INTEGER NOT NULL,
    child  INTEGER NOT NULL,
    PRIMARY KEY (parent, idx)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS versions (
    head BLOB PRIMARY KEY
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS version_namespaces (
    head BLOB    NOT NULL,
    key  TEXT    NOT NULL,
    root INTEGER NOT NULL,
    PRIMARY KEY (head, key)
) WITHOUT ROWID;
";

/// A [`Storage`] persisted in a single SQLite database.
#[derive(Debug)]
pub struct SqliteStorage {
    conn: Connection,
}

impl SqliteStorage {
    /// Opens the store in the database at `path`, creating file and
    /// schema as needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::setup(Connection::open(path)?)
    }

    /// Opens a store in a fresh in-memory database. For tests.
    pub fn open_in_memory() -> Result<Self, Error> {
        Self::setup(Connection::open_in_memory()?)
    }

    fn setup(conn: Connection) -> Result<Self, Error> {
        let version = match conn.pragma_query_value(None, "user_version", |row| row.get(0))? {
            version @ (0 | SCHEMA_VERSION) => version,
            version => return Err(Error::SchemaVersion(version)),
        };
        match conn.pragma_query_value(None, "application_id", |row| row.get(0))? {
            // Unstamped: a fresh database, or one from before the id
            // existed. Refuse foreign files before writing anything.
            0 => {
                if version == 0 {
                    // The vacuum mode needs pointer-map pages woven
                    // through the file, so it must be chosen before
                    // anything — the WAL switch below included — writes
                    // the first page.
                    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
                }
                conn.pragma_update(None, "application_id", APPLICATION_ID)?;
            }
            APPLICATION_ID => {}
            id => return Err(Error::ApplicationId(id)),
        }

        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        // These two pragmas echo the value that took effect (journal_mode
        // is "memory" for in-memory stores), so read the echo rather than
        // assert it.
        let _mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        let _limit: i64 =
            conn.pragma_update_and_check(None, "journal_size_limit", JOURNAL_SIZE_LIMIT, |row| {
                row.get(0)
            })?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.set_prepared_statement_cache_capacity(32);

        if version == 0 {
            conn.execute_batch(SCHEMA)?;
            conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        Ok(Self { conn })
    }

    /// Every `(key, root)` of the version at `head`, in key order — the
    /// BINARY collation on `key` is memcmp over UTF-8, which matches
    /// `String`'s `Ord`.
    fn namespace_roots(&self, head: EnvelopeDigest) -> Result<Vec<(NamespaceKey, i64)>, Error> {
        let roots: Vec<(String, i64)> = self
            .conn
            .prepare_cached(
                "SELECT key, root FROM version_namespaces WHERE head = ?1 ORDER BY key",
            )?
            .query_map([head.as_slice()], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        if roots.is_empty() {
            assert!(
                version_exists(&self.conn, head)?,
                "head is pre-validated: the version exists"
            );
        }
        roots
            .into_iter()
            .map(|(key, root)| Ok((key_from(key)?, root)))
            .collect()
    }
}

// Stored discriminants for `nodes.kind`.
const LEAF: i64 = 0;
const MAP: i64 = 1;
const ARRAY: i64 = 2;

fn kind_from(code: i64) -> Result<NodeKind, Error> {
    match code {
        LEAF => Ok(NodeKind::Leaf),
        MAP => Ok(NodeKind::Map),
        ARRAY => Ok(NodeKind::Array),
        _ => Err(Error::Corrupt("unknown node kind")),
    }
}

// Stored discriminants for `envelopes.status`.
const UNCHECKED: i64 = 0;
const FAILED: i64 = 1;
const ALL_MATCHED: i64 = 2;

fn status_columns(status: &VerificationStatus) -> (i64, Option<i64>, Option<Vec<u8>>) {
    match status {
        VerificationStatus::Unchecked => (UNCHECKED, None, None),
        VerificationStatus::Failed { failing_key_ids } => (
            FAILED,
            None,
            Some(
                failing_key_ids
                    .iter()
                    .flat_map(|id| *id.as_bytes())
                    .collect(),
            ),
        ),
        VerificationStatus::AllMatched { total_weight } => {
            (ALL_MATCHED, Some(i64::from(*total_weight)), None)
        }
    }
}

fn status_from(
    code: i64,
    weight: Option<i64>,
    bad_keys: Option<Vec<u8>>,
) -> Result<VerificationStatus, Error> {
    match code {
        UNCHECKED => Ok(VerificationStatus::Unchecked),
        FAILED => Ok(VerificationStatus::Failed {
            failing_key_ids: key_ids_from(
                &bad_keys.ok_or(Error::Corrupt("failed status without its keys"))?,
            )?,
        }),
        ALL_MATCHED => Ok(VerificationStatus::AllMatched {
            total_weight: weight
                .ok_or(Error::Corrupt("all-matched status without a weight"))?
                .try_into()
                .map_err(|_| Error::Corrupt("verification weight out of range"))?,
        }),
        _ => Err(Error::Corrupt("unknown verification status")),
    }
}

/// The key ids [`status_columns`] concatenated, one 32-byte id after
/// another.
fn key_ids_from(blob: &[u8]) -> Result<BTreeSet<KeyId>, Error> {
    let (ids, rest) = blob.as_chunks::<32>();
    match rest.is_empty() {
        true => Ok(ids.iter().copied().map(KeyId::from_bytes).collect()),
        false => Err(Error::Corrupt("failing key ids are not whole ids")),
    }
}

fn digest_from(blob: Vec<u8>) -> Result<EnvelopeDigest, Error> {
    blob.try_into()
        .map(EnvelopeDigest::from_bytes)
        .map_err(|_| Error::Corrupt("stored digest is not 32 bytes"))
}

fn key_from(key: String) -> Result<NamespaceKey, Error> {
    NamespaceKey::try_new(key).map_err(|_| Error::Corrupt("stored namespace key is empty"))
}

fn version_exists(conn: &Connection, head: EnvelopeDigest) -> Result<bool, Error> {
    Ok(conn
        .prepare_cached("SELECT EXISTS (SELECT 1 FROM versions WHERE head = ?1)")?
        .query_row([head.as_slice()], |row| row.get(0))?)
}

/// The root node of the namespace at `key` in the version at `head` —
/// `None` when that version holds no such namespace.
///
/// # Panics
///
/// When the version itself is absent: addressing an unknown head is a
/// broken invariant per the [`Storage`] contract.
fn namespace_root(
    conn: &Connection,
    head: EnvelopeDigest,
    key: &NamespaceKey,
) -> Result<Option<i64>, Error> {
    let root = conn
        .prepare_cached("SELECT root FROM version_namespaces WHERE head = ?1 AND key = ?2")?
        .query_row(params![head.as_slice(), key.as_ref()], |row| row.get(0))
        .optional()?;
    if root.is_none() {
        assert!(
            version_exists(conn, head)?,
            "head is pre-validated: the version exists"
        );
    }
    Ok(root)
}

/// Registers `head` as a version, clearing whatever an earlier install or
/// commit under the same head left behind.
fn replace_version(conn: &Connection, head: EnvelopeDigest) -> Result<(), Error> {
    conn.prepare_cached("INSERT OR REPLACE INTO versions (head) VALUES (?1)")?
        .execute([head.as_slice()])?;
    conn.prepare_cached("DELETE FROM version_namespaces WHERE head = ?1")?
        .execute([head.as_slice()])?;
    Ok(())
}

fn set_root(
    conn: &Connection,
    head: EnvelopeDigest,
    key: &NamespaceKey,
    root: i64,
) -> Result<(), Error> {
    conn.prepare_cached(
        "INSERT OR REPLACE INTO version_namespaces (head, key, root) VALUES (?1, ?2, ?3)",
    )?
    .execute(params![head.as_slice(), key.as_ref(), root])?;
    Ok(())
}

fn insert_node(conn: &Connection, kind: i64, leaf: Option<&[u8]>) -> Result<i64, Error> {
    conn.prepare_cached("INSERT INTO nodes (kind, leaf) VALUES (?1, ?2)")?
        .execute(params![kind, leaf])?;
    Ok(conn.last_insert_rowid())
}

fn node(conn: &Connection, id: i64) -> Result<(NodeKind, Option<Vec<u8>>), Error> {
    let (code, leaf) = conn
        .prepare_cached("SELECT kind, leaf FROM nodes WHERE id = ?1")?
        .query_row([id], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?
        .ok_or(Error::Corrupt("edge references a missing node"))?;
    Ok((kind_from(code)?, leaf))
}

fn node_kind(conn: &Connection, id: i64) -> Result<NodeKind, Error> {
    node(conn, id).map(|(kind, _)| kind)
}

fn map_child(conn: &Connection, parent: i64, key: &str) -> Result<Option<i64>, Error> {
    Ok(conn
        .prepare_cached("SELECT child FROM map_edges WHERE parent = ?1 AND key = ?2")?
        .query_row(params![parent, key], |row| row.get(0))
        .optional()?)
}

fn array_child(conn: &Connection, parent: i64, idx: u32) -> Result<Option<i64>, Error> {
    Ok(conn
        .prepare_cached("SELECT child FROM array_edges WHERE parent = ?1 AND idx = ?2")?
        .query_row(params![parent, i64::from(idx)], |row| row.get(0))
        .optional()?)
}

fn insert_map_edge(conn: &Connection, parent: i64, key: &str, child: i64) -> Result<(), Error> {
    conn.prepare_cached("INSERT INTO map_edges (parent, key, child) VALUES (?1, ?2, ?3)")?
        .execute(params![parent, key, child])?;
    Ok(())
}

fn insert_array_edge(conn: &Connection, parent: i64, idx: i64, child: i64) -> Result<(), Error> {
    conn.prepare_cached("INSERT INTO array_edges (parent, idx, child) VALUES (?1, ?2, ?3)")?
        .execute(params![parent, idx, child])?;
    Ok(())
}

/// Stores `value` as a fresh node tree, yielding its root id.
fn insert_value(conn: &Connection, value: &Value) -> Result<i64, Error> {
    match value {
        Value::Map(map) => {
            let id = insert_node(conn, MAP, None)?;
            map.iter().try_for_each(|(key, child)| {
                insert_value(conn, child).and_then(|child| insert_map_edge(conn, id, key, child))
            })?;
            Ok(id)
        }
        Value::Array(items) => {
            let id = insert_node(conn, ARRAY, None)?;
            items.iter().enumerate().try_for_each(|(idx, item)| {
                let idx = i64::try_from(idx).expect("array lengths fit an i64");
                insert_value(conn, item).and_then(|child| insert_array_edge(conn, id, idx, child))
            })?;
            Ok(id)
        }
        leaf => {
            let bytes = wire::encode(leaf)?;
            insert_node(conn, LEAF, Some(&bytes))
        }
    }
}

/// Materializes the subtree rooted at `id`.
fn value_of(conn: &Connection, id: i64) -> Result<Value, Error> {
    match node(conn, id)? {
        (NodeKind::Leaf, leaf) => Ok(wire::decode(
            &leaf.ok_or(Error::Corrupt("leaf node without a payload"))?,
        )?),
        (NodeKind::Map, _) => {
            let edges: Vec<(String, i64)> = conn
                .prepare_cached("SELECT key, child FROM map_edges WHERE parent = ?1")?
                .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<Result<_, _>>()?;
            edges
                .into_iter()
                .map(|(key, child)| Ok((key, value_of(conn, child)?)))
                .collect::<Result<BTreeMap<_, _>, Error>>()
                .map(Value::Map)
        }
        (NodeKind::Array, _) => {
            let children: Vec<i64> = conn
                .prepare_cached("SELECT child FROM array_edges WHERE parent = ?1 ORDER BY idx")?
                .query_map([id], |row| row.get(0))?
                .collect::<Result<_, _>>()?;
            children
                .into_iter()
                .map(|child| value_of(conn, child))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array)
        }
    }
}

/// A new map node with `old`'s edges, minus the one at `except`.
fn new_map_without(conn: &Connection, old: i64, except: &str) -> Result<i64, Error> {
    let id = insert_node(conn, MAP, None)?;
    conn.prepare_cached(
        "INSERT INTO map_edges (parent, key, child)
         SELECT ?1, key, child FROM map_edges WHERE parent = ?2 AND key <> ?3",
    )?
    .execute(params![id, old, except])?;
    Ok(id)
}

/// A new array node with `old`'s edges, the one at `idx` replaced by `child`.
fn new_array_replacing(conn: &Connection, old: i64, idx: u32, child: i64) -> Result<i64, Error> {
    let id = insert_node(conn, ARRAY, None)?;
    conn.prepare_cached(
        "INSERT INTO array_edges (parent, idx, child)
         SELECT ?1, idx, child FROM array_edges WHERE parent = ?2 AND idx <> ?3",
    )?
    .execute(params![id, old, i64::from(idx)])?;
    insert_array_edge(conn, id, i64::from(idx), child)?;
    Ok(id)
}

/// A new array node with `old`'s edges minus the one at `idx`, later
/// indices shifted down.
fn new_array_removing(conn: &Connection, old: i64, idx: u32) -> Result<i64, Error> {
    let id = insert_node(conn, ARRAY, None)?;
    conn.prepare_cached(
        "INSERT INTO array_edges (parent, idx, child)
         SELECT ?1, CASE WHEN idx > ?3 THEN idx - 1 ELSE idx END, child
         FROM array_edges WHERE parent = ?2 AND idx <> ?3",
    )?
    .execute(params![id, old, i64::from(idx)])?;
    Ok(id)
}

/// A new array node with `old`'s edges plus `child` appended.
fn new_array_appending(conn: &Connection, old: i64, child: i64) -> Result<i64, Error> {
    match node_kind(conn, old)? {
        NodeKind::Array => {}
        _ => unreachable!("AmendAt is pre-validated: the append target is an array"),
    }
    let len: i64 = conn
        .prepare_cached("SELECT COUNT(*) FROM array_edges WHERE parent = ?1")?
        .query_row([old], |row| row.get(0))?;
    let id = insert_node(conn, ARRAY, None)?;
    conn.prepare_cached(
        "INSERT INTO array_edges (parent, idx, child)
         SELECT ?1, idx, child FROM array_edges WHERE parent = ?2",
    )?
    .execute(params![id, old])?;
    insert_array_edge(conn, id, len, child)?;
    Ok(id)
}

/// A new leaf holding `old`'s integer with `inc` applied.
fn increment_leaf(conn: &Connection, old: i64, inc: &IncrementDecrement) -> Result<i64, Error> {
    let leaf = match node(conn, old)? {
        (NodeKind::Leaf, leaf) => leaf.ok_or(Error::Corrupt("leaf node without a payload"))?,
        _ => unreachable!("AmendAt is pre-validated: the target is an integer"),
    };
    let n = match wire::decode(&leaf)? {
        Value::Int(n) => n,
        _ => unreachable!("AmendAt is pre-validated: the target is an integer"),
    };
    let sum = inc
        .apply(n)
        .expect("AmendAt is pre-validated: the sum fits an i64 or clamps");
    let bytes = wire::encode(&Value::Int(sum))?;
    insert_node(conn, LEAF, Some(&bytes))
}

/// Path-copies `node` along `path`: every node on the path is cloned, the
/// clone pointing at the original's children except where the path
/// continues, and `terminal` decides what the last segment addresses —
/// handed the existing child (if any), it yields the replacement, or
/// `None` to remove it (later array indices shift down).
fn replace_child<F>(
    conn: &Connection,
    node: i64,
    path: &[Subkey],
    terminal: F,
) -> Result<i64, Error>
where
    F: FnOnce(&Connection, Option<i64>) -> Result<Option<i64>, Error>,
{
    let (segment, rest) = path
        .split_first()
        .expect("SubkeyPath is validated non-empty");
    match (node_kind(conn, node)?, segment) {
        (NodeKind::Map, Subkey::Key(key)) => {
            let child = map_child(conn, node, key)?;
            let replacement = match (rest, child) {
                ([], child) => terminal(conn, child)?,
                (rest, Some(child)) => Some(replace_child(conn, child, rest, terminal)?),
                (_, None) => unreachable!("op is pre-validated: every parent exists"),
            };
            let id = new_map_without(conn, node, key)?;
            if let Some(child) = replacement {
                insert_map_edge(conn, id, key, child)?;
            }
            Ok(id)
        }
        (NodeKind::Array, Subkey::Index(idx)) => {
            let child = array_child(conn, node, *idx)?
                .expect("op is pre-validated: the index is in bounds");
            if rest.is_empty() {
                match terminal(conn, Some(child))? {
                    Some(child) => new_array_replacing(conn, node, *idx, child),
                    None => new_array_removing(conn, node, *idx),
                }
            } else {
                let child = replace_child(conn, child, rest, terminal)?;
                new_array_replacing(conn, node, *idx, child)
            }
        }
        _ => unreachable!("op is pre-validated: the parent's shape matches the segment"),
    }
}

/// Applies `op` to the value rooted at `node`, yielding the new root id.
fn amend_node(conn: &Connection, node: i64, op: AmendOp) -> Result<i64, Error> {
    match op {
        AmendOp::AppendEntry(entry) => {
            let entry = insert_value(conn, &entry)?;
            new_array_appending(conn, node, entry)
        }
        AmendOp::IncrementDecrement(inc) => increment_leaf(conn, node, &inc),
    }
}

impl Storage for SqliteStorage {
    type Error = Error;

    fn contains_version(&self, head: EnvelopeDigest) -> Result<bool, Error> {
        version_exists(&self.conn, head)
    }

    fn resolve(
        &self,
        head: EnvelopeDigest,
        key: &NamespaceKey,
        path: &[Subkey],
    ) -> Result<Option<Resolution>, Error> {
        let Some(root) = namespace_root(&self.conn, head, key)? else {
            return Ok(None);
        };
        let mut current = root;
        for (depth, segment) in path.iter().enumerate() {
            let kind = node_kind(&self.conn, current)?;
            let child = match (kind, segment) {
                (NodeKind::Map, Subkey::Key(key)) => map_child(&self.conn, current, key)?,
                (NodeKind::Array, Subkey::Index(idx)) => array_child(&self.conn, current, *idx)?,
                _ => return Ok(Some(Resolution::Mismatch { depth })),
            };
            match child {
                Some(child) => current = child,
                None => return Ok(Some(Resolution::Missing { depth, at: kind })),
            }
        }
        node_kind(&self.conn, current).map(|kind| Some(Resolution::Node(kind)))
    }

    fn value_at(
        &self,
        head: EnvelopeDigest,
        key: &NamespaceKey,
        path: &[Subkey],
    ) -> Result<Option<Value>, Error> {
        let Some(root) = namespace_root(&self.conn, head, key)? else {
            return Ok(None);
        };
        let target = path.iter().try_fold(Some(root), |node, segment| {
            let Some(node) = node else { return Ok(None) };
            match (node_kind(&self.conn, node)?, segment) {
                (NodeKind::Map, Subkey::Key(key)) => map_child(&self.conn, node, key),
                (NodeKind::Array, Subkey::Index(idx)) => array_child(&self.conn, node, *idx),
                _ => Ok(None),
            }
        })?;
        target.map(|id| value_of(&self.conn, id)).transpose()
    }

    fn namespace(
        &self,
        head: EnvelopeDigest,
        key: &NamespaceKey,
    ) -> Result<Option<Namespace>, Error> {
        namespace_root(&self.conn, head, key)?
            .map(|root| value_of(&self.conn, root).map(|value| Namespace { value }))
            .transpose()
    }

    fn namespaces(
        &self,
        head: EnvelopeDigest,
    ) -> impl Iterator<Item = Result<(NamespaceKey, Namespace), Error>> {
        // The key list is eager (it's tiny); each namespace materializes
        // lazily as the iterator is driven.
        let (roots, err) = match self.namespace_roots(head) {
            Ok(roots) => (roots, None),
            Err(err) => (Vec::new(), Some(Err(err))),
        };
        err.into_iter().chain(
            roots.into_iter().map(|(key, root)| {
                value_of(&self.conn, root).map(|value| (key, Namespace { value }))
            }),
        )
    }

    fn commit(
        &mut self,
        parent: EnvelopeDigest,
        head: EnvelopeDigest,
        op: NamespaceOp,
    ) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        assert!(
            version_exists(&tx, parent)?,
            "head is pre-validated: the version exists"
        );
        replace_version(&tx, head)?;
        tx.prepare_cached(
            "INSERT INTO version_namespaces (head, key, root)
             SELECT ?1, key, root FROM version_namespaces WHERE head = ?2",
        )?
        .execute(params![head.as_slice(), parent.as_slice()])?;

        match op {
            NamespaceOp::Put(key, namespace) => {
                let root = insert_value(&tx, &namespace.value)?;
                set_root(&tx, head, &key, root)?;
            }
            NamespaceOp::Delete(key) => {
                let deleted = tx
                    .prepare_cached("DELETE FROM version_namespaces WHERE head = ?1 AND key = ?2")?
                    .execute(params![head.as_slice(), key.as_ref()])?;
                assert_eq!(deleted, 1, "Delete is pre-validated: the namespace exists");
            }
            NamespaceOp::SetAt { key, path, value } => {
                let root = namespace_root(&tx, head, &key)?
                    .expect("SetAt is pre-validated: the namespace exists");
                let root = replace_child(&tx, root, path.as_ref(), |conn, old| match value {
                    Some(value) => insert_value(conn, &value).map(Some),
                    None => {
                        assert!(
                            old.is_some(),
                            "SetAt is pre-validated: the value being cleared exists"
                        );
                        Ok(None)
                    }
                })?;
                set_root(&tx, head, &key, root)?;
            }
            NamespaceOp::AmendAt { key, path, op } => {
                let root = namespace_root(&tx, head, &key)?
                    .expect("AmendAt is pre-validated: the namespace exists");
                let root = match path {
                    None => amend_node(&tx, root, op)?,
                    Some(path) => replace_child(&tx, root, path.as_ref(), |conn, old| match op {
                        AmendOp::AppendEntry(entry) => {
                            let entry = insert_value(conn, &entry)?;
                            match old {
                                Some(target) => new_array_appending(conn, target, entry).map(Some),
                                // A missing terminal is a fresh one-entry
                                // array under a map, pre-validated.
                                None => {
                                    let array = insert_node(conn, ARRAY, None)?;
                                    insert_array_edge(conn, array, 0, entry)?;
                                    Ok(Some(array))
                                }
                            }
                        }
                        AmendOp::IncrementDecrement(inc) => {
                            let target = old.expect("AmendAt is pre-validated: the target exists");
                            increment_leaf(conn, target, &inc).map(Some)
                        }
                    })?,
                };
                set_root(&tx, head, &key, root)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn install(
        &mut self,
        head: EnvelopeDigest,
        namespaces: impl IntoIterator<Item = (NamespaceKey, Namespace)>,
    ) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        replace_version(&tx, head)?;
        namespaces.into_iter().try_for_each(|(key, namespace)| {
            insert_value(&tx, &namespace.value).and_then(|root| set_root(&tx, head, &key, root))
        })?;
        tx.commit()?;
        Ok(())
    }

    fn retain(&mut self, keep: &[EnvelopeDigest]) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        tx.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS keep (head BLOB PRIMARY KEY);
             DELETE FROM keep;",
        )?;
        keep.iter().try_for_each(|head| -> Result<(), Error> {
            tx.prepare_cached("INSERT OR IGNORE INTO keep (head) VALUES (?1)")?
                .execute([head.as_slice()])?;
            Ok(())
        })?;
        // Drop unkept versions, then mark-and-sweep: any node a surviving
        // root still reaches was shared and must stay.
        tx.execute_batch(
            "DELETE FROM versions WHERE head NOT IN (SELECT head FROM keep);
             DELETE FROM version_namespaces WHERE head NOT IN (SELECT head FROM keep);

             CREATE TEMP TABLE IF NOT EXISTS reachable (id INTEGER PRIMARY KEY);
             DELETE FROM reachable;
             WITH RECURSIVE walk (id) AS (
                 SELECT root FROM version_namespaces
                 UNION
                 SELECT child FROM map_edges JOIN walk ON map_edges.parent = walk.id
                 UNION
                 SELECT child FROM array_edges JOIN walk ON array_edges.parent = walk.id
             )
             INSERT INTO reachable SELECT id FROM walk;

             DELETE FROM map_edges WHERE parent NOT IN (SELECT id FROM reachable);
             DELETE FROM array_edges WHERE parent NOT IN (SELECT id FROM reachable);
             DELETE FROM nodes WHERE id NOT IN (SELECT id FROM reachable);",
        )?;
        tx.commit()?;
        // Retain is the one place bulk garbage appears, so release the
        // freed pages right here rather than taxing every commit
        // (auto_vacuum = INCREMENTAL; ordinary writes never vacuum).
        // Each step frees one page, so the statement must be drained,
        // not just executed.
        let mut vacuum = self.conn.prepare("PRAGMA incremental_vacuum")?;
        let mut pages = vacuum.query([])?;
        while pages.next()?.is_some() {}
        // Refresh planner statistics occasionally; retain is the only
        // moment table shapes change in bulk, and every retain would
        // overpay for what point lookups barely use.
        if rand::random_ratio(1, 10) {
            self.conn.execute_batch("PRAGMA optimize;")?;
        }
        Ok(())
    }

    fn put_envelope(&mut self, digest: EnvelopeDigest, envelope: Envelope) -> Result<(), Error> {
        let bytes = wire::encode(&envelope)?;
        let prev = envelope
            .payload()
            .prev_digest()
            .map(EnvelopeDigest::as_slice);
        let (status, weight, bad_keys) = status_columns(envelope.verification_status());
        // An upsert rather than INSERT OR REPLACE: the row being replaced
        // holds the time this node first saw the envelope, and a status
        // upgraded an hour later must not restamp it.
        self.conn
            .prepare_cached(
                "INSERT INTO envelopes (digest, bytes, prev, status, weight, bad_keys, stored_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT (digest) DO UPDATE SET
                     bytes = excluded.bytes,
                     prev = excluded.prev,
                     status = excluded.status,
                     weight = excluded.weight,
                     bad_keys = excluded.bad_keys",
            )?
            .execute(params![
                digest.as_slice(),
                bytes,
                prev,
                status,
                weight,
                bad_keys,
                StoredAt::now().timestamp_millis(),
            ])?;
        Ok(())
    }

    fn logged_envelope(&self, digest: EnvelopeDigest) -> Result<Option<LogEntry>, Error> {
        self.conn
            .prepare_cached(
                "SELECT bytes, status, weight, bad_keys, stored_at FROM envelopes WHERE digest = ?1",
            )?
            .query_row([digest.as_slice()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .optional()?
            .map(|(bytes, status, weight, bad_keys, stored_at)| {
                let mut envelope: Envelope = wire::decode(&bytes)?;
                envelope.set_verification_status(status_from(status, weight, bad_keys)?);
                Ok(LogEntry {
                    envelope,
                    stored_at: StoredAt::from_timestamp_millis(stored_at)
                        .ok_or(Error::Corrupt("stored-at is not a time"))?,
                })
            })
            .transpose()
    }

    fn remove_envelope(&mut self, digest: EnvelopeDigest) -> Result<(), Error> {
        self.conn
            .prepare_cached("DELETE FROM envelopes WHERE digest = ?1")?
            .execute([digest.as_slice()])?;
        Ok(())
    }

    fn children(
        &self,
        parent: EnvelopeDigest,
    ) -> impl Iterator<Item = Result<EnvelopeDigest, Error>> {
        // BINARY collation on the digest BLOB is memcmp — exactly the
        // big-endian `Ord` the fork rule reads.
        let digests = self
            .conn
            .prepare_cached("SELECT digest FROM envelopes WHERE prev = ?1 ORDER BY digest")
            .map_err(Error::from)
            .and_then(|mut stmt| {
                stmt.query_map([parent.as_slice()], |row| row.get::<_, Vec<u8>>(0))?
                    .map(|blob| digest_from(blob?))
                    .collect::<Result<Vec<_>, Error>>()
            });
        let (digests, err) = match digests {
            Ok(digests) => (digests, None),
            Err(err) => (Vec::new(), Some(Err(err))),
        };
        err.into_iter().chain(digests.into_iter().map(Ok))
    }

    fn parent(&self, digest: EnvelopeDigest) -> Result<Option<EnvelopeDigest>, Error> {
        // The column read the default's decode-the-envelope would waste:
        // chain walks call this once per hop.
        self.conn
            .prepare_cached("SELECT prev FROM envelopes WHERE digest = ?1")?
            .query_row([digest.as_slice()], |row| row.get::<_, Option<Vec<u8>>>(0))
            .optional()?
            .flatten()
            .map(digest_from)
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use wire::{
        Envelope, EnvelopeDigest, Msg, VerificationStatus,
        msg::{Namespace, NamespaceKey, SetNamespace, Value},
        subkey::{Subkey, SubkeyPath},
    };

    use super::SqliteStorage;
    use crate::{NamespaceOp, Storage};

    crate::storage_conformance!(SqliteStorage::open_in_memory().unwrap());

    fn digest(byte: u8) -> EnvelopeDigest {
        EnvelopeDigest::from_bytes([byte; 32])
    }

    fn key(k: &str) -> NamespaceKey {
        NamespaceKey::try_new(k).unwrap()
    }

    fn nested() -> Namespace {
        Namespace {
            value: Value::Map(
                [
                    (
                        "a".to_string(),
                        Value::Map([("b".to_string(), Value::String("1".into()))].into()),
                    ),
                    (
                        "list".to_string(),
                        Value::Array(vec![Value::String("x".into())]),
                    ),
                ]
                .into(),
            ),
        }
    }

    /// The one thing in-memory conformance can't prove: versions, the
    /// envelope log, and the out-of-band verification status all survive
    /// dropping the store and reopening the file.
    #[test]
    fn a_reopened_file_reads_everything_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite3");

        let mut envelope = Envelope::new(Msg::SetNamespace(SetNamespace {
            prev: digest(1),
            key: key("n"),
            namespace: nested(),
        }));
        envelope.set_verification_status(VerificationStatus::AllMatched { total_weight: 7 });
        let envelope_digest = envelope.digest().unwrap();

        {
            let mut store = SqliteStorage::open(&path).unwrap();
            store.install(digest(1), [(key("n"), nested())]).unwrap();
            store
                .put_envelope(envelope_digest, envelope.clone())
                .unwrap();
        }

        let store = SqliteStorage::open(&path).unwrap();
        assert!(store.contains_version(digest(1)).unwrap());
        assert_eq!(
            store.namespace(digest(1), &key("n")).unwrap(),
            Some(nested())
        );
        assert_eq!(store.envelope(envelope_digest).unwrap(), Some(envelope));
        assert_eq!(
            store
                .children(digest(1))
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![envelope_digest]
        );
    }

    /// The conformance suite proves survivors survive `retain`; this
    /// proves the garbage actually goes.
    #[test]
    fn retain_sweeps_unreachable_nodes() {
        let mut store = SqliteStorage::open_in_memory().unwrap();
        store.install(digest(1), [(key("n"), nested())]).unwrap();
        store
            .commit(
                digest(1),
                digest(2),
                NamespaceOp::SetAt {
                    key: key("n"),
                    path: SubkeyPath::try_new(vec![
                        Subkey::Key("a".into()),
                        Subkey::Key("b".into()),
                    ])
                    .unwrap(),
                    value: Some(Value::String("2".into())),
                },
            )
            .unwrap();

        let nodes = |store: &SqliteStorage| -> i64 {
            store
                .conn
                .query_row("SELECT COUNT(*) FROM nodes", [], |row| row.get(0))
                .unwrap()
        };

        let both_versions = nodes(&store);
        store.retain(&[digest(2)]).unwrap();
        let survivor = nodes(&store);
        assert!(survivor < both_versions, "the version-1-only path is swept");
        assert!(survivor > 0, "the kept version's nodes stay");

        store.retain(&[]).unwrap();
        assert_eq!(nodes(&store), 0, "no versions, no nodes");
        let edges: i64 = store
            .conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM map_edges) + (SELECT COUNT(*) FROM array_edges)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(edges, 0, "no nodes, no edges");
    }

    /// Retain ends with an incremental vacuum, so the pages the sweep
    /// frees go back to the file rather than accumulating on the
    /// freelist.
    #[test]
    fn retain_releases_freed_pages() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteStorage::open(dir.path().join("ledger.sqlite3")).unwrap();

        let mode: i64 = store
            .conn
            .pragma_query_value(None, "auto_vacuum", |row| row.get(0))
            .unwrap();
        assert_eq!(
            mode, 2,
            "a fresh file is created with auto_vacuum = INCREMENTAL"
        );

        // Enough nodes to spill past the first page, so the sweep frees
        // whole pages rather than just slots.
        let big = Namespace {
            value: Value::Array((0..2_000).map(Value::Int).collect()),
        };
        store.install(digest(1), [(key("n"), big)]).unwrap();
        store.retain(&[]).unwrap();

        let freelist: i64 = store
            .conn
            .pragma_query_value(None, "freelist_count", |row| row.get(0))
            .unwrap();
        assert_eq!(freelist, 0, "retain vacuums what it frees");
    }

    #[test]
    fn a_file_is_stamped_and_tuned_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStorage::open(dir.path().join("ledger.sqlite3")).unwrap();

        let pragma = |name| -> i64 {
            store
                .conn
                .pragma_query_value(None, name, |row| row.get(0))
                .unwrap()
        };
        assert_eq!(pragma("application_id"), super::APPLICATION_ID);
        assert_eq!(pragma("busy_timeout"), 5_000);
        assert_eq!(pragma("temp_store"), 2, "2 is MEMORY");
        assert_eq!(pragma("journal_size_limit"), super::JOURNAL_SIZE_LIMIT);
    }

    /// A database some other application stamped is refused before
    /// anything writes to it.
    #[test]
    fn a_foreign_database_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foreign.sqlite3");
        rusqlite::Connection::open(&path)
            .unwrap()
            .pragma_update(None, "application_id", 0x1234_5678)
            .unwrap();

        assert!(matches!(
            SqliteStorage::open(&path),
            Err(super::Error::ApplicationId(0x1234_5678))
        ));
    }
}
