//! Ledger state, advanced one envelope at a time.
//!
//! [`wire`] owns the encoding; this crate owns what an envelope *means*.
//! A [`Ledger`] is opened from the `Init` envelope that starts a chain and
//! moved forward by [`Ledger::apply`], the way a database replays its log.
//! Where the state lives is [`storage`]'s business: a [`Ledger`] is a
//! cursor into a [`storage::Storage`], addressing state by head, so many
//! ledgers can share one store and an apply touches only what its
//! envelope addresses.
//!
//! A [`Chain`] sits above the cursor: it stores every envelope a node has
//! seen — competing forks included — into the store's log, and maintains
//! the ledger on the canonical path through them, where at every fork the
//! child with the lowest digest wins.

mod chain;
pub use chain::{Chain, Insert};

mod change;
pub use change::{Change, ChangeDiffer, ChangeSet, Movement};

mod error;
pub use error::{ApplyError, Error, TrustedKeysError, ValueError};

mod schema;
pub use schema::{
    Bounds, Schema, SchemaError, SchemaErrorKind, SchemaSetError, Violation, ViolationKind,
};

mod ledger;
pub use ledger::{
    CLUSTER_NODES_KEY, ClusterNode, DEFAULT_MIN_KEEP_MINUTES, Ledger, MIN_ENVELOPE_SIGNATURES_KEY,
    MIN_ENVELOPE_WEIGHT_KEY, MIN_KEEP_MINUTES_KEY, NODE_NAME_FIELD, SCHEMA_KEY, TRUSTED_KEYS_KEY,
};
