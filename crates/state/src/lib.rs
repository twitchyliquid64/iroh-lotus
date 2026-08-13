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
//! A [`Chain`] sits above the cursor: it files every envelope a node has
//! seen — competing forks included — into the store's log, and maintains
//! the ledger on the canonical path through them, where at every fork the
//! child with the lowest digest wins.

mod chain;
pub use chain::{Chain, Insert};

mod error;
pub use error::{ApplyError, Error};

mod ledger;
pub use ledger::Ledger;
