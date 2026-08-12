//! Ledger state, advanced one envelope at a time.
//!
//! [`wire`] owns the encoding; this crate owns what an envelope *means*.
//! A [`Ledger`] is opened from the `Init` envelope that starts a chain and
//! moved forward by [`Ledger::apply`], the way a database replays its log.
//! Where the state lives is [`storage`]'s business: a [`Ledger`] is a
//! cursor into a [`storage::Storage`], addressing state by head, so many
//! ledgers can share one store and an apply touches only what its
//! envelope addresses.

mod error;
pub use error::{ApplyError, Error};

mod ledger;
pub use ledger::Ledger;
