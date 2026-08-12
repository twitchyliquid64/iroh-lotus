//! Ledger state, advanced one envelope at a time.
//!
//! [`wire`] owns the encoding; this crate owns what an envelope *means*.
//! A [`Ledger`] is opened from the `Init` envelope that starts a chain and
//! moved forward by [`Ledger::apply`], the way a database replays its log.

mod error;
pub use error::{ApplyError, Error};

mod ledger;
pub use ledger::Ledger;
