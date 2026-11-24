//! A filer, from the side that mounts it.
//!
//! A client needs three things and no ledger: a key of its own, which is
//! all a filer knows it by ([`key`]); a [`Ticket`] saying which filer and
//! which volume; and a [`Session`], which keeps a connection to that filer
//! and carries operations over it.

pub mod key;

mod session;
pub use session::{Error, Session};

mod ticket;
pub use ticket::{Ticket, TicketError};

pub use filer_proto as proto;
