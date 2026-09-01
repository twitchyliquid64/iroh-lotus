//! A running lotusd, as a Rust API.
//!
//! A [`Client`] names the daemon's control socket — [`Client::discover`]
//! finds it where `lotusd` keeps it by default — and opens one connection
//! per request, which is how the protocol works: there is nothing to hold
//! open, share, or reconnect. Every method of the protocol has a typed
//! method on the client; [`Client::call`] and [`Client::stream`] take any
//! [`rpc::Method`] for what those do not cover.
//!
//! ```no_run
//! use lotus_sdk::{Client, NamespaceKey, Value};
//!
//! # async fn example() -> Result<(), lotus_sdk::Error> {
//! let client = Client::discover()?;
//! let key = NamespaceKey::try_new("cfg").expect("not empty");
//!
//! let written = client.set(key.clone(), None, "hello").await?;
//! let at = client.read(key, None).await?;
//! assert_eq!(at.head, written.head);
//! assert_eq!(at.value, Some(Value::from("hello")));
//! # Ok(())
//! # }
//! ```
//!
//! A watch streams every movement of the chain its selector picks out
//! until the [`Streaming`] is dropped. Open it *before* reading the value
//! it guards: a change between the read and the watch then arrives as the
//! first event instead of going unseen. An event says what changed, not
//! what it became, so a watcher reads the value back at the event's head.
//!
//! ```no_run
//! use lotus_sdk::{Client, NamespaceKey, WatchEvent, WatchSelector};
//!
//! # async fn example() -> Result<(), lotus_sdk::Error> {
//! let client = Client::discover()?;
//! let key = NamespaceKey::try_new("cfg").expect("not empty");
//!
//! let mut watch = client.watch(WatchSelector::Namespace(key.clone())).await?;
//! let mut current = client.read(key.clone(), None).await?;
//! while let Some(WatchEvent::Changed(changed)) = watch.next().await? {
//!     if changed.head != current.head {
//!         current = client.read(key.clone(), None).await?;
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! [`Streaming`] also implements [`tokio_stream::Stream`], for `select!`
//! and the combinators.
//!
//! The request and response types are [`lotusd-rpc`](lotusd_rpc)'s, reached
//! here as [`rpc`], and the values a program builds are [`wire`]'s; the
//! ones every program touches are re-exported at the root, so most need no
//! other crate.

mod discover;
pub use discover::{SOCKET_NAME, STATE_DIR_ENV, socket_in, state_dir};

mod error;
pub use error::Error;

mod streaming;
pub use streaming::Streaming;

mod client;
pub use client::Client;

pub use lotusd_rpc as rpc;
pub use lotusd_rpc::{
    ChainRange, ChainWalk, Changed, Compacted, EnvelopeFrame, EnvelopeSelector, Failure,
    FailureKind, GetEnvelopes, InviteCode, NamespaceChange, NamespaceEntry, NamespaceList,
    NodeStatus, Queried, QueryKind, Shape, ValueAt, ValueMeta, WatchEvent, WatchSelector,
    WriteOutcome, Written,
};
pub use wire;
pub use wire::{
    Envelope, EnvelopeDigest, KeyId,
    msg::{Match, NamespaceKey, Predicate, Value},
    subkey::{PathParseError, Subkey, SubkeyPath},
};
