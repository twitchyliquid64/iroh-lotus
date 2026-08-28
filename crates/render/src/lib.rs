//! How an envelope is shown to a person.
//!
//! One rendering, shared by everything that prints envelopes: the daemon
//! inspecting what it holds on disk and the CLI printing what it fetched
//! over the control socket must not disagree about what an envelope looks
//! like.
//!
//! A [`Render`] is built up with whatever context the caller has — which
//! digests to mark, where the envelopes came from, whether to colour them —
//! and then writes stanzas into any [`fmt::Write`](core::fmt::Write).

mod envelope;
pub use envelope::Render;

mod style;
pub use style::{ColorChoice, Palette};
