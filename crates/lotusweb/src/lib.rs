//! A web view onto a running lotusd: browse and edit what the ledger holds.
//!
//! One page, a sidebar of namespaces beside a main pane, walked like a file
//! browser: a namespace opens at its root, every map key and array index is
//! a link one level down, and breadcrumbs lead back up. Leaves are edited as
//! JSON in place; containers take new entries, can be replaced whole, and
//! can be deleted.
//!
//! The pages are plain HTML over [htmx](https://htmx.org) 4: every link and
//! form fetches the main pane alone and swaps it in, the sidebar riding
//! along out of band so the namespace list and head never go stale. The
//! same URLs answer a plain navigation with a whole document — which is
//! also what htmx asks for when it restores history — so every link is a
//! real one, fit to copy or open in a new tab; the forms need htmx, HTML
//! alone having no `PUT` or `DELETE`.
//!
//! A ledger location is spelled in the URL as `lotusctl` spells it on the
//! command line, `/ns/<namespace>/<path>` with the path written
//! `servers[0].host`, so a path copied from one reads in the other.
//!
//! Every read and write goes through [`lotus_sdk`]; [`router`] is the whole
//! server, over a [`Client`](lotus_sdk::Client).

mod app;
pub use app::router;

mod error;
pub use error::Error;

mod frame;
mod json;

mod location;
pub use location::Location;

mod view;
