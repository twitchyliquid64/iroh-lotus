//! The filer client as a command: `lotusfs`.
//!
//! [`cli`] is the command itself. [`fuse`] is a volume as the kernel's
//! FUSE requests see it; it builds wherever FUSE is spoken, mounts only
//! on Linux, and is tested without mounting anywhere.

pub mod cli;
pub mod fuse;
