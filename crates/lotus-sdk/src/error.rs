//! What can go wrong between a program and the daemon.

use std::{io, path::PathBuf};

use lotusd_rpc::{Failure, FailureKind};

/// An error reaching the daemon, or one it reported back.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No state directory could be determined, so there is no socket to
    /// look for.
    #[error(
        "no state directory found: set {} or name the socket",
        crate::STATE_DIR_ENV
    )]
    NoStateDir,
    /// The control socket could not be connected to.
    #[error("could not connect to the daemon at {}", path.display())]
    Connect {
        /// The socket that was tried.
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The daemon was reached, and the request went wrong from there —
    /// on the wire, or as a [`Failure`] it reported.
    #[error(transparent)]
    Rpc(#[from] lotusd_rpc::Error),
}

impl Error {
    /// The failure the daemon reported, when that is what this is: it
    /// understood the request and could not, or would not, serve it.
    pub fn failure(&self) -> Option<&Failure> {
        match self {
            Error::Rpc(lotusd_rpc::Error::Failed(failure)) => Some(failure),
            _ => None,
        }
    }

    /// Whether the chain refused what was asked. Asking again the same way
    /// gets the same answer; the request itself has to change.
    pub fn is_rejected(&self) -> bool {
        self.failure()
            .is_some_and(|failure| failure.kind == FailureKind::Rejected)
    }

    /// Whether no daemon is listening at the socket: there is no socket
    /// file (none ever ran there, or the state directory is another's) or
    /// nothing accepts on the one there is (a daemon left it behind).
    pub fn is_daemon_unreachable(&self) -> bool {
        matches!(
            self,
            Error::Connect { source, .. }
                if matches!(
                    source.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                )
        )
    }
}
