//! What a request can fail with, and the status each failure answers with.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::view;

/// Why a request could not be served.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The URL names no ledger location: a malformed namespace or path.
    #[error("{0}")]
    BadRequest(String),
    /// The request was understood and its content refused — text that is
    /// not a value, or a write the chain rejected.
    #[error("{0}")]
    Invalid(String),
    /// The daemon could not be reached, or broke serving the request.
    #[error(transparent)]
    Daemon(lotus_sdk::Error),
}

impl From<lotus_sdk::Error> for Error {
    /// A refusal by the chain is the request's fault, not the daemon's.
    fn from(err: lotus_sdk::Error) -> Self {
        if err.is_rejected() {
            Error::Invalid(describe(&err))
        } else {
            Error::Daemon(err)
        }
    }
}

impl Error {
    /// The status this failure is answered with.
    pub fn status(&self) -> StatusCode {
        match self {
            Error::BadRequest(_) => StatusCode::BAD_REQUEST,
            Error::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Error::Daemon(err) if err.is_daemon_unreachable() => StatusCode::BAD_GATEWAY,
            Error::Daemon(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// The failure as a person reads it: the whole source chain, since the
    /// top of it alone ("could not connect") says nothing actionable.
    pub fn describe(&self) -> String {
        describe(self)
    }
}

/// Joins an error and its sources into one line.
fn describe(err: &dyn std::error::Error) -> String {
    std::iter::successors(Some(err), |err| (*err).source())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

impl IntoResponse for Error {
    /// The bare failure, for when it happens before a handler runs — an
    /// unreadable URL — and there is no daemon in hand to draw the
    /// sidebar from.
    fn into_response(self) -> Response {
        let status = self.status();
        (status, view::bare(status, &self.describe())).into_response()
    }
}
