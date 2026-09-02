//! How much of a page a request wants back.

use std::convert::Infallible;

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, header::HeaderMap, request::Parts},
    response::{IntoResponse, Response},
};

use crate::view::{self, Page};

/// The htmx request headers a frame is read from.
const HX_REQUEST: &str = "hx-request";
const HX_HISTORY_RESTORE: &str = "hx-history-restore-request";
const HX_CURRENT_URL: &str = "hx-current-url";

/// Whether a request is answered with the whole document or the main
/// pane alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// The whole document: a plain navigation, or htmx restoring history,
    /// which fetches the page again and selects what it needs from it.
    Document,
    /// The main pane, with the sidebar riding along out of band: what an
    /// htmx link or form swaps in.
    Pane {
        /// The path the browser shows, when htmx said.
        current: Option<String>,
    },
}

impl Frame {
    fn from_headers(headers: &HeaderMap) -> Self {
        let is_true = |name| headers.get(name).is_some_and(|value| value == "true");
        if is_true(HX_REQUEST) && !is_true(HX_HISTORY_RESTORE) {
            let current = headers
                .get(HX_CURRENT_URL)
                .and_then(|value| value.to_str().ok())
                .and_then(path_of)
                .map(str::to_owned);
            Frame::Pane { current }
        } else {
            Frame::Document
        }
    }

    /// Whether the browser already shows `path`, as far as htmx said.
    pub fn shows(&self, path: &str) -> bool {
        matches!(self, Frame::Pane { current: Some(current) } if current == path)
    }

    /// Renders `page` as this frame asks for it.
    pub fn render(&self, status: StatusCode, page: Page<'_>) -> Response {
        let markup = match self {
            Frame::Document => view::document(page),
            Frame::Pane { .. } => view::fragment(page),
        };
        (status, markup).into_response()
    }
}

/// The path of an absolute URL, query and fragment dropped.
fn path_of(url: &str) -> Option<&str> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let path = &rest[rest.find('/')?..];
    Some(path.split(['?', '#']).next().unwrap_or(path))
}

impl<S: Send + Sync> FromRequestParts<S> for Frame {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Frame::from_headers(&parts.headers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(name, value)| {
                (
                    axum::http::HeaderName::from_static(name),
                    value.parse().unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn a_plain_navigation_gets_the_document() {
        assert_eq!(Frame::from_headers(&headers(&[])), Frame::Document);
    }

    #[test]
    fn an_htmx_request_gets_the_pane() {
        assert_eq!(
            Frame::from_headers(&headers(&[(HX_REQUEST, "true")])),
            Frame::Pane { current: None }
        );
    }

    #[test]
    fn the_pane_knows_where_the_browser_is() {
        let frame = Frame::from_headers(&headers(&[
            (HX_REQUEST, "true"),
            (HX_CURRENT_URL, "http://localhost:8080/ns/cfg?x=1#top"),
        ]));
        assert!(frame.shows("/ns/cfg"));
        assert!(!frame.shows("/ns/cfg/host"));
        assert!(!Frame::Document.shows("/ns/cfg"));
    }

    /// htmx restores history by fetching the page whole and picking the
    /// body out of it, so a fragment would leave it nothing to pick.
    #[test]
    fn a_history_restore_gets_the_document() {
        assert_eq!(
            Frame::from_headers(&headers(&[
                (HX_REQUEST, "true"),
                (HX_HISTORY_RESTORE, "true")
            ])),
            Frame::Document
        );
    }
}
