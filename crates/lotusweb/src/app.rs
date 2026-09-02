//! The server: its routes, and what each does with the daemon.
//!
//! Every location has one URL, `/ns/<namespace>[/<path>]`, and the HTTP
//! method says what happens there: `GET` shows it, `PUT` replaces what it
//! holds, `POST` adds an entry inside it, `PATCH` adds to the integer it
//! is, `DELETE` removes it.

use axum::{
    Router,
    extract::{Form, State},
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use lotus_sdk::{Client, NamespaceKey, Subkey, Written};
use serde::Deserialize;

use crate::{
    Error, Location,
    frame::Frame,
    json,
    view::{self, Page, Sidebar},
};

const HTMX: &str = include_str!("../static/htmx.min.js");
const STYLE: &str = include_str!("../static/style.css");

/// The response header that moves the browser's URL after a write.
const HX_PUSH_URL: HeaderName = HeaderName::from_static("hx-push-url");

/// Where the whole ledger is browsed from.
const HOME_URL: &str = "/";

#[derive(Debug, Clone)]
struct App {
    client: Client,
}

/// The whole server, over the daemon at `client`.
pub fn router(client: Client) -> Router {
    let location = get(browse)
        .put(replace)
        .post(insert)
        .patch(increment)
        .delete(remove);
    Router::new()
        .route(HOME_URL, get(home))
        .route(view::CREATE_URL, post(create))
        .route("/ns/{key}", location.clone())
        .route("/ns/{key}/{*path}", location)
        .route(
            view::HTMX_URL,
            get(|| async { asset("text/javascript", HTMX) }),
        )
        .route(view::STYLE_URL, get(|| async { asset("text/css", STYLE) }))
        .with_state(App { client })
}

fn asset(content_type: &'static str, body: &'static str) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, content_type)], body)
}

/// What the editor forms submit.
#[derive(Debug, Deserialize)]
struct ValueForm {
    value: String,
}

/// What the add-entry form submits: a key for a map, none for an array.
#[derive(Debug, Deserialize)]
struct EntryForm {
    key: Option<String>,
    value: String,
}

/// What the increment form submits: how much to add, negative to take.
#[derive(Debug, Deserialize)]
struct IncrementForm {
    delta: String,
}

/// What the create-namespace form submits.
#[derive(Debug, Deserialize)]
struct NamespaceForm {
    key: String,
    value: String,
}

async fn home(State(app): State<App>, frame: Frame) -> Response {
    app.home(&frame, None).await
}

async fn browse(State(app): State<App>, frame: Frame, location: Location) -> Response {
    app.show(&frame, &location, None).await
}

async fn replace(
    State(app): State<App>,
    frame: Frame,
    location: Location,
    Form(form): Form<ValueForm>,
) -> Response {
    let written = async {
        let value = parse(&form.value)?;
        app.client
            .set(location.key().clone(), location.path().cloned(), value)
            .await
            .map_err(Error::from)
    }
    .await;
    match written {
        Ok(written) => {
            app.landed(
                frame,
                Some(&location),
                Some(&location),
                &wrote(&location, &written),
            )
            .await
        }
        Err(error) => app.fail(&frame, Some(&location), &error).await,
    }
}

async fn insert(
    State(app): State<App>,
    frame: Frame,
    location: Location,
    Form(form): Form<EntryForm>,
) -> Response {
    let written = async {
        let value = parse(&form.value)?;
        match form.key {
            Some(key) => {
                let child = location.child(Subkey::Key(key));
                let written = app
                    .client
                    .set(child.key().clone(), child.path().cloned(), value)
                    .await?;
                Ok(wrote(&child, &written))
            }
            None => {
                let written = app
                    .client
                    .push(location.key().clone(), location.path().cloned(), value)
                    .await?;
                Ok(format!("Appended to {location}; {}", moved(&written)))
            }
        }
    }
    .await;
    match written {
        Ok(notice) => {
            app.landed(frame, Some(&location), Some(&location), &notice)
                .await
        }
        Err(error) => app.fail(&frame, Some(&location), &error).await,
    }
}

async fn increment(
    State(app): State<App>,
    frame: Frame,
    location: Location,
    Form(form): Form<IncrementForm>,
) -> Response {
    let written = async {
        let delta: i64 = form.delta.trim().parse().map_err(|_| {
            Error::Invalid(format!("`{}` is not a whole number to add", form.delta))
        })?;
        let written = app
            .client
            .increment(location.key().clone(), location.path().cloned(), delta)
            .await?;
        Ok(format!("Added {delta} to {location}; {}", moved(&written)))
    }
    .await;
    match written {
        Ok(notice) => {
            app.landed(frame, Some(&location), Some(&location), &notice)
                .await
        }
        Err(error) => app.fail(&frame, Some(&location), &error).await,
    }
}

async fn create(State(app): State<App>, frame: Frame, Form(form): Form<NamespaceForm>) -> Response {
    let written = async {
        let key = NamespaceKey::try_new(form.key.trim())
            .map_err(|e| Error::Invalid(format!("not a namespace name: {e}")))?;
        let value = parse(&form.value)?;
        let written = app.client.set(key.clone(), None, value).await?;
        Ok((Location::namespace(key), written))
    }
    .await;
    match written {
        Ok((location, written)) => {
            let notice = wrote(&location, &written);
            app.landed(frame, None, Some(&location), &notice).await
        }
        Err(error) => app.fail(&frame, None, &error).await,
    }
}

async fn remove(State(app): State<App>, frame: Frame, location: Location) -> Response {
    let deleted = app
        .client
        .delete(location.key().clone(), location.path().cloned())
        .await
        .map_err(Error::from);
    match deleted {
        Ok(written) => {
            let notice = format!("Deleted {location}; {}", moved(&written));
            app.landed(frame, Some(&location), location.parent().as_ref(), &notice)
                .await
        }
        Err(error) => app.fail(&frame, Some(&location), &error).await,
    }
}

/// Reads form text as a value, a failure being the request's.
fn parse(text: &str) -> Result<lotus_sdk::Value, Error> {
    json::parse(text).map_err(|e| Error::Invalid(e.to_string()))
}

fn wrote(location: &Location, written: &Written) -> String {
    format!("Wrote {location}; {}", moved(written))
}

/// What a write did to the chain, for a notice.
fn moved(written: &Written) -> String {
    let head: String = written.head.to_hex().as_ref().chars().take(12).collect();
    format!("head {} at {head}", written.outcome)
}

/// `response` with the browser's URL moved to `url`.
fn pushed(mut response: Response, url: &str) -> Response {
    let url = HeaderValue::from_str(url).expect("a percent-encoded URL is ASCII");
    response.headers_mut().insert(HX_PUSH_URL, url);
    response
}

impl App {
    /// The namespace list, as far as the daemon allows.
    async fn sidebar(&self) -> Sidebar {
        match self.client.list_namespaces().await {
            Ok(list) => Sidebar::Listed {
                head: list.head,
                namespaces: list.namespaces,
            },
            Err(error) => {
                let error = Error::from(error);
                tracing::warn!(error = %error.describe(), "listing namespaces");
                Sidebar::Unavailable(error.describe())
            }
        }
    }

    async fn home(&self, frame: &Frame, notice: Option<&str>) -> Response {
        let sidebar = self.sidebar().await;
        frame.render(
            StatusCode::OK,
            Page {
                sidebar: &sidebar,
                active: None,
                title: "lotusweb".into(),
                pane: view::home(notice),
            },
        )
    }

    /// What `location` holds, read now, with `notice` above it.
    async fn show(&self, frame: &Frame, location: &Location, notice: Option<&str>) -> Response {
        let read = self
            .client
            .read(location.key().clone(), location.path().cloned())
            .await
            .map_err(Error::from);
        let sidebar = self.sidebar().await;
        let (status, pane) = match &read {
            Ok(at) => (StatusCode::OK, view::value_pane(location, at, notice)),
            Err(error) => {
                tracing::warn!(%location, error = %error.describe(), "reading");
                let status = error.status();
                (
                    status,
                    view::error_pane(Some(location), status, &error.describe()),
                )
            }
        };
        frame.render(
            status,
            Page {
                sidebar: &sidebar,
                active: Some(location.key()),
                title: format!("{location} · lotusweb"),
                pane,
            },
        )
    }

    /// Where a write on `from` leaves the browser: at `destination` —
    /// home, for `None` — reading `notice`. A plain form submission is
    /// redirected there, so a reload never repeats the write.
    async fn landed(
        &self,
        frame: Frame,
        from: Option<&Location>,
        destination: Option<&Location>,
        notice: &str,
    ) -> Response {
        tracing::info!(notice, "written");
        let url = destination.map_or_else(|| HOME_URL.to_string(), Location::url);
        match frame {
            Frame::Document => axum::response::Redirect::to(&url).into_response(),
            Frame::Pane { .. } => {
                // Pushing the URL the browser already shows would leave a
                // duplicate history entry: a row deleted from the table it
                // is listed in lands on the page it was deleted from.
                let already_there = frame.shows(&url) || (from.is_some() && destination == from);
                let response = match destination {
                    Some(destination) => self.show(&frame, destination, Some(notice)).await,
                    None => self.home(&frame, Some(notice)).await,
                };
                if already_there {
                    response
                } else {
                    pushed(response, &url)
                }
            }
        }
    }

    /// `error`, in the pane, at `location` when the request had one.
    async fn fail(&self, frame: &Frame, location: Option<&Location>, error: &Error) -> Response {
        tracing::warn!(location = location.map(ToString::to_string), error = %error.describe(), "refused");
        let sidebar = self.sidebar().await;
        let status = error.status();
        frame.render(
            status,
            Page {
                sidebar: &sidebar,
                active: location.map(Location::key),
                title: format!("{} · lotusweb", status.as_u16()),
                pane: view::error_pane(location, status, &error.describe()),
            },
        )
    }
}
