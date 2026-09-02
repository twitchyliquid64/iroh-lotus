//! The pages, driven against a real daemon over a real control socket:
//! browsing down a namespace, and every write the forms make.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode, header},
};
use lotus_sdk::{Client, NamespaceKey, SubkeyPath, Value};
use lotusd::{Core, IfInitialized, Server, ServerHandle};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use tempfile::TempDir;
use tokio::{net::UnixListener, task::JoinHandle};
use tower::ServiceExt;

/// A daemon on a fresh state dir, the router over it, and a client beside
/// it to check what the pages did.
struct Node {
    // Held so the socket outlives the test.
    _dir: TempDir,
    client: Client,
    router: Router,
    // Both held so the mainloop outlives the test: the server stops when
    // its last handle drops.
    _handle: ServerHandle,
    _join: JoinHandle<()>,
}

async fn node() -> Node {
    let dir = TempDir::new().unwrap();
    let core = Core::create_in_state_dir(dir.path().to_path_buf(), IfInitialized::Fail)
        .await
        .unwrap();
    let listener = UnixListener::bind(lotus_sdk::socket_in(dir.path())).unwrap();
    let (handle, join) = Server::new(core, listener).unwrap().run().await;
    let client = Client::in_state_dir(dir.path());

    Node {
        router: lotusweb::router(client.clone()),
        client,
        _dir: dir,
        _handle: handle,
        _join: join,
    }
}

/// A node holding one namespace, `cfg`, with a map and an array inside.
async fn seeded() -> Node {
    let node = node().await;
    node.client
        .set(
            key("cfg"),
            None,
            Value::from_iter([
                ("host", Value::from("a.example")),
                ("port", Value::Int(443)),
                (
                    "servers",
                    Value::from_iter([Value::from("s1"), Value::from("s2")]),
                ),
            ]),
        )
        .await
        .unwrap();
    node
}

fn key(text: &str) -> NamespaceKey {
    NamespaceKey::try_new(text).unwrap()
}

fn path(text: &str) -> SubkeyPath {
    text.parse().unwrap()
}

/// A request from inside the page: what an htmx link or form sends.
fn htmx(request: Request<Body>) -> Request<Body> {
    let (mut parts, body) = request.into_parts();
    parts.headers.insert("hx-request", "true".parse().unwrap());
    Request::from_parts(parts, body)
}

/// A plain navigation to `uri`.
fn get(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}

/// A form submission by `method` to `uri`.
fn form(method: &str, uri: &str, fields: &[(&str, &str)]) -> Request<Body> {
    let body = fields
        .iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                utf8_percent_encode(name, NON_ALPHANUMERIC),
                utf8_percent_encode(value, NON_ALPHANUMERIC)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

/// What the router answered `request` with.
async fn send(node: &Node, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let response = node.router.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let body = to_bytes(body, usize::MAX).await.unwrap();
    (
        parts.status,
        parts.headers,
        String::from_utf8(body.to_vec()).expect("the pages are text"),
    )
}

fn pushed_to(headers: &HeaderMap) -> Option<&str> {
    headers.get("hx-push-url").map(|url| url.to_str().unwrap())
}

#[tokio::test]
async fn the_home_page_lists_the_namespaces_in_the_sidebar() {
    let node = seeded().await;

    let (status, _, body) = send(&node, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with("<!DOCTYPE html>"), "{body}");
    assert!(body.contains(r#"href="/ns/cfg""#), "{body}");
    assert!(body.contains("Pick a namespace"), "{body}");
    // htmx 4 inherits nothing on its own: the target is marked inherited.
    assert!(
        body.contains(r##"<body hx-target:inherited="#main">"##),
        "{body}"
    );
}

#[tokio::test]
async fn a_namespace_opens_on_its_entries_with_a_link_each() {
    let node = seeded().await;

    let (status, _, body) = send(&node, get("/ns/cfg")).await;
    assert_eq!(status, StatusCode::OK);
    for link in ["/ns/cfg/host", "/ns/cfg/port", "/ns/cfg/servers"] {
        assert!(
            body.contains(&format!(r#"hx-get="{link}""#)),
            "{link} in {body}"
        );
    }
    assert!(body.contains("a.example"), "{body}");
    assert!(body.contains("array · 2"), "{body}");
    assert!(body.contains("Delete namespace"), "{body}");
    // Each row can be deleted where it is listed.
    assert!(
        body.contains(r#"hx-delete="/ns/cfg/host" hx-confirm="Delete cfg › host?""#),
        "{body}"
    );
}

#[tokio::test]
async fn a_path_is_walked_a_level_at_a_time_with_breadcrumbs_back() {
    let node = seeded().await;

    let (status, _, body) = send(&node, get("/ns/cfg/servers")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains(r#"hx-get="/ns/cfg/servers%5B0%5D""#),
        "{body}"
    );
    assert!(
        body.contains(r#"hx-get="/ns/cfg/servers%5B1%5D""#),
        "{body}"
    );

    let (status, _, body) = send(&node, get("/ns/cfg/servers%5B1%5D")).await;
    assert_eq!(status, StatusCode::OK);
    // The crumbs: the namespace and the array as links, the index as text.
    assert!(
        body.contains(r#"<a href="/ns/cfg" hx-get="/ns/cfg""#),
        "{body}"
    );
    assert!(
        body.contains(r#"<a href="/ns/cfg/servers" hx-get="/ns/cfg/servers""#),
        "{body}"
    );
    assert!(
        body.contains(r#"<span class="current">[1]</span>"#),
        "{body}"
    );
    // A leaf is shown in its editor.
    assert!(body.contains(r#"<textarea name="value""#), "{body}");
    assert!(body.contains("&quot;s2&quot;"), "{body}");
}

#[tokio::test]
async fn an_htmx_request_gets_the_pane_with_the_sidebar_out_of_band() {
    let node = seeded().await;

    let (status, _, body) = send(&node, htmx(get("/ns/cfg"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("<html"), "{body}");
    assert!(body.contains("<title>cfg · lotusweb</title>"), "{body}");
    assert!(
        body.contains(r#"<nav id="sidebar" hx-swap-oob="outerHTML""#),
        "{body}"
    );
    assert!(body.contains(r#"<li class="active">"#), "{body}");
}

/// htmx restores history by fetching the page whole and swapping its body.
#[tokio::test]
async fn a_history_restore_gets_the_whole_document() {
    let node = seeded().await;

    let mut request = htmx(get("/ns/cfg"));
    request
        .headers_mut()
        .insert("hx-history-restore-request", "true".parse().unwrap());
    let (status, _, body) = send(&node, request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with("<!DOCTYPE html>"), "{body}");
}

#[tokio::test]
async fn a_leaf_is_replaced_from_its_editor() {
    let node = seeded().await;

    let request = htmx(form("PUT", "/ns/cfg/host", &[("value", "\"b.example\"")]));
    let (status, headers, body) = send(&node, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("Wrote cfg › host"), "{body}");
    assert!(body.contains("&quot;b.example&quot;"), "{body}");
    // Same URL as before: nothing to push.
    assert_eq!(pushed_to(&headers), None);

    let at = node.client.read(key("cfg"), path("host")).await.unwrap();
    assert_eq!(at.value, Some(Value::from("b.example")));
}

#[tokio::test]
async fn an_entry_is_added_to_a_map_and_appended_to_an_array() {
    let node = seeded().await;

    let request = htmx(form(
        "POST",
        "/ns/cfg",
        &[("key", "tls"), ("value", "true")],
    ));
    let (status, _, body) = send(&node, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains(r#"hx-get="/ns/cfg/tls""#), "{body}");

    let request = htmx(form("POST", "/ns/cfg/servers", &[("value", "\"s3\"")]));
    let (status, _, body) = send(&node, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("array · 3"), "{body}");

    let at = node.client.read(key("cfg"), None).await.unwrap();
    assert_eq!(
        at.value,
        Some(Value::from_iter([
            ("host", Value::from("a.example")),
            ("port", Value::Int(443)),
            (
                "servers",
                Value::from_iter([Value::from("s1"), Value::from("s2"), Value::from("s3")])
            ),
            ("tls", Value::Bool(true)),
        ]))
    );
}

#[tokio::test]
async fn an_integer_is_incremented_by_a_delta() {
    let node = seeded().await;

    let (_, _, body) = send(&node, get("/ns/cfg/port")).await;
    assert!(body.contains(r#"hx-patch="/ns/cfg/port""#), "{body}");
    // Only an integer offers it.
    let (_, _, body) = send(&node, get("/ns/cfg/host")).await;
    assert!(!body.contains("hx-patch"), "{body}");

    let request = htmx(form("PATCH", "/ns/cfg/port", &[("delta", "7")]));
    let (status, _, body) = send(&node, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("Added 7 to cfg › port"), "{body}");
    assert!(body.contains(">450</textarea>"), "{body}");

    let request = htmx(form("PATCH", "/ns/cfg/port", &[("delta", "-50")]));
    let (status, _, body) = send(&node, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let at = node.client.read(key("cfg"), path("port")).await.unwrap();
    assert_eq!(at.value, Some(Value::Int(400)));

    let request = htmx(form("PATCH", "/ns/cfg/port", &[("delta", "1.5")]));
    let (status, _, body) = send(&node, request).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body.contains("not a whole number to add"), "{body}");

    // What is not an integer refuses the delta on the chain's word.
    let request = htmx(form("PATCH", "/ns/cfg/host", &[("delta", "1")]));
    let (status, _, _) = send(&node, request).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn a_namespace_is_created_from_the_home_page() {
    let node = node().await;

    let request = htmx(form(
        "POST",
        "/ns",
        &[("key", "new"), ("value", "{\"a\": 1}")],
    ));
    let (status, headers, body) = send(&node, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(pushed_to(&headers), Some("/ns/new"));
    assert!(body.contains(r#"hx-get="/ns/new/a""#), "{body}");

    // Alongside the namespaces a blank ledger starts with.
    let list = node.client.list_namespaces().await.unwrap();
    assert!(list.namespaces.iter().any(|entry| entry.key == key("new")));
}

#[tokio::test]
async fn what_is_not_held_can_be_created_in_place() {
    let node = seeded().await;

    let (status, _, body) = send(&node, get("/ns/cfg/missing")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Nothing is held here."), "{body}");
    assert!(body.contains(r#"hx-put="/ns/cfg/missing""#), "{body}");

    let (status, _, body) = send(&node, get("/ns/absent")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("This namespace does not exist yet."),
        "{body}"
    );
}

#[tokio::test]
async fn deleting_lands_on_the_parent() {
    let node = seeded().await;

    let request = htmx(
        Request::delete("/ns/cfg/servers%5B0%5D")
            .body(Body::empty())
            .unwrap(),
    );
    let (status, headers, body) = send(&node, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(pushed_to(&headers), Some("/ns/cfg/servers"));
    assert!(body.contains("Deleted cfg › servers[0]"), "{body}");
    let at = node.client.read(key("cfg"), path("servers")).await.unwrap();
    assert_eq!(at.value, Some(Value::from_iter([Value::from("s2")])));

    // Deleted from the row in the table listing it, the browser is already
    // on the parent: nothing to push.
    let mut request = htmx(
        Request::delete("/ns/cfg/servers%5B0%5D")
            .body(Body::empty())
            .unwrap(),
    );
    request.headers_mut().insert(
        "hx-current-url",
        "http://localhost:8080/ns/cfg/servers".parse().unwrap(),
    );
    let (status, headers, body) = send(&node, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(pushed_to(&headers), None);
    assert!(body.contains("Empty."), "{body}");

    let request = htmx(Request::delete("/ns/cfg").body(Body::empty()).unwrap());
    let (status, headers, body) = send(&node, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(pushed_to(&headers), Some("/"));
    assert!(body.contains("Pick a namespace"), "{body}");
    assert!(!body.contains(r#"href="/ns/cfg""#), "{body}");
    let at = node.client.read(key("cfg"), None).await.unwrap();
    assert_eq!(at.value, None);
}

/// Without htmx, a write is answered by a redirect to what it changed, so
/// a reload of the page never repeats it.
#[tokio::test]
async fn a_plain_form_submission_is_redirected() {
    let node = seeded().await;

    let request = form("PUT", "/ns/cfg/host", &[("value", "\"b.example\"")]);
    let (status, headers, _) = send(&node, request).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/ns/cfg/host");

    let request = Request::delete("/ns/cfg/host").body(Body::empty()).unwrap();
    let (status, headers, _) = send(&node, request).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[header::LOCATION], "/ns/cfg");
}

#[tokio::test]
async fn text_that_is_not_a_value_is_refused_and_nothing_is_written() {
    let node = seeded().await;
    let before = node.client.chain_range().await.unwrap().head;

    for (text, why) in [
        ("hello", "not JSON"),
        ("null", "null is not a value"),
        ("1.5", "not a whole number"),
    ] {
        let request = htmx(form("PUT", "/ns/cfg/host", &[("value", text)]));
        let (status, _, body) = send(&node, request).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{text}: {body}");
        assert!(body.contains(why), "{text}: {body}");
        // The error stays inside the page: the crumbs lead back.
        assert!(body.contains(r#"hx-get="/ns/cfg""#), "{body}");
    }

    assert_eq!(node.client.chain_range().await.unwrap().head, before);
}

#[tokio::test]
async fn what_the_chain_refuses_is_reported() {
    let node = seeded().await;

    // Appending to a string.
    let request = htmx(form("POST", "/ns/cfg/host", &[("value", "\"x\"")]));
    let (status, _, body) = send(&node, request).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body.contains("422"), "{body}");
}

#[tokio::test]
async fn a_url_that_names_no_location_is_a_bad_request() {
    let node = seeded().await;

    let (status, _, body) = send(&node, get("/ns/cfg/a..b")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("is not a path"), "{body}");
}

#[tokio::test]
async fn a_daemon_that_is_not_there_is_a_bad_gateway() {
    let dir = TempDir::new().unwrap();
    let node = Node {
        client: Client::in_state_dir(dir.path()),
        router: lotusweb::router(Client::in_state_dir(dir.path())),
        _dir: dir,
        _handle: {
            // No daemon: a throwaway server, so the struct can be built.
            let throwaway = TempDir::new().unwrap();
            let core =
                Core::create_in_state_dir(throwaway.path().to_path_buf(), IfInitialized::Fail)
                    .await
                    .unwrap();
            let listener = UnixListener::bind(lotus_sdk::socket_in(throwaway.path())).unwrap();
            Server::new(core, listener).unwrap().run().await.0
        },
        _join: tokio::spawn(async {}),
    };
    assert!(
        node.client
            .status()
            .await
            .unwrap_err()
            .is_daemon_unreachable()
    );

    let (status, _, body) = send(&node, get("/ns/cfg")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(body.contains("could not connect to the daemon"), "{body}");

    // The home page still draws, saying why the sidebar is empty.
    let (status, _, body) = send(&node, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("could not connect to the daemon"), "{body}");
}

#[tokio::test]
async fn the_assets_are_served() {
    let node = node().await;

    let (status, headers, body) = send(&node, get("/static/htmx.min.js")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "text/javascript");
    assert!(body.starts_with("var htmx="), "{}", &body[..40]);

    let (status, headers, _) = send(&node, get("/static/style.css")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "text/css");
}
