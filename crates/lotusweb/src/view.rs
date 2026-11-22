//! The pages, as HTML.
//!
//! One document: a sidebar of namespaces beside the main pane. Every link
//! and form in it asks for the pane alone (`hx-target` is inherited from
//! `body`, htmx 4 inheriting nothing on its own) and the pane's answer
//! carries the sidebar out of band, so both are always read at one head.

use axum::http::StatusCode;
use std::collections::{BTreeMap, BTreeSet};

use lotus_sdk::{
    EnvelopeDigest, NamespaceEntry, NamespaceKey, Schema, Subkey, Value, ValueAt, schema::Kind,
};
use maud::{DOCTYPE, Markup, html};

use crate::{
    Location, chain, form, json,
    known::{self, Known, Place},
    peers,
};

/// Where the embedded htmx build is served.
pub const HTMX_URL: &str = "/static/htmx.min.js";
/// Where the stylesheet is served.
pub const STYLE_URL: &str = "/static/style.css";

/// Where a namespace is created from the home pane.
pub const CREATE_URL: &str = "/ns";

/// How many characters of a value a listing shows.
const PREVIEW_WIDTH: usize = 72;

/// How much of a digest is shown; the rest is a hover away.
const SHORT_DIGEST: usize = 12;

/// What the ledger's own namespaces begin with: hidden until asked for.
const INTERNAL_PREFIX: &str = "_lotus";

/// The namespace list beside every page.
#[derive(Debug)]
pub enum Sidebar {
    /// What the ledger holds, at the head it was listed at.
    Listed {
        head: EnvelopeDigest,
        namespaces: Vec<NamespaceEntry>,
    },
    /// The list could not be read; why, for a person.
    Unavailable(String),
}

/// What the pane shows, marked in the sidebar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Active<'a> {
    /// Nothing the sidebar lists: home, or a failure before any page.
    Nothing,
    /// A location inside this namespace.
    Namespace(&'a NamespaceKey),
    /// The chain.
    Chain,
    /// The peers.
    Peers,
}

/// One page: what fills each part of the document.
#[derive(Debug)]
pub struct Page<'a> {
    pub sidebar: &'a Sidebar,
    pub active: Active<'a>,
    pub title: String,
    pub pane: Markup,
}

/// The whole document.
pub fn document(page: Page<'_>) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (page.title) }
                link rel="stylesheet" href=(STYLE_URL);
                script src=(HTMX_URL) {}
            }
            // Inherited by every link and form: all of them swap the pane.
            body hx-target:inherited="#main" {
                div.shell {
                    // The toggle sits outside the swapped nav, so it keeps
                    // its state as the pages change; the stylesheet hides
                    // the internal rows off it.
                    aside.side {
                        a.brand href="/" hx-get="/" hx-push-url="true" { "lotus" }
                        label.toggle {
                            input #show-internal type="checkbox";
                            "Show internal namespaces"
                        }
                        (sidebar(page.sidebar, page.active, None))
                    }
                    main #main { (page.pane) }
                }
            }
        }
    }
}

/// The pane alone, for htmx to swap in — the title to take, and the
/// sidebar to put in place out of band.
pub fn fragment(page: Page<'_>) -> Markup {
    html! {
        title { (page.title) }
        (page.pane)
        (sidebar(page.sidebar, page.active, Some("outerHTML")))
    }
}

fn sidebar(sidebar: &Sidebar, active: Active<'_>, swap_oob: Option<&str>) -> Markup {
    html! {
        nav #sidebar hx-swap-oob=[swap_oob] aria-label="Namespaces" {
            @match sidebar {
                Sidebar::Listed { head, namespaces } => {
                    p.head title=(head.to_hex().as_ref()) {
                        "head " a href=(chain::CHAIN_URL) hx-get=(chain::CHAIN_URL) hx-push-url="true" {
                            code { (short(head)) }
                        }
                    }
                    @if namespaces.is_empty() {
                        p.empty { "No namespaces yet." }
                    }
                    ul.namespaces {
                        @for entry in namespaces {
                            li.active[active == Active::Namespace(&entry.key)]
                                .internal[entry.key.as_ref().starts_with(INTERNAL_PREFIX)] {
                                (link(&Location::namespace(entry.key.clone()), entry.key.as_ref()))
                                span.shape { (entry.shape) }
                            }
                        }
                    }
                }
                Sidebar::Unavailable(why) => {
                    p.error { (why) }
                }
            }
            // Apart from the namespaces, at the bottom: what is not one.
            ul.tools {
                li.active[active == Active::Chain] {
                    a href=(chain::CHAIN_URL) hx-get=(chain::CHAIN_URL) hx-push-url="true" { "Chain" }
                    span.shape { "log" }
                }
                li.active[active == Active::Peers] {
                    a href=(peers::PEERS_URL) hx-get=(peers::PEERS_URL) hx-push-url="true" { "Peers" }
                    span.shape { "status" }
                }
            }
            footer { "lotusweb " (version::VERSION) }
        }
    }
}

/// A link that browses to `to`, whether or not script is on.
pub fn link(to: &Location, label: &str) -> Markup {
    let url = to.url();
    html! { a href=(url) hx-get=(url) hx-push-url="true" { (label) } }
}

/// The first characters of a digest, enough to tell it apart on a page.
pub fn short(digest: &EnvelopeDigest) -> String {
    digest
        .to_hex()
        .as_ref()
        .chars()
        .take(SHORT_DIGEST)
        .collect()
}

/// The pane before any namespace is picked.
pub fn home(notice: Option<&str>) -> Markup {
    html! {
        section.home {
            h1 { "iroh-lotus" }
            @if let Some(notice) = notice { p.notice { (notice) } }
            p { "Pick a namespace from the sidebar to browse what the ledger holds." }
            details.add {
                summary { "Create a namespace" }
                form hx-post=(CREATE_URL) action=(CREATE_URL) method="post" {
                    label { "Name" input name="key" required; }
                    (value_field(form::JSON, None, "{}"))
                    button { "Create" }
                }
            }
        }
    }
}

/// The way to `location`, each step a link but the last.
fn crumbs(location: &Location) -> Markup {
    let crumbs: Vec<_> = location.crumbs().collect();
    let (here, before) = crumbs
        .split_last()
        .expect("a location's crumbs end on itself");
    html! {
        nav.crumbs aria-label="Breadcrumb" {
            a href="/" hx-get="/" hx-push-url="true" { "Home" }
            @for crumb in before {
                span.sep { "›" }
                (link(crumb, &crumb.name()))
            }
            span.sep { "›" }
            span.current { (here.name()) }
        }
    }
}

/// What `location` holds, and the forms that change it. Where the
/// namespace's schema speaks of the location — `known` — the page says
/// what it says, and the forms are typed by it.
pub fn value_pane(
    location: &Location,
    at: &ValueAt,
    known: Option<&Known<'_>>,
    notice: Option<&str>,
) -> Markup {
    let schema = known.map(|known| known.schema);
    html! {
        (crumbs(location))
        header.pane-head {
            h1 { (location.name()) }
            @if let Some(value) = &at.value { span.badge { (kind(value)) } }
            span.head title=(at.head.to_hex().as_ref()) { "read at " code { (short(&at.head)) } }
        }
        @if let Some(known) = known { (schema_note(known)) }
        @if let Some(notice) = notice { p.notice { (notice) } }
        @match &at.value {
            None => (missing(location, schema)),
            Some(value @ Value::Map(held)) => {
                @if let Some(Kind::Struct { fields, required }) = schema.map(Schema::kind) {
                    // A struct's keys are the schema's: each is listed,
                    // set or not, and there is none to add.
                    (struct_fields(location, held, fields, required))
                    (set_password(location))
                } @else {
                    (entries(location, held.iter().map(|(key, value)| (Subkey::Key(key.clone()), value))))
                    (set_password(location))
                    (add_entry(location, schema, Some("Add entry")))
                }
                (replace(location, value))
                (moving(location, known))
            }
            Some(value @ Value::Array(items)) => {
                // An index past `u32` is one no path can address, so no link.
                (entries(location, items.iter().enumerate().filter_map(|(i, value)| {
                    u32::try_from(i).ok().map(|i| (Subkey::Index(i), value))
                })))
                (add_entry(location, schema, None))
                (replace(location, value))
                (moving(location, known))
            }
            Some(value @ Value::Key(_)) => {
                pre.value { (json::pretty(value)) }
                p.note { "A trusted key: plain JSON cannot spell one, so it is edited with lotusctl." }
                (moving(location, known))
            }
            Some(value) => {
                form.editor hx-put=(location.url()) {
                    @match schema.filter(|schema| form::edits(schema, value)) {
                        Some(schema) => (form::inputs(schema, Some(value))),
                        None => (value_field(form::JSON, Some(value), "")),
                    }
                    button { "Save" }
                }
                @if matches!(value, Value::Int(_)) { (increment(location)) }
                (moving(location, known))
            }
        }
    }
}

/// What the schema says of the location: its type and restrictions, what
/// it is for, and what each entry inside is held to.
fn schema_note(known: &Known<'_>) -> Markup {
    let schema = known.schema;
    let entry = known::entry(schema).filter(|entry| !matches!(entry.kind(), Kind::Any));
    // An `any` nobody described says nothing worth a line.
    let silent = matches!(schema.kind(), Kind::Any) && schema.description().is_none();
    html! {
        @if !silent {
            section.schema aria-label="Schema" {
                p.schema-type {
                    span.schema-label { "Schema" }
                    code { (known::summary(schema)) }
                    @match known.place {
                        Place::Field { required: true } => span.required { "required" },
                        Place::Field { required: false } => span.optional { "optional" },
                        Place::Free => {},
                    }
                }
                @if let Some(description) = schema.description() { p.description { (description) } }
                @if let Some(entry) = entry {
                    p.schema-type {
                        span.schema-label { "Each entry" }
                        code { (known::summary(entry)) }
                    }
                    @if let Some(description) = entry.description() { p.description { (description) } }
                }
            }
        }
    }
}

/// A struct's fields as its schema declares them, one row each whether
/// or not it is set, then whatever else the map holds.
fn struct_fields(
    location: &Location,
    held: &BTreeMap<String, Value>,
    fields: &BTreeMap<String, Schema>,
    required: &BTreeSet<String>,
) -> Markup {
    let undeclared = held.iter().filter(|(name, _)| !fields.contains_key(*name));
    html! {
        table.entries.fields {
            thead { tr { th { "Field" } th { "Type" } th { "Value" } th {} } }
            tbody {
                @for (name, schema) in fields {
                    @let child = location.child(Subkey::Key(name.clone()));
                    @let needed = required.contains(name);
                    tr {
                        td.name {
                            (link(&child, name))
                            @if needed { span.required { "required" } }
                            @if let Some(description) = schema.description() {
                                p.description { (description) }
                            }
                        }
                        td.kind { (known::summary(schema)) }
                        @match held.get(name) {
                            Some(value) => {
                                td.preview { code { (json::preview(value, PREVIEW_WIDTH)) } }
                                td.actions { @if !needed { (delete_row(&child)) } }
                            }
                            None => {
                                td.preview { span.absent { "not set" } }
                                td.actions {}
                            }
                        }
                    }
                }
                @for (name, value) in undeclared {
                    @let child = location.child(Subkey::Key(name.clone()));
                    tr {
                        td.name { (link(&child, name)) }
                        td.kind { (kind(value)) }
                        td.preview { code { (json::preview(value, PREVIEW_WIDTH)) } }
                        td.actions { (delete_row(&child)) }
                    }
                }
            }
        }
    }
}

/// The button that deletes the entry a listing's row shows.
fn delete_row(child: &Location) -> Markup {
    html! {
        button.danger.small hx-delete=(child.url()) hx-confirm=(format!("Delete {child}?")) {
            "Delete"
        }
    }
}

/// Renaming and deleting, as far as the schema lets the value move: a
/// struct's field keeps its name, and a required one stays.
fn moving(location: &Location, known: Option<&Known<'_>>) -> Markup {
    html! {
        @if known.is_none_or(Known::renamable) { (rename(location)) }
        @if known.is_some_and(Known::required) {
            p.note { "Required by the schema, so it cannot be deleted." }
        } @else {
            (delete(location))
        }
    }
}

/// A listing of a container's entries, one link each.
fn entries<'a>(location: &Location, entries: impl Iterator<Item = (Subkey, &'a Value)>) -> Markup {
    let rows: Vec<_> = entries.collect();
    html! {
        @if rows.is_empty() {
            p.empty { "Empty." }
        } @else {
            table.entries {
                thead { tr { th { "Name" } th { "Kind" } th { "Value" } th {} } }
                tbody {
                    @for (subkey, value) in rows {
                        @let child = location.child(subkey.clone());
                        tr {
                            td.name { (link(&child, &subkey.to_string())) }
                            td.kind { (kind(value)) }
                            td.preview { code { (json::preview(value, PREVIEW_WIDTH)) } }
                            td.actions { (delete_row(&child)) }
                        }
                    }
                }
            }
        }
    }
}

/// The value's kind, and how much of it there is.
fn kind(value: &Value) -> String {
    match value {
        Value::String(_) => "string".into(),
        Value::Int(_) => "int".into(),
        Value::Bool(_) => "bool".into(),
        Value::Key(_) => "trusted key".into(),
        Value::Array(items) => format!("array · {}", items.len()),
        Value::Map(fields) => format!("map · {}", fields.len()),
    }
}

/// The JSON editor every form writes through; `current` prefills it.
fn value_field(name: &str, current: Option<&Value>, placeholder: &str) -> Markup {
    let text = current.map(json::pretty).unwrap_or_default();
    let rows = text.lines().count().clamp(3, 24);
    html! {
        label {
            "Value (JSON)"
            textarea name=(name) rows=(rows) placeholder=(placeholder) spellcheck="false" { (text) }
        }
    }
}

/// Adds an entry to a map — `keyed` names the form — or appends to an
/// array. Where `schema`, the container's, types its entries, the form is
/// laid out in the page and typed by it; otherwise it is JSON, folded away.
fn add_entry(location: &Location, schema: Option<&Schema>, keyed: Option<&str>) -> Markup {
    let title = keyed.unwrap_or("Append item");
    let key = html! {
        @if keyed.is_some() {
            label { "Key" input name=(form::KEY) required; }
        }
    };
    let button = html! { button { (keyed.map_or("Append", |_| "Add")) } };
    match schema
        .and_then(known::entry)
        .filter(|entry| form::typed(entry))
    {
        Some(entry) => html! {
            section.add {
                h2 { (title) }
                form hx-post=(location.url()) {
                    (key)
                    (form::inputs(entry, None))
                    (button)
                }
            }
        },
        None => html! {
            details.add {
                summary { (title) }
                form hx-post=(location.url()) {
                    (key)
                    (value_field(form::JSON, None, "\"text\", 7, true, [ … ] or { … }"))
                    (button)
                }
            }
        },
    }
}

/// Adds to an integer without retyping it — a counter bumped, a quota
/// eased — negative to take from it.
fn increment(location: &Location) -> Markup {
    html! {
        details.increment {
            summary { "Increment" }
            form hx-patch=(location.url()) {
                label {
                    "Delta"
                    input type="number" name="delta" value="1" step="1" required;
                }
                button { "Increment" }
            }
        }
    }
}

/// Moves a map entry to another key, its value untouched; nothing, where
/// `location` is not one. The value is carried as the ledger holds it,
/// so an entry holding a trusted key can be renamed though not edited.
fn rename(location: &Location) -> Markup {
    html! {
        @if let Some(key) = location.map_key() {
            details.rename {
                summary { "Rename key" }
                form hx-patch=(location.url()) {
                    label { "New key" input name="key" value=(key) required; }
                    button { "Rename" }
                }
            }
        }
    }
}

/// Sets the password of the user whose `auth.users` entry `location` is;
/// nothing, where it is not one. The server hashes it before writing.
fn set_password(location: &Location) -> Markup {
    html! {
        @if let Some(user) = location.auth_user() {
            details.password {
                summary { "Set password" }
                form hx-patch=(location.url()) {
                    // The username lets a password manager file it.
                    input type="hidden" name="username" value=(user) autocomplete="username";
                    label {
                        "New password"
                        input type="password" name="password" autocomplete="new-password" required;
                    }
                    button { "Set password" }
                }
            }
        }
    }
}

/// Replaces a container whole.
fn replace(location: &Location, value: &Value) -> Markup {
    html! {
        details.replace {
            summary { "Replace whole value" }
            @if json::holds_key(value) {
                p.note { "Holds a trusted key, which plain JSON cannot spell; edit it with lotusctl." }
            } @else {
                form hx-put=(location.url()) {
                    (value_field(form::JSON, Some(value), ""))
                    button { "Save" }
                }
            }
        }
    }
}

fn delete(location: &Location) -> Markup {
    let confirm = if location.is_root() {
        format!("Delete the namespace {location} and everything in it?")
    } else {
        format!("Delete {location}?")
    };
    html! {
        div.danger-zone {
            button.danger hx-delete=(location.url()) hx-confirm=(confirm) {
                @if location.is_root() { "Delete namespace" } @else { "Delete" }
            }
        }
    }
}

/// Nothing is held at `location`: say so, and offer to put something
/// there, typed by `schema` where it types what goes there.
fn missing(location: &Location, schema: Option<&Schema>) -> Markup {
    html! {
        @if location.is_root() {
            p.empty { "This namespace does not exist yet." }
        } @else {
            p.empty { "Nothing is held here." }
        }
        form.editor hx-put=(location.url()) {
            @match schema.filter(|schema| form::typed(schema)) {
                Some(schema) => (form::inputs(schema, None)),
                None => (value_field(form::JSON, None, "{}")),
            }
            button { "Create" }
        }
    }
}

/// A failure, in the pane, with the way back where there is one.
pub fn error_pane(location: Option<&Location>, status: StatusCode, message: &str) -> Markup {
    html! {
        @if let Some(location) = location { (crumbs(location)) }
        section.failure {
            h1 { (status.as_u16()) " " (status.canonical_reason().unwrap_or("Error")) }
            p.error { (message) }
        }
    }
}

/// A failure before any page could be drawn: the document around an
/// error pane, with no ledger to list beside it.
pub fn bare(status: StatusCode, message: &str) -> Markup {
    let sidebar = Sidebar::Unavailable("Not read.".into());
    document(Page {
        sidebar: &sidebar,
        active: Active::Nothing,
        title: format!("{} · lotusweb", status.as_u16()),
        pane: error_pane(None, status, message),
    })
}
