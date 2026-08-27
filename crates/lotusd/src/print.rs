//! How `lotusd debug` renders what it finds.
//!
//! Part of the binary, not the library: this is CLI presentation, and the
//! shapes it prints are the wire types themselves.

use std::fmt;

use lotusd::Core;
use wire::{Envelope, EnvelopeDigest, Msg, VerificationStatus, msg::AmendOp};

/// Width the field labels are padded to.
const LABEL: usize = 13;

/// Prints `envelopes` — a chain in the order [`Core::canonical_chain`] gives
/// them, oldest first — one stanza each.
pub fn print_chain(core: &Core, envelopes: &[(EnvelopeDigest, Envelope)]) {
    println!(
        "{} on {core}\n",
        plural(envelopes.len(), "envelope", "envelopes"),
    );

    envelopes
        .iter()
        .enumerate()
        .for_each(|(index, (digest, envelope))| {
            let marks = [
                (*digest == core.root(), "root"),
                (*digest == core.head(), "head"),
            ]
            .into_iter()
            .filter_map(|(is, mark)| is.then_some(mark))
            .collect::<Vec<_>>();

            let marks = match marks.is_empty() {
                true => String::new(),
                false => format!("  [{}]", marks.join(", ")),
            };
            println!("#{index} {}{marks}", digest.to_hex().as_ref());

            field(
                "prev",
                envelope.payload().prev_digest().map_or_else(
                    || "— (genesis)".to_string(),
                    |prev| prev.to_hex().as_ref().to_string(),
                ),
            );
            field("message", describe(envelope.payload()));

            if let Msg::Init(init) = envelope.payload() {
                field_list(
                    "namespaces",
                    init.state.namespaces.keys().map(ToString::to_string),
                );
            }

            field(
                "verification",
                describe_status(envelope.verification_status()),
            );
            field_list(
                "signed by",
                envelope
                    .signatures()
                    .keys()
                    .map(|id| id.to_hex().as_ref().to_string()),
            );

            // Nothing to show per timestamp while `SignedTimestamp` is empty.
            field("timestamps", envelope.timestamps().len());
            println!();
        });
}

/// Prints one labelled field.
fn field(label: &str, value: impl fmt::Display) {
    field_list(label, [value.to_string()]);
}

/// Prints one labelled field over as many lines as it has values, the label
/// on the first. An empty list prints as an em dash.
fn field_list(label: &str, values: impl IntoIterator<Item = String>) {
    let mut values = values.into_iter();
    let Some(first) = values.next() else {
        println!("   {label:<LABEL$}  —");
        return;
    };

    println!("   {label:<LABEL$}  {first}");
    values.for_each(|value| println!("   {:<LABEL$}  {value}", ""));
}

/// A one-line summary of what a message does.
fn describe(msg: &Msg) -> String {
    match msg {
        Msg::Init(init) => format!(
            "init, {}",
            plural(init.state.namespaces.len(), "namespace", "namespaces")
        ),
        Msg::SetNamespace(set) => format!("set namespace {}", set.key),
        Msg::SetNamespaceKey(set) => match set.value {
            Some(_) => format!("set {} at {}", set.key, set.path),
            None => format!("clear {} at {}", set.key, set.path),
        },
        Msg::AmendNamespaceKey(amend) => {
            let target = amend.path.as_ref().map_or_else(
                || amend.key.to_string(),
                |path| format!("{} at {path}", amend.key),
            );
            match &amend.op {
                AmendOp::AppendEntry(_) => format!("append an entry to {target}"),
                AmendOp::IncrementDecrement(op) => format!("add {} to {target}", op.delta),
            }
        }
        Msg::DeleteNamespace(delete) => format!("delete namespace {}", delete.key),
    }
}

/// How an envelope's signatures scored, as stored — the status a node
/// resolves forks on, not one recomputed here.
fn describe_status(status: &VerificationStatus) -> String {
    match status {
        VerificationStatus::Unchecked => "unchecked".to_string(),
        VerificationStatus::Failed => "failed".to_string(),
        VerificationStatus::AllMatched { total_weight } => {
            format!("all matched, weight {total_weight}")
        }
    }
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}
