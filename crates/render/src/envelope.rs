//! Rendering envelopes as stanzas a person reads.

use core::fmt;

use chrono::{DateTime, Local, Utc};
use wire::{Envelope, EnvelopeDigest, Msg, VerificationStatus, msg::AmendOp};

use crate::style::{Palette, Style};

/// Width the field labels are padded to.
const LABEL: usize = 13;

/// One envelope, as a rendering takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The digest it is shown under.
    pub digest: EnvelopeDigest,
    /// The envelope itself, carrying the verification status the node that
    /// holds it reached.
    pub envelope: Envelope,
    /// When that node's log first stored it, where that is known. Local
    /// bookkeeping off one machine's clock — shown because an operator
    /// reading a log wants it, never because anything acts on it.
    ///
    /// Held as the instant it names and shown in the zone the reader's
    /// machine is in, offset and all: an operator comparing a log against
    /// their own wall clock should not have to do the arithmetic, and the
    /// offset says which clock the reading was put into.
    pub stored_at: Option<DateTime<Utc>>,
}

impl Entry {
    /// An envelope with nothing known about when it arrived.
    pub fn new(digest: EnvelopeDigest, envelope: Envelope) -> Self {
        Self {
            digest,
            envelope,
            stored_at: None,
        }
    }

    /// The same entry, stamped with when its node first stored it.
    pub fn with_stored_at(mut self, stored_at: Option<DateTime<Utc>>) -> Self {
        self.stored_at = stored_at;
        self
    }
}

/// Renders envelopes, and chains of them.
///
/// Everything beyond the envelopes themselves is optional context the
/// caller supplies: which digests are worth marking, what to say the
/// envelopes came from, and whether to colour any of it.
#[derive(Debug, Default, Clone)]
pub struct Render {
    palette: Palette,
    root: Option<EnvelopeDigest>,
    head: Option<EnvelopeDigest>,
    header: Option<String>,
}

impl Render {
    /// A plain, unmarked rendering.
    pub fn new() -> Self {
        Self::default()
    }

    /// Renders in `palette`.
    pub fn with_palette(mut self, palette: Palette) -> Self {
        self.palette = palette;
        self
    }

    /// Marks `root` — the oldest envelope still held — where it is shown.
    pub fn with_root(mut self, root: EnvelopeDigest) -> Self {
        self.root = Some(root);
        self
    }

    /// Marks `head` — the canonical head — where it is shown.
    pub fn with_head(mut self, head: EnvelopeDigest) -> Self {
        self.head = Some(head);
        self
    }

    /// Says where a chain came from, in the line above it.
    pub fn with_header(mut self, header: impl Into<String>) -> Self {
        self.header = Some(header.into());
        self
    }

    /// Writes `envelopes` — a chain, oldest first — under a line counting
    /// them, one numbered stanza each.
    pub fn write_chain<W: fmt::Write>(&self, out: &mut W, envelopes: &[Entry]) -> fmt::Result {
        let count = plural(envelopes.len(), "envelope", "envelopes");
        let header = match &self.header {
            Some(header) => format!("{count} on {header}"),
            None => count,
        };
        writeln!(out, "{}\n", self.palette.paint(Style::Header, header))?;

        envelopes
            .iter()
            .enumerate()
            .try_for_each(|(index, entry)| self.write_stanza(out, Some(index), entry))
    }

    /// Writes one envelope's stanza, unnumbered: nothing says where it
    /// sits, only what it is.
    pub fn write_envelope<W: fmt::Write>(&self, out: &mut W, entry: &Entry) -> fmt::Result {
        self.write_stanza(out, None, entry)
    }

    /// The rendering of a chain, as [`write_chain`](Self::write_chain)
    /// writes it.
    pub fn chain(&self, envelopes: &[Entry]) -> String {
        let mut out = String::new();
        // Writing to a String is infallible; `fmt::Write` cannot say so.
        let _ = self.write_chain(&mut out, envelopes);
        out
    }

    /// The rendering of one envelope, as
    /// [`write_envelope`](Self::write_envelope) writes it.
    pub fn envelope(&self, entry: &Entry) -> String {
        let mut out = String::new();
        let _ = self.write_envelope(&mut out, entry);
        out
    }

    /// One envelope: its digest and marks on the first line, then a field
    /// per line, then a blank line.
    fn write_stanza<W: fmt::Write>(
        &self,
        out: &mut W,
        index: Option<usize>,
        entry: &Entry,
    ) -> fmt::Result {
        let Entry {
            digest,
            envelope,
            stored_at,
        } = entry;

        let number = index.map_or_else(String::new, |index| format!("#{index} "));
        let marks = [(self.root, "root"), (self.head, "head")]
            .into_iter()
            .filter_map(|(marked, mark)| (marked == Some(*digest)).then_some(mark))
            .collect::<Vec<_>>();
        let marks = match marks.is_empty() {
            true => String::new(),
            false => format!(
                "  {}",
                self.palette
                    .paint(Style::Mark, format!("[{}]", marks.join(", ")))
            ),
        };
        writeln!(out, "{number}{}{marks}", self.digest(digest))?;

        self.field(
            out,
            "prev",
            envelope.payload().prev_digest().map_or_else(
                || self.palette.paint(Style::Absent, "— (genesis)").to_string(),
                |prev| self.digest(prev).to_string(),
            ),
        )?;
        self.field(out, "message", describe(envelope.payload()))?;

        if let Msg::Init(init) = envelope.payload() {
            self.field_list(
                out,
                "namespaces",
                init.state.namespaces.keys().map(ToString::to_string),
            )?;
        }

        self.field(
            out,
            "verification",
            self.describe_status(envelope.verification_status()),
        )?;
        self.field_list(
            out,
            "signed by",
            envelope
                .signatures()
                .keys()
                .map(|id| id.to_hex().as_ref().to_string()),
        )?;

        // Nothing to show per timestamp while `SignedTimestamp` is empty.
        self.field(out, "timestamps", envelope.timestamps().len())?;
        // Last, and apart from the attested timestamps above on purpose:
        // this one is a note the local log made, not anything signed.
        self.field_list(
            out,
            "stored",
            stored_at.map(|at| {
                at.with_timezone(&Local)
                    .format("%Y-%m-%d %H:%M:%S%.3f %:z")
                    .to_string()
            }),
        )?;
        writeln!(out)
    }

    /// A digest in the colour digests are written in.
    fn digest(&self, digest: &EnvelopeDigest) -> impl fmt::Display {
        self.palette
            .paint(Style::Digest, digest.to_hex().as_ref().to_string())
    }

    /// Writes one labelled field.
    fn field<W: fmt::Write>(
        &self,
        out: &mut W,
        label: &str,
        value: impl fmt::Display,
    ) -> fmt::Result {
        self.field_list(out, label, [value.to_string()])
    }

    /// Writes one labelled field over as many lines as it has values, the
    /// label on the first. An empty list writes as an em dash.
    ///
    /// The label is padded before it is painted: an escape sequence is
    /// bytes the terminal never shows, and a width counts what it does.
    fn field_list<W: fmt::Write>(
        &self,
        out: &mut W,
        label: &str,
        values: impl IntoIterator<Item = String>,
    ) -> fmt::Result {
        let label = self.palette.paint(Style::Label, format!("{label:<LABEL$}"));

        let mut values = values.into_iter();
        let Some(first) = values.next() else {
            return writeln!(
                out,
                "   {label}  {}",
                self.palette.paint(Style::Absent, "—")
            );
        };

        writeln!(out, "   {label}  {first}")?;
        values.try_for_each(|value| writeln!(out, "   {:<LABEL$}  {value}", ""))
    }

    /// How an envelope's signatures scored, as stored — the status a node
    /// resolves forks on, not one recomputed here.
    fn describe_status(&self, status: &VerificationStatus) -> impl fmt::Display {
        let (style, text) = match status {
            VerificationStatus::Unchecked => (Style::Unknown, "unchecked".to_string()),
            VerificationStatus::Failed => (Style::Bad, "failed".to_string()),
            VerificationStatus::AllMatched { total_weight } => {
                (Style::Good, format!("all matched, weight {total_weight}"))
            }
        };
        self.palette.paint(style, text)
    }
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

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}
