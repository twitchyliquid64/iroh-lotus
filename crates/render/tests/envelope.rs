//! What an envelope looks like to a person, pinned line for line.
//!
//! One rendering serves the daemon and the CLI both, so the stanza is a
//! contract between them rather than each one's private taste.

use chrono::{DateTime, FixedOffset, NaiveDate, Utc};
use render::{ColorChoice, Entry, Palette, Render};
use wire::{
    Envelope, EnvelopeDigest, Msg, VerificationStatus,
    keys::{Ed25519Signature, KeyId, Signature},
    msg::{FullCheckpoint, InitMsg, Namespace, NamespaceKey, SetNamespace, Value},
};

/// The digest an envelope is filed under. Made up: what is rendered is the
/// digest it is shown under, which the caller supplies.
fn digest(byte: u8) -> EnvelopeDigest {
    EnvelopeDigest::from_bytes([byte; 32])
}

/// A fixed reading, so what is rendered doesn't move with the clock.
fn stored_at() -> DateTime<Utc> {
    NaiveDate::from_ymd_opt(2026, 8, 27)
        .unwrap()
        .and_hms_milli_opt(12, 43, 1, 250)
        .unwrap()
        .and_utc()
}

fn hex(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn key(k: &str) -> NamespaceKey {
    NamespaceKey::try_new(k).unwrap()
}

/// A genesis carrying one namespace.
fn genesis() -> Envelope {
    Envelope::new(Msg::Init(InitMsg {
        state: FullCheckpoint {
            namespaces: [(
                key("cfg"),
                Namespace {
                    value: Value::Int(1),
                },
            )]
            .into(),
        },
    }))
}

/// A write onto `prev`.
fn set(prev: EnvelopeDigest) -> Envelope {
    Envelope::new(Msg::SetNamespace(SetNamespace {
        prev,
        key: key("cfg"),
        namespace: Namespace {
            value: Value::Int(2),
        },
    }))
}

/// An entry with nothing known about when it arrived, which is most of
/// what these tests render.
fn entry(digest_byte: u8, envelope: Envelope) -> Entry {
    Entry::new(digest(digest_byte), envelope)
}

fn signed(envelope: Envelope, byte: u8) -> Envelope {
    envelope.with_signature(
        KeyId::from_bytes([byte; 32]),
        Signature::Ed25519(Ed25519Signature::from_bytes([0xcd; 64])),
    )
}

/// Strips every SGR sequence, leaving what a terminal would actually show.
fn plain(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find('\x1b') {
        out.push_str(&rest[..start]);
        let end = rest[start..]
            .find('m')
            .expect("every sequence this crate writes ends in `m`");
        rest = &rest[start + end + 1..];
    }
    out.push_str(rest);
    out
}

#[test]
fn a_chain_renders_a_numbered_stanza_per_envelope() {
    let chain = [entry(1, genesis()), entry(2, set(digest(1)))];
    let rendered = Render::new()
        .with_root(digest(1))
        .with_head(digest(2))
        .chain(&chain);

    assert_eq!(
        rendered,
        format!(
            "\
2 envelopes

#0 {}  [root]
   prev           — (genesis)
   message        init, 1 namespace
   namespaces     cfg
   verification   unchecked
   signed by      —
   timestamps     0
   stored         —

#1 {}  [head]
   prev           {}
   message        set namespace cfg
   verification   unchecked
   signed by      —
   timestamps     0
   stored         —

",
            hex(1),
            hex(2),
            hex(1),
        ),
    );
}

/// The header says where the envelopes came from when the caller knows.
#[test]
fn a_header_names_where_the_chain_came_from() {
    let rendered = Render::new()
        .with_header("/run/lotus/local.sock")
        .chain(&[entry(1, genesis())]);

    assert!(
        rendered.starts_with("1 envelope on /run/lotus/local.sock\n\n"),
        "got {rendered}",
    );
}

/// An empty chain still says so rather than printing nothing at all.
#[test]
fn an_empty_chain_renders_only_its_count() {
    assert_eq!(Render::new().chain(&[]), "0 envelopes\n\n");
}

/// The two marks are independent, and a one-envelope chain wears both.
#[test]
fn an_envelope_that_is_both_ends_of_the_chain_is_marked_twice() {
    let rendered = Render::new()
        .with_root(digest(1))
        .with_head(digest(1))
        .chain(&[entry(1, genesis())]);

    assert!(rendered.contains(&format!("#0 {}  [root, head]\n", hex(1))));
}

/// Nothing is marked when the caller says nothing about the chain's ends —
/// which is the CLI fetching envelopes it has no range for.
#[test]
fn nothing_is_marked_without_a_root_or_head() {
    let rendered = Render::new().chain(&[entry(1, genesis())]);

    assert!(rendered.contains(&format!("#0 {}\n", hex(1))));
}

/// A lone envelope carries no number: nothing says where it sits.
#[test]
fn one_envelope_renders_unnumbered() {
    let rendered = Render::new().envelope(&entry(2, set(digest(1))));

    assert_eq!(
        rendered,
        format!(
            "\
{}
   prev           {}
   message        set namespace cfg
   verification   unchecked
   signed by      —
   timestamps     0
   stored         —

",
            hex(2),
            hex(1),
        ),
    );
}

/// The status is reported as stored, never recomputed here: what a node
/// resolves forks on is what an operator has to be shown.
#[test]
fn verification_is_reported_as_the_envelope_holds_it() {
    let statuses = [
        (VerificationStatus::Unchecked, "unchecked"),
        (
            VerificationStatus::Failed {
                failing_key_ids: [KeyId::from_bytes([3u8; 32])].into(),
            },
            "failed, 1 bad signature",
        ),
        (
            VerificationStatus::Failed {
                failing_key_ids: [KeyId::from_bytes([3u8; 32]), KeyId::from_bytes([4u8; 32])]
                    .into(),
            },
            "failed, 2 bad signatures",
        ),
        (
            VerificationStatus::AllMatched { total_weight: 5 },
            "all matched, weight 5",
        ),
    ];

    for (status, expected) in statuses {
        let mut envelope = genesis();
        envelope.set_verification_status(status);

        assert!(
            Render::new()
                .envelope(&entry(1, envelope))
                .contains(&format!("   verification   {expected}\n")),
            "expected {expected}",
        );
    }
}

/// Every signer gets a line, the label only on the first.
#[test]
fn signers_are_listed_one_per_line_under_a_single_label() {
    let envelope = signed(signed(genesis(), 0x11), 0xee);

    assert!(
        Render::new()
            .envelope(&entry(1, envelope.clone()))
            .contains(&format!(
                "   signed by      {}\n                  {}\n",
                hex(0x11),
                hex(0xee),
            )),
        "got {}",
        Render::new().envelope(&entry(1, envelope)),
    );
}

/// Colour is decoration and nothing else: strip it and the same rendering
/// is left, so the two palettes can never drift into saying different
/// things.
#[test]
fn colour_only_wraps_what_the_plain_rendering_already_says() {
    let chain = [
        entry(1, genesis()).with_stored_at(Some(stored_at())),
        entry(2, set(digest(1))),
    ];
    let render = Render::new().with_root(digest(1)).with_head(digest(2));

    let coloured = render.clone().with_palette(Palette::Ansi).chain(&chain);
    assert_ne!(coloured, render.chain(&chain), "nothing was coloured");
    assert_eq!(plain(&coloured), render.chain(&chain));
}

/// A label is padded before it is painted: escape bytes are not columns,
/// so padding the painted label would shift every value on the line.
#[test]
fn colour_does_not_disturb_the_columns() {
    let coloured = Render::new()
        .with_palette(Palette::Ansi)
        .envelope(&entry(1, genesis()));

    assert!(
        plain(&coloured).contains("   verification   unchecked\n"),
        "got {}",
        plain(&coloured),
    );
}

/// Both palettes reset what they set, so nothing bleeds past the value it
/// was meant to colour.
#[test]
fn every_sequence_is_closed() {
    let coloured = Render::new()
        .with_palette(Palette::Ansi)
        .with_head(digest(1))
        .chain(&[entry(1, genesis())]);

    assert_eq!(
        coloured.matches("\x1b[0m").count(),
        coloured.matches('\x1b').count() - coloured.matches("\x1b[0m").count(),
        "every opening sequence needs its reset",
    );
}

/// Something that is not a terminal is not coloured, whatever the terminal
/// the process was started from does.
#[test]
fn auto_does_not_colour_what_is_not_a_terminal() {
    // `IsTerminal` is sealed, so this takes a real handle that isn't one.
    let sink = std::fs::File::create("/dev/null").unwrap();

    assert_eq!(ColorChoice::Auto.palette(&sink), Palette::Plain);
    assert_eq!(ColorChoice::Never.palette(&sink), Palette::Plain);
    // `Always` is what a caller redirecting to a pager or a test reaches for.
    assert_eq!(ColorChoice::Always.palette(&sink), Palette::Ansi);
}

/// The time the log took an envelope is shown where it is known, and reads
/// as absent where it is not — a log written before anything recorded one.
///
/// Read back through the offset it carries rather than compared against a
/// fixed string: the zone is the one the machine running this is in, so
/// the digits move with the host while the instant may not.
#[test]
fn the_time_the_log_took_an_envelope_is_shown_where_it_is_known() {
    let stamped = Render::new().envelope(&entry(1, genesis()).with_stored_at(Some(stored_at())));
    let shown = stamped
        .lines()
        .find_map(|line| line.trim().strip_prefix("stored"))
        .expect("the stanza carries a stored field")
        .trim();

    assert_eq!(
        DateTime::<FixedOffset>::parse_from_str(shown, "%Y-%m-%d %H:%M:%S%.3f %:z")
            .unwrap_or_else(|e| panic!("{shown:?} is not a zoned reading: {e}"))
            .to_utc(),
        stored_at(),
    );

    let unstamped = Render::new().envelope(&entry(1, genesis()));
    assert!(
        unstamped.contains("   stored         —\n"),
        "got {unstamped}",
    );
}
