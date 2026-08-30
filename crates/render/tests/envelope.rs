//! What an envelope looks like to a person, pinned line for line.
//!
//! One rendering serves the daemon and the CLI both, so the stanza is a
//! contract between them rather than each one's private taste.

use chrono::{DateTime, FixedOffset, NaiveDate, Utc};
use render::{ColorChoice, Entry, Palette, Render};
use wire::{
    Envelope, EnvelopeDigest, Msg, VerificationStatus,
    keys::{Ed25519Signature, KeyId, Signature},
    msg::{
        AmendNamespaceKey, AmendOp, FullCheckpoint, IncrementDecrement, InitMsg, Match, Namespace,
        NamespaceKey, Predicate, SetNamespace, SetNamespaceKey, Value,
    },
    subkey::SubkeyPath,
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
   namespaces     cfg = 1
   verification   unchecked
   signed by      —
   timestamps     0
   stored         —

#1 {}  [head]
   prev           {}
   message        set namespace cfg
   value          2
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
   value          2
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

/// A path and the namespace it reaches into are painted apart, so a name
/// in one never reads as a name in the other.
#[test]
fn the_path_and_the_namespace_are_painted_apart() {
    let coloured = Render::new()
        .with_palette(Palette::Ansi)
        .envelope(&entry(2, write(Some(Value::Int(1)))));

    // Not through `field`: the escapes are the point, and it reads the
    // labels a palette has painted over.
    let message = coloured
        .lines()
        .find(|line| plain(line).starts_with("   message "))
        .expect("a stanza carries a message line");
    assert!(
        message.contains("servers\x1b[0m in namespace \x1b["),
        "the path closes before the namespace opens: got {message:?}",
    );
    assert!(
        plain(message).ends_with("set servers in namespace cfg"),
        "got {:?}",
        plain(message),
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

/// A write onto a path inside a namespace.
fn write(value: Option<Value>) -> Envelope {
    Envelope::new(Msg::SetNamespaceKey(SetNamespaceKey {
        prev: digest(1),
        key: key("cfg"),
        path: "servers".parse::<SubkeyPath>().unwrap(),
        value,
    }))
}

/// An amendment of the array at `cfg.servers`.
fn amend(op: AmendOp) -> Envelope {
    Envelope::new(Msg::AmendNamespaceKey(AmendNamespaceKey {
        prev: digest(1),
        key: key("cfg"),
        path: Some("servers".parse().unwrap()),
        op,
    }))
}

/// The lines of the field labelled `label`, unlabelled and undented — the
/// label sits on the first alone, so the rest are found by their column.
fn field(rendered: &str, label: &str) -> Vec<String> {
    rendered
        .lines()
        .skip_while(|line| !line.starts_with(&format!("   {label} ")))
        .take_while(|line| !line.is_empty())
        .enumerate()
        .take_while(|(index, line)| *index == 0 || line.starts_with("                  "))
        .map(|(_, line)| line[18..].to_string())
        .collect()
}

/// Small values are the point: an operator reading a write should see what
/// it wrote without going back to the daemon for it.
#[test]
fn a_value_that_fits_is_shown_whole_on_one_line() {
    let value = Value::Map(
        [
            ("host".to_string(), Value::String("10.0.0.1".to_string())),
            ("port".to_string(), Value::Int(4433)),
            ("tls".to_string(), Value::Bool(true)),
        ]
        .into(),
    );

    assert_eq!(
        field(
            &Render::new().envelope(&entry(2, write(Some(value)))),
            "value"
        ),
        [r#"{"host": "10.0.0.1", "port": 4433, "tls": true}"#],
    );
}

/// A value too wide for a line is broken over them, JSON-shaped, so what
/// it holds can still be read down the page.
#[test]
fn a_value_too_wide_for_a_line_is_broken_over_lines() {
    let value = Value::Map(
        [(
            "iroh".to_string(),
            Value::Map(
                [
                    ("endpoint_id".to_string(), Value::String("e5c8".repeat(4))),
                    (
                        "addrs".to_string(),
                        Value::Array(vec![Value::String("192.168.1.5:41234".to_string())]),
                    ),
                ]
                .into(),
            ),
        )]
        .into(),
    );

    assert_eq!(
        field(
            &Render::new().envelope(&entry(2, write(Some(value)))),
            "value"
        ),
        [
            "{",
            r#"  "iroh": {"#,
            r#"    "addrs": ["192.168.1.5:41234"],"#,
            r#"    "endpoint_id": "e5c8e5c8e5c8e5c8""#,
            "  }",
            "}",
        ],
    );
}

/// The screen is the budget: a value with more in it than a stanza holds
/// is cut off at a count of what was left out.
#[test]
fn a_value_larger_than_the_stanza_is_elided() {
    let value = Value::Array(
        (0..40)
            .map(|n| {
                Value::Map([("host".to_string(), Value::String(format!("10.0.0.{n}")))].into())
            })
            .collect(),
    );
    let lines = field(
        &Render::new().envelope(&entry(2, write(Some(value)))),
        "value",
    );

    assert_eq!(
        lines,
        [
            "[",
            r#"  {"host": "10.0.0.0"},"#,
            r#"  {"host": "10.0.0.1"},"#,
            r#"  {"host": "10.0.0.2"},"#,
            r#"  {"host": "10.0.0.3"},"#,
            r#"  {"host": "10.0.0.4"},"#,
            "  … 35 more",
            "]",
        ],
    );
}

/// No line runs past the width a stanza is written to, however deep the
/// value nests or however long one string in it runs.
#[test]
fn no_previewed_line_runs_past_the_stanza_s_width() {
    let deep = (0..12).fold(Value::String("x".repeat(400)), |value, depth| {
        Value::Map([(format!("level-{depth}"), value)].into())
    });
    let rendered = Render::new().envelope(&entry(2, write(Some(deep))));
    let lines = field(&rendered, "value");

    // Wide enough to be worth reading, narrow enough that the 18 columns
    // of label before it still leave the stanza inside 80.
    assert!(
        lines.iter().all(|line| line.chars().count() <= 60),
        "got {rendered}",
    );
    assert!(lines.len() > 1, "got {rendered}");
}

/// A long string is cut inside its quotes: one that ends mid-escape reads
/// as a broken value rather than a shortened one.
#[test]
fn a_long_string_is_elided_inside_its_quotes() {
    let value = Value::String("scootaloo ".repeat(20));
    let lines = field(
        &Render::new().envelope(&entry(2, write(Some(value)))),
        "value",
    );

    assert_eq!(lines.len(), 1, "got {lines:?}");
    assert!(
        lines[0].starts_with(r#""scootaloo scootaloo "#) && lines[0].ends_with(r#"…""#),
        "got {}",
        lines[0],
    );
}

/// Clearing a path writes no value, and the summary line already says so.
#[test]
fn a_cleared_path_shows_no_value() {
    let rendered = Render::new().envelope(&entry(2, write(None)));

    assert!(
        rendered.contains("   message        clear servers in namespace cfg\n"),
        "got {rendered}"
    );
    assert!(!rendered.contains("   value  "), "got {rendered}");
}

/// An appended entry is the whole of what the message writes.
#[test]
fn an_appended_entry_is_shown() {
    let entry_value =
        Value::Map([("host".to_string(), Value::String("10.0.0.9".to_string()))].into());
    let rendered = Render::new().envelope(&entry(2, amend(AmendOp::AppendEntry(entry_value))));

    assert_eq!(field(&rendered, "entry"), [r#"{"host": "10.0.0.9"}"#]);
}

/// A delete says what it matches on: the count in the summary line names
/// how many conditions there are, never what they look for.
#[test]
fn the_conditions_of_a_delete_are_listed() {
    let predicate = Predicate::try_new(vec![
        Match::at(
            "host".parse().unwrap(),
            Value::String("10.0.0.1".to_string()),
        ),
        Match::entry(Value::Int(3)),
    ])
    .unwrap();
    let rendered = Render::new().envelope(&entry(2, amend(AmendOp::DeleteMatching(predicate))));

    assert_eq!(
        field(&rendered, "matching"),
        [r#"host = "10.0.0.1""#, "entry = 3"],
    );
}

/// The delta alone says what an increment does only while it is unclamped:
/// where bounds are set, they are shown.
#[test]
fn an_increment_shows_the_bounds_it_clamps_to() {
    let clamped = amend(AmendOp::IncrementDecrement(
        IncrementDecrement::new(5).with_min(0).with_max(10),
    ));
    assert_eq!(
        field(&Render::new().envelope(&entry(2, clamped)), "clamped"),
        ["at least 0, at most 10"],
    );

    let plain = amend(AmendOp::IncrementDecrement(IncrementDecrement::new(-1)));
    let rendered = Render::new().envelope(&entry(2, plain));
    assert!(
        rendered.contains("   message        add -1 to servers in namespace cfg\n"),
        "got {rendered}"
    );
    assert!(!rendered.contains("clamped"), "got {rendered}");
}

/// A genesis of `namespaces`, in the order given.
fn init(namespaces: Vec<(&str, Value)>) -> Envelope {
    Envelope::new(Msg::Init(InitMsg {
        state: FullCheckpoint {
            namespaces: namespaces
                .into_iter()
                .map(|(name, value)| (key(name), Namespace { value }))
                .collect(),
        },
    }))
}

/// A genesis establishes what the ledger starts as, which is more than
/// the names it starts with.
#[test]
fn a_genesis_shows_what_its_namespaces_hold() {
    let rendered = Render::new().envelope(&entry(
        1,
        init(vec![
            ("cfg", Value::Int(1)),
            ("motd", Value::String("hello there".to_string())),
        ]),
    ));

    assert_eq!(
        field(&rendered, "namespaces"),
        ["cfg = 1", r#"motd = "hello there""#],
    );
}

/// The namespaces share the room one value gets, so a genesis carrying a
/// whole cluster stays a stanza: no one namespace spends the lines the
/// rest are shown in.
#[test]
fn the_namespaces_of_a_genesis_share_the_room_between_them() {
    let nodes = |count: u8| {
        Value::Map(
            (0..count)
                .map(|n| {
                    (
                        hex(n),
                        Value::Map(
                            [("iroh".to_string(), Value::String(format!("10.0.0.{n}")))].into(),
                        ),
                    )
                })
                .collect(),
        )
    };
    let rendered = Render::new().envelope(&entry(
        1,
        init(vec![
            ("keys", nodes(4)),
            ("nodes", nodes(9)),
            ("cfg", Value::Bool(true)),
        ]),
    ));
    let lines = field(&rendered, "namespaces");

    assert_eq!(lines.len(), 3, "got {lines:?}");
    assert!(
        lines
            .iter()
            .zip(["cfg = ", "keys = ", "nodes = "])
            .all(|(line, label)| line.starts_with(label)),
        "got {lines:?}",
    );
    assert!(
        lines[1].ends_with('…') && lines[2].ends_with('…'),
        "got {lines:?}",
    );
}

/// One namespace has the whole budget, and a value worth breaking over
/// lines is broken over them.
#[test]
fn a_lone_namespace_is_shown_over_as_many_lines_as_it_takes() {
    let value = Value::Map(
        [(
            "iroh".to_string(),
            Value::Map(
                [
                    ("addrs".to_string(), Value::Array(vec![Value::Int(1)])),
                    ("endpoint_id".to_string(), Value::String("e5c8".repeat(4))),
                ]
                .into(),
            ),
        )]
        .into(),
    );
    let rendered = Render::new().envelope(&entry(1, init(vec![("nodes", value)])));

    assert_eq!(
        field(&rendered, "namespaces"),
        [
            "nodes = {",
            r#"  "iroh": {"addrs": [1], "endpoint_id": "e5c8e5c8e5c8e5c8"}"#,
            "}",
        ],
    );
}
