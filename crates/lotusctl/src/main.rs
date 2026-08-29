use std::{collections::BTreeMap, fmt, path::PathBuf, process::ExitCode, time::Duration};

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use lotusd_rpc::{
    Call, ChainWalk, CreateInvite, EnvelopeFrame, GetChainRange, GetEnvelopes, GetStatus,
    GetVersion, InviteCode, NamespaceChange, NodeStatus, Read, ValueAt, Watch, WatchEvent,
    WatchSelector, WeakDelete, WeakIncrement, WeakPush, WeakSet, WriteOutcome, Written, call,
};
use render::{ColorChoice, Entry, Render};
use tokio::net::UnixStream;
use tokio::runtime::Builder;
use wire::{
    EnvelopeDigest,
    msg::{NamespaceKey, Value},
    subkey::SubkeyPath,
};

/// The version of this CLI.
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "lotusctl", version = VERSION)]
#[command(about = "Controls a running iroh-lotus daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[command(flatten)]
    global_args: GlobalArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Generate shell completion script
    #[command(
        long_about = "Generate a shell tab-completion script for lotusctl.\nSupported shells include bash, zsh, elvish and fish.\n\n   source <(lotusctl completions bash)"
    )]
    Completions(CompletionsArgs),
    /// Prints the canonical chain the daemon holds, oldest envelope first
    Chain(ChainCommand),
    /// Prints the envelopes named, wherever they sit in the daemon's log
    Show(ShowCommand),
    /// Prints a value from a namespace, and the head it was read at
    Read(ReadCommand),
    /// Writes a value into a namespace, signed by the daemon's own key
    #[command(
        long_about = "Writes a value into a namespace, signed by the daemon's own key.\n\n\
        The write is chained onto whatever head the daemon stands at, with no \
        precondition on what was there before, and carries this one node's \
        signature. With --path, the value replaces what the path addresses; every \
        parent of it must already exist. Without, the whole namespace is set, and \
        created if the ledger does not hold it.\n\n\
        The value is always a JSON literal: a string, a whole number, true or \
        false, an array or an object. A string is quoted even when it is one \
        word, so `weak-set cfg '\"hello\"'` writes the string hello and \
        `weak-set cfg 7` the number 7."
    )]
    WeakSet(WeakSetCommand),
    /// Appends a value to an array in a namespace, signed by the daemon's
    /// own key
    #[command(
        long_about = "Appends a value to an array in a namespace, signed by the daemon's own key.\n\n\
        Chained onto whatever head the daemon stands at, as weak-set is. With \
        --path, the value is appended to the array the path addresses; a path \
        addressing nothing under an existing map starts a one-entry array. \
        Without, the namespace's whole value must be one array.\n\n\
        The value is always a JSON literal, strings quoted."
    )]
    WeakPush(WeakPushCommand),
    /// Clears a value in a namespace, or deletes the namespace, signed by
    /// the daemon's own key
    #[command(
        long_about = "Clears a value in a namespace, or deletes the namespace, signed by the daemon's own key.\n\n\
        Chained onto whatever head the daemon stands at, as weak-set is. With \
        --path, what the path addresses is removed — a key from its map, an \
        element from its array — and must exist. Without, the whole namespace \
        is deleted."
    )]
    WeakDelete(WeakDeleteCommand),
    /// Adds to an integer in a namespace, signed by the daemon's own key
    #[command(
        long_about = "Adds to an integer in a namespace, signed by the daemon's own key.\n\n\
        Chained onto whatever head the daemon stands at, as weak-set is. With \
        --path, the delta is added to the integer the path addresses; without, \
        the namespace's whole value must be one integer. Either way it must \
        already exist. A negative delta decrements. The sum is clamped up to \
        --min and down to --max where they are given."
    )]
    WeakIncrement(WeakIncrementCommand),
    /// Invites a new node into the cluster, printing the word it joins with
    #[command(
        long_about = "Invites a new node into the cluster, printing the word it joins with.\n\n\
        Run `lotusd bootstrap <word>` on a blank node: it dials this daemon, \
        pulls the chain, and is then admitted — its key trusted at --weight and \
        its endpoint listed — by this daemon's signature alone. The word carries \
        a one-time secret the daemon keeps in memory until it is used or --ttl \
        passes, so treat it as a credential and hand it over privately."
    )]
    Invite(InviteCommand),
    /// Reports who the daemon is, how much of the chain it holds, and how
    /// it stands with its peers
    Status,
    /// Reports this CLI's version alongside the daemon's
    Version,
    /// Reports movements of the chain as they happen, until interrupted
    Watch(WatchCommand),
}

/// The arguments for the chain subcommand.
#[derive(Debug, Args)]
struct ChainCommand {
    /// Print at most this many envelopes, counted back from the head
    #[arg(long, short = 'n')]
    limit: Option<u32>,

    /// Print only what the daemon stored within this window, written like
    /// `90s`, `15m`, `2h` or `7d`
    ///
    /// Measured on the daemon's clock, against the time its log first saw
    /// each envelope — for looking at what has been arriving, never a
    /// statement about when anything was signed.
    #[arg(long, value_parser = parse_window)]
    since: Option<Duration>,
}

impl ChainCommand {
    /// The walk these arguments ask the daemon for.
    fn walk(&self) -> ChainWalk {
        let walk = self.limit.map_or_else(ChainWalk::default, |limit| {
            ChainWalk::default().with_limit(limit)
        });
        self.since.map_or(walk, |since| walk.with_since(since))
    }
}

/// Reads a window like `90s`, `15m`, `2h` or `7d`, for clap. A bare number
/// is seconds; `ms` is there because the protocol carries milliseconds.
fn parse_window(text: &str) -> Result<Duration, String> {
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (count, unit) = text.split_at(split);

    let count: u64 = count
        .parse()
        .map_err(|_| format!("`{text}` is not a window; write one like 90s, 15m, 2h or 7d"))?;
    let millis = match unit {
        "ms" => 1,
        "" | "s" => 1_000,
        "m" => 60 * 1_000,
        "h" => 60 * 60 * 1_000,
        "d" => 24 * 60 * 60 * 1_000,
        unit => return Err(format!("`{unit}` is not a unit; use ms, s, m, h or d")),
    };

    count
        .checked_mul(millis)
        .map(Duration::from_millis)
        .ok_or_else(|| format!("`{text}` is a longer window than any log covers"))
}

/// The arguments for the show subcommand.
#[derive(Debug, Args)]
struct ShowCommand {
    /// The envelope digests to print, in hex
    #[arg(value_parser = parse_digest, required = true)]
    digests: Vec<EnvelopeDigest>,
}

/// The arguments for the read subcommand.
#[derive(Debug, Args)]
struct ReadCommand {
    /// The namespace to read
    #[arg(value_parser = parse_namespace_key)]
    key: NamespaceKey,

    /// A path within it, written as `servers[0].host`; the whole
    /// namespace when left out
    path: Option<SubkeyPath>,

    /// Print the value in the ledger's tagged JSON form, which spells
    /// every value type — `{"type": "int", "value": 7}` — where the plain
    /// form prints a trusted key in that form and everything else bare
    #[arg(long)]
    tagged: bool,
}

/// The arguments for the weak-set subcommand.
#[derive(Debug, Args)]
struct WeakSetCommand {
    /// The namespace to write to
    #[arg(value_parser = parse_namespace_key)]
    key: NamespaceKey,

    /// The value to write, as a JSON literal — strings quoted
    value: String,

    /// The path within the namespace to set, written as `servers[0].host`;
    /// the whole namespace when left out
    #[arg(long, short)]
    path: Option<SubkeyPath>,

    /// Read the value in the ledger's tagged JSON form,
    /// `{"type": "int", "value": 7}`, which can spell a trusted key
    #[arg(long)]
    tagged: bool,
}

impl WeakSetCommand {
    /// The value these arguments write.
    fn value(&self) -> Result<Value, MainError> {
        parse_value(&self.value, self.tagged)
    }
}

/// The arguments for the weak-push subcommand.
#[derive(Debug, Args)]
struct WeakPushCommand {
    /// The namespace to write to
    #[arg(value_parser = parse_namespace_key)]
    key: NamespaceKey,

    /// The value to append, as a JSON literal — strings quoted
    value: String,

    /// The path of the array within the namespace, written as
    /// `servers[0].tags`; the namespace's whole value when left out
    #[arg(long, short)]
    path: Option<SubkeyPath>,

    /// Read the value in the ledger's tagged JSON form,
    /// `{"type": "int", "value": 7}`, which can spell a trusted key
    #[arg(long)]
    tagged: bool,
}

impl WeakPushCommand {
    /// The value these arguments append.
    fn value(&self) -> Result<Value, MainError> {
        parse_value(&self.value, self.tagged)
    }
}

/// The arguments for the weak-delete subcommand.
#[derive(Debug, Args)]
struct WeakDeleteCommand {
    /// The namespace to write to
    #[arg(value_parser = parse_namespace_key)]
    key: NamespaceKey,

    /// The path within the namespace to clear, written as
    /// `servers[0].host`; the whole namespace is deleted when left out
    #[arg(long, short)]
    path: Option<SubkeyPath>,
}

/// The arguments for the weak-increment subcommand.
#[derive(Debug, Args)]
struct WeakIncrementCommand {
    /// The namespace to write to
    #[arg(value_parser = parse_namespace_key)]
    key: NamespaceKey,

    /// How much to add; negative to subtract
    #[arg(allow_negative_numbers = true)]
    delta: i64,

    /// The path of the integer within the namespace, written as
    /// `servers[0].weight`; the namespace's whole value when left out
    #[arg(long, short)]
    path: Option<SubkeyPath>,

    /// Clamp the sum up to this floor
    #[arg(long, allow_negative_numbers = true)]
    min: Option<i64>,

    /// Clamp the sum down to this ceiling
    #[arg(long, allow_negative_numbers = true)]
    max: Option<i64>,
}

/// Reads a value from the command line: a JSON literal, or the ledger's
/// tagged form when `tagged`.
fn parse_value(text: &str, tagged: bool) -> Result<Value, MainError> {
    if tagged {
        return serde_json::from_str(text)
            .map_err(|e| MainError::Other(format!("`{text}` is not a tagged value: {e}")));
    }
    serde_json::from_str(text)
        .map_err(|e| {
            MainError::Other(format!(
                "`{text}` is not JSON: {e}; a string is written quoted, as '\"text\"'"
            ))
        })
        .and_then(value_from_json)
}

/// Reads a plain JSON value as a ledger value: objects are maps, numbers
/// must be whole and fit an `i64`, and `null` is nothing the ledger holds.
fn value_from_json(json: serde_json::Value) -> Result<Value, MainError> {
    match json {
        serde_json::Value::String(text) => Ok(Value::String(text)),
        serde_json::Value::Bool(flag) => Ok(Value::Bool(flag)),
        serde_json::Value::Number(number) => number.as_i64().map(Value::Int).ok_or_else(|| {
            MainError::Other(format!("{number} is not a whole number an i64 holds"))
        }),
        serde_json::Value::Array(items) => items
            .into_iter()
            .map(value_from_json)
            .collect::<Result<_, _>>()
            .map(Value::Array),
        serde_json::Value::Object(fields) => fields
            .into_iter()
            .map(|(key, value)| value_from_json(value).map(|value| (key, value)))
            .collect::<Result<_, _>>()
            .map(Value::Map),
        serde_json::Value::Null => Err(MainError::Other(
            "null is not a value the ledger holds".to_string(),
        )),
    }
}

/// Writes a ledger value as plain JSON: maps are objects, and a trusted
/// key — which plain JSON has no shape for — is written in the ledger's
/// tagged form, `{"type": "key", "value": …}`.
fn value_to_json(value: &Value) -> Result<serde_json::Value, MainError> {
    Ok(match value {
        Value::String(text) => serde_json::Value::String(text.clone()),
        Value::Int(n) => serde_json::Value::from(*n),
        Value::Bool(flag) => serde_json::Value::Bool(*flag),
        Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(value_to_json).collect::<Result<_, _>>()?)
        }
        Value::Map(fields) => serde_json::Value::Object(
            fields
                .iter()
                .map(|(key, value)| value_to_json(value).map(|value| (key.clone(), value)))
                .collect::<Result<_, _>>()?,
        ),
        Value::Key(_) => serde_json::to_value(value).map_err(MainError::Json)?,
    })
}

/// What `read` reports.
#[derive(Debug, serde::Serialize)]
struct ReadLine {
    head: EnvelopeDigest,
    /// The value as JSON — plain or tagged as asked — or `null` when the
    /// daemon holds nothing at the path.
    value: serde_json::Value,
}

impl ReadLine {
    fn new(at: ValueAt, tagged: bool) -> Result<Self, MainError> {
        let value = match at.value {
            None => serde_json::Value::Null,
            Some(value) if tagged => serde_json::to_value(&value).map_err(MainError::Json)?,
            Some(value) => value_to_json(&value)?,
        };
        Ok(Self {
            head: at.head,
            value,
        })
    }
}

impl fmt::Display for ReadLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "head   {}", self.head.to_hex().as_ref())?;
        match &self.value {
            serde_json::Value::Null => writeln!(f, "value  — (not set)"),
            value => writeln!(f, "value  {value}"),
        }
    }
}

/// What `weak-set` reports.
#[derive(Debug, serde::Serialize)]
struct WrittenLine {
    envelope: EnvelopeDigest,
    head: EnvelopeDigest,
    outcome: WriteOutcome,
}

impl From<Written> for WrittenLine {
    fn from(written: Written) -> Self {
        Self {
            envelope: written.digest,
            head: written.head,
            outcome: written.outcome,
        }
    }
}

impl fmt::Display for WrittenLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "envelope  {}", self.envelope.to_hex().as_ref())?;
        writeln!(f, "head      {}", self.head.to_hex().as_ref())?;
        writeln!(f, "outcome   {}", self.outcome)
    }
}

/// The arguments for the watch subcommand.
#[derive(Debug, Args)]
struct WatchCommand {
    #[command(subcommand)]
    watch: WatchArgs,

    /// Stop after this many events rather than running until interrupted
    ///
    /// Global so it reads naturally after what is being watched:
    /// `watch head -n 1`.
    #[arg(long, short = 'n', global = true)]
    count: Option<u32>,
}

/// What `watch` follows. One per invocation: a connection carries one
/// request, so watching two things means two invocations.
#[derive(Debug, Subcommand)]
enum WatchArgs {
    /// Every movement of the canonical head, whatever it changed
    Head,
    /// Any change anywhere under a namespace
    Namespace {
        /// The namespace to watch
        #[arg(value_parser = parse_namespace_key)]
        key: NamespaceKey,
    },
    /// A change to one value inside a namespace
    Path {
        /// The namespace the path is walked from
        #[arg(value_parser = parse_namespace_key)]
        key: NamespaceKey,
        /// The path within it, written as `servers[0].host`
        path: SubkeyPath,
    },
    /// An envelope leaving the canonical chain, as a reorg rewrites past it
    Orphaned {
        /// The envelope digest to watch, in hex
        #[arg(value_parser = parse_digest)]
        digest: EnvelopeDigest,
    },
}

impl WatchArgs {
    /// What this asks the daemon to watch.
    fn selector(&self) -> WatchSelector {
        match self {
            WatchArgs::Head => WatchSelector::Head,
            WatchArgs::Namespace { key } => WatchSelector::Namespace(key.clone()),
            WatchArgs::Path { key, path } => WatchSelector::Path(lotusd_rpc::WatchPath {
                key: key.clone(),
                path: path.clone(),
            }),
            WatchArgs::Orphaned { digest } => WatchSelector::Orphaned(*digest),
        }
    }
}

/// Reads a namespace key, for clap.
fn parse_namespace_key(text: &str) -> Result<NamespaceKey, String> {
    NamespaceKey::try_new(text).map_err(|e| e.to_string())
}

/// Reads an envelope digest from hex, for clap.
fn parse_digest(text: &str) -> Result<EnvelopeDigest, String> {
    EnvelopeDigest::from_hex(text).map_err(|e| e.to_string())
}

/// The arguments for the invite subcommand.
#[derive(Debug, Args)]
struct InviteCommand {
    /// The weight the new node's key is trusted at
    #[arg(long, default_value_t = 1)]
    weight: u32,

    /// How long the invite stays good, written like `90s`, `15m` or `2h`;
    /// the daemon caps it
    #[arg(long, value_parser = parse_window, default_value = "10m")]
    ttl: Duration,
}

/// What `invite` reports.
#[derive(Debug, serde::Serialize)]
struct InviteLine {
    invite: String,
    expires_in_millis: u64,
}

impl From<InviteCode> for InviteLine {
    fn from(code: InviteCode) -> Self {
        Self {
            invite: code.text,
            expires_in_millis: code.expires_in_millis,
        }
    }
}

impl fmt::Display for InviteLine {
    /// The word on a line of its own, so a double-click selects exactly it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "On the new node, run:")?;
        writeln!(f)?;
        writeln!(f, "    lotusd bootstrap {}", self.invite)?;
        writeln!(f)?;
        writeln!(
            f,
            "The invite admits one node and expires in {}.",
            window(Duration::from_millis(self.expires_in_millis))
        )
    }
}

/// A duration as a person would write it: `10m`, `90s`, `2h`.
fn window(duration: Duration) -> String {
    let secs = duration.as_secs();
    match secs {
        s if s % 3600 == 0 && s > 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 && s > 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// The arguments for the completions subcommand.
#[derive(Debug, clap::Args)]
struct CompletionsArgs {
    /// The shell type for a CLI completion script should be printed
    #[arg(value_parser)]
    shell: Shell,
}

/// Shared arguments for all subcommands.
#[derive(Debug, Args)]
struct GlobalArgs {
    /// Override the directory where state is stored (default: $XDG_STATE_DIR/iroh-lotus)
    #[arg(long, alias = "sd")]
    state_dir: Option<PathBuf>,

    /// How to render output
    #[arg(long, short, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// When to colour the output. JSON is never coloured
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,
}

/// How a command renders what it read.
#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Labelled lines, for a human
    Text,
    /// One JSON object
    Json,
}

impl GlobalArgs {
    /// StateDir returns the directory where daemon state is stored: the `--state-dir`
    /// override when given, otherwise `iroh-lotus` under the platform state directory
    /// (`$XDG_STATE_HOME`, falling back to `~/.local/state`, on Linux).
    ///
    /// Fails only when no home directory can be determined.
    fn state_dir(&self) -> Result<PathBuf, MainError> {
        self.state_dir
            .clone()
            .or_else(|| {
                dirs::state_dir()
                    .or_else(dirs::data_local_dir)
                    .map(|dir| dir.join("iroh-lotus"))
            })
            .ok_or_else(|| {
                MainError::Other(
                    "no state directory found; pass --state-dir to set one".to_string(),
                )
            })
    }

    /// The path to the local control socket.
    fn local_sock_path(&self) -> Result<PathBuf, MainError> {
        self.state_dir().map(|sd| sd.join("local.sock"))
    }
}

/// What `version` reports.
#[derive(Debug, serde::Serialize)]
struct Versions {
    client: String,
    daemon: String,
}

/// One line of what `watch` reports.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum WatchLine {
    /// The chain moved.
    Changed {
        from: EnvelopeDigest,
        head: EnvelopeDigest,
        /// Each changed namespace, against the paths touched inside it —
        /// empty when the namespace changed as a whole.
        changes: BTreeMap<String, Vec<String>>,
        orphaned: Vec<String>,
    },
    /// The envelope asked about had already left the chain.
    AlreadyOrphaned { digest: String },
}

impl From<WatchEvent> for WatchLine {
    fn from(event: WatchEvent) -> Self {
        match event {
            WatchEvent::Changed(changed) => WatchLine::Changed {
                from: changed.from,
                head: changed.head,
                changes: changed
                    .changes
                    .into_iter()
                    .map(|(key, change)| {
                        let paths = match change {
                            NamespaceChange::Whole => Vec::new(),
                            NamespaceChange::Paths(paths) => {
                                paths.iter().map(SubkeyPath::to_string).collect()
                            }
                        };
                        (key.into_inner(), paths)
                    })
                    .collect(),
                orphaned: changed
                    .orphaned
                    .iter()
                    .map(|digest| digest.to_hex().as_ref().to_owned())
                    .collect(),
            },
            WatchEvent::AlreadyOrphaned(digest) => WatchLine::AlreadyOrphaned {
                digest: digest.to_hex().as_ref().to_owned(),
            },
        }
    }
}

impl fmt::Display for WatchLine {
    /// One event, one block: a header line and an indented line per thing
    /// that changed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WatchLine::Changed {
                from,
                head,
                changes,
                orphaned,
            } => {
                writeln!(
                    f,
                    "changed  {} -> {}",
                    from.to_hex().as_ref(),
                    head.to_hex().as_ref(),
                )?;
                changes.iter().try_for_each(|(key, paths)| {
                    if paths.is_empty() {
                        writeln!(f, "  {key}  (whole namespace)")
                    } else {
                        paths
                            .iter()
                            .try_for_each(|path| writeln!(f, "  {key}  {path}"))
                    }
                })?;
                orphaned
                    .iter()
                    .try_for_each(|digest| writeln!(f, "  orphaned  {digest}"))
            }
            WatchLine::AlreadyOrphaned { digest } => {
                writeln!(f, "already orphaned  {digest}")
            }
        }
    }
}

fn main() -> ExitCode {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime needs no resources to start");

    let res = runtime.block_on(async_main());
    drop(runtime);

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:?}");
            ExitCode::FAILURE
        }
    }
}

async fn async_main() -> Result<(), MainError> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Completions(args) => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(args.shell, &mut cmd, name, &mut std::io::stdout());
        }
        Command::Chain(args) => {
            let path = cli.global_args.local_sock_path()?;
            let frames = envelopes(&path, GetEnvelopes::walk(args.walk())).await?;

            match cli.global_args.format {
                Format::Json => print_json(&frames)?,
                Format::Text => print!(
                    "{}",
                    renderer(&cli.global_args, &path)
                        .await?
                        .with_header(path.display().to_string())
                        .chain(&entries(frames))
                ),
            }
        }
        Command::Show(args) => {
            let path = cli.global_args.local_sock_path()?;
            let frames = envelopes(&path, GetEnvelopes::digests(args.digests.clone())).await?;
            let missing = missing(&args.digests, &frames);

            match cli.global_args.format {
                Format::Json => print_json(&frames)?,
                Format::Text => {
                    let render = renderer(&cli.global_args, &path).await?;
                    entries(frames)
                        .iter()
                        .for_each(|entry| print!("{}", render.envelope(entry)));
                }
            }

            // Reported after what was found, so a typo in one digest does
            // not cost the answer to the others.
            if !missing.is_empty() {
                return Err(MainError::Other(format!(
                    "the daemon holds no envelope {}",
                    missing
                        .iter()
                        .map(|digest| digest.to_hex().as_ref().to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                )));
            }
        }
        Command::Read(args) => {
            let path = cli.global_args.local_sock_path()?;
            let at = call(
                connect(&path).await?,
                Read {
                    key: args.key.clone(),
                    path: args.path.clone(),
                },
            )
            .await
            .map_err(MainError::Rpc)?;
            let line = ReadLine::new(at, args.tagged)?;

            match cli.global_args.format {
                Format::Text => print!("{line}"),
                Format::Json => print_json(&line)?,
            }
        }
        Command::WeakSet(args) => {
            let value = args.value()?;
            write(
                &cli.global_args,
                WeakSet {
                    key: args.key.clone(),
                    path: args.path.clone(),
                    value,
                },
            )
            .await?
        }
        Command::WeakPush(args) => {
            let value = args.value()?;
            write(
                &cli.global_args,
                WeakPush {
                    key: args.key.clone(),
                    path: args.path.clone(),
                    value,
                },
            )
            .await?
        }
        Command::WeakDelete(args) => {
            write(
                &cli.global_args,
                WeakDelete {
                    key: args.key.clone(),
                    path: args.path.clone(),
                },
            )
            .await?
        }
        Command::WeakIncrement(args) => {
            write(
                &cli.global_args,
                WeakIncrement {
                    key: args.key.clone(),
                    path: args.path.clone(),
                    delta: args.delta,
                    min: args.min,
                    max: args.max,
                },
            )
            .await?
        }
        Command::Invite(args) => {
            let path = cli.global_args.local_sock_path()?;
            let code = call(
                connect(&path).await?,
                CreateInvite {
                    weight: args.weight,
                    ttl_millis: u64::try_from(args.ttl.as_millis()).unwrap_or(u64::MAX),
                },
            )
            .await
            .map_err(MainError::Rpc)?;
            let line = InviteLine::from(code);

            match cli.global_args.format {
                Format::Text => print!("{line}"),
                Format::Json => print_json(&line)?,
            }
        }
        Command::Status => {
            let path = cli.global_args.local_sock_path()?;
            let status = call(connect(&path).await?, GetStatus {})
                .await
                .map_err(MainError::Rpc)?;

            match cli.global_args.format {
                Format::Text => print!("{}", StatusText(&status)),
                Format::Json => print_json(&status)?,
            }
        }
        Command::Watch(args) => {
            let path = cli.global_args.local_sock_path()?;
            let mut call = Call::send(
                connect(&path).await?,
                Watch {
                    selector: args.watch.selector(),
                },
            )
            .await
            .map_err(MainError::Rpc)?;

            let mut seen = 0;
            // Ends when the daemon stops answering, or when enough has been
            // seen; dropping the call is what unsubscribes.
            while let Some(event) = call.next().await.map_err(MainError::Rpc)? {
                let line = WatchLine::from(event);
                match cli.global_args.format {
                    Format::Text => print!("{line}"),
                    // One object per line: a stream is read as it arrives,
                    // so it cannot be one pretty-printed document.
                    Format::Json => {
                        println!("{}", serde_json::to_string(&line).map_err(MainError::Json)?)
                    }
                }
                // Unbuffered on purpose: whatever is reading this is waiting.
                std::io::Write::flush(&mut std::io::stdout())
                    .map_err(|e| MainError::IO(e, "writing an event"))?;

                seen += 1;
                if args.count.is_some_and(|count| seen >= count) {
                    break;
                }
            }
        }
        Command::Version => {
            let path = cli.global_args.local_sock_path()?;
            let daemon = call(connect(&path).await?, GetVersion {})
                .await
                .map_err(MainError::Rpc)?;

            let versions = Versions {
                client: VERSION.to_string(),
                daemon,
            };

            match cli.global_args.format {
                Format::Text => {
                    println!("lotusctl  {}", versions.client);
                    println!("lotusd    {}", versions.daemon);
                }
                Format::Json => print_json(&versions)?,
            }
        }
    }

    Ok(())
}

/// `status` as labelled lines.
///
/// Ids are printed whole: an operator copies them into a ledger entry or
/// another node's arguments, and a shortened id is one they cannot.
struct StatusText<'a>(&'a NodeStatus);

impl fmt::Display for StatusText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = self.0;
        writeln!(f, "version    {}", status.version)?;
        writeln!(f, "node id    {}", status.node.to_hex().as_ref())?;
        match &status.endpoint {
            Some(endpoint) => {
                writeln!(f, "endpoint   {}", endpoint.id)?;
                match endpoint.addrs.as_slice() {
                    [] => writeln!(f, "addresses  none known yet")?,
                    [first, rest @ ..] => {
                        writeln!(f, "addresses  {first}")?;
                        for addr in rest {
                            writeln!(f, "           {addr}")?;
                        }
                    }
                }
                if let Some(published) = &status.published {
                    writeln!(f, "listing    {published}")?;
                }
            }
            None => writeln!(f, "endpoint   none (not serving peers)")?,
        }
        writeln!(f, "root       {}", status.chain.root.to_hex().as_ref())?;
        writeln!(f, "head       {}", status.chain.head.to_hex().as_ref())?;
        writeln!(
            f,
            "inbound    {} {}",
            status.inbound,
            plural(status.inbound as usize, "connection", "connections")
        )?;
        writeln!(f, "peers      {} kept", status.peers.len())?;
        for peer in &status.peers {
            writeln!(
                f,
                "           {}  {}  {}",
                peer.node.to_hex().as_ref(),
                peer.endpoint,
                peer.state
            )?;
        }
        Ok(())
    }
}

fn plural(n: usize, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 { one } else { many }
}

/// Sends one weak write to the daemon and prints what it did.
async fn write<M>(args: &GlobalArgs, request: M) -> Result<(), MainError>
where
    M: lotusd_rpc::Method<Response = Written>,
{
    let path = args.local_sock_path()?;
    let written = call(connect(&path).await?, request)
        .await
        .map_err(MainError::Rpc)?;
    let line = WrittenLine::from(written);

    match args.format {
        Format::Text => print!("{line}"),
        Format::Json => print_json(&line)?,
    }
    Ok(())
}

/// Fetches whatever `request` selects, reading the stream to its end.
async fn envelopes(
    path: &std::path::Path,
    request: GetEnvelopes,
) -> Result<Vec<EnvelopeFrame>, MainError> {
    let mut call = Call::send(connect(path).await?, request)
        .await
        .map_err(MainError::Rpc)?;

    let mut frames = Vec::new();
    while let Some(frame) = call.next().await.map_err(MainError::Rpc)? {
        frames.push(frame);
    }
    Ok(frames)
}

/// The envelopes the frames carry, ready to render: the verification
/// status the daemon holds each under put back, and the time its log first
/// saw it alongside.
fn entries(frames: Vec<EnvelopeFrame>) -> Vec<Entry> {
    frames
        .into_iter()
        .map(|frame| {
            let stored_at = frame.stored_at();
            let (digest, envelope) = frame.into_parts();
            Entry::new(digest, envelope).with_stored_at(stored_at)
        })
        .collect()
}

/// The digests asked for that came back in no frame.
fn missing(asked: &[EnvelopeDigest], frames: &[EnvelopeFrame]) -> Vec<EnvelopeDigest> {
    asked
        .iter()
        .filter(|digest| !frames.iter().any(|frame| frame.digest == **digest))
        .copied()
        .collect()
}

/// A renderer that marks the ends of the chain the daemon at `path` holds.
///
/// A second connection — one carries one request — so the chain can move
/// between reading it and reading the envelopes. The cost is a stale mark
/// on a printout, never a wrong envelope.
async fn renderer(args: &GlobalArgs, path: &std::path::Path) -> Result<Render, MainError> {
    let range = call(connect(path).await?, GetChainRange {})
        .await
        .map_err(MainError::Rpc)?;

    Ok(Render::new()
        .with_palette(args.color.palette(&std::io::stdout()))
        .with_root(range.root)
        .with_head(range.head))
}

/// Connects to the daemon's control socket.
async fn connect(path: &std::path::Path) -> Result<UnixStream, MainError> {
    UnixStream::connect(path)
        .await
        .map_err(|e| MainError::IO(e, "connecting to the control socket"))
}

/// Renders one JSON object.
fn print_json<T: serde::Serialize>(value: &T) -> Result<(), MainError> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(MainError::Json)?
    );

    Ok(())
}

/// An error at the top level of the CLI.
#[derive(Debug)]
pub enum MainError {
    IO(std::io::Error, &'static str),
    /// The daemon could not be reached, or would not answer.
    Rpc(lotusd_rpc::Error),
    Json(serde_json::Error),
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_prints_in_its_largest_whole_unit() {
        assert_eq!(window(Duration::from_secs(600)), "10m");
        assert_eq!(window(Duration::from_secs(7200)), "2h");
        assert_eq!(window(Duration::from_secs(90)), "90s");
        assert_eq!(window(Duration::ZERO), "0s");
    }

    #[test]
    fn a_window_reads_in_whichever_unit_it_was_written() {
        let cases = [
            ("30", 30_000),
            ("30s", 30_000),
            ("250ms", 250),
            ("15m", 15 * 60_000),
            ("2h", 2 * 60 * 60_000),
            ("7d", 7 * 24 * 60 * 60_000),
            ("0s", 0),
        ];

        for (text, millis) in cases {
            assert_eq!(
                parse_window(text),
                Ok(Duration::from_millis(millis)),
                "{text}",
            );
        }
    }

    /// Nothing is guessed at: a window nobody could have meant is refused
    /// rather than read as some other window.
    #[test]
    fn a_window_that_is_not_one_is_refused() {
        for bad in [
            "", "s", "m5", "5 m", "-5m", "5x", "5us", "5w", "abc", "1.5h",
        ] {
            assert!(parse_window(bad).is_err(), "`{bad}` should not parse");
        }

        // Overflowing the multiply is refused, not wrapped into a short
        // window that would quietly hide most of the chain.
        assert!(parse_window(&format!("{}d", u64::MAX)).is_err());
    }
}
