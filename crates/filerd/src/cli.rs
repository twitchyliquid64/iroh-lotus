//! The `filerd` command: its arguments, and what each subcommand does.
//!
//! Here rather than in the binary so a test can run the command as an
//! operator would, in its own process: [`execute`] is everything `main`
//! does but read the arguments, set up logging and listen for signals.

use std::{
    future::Future,
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    time::Duration,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use filer_client::{Ticket, TicketError, key};
use filer_proto::VolumeName;

use crate::{
    Backing, DEFAULT_SETTLE, Filer,
    ledger::{self, Claim, Entry},
};
use iroh::{
    Endpoint, RelayMode,
    endpoint::{default_relay_mode, presets},
    tls::CaTlsConfig,
};
use lotus_sdk::Client;

/// The directory under the user's state directory the filer keeps its key
/// in by default.
const STATE_DIR_NAME: &str = "iroh-lotus-filer";

/// The file the filer's endpoint key is kept in, under its state directory.
const SECRET_FILENAME: &str = "filer-secret";

#[derive(Debug, Parser)]
#[command(name = "filerd", version = version::VERSION, long_version = version::LONG_VERSION)]
#[command(about = "Serves volumes of files over iroh, announced in an iroh-lotus ledger")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,

    /// The lotus daemon's state directory, where its control socket is
    /// (default: $XDG_STATE_DIR/iroh-lotus, or /var/lib/lotus when only
    /// that exists)
    #[arg(long, env = "LOTUS_STATE_DIR", global = true)]
    lotus_state_dir: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Runs the filer in the foreground
    Run(RunArgs),
    /// Prints the ticket a client mounts a volume with
    #[command(long_about = "Prints the ticket a client mounts a volume with.\n\n\
        Read from the ledger, so it works on any node of the cluster once a \
        filer has claimed the volume. The ticket says where the filer is and \
        nothing more: a client is admitted by its endpoint id (`lotusfs id`), \
        which must be listed under the volume's `allowed_clients`.")]
    Ticket(TicketArgs),
}

#[derive(Debug, Args)]
struct RunArgs {
    /// A volume to serve, as NAME=DIRECTORY; repeat for more, or separate
    /// them with commas
    #[arg(
        long = "volume",
        short,
        value_name = "NAME=DIRECTORY",
        value_parser = parse_volume,
        required = true,
        env = "LOTUS_FILER_VOLUMES",
        value_delimiter = ','
    )]
    volumes: Vec<(VolumeName, PathBuf)>,

    /// Where the filer keeps its endpoint key (default: iroh-lotus-filer
    /// under the user's state directory, or their local data directory
    /// where the platform has none)
    #[arg(long, env = "LOTUS_FILER_STATE_DIR")]
    state_dir: Option<PathBuf>,

    /// Which relay infrastructure the iroh endpoint uses
    #[arg(long, value_enum, env = "LOTUS_FILER_RELAY", default_value_t = Relay::N0)]
    relay: Relay,

    /// Bind the iroh endpoint's UDP socket here instead of 0.0.0.0:0 and
    /// [::]:0; repeat for one address per IP family
    #[arg(long, env = "LOTUS_FILER_BIND", value_delimiter = ',')]
    bind: Vec<SocketAddr>,

    /// Claim volumes the ledger lists under another filer, once, at start.
    ///
    /// Without it such a volume is left alone and not served: moving a
    /// volume between filers is an operator's decision.
    #[arg(long)]
    takeover: bool,

    /// How long, in seconds, the endpoint's address is left to settle
    /// after it moves before it is written to the ledger
    #[arg(long, value_name = "SECONDS", value_parser = parse_seconds, default_value_t = DEFAULT_SETTLE.as_secs_f64())]
    settle: f64,
}

#[derive(Debug, Args)]
struct TicketArgs {
    /// The volume to print a ticket for
    #[arg(value_parser = parse_volume_name)]
    volume: VolumeName,
}

/// The relay infrastructure the endpoint binds with, as `--relay` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Relay {
    /// No relays: direct connections only
    None,
    /// The n0 public relay network
    N0,
}

/// Reads a length of time in seconds, for clap.
fn parse_seconds(text: &str) -> Result<f64, String> {
    text.parse::<f64>()
        .ok()
        .filter(|seconds| Duration::try_from_secs_f64(*seconds).is_ok())
        .ok_or_else(|| format!("`{text}` is not a number of seconds"))
}

/// Reads a volume's name, for clap.
fn parse_volume_name(name: &str) -> Result<VolumeName, String> {
    VolumeName::try_new(name).map_err(|_| {
        format!("`{name}` is not a volume name: lowercase letters, digits, `-` and `_` only")
    })
}

/// Reads a `NAME=DIRECTORY` volume, for clap.
fn parse_volume(text: &str) -> Result<(VolumeName, PathBuf), String> {
    let (name, path) = text
        .split_once('=')
        .ok_or("expected NAME=DIRECTORY".to_owned())?;
    Ok((parse_volume_name(name)?, PathBuf::from(path)))
}

/// Why the command failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no state directory found; pass --state-dir to set one")]
    NoStateDir,
    #[error("no lotus state directory found; pass --lotus-state-dir to set one")]
    NoLotusStateDir,
    #[error("volume {volume} is listed twice")]
    DuplicateVolume { volume: VolumeName },
    #[error("volume {volume}: opening the directory {}", path.display())]
    OpenVolume {
        volume: VolumeName,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Key(#[from] key::KeyError),
    #[error("binding the endpoint to the addresses given")]
    BindAddr(#[source] iroh::endpoint::InvalidSocketAddr),
    #[error("binding the endpoint")]
    Bind(#[source] iroh::endpoint::BindError),
    #[error("writing the output")]
    Output(#[source] io::Error),
    #[error("reading the ledger")]
    Ledger(#[source] lotus_sdk::Error),
    #[error("the ledger does not list a volume called {volume}")]
    NotListed { volume: VolumeName },
    #[error("no filer has claimed {volume} yet")]
    Unclaimed { volume: VolumeName },
    #[error("the endpoint the ledger names for {volume} does not read: {why}")]
    UnreadableClaim { volume: VolumeName, why: String },
    #[error(transparent)]
    Ticket(#[from] TicketError),
}

/// Carries out the command `cli` asks for, printing what it prints to
/// `out`. A filer runs until `shutdown` resolves.
pub async fn execute(
    cli: Cli,
    out: &mut impl Write,
    shutdown: impl Future<Output = ()>,
) -> Result<(), Error> {
    let lotus_state_dir = cli
        .lotus_state_dir
        .or_else(lotus_sdk::find_state_dir)
        .ok_or(Error::NoLotusStateDir)?;
    let client = Client::in_state_dir(&lotus_state_dir);

    match cli.command {
        Command::Run(args) => run(client, args, shutdown).await,
        Command::Ticket(args) => ticket(client, args, out).await,
    }
}

/// Prints the ticket for a volume as the ledger lists it.
async fn ticket(client: Client, args: TicketArgs, out: &mut impl Write) -> Result<(), Error> {
    let volume = args.volume;
    let namespace = client
        .read(ledger::namespace(), None)
        .await
        .map_err(Error::Ledger)?
        .value;
    let filer = match Entry::find(namespace.as_ref(), &volume).map(|entry| entry.claim) {
        None => return Err(Error::NotListed { volume }),
        Some(Claim::Unclaimed) => return Err(Error::Unclaimed { volume }),
        Some(Claim::Unreadable(why)) => return Err(Error::UnreadableClaim { volume, why }),
        Some(Claim::Endpoint(filer)) => filer,
    };
    writeln!(out, "{}", Ticket { volume, filer }.encode()?).map_err(Error::Output)
}

/// Serves the volumes given until `shutdown` resolves.
async fn run(
    client: Client,
    args: RunArgs,
    shutdown: impl Future<Output = ()>,
) -> Result<(), Error> {
    let volumes = args.volumes.into_iter().try_fold(
        Vec::<(VolumeName, Backing)>::new(),
        |mut volumes, (volume, path)| {
            if volumes.iter().any(|(listed, _)| *listed == volume) {
                return Err(Error::DuplicateVolume { volume });
            }
            match Backing::open(&path) {
                Ok(backing) => {
                    tracing::info!(%volume, path = %path.display(), "serving volume");
                    volumes.push((volume, backing));
                    Ok(volumes)
                }
                Err(source) => Err(Error::OpenVolume {
                    volume,
                    path,
                    source,
                }),
            }
        },
    )?;

    let state_dir = args
        .state_dir
        .or_else(|| dirs::state_dir().map(|dir| dir.join(STATE_DIR_NAME)))
        .or_else(|| dirs::data_local_dir().map(|dir| dir.join(STATE_DIR_NAME)))
        .ok_or(Error::NoStateDir)?;

    let secret = key::load_or_create(&state_dir.join(SECRET_FILENAME)).await?;
    let builder = Endpoint::builder(presets::Minimal)
        .ca_tls_config(CaTlsConfig::system())
        .relay_mode(match args.relay {
            Relay::None => RelayMode::Disabled,
            Relay::N0 => default_relay_mode(),
        })
        .secret_key(secret)
        .alpns(vec![filer_proto::ALPN.to_vec()]);
    let builder = if args.bind.is_empty() {
        builder
    } else {
        args.bind
            .iter()
            .try_fold(builder.clear_ip_transports(), |builder, addr| {
                builder.bind_addr(*addr)
            })
            .map_err(Error::BindAddr)?
    };
    let endpoint = builder.bind().await.map_err(Error::Bind)?;
    tracing::info!(
        socket = %client.socket_path().display(),
        "Endpoint ID: {}",
        endpoint.id().to_z32()
    );

    let handle = volumes
        .into_iter()
        .fold(
            Filer::new(client, endpoint.clone()),
            |filer, (volume, backing)| filer.with_volume(volume, backing),
        )
        .with_takeover(args.takeover)
        .with_settle(Duration::from_secs_f64(args.settle))
        .spawn();

    shutdown.await;
    handle.shutdown().await;
    endpoint.close().await;
    Ok(())
}
