use std::{io, net::SocketAddr, path::PathBuf, process::ExitCode};

use clap::{Parser, ValueEnum};
use filer_proto::VolumeName;
use filerd::{Filer, key};
use iroh::{
    Endpoint, RelayMode,
    endpoint::{default_relay_mode, presets},
    tls::CaTlsConfig,
};
use lotus_sdk::Client;
use tokio::{runtime::Builder, signal::unix::SignalKind};
use tracing_subscriber::EnvFilter;

/// The directory under the user's state directory the filer keeps its key
/// in by default.
const STATE_DIR_NAME: &str = "iroh-lotus-filer";

#[derive(Parser)]
#[command(name = "filerd", version = version::VERSION, long_version = version::LONG_VERSION)]
#[command(about = "Serves volumes of files over iroh, announced in an iroh-lotus ledger")]
struct Cli {
    /// A volume to serve, as NAME=DIRECTORY; repeat for more
    #[arg(long = "volume", short, value_name = "NAME=DIRECTORY", value_parser = parse_volume, required = true)]
    volumes: Vec<(VolumeName, PathBuf)>,

    /// Where the filer keeps its endpoint key (default: iroh-lotus-filer
    /// under the user's state directory, or their local data directory
    /// where the platform has none)
    #[arg(long, env = "LOTUS_FILER_STATE_DIR")]
    state_dir: Option<PathBuf>,

    /// The lotus daemon's state directory, where its control socket is
    /// (default: $XDG_STATE_DIR/iroh-lotus, or /var/lib/lotus when only
    /// that exists)
    #[arg(long, env = "LOTUS_STATE_DIR")]
    lotus_state_dir: Option<PathBuf>,

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
}

/// The relay infrastructure the endpoint binds with, as `--relay` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Relay {
    /// No relays: direct connections only
    None,
    /// The n0 public relay network
    N0,
}

/// Reads a `NAME=DIRECTORY` volume, for clap.
fn parse_volume(text: &str) -> Result<(VolumeName, PathBuf), String> {
    let (name, path) = text
        .split_once('=')
        .ok_or("expected NAME=DIRECTORY".to_owned())?;
    let name = VolumeName::try_new(name).map_err(|_| {
        format!("`{name}` is not a volume name: lowercase letters, digits, `-` and `_` only")
    })?;
    Ok((name, PathBuf::from(path)))
}

#[derive(Debug, thiserror::Error)]
enum MainError {
    #[error("no state directory found; pass --state-dir to set one")]
    NoStateDir,
    #[error("no lotus state directory found; pass --lotus-state-dir to set one")]
    NoLotusStateDir,
    #[error("volume {volume} is listed twice")]
    DuplicateVolume { volume: VolumeName },
    #[error("volume {volume}: {} is not a directory", path.display())]
    NotADirectory {
        volume: VolumeName,
        path: PathBuf,
        #[source]
        source: Option<io::Error>,
    },
    #[error(transparent)]
    Key(#[from] key::KeyError),
    #[error("binding the endpoint to the addresses given")]
    BindAddr(#[source] iroh::endpoint::InvalidSocketAddr),
    #[error("binding the endpoint")]
    Bind(#[source] iroh::endpoint::BindError),
    #[error("listening for signals")]
    Signal(#[source] io::Error),
}

fn main() -> ExitCode {
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime needs no resources to start");

    let res = runtime.block_on(async_main());
    drop(runtime);

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            std::iter::successors(std::error::Error::source(&e), |e| (*e).source())
                .for_each(|cause| eprintln!("  caused by: {cause}"));
            ExitCode::FAILURE
        }
    }
}

async fn async_main() -> Result<(), MainError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let filer = cli.volumes.into_iter().try_fold(
        Vec::<(VolumeName, PathBuf)>::new(),
        |mut volumes, (volume, path)| {
            if volumes.iter().any(|(listed, _)| *listed == volume) {
                return Err(MainError::DuplicateVolume { volume });
            }
            match std::fs::metadata(&path) {
                Ok(meta) if meta.is_dir() => {}
                Ok(_) => {
                    return Err(MainError::NotADirectory {
                        volume,
                        path,
                        source: None,
                    });
                }
                Err(source) => {
                    return Err(MainError::NotADirectory {
                        volume,
                        path,
                        source: Some(source),
                    });
                }
            }
            volumes.push((volume, path));
            Ok(volumes)
        },
    )?;

    let state_dir = cli
        .state_dir
        .or_else(|| dirs::state_dir().map(|dir| dir.join(STATE_DIR_NAME)))
        .or_else(|| dirs::data_local_dir().map(|dir| dir.join(STATE_DIR_NAME)))
        .ok_or(MainError::NoStateDir)?;
    let lotus_state_dir = cli
        .lotus_state_dir
        .or_else(lotus_sdk::find_state_dir)
        .ok_or(MainError::NoLotusStateDir)?;
    let client = Client::in_state_dir(&lotus_state_dir);

    let secret = key::load_or_create(&state_dir).await?;
    let builder = Endpoint::builder(presets::Minimal)
        .ca_tls_config(CaTlsConfig::system())
        .relay_mode(match cli.relay {
            Relay::None => RelayMode::Disabled,
            Relay::N0 => default_relay_mode(),
        })
        .secret_key(secret)
        .alpns(vec![filer_proto::ALPN.to_vec()]);
    let builder = if cli.bind.is_empty() {
        builder
    } else {
        cli.bind
            .iter()
            .try_fold(builder.clear_ip_transports(), |builder, addr| {
                builder.bind_addr(*addr)
            })
            .map_err(MainError::BindAddr)?
    };
    let endpoint = builder.bind().await.map_err(MainError::Bind)?;
    tracing::info!(
        socket = %client.socket_path().display(),
        "Endpoint ID: {}",
        endpoint.id().to_z32()
    );

    let handle = filer
        .into_iter()
        .fold(
            Filer::new(client, endpoint.clone()),
            |filer, (volume, path)| filer.with_volume(volume, path),
        )
        .with_takeover(cli.takeover)
        .spawn();

    let mut interrupt =
        tokio::signal::unix::signal(SignalKind::interrupt()).map_err(MainError::Signal)?;
    let mut terminate =
        tokio::signal::unix::signal(SignalKind::terminate()).map_err(MainError::Signal)?;
    tokio::select! {
        _ = interrupt.recv() => {}
        _ = terminate.recv() => {}
    }
    handle.shutdown().await;
    endpoint.close().await;
    Ok(())
}
