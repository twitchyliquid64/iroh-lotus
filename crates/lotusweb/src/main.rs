use std::{io, net::SocketAddr, path::PathBuf, process::ExitCode};

use clap::Parser;
use lotus_sdk::Client;
use tokio::{net::TcpListener, runtime::Builder};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "lotusweb", version = version::VERSION, long_version = version::LONG_VERSION)]
#[command(about = "Serves a web view onto a running iroh-lotus daemon")]
struct Cli {
    /// The address to serve on
    #[arg(
        long,
        short,
        default_value = "127.0.0.1:8080",
        env = "LOTUS_WEB_LISTEN"
    )]
    listen: SocketAddr,

    /// The daemon's state directory, where its control socket is (default:
    /// $XDG_STATE_DIR/iroh-lotus, or /var/lib/lotus when only that exists)
    #[arg(long, alias = "sd", env = "LOTUS_STATE_DIR")]
    state_dir: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
enum MainError {
    #[error("no state directory found; pass --state-dir to set one")]
    NoStateDir,
    #[error("could not listen on {addr}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("serving")]
    Serve(#[source] io::Error),
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
    let state_dir = cli
        .state_dir
        .or_else(lotus_sdk::find_state_dir)
        .ok_or(MainError::NoStateDir)?;
    let client = Client::in_state_dir(&state_dir);

    let listener = TcpListener::bind(cli.listen)
        .await
        .map_err(|source| MainError::Bind {
            addr: cli.listen,
            source,
        })?;
    tracing::info!(
        listen = %cli.listen,
        socket = %client.socket_path().display(),
        "serving http://{}",
        cli.listen
    );

    axum::serve(listener, lotusweb::router(client))
        .with_graceful_shutdown(async {
            // Nothing to do if the signal can't be listened for: serve until killed.
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::warn!(%error, "not listening for ctrl-c");
                std::future::pending::<()>().await;
            }
        })
        .await
        .map_err(MainError::Serve)
}
