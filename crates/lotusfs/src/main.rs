use std::process::ExitCode;

use clap::Parser;
use lotusfs::cli::{self, Cli};
use tokio::{
    runtime::Builder,
    signal::unix::{SignalKind, signal},
};
use tracing_subscriber::EnvFilter;

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

async fn async_main() -> Result<(), cli::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    cli::execute(cli, &mut std::io::stdout(), interrupted()).await
}

/// Resolves on the first interrupt or terminate signal; never, where the
/// signals cannot be listened for — a mount then stays until killed.
async fn interrupted() {
    let (Ok(mut interrupt), Ok(mut terminate)) = (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    ) else {
        tracing::warn!("not listening for signals");
        return std::future::pending().await;
    };
    tokio::select! {
        _ = interrupt.recv() => {}
        _ = terminate.recv() => {}
    }
}
