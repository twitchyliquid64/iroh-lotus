use std::{path::PathBuf, process::ExitCode};

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use iroh::{Endpoint, endpoint::presets};
use lotusd::{Core, IfInitialized, Server, peer_ingress::Protocol};
use render::{ColorChoice, Entry, Render};
use tokio::net::UnixListener;
use tokio::runtime::Builder;
use tokio::signal::unix::SignalKind;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "lotusd", version = "0.0.1")]
#[command(about = "The iroh-lotus daemon")]
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
        long_about = "Generate a shell tab-completion script for the iroh-lotus daemon.\nSupported shells include bash, zsh, elvish and fish.\n\n   source <(minimald completions bash)"
    )]
    Completions(CompletionsArgs),
    /// Runs the daemon in the foreground
    Run,
    /// Initializes a new cluster
    Init(InitArgs),
    /// Inspects what this node has on disk
    #[command(subcommand)]
    Debug(DebugCommand),
}

/// The inspection subcommands. Read-only: none of these touch the ledger.
#[derive(Debug, Subcommand)]
enum DebugCommand {
    /// Prints the canonical chain, from the oldest envelope still held to head
    Chain(ChainArgs),
}

/// The arguments for the debug chain subcommand.
#[derive(Debug, Args)]
struct ChainArgs {
    /// Print at most this many envelopes, counted back from the head
    #[arg(long, short = 'n')]
    limit: Option<u32>,

    /// When to colour the output
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,
}

/// The arguments for the completions subcommand.
#[derive(Debug, clap::Args)]
struct CompletionsArgs {
    /// The shell type for a CLI completion script should be printed
    #[arg(value_parser)]
    shell: Shell,
}

/// The arguments for the init subcommand.
#[derive(Debug, clap::Args)]
struct InitArgs {
    /// Re-initialize the cluster even if this state directory is already initialized.
    ///
    /// Init is potentially destructive to data if this is set.
    #[arg(long = "overwrite_existing")]
    overwrite_existing: bool,
}

/// Shared arguments for all subcommands.
#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// Override the directory where state is stored (default: $XDG_STATE_DIR/iroh-lotus)
    #[arg(long, alias = "sd")]
    state_dir: Option<PathBuf>,
}

impl GlobalArgs {
    /// StateDir returns the directory where daemon state is stored: the `--state-dir`
    /// override when given, otherwise `iroh-lotus` under the platform state directory
    /// (`$XDG_STATE_HOME`, falling back to `~/.local/state`, on Linux).
    ///
    /// Fails only when no home directory can be determined.
    pub fn state_dir(&self) -> Result<PathBuf, MainError> {
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
    pub fn local_sock_path(&self) -> Result<PathBuf, MainError> {
        self.state_dir().map(|sd| sd.join("local.sock"))
    }
}

fn main() -> ExitCode {
    let runtime = Builder::new_multi_thread()
        .name("lotusd")
        .thread_name("lotusd-worker")
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()
        .unwrap();

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
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    // Handle all non-run commands
    match &cli.command {
        Command::Completions(args) => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(args.shell, &mut cmd, name, &mut std::io::stdout());
        }
        Command::Run => {}
        Command::Init(a) => {
            let core = Core::create_in_state_dir(
                cli.global_args.state_dir()?,
                if a.overwrite_existing {
                    IfInitialized::Overwrite
                } else {
                    IfInitialized::Fail
                },
            )
            .await
            .map_err(MainError::Init)?;

            println!("Initialized cluster {core}");
        }
        Command::Debug(DebugCommand::Chain(args)) => {
            let core = Core::init_with_state_dir(cli.global_args.state_dir()?)
                .await
                .map_err(MainError::Init)?;
            let chain: Vec<Entry> = core
                .canonical_chain(args.limit, None)
                .map_err(MainError::Storage)?
                .into_iter()
                .map(|(digest, entry)| {
                    Entry::new(digest, entry.envelope)
                        .with_stored_at(Some(entry.stored_at.naive_utc().and_utc()))
                })
                .collect();

            print!(
                "{}",
                Render::new()
                    .with_palette(args.color.palette(&std::io::stdout()))
                    .with_header(core.to_string())
                    .with_root(core.root())
                    .with_head(core.head())
                    .chain(&chain)
            );
        }
    }

    // Handle run
    if let Command::Run = cli.command {
        let core = Core::init_with_state_dir(cli.global_args.state_dir()?)
            .await
            .map_err(MainError::Init)?;
        tracing::info!("core initialized: {core}");

        let local_path = cli.global_args.local_sock_path()?;
        if let Err(e) = std::fs::remove_file(&local_path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            return Err(MainError::IO(e, "socket already in use"));
        }
        let listener =
            UnixListener::bind(&local_path).map_err(|e| MainError::IO(e, "listening to socket"))?;
        tracing::info!("Control-socket listening on {}", local_path.display());
        tracing::info!("Node ID:     {}", core.key_id().to_hex().as_ref());
        tracing::info!("Endpoint ID: {}", core.iroh_secret().public().to_z32());

        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(core.iroh_secret().clone())
            .alpns(Protocol::alpns())
            .bind()
            .await
            .map_err(MainError::Bind)?;

        let (serv, join_hnd) = Server::new(core, listener)
            .map_err(MainError::Init)?
            .with_endpoint(endpoint)
            .run()
            .await;

        let mut sig_int = tokio::signal::unix::signal(SignalKind::interrupt()).unwrap();
        sig_int.recv().await;
        if serv.shutdown().await.is_ok() {
            let _ = join_hnd.await;
        }
    }

    Ok(())
}

/// An error at the top level of the daemon.
#[derive(Debug)]
pub enum MainError {
    IO(std::io::Error, &'static str),
    Init(lotusd::InitError),
    /// The iroh endpoint could not be bound.
    Bind(iroh::endpoint::BindError),
    /// The envelope log could not be read.
    Storage(storage::sqlite::Error),
    Other(String),
}
