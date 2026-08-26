use std::{collections::BTreeMap, path::PathBuf, process::ExitCode};

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use lotusd::Core;
use state::Chain;
use storage::SqliteStorage;
use tokio::{fs, runtime::Builder};

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
    let cli = Cli::parse();

    match cli.command {
        Command::Completions(args) => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(args.shell, &mut cmd, name, &mut std::io::stdout());
        }
        Command::Run => {
            let core = Core::init_with_state_dir(cli.global_args.state_dir()?)
                .await
                .map_err(MainError::Init)?;
            println!("core: {core}");
        }
        Command::Init(a) => {
            let state_dir = cli.global_args.state_dir()?;
            fs::create_dir_all(&state_dir)
                .await
                .map_err(|e| MainError::IO(e, "creating state-dir"))?;

            if fs::try_exists(state_dir.join(lotusd::OLDEST_ENVELOPE_FILENAME))
                .await
                .map_err(|e| MainError::IO(e, "reading oldest-envelope"))?
                && !a.overwrite_existing
            {
                return Err(MainError::Other(format!(
                    "Cluster at {} already initialized, pass --overwrite_existing to overwrite",
                    state_dir.display(),
                )));
            }

            // Make the init message
            use wire::{Envelope, Msg, VerificationStatus, msg::FullCheckpoint, msg::InitMsg};
            let mut envelope = Envelope::new(Msg::Init(InitMsg {
                state: FullCheckpoint {
                    namespaces: BTreeMap::from_iter([]),
                },
            }));
            envelope.set_verification_status(VerificationStatus::AllMatched { total_weight: 2 });

            let mut storage = SqliteStorage::open(state_dir.join(lotusd::SQLITE_DB_FILENAME))
                .map_err(MainError::Storage)?;
            let chain = Chain::init(&mut storage, envelope).map_err(MainError::Chain)?;

            // Written only once the genesis is durable, so the file never names an
            // envelope the store is missing.
            fs::write(
                state_dir.join(lotusd::OLDEST_ENVELOPE_FILENAME),
                chain.root().as_bytes(),
            )
            .await
            .map_err(|e| MainError::IO(e, "writing oldest-envelope"))?;

            println!(
                "Initialized cluster at {} rooted at {}",
                state_dir.display(),
                chain.root().to_hex().as_ref()
            );
        }
    }

    Ok(())
}

/// An error at the top level of the daemon.
#[derive(Debug)]
pub enum MainError {
    Init(lotusd::InitError),
    /// The sqlite store could not be opened.
    Storage(storage::sqlite::Error),
    /// The genesis envelope could not be committed to the chain.
    Chain(state::Error<storage::sqlite::Error>),
    IO(std::io::Error, &'static str),
    Other(String),
}
