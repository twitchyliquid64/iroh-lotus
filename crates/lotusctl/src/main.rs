use std::{path::PathBuf, process::ExitCode};

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use lotusd_rpc::{GetChainRange, GetVersion, call};
use tokio::net::UnixStream;
use tokio::runtime::Builder;
use wire::EnvelopeDigest;

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
    /// Reports the daemon's version and how much of the chain it holds
    Status,
    /// Reports this CLI's version alongside the daemon's
    Version,
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

/// What `status` reports.
#[derive(Debug, serde::Serialize)]
struct Status {
    version: String,
    root: EnvelopeDigest,
    head: EnvelopeDigest,
}

/// What `version` reports.
#[derive(Debug, serde::Serialize)]
struct Versions {
    client: String,
    daemon: String,
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
        Command::Status => {
            let path = cli.global_args.local_sock_path()?;

            // One request per connection, so each method gets its own.
            let version = call(connect(&path).await?, GetVersion {})
                .await
                .map_err(MainError::Rpc)?;
            let range = call(connect(&path).await?, GetChainRange {})
                .await
                .map_err(MainError::Rpc)?;

            let status = Status {
                version,
                root: range.root,
                head: range.head,
            };

            match cli.global_args.format {
                Format::Text => {
                    println!("version  {}", status.version);
                    println!("root     {}", status.root.to_hex().as_ref());
                    println!("head     {}", status.head.to_hex().as_ref());
                }
                Format::Json => print_json(&status)?,
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
