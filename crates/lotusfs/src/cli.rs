//! The `lotusfs` command: its arguments, and what each subcommand does.
//!
//! Here rather than in the binary so a test can run the command as a user
//! would, in its own process: [`execute`] is everything `main` does but
//! read the arguments, set up logging and listen for signals.

use std::{
    future::Future,
    io::{self, Write},
    path::PathBuf,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use filer_client::{Session, Ticket, key};
use filer_proto::fs::{Attr, Kind, MAX_IO_LEN, Read, Request};
use iroh::{
    Endpoint, RelayMode,
    endpoint::{default_relay_mode, presets},
    tls::CaTlsConfig,
};

/// The directory under the user's state directory the client keeps its key
/// in by default.
const STATE_DIR_NAME: &str = "iroh-lotus-fs";

/// The file the client's endpoint key is kept in, under its state directory.
const SECRET_FILENAME: &str = "client-secret";

#[derive(Debug, Parser)]
#[command(name = "lotusfs", version = version::VERSION, long_version = version::LONG_VERSION)]
#[command(about = "Mounts and reads volumes served by an iroh-lotus filer")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Where the client keeps its endpoint key (default: iroh-lotus-fs
    /// under the user's state directory, or their local data directory
    /// where the platform has none)
    #[arg(long, env = "LOTUS_FS_STATE_DIR", global = true)]
    state_dir: Option<PathBuf>,

    /// Which relay infrastructure the iroh endpoint uses
    #[arg(long, value_enum, env = "LOTUS_FS_RELAY", default_value_t = Relay::N0, global = true)]
    relay: Relay,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Prints this client's endpoint id, creating its key if need be
    #[command(
        long_about = "Prints this client's endpoint id, creating its key if need be.\n\n\
        The id is all a filer knows a client by: an operator lists it under \
        the volume's `allowed_clients` in the ledger, with the mode it may \
        have."
    )]
    Id,
    /// Mounts a volume at a directory, in the foreground
    Mount(MountArgs),
    /// Lists a directory of a volume, or describes a file
    Ls(PathArgs),
    /// Writes a file of a volume to standard output
    Cat(PathArgs),
}

#[derive(Debug, Args)]
struct MountArgs {
    /// The volume's ticket, from `filerd ticket`
    ticket: Ticket,
    /// The directory to mount it at
    mountpoint: PathBuf,
}

#[derive(Debug, Args)]
struct PathArgs {
    /// The volume's ticket, from `filerd ticket`
    ticket: Ticket,
    /// The path inside the volume
    #[arg(default_value = "/")]
    path: String,
}

/// The relay infrastructure the endpoint binds with, as `--relay` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Relay {
    /// No relays: direct connections only
    None,
    /// The n0 public relay network
    N0,
}

/// Why the command failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no state directory found; pass --state-dir to set one")]
    NoStateDir,
    #[error(transparent)]
    Key(#[from] key::KeyError),
    #[error("binding the endpoint")]
    Bind(#[source] iroh::endpoint::BindError),
    #[error(transparent)]
    Filer(#[from] filer_client::Error),
    #[error("{path} is a directory")]
    IsDir { path: String },
    #[error("writing the output")]
    Output(#[source] io::Error),
    #[cfg(target_os = "linux")]
    #[error("mounting at {}", mountpoint.display())]
    Mount {
        mountpoint: PathBuf,
        #[source]
        source: io::Error,
    },
    #[cfg(target_os = "linux")]
    #[error(
        "{} was detached, but something still has it open; it goes away when that does",
        mountpoint.display()
    )]
    StillInUse { mountpoint: PathBuf },
    #[cfg(not(target_os = "linux"))]
    #[error("mounting is only built for Linux so far; `ls` and `cat` work here")]
    MountUnsupported,
}

/// The endpoint the command dials from, identified by the key in `cli`'s
/// state directory — created there on first use.
pub async fn endpoint(cli: &Cli) -> Result<Endpoint, Error> {
    let state_dir = cli
        .state_dir
        .clone()
        .or_else(|| dirs::state_dir().map(|dir| dir.join(STATE_DIR_NAME)))
        .or_else(|| dirs::data_local_dir().map(|dir| dir.join(STATE_DIR_NAME)))
        .ok_or(Error::NoStateDir)?;
    let secret = key::load_or_create(&state_dir.join(SECRET_FILENAME)).await?;
    Endpoint::builder(presets::Minimal)
        .ca_tls_config(CaTlsConfig::system())
        .relay_mode(match cli.relay {
            Relay::None => RelayMode::Disabled,
            Relay::N0 => default_relay_mode(),
        })
        .secret_key(secret)
        .bind()
        .await
        .map_err(Error::Bind)
}

/// Carries out the command `cli` asks for, printing what it prints to
/// `out`. A mount stays until `shutdown` resolves.
pub async fn execute(
    cli: Cli,
    out: &mut impl Write,
    shutdown: impl Future<Output = ()>,
) -> Result<(), Error> {
    let endpoint = endpoint(&cli).await?;
    let done = match cli.command {
        Command::Id => writeln!(out, "{}", endpoint.id().to_z32()).map_err(Error::Output),
        Command::Ls(args) => ls(Session::new(endpoint.clone(), args.ticket), &args.path, out).await,
        Command::Cat(args) => {
            cat(Session::new(endpoint.clone(), args.ticket), &args.path, out).await
        }
        Command::Mount(args) => {
            mount(
                Session::new(endpoint.clone(), args.ticket),
                args.mountpoint,
                shutdown,
            )
            .await
        }
    };
    endpoint.close().await;
    done
}

/// One line of a listing: kind and permissions, size, name.
fn line(attr: &Attr, name: &str) -> String {
    let kind = match attr.kind {
        Kind::File => '-',
        Kind::Dir => 'd',
        Kind::Symlink => 'l',
    };
    format!("{kind}{:04o} {:>12} {name}", attr.mode, attr.size)
}

async fn ls(session: Session, path: &str, out: &mut impl Write) -> Result<(), Error> {
    let attr = session.walk(path).await?;
    let lines = match attr.kind {
        Kind::Dir => session
            .list(attr.node)
            .await?
            .iter()
            .map(|entry| line(&entry.attr, entry.name.as_str()))
            .collect(),
        Kind::File | Kind::Symlink => vec![line(&attr, path)],
    };
    lines
        .iter()
        .try_for_each(|line| writeln!(out, "{line}"))
        .map_err(Error::Output)
}

async fn cat(session: Session, path: &str, out: &mut impl Write) -> Result<(), Error> {
    let attr = session.walk(path).await?;
    if attr.kind == Kind::Dir {
        return Err(Error::IsDir {
            path: path.to_owned(),
        });
    }
    let mut offset = 0;
    loop {
        let data = session
            .data(Request::Read(Read {
                node: attr.node,
                offset,
                len: MAX_IO_LEN,
            }))
            .await?;
        if data.is_empty() {
            return out.flush().map_err(Error::Output);
        }
        out.write_all(&data).map_err(Error::Output)?;
        offset += data.len() as u64;
    }
}

#[cfg(target_os = "linux")]
async fn mount(
    session: Session,
    mountpoint: PathBuf,
    shutdown: impl Future<Output = ()>,
) -> Result<(), Error> {
    // Dialled before mounting, so a ticket that leads nowhere, or a filer
    // that does not permit this client, fails here and not on first use.
    let mode = session.connect().await?;
    let volume = session.ticket().volume.clone();
    let mounted = crate::fuse::mount(
        tokio::runtime::Handle::current(),
        std::sync::Arc::new(session),
        mode,
        &mountpoint,
    )
    .map_err(|source| Error::Mount {
        mountpoint: mountpoint.clone(),
        source,
    })?;
    eprintln!("{volume} mounted at {} ({mode})", mountpoint.display());

    shutdown.await;
    tokio::task::spawn_blocking(move || mounted.umount_and_join())
        .await
        .expect("unmounting does not panic")
        .map_err(|source| match source.kind() {
            io::ErrorKind::ResourceBusy => Error::StillInUse { mountpoint },
            _ => Error::Mount { mountpoint, source },
        })
}

#[cfg(not(target_os = "linux"))]
async fn mount(_: Session, _: PathBuf, _: impl Future<Output = ()>) -> Result<(), Error> {
    Err(Error::MountUnsupported)
}
