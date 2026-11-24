//! The `lotusfs` command: its arguments, and what each subcommand does.
//!
//! Here rather than in the binary so a test can run the command as a user
//! would, in its own process: [`execute`] is everything `main` does but
//! read the arguments, set up logging and listen for signals.

use std::{
    fmt,
    future::Future,
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use filer_client::{Session, Ticket, key};
use filer_proto::fs::{
    self, Attr, ByteBuf, Create, Errno, Fsync, Kind, Lookup, MAX_IO_LEN, Name, Read, Request,
    SetAttr,
};
use iroh::{
    Endpoint, RelayMode,
    endpoint::{default_relay_mode, presets},
    tls::CaTlsConfig,
};
use tokio::io::{AsyncRead, AsyncReadExt};

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
    /// Writes standard input, or a local file, to a file of a volume
    #[command(
        long_about = "Writes standard input, or a local file, to a file of a volume.\n\n\
        The file is created where it is missing and truncated where it is not, \
        as a shell's `>` would. A path naming a directory takes a local file \
        under its own name, as `cp` would. A write cut off part way leaves the \
        file holding what arrived."
    )]
    Put(PutArgs),
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

#[derive(Debug, Args)]
struct PutArgs {
    /// The volume's ticket, from `filerd ticket`
    ticket: Ticket,
    /// The path inside the volume to write to
    path: String,
    /// The local file to copy; standard input when absent or `-`
    file: Option<PathBuf>,
}

/// Where `put` reads what it writes.
#[derive(Debug, Clone)]
pub enum Origin {
    Stdin,
    File(PathBuf),
}

impl Origin {
    fn new(file: Option<PathBuf>) -> Self {
        match file {
            Some(path) if path != Path::new("-") => Origin::File(path),
            _ => Origin::Stdin,
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::Stdin => f.write_str("standard input"),
            Origin::File(path) => write!(f, "{}", path.display()),
        }
    }
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
    #[error("reading {origin}")]
    Input {
        origin: Origin,
        #[source]
        source: io::Error,
    },
    #[error("{} has no name a volume can hold", .0.display())]
    Unnamed(PathBuf),
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
    #[error("mounting is only built for Linux so far; `ls`, `cat` and `put` work here")]
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

/// Carries out the command `cli` asks for, reading what it reads from
/// standard input from `stdin` and printing what it prints to `out`. A
/// mount stays until `shutdown` resolves.
pub async fn execute(
    cli: Cli,
    stdin: impl AsyncRead + Unpin,
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
        Command::Put(args) => {
            put(
                Session::new(endpoint.clone(), args.ticket),
                &args.path,
                Origin::new(args.file),
                stdin,
            )
            .await
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

/// The file to write to: an entry of a directory, or a directory to take
/// a local file under its own name.
enum Target {
    Entry { parent: Attr, name: Name },
    Dir(Attr),
}

/// Resolves `path` to where `put` writes.
async fn target(session: &Session, path: &str) -> Result<Target, Error> {
    let trimmed = path.trim_end_matches('/');
    let (parent, last) = trimmed.rsplit_once('/').unwrap_or(("", trimmed));
    let parent = session.walk(parent).await?;
    if last.is_empty() {
        return Ok(Target::Dir(parent));
    }
    let name = Name::try_new(last).map_err(|_| filer_client::Error::Op(Errno::Invalid))?;
    let found = session
        .attr(Request::Lookup(Lookup {
            parent: parent.node,
            name: name.clone(),
        }))
        .await;
    match found {
        Ok(attr) if attr.kind == Kind::Dir => Ok(Target::Dir(attr)),
        Ok(_) => Ok(Target::Entry { parent, name }),
        Err(e) if e.errno() == Some(Errno::NotFound) => Ok(Target::Entry { parent, name }),
        Err(e) => Err(e.into()),
    }
}

async fn put(
    session: Session,
    path: &str,
    origin: Origin,
    stdin: impl AsyncRead + Unpin,
) -> Result<(), Error> {
    let read_err = |source| Error::Input {
        origin: origin.clone(),
        source,
    };
    // Opened before the volume is touched, so a missing local file
    // changes nothing there.
    let (input, mode): (Box<dyn AsyncRead + Unpin>, u32) = match &origin {
        Origin::Stdin => (Box::new(stdin), 0o644),
        Origin::File(file) => {
            let opened = tokio::fs::File::open(file).await.map_err(read_err)?;
            let meta = opened.metadata().await.map_err(read_err)?;
            if meta.is_dir() {
                return Err(read_err(io::ErrorKind::IsADirectory.into()));
            }
            (Box::new(opened), meta.permissions().mode() & 0o7777)
        }
    };

    let (parent, name) = match (target(&session, path).await?, &origin) {
        (Target::Entry { parent, name }, _) => (parent, name),
        (Target::Dir(dir), Origin::File(file)) => (
            dir,
            file.file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| Name::try_new(name).ok())
                .ok_or_else(|| Error::Unnamed(file.clone()))?,
        ),
        (Target::Dir(_), Origin::Stdin) => {
            return Err(Error::IsDir {
                path: path.to_owned(),
            });
        }
    };

    let node = session
        .attr(Request::Create(Create {
            parent: parent.node,
            name,
            mode,
            exclusive: false,
        }))
        .await?
        .node;
    session
        .attr(Request::SetAttr(SetAttr {
            node,
            mode: None,
            size: Some(0),
            atime: None,
            mtime: None,
        }))
        .await?;
    write_all(&session, node, input)
        .await
        .map_err(|e| match e {
            Copy::Read(source) => read_err(source),
            Copy::Filer(e) => Error::Filer(e),
        })?;
    session
        .done(Request::Fsync(Fsync { node }))
        .await
        .map_err(Error::Filer)
}

/// How copying into a file of a volume failed.
enum Copy {
    Read(io::Error),
    Filer(filer_client::Error),
}

/// Writes everything `input` holds into `node` from its start, a request
/// at a time.
async fn write_all(
    session: &Session,
    node: fs::NodeId,
    mut input: impl AsyncRead + Unpin,
) -> Result<(), Copy> {
    let mut offset = 0;
    loop {
        let mut chunk = Vec::new();
        (&mut input)
            .take(MAX_IO_LEN.into())
            .read_to_end(&mut chunk)
            .await
            .map_err(Copy::Read)?;
        if chunk.is_empty() {
            return Ok(());
        }
        let len = chunk.len() as u64;
        session
            .done(Request::Write(fs::Write {
                node,
                offset,
                data: ByteBuf::from(chunk),
            }))
            .await
            .map_err(Copy::Filer)?;
        offset += len;
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
