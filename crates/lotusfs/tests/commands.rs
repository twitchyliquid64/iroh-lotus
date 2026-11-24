//! `filerd` and `lotusfs` as an operator and a user run them, in one
//! process: each command is parsed from its arguments and run through the
//! same code its binary runs, against a real lotus daemon over its control
//! socket and real iroh endpoints on loopback.
//!
//! Nothing is mounted, so nothing is needed of the host. What a mount
//! would do is covered a layer down: the FUSE layer is driven directly,
//! as the kernel would drive it.

use std::{
    net::UdpSocket,
    sync::Arc,
    time::{Duration, Instant},
};

use clap::Parser;
use filer_client::{
    Session, Ticket,
    proto::{
        Close,
        fs::{Create, Kind, Lookup, MAX_IO_LEN, Mkdir, Request, Unlink},
    },
};
use lotus_sdk::{Client, NamespaceKey, Value};
use lotusd::{Core, IfInitialized, Server, ServerHandle};
use lotusfs::fuse::Volume;
use tempfile::TempDir;
use tokio::{net::UnixListener, sync::oneshot, task::JoinHandle, time::timeout};

/// How long a step gets before we call it hung. Generous: this bounds a
/// test failure, it does not measure anything.
const GRACE: Duration = Duration::from_secs(30);

/// The inode number of a volume's root.
const ROOT: u64 = 1;

/// A lotus daemon, a directory to serve, and somewhere for a filer and a
/// client to keep their keys.
struct World {
    ledger: Client,
    lotus_state: TempDir,
    volume: TempDir,
    filer_state: TempDir,
    client_state: TempDir,
    /// The loopback port the filer binds, the same across restarts so a
    /// ticket made before one is good after it.
    port: u16,
    // Held so the daemon's mainloop outlives the test.
    _handle: ServerHandle,
    _join: JoinHandle<()>,
}

/// A `filerd run` in progress.
struct Filer {
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result<(), filerd::cli::Error>>,
}

impl Filer {
    /// Stops the filer as a signal would, and waits for the command to
    /// return.
    async fn stop(self) {
        self.stop.send(()).unwrap();
        timeout(GRACE, self.task).await.unwrap().unwrap().unwrap();
    }
}

impl World {
    async fn new() -> Self {
        let lotus_state = TempDir::new().unwrap();
        let core = Core::create_in_state_dir(lotus_state.path().to_path_buf(), IfInitialized::Fail)
            .await
            .unwrap();
        let listener = UnixListener::bind(lotus_sdk::socket_in(lotus_state.path())).unwrap();
        let (handle, join) = Server::new(core, listener).unwrap().run().await;
        // Whatever port the OS hands out now is free in a moment too.
        let port = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        Self {
            ledger: Client::in_state_dir(lotus_state.path()),
            lotus_state,
            volume: TempDir::new().unwrap(),
            filer_state: TempDir::new().unwrap(),
            client_state: TempDir::new().unwrap(),
            port,
            _handle: handle,
            _join: join,
        }
    }

    fn filerd_cli(&self, args: &[&str]) -> filerd::cli::Cli {
        filerd::cli::Cli::try_parse_from(
            [
                "filerd",
                "--lotus-state-dir",
                self.lotus_state.path().to_str().unwrap(),
            ]
            .into_iter()
            .chain(args.iter().copied()),
        )
        .unwrap()
    }

    fn lotusfs_cli(&self, args: &[&str]) -> lotusfs::cli::Cli {
        lotusfs::cli::Cli::try_parse_from(
            [
                "lotusfs",
                "--state-dir",
                self.client_state.path().to_str().unwrap(),
                "--relay",
                "none",
            ]
            .into_iter()
            .chain(args.iter().copied()),
        )
        .unwrap()
    }

    /// Runs a `filerd` command that returns, and gives what it printed.
    async fn filerd(&self, args: &[&str]) -> Result<String, filerd::cli::Error> {
        let mut out = Vec::new();
        filerd::cli::execute(self.filerd_cli(args), &mut out, std::future::pending()).await?;
        Ok(String::from_utf8(out).unwrap())
    }

    /// Runs a `lotusfs` command that returns, and gives what it printed.
    async fn lotusfs(&self, args: &[&str]) -> Result<String, lotusfs::cli::Error> {
        let mut out = Vec::new();
        let run = lotusfs::cli::execute(self.lotusfs_cli(args), &mut out, std::future::pending());
        timeout(GRACE, run).await.expect("the command returns")?;
        Ok(String::from_utf8(out).unwrap())
    }

    /// Starts `filerd run` serving the volume as `scratch`.
    fn start_filer(&self) -> Filer {
        let bind = format!("127.0.0.1:{}", self.port);
        let cli = self.filerd_cli(&[
            "run",
            "--volume",
            &format!("scratch={}", self.volume.path().display()),
            "--state-dir",
            self.filer_state.path().to_str().unwrap(),
            "--relay",
            "none",
            "--bind",
            &bind,
            "--settle",
            "0.1",
        ]);
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            filerd::cli::execute(cli, &mut std::io::sink(), async {
                // Dropped or sent, either stops it.
                let _ = stopped.await;
            })
            .await
        });
        Filer { stop, task }
    }

    /// This client's endpoint id, as `lotusfs id` prints it.
    async fn client_id(&self) -> String {
        self.lotusfs(&["id"]).await.unwrap().trim().to_owned()
    }

    /// Permits this client on `scratch` at `mode`, as an operator would
    /// in the ledger.
    async fn permit(&self, mode: &str) {
        let client = Value::from_iter([
            ("endpoint_id", self.client_id().await),
            ("mode", mode.to_owned()),
        ]);
        let written = self
            .ledger
            .set(
                NamespaceKey::try_new("filers").unwrap(),
                "scratch.allowed_clients"
                    .parse::<lotus_sdk::SubkeyPath>()
                    .unwrap(),
                Value::from_iter([("laptop", client)]),
            )
            .await;
        written.expect("the ledger takes the client");
    }

    /// The ticket `filerd ticket scratch` prints, once it names somewhere
    /// the filer can be dialled.
    async fn ticket(&self) -> String {
        let listed = |ticket: &str| {
            ticket
                .parse::<Ticket>()
                .is_ok_and(|ticket| !ticket.filer.is_empty())
        };
        eventually(async || {
            self.filerd(&["ticket", "scratch"])
                .await
                .ok()
                .map(|ticket| ticket.trim().to_owned())
                .filter(|ticket| listed(ticket))
        })
        .await
    }

    /// The line `lotusfs ls` prints for the file at `path` in the volume,
    /// listed as `name`: its permissions and size are the backing
    /// filesystem's, which the test does not decide.
    fn line(&self, kind: char, path: &str, name: &str) -> String {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(self.volume.path().join(path)).unwrap();
        format!(
            "{kind}{:04o} {:>12} {name}",
            meta.mode() & 0o7777,
            meta.len()
        )
    }

    /// Runs a `lotusfs` command until the filer admits it: what an
    /// operator writes to the ledger takes a moment to reach the filer.
    async fn admitted(&self, args: &[&str]) -> String {
        eventually(async || self.lotusfs(args).await.ok()).await
    }
}

/// Tries `step` until it yields something, for as long as [`GRACE`].
async fn eventually<T>(mut step: impl AsyncFnMut() -> Option<T>) -> T {
    let started = Instant::now();
    loop {
        if let Some(done) = step().await {
            return done;
        }
        assert!(started.elapsed() < GRACE, "gave up waiting");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn name(text: &str) -> filer_client::proto::fs::Name {
    filer_client::proto::fs::Name::try_new(text).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_volume_goes_from_served_to_read_through_the_commands() {
    let world = World::new().await;
    std::fs::write(world.volume.path().join("seed.txt"), b"from the filer\n").unwrap();
    std::fs::create_dir(world.volume.path().join("docs")).unwrap();
    std::fs::write(world.volume.path().join("docs/a"), b"a").unwrap();
    let filer = world.start_filer();

    // The filer claims the volume, and any node can print its ticket.
    let ticket = world.ticket().await;
    assert!(ticket.starts_with("lotusfs1"), "{ticket}");

    // A client the ledger does not list is refused, ticket or no.
    let refused = world.lotusfs(&["ls", &ticket]).await.unwrap_err();
    assert!(
        matches!(
            refused,
            lotusfs::cli::Error::Filer(filer_client::Error::Refused(Close::NotPermitted))
        ),
        "{refused:?}"
    );

    // Listed, it reads.
    world.permit("ro").await;
    let listing = world.admitted(&["ls", &ticket]).await;
    assert_eq!(
        listing.lines().collect::<Vec<_>>(),
        [
            world.line('d', "docs", "docs"),
            world.line('-', "seed.txt", "seed.txt")
        ]
    );
    assert_eq!(
        world.lotusfs(&["ls", &ticket, "docs"]).await.unwrap(),
        format!("{}\n", world.line('-', "docs/a", "a"))
    );
    assert_eq!(
        world.lotusfs(&["cat", &ticket, "/seed.txt"]).await.unwrap(),
        "from the filer\n"
    );

    // And what makes no sense says so.
    assert!(matches!(
        world.lotusfs(&["cat", &ticket, "docs"]).await,
        Err(lotusfs::cli::Error::IsDir { .. })
    ));
    assert!(matches!(
        world.lotusfs(&["cat", &ticket, "missing"]).await,
        Err(lotusfs::cli::Error::Filer(_))
    ));

    filer.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ticket_for_a_volume_nobody_serves_is_refused() {
    let world = World::new().await;

    assert!(matches!(
        world.filerd(&["ticket", "scratch"]).await,
        Err(filerd::cli::Error::NotListed { .. })
    ));
}

/// What a mount does, without the mount: the FUSE layer driven as the
/// kernel drives it, by inode number, over the endpoint and ticket the
/// commands produce — through a restart of the filer, which forgets where
/// every file is.
#[tokio::test(flavor = "multi_thread")]
async fn the_fuse_layer_works_a_volume_through_a_filer_restart() {
    let world = World::new().await;
    let filer = world.start_filer();
    let ticket = world.ticket().await;
    world.permit("rw").await;
    world.admitted(&["ls", &ticket]).await;

    let endpoint = lotusfs::cli::endpoint(&world.lotusfs_cli(&["id"]))
        .await
        .unwrap();
    let session = Arc::new(Session::new(endpoint.clone(), ticket.parse().unwrap()));
    let volume = Volume::new(session, (1000, 1000));
    let mkdir = |parent, name| {
        Request::Mkdir(Mkdir {
            parent,
            name,
            mode: 0o755,
        })
    };
    let create = |parent, name| {
        Request::Create(Create {
            parent,
            name,
            mode: 0o644,
            exclusive: true,
        })
    };

    // A file two directories down, larger than one request carries.
    let docs = volume.entry(ROOT, name("docs"), mkdir).await.unwrap();
    let deep = volume
        .entry(docs.node.ino(), name("deep"), mkdir)
        .await
        .unwrap();
    let file = volume
        .entry(deep.node.ino(), name("big"), create)
        .await
        .unwrap();
    let contents: Vec<u8> = (0..MAX_IO_LEN as usize * 2 + 4321)
        .map(|i| (i % 251) as u8)
        .collect();
    let written = volume
        .write(file.node.ino(), 0, contents.clone())
        .await
        .unwrap();
    assert_eq!(written as usize, contents.len());
    assert_eq!(
        std::fs::read(world.volume.path().join("docs/deep/big")).unwrap(),
        contents
    );
    let read = volume
        .read(file.node.ino(), 0, contents.len() as u32 + 100)
        .await
        .unwrap();
    assert!(read == contents, "read back {} bytes", read.len());

    // Listed, moved, and found where it went.
    let listed = volume.list(deep.node.ino()).await.unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|entry| (entry.name.as_str(), entry.attr.kind))
            .collect::<Vec<_>>(),
        [("big", Kind::File)]
    );
    volume
        .rename(deep.node.ino(), name("big"), docs.node.ino(), name("moved"))
        .await
        .unwrap();
    assert!(world.volume.path().join("docs/moved").exists());

    // The filer restarts and knows no node. The kernel still holds its
    // inode numbers, and they still work: the file where it moved to,
    // and a directory two levels down.
    filer.stop().await;
    let filer = world.start_filer();
    let after = timeout(GRACE, volume.read(file.node.ino(), 4321, 10))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after, contents[4321..4331]);
    let made = volume
        .entry(deep.node.ino(), name("after"), create)
        .await
        .unwrap();
    assert!(world.volume.path().join("docs/deep/after").exists());

    // A file removed behind the kernel's back is stale, not someone else's.
    std::fs::remove_file(world.volume.path().join("docs/deep/after")).unwrap();
    let stale = volume.read(made.node.ino(), 0, 1).await.unwrap_err();
    assert_eq!(stale.code(), fuser::Errno::ESTALE.code());

    // The filer's refusals reach the kernel as the errno they mean.
    let missing = volume
        .done(ROOT, |parent| {
            Request::Unlink(Unlink {
                parent,
                name: name("missing"),
            })
        })
        .await
        .unwrap_err();
    assert_eq!(missing.code(), fuser::Errno::ENOENT.code());

    // Once the kernel forgets a node, its number means nothing.
    volume.forget(file.node.ino(), 1);
    let forgotten = volume.read(file.node.ino(), 0, 1).await.unwrap_err();
    assert_eq!(forgotten.code(), fuser::Errno::ESTALE.code());
    // And looking it up again makes it known again.
    let found = volume
        .entry(docs.node.ino(), name("moved"), |parent, name| {
            Request::Lookup(Lookup { parent, name })
        })
        .await
        .unwrap();
    assert_eq!(found.node, file.node);

    filer.stop().await;
    endpoint.close().await;
}

/// Narrowed to read-only in the ledger, a client that was writing is
/// hung up on and comes back able only to read.
#[tokio::test(flavor = "multi_thread")]
async fn narrowing_a_client_in_the_ledger_stops_its_writes() {
    let world = World::new().await;
    std::fs::write(world.volume.path().join("seed.txt"), b"as it was").unwrap();
    let filer = world.start_filer();
    let ticket = world.ticket().await;
    world.permit("rw").await;
    world.admitted(&["ls", &ticket]).await;

    let endpoint = lotusfs::cli::endpoint(&world.lotusfs_cli(&["id"]))
        .await
        .unwrap();
    let volume = Volume::new(
        Arc::new(Session::new(endpoint.clone(), ticket.parse().unwrap())),
        (1000, 1000),
    );
    let lookup = |parent, name| Request::Lookup(Lookup { parent, name });
    let seed = volume.entry(ROOT, name("seed.txt"), lookup).await.unwrap();
    volume
        .write(seed.node.ino(), 0, b"AS".to_vec())
        .await
        .unwrap();

    world.permit("ro").await;

    // The change takes a moment to reach the filer, and until it does
    // writes still land — so these write what is already there.
    let refused =
        eventually(async || volume.write(seed.node.ino(), 0, b"AS".to_vec()).await.err()).await;
    // Hung up on mid-write, or refused outright once reconnected.
    assert!(
        [fuser::Errno::EROFS.code(), fuser::Errno::EACCES.code()].contains(&refused.code()),
        "{refused:?}"
    );
    let read = eventually(async || volume.read(seed.node.ino(), 0, 100).await.ok()).await;
    assert_eq!(read, b"AS it was");
    let refused = volume
        .write(seed.node.ino(), 0, b"no".to_vec())
        .await
        .unwrap_err();
    assert_eq!(refused.code(), fuser::Errno::EROFS.code());

    filer.stop().await;
    endpoint.close().await;
}
