//! A volume as a FUSE filesystem.
//!
//! The kernel's requests are the protocol's, near enough one for one, so
//! most of this is translation. What it adds is memory. The kernel names
//! a file by inode number alone; the filer wants the generation with it,
//! and — when it has restarted and forgotten where files are — to be
//! shown the way again. So every node the kernel has been told of is
//! remembered with its full id and the directory and name it was found
//! under, and an operation the filer answers [`Errno::Stale`] is tried
//! once more after looking the node up again from its parent, and that
//! from its own, up to the root.
//!
//! The kernel's callbacks are synchronous and the session is not, so each
//! one hands its reply to a task on the runtime and returns.
//!
//! Everything is shown as owned by whoever owns the mountpoint: ownership
//! does not travel the protocol.

use std::{
    collections::HashMap,
    ffi::OsStr,
    future::Future,
    io,
    os::unix::fs::MetadataExt,
    path::Path,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use filer_client::{Error, Session};
use filer_proto::{
    Close, Mode,
    fs::{
        Attr, ByteBuf, Create, DirEntry, Errno as Refusal, Fsync, GetAttr, Kind, Lookup,
        MAX_IO_LEN, Mkdir, Name, NodeId, Read, ReadLink, Rename, Reply, Request, Rmdir, SetAttr,
        Symlink, Time, Unlink, Write,
    },
};
use fuser::{
    BackgroundSession, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, LockOwner, MountOption, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, TimeOrNow,
    WriteFlags,
};
use tokio::runtime::Handle;

/// How long the kernel may go on what it was last told of a node before
/// asking again. Other clients change the volume unannounced, so this is
/// how stale a view can get.
const TTL: Duration = Duration::from_secs(1);

/// The inode number of the root, the kernel's and the protocol's alike.
const ROOT: u64 = 1;

/// A node the kernel has been told of.
#[derive(Debug, Clone)]
struct Known {
    id: NodeId,
    /// The inode number of the directory it was last found in.
    parent: u64,
    name: Name,
    /// How many lookups the kernel holds on it; forgotten at zero.
    lookups: u64,
}

/// Why an operation did not come back with a reply to pass on.
enum Fail {
    /// The filer does not know the node. Worth looking it up again.
    Stale,
    Errno(Errno),
}

type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A volume as the kernel's requests see it: every operation by inode
/// number, each answered with what the kernel is to be told.
///
/// Apart from the kernel, so it can be driven without a mount.
pub struct Volume {
    session: Arc<Session>,
    /// Who everything is shown as owned by.
    owner: (u32, u32),
    nodes: Mutex<HashMap<u64, Known>>,
    /// The listings of open directories, by handle: read whole on the
    /// first read, so the offsets the kernel resumes from stay put.
    dirs: Mutex<HashMap<u64, Arc<Vec<DirEntry>>>>,
    next_dir: AtomicU64,
}

impl Volume {
    /// The volume `session` is for, everything on it shown as owned by
    /// the user and group `owner`.
    pub fn new(session: Arc<Session>, owner: (u32, u32)) -> Self {
        Self {
            session,
            owner,
            nodes: Mutex::new(HashMap::new()),
            dirs: Mutex::new(HashMap::new()),
            next_dir: AtomicU64::new(1),
        }
    }

    fn nodes(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Known>> {
        self.nodes.lock().expect("nothing panics holding the nodes")
    }

    fn dirs(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Arc<Vec<DirEntry>>>> {
        self.dirs
            .lock()
            .expect("nothing panics holding the listings")
    }

    /// The id the kernel means by `ino`.
    fn id(&self, ino: u64) -> Result<NodeId, Errno> {
        if ino == ROOT {
            return Ok(NodeId::ROOT);
        }
        self.nodes()
            .get(&ino)
            .map(|known| known.id)
            .ok_or(Errno::ESTALE)
    }

    /// Notes that the kernel was told of `attr`'s node, found at `name`
    /// in `parent`, and holds one more lookup on it.
    fn remember(&self, parent: u64, name: Name, attr: &Attr) {
        if attr.node == NodeId::ROOT {
            return;
        }
        let mut nodes = self.nodes();
        let lookups = nodes.get(&attr.node.ino()).map_or(0, |known| known.lookups);
        nodes.insert(
            attr.node.ino(),
            Known {
                id: attr.node,
                parent,
                name,
                lookups: lookups + 1,
            },
        );
    }

    /// Drops `lookups` of the lookups the kernel holds on `ino`, and the
    /// node with the last of them.
    pub fn forget(&self, ino: u64, lookups: u64) {
        let mut nodes = self.nodes();
        if let Some(known) = nodes.get_mut(&ino) {
            known.lookups = known.lookups.saturating_sub(lookups);
            if known.lookups == 0 {
                nodes.remove(&ino);
            }
        }
    }

    /// Sends `request`, sorting what comes back into a reply to pass on,
    /// a stale node, and everything else as the errno the kernel gets.
    async fn send(&self, request: Request) -> Result<Reply, Fail> {
        match self.session.call(request).await {
            Ok(Reply::Error(Refusal::Stale)) => Err(Fail::Stale),
            Ok(Reply::Error(refusal)) => Err(Fail::Errno(errno(refusal))),
            Ok(reply) => Ok(reply),
            Err(error) => {
                tracing::warn!(%error, "the filer could not be asked");
                Err(Fail::Errno(match error {
                    Error::Refused(Close::NotPermitted | Close::Revoked) => Errno::EACCES,
                    _ => Errno::EIO,
                }))
            }
        }
    }

    /// Shows the filer the way to `ino` again: looks it up from its
    /// parent, reviving that first if it too is stale. Fails with `ESTALE`
    /// when what is found there is no longer the node the kernel knows.
    fn revive(&self, ino: u64) -> Boxed<'_, Result<NodeId, Errno>> {
        Box::pin(async move {
            if ino == ROOT {
                return Ok(NodeId::ROOT);
            }
            let known = self.nodes().get(&ino).cloned().ok_or(Errno::ESTALE)?;
            let lookup = |parent| {
                Request::Lookup(Lookup {
                    parent,
                    name: known.name.clone(),
                })
            };
            let found = match self.send(lookup(self.id(known.parent)?)).await {
                Err(Fail::Stale) => self.send(lookup(self.revive(known.parent).await?)).await,
                found => found,
            };
            match found {
                Ok(Reply::Attr(attr)) if attr.node == known.id => Ok(known.id),
                Ok(_) | Err(Fail::Stale) => Err(Errno::ESTALE),
                Err(Fail::Errno(e)) if e.code() == Errno::ENOENT.code() => Err(Errno::ESTALE),
                Err(Fail::Errno(e)) => Err(e),
            }
        })
    }

    /// Carries out the request `make` builds for `ino`, reviving the node
    /// and trying once more when the filer calls it stale.
    async fn on(&self, ino: u64, make: impl Fn(NodeId) -> Request) -> Result<Reply, Errno> {
        let retried = match self.send(make(self.id(ino)?)).await {
            Err(Fail::Stale) => self.send(make(self.revive(ino).await?)).await,
            first => first,
        };
        retried.map_err(|fail| match fail {
            Fail::Stale => Errno::ESTALE,
            Fail::Errno(e) => e,
        })
    }

    /// Carries out a request on `ino` that ends in attributes.
    pub async fn attr(&self, ino: u64, make: impl Fn(NodeId) -> Request) -> Result<Attr, Errno> {
        match self.on(ino, make).await? {
            Reply::Attr(attr) => Ok(attr),
            _ => Err(Errno::EIO),
        }
    }

    /// Carries out a request on `ino` that ends in nothing.
    pub async fn done(&self, ino: u64, make: impl Fn(NodeId) -> Request) -> Result<(), Errno> {
        match self.on(ino, make).await? {
            Reply::Done(_) => Ok(()),
            _ => Err(Errno::EIO),
        }
    }

    /// Carries out a request in the directory `parent` that ends in the
    /// node at `name` there, and remembers the kernel is told of it.
    pub async fn entry(
        &self,
        parent: u64,
        name: Name,
        make: impl Fn(NodeId, Name) -> Request,
    ) -> Result<Attr, Errno> {
        let attr = self.attr(parent, |id| make(id, name.clone())).await?;
        self.remember(parent, name, &attr);
        Ok(attr)
    }

    /// Reads `size` bytes of the file `ino` from `offset`, fewer only at
    /// its end.
    pub async fn read(&self, ino: u64, offset: u64, size: u32) -> Result<Vec<u8>, Errno> {
        // The kernel takes a short read for the end of the file, so what
        // one request cannot carry is fetched with more.
        let mut data = Vec::with_capacity(size as usize);
        while data.len() < size as usize {
            let at = offset + data.len() as u64;
            let len = (size as usize - data.len()).min(MAX_IO_LEN as usize) as u32;
            let Reply::Data(part) = self
                .on(ino, |node| {
                    Request::Read(Read {
                        node,
                        offset: at,
                        len,
                    })
                })
                .await?
            else {
                return Err(Errno::EIO);
            };
            if part.is_empty() {
                break;
            }
            data.extend_from_slice(&part);
        }
        Ok(data)
    }

    /// Writes `data` into the file `ino` at `offset`.
    pub async fn write(&self, ino: u64, offset: u64, data: Vec<u8>) -> Result<u32, Errno> {
        let mut at = offset;
        for chunk in data.chunks(MAX_IO_LEN as usize) {
            self.done(ino, |node| {
                Request::Write(Write {
                    node,
                    offset: at,
                    data: ByteBuf::from(chunk.to_vec()),
                })
            })
            .await?;
            at += chunk.len() as u64;
        }
        Ok(data.len() as u32)
    }

    /// Every entry of the directory `ino`.
    pub async fn list(&self, ino: u64) -> Result<Vec<DirEntry>, Errno> {
        let list = |node| async move {
            match self.session.list(node).await {
                Err(error) if error.errno() == Some(Refusal::Stale) => Err(Fail::Stale),
                Err(Error::Op(refusal)) => Err(Fail::Errno(errno(refusal))),
                Err(error) => {
                    tracing::warn!(%error, "the filer could not be asked");
                    Err(Fail::Errno(Errno::EIO))
                }
                Ok(entries) => Ok(entries),
            }
        };
        let retried = match list(self.id(ino)?).await {
            Err(Fail::Stale) => list(self.revive(ino).await?).await,
            first => first,
        };
        retried.map_err(|fail| match fail {
            Fail::Stale => Errno::ESTALE,
            Fail::Errno(e) => e,
        })
    }

    /// Moves `name` in `parent` to `new_name` in `new_parent`.
    pub async fn rename(
        &self,
        parent: u64,
        name: Name,
        new_parent: u64,
        new_name: Name,
    ) -> Result<(), Errno> {
        let rename = |parent, new_parent| {
            Request::Rename(Rename {
                parent,
                name: name.clone(),
                new_parent,
                new_name: new_name.clone(),
            })
        };
        let retried = match self
            .send(rename(self.id(parent)?, self.id(new_parent)?))
            .await
        {
            Err(Fail::Stale) => {
                let (from, to) = (self.revive(parent).await?, self.revive(new_parent).await?);
                self.send(rename(from, to)).await
            }
            first => first,
        };
        retried.map_err(|fail| match fail {
            Fail::Stale => Errno::ESTALE,
            Fail::Errno(e) => e,
        })?;
        // The node moved; where it is remembered moves with it, or
        // reviving it later would look in the place it left.
        if let Some(known) = self
            .nodes()
            .values_mut()
            .find(|known| known.parent == parent && known.name == name)
        {
            known.parent = new_parent;
            known.name = new_name;
        }
        Ok(())
    }

    fn file_attr(&self, attr: &Attr) -> FileAttr {
        let time = |time: Time| {
            let since = Duration::new(time.secs.unsigned_abs(), 0);
            let at = if time.secs >= 0 {
                UNIX_EPOCH.checked_add(since)
            } else {
                UNIX_EPOCH.checked_sub(since)
            };
            at.and_then(|at| at.checked_add(Duration::new(0, time.nanos)))
                .unwrap_or(UNIX_EPOCH)
        };
        FileAttr {
            ino: INodeNo(attr.node.ino()),
            size: attr.size,
            blocks: attr.size.div_ceil(512),
            atime: time(attr.atime),
            mtime: time(attr.mtime),
            ctime: time(attr.ctime),
            crtime: time(attr.ctime),
            kind: file_type(attr.kind),
            perm: attr.mode as u16,
            nlink: attr.nlink,
            uid: self.owner.0,
            gid: self.owner.1,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        }
    }
}

fn file_type(kind: Kind) -> FileType {
    match kind {
        Kind::File => FileType::RegularFile,
        Kind::Dir => FileType::Directory,
        Kind::Symlink => FileType::Symlink,
    }
}

/// What the kernel is told for a failure the filer reported.
fn errno(refusal: Refusal) -> Errno {
    match refusal {
        Refusal::NotFound => Errno::ENOENT,
        Refusal::Exists => Errno::EEXIST,
        Refusal::NotDir => Errno::ENOTDIR,
        Refusal::IsDir => Errno::EISDIR,
        Refusal::NotEmpty => Errno::ENOTEMPTY,
        Refusal::Stale => Errno::ESTALE,
        Refusal::ReadOnly => Errno::EROFS,
        Refusal::Access => Errno::EACCES,
        Refusal::Invalid => Errno::EINVAL,
        Refusal::NoSpace => Errno::ENOSPC,
        Refusal::TooLarge => Errno::EFBIG,
        Refusal::CrossDevice => Errno::EXDEV,
        Refusal::Unsupported => Errno::ENOTSUP,
        Refusal::Io => Errno::EIO,
    }
}

/// The protocol's spelling of a time the kernel sets.
fn wire_time(time: TimeOrNow) -> Time {
    let at = match time {
        TimeOrNow::SpecificTime(at) => at,
        TimeOrNow::Now => SystemTime::now(),
    };
    match at.duration_since(UNIX_EPOCH) {
        Ok(since) => Time {
            secs: i64::try_from(since.as_secs()).unwrap_or(i64::MAX),
            nanos: since.subsec_nanos(),
        },
        // Before the epoch: whole seconds back, then nanoseconds forward.
        Err(before) => {
            let before = before.duration();
            let (secs, nanos) = match before.subsec_nanos() {
                0 => (before.as_secs(), 0),
                nanos => (before.as_secs() + 1, 1_000_000_000 - nanos),
            };
            Time {
                secs: i64::try_from(secs).map_or(i64::MIN, |secs| -secs),
                nanos,
            }
        }
    }
}

/// A name the kernel gave, as the protocol carries one.
fn name(name: &OsStr) -> Result<Name, Errno> {
    name.to_str()
        .and_then(|name| Name::try_new(name).ok())
        .ok_or(Errno::EINVAL)
}

/// The filesystem handed to the kernel: the volume, and the runtime its
/// operations run on.
struct Mounted {
    volume: Arc<Volume>,
    runtime: Handle,
}

impl Mounted {
    /// Runs `op` on the runtime and hands what it yields to `reply`.
    fn run<T, F>(&self, op: impl FnOnce(Arc<Volume>) -> F, reply: impl FnOnce(T) + Send + 'static)
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let op = op(Arc::clone(&self.volume));
        self.runtime.spawn(async move { reply(op.await) });
    }
}

fn entry(volume: &Volume, found: Result<Attr, Errno>, reply: ReplyEntry) {
    match found {
        Ok(attr) => reply.entry(
            &TTL,
            &volume.file_attr(&attr),
            Generation(attr.node.generation()),
        ),
        Err(e) => reply.error(e),
    }
}

fn empty(done: Result<(), Errno>, reply: ReplyEmpty) {
    match done {
        Ok(()) => reply.ok(),
        Err(e) => reply.error(e),
    }
}

impl Filesystem for Mounted {
    fn lookup(&self, _req: &fuser::Request, parent: INodeNo, name_: &OsStr, reply: ReplyEntry) {
        // A name the protocol cannot carry names nothing on the volume.
        let Ok(name) = name(name_) else {
            return reply.error(Errno::ENOENT);
        };
        self.run(
            move |v| async move {
                let found = v
                    .entry(parent.0, name, |parent, name| {
                        Request::Lookup(Lookup { parent, name })
                    })
                    .await;
                (v, found)
            },
            move |(v, found)| entry(&v, found, reply),
        );
    }

    fn forget(&self, _req: &fuser::Request, ino: INodeNo, nlookup: u64) {
        self.volume.forget(ino.0, nlookup);
    }

    fn getattr(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        _fh: Option<FileHandle>,
        reply: ReplyAttr,
    ) {
        self.run(
            move |v| async move {
                let attr = v
                    .attr(ino.0, |node| Request::GetAttr(GetAttr { node }))
                    .await;
                (v, attr)
            },
            move |(v, attr)| match attr {
                Ok(attr) => reply.attr(&TTL, &v.file_attr(&attr)),
                Err(e) => reply.error(e),
            },
        );
    }

    fn setattr(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        _kill_suid_gid: bool,
        reply: ReplyAttr,
    ) {
        // Ownership does not travel, so a change of owner changes nothing
        // and is not an error: tools that copy files try it as a matter
        // of course.
        let (atime, mtime) = (atime.map(wire_time), mtime.map(wire_time));
        let changes = mode.is_some() || size.is_some() || atime.is_some() || mtime.is_some();
        self.run(
            move |v| async move {
                let attr = v
                    .attr(ino.0, |node| {
                        if changes {
                            Request::SetAttr(SetAttr {
                                node,
                                mode,
                                size,
                                atime,
                                mtime,
                            })
                        } else {
                            Request::GetAttr(GetAttr { node })
                        }
                    })
                    .await;
                (v, attr)
            },
            move |(v, attr)| match attr {
                Ok(attr) => reply.attr(&TTL, &v.file_attr(&attr)),
                Err(e) => reply.error(e),
            },
        );
    }

    fn readlink(&self, _req: &fuser::Request, ino: INodeNo, reply: ReplyData) {
        self.run(
            move |v| async move {
                v.on(ino.0, |node| Request::ReadLink(ReadLink { node }))
                    .await
            },
            move |target| match target {
                Ok(Reply::Link(target)) => reply.data(target.as_bytes()),
                Ok(_) => reply.error(Errno::EIO),
                Err(e) => reply.error(e),
            },
        );
    }

    fn mkdir(
        &self,
        _req: &fuser::Request,
        parent: INodeNo,
        name_: &OsStr,
        mode: u32,
        umask: u32,
        _owner: fuser::Owner,
        reply: ReplyEntry,
    ) {
        let Ok(name) = name(name_) else {
            return reply.error(Errno::EINVAL);
        };
        self.run(
            move |v| async move {
                let made = v
                    .entry(parent.0, name, |parent, name| {
                        Request::Mkdir(Mkdir {
                            parent,
                            name,
                            mode: mode & !umask,
                        })
                    })
                    .await;
                (v, made)
            },
            move |(v, made)| entry(&v, made, reply),
        );
    }

    fn unlink(&self, _req: &fuser::Request, parent: INodeNo, name_: &OsStr, reply: ReplyEmpty) {
        let Ok(name) = name(name_) else {
            return reply.error(Errno::ENOENT);
        };
        self.run(
            move |v| async move {
                v.done(parent.0, |parent| {
                    Request::Unlink(Unlink {
                        parent,
                        name: name.clone(),
                    })
                })
                .await
            },
            move |done| empty(done, reply),
        );
    }

    fn rmdir(&self, _req: &fuser::Request, parent: INodeNo, name_: &OsStr, reply: ReplyEmpty) {
        let Ok(name) = name(name_) else {
            return reply.error(Errno::ENOENT);
        };
        self.run(
            move |v| async move {
                v.done(parent.0, |parent| {
                    Request::Rmdir(Rmdir {
                        parent,
                        name: name.clone(),
                    })
                })
                .await
            },
            move |done| empty(done, reply),
        );
    }

    fn symlink(
        &self,
        _req: &fuser::Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        _owner: fuser::Owner,
        reply: ReplyEntry,
    ) {
        let (Ok(name), Some(target)) = (name(link_name), target.to_str().map(str::to_owned)) else {
            return reply.error(Errno::EINVAL);
        };
        self.run(
            move |v| async move {
                let made = v
                    .entry(parent.0, name, |parent, name| {
                        Request::Symlink(Symlink {
                            parent,
                            name,
                            target: target.clone(),
                        })
                    })
                    .await;
                (v, made)
            },
            move |(v, made)| entry(&v, made, reply),
        );
    }

    fn rename(
        &self,
        _req: &fuser::Request,
        parent: INodeNo,
        name_: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        _owner: Option<fuser::Owner>,
        reply: ReplyEmpty,
    ) {
        // The protocol's rename replaces, and has no other kind.
        if !flags.is_empty() {
            return reply.error(Errno::EINVAL);
        }
        let (Ok(name), Ok(new_name)) = (name(name_), name(newname)) else {
            return reply.error(Errno::EINVAL);
        };
        self.run(
            move |v| async move { v.rename(parent.0, name, newparent.0, new_name).await },
            move |done| empty(done, reply),
        );
    }

    fn read(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        self.run(
            move |v| async move { v.read(ino.0, offset, size).await },
            move |data| match data {
                Ok(data) => reply.data(&data),
                Err(e) => reply.error(e),
            },
        );
    }

    fn write(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let data = data.to_vec();
        self.run(
            move |v| async move { v.write(ino.0, offset, data).await },
            move |written| match written {
                Ok(written) => reply.written(written),
                Err(e) => reply.error(e),
            },
        );
    }

    fn flush(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        // Nothing is buffered here: a write has reached the filer by the
        // time it is answered.
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        self.run(
            move |v| async move { v.done(ino.0, |node| Request::Fsync(Fsync { node })).await },
            move |done| empty(done, reply),
        );
    }

    fn opendir(&self, _req: &fuser::Request, _ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let handle = self.volume.next_dir.fetch_add(1, Ordering::Relaxed);
        reply.opened(FileHandle(handle), FopenFlags::empty());
    }

    fn readdir(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        self.run(
            move |v| async move {
                // Read afresh from the start, so a rewound directory is
                // listed as it now is; resumed from what was read.
                let held = (offset != 0)
                    .then(|| v.dirs().get(&fh.0).cloned())
                    .flatten();
                match held {
                    Some(listing) => Ok(listing),
                    None => {
                        let listing = Arc::new(v.list(ino.0).await?);
                        v.dirs().insert(fh.0, Arc::clone(&listing));
                        Ok(listing)
                    }
                }
            },
            move |listing: Result<Arc<Vec<DirEntry>>, Errno>| {
                let listing = match listing {
                    Ok(listing) => listing,
                    Err(e) => return reply.error(e),
                };
                let dots = [".", ".."]
                    .into_iter()
                    .map(|dot| (ino, FileType::Directory, dot));
                let entries = listing.iter().map(|entry| {
                    (
                        INodeNo(entry.attr.node.ino()),
                        file_type(entry.attr.kind),
                        entry.name.as_str(),
                    )
                });
                // An entry's offset is where the one after it starts.
                for (at, (ino, kind, name)) in dots.chain(entries).enumerate().skip(offset as usize)
                {
                    if reply.add(ino, at as u64 + 1, kind, name) {
                        break;
                    }
                }
                reply.ok();
            },
        );
    }

    fn releasedir(
        &self,
        _req: &fuser::Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        self.volume.dirs().remove(&fh.0);
        reply.ok();
    }

    fn create(
        &self,
        _req: &fuser::Request,
        parent: INodeNo,
        name_: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        _kill_suid_gid: bool,
        _owner: fuser::Owner,
        reply: ReplyCreate,
    ) {
        let Ok(name) = name(name_) else {
            return reply.error(Errno::EINVAL);
        };
        let exclusive = flags & libc::O_EXCL != 0;
        let truncate = flags & libc::O_TRUNC != 0;
        self.run(
            move |v| async move {
                let made = async {
                    let made = v
                        .entry(parent.0, name, |parent, name| {
                            Request::Create(Create {
                                parent,
                                name,
                                mode: mode & !umask,
                                exclusive,
                            })
                        })
                        .await?;
                    // A create that found the file already there is still
                    // an open, and one asked to truncate.
                    if truncate && made.size > 0 {
                        v.attr(made.node.ino(), |node| {
                            Request::SetAttr(SetAttr {
                                node,
                                mode: None,
                                size: Some(0),
                                atime: None,
                                mtime: None,
                            })
                        })
                        .await
                    } else {
                        Ok(made)
                    }
                };
                let made = made.await;
                (v, made)
            },
            move |(v, made)| match made {
                Ok(attr) => reply.created(
                    &TTL,
                    &v.file_attr(&attr),
                    Generation(attr.node.generation()),
                    FileHandle(0),
                    FopenFlags::empty(),
                ),
                Err(e) => reply.error(e),
            },
        );
    }
}

/// Mounts `session`'s volume at `mountpoint`, its operations running on
/// `runtime`. Unmounted when the returned session is joined or dropped.
pub fn mount(
    runtime: Handle,
    session: Arc<Session>,
    mode: Mode,
    mountpoint: &Path,
) -> io::Result<BackgroundSession> {
    let owner = std::fs::metadata(mountpoint)?;
    let volume = Arc::new(Volume::new(
        Arc::clone(&session),
        (owner.uid(), owner.gid()),
    ));

    let mut config = Config::default();
    config.mount_options.extend([
        MountOption::FSName(format!("lotusfs:{}", session.ticket().volume)),
        MountOption::Subtype("lotusfs".to_owned()),
        // The kernel checks permission bits against the owner shown, as
        // it would on a local disk.
        MountOption::DefaultPermissions,
        MountOption::NoDev,
        MountOption::NoSuid,
        match mode {
            Mode::ReadOnly => MountOption::RO,
            Mode::ReadWrite => MountOption::RW,
        },
    ]);
    fuser::spawn_mount(Mounted { volume, runtime }, mountpoint, &config)
}
