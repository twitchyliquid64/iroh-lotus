//! A volume's directory, and the operations of the protocol carried out
//! against it.
//!
//! Every path opened for a client resolves beneath the volume's root: the
//! root is held as a [`Dir`], which cannot be walked out of — not by `..`,
//! not through a symlink a client planted — and a client names files by
//! [`NodeId`] and [`Name`], never by path.
//!
//! A node's id is its inode number on the backing filesystem, so it
//! outlives the connection and the filer. Filesystems hand a freed number
//! straight to the next file, so the id also carries a generation — on
//! Linux, the file's creation time — and a file is the one an id names
//! only when both match. That is as good as the creation time is: a
//! filesystem that records none leaves the generation 0, and two files
//! given one number within one tick of its clock cannot be told apart. Turning an id back into a file
//! needs to know where the file is, which is remembered — parent and name
//! per node — as lookups and listings find it. That memory is the only
//! state here and it is disposable: an id it does not hold, or one whose
//! remembered place now holds some other file, answers [`Errno::Stale`]
//! and the client looks it up again.
//!
//! Everything blocks. Callers run it off the async runtime.

use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, SystemTimeSpec};
use cap_std::{
    ambient_authority,
    fs::{
        Dir, DirBuilder, DirBuilderExt, FileExt, Metadata, MetadataExt, OpenOptions,
        OpenOptionsExt, Permissions, PermissionsExt,
    },
};
use filer_proto::fs::{
    Attr, ByteBuf, Create, DirEntry, DirPage, Done, Errno, Fsync, GetAttr, Kind, Lookup,
    MAX_DIR_PAGE, MAX_IO_LEN, MAX_TARGET_LEN, Mkdir, Name, NodeId, Read, ReadDir, ReadLink, Rename,
    Reply, Request, Rmdir, SetAttr, Symlink, Time, Unlink, Write,
};

/// The permission bits a client may set.
const MODE_MASK: u32 = 0o7777;

/// How deep a remembered place may sit below the root before it is taken
/// for a loop in the memory rather than a path.
const MAX_DEPTH: usize = 4096;

/// Where a node was last found.
#[derive(Debug, Clone)]
struct Place {
    parent: NodeId,
    name: Name,
}

/// A directory served as a volume.
#[derive(Debug)]
pub struct Backing {
    root: Dir,
    /// The root's inode number, which trades places with 1 so the root is
    /// [`NodeId::ROOT`] whatever the filesystem numbers it.
    root_ino: u64,
    /// The filesystem the root is on. Nothing on another is served.
    dev: u64,
    /// Never pruned: an entry is a few dozen bytes, and one for a file
    /// that is gone only costs that.
    places: Mutex<HashMap<NodeId, Place>>,
}

impl Backing {
    /// Opens the directory at `path` to serve it.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let root = Dir::open_ambient_dir(path, ambient_authority())?;
        let meta = root.dir_metadata()?;
        Ok(Self {
            root_ino: meta.ino(),
            dev: meta.dev(),
            root,
            places: Mutex::new(HashMap::new()),
        })
    }

    /// Carries out `request`.
    pub fn handle(&self, request: Request) -> Reply {
        let outcome = match request {
            Request::Lookup(r) => self.lookup(r).map(Reply::Attr),
            Request::GetAttr(r) => self.get_attr(r).map(Reply::Attr),
            Request::SetAttr(r) => self.set_attr(r).map(Reply::Attr),
            Request::ReadDir(r) => self.read_dir(r).map(Reply::Dir),
            Request::Read(r) => self.read(r).map(Reply::Data),
            Request::Write(r) => self.write(r).map(done),
            Request::Create(r) => self.create(r).map(Reply::Attr),
            Request::Mkdir(r) => self.mkdir(r).map(Reply::Attr),
            Request::Unlink(r) => self.unlink(r).map(done),
            Request::Rmdir(r) => self.rmdir(r).map(done),
            Request::Rename(r) => self.rename(r).map(done),
            Request::Symlink(r) => self.symlink(r).map(Reply::Attr),
            Request::ReadLink(r) => self.read_link(r).map(Reply::Link),
            Request::Fsync(r) => self.fsync(r).map(done),
        };
        outcome.unwrap_or_else(Reply::Error)
    }

    fn places(&self) -> std::sync::MutexGuard<'_, HashMap<NodeId, Place>> {
        self.places
            .lock()
            .expect("nothing panics while holding the places")
    }

    /// The id of the node `meta` describes.
    fn node(&self, meta: &Metadata) -> NodeId {
        let generation = generation(meta);
        match meta.ino() {
            ino if ino == self.root_ino => NodeId::ROOT,
            ino if ino == NodeId::ROOT.ino() => NodeId::new(self.root_ino, generation),
            ino => NodeId::new(ino, generation),
        }
    }

    /// What the protocol says of the node `meta` describes.
    fn attr(&self, meta: &Metadata) -> Result<Attr, Errno> {
        if meta.dev() != self.dev {
            return Err(Errno::CrossDevice);
        }
        let kind = if meta.is_dir() {
            Kind::Dir
        } else if meta.is_file() {
            Kind::File
        } else if meta.is_symlink() {
            Kind::Symlink
        } else {
            return Err(Errno::Unsupported);
        };
        let time = |secs, nanos: i64| Time {
            secs,
            nanos: u32::try_from(nanos).unwrap_or(0),
        };
        Ok(Attr {
            node: self.node(meta),
            kind,
            size: meta.size(),
            mode: meta.mode() & MODE_MASK,
            nlink: u32::try_from(meta.nlink()).unwrap_or(u32::MAX),
            atime: time(meta.atime(), meta.atime_nsec()),
            mtime: time(meta.mtime(), meta.mtime_nsec()),
            ctime: time(meta.ctime(), meta.ctime_nsec()),
        })
    }

    /// Reads what is at `path` without following a symlink there.
    ///
    /// Through the directory holding it, by its name alone: only metadata
    /// read by a single name carries the creation time a generation is
    /// made from, and read any other way the one file would be given two
    /// ids.
    fn stat(&self, path: impl AsRef<Path>) -> io::Result<Metadata> {
        let path = path.as_ref();
        match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
                self.root.open_dir(parent)?.symlink_metadata(name)
            }
            _ => self.root.symlink_metadata(path),
        }
    }

    /// The path, from the root, of where `node` was last found.
    fn remembered(&self, node: NodeId) -> Result<PathBuf, Errno> {
        let places = self.places();
        let names =
            std::iter::successors(Some(node), |at| places.get(at).map(|place| place.parent))
                .take_while(|at| *at != NodeId::ROOT)
                .take(MAX_DEPTH + 1)
                .map(|at| places.get(&at).map(|place| place.name.as_str()))
                .collect::<Option<Vec<_>>>()
                .filter(|names| names.len() <= MAX_DEPTH)
                .ok_or(Errno::Stale)?;
        Ok(if names.is_empty() {
            PathBuf::from(".")
        } else {
            names.into_iter().rev().collect()
        })
    }

    /// Where `node` is and what it is now, having checked that what is
    /// there is still `node`.
    fn find(&self, node: NodeId) -> Result<(PathBuf, Metadata), Errno> {
        let path = self.remembered(node)?;
        let found = self.stat(&path).ok().filter(|meta| self.node(meta) == node);
        match found {
            Some(meta) => Ok((path, meta)),
            None => {
                self.places().remove(&node);
                Err(Errno::Stale)
            }
        }
    }

    /// The path of `name` in the directory `parent`.
    fn child(&self, parent: NodeId, name: &Name) -> Result<PathBuf, Errno> {
        let (dir, meta) = self.find(parent)?;
        if !meta.is_dir() {
            return Err(Errno::NotDir);
        }
        Ok(dir.join(name.as_str()))
    }

    /// Describes the node `meta` was read from at `name` in `parent`, and
    /// remembers it is there.
    fn enter(&self, parent: NodeId, name: Name, meta: &Metadata) -> Result<Attr, Errno> {
        let attr = self.attr(meta)?;
        if attr.node != NodeId::ROOT {
            self.places().insert(attr.node, Place { parent, name });
        }
        Ok(attr)
    }

    /// Opens the file `node` without following a symlink put in its place.
    fn open_file(
        &self,
        node: NodeId,
        options: &mut OpenOptions,
    ) -> Result<cap_std::fs::File, Errno> {
        let (path, meta) = self.find(node)?;
        if meta.is_dir() {
            return Err(Errno::IsDir);
        }
        if !meta.is_file() {
            return Err(Errno::Invalid);
        }
        let file = self
            .root
            .open_with(&path, options.follow(FollowSymlinks::No))
            .map_err(errno)?;
        // The path was checked a moment ago; the file opened is checked
        // too, in case the name changed hands in between. By number alone:
        // an open file's metadata does not carry what a generation is
        // read from.
        match file.metadata() {
            Ok(opened) if opened.ino() == meta.ino() && opened.dev() == meta.dev() => Ok(file),
            Ok(_) => Err(Errno::Stale),
            Err(e) => Err(errno(e)),
        }
    }

    fn lookup(&self, r: Lookup) -> Result<Attr, Errno> {
        let path = self.child(r.parent, &r.name)?;
        let meta = self.stat(&path).map_err(errno)?;
        self.enter(r.parent, r.name, &meta)
    }

    fn get_attr(&self, r: GetAttr) -> Result<Attr, Errno> {
        let (_, meta) = self.find(r.node)?;
        self.attr(&meta)
    }

    fn set_attr(&self, r: SetAttr) -> Result<Attr, Errno> {
        let (path, meta) = self.find(r.node)?;
        // Every change here is made by path and would follow a symlink to
        // whatever it points at.
        if meta.is_symlink() {
            return Err(Errno::Unsupported);
        }
        let atime = r.atime.map(time_spec).transpose()?;
        let mtime = r.mtime.map(time_spec).transpose()?;

        if let Some(size) = r.size {
            self.open_file(r.node, OpenOptions::new().write(true))?
                .set_len(size)
                .map_err(errno)?;
        }
        if let Some(mode) = r.mode {
            self.root
                .set_permissions(&path, Permissions::from_mode(mode & MODE_MASK))
                .map_err(errno)?;
        }
        if atime.is_some() || mtime.is_some() {
            self.root.set_times(&path, atime, mtime).map_err(errno)?;
        }
        self.get_attr(GetAttr { node: r.node })
    }

    fn read_dir(&self, r: ReadDir) -> Result<DirPage, Errno> {
        let (path, meta) = self.find(r.node)?;
        if !meta.is_dir() {
            return Err(Errno::NotDir);
        }
        let limit = r.limit.clamp(1, MAX_DIR_PAGE) as usize;

        // The whole directory is read and sorted for every page: the
        // cursor is a name, so nothing is held between pages and a page
        // costs the directory's size. An entry that cannot be read, or
        // whose name is not one the protocol carries, is left out.
        let mut entries = self
            .root
            .read_dir(&path)
            .map_err(errno)?
            .filter_map(Result::ok)
            .filter_map(|entry| Name::try_new(entry.file_name().into_string().ok()?).ok())
            .filter(|name| r.after.as_ref().is_none_or(|after| name > after))
            .collect::<Vec<_>>();
        entries.sort_unstable();

        let more = entries.len() > limit;
        let entries = entries
            .into_iter()
            .take(limit)
            .filter_map(|name| {
                let meta = self.stat(path.join(name.as_str())).ok()?;
                let attr = self.enter(r.node, name.clone(), &meta).ok()?;
                Some(DirEntry { name, attr })
            })
            .collect();
        Ok(DirPage { entries, more })
    }

    fn read(&self, r: Read) -> Result<ByteBuf, Errno> {
        let file = self.open_file(r.node, OpenOptions::new().read(true))?;
        let mut data = vec![0; r.len.min(MAX_IO_LEN) as usize];
        let mut filled = 0;
        while filled < data.len() {
            let at = r.offset.checked_add(filled as u64).ok_or(Errno::Invalid)?;
            match file.read_at(&mut data[filled..], at) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(errno(e)),
            }
        }
        data.truncate(filled);
        Ok(ByteBuf::from(data))
    }

    fn write(&self, r: Write) -> Result<(), Errno> {
        if r.data.len() > MAX_IO_LEN as usize {
            return Err(Errno::Invalid);
        }
        self.open_file(r.node, OpenOptions::new().write(true))?
            .write_all_at(&r.data, r.offset)
            .map_err(errno)
    }

    fn create(&self, r: Create) -> Result<Attr, Errno> {
        let path = self.child(r.parent, &r.name)?;
        let mut options = OpenOptions::new();
        options
            .write(true)
            .mode(r.mode & MODE_MASK)
            .follow(FollowSymlinks::No);
        if r.exclusive {
            options.create_new(true);
        } else {
            options.create(true);
        }
        self.root.open_with(&path, &options).map_err(errno)?;
        let meta = self.stat(&path).map_err(errno)?;
        self.enter(r.parent, r.name, &meta)
    }

    fn mkdir(&self, r: Mkdir) -> Result<Attr, Errno> {
        let path = self.child(r.parent, &r.name)?;
        let mut builder = DirBuilder::new();
        builder.mode(r.mode & MODE_MASK);
        self.root.create_dir_with(&path, &builder).map_err(errno)?;
        let meta = self.stat(&path).map_err(errno)?;
        self.enter(r.parent, r.name, &meta)
    }

    fn unlink(&self, r: Unlink) -> Result<(), Errno> {
        let path = self.child(r.parent, &r.name)?;
        let meta = self.stat(&path).map_err(errno)?;
        if meta.is_dir() {
            return Err(Errno::IsDir);
        }
        self.root.remove_file(&path).map_err(errno)?;
        // With other links left, the place is merely wrong, and `find`
        // notices that for itself.
        if meta.nlink() <= 1 {
            self.places().remove(&self.node(&meta));
        }
        Ok(())
    }

    fn rmdir(&self, r: Rmdir) -> Result<(), Errno> {
        let path = self.child(r.parent, &r.name)?;
        let meta = self.stat(&path).map_err(errno)?;
        if !meta.is_dir() {
            return Err(Errno::NotDir);
        }
        self.root.remove_dir(&path).map_err(errno)?;
        self.places().remove(&self.node(&meta));
        Ok(())
    }

    fn rename(&self, r: Rename) -> Result<(), Errno> {
        let from = self.child(r.parent, &r.name)?;
        let to = self.child(r.new_parent, &r.new_name)?;
        let meta = self.stat(&from).map_err(errno)?;
        self.root.rename(&from, &self.root, &to).map_err(errno)?;
        // Everything below a moved directory is remembered by its parent,
        // so moving the one place moves them all.
        self.enter(r.new_parent, r.new_name, &meta).map(|_| ())
    }

    fn symlink(&self, r: Symlink) -> Result<Attr, Errno> {
        if r.target.is_empty() || r.target.len() > MAX_TARGET_LEN || r.target.contains('\0') {
            return Err(Errno::Invalid);
        }
        let path = self.child(r.parent, &r.name)?;
        // The target is stored as given, absolute or not: it is the
        // client's to resolve, and nothing here ever follows it.
        self.root
            .symlink_contents(&r.target, &path)
            .map_err(errno)?;
        let meta = self.stat(&path).map_err(errno)?;
        self.enter(r.parent, r.name, &meta)
    }

    fn read_link(&self, r: ReadLink) -> Result<String, Errno> {
        let (path, meta) = self.find(r.node)?;
        if !meta.is_symlink() {
            return Err(Errno::Invalid);
        }
        self.root
            .read_link_contents(&path)
            .map_err(errno)?
            .into_os_string()
            .into_string()
            .map_err(|_| Errno::Unsupported)
    }

    fn fsync(&self, r: Fsync) -> Result<(), Errno> {
        self.open_file(r.node, OpenOptions::new().read(true))?
            .sync_all()
            .map_err(errno)
    }
}

/// Which holder of its inode number the file `meta` describes is: its
/// creation time in nanoseconds, or 0 where there is none to go by.
///
/// Only metadata read by path carries a creation time; an open file's
/// does not. Every id is therefore made from a path's metadata, or the
/// same file would be given two.
///
/// Linux only. There a freed number goes straight to the next file and a
/// creation time never changes. macOS is the other way about on both:
/// APFS does not reuse numbers, and setting a file's modification time
/// before its creation time moves the creation time back with it.
#[cfg(target_os = "linux")]
fn generation(meta: &Metadata) -> u64 {
    meta.created()
        .ok()
        .and_then(|born| born.into_std().duration_since(UNIX_EPOCH).ok())
        .map_or(0, |since| {
            u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
        })
}

#[cfg(not(target_os = "linux"))]
fn generation(_: &Metadata) -> u64 {
    0
}

fn done(_: ()) -> Reply {
    Reply::Done(Done {})
}

/// The time `time` names, as the filesystem is asked to set it.
fn time_spec(time: Time) -> Result<SystemTimeSpec, Errno> {
    if time.nanos >= 1_000_000_000 {
        return Err(Errno::Invalid);
    }
    let since = Duration::new(time.secs.unsigned_abs(), 0);
    let at: Option<SystemTime> = if time.secs >= 0 {
        UNIX_EPOCH.checked_add(since)
    } else {
        UNIX_EPOCH.checked_sub(since)
    };
    at.and_then(|at| at.checked_add(Duration::new(0, time.nanos)))
        .map(|at| SystemTimeSpec::Absolute(cap_std::time::SystemTime::from_std(at)))
        .ok_or(Errno::Invalid)
}

/// What a failure of the backing filesystem is called on the wire.
fn errno(error: io::Error) -> Errno {
    use io::ErrorKind as K;
    match error.kind() {
        K::NotFound => Errno::NotFound,
        K::AlreadyExists => Errno::Exists,
        K::NotADirectory => Errno::NotDir,
        K::IsADirectory => Errno::IsDir,
        K::DirectoryNotEmpty => Errno::NotEmpty,
        K::PermissionDenied | K::ReadOnlyFilesystem => Errno::Access,
        K::InvalidInput | K::InvalidFilename => Errno::Invalid,
        K::StorageFull | K::QuotaExceeded => Errno::NoSpace,
        K::FileTooLarge => Errno::TooLarge,
        K::CrossesDevices => Errno::CrossDevice,
        K::Unsupported => Errno::Unsupported,
        _ => {
            tracing::debug!(%error, "the backing filesystem failed");
            Errno::Io
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    const ROOT: NodeId = NodeId::ROOT;

    /// A volume over a fresh directory, inside a parent that holds a file
    /// no client should ever reach.
    struct Volume {
        outside: TempDir,
        backing: Backing,
    }

    impl Volume {
        fn new() -> Self {
            let outside = TempDir::new().unwrap();
            std::fs::write(outside.path().join("secret"), b"keep out").unwrap();
            std::fs::create_dir(outside.path().join("volume")).unwrap();
            let backing = Backing::open(outside.path().join("volume")).unwrap();
            Self { outside, backing }
        }

        /// The volume's directory, for reaching around the filer.
        fn dir(&self) -> PathBuf {
            self.outside.path().join("volume")
        }

        fn attr(&self, request: Request) -> Result<Attr, Errno> {
            match self.backing.handle(request) {
                Reply::Attr(attr) => Ok(attr),
                Reply::Error(errno) => Err(errno),
                other => panic!("expected attributes, got {other:?}"),
            }
        }

        fn done(&self, request: Request) -> Result<(), Errno> {
            match self.backing.handle(request) {
                Reply::Done(_) => Ok(()),
                Reply::Error(errno) => Err(errno),
                other => panic!("expected done, got {other:?}"),
            }
        }

        fn lookup(&self, parent: NodeId, name: &str) -> Result<Attr, Errno> {
            self.attr(Request::Lookup(Lookup {
                parent,
                name: n(name),
            }))
        }

        fn create(&self, parent: NodeId, name: &str) -> Attr {
            self.attr(Request::Create(Create {
                parent,
                name: n(name),
                mode: 0o644,
                exclusive: true,
            }))
            .unwrap()
        }

        fn mkdir(&self, parent: NodeId, name: &str) -> Attr {
            self.attr(Request::Mkdir(Mkdir {
                parent,
                name: n(name),
                mode: 0o755,
            }))
            .unwrap()
        }

        fn write(&self, node: NodeId, offset: u64, data: &[u8]) -> Result<(), Errno> {
            self.done(Request::Write(Write {
                node,
                offset,
                data: ByteBuf::from(data.to_vec()),
            }))
        }

        fn read(&self, node: NodeId, offset: u64, len: u32) -> Result<Vec<u8>, Errno> {
            match self
                .backing
                .handle(Request::Read(Read { node, offset, len }))
            {
                Reply::Data(data) => Ok(data.into_vec()),
                Reply::Error(errno) => Err(errno),
                other => panic!("expected data, got {other:?}"),
            }
        }

        fn list(&self, node: NodeId, after: Option<&str>, limit: u32) -> DirPage {
            match self.backing.handle(Request::ReadDir(ReadDir {
                node,
                after: after.map(n),
                limit,
            })) {
                Reply::Dir(page) => page,
                other => panic!("expected a listing, got {other:?}"),
            }
        }

        fn rename(&self, parent: NodeId, name: &str, to: NodeId, new: &str) -> Result<(), Errno> {
            self.done(Request::Rename(Rename {
                parent,
                name: n(name),
                new_parent: to,
                new_name: n(new),
            }))
        }

        fn symlink(&self, name: &str, target: &str) -> Attr {
            self.attr(Request::Symlink(Symlink {
                parent: ROOT,
                name: n(name),
                target: target.to_owned(),
            }))
            .unwrap()
        }
    }

    fn n(name: &str) -> Name {
        Name::try_new(name).unwrap()
    }

    fn names(page: &DirPage) -> Vec<&str> {
        page.entries.iter().map(|e| e.name.as_str()).collect()
    }

    #[test]
    fn the_root_is_node_one() {
        let v = Volume::new();
        let attr = v.attr(Request::GetAttr(GetAttr { node: ROOT })).unwrap();
        assert_eq!(attr.node, ROOT);
        assert_eq!(attr.kind, Kind::Dir);
    }

    #[test]
    fn a_file_is_created_written_and_read_back() {
        let v = Volume::new();
        let file = v.create(ROOT, "notes");
        assert_eq!((file.kind, file.size, file.mode), (Kind::File, 0, 0o644));

        v.write(file.node, 0, b"hello world").unwrap();
        v.write(file.node, 6, b"there").unwrap();

        assert_eq!(v.read(file.node, 0, 100).unwrap(), b"hello there");
        assert_eq!(v.read(file.node, 6, 3).unwrap(), b"the");
        assert_eq!(v.read(file.node, 50, 10).unwrap(), b"");
        assert_eq!(v.lookup(ROOT, "notes").unwrap().size, 11);
        assert_eq!(
            std::fs::read(v.dir().join("notes")).unwrap(),
            b"hello there"
        );
    }

    /// However a file is come by, it is the same node — in the root, where
    /// paths are spelled differently, and below it.
    #[test]
    fn a_file_has_one_id_by_every_route() {
        let v = Volume::new();
        let dir = v.mkdir(ROOT, "dir");
        for parent in [ROOT, dir.node] {
            let created = v.create(parent, "notes");
            let listed = v.list(parent, None, 10);
            let listed = listed
                .entries
                .iter()
                .find(|entry| entry.name.as_str() == "notes")
                .unwrap();
            let got = v
                .attr(Request::GetAttr(GetAttr { node: created.node }))
                .unwrap();

            assert_eq!(v.lookup(parent, "notes").unwrap().node, created.node);
            assert_eq!(listed.attr.node, created.node);
            assert_eq!(got.node, created.node);
        }
    }

    #[test]
    fn creating_over_a_name_is_refused_only_when_exclusive() {
        let v = Volume::new();
        let first = v.create(ROOT, "notes");
        let create = |exclusive| {
            v.attr(Request::Create(Create {
                parent: ROOT,
                name: n("notes"),
                mode: 0o600,
                exclusive,
            }))
        };

        assert_eq!(create(true), Err(Errno::Exists));
        assert_eq!(create(false).unwrap().node, first.node);
    }

    #[test]
    fn nodes_are_found_through_nested_directories() {
        let v = Volume::new();
        let a = v.mkdir(ROOT, "a");
        let b = v.mkdir(a.node, "b");
        let file = v.create(b.node, "deep");
        v.write(file.node, 0, b"x").unwrap();

        assert_eq!(std::fs::read(v.dir().join("a/b/deep")).unwrap(), b"x");
        assert_eq!(v.lookup(b.node, "deep").unwrap().node, file.node);
        assert_eq!(v.lookup(ROOT, "missing"), Err(Errno::NotFound));
        assert_eq!(v.lookup(file.node, "x"), Err(Errno::NotDir));
    }

    #[test]
    fn a_listing_pages_in_name_order() {
        let v = Volume::new();
        for name in ["c", "a", "e", "b", "d"] {
            v.create(ROOT, name);
        }

        let first = v.list(ROOT, None, 2);
        assert_eq!((names(&first), first.more), (vec!["a", "b"], true));
        let second = v.list(ROOT, Some("b"), 2);
        assert_eq!((names(&second), second.more), (vec!["c", "d"], true));
        let last = v.list(ROOT, Some("d"), 2);
        assert_eq!((names(&last), last.more), (vec!["e"], false));
    }

    #[test]
    fn a_listing_makes_its_entries_known() {
        let v = Volume::new();
        std::fs::write(v.dir().join("already-there"), b"data").unwrap();

        let page = v.list(ROOT, None, 10);
        let entry = &page.entries[0];
        assert_eq!(entry.attr.size, 4);
        assert_eq!(v.read(entry.attr.node, 0, 10).unwrap(), b"data");
    }

    #[test]
    fn a_rename_keeps_the_node_and_what_is_under_it() {
        let v = Volume::new();
        let dir = v.mkdir(ROOT, "old");
        let file = v.create(dir.node, "inside");
        v.write(file.node, 0, b"kept").unwrap();
        let elsewhere = v.mkdir(ROOT, "elsewhere");

        v.rename(ROOT, "old", elsewhere.node, "new").unwrap();

        assert_eq!(v.lookup(ROOT, "old"), Err(Errno::NotFound));
        assert_eq!(v.lookup(elsewhere.node, "new").unwrap().node, dir.node);
        assert_eq!(v.read(file.node, 0, 10).unwrap(), b"kept");
        assert_eq!(
            std::fs::read(v.dir().join("elsewhere/new/inside")).unwrap(),
            b"kept"
        );
    }

    #[test]
    fn a_removed_node_is_stale() {
        let v = Volume::new();
        let file = v.create(ROOT, "gone");
        let dir = v.mkdir(ROOT, "dir");

        v.done(Request::Unlink(Unlink {
            parent: ROOT,
            name: n("gone"),
        }))
        .unwrap();
        v.done(Request::Rmdir(Rmdir {
            parent: ROOT,
            name: n("dir"),
        }))
        .unwrap();

        assert_eq!(v.read(file.node, 0, 1), Err(Errno::Stale));
        assert_eq!(v.lookup(dir.node, "x"), Err(Errno::Stale));
        assert_eq!(v.lookup(ROOT, "gone"), Err(Errno::NotFound));
    }

    #[test]
    fn removing_refuses_the_wrong_kind_and_a_full_directory() {
        let v = Volume::new();
        let dir = v.mkdir(ROOT, "dir");
        v.create(dir.node, "inside");
        v.create(ROOT, "file");
        let unlink = |name| {
            v.done(Request::Unlink(Unlink {
                parent: ROOT,
                name: n(name),
            }))
        };
        let rmdir = |name| {
            v.done(Request::Rmdir(Rmdir {
                parent: ROOT,
                name: n(name),
            }))
        };

        assert_eq!(unlink("dir"), Err(Errno::IsDir));
        assert_eq!(rmdir("file"), Err(Errno::NotDir));
        assert_eq!(rmdir("dir"), Err(Errno::NotEmpty));
    }

    /// A filer that restarted has forgotten every place; the ids are
    /// still good once the client looks the files up again.
    #[test]
    fn an_id_unknown_after_a_restart_is_stale_until_looked_up_again() {
        let v = Volume::new();
        let file = v.create(ROOT, "notes");
        v.write(file.node, 0, b"still here").unwrap();

        let restarted = Volume {
            backing: Backing::open(v.dir()).unwrap(),
            outside: v.outside,
        };
        assert_eq!(restarted.read(file.node, 0, 10), Err(Errno::Stale));
        assert_eq!(restarted.lookup(ROOT, "notes").unwrap().node, file.node);
        assert_eq!(restarted.read(file.node, 0, 10).unwrap(), b"still here");
    }

    /// A name that changed hands behind the filer's back does not let an
    /// old id reach the new file.
    #[test]
    fn an_id_does_not_follow_its_name_to_another_file() {
        let v = Volume::new();
        let file = v.create(ROOT, "notes");

        // Created while the first still exists, so the two cannot share
        // an inode number.
        std::fs::write(v.dir().join("other"), b"another file").unwrap();
        std::fs::rename(v.dir().join("other"), v.dir().join("notes")).unwrap();

        assert_eq!(v.read(file.node, 0, 100), Err(Errno::Stale));
    }

    /// The same, where the filesystem hands the freed inode number to the
    /// newcomer — as Linux filesystems do, at once.
    #[test]
    fn an_id_does_not_reach_the_next_file_given_its_inode_number() {
        let v = Volume::new();
        let file = v.create(ROOT, "notes");
        if file.node.generation() == 0 {
            // No creation times here, so nothing to tell the two apart by.
            return;
        }

        std::fs::remove_file(v.dir().join("notes")).unwrap();
        // Longer than a tick of any filesystem's clock.
        std::thread::sleep(Duration::from_millis(50));
        std::fs::write(v.dir().join("notes"), b"another file").unwrap();

        assert_eq!(v.read(file.node, 0, 100), Err(Errno::Stale));
        let found = v.lookup(ROOT, "notes").unwrap();
        assert_ne!(found.node, file.node);
        assert_eq!(v.read(found.node, 0, 100).unwrap(), b"another file");
    }

    #[test]
    fn attributes_are_set_one_at_a_time() {
        let v = Volume::new();
        let file = v.create(ROOT, "notes");
        v.write(file.node, 0, b"hello world").unwrap();
        let set = |change: SetAttr| v.attr(Request::SetAttr(change)).unwrap();
        let unchanged = SetAttr {
            node: file.node,
            mode: None,
            size: None,
            atime: None,
            mtime: None,
        };

        assert_eq!(
            set(SetAttr {
                size: Some(5),
                ..unchanged
            })
            .size,
            5
        );
        assert_eq!(v.read(file.node, 0, 100).unwrap(), b"hello");
        assert_eq!(
            set(SetAttr {
                mode: Some(0o600),
                ..unchanged
            })
            .mode,
            0o600
        );
        let at = Time {
            secs: 1_000_000,
            nanos: 5,
        };
        let attr = set(SetAttr {
            mtime: Some(at),
            ..unchanged
        });
        assert_eq!((attr.mtime, attr.size, attr.mode), (at, 5, 0o600));
    }

    #[test]
    fn a_symlink_is_stored_and_read_back_but_never_followed() {
        let v = Volume::new();
        let link = v.symlink("link", "/etc/passwd");
        assert_eq!(link.kind, Kind::Symlink);

        assert_eq!(
            v.backing
                .handle(Request::ReadLink(ReadLink { node: link.node })),
            Reply::Link("/etc/passwd".to_owned())
        );
        assert_eq!(v.read(link.node, 0, 10), Err(Errno::Invalid));
        assert_eq!(v.write(link.node, 0, b"x"), Err(Errno::Invalid));
    }

    /// The escape a read-write client would try: plant a symlink out of
    /// the volume, then reach through it.
    #[test]
    fn a_symlink_out_of_the_volume_leads_nowhere() {
        let v = Volume::new();
        let up = v.symlink("up", "..");
        let abs = v.symlink("abs", v.outside.path().to_str().unwrap());

        for link in [up.node, abs.node] {
            assert_eq!(v.lookup(link, "secret"), Err(Errno::NotDir));
            assert_eq!(
                v.attr(Request::Create(Create {
                    parent: link,
                    name: n("planted"),
                    mode: 0o644,
                    exclusive: false,
                })),
                Err(Errno::NotDir)
            );
        }
        assert!(!v.outside.path().join("planted").exists());
    }

    /// The same escape with the race won: a directory the filer knows is
    /// swapped for a symlink out of the volume behind its back.
    #[test]
    fn a_directory_swapped_for_a_symlink_out_is_not_walked() {
        let v = Volume::new();
        let dir = v.mkdir(ROOT, "dir");
        let inner = v.mkdir(dir.node, "inner");

        std::fs::remove_dir(v.dir().join("dir/inner")).unwrap();
        std::fs::remove_dir(v.dir().join("dir")).unwrap();
        std::os::unix::fs::symlink(v.outside.path(), v.dir().join("dir")).unwrap();

        // Stale where the swap is noticed; where the symlink was handed
        // the directory's inode number within a tick, it is at least not
        // a directory.
        assert!(matches!(
            v.lookup(dir.node, "secret"),
            Err(Errno::Stale | Errno::NotDir)
        ));
        assert_eq!(v.lookup(inner.node, "x"), Err(Errno::Stale));
        assert!(matches!(
            v.read(dir.node, 0, 10),
            Err(Errno::Stale | Errno::Invalid)
        ));
    }

    #[test]
    fn an_oversized_write_is_refused() {
        let v = Volume::new();
        let file = v.create(ROOT, "big");
        let data = vec![0; MAX_IO_LEN as usize + 1];
        assert_eq!(v.write(file.node, 0, &data), Err(Errno::Invalid));
    }
}
