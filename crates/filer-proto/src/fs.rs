//! The filesystem operations of a connection, once it is welcomed.
//!
//! Each operation is one bidirectional stream: the client opens it, sends
//! one [`Request`] frame, and reads one [`Reply`] frame back. Streams are
//! independent, so operations run concurrently and none waits on another.
//!
//! The filer keeps nothing per connection. A file is named by its
//! [`NodeId`] in every operation that touches it — there is no open and no
//! handle — so a client that reconnects carries on with the ids it has.
//! An id the filer no longer knows answers [`Errno::Stale`]: the client
//! looks the file up again from a directory it still holds, the root at
//! the last.
//!
//! Ownership does not travel. The filer serves every client as one local
//! user, and a client shows what it mounts as owned by whoever mounted it.

use cbor2::Cbor;
use nutype::nutype;
/// File contents on the wire: one byte string.
pub use serde_bytes::ByteBuf;

/// The most bytes one [`Read`] returns or one [`Write`] carries.
pub const MAX_IO_LEN: u32 = 512 * 1024;

/// The most entries one [`DirPage`] holds.
pub const MAX_DIR_PAGE: u32 = 1024;

/// The longest a [`Name`] may be, in bytes.
pub const MAX_NAME_LEN: usize = 255;

/// The longest a symlink's target may be, in bytes.
pub const MAX_TARGET_LEN: usize = 4096;

/// A file, directory or symlink on a volume.
///
/// Stable for as long as the file exists, across connections and filer
/// restarts. Opaque otherwise: a client compares ids and hands them back.
///
/// Two parts, as a FUSE inode has. The number is reused once a file is
/// gone; the generation tells the file that then gets it apart from the
/// one that had it, so an id held past its file's removal goes
/// [`Errno::Stale`] instead of reaching the newcomer.
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId {
    #[cbor(key = 1)]
    ino: u64,
    #[cbor(key = 2)]
    generation: u64,
}

impl NodeId {
    /// The volume's root directory.
    pub const ROOT: NodeId = NodeId::new(1, 0);

    /// The id with the number `ino` and the generation `generation`.
    pub const fn new(ino: u64, generation: u64) -> Self {
        Self { ino, generation }
    }

    /// The id's number: unique among the files a volume holds at one time.
    pub const fn ino(self) -> u64 {
        self.ino
    }

    /// Which holder of the number this is; 0 where the filer cannot tell.
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// One entry's name in a directory: not empty, no `/` or NUL, and neither
/// `.` nor `..` — so a name is never a path.
///
/// UTF-8 only. A file whose name is not is not served.
#[nutype(
    validate(predicate = |name| {
        !name.is_empty()
            && name.len() <= MAX_NAME_LEN
            && name != "."
            && name != ".."
            && !name.bytes().any(|b| b == b'/' || b == 0)
    }),
    derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        AsRef,
        Display,
        Serialize,
        Deserialize
    )
)]
pub struct Name(String);

impl Name {
    /// The name as text.
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }
}

/// What a node is. Anything else a directory may hold — devices, sockets,
/// fifos — is not served.
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    File,
    Dir,
    Symlink,
}

/// A point in time, as seconds and nanoseconds since the Unix epoch.
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq, PartialOrd, Ord)]
pub struct Time {
    #[cbor(key = 1)]
    pub secs: i64,
    #[cbor(key = 2)]
    pub nanos: u32,
}

/// What the filer knows of a node.
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq)]
pub struct Attr {
    #[cbor(key = 1)]
    pub node: NodeId,
    #[cbor(key = 2)]
    pub kind: Kind,
    /// Length in bytes; of the target, for a symlink.
    #[cbor(key = 3)]
    pub size: u64,
    /// The permission bits alone, `0o7777` at most.
    #[cbor(key = 4)]
    pub mode: u32,
    #[cbor(key = 5)]
    pub nlink: u32,
    #[cbor(key = 6)]
    pub atime: Time,
    #[cbor(key = 7)]
    pub mtime: Time,
    #[cbor(key = 8)]
    pub ctime: Time,
}

/// Finds `name` in the directory `parent`. Answered with [`Reply::Attr`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Lookup {
    #[cbor(key = 1)]
    pub parent: NodeId,
    #[cbor(key = 2)]
    pub name: Name,
}

/// Describes `node`. Answered with [`Reply::Attr`].
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq)]
pub struct GetAttr {
    #[cbor(key = 1)]
    pub node: NodeId,
}

/// Changes what is set of `node`'s attributes, leaving the rest. Answered
/// with [`Reply::Attr`], the node as it then stands.
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq)]
pub struct SetAttr {
    #[cbor(key = 1)]
    pub node: NodeId,
    /// The permission bits.
    #[cbor(key = 2)]
    pub mode: Option<u32>,
    /// The length to truncate or extend a file to.
    #[cbor(key = 3)]
    pub size: Option<u64>,
    #[cbor(key = 4)]
    pub atime: Option<Time>,
    #[cbor(key = 5)]
    pub mtime: Option<Time>,
}

/// Lists the directory `node`, in name order. Answered with [`Reply::Dir`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct ReadDir {
    #[cbor(key = 1)]
    pub node: NodeId,
    /// The last name of the page before, to carry on after it; `None` to
    /// start. A cursor by name, so a listing survives the directory
    /// changing under it.
    #[cbor(key = 2)]
    pub after: Option<Name>,
    /// The most entries wanted; [`MAX_DIR_PAGE`] caps it.
    #[cbor(key = 3)]
    pub limit: u32,
}

/// Reads up to `len` bytes of the file `node` from `offset`. Answered with
/// [`Reply::Data`], shorter than asked only at the end of the file.
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq)]
pub struct Read {
    #[cbor(key = 1)]
    pub node: NodeId,
    #[cbor(key = 2)]
    pub offset: u64,
    /// [`MAX_IO_LEN`] caps it.
    #[cbor(key = 3)]
    pub len: u32,
}

/// Writes `data` into the file `node` at `offset`, all of it or none.
/// Answered with [`Reply::Done`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Write {
    #[cbor(key = 1)]
    pub node: NodeId,
    #[cbor(key = 2)]
    pub offset: u64,
    /// [`MAX_IO_LEN`] bytes at most.
    #[cbor(key = 3)]
    pub data: ByteBuf,
}

/// Creates the file `name` in `parent`, or finds the one already there.
/// Answered with [`Reply::Attr`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Create {
    #[cbor(key = 1)]
    pub parent: NodeId,
    #[cbor(key = 2)]
    pub name: Name,
    #[cbor(key = 3)]
    pub mode: u32,
    /// Refuse with [`Errno::Exists`] when the name is taken.
    #[cbor(key = 4)]
    pub exclusive: bool,
}

/// Creates the directory `name` in `parent`. Answered with [`Reply::Attr`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Mkdir {
    #[cbor(key = 1)]
    pub parent: NodeId,
    #[cbor(key = 2)]
    pub name: Name,
    #[cbor(key = 3)]
    pub mode: u32,
}

/// Removes the file or symlink `name` from `parent`. Answered with
/// [`Reply::Done`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Unlink {
    #[cbor(key = 1)]
    pub parent: NodeId,
    #[cbor(key = 2)]
    pub name: Name,
}

/// Removes the empty directory `name` from `parent`. Answered with
/// [`Reply::Done`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Rmdir {
    #[cbor(key = 1)]
    pub parent: NodeId,
    #[cbor(key = 2)]
    pub name: Name,
}

/// Moves `name` in `parent` to `new_name` in `new_parent`, replacing what
/// is there. The node keeps its id. Answered with [`Reply::Done`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Rename {
    #[cbor(key = 1)]
    pub parent: NodeId,
    #[cbor(key = 2)]
    pub name: Name,
    #[cbor(key = 3)]
    pub new_parent: NodeId,
    #[cbor(key = 4)]
    pub new_name: Name,
}

/// Creates the symlink `name` in `parent`, pointing at `target`. The
/// filer stores the target and never follows it. Answered with
/// [`Reply::Attr`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Symlink {
    #[cbor(key = 1)]
    pub parent: NodeId,
    #[cbor(key = 2)]
    pub name: Name,
    /// [`MAX_TARGET_LEN`] bytes at most.
    #[cbor(key = 3)]
    pub target: String,
}

/// Reads where the symlink `node` points. Answered with [`Reply::Link`].
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq)]
pub struct ReadLink {
    #[cbor(key = 1)]
    pub node: NodeId,
}

/// Has the file `node`'s contents reach stable storage. Answered with
/// [`Reply::Done`].
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq)]
pub struct Fsync {
    #[cbor(key = 1)]
    pub node: NodeId,
}

/// One operation on a volume.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    Lookup(Lookup),
    GetAttr(GetAttr),
    SetAttr(SetAttr),
    ReadDir(ReadDir),
    Read(Read),
    Write(Write),
    Create(Create),
    Mkdir(Mkdir),
    Unlink(Unlink),
    Rmdir(Rmdir),
    Rename(Rename),
    Symlink(Symlink),
    ReadLink(ReadLink),
    Fsync(Fsync),
}

impl Request {
    /// Whether the operation changes the volume, and so needs
    /// [`Mode::ReadWrite`](crate::Mode::ReadWrite).
    pub fn mutates(&self) -> bool {
        match self {
            Request::Lookup(_)
            | Request::GetAttr(_)
            | Request::ReadDir(_)
            | Request::Read(_)
            | Request::ReadLink(_) => false,
            Request::SetAttr(_)
            | Request::Write(_)
            | Request::Create(_)
            | Request::Mkdir(_)
            | Request::Unlink(_)
            | Request::Rmdir(_)
            | Request::Rename(_)
            | Request::Symlink(_)
            | Request::Fsync(_) => true,
        }
    }
}

/// One entry of a directory listing.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct DirEntry {
    #[cbor(key = 1)]
    pub name: Name,
    #[cbor(key = 2)]
    pub attr: Attr,
}

/// One page of a directory listing.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct DirPage {
    #[cbor(key = 1)]
    pub entries: Vec<DirEntry>,
    /// Whether names follow the last one here.
    #[cbor(key = 2)]
    pub more: bool,
}

/// The answer to a [`Request`].
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Reply {
    Attr(Attr),
    Dir(DirPage),
    Data(ByteBuf),
    Link(String),
    Done(Done),
    Error(Errno),
}

/// The operation was carried out and has nothing to say.
#[derive(Debug, Copy, Clone, Default, Cbor, PartialEq, Eq)]
pub struct Done {}

/// Why an operation was refused or failed.
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Errno {
    /// Nothing is there under that name.
    NotFound,
    /// The name is taken.
    Exists,
    /// A directory was needed.
    NotDir,
    /// A directory will not do.
    IsDir,
    /// The directory still holds entries.
    NotEmpty,
    /// The filer does not know the node id, or what it named is gone. Look
    /// it up again.
    Stale,
    /// The client is permitted to read only.
    ReadOnly,
    /// The filer's own user may not do this to the file.
    Access,
    /// The request makes no sense for what it names.
    Invalid,
    /// The volume is full.
    NoSpace,
    /// The file would be larger than the volume allows.
    TooLarge,
    /// The operation would reach another filesystem mounted inside the
    /// volume, which is not served.
    CrossDevice,
    /// The filer does not do this, or not to this kind of node.
    Unsupported,
    /// The filer's storage failed.
    Io,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{read_frame, write_frame};

    #[test]
    fn a_name_is_never_a_path() {
        assert!(Name::try_new("notes.txt").is_ok());
        assert!(Name::try_new("..hidden").is_ok());
        assert!(Name::try_new("").is_err());
        assert!(Name::try_new(".").is_err());
        assert!(Name::try_new("..").is_err());
        assert!(Name::try_new("a/b").is_err());
        assert!(Name::try_new("a\0b").is_err());
        assert!(Name::try_new("a".repeat(MAX_NAME_LEN + 1)).is_err());
    }

    #[tokio::test]
    async fn requests_and_replies_roundtrip() {
        let request = Request::Write(Write {
            node: NodeId::new(7, 1),
            offset: 3,
            data: ByteBuf::from(vec![0, 1, 2, 255]),
        });
        let reply = Reply::Dir(DirPage {
            entries: vec![DirEntry {
                name: Name::try_new("a").unwrap(),
                attr: Attr {
                    node: NodeId::new(9, 2),
                    kind: Kind::Symlink,
                    size: 4,
                    mode: 0o777,
                    nlink: 1,
                    atime: Time { secs: 1, nanos: 2 },
                    mtime: Time { secs: -3, nanos: 4 },
                    ctime: Time { secs: 5, nanos: 6 },
                },
            }],
            more: true,
        });

        let mut buf = Vec::new();
        write_frame(&mut buf, &request).await.unwrap();
        write_frame(&mut buf, &reply).await.unwrap();
        write_frame(&mut buf, &Reply::Done(Done {})).await.unwrap();
        write_frame(&mut buf, &Reply::Error(Errno::Stale))
            .await
            .unwrap();

        let mut reader = buf.as_slice();
        assert_eq!(
            read_frame::<Request, _>(&mut reader).await.unwrap(),
            request
        );
        assert_eq!(read_frame::<Reply, _>(&mut reader).await.unwrap(), reply);
        assert_eq!(
            read_frame::<Reply, _>(&mut reader).await.unwrap(),
            Reply::Done(Done {})
        );
        assert_eq!(
            read_frame::<Reply, _>(&mut reader).await.unwrap(),
            Reply::Error(Errno::Stale)
        );
    }

    /// File contents travel as one byte string, not an array of integers.
    #[test]
    fn data_is_a_byte_string() {
        let data = vec![200u8; 1000];
        let encoded = wire::encode(&Reply::Data(ByteBuf::from(data))).unwrap();
        assert!(encoded.len() < 1020, "{} bytes", encoded.len());
    }

    #[tokio::test]
    async fn a_request_naming_a_path_does_not_decode() {
        #[derive(Cbor)]
        struct RawLookup {
            #[cbor(key = 1)]
            parent: u64,
            #[cbor(key = 2)]
            name: String,
        }
        #[derive(Cbor)]
        #[serde(rename_all = "snake_case")]
        enum RawRequest {
            Lookup(RawLookup),
        }
        let mut buf = Vec::new();
        write_frame(
            &mut buf,
            &RawRequest::Lookup(RawLookup {
                parent: 1,
                name: "../etc".to_owned(),
            }),
        )
        .await
        .unwrap();

        assert!(read_frame::<Request, _>(&mut buf.as_slice()).await.is_err());
    }
}
