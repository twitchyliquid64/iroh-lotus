//! The protocol a filer client speaks to `filerd`, directly over iroh.
//!
//! A connection is opened under [`ALPN`] and serves one volume. The client
//! opens a bidirectional stream and sends a [`Hello`] naming the volume;
//! the filer answers with a [`Welcome`] saying what the client may do
//! there, or closes the connection with a [`Close`] code. Who the client
//! is never travels in a frame: it is the endpoint id iroh authenticated
//! at the handshake, and the filer looks that up in the ledger.
//!
//! Frames are a four-byte big-endian length followed by that many bytes of
//! canonical CBOR, as on the rest of the cluster's wires.
//!
//! Nothing here depends on iroh or on a running lotus — `wire` is taken
//! for its codec alone — so a client needs neither a ledger nor a control
//! socket to speak it.

use core::fmt;
use std::io;

use cbor2::Cbor;
use nutype::nutype;
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The ALPN a filer connection is opened under.
pub const ALPN: &[u8] = b"lotus-filer/0";

/// The largest frame body either side will read or write.
pub const MAX_FRAME_LEN: u32 = 1 << 20;

/// The longest a [`VolumeName`] may be, in bytes.
pub const MAX_VOLUME_NAME_LEN: usize = 64;

/// The name a volume is served and listed under.
///
/// Lowercase ASCII letters, digits, `-` and `_` only, so it is spelled the
/// same as a ledger key, a path segment and a command-line argument.
#[nutype(
    validate(predicate = |name| {
        !name.is_empty()
            && name.len() <= MAX_VOLUME_NAME_LEN
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
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
        FromStr,
        Serialize,
        Deserialize
    )
)]
pub struct VolumeName(String);

impl VolumeName {
    /// The name as text.
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }
}

/// What a client may do on a volume. Ordered by how much it permits.
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    ReadOnly,
    ReadWrite,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::ReadOnly => "read-only",
            Mode::ReadWrite => "read-write",
        })
    }
}

/// The client's first frame: the volume it wants.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Hello {
    #[cbor(key = 1)]
    pub volume: VolumeName,
}

/// The filer's answer to a [`Hello`] it admits.
#[derive(Debug, Copy, Clone, Cbor, PartialEq, Eq)]
pub struct Welcome {
    /// What the client may do for as long as the connection stands. A
    /// grant that later widens is picked up by reconnecting.
    #[cbor(key = 1)]
    pub mode: Mode,
}

/// Why the filer closed a connection, as the QUIC application close code
/// the client sees.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Close {
    /// The filer is stopping.
    ShuttingDown,
    /// The client broke the protocol.
    Breach,
    /// The filer broke while serving.
    Internal,
    /// The client is not permitted on the volume it named. Also what an
    /// unknown volume gets, so the answer does not say which volumes exist.
    NotPermitted,
    /// The client was permitted when it connected and no longer is, or is
    /// permitted less.
    Revoked,
    /// The filer cannot serve the volume right now: it cannot read the
    /// ledger, or the ledger gives the volume to another filer.
    Unavailable,
}

impl Close {
    const ALL: [Close; 6] = [
        Close::ShuttingDown,
        Close::Breach,
        Close::Internal,
        Close::NotPermitted,
        Close::Revoked,
        Close::Unavailable,
    ];

    /// The application close code.
    pub fn code(self) -> u32 {
        match self {
            Close::ShuttingDown => 1,
            Close::Breach => 2,
            Close::Internal => 3,
            Close::NotPermitted => 4,
            Close::Revoked => 5,
            Close::Unavailable => 6,
        }
    }

    /// The reason a close code stands for, if it is one of ours.
    pub fn from_code(code: u64) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|close| u64::from(close.code()) == code)
    }

    /// The reason phrase sent alongside the code, for logs.
    pub fn reason(self) -> &'static [u8] {
        match self {
            Close::ShuttingDown => b"shutting down",
            Close::Breach => b"protocol breach",
            Close::Internal => b"internal error",
            Close::NotPermitted => b"not permitted",
            Close::Revoked => b"permission revoked",
            Close::Unavailable => b"volume unavailable",
        }
    }
}

/// Why a frame could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("reading or writing the stream")]
    Io(#[source] io::Error),
    /// A frame of this many bytes, more than [`MAX_FRAME_LEN`].
    #[error("a frame of {0} bytes is too large")]
    TooLarge(u64),
    #[error("encoding or decoding a frame")]
    Codec(#[source] wire::Error),
}

/// Reads one frame.
pub async fn read_frame<T, R>(reader: &mut R) -> Result<T, FrameError>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin + ?Sized,
{
    let len = reader.read_u32().await.map_err(FrameError::Io)?;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len.into()));
    }
    let mut body = vec![0; len as usize];
    reader.read_exact(&mut body).await.map_err(FrameError::Io)?;
    wire::decode(&body).map_err(FrameError::Codec)
}

/// Writes one frame and flushes it.
pub async fn write_frame<T, W>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    T: ?Sized + Serialize,
    W: AsyncWrite + Unpin + ?Sized,
{
    let body = wire::encode(value).map_err(FrameError::Codec)?;
    let len = u32::try_from(body.len())
        .ok()
        .filter(|len| *len <= MAX_FRAME_LEN)
        .ok_or(FrameError::TooLarge(body.len() as u64))?;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(FrameError::Io)?;
    writer.write_all(&body).await.map_err(FrameError::Io)?;
    writer.flush().await.map_err(FrameError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_names_are_plain() {
        assert!(VolumeName::try_new("scratch-2_b").is_ok());
        assert!(VolumeName::try_new("").is_err());
        assert!(VolumeName::try_new("Scratch").is_err());
        assert!(VolumeName::try_new("a.b").is_err());
        assert!(VolumeName::try_new("a/b").is_err());
        assert!(VolumeName::try_new("a".repeat(MAX_VOLUME_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn read_only_is_the_lesser_mode() {
        assert_eq!(Mode::ReadOnly.min(Mode::ReadWrite), Mode::ReadOnly);
    }

    #[test]
    fn close_codes_roundtrip() {
        for close in Close::ALL {
            assert_eq!(Close::from_code(close.code().into()), Some(close));
        }
        assert_eq!(Close::from_code(0), None);
    }

    #[tokio::test]
    async fn frames_roundtrip() {
        let hello = Hello {
            volume: VolumeName::try_new("scratch").unwrap(),
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &hello).await.unwrap();
        write_frame(
            &mut buf,
            &Welcome {
                mode: Mode::ReadOnly,
            },
        )
        .await
        .unwrap();

        let mut reader = buf.as_slice();
        assert_eq!(read_frame::<Hello, _>(&mut reader).await.unwrap(), hello);
        assert_eq!(
            read_frame::<Welcome, _>(&mut reader).await.unwrap(),
            Welcome {
                mode: Mode::ReadOnly
            }
        );
    }

    #[tokio::test]
    async fn a_hello_naming_a_bad_volume_does_not_decode() {
        #[derive(Cbor)]
        struct Raw {
            #[cbor(key = 1)]
            volume: String,
        }
        let mut buf = Vec::new();
        write_frame(
            &mut buf,
            &Raw {
                volume: "../etc".to_owned(),
            },
        )
        .await
        .unwrap();

        assert!(matches!(
            read_frame::<Hello, _>(&mut buf.as_slice()).await,
            Err(FrameError::Codec(_))
        ));
    }

    #[tokio::test]
    async fn an_oversized_frame_is_refused_before_it_is_read() {
        let buf = (MAX_FRAME_LEN + 1).to_be_bytes();
        assert!(matches!(
            read_frame::<Hello, _>(&mut buf.as_slice()).await,
            Err(FrameError::TooLarge(_))
        ));
    }
}
