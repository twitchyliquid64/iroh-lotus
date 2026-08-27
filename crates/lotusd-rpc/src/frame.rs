//! Length-prefixed canonical CBOR framing.
//!
//! A frame is a four-byte big-endian length followed by that many bytes of
//! canonical CBOR. The prefix bounds what a peer can make us allocate: a
//! frame claiming more than [`MAX_FRAME_LEN`] is a protocol error, not a
//! large read.

use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Error;

/// The largest frame body either side will read or write.
pub const MAX_FRAME_LEN: u32 = 1 << 20;

/// Reads one frame, or `None` where the peer closed between frames.
pub(crate) async fn read<T, R>(reader: &mut R) -> Result<Option<T>, Error>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin + ?Sized,
{
    // Filled by hand rather than with `read_exact`, which cannot tell a peer
    // that closed cleanly from one that closed mid-prefix.
    let mut prefix = [0u8; 4];
    let mut filled = 0;
    while filled < prefix.len() {
        match reader
            .read(&mut prefix[filled..])
            .await
            .map_err(Error::IO)?
        {
            0 if filled == 0 => return Ok(None),
            0 => return Err(Error::Truncated),
            n => filled += n,
        }
    }

    let len = u32::from_be_bytes(prefix);
    if len > MAX_FRAME_LEN {
        return Err(Error::FrameTooLarge(len.into()));
    }

    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::Truncated
        } else {
            Error::IO(e)
        }
    })?;

    wire::decode(&body).map(Some).map_err(Error::Codec)
}

/// Writes one frame and flushes it, so a response is on the wire before the
/// handler goes back to waiting.
pub(crate) async fn write<T, W>(writer: &mut W, value: &T) -> Result<(), Error>
where
    T: ?Sized + Serialize,
    W: AsyncWrite + Unpin + ?Sized,
{
    let body = wire::encode(value).map_err(Error::Codec)?;
    let len = u32::try_from(body.len())
        .ok()
        .filter(|len| *len <= MAX_FRAME_LEN)
        .ok_or(Error::FrameTooLarge(body.len() as u64))?;

    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(Error::IO)?;
    writer.write_all(&body).await.map_err(Error::IO)?;
    writer.flush().await.map_err(Error::IO)
}
