//! Length-prefixed canonical CBOR framing.
//!
//! A frame is a four-byte big-endian length followed by that many bytes of
//! canonical CBOR. The prefix bounds what a peer can make us allocate: a
//! frame claiming more than [`MAX_FRAME_LEN`] is a protocol error, not a
//! large read.

use core::{
    pin::Pin,
    task::{Context, Poll, ready},
};
use std::io;

use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::Error;

/// The largest frame body either side will read or write.
pub const MAX_FRAME_LEN: u32 = 1 << 20;

/// Reads frames off a stream one poll at a time, keeping what has arrived
/// of the frame in progress between polls — so a `Stream` of frames needs
/// no boxed future.
#[derive(Debug)]
pub(crate) struct Reader {
    progress: Progress,
}

#[derive(Debug)]
enum Progress {
    /// Reading the length prefix, `filled` bytes of it so far.
    Prefix { buf: [u8; 4], filled: usize },
    /// Reading a body of `buf.len()` bytes, `filled` so far.
    Body { buf: Vec<u8>, filled: usize },
    /// The peer closed, or the stream broke: nothing more comes.
    Done,
}

impl Reader {
    pub(crate) fn new() -> Self {
        Self {
            progress: Progress::Prefix {
                buf: [0; 4],
                filled: 0,
            },
        }
    }

    /// Polls for the next frame, or `None` where the peer closed between
    /// frames. Once it has returned `None` or an error it returns `None`
    /// for good.
    pub(crate) fn poll_read<T, R>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
    ) -> Poll<Result<Option<T>, Error>>
    where
        T: DeserializeOwned,
        R: AsyncRead + ?Sized,
    {
        loop {
            let (dst, mid_frame) = match &mut self.progress {
                Progress::Done => return Poll::Ready(Ok(None)),
                Progress::Prefix { buf, filled } if *filled == buf.len() => {
                    let len = u32::from_be_bytes(*buf);
                    if len > MAX_FRAME_LEN {
                        self.progress = Progress::Done;
                        return Poll::Ready(Err(Error::FrameTooLarge(len.into())));
                    }
                    self.progress = Progress::Body {
                        buf: vec![0; len as usize],
                        filled: 0,
                    };
                    continue;
                }
                Progress::Body { buf, filled } if *filled == buf.len() => {
                    let body = core::mem::take(buf);
                    self.progress = Progress::Prefix {
                        buf: [0; 4],
                        filled: 0,
                    };
                    return Poll::Ready(wire::decode(&body).map(Some).map_err(Error::Codec));
                }
                Progress::Prefix { buf, filled } => (&mut buf[*filled..], *filled > 0),
                Progress::Body { buf, filled } => (&mut buf[*filled..], true),
            };

            let read = ready!(fill(cx, reader.as_mut(), dst));
            let ended = match read {
                Ok(0) if !mid_frame => Ok(None),
                Ok(0) => Err(Error::Truncated),
                Err(e) => Err(Error::IO(e)),
                Ok(n) => {
                    match &mut self.progress {
                        Progress::Prefix { filled, .. } | Progress::Body { filled, .. } => {
                            *filled += n;
                        }
                        Progress::Done => unreachable!("the stream ends only by returning"),
                    }
                    continue;
                }
            };
            self.progress = Progress::Done;
            return Poll::Ready(ended);
        }
    }
}

/// One read into `dst`: how many bytes landed, zero at end of stream.
fn fill<R>(cx: &mut Context<'_>, reader: Pin<&mut R>, dst: &mut [u8]) -> Poll<io::Result<usize>>
where
    R: AsyncRead + ?Sized,
{
    let mut buf = ReadBuf::new(dst);
    ready!(reader.poll_read(cx, &mut buf))?;
    Poll::Ready(Ok(buf.filled().len()))
}

/// Reads one frame, or `None` where the peer closed between frames.
pub(crate) async fn read<T, R>(reader: &mut R) -> Result<Option<T>, Error>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin + ?Sized,
{
    let mut frames = Reader::new();
    core::future::poll_fn(|cx| frames.poll_read(cx, Pin::new(&mut *reader))).await
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
