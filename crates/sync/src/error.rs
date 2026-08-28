use crate::frame::MAX_FRAME_LEN;

/// What moving frames on and off the wire can fail with.
///
/// Session machines never produce this: a peer that misbehaves at the
/// protocol level surfaces as an [`Effect::Violation`](crate::Effect)
/// instead.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A message failed to encode or decode.
    #[error("message codec")]
    Wire(#[from] wire::Error),
    /// A frame longer than [`MAX_FRAME_LEN`]; holds the claimed length.
    #[error("a frame of {0} bytes exceeds the {MAX_FRAME_LEN}-byte cap")]
    FrameTooLarge(u64),
    /// The underlying stream failed.
    #[error("stream")]
    Io(#[from] std::io::Error),
}
