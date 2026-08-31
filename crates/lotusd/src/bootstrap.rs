//! Joining a cluster from nothing: the protocol a blank node speaks to
//! the node that invited it, and both ends of it.
//!
//! One connection under [`ALPN`], opened by the joiner. Its first
//! bi-stream is the control stream, and on it:
//!
//! 1. The joiner sends [`Join`]: the invite's token and its own public
//!    key. The sponsor redeems the token — once, and only before it
//!    expires — and answers [`Welcome`] with the root envelope, or
//!    [`Refused`].
//! 2. The joiner checks the root is the one the invite pinned, opens its
//!    chain on it, and pulls the rest over a second bi-stream: an ordinary
//!    [`sync`] session, the sponsor serving.
//! 3. Only then does the sponsor admit the joiner — trusting its key and
//!    listing its endpoint, signed by the sponsor alone — and send
//!    [`Admitted`] naming the envelope that did. A joiner that fails
//!    part-way leaves nothing in the ledger.
//! 4. The joiner pulls once more, over a third bi-stream, and checks the
//!    admission is on the chain it now stands on.
//!
//! The token is a bearer secret and nothing more elaborate: iroh already
//! encrypts the connection and authenticates the sponsor's endpoint, so
//! the joiner cannot be talking to anyone but the node the invite named.
//! The token's whole job is telling the sponsor which invite this is.
//!
//! The joiner side runs against a bare [`Core`] — there is no server yet
//! — through the same [`sync_driver`] the daemon uses.

use std::{
    io,
    time::{Duration, Instant},
};

use cbor2::Cbor;
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::{ConnectError, Connection, ConnectionError, SendStream},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};
use wire::{Envelope, EnvelopeDigest, Key, KeyId, PublicKey, msg::FullCheckpoint};

use crate::{
    AdmitError, CannotSignAlone, ChainError, Core, InitError, NodeKeys, ServerHandle,
    invite::{self, Invite, Token},
    peer_ingress::CloseReason,
    sync_driver::{self, SyncError},
};

/// The ALPN a joiner opens its bootstrap connection under.
pub const ALPN: &[u8] = b"iroh-lotus/bootstrap/1";

/// The protocol version spoken by this build. Exact match required.
///
/// 2 taught [`Welcome`] to carry the checkpoint a compacted root stands
/// for.
pub const PROTOCOL_VERSION: u32 = 2;

/// How long either side waits on the other for one step of the control
/// stream before giving up on the join.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// The joiner's opening frame.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Join {
    /// Must equal [`PROTOCOL_VERSION`] exactly.
    #[cbor(key = 1)]
    pub version: u32,
    #[cbor(key = 2)]
    pub token: Token,
    /// The key the joiner will sign with, for the sponsor to trust.
    #[cbor(key = 3)]
    pub key: PublicKey,
}

/// The sponsor's answer to a good [`Join`]: the envelope to root on.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Welcome {
    #[cbor(key = 1)]
    pub root: Envelope,
    /// The checkpoint of the state standing at `root`, when compaction
    /// has moved the sponsor's root past the `Init` — an `Init` carries
    /// its own state and sends none.
    ///
    /// The invite pins `root`'s digest, which attests the envelope alone:
    /// the checkpoint rides on the sponsor's vouch, like the root itself.
    #[cbor(key = 2)]
    pub state: Option<FullCheckpoint>,
}

/// The sponsor's answer when the join cannot go on. Ends the session.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Refused {
    /// For the operator at the joiner's terminal, never for code.
    #[cbor(key = 1)]
    pub reason: String,
}

/// The sponsor saying the joiner is now in the ledger, and which envelope
/// put it there.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
pub struct Admitted {
    #[cbor(key = 1)]
    pub digest: EnvelopeDigest,
}

/// A frame on the control stream.
#[derive(Debug, Clone, Cbor, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Message {
    Join(Join),
    // Boxed for size alone: a Welcome carries an envelope and possibly a
    // checkpoint, dwarfing its siblings. Box is transparent on the wire.
    Welcome(Box<Welcome>),
    Refused(Refused),
    Admitted(Admitted),
}

impl Message {
    fn kind(&self) -> &'static str {
        match self {
            Message::Join(_) => "Join",
            Message::Welcome(_) => "Welcome",
            Message::Refused(_) => "Refused",
            Message::Admitted(_) => "Admitted",
        }
    }
}

/// Why a control-stream frame could not be moved.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("stream")]
    Io(#[source] io::Error),
    #[error("a frame of {len} bytes exceeds the {}-byte cap", sync::MAX_FRAME_LEN)]
    TooLarge { len: u64 },
    #[error("message codec")]
    Wire(#[source] wire::Error),
    #[error("the stream ended between frames")]
    Closed,
}

impl From<io::Error> for FrameError {
    fn from(err: io::Error) -> Self {
        FrameError::Io(err)
    }
}

impl From<wire::Error> for FrameError {
    fn from(err: wire::Error) -> Self {
        FrameError::Wire(err)
    }
}

/// Writes one length-prefixed frame, the same shape as the sync wire's.
async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &Message,
) -> Result<(), FrameError> {
    let body = wire::encode(message)?;
    let len = u32::try_from(body.len())
        .ok()
        .filter(|&len| len <= sync::MAX_FRAME_LEN)
        .ok_or(FrameError::TooLarge {
            len: body.len() as u64,
        })?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads one frame, or [`FrameError::Closed`] where the peer finished the
/// stream cleanly between frames.
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Message, FrameError> {
    let mut prefix = [0u8; 4];
    match reader.read_exact(&mut prefix).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(FrameError::Closed),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(prefix);
    if len > sync::MAX_FRAME_LEN {
        return Err(FrameError::TooLarge { len: len.into() });
    }
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body).await?;
    Ok(wire::decode(&body)?)
}

/// Waits at most [`STEP_TIMEOUT`] for one step of the control stream.
async fn step<T, E>(what: impl Future<Output = Result<T, E>>) -> Result<T, StepError<E>>
where
    E: core::error::Error + 'static,
{
    timeout(STEP_TIMEOUT, what)
        .await
        .map_err(|_| StepError::TimedOut)?
        .map_err(StepError::Failed)
}

/// One step of the control stream not completing.
#[derive(Debug, thiserror::Error)]
pub enum StepError<E: core::error::Error + 'static> {
    #[error(transparent)]
    Failed(E),
    #[error("the peer did not answer within {STEP_TIMEOUT:?}")]
    TimedOut,
}

// ---------------------------------------------------------------------
// The sponsor's book of invites.

/// The invites a running node has handed out and not yet seen redeemed.
/// In memory only: a restart forgets them, which is the point of a
/// short-lived secret.
#[derive(Debug, Default)]
pub(crate) struct Invites {
    pending: Vec<Pending>,
}

#[derive(Debug)]
struct Pending {
    token: Token,
    weight: u32,
    expires: Instant,
    /// The root the invite promised the joiner — compaction must not
    /// prune it while the invite can still be redeemed.
    root: EnvelopeDigest,
}

/// What redeeming a token entitles the joiner to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Redeemed {
    /// The weight the sponsor will trust the joiner's key at.
    pub(crate) weight: u32,
}

impl Invites {
    /// Records a fresh invite, good for `ttl` from `now`, admitting one
    /// node at `weight` onto the chain rooted at `root`.
    pub(crate) fn issue(
        &mut self,
        token: Token,
        weight: u32,
        ttl: Duration,
        now: Instant,
        root: EnvelopeDigest,
    ) {
        self.prune(now);
        self.pending.push(Pending {
            token,
            weight,
            expires: now.checked_add(ttl).unwrap_or(now),
            root,
        });
    }

    /// Consumes the invite `token` names. Every pending token is compared
    /// in constant time, so a miss costs the same whichever it missed.
    pub(crate) fn redeem(&mut self, token: &Token, now: Instant) -> Result<Redeemed, RedeemError> {
        let found = self
            .pending
            .iter()
            .enumerate()
            .fold(None, |found, (i, pending)| {
                if pending.token.matches(token) {
                    Some(i)
                } else {
                    found
                }
            });
        let outcome = match found {
            None => Err(RedeemError::Unknown),
            Some(i) => {
                let pending = self.pending.remove(i);
                if pending.expires <= now {
                    Err(RedeemError::Expired)
                } else {
                    Ok(Redeemed {
                        weight: pending.weight,
                    })
                }
            }
        };
        self.prune(now);
        outcome
    }

    fn prune(&mut self, now: Instant) {
        self.pending.retain(|pending| pending.expires > now);
    }

    /// The roots outstanding invites promise a joiner, for compaction to
    /// keep: a redeemed [`Welcome`] must still hold what the invite
    /// pinned.
    pub(crate) fn pinned_roots(&self, now: Instant) -> std::collections::BTreeSet<EnvelopeDigest> {
        self.pending
            .iter()
            .filter(|pending| pending.expires > now)
            .map(|pending| pending.root)
            .collect()
    }

    /// How many invites are outstanding.
    #[cfg(test)]
    fn pending(&self) -> usize {
        self.pending.len()
    }
}

/// Why a token could not be redeemed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RedeemError {
    /// No such invite: never issued, already used, or long expired.
    #[error("the invite is not one this node issued, or was used already")]
    Unknown,
    #[error("the invite has expired")]
    Expired,
}

/// Why a node could not issue or honour an invite.
#[derive(Debug, thiserror::Error)]
pub enum InviteError {
    #[error("this node serves no peers, so nothing could dial it")]
    NoEndpoint,
    /// An admission is one node's signature, and this node's would not
    /// apply on its own.
    #[error("this node cannot admit a peer alone")]
    CannotSignAlone(#[source] CannotSignAlone),
    #[error(transparent)]
    Redeem(RedeemError),
    #[error("reading the ledger")]
    Chain(#[source] ChainError),
    #[error("the OS could not supply entropy for a token")]
    Entropy(#[source] rand::rngs::SysError),
    #[error("the server is shutting down")]
    ServerGone,
}

// ---------------------------------------------------------------------
// The sponsor's side of a join.

/// Why serving a join ended without admitting anyone.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("accepting the control stream")]
    Accept(#[source] StepError<ConnectionError>),
    #[error("on the control stream")]
    Frame(#[source] StepError<FrameError>),
    #[error("expected {expected}, got {got}")]
    Unexpected {
        expected: &'static str,
        got: &'static str,
    },
    #[error("joiner speaks protocol version {theirs}, this node speaks {PROTOCOL_VERSION}")]
    Version { theirs: u32 },
    #[error("the invite could not be redeemed")]
    Invite(#[source] InviteError),
    #[error("serving the joiner's pull")]
    Sync(#[source] SyncError),
    #[error("admitting the joiner")]
    Admit(#[source] AdmitError),
}

impl ServeError {
    /// Whose fault, as the close code says it.
    fn close_reason(&self) -> CloseReason {
        match self {
            ServeError::Invite(InviteError::ServerGone)
            | ServeError::Admit(AdmitError::ServerGone) => CloseReason::ShuttingDown,
            ServeError::Invite(_)
            | ServeError::Admit(_)
            | ServeError::Sync(SyncError::Answer(_)) => CloseReason::Local,
            _ => CloseReason::Breach,
        }
    }
}

/// Serves one joiner's connection to completion, closing it after.
pub(crate) async fn serve(server: &ServerHandle, conn: &Connection) {
    match serve_join(server, conn).await {
        Ok(node) => {
            tracing::info!(%node, "admitted a node by invite");
            conn.close(0u32.into(), b"joined");
        }
        Err(e) => {
            tracing::warn!(error = %e, "join failed");
            e.close_reason().close(conn);
        }
    }
}

async fn serve_join(server: &ServerHandle, conn: &Connection) -> Result<KeyId, ServeError> {
    let (mut send, mut recv) = step(conn.accept_bi()).await.map_err(ServeError::Accept)?;

    let join = match step(read_frame(&mut recv))
        .await
        .map_err(ServeError::Frame)?
    {
        Message::Join(join) => join,
        other => {
            return Err(ServeError::Unexpected {
                expected: "Join",
                got: other.kind(),
            });
        }
    };
    if join.version != PROTOCOL_VERSION {
        refuse(&mut send, "protocol version mismatch").await;
        return Err(ServeError::Version {
            theirs: join.version,
        });
    }

    let welcome = match server.redeem_invite(join.token).await {
        Ok(welcome) => welcome,
        Err(e) => {
            refuse(&mut send, &e.to_string()).await;
            return Err(ServeError::Invite(e));
        }
    };
    step(write_frame(
        &mut send,
        &Message::Welcome(Box::new(Welcome {
            root: welcome.root,
            state: welcome.state,
        })),
    ))
    .await
    .map_err(ServeError::Frame)?;

    serve_pull(server, conn).await?;

    let key = Key::new(join.key, welcome.weight);
    let node = key.id();
    let digest = match server.admit(key, EndpointAddr::new(conn.remote_id())).await {
        Ok(digest) => digest,
        Err(e) => {
            refuse(&mut send, &format!("admission refused: {e}")).await;
            return Err(ServeError::Admit(e));
        }
    };
    step(write_frame(
        &mut send,
        &Message::Admitted(Admitted { digest }),
    ))
    .await
    .map_err(ServeError::Frame)?;

    serve_pull(server, conn).await?;

    // The joiner finishes the control stream once it has checked its
    // admission, and only then is the connection closed from this side:
    // a close racing the last frame of the pull would drop it.
    match step(read_frame(&mut recv)).await {
        Err(StepError::Failed(FrameError::Closed | FrameError::Io(_))) => Ok(node),
        Err(e) => Err(ServeError::Frame(e)),
        Ok(other) => Err(ServeError::Unexpected {
            expected: "the end of the control stream",
            got: other.kind(),
        }),
    }
}

/// Serves the pull the joiner opens on its next bi-stream.
async fn serve_pull(server: &ServerHandle, conn: &Connection) -> Result<(), ServeError> {
    let (send, recv) = step(conn.accept_bi()).await.map_err(ServeError::Accept)?;
    match sync_driver::serve(tokio::io::join(recv, send), server).await {
        Ok(_) => Ok(()),
        // Routine: a joiner already at our head learns so from `Hello`
        // and closes without another frame.
        Err(SyncError::PeerClosed) => Ok(()),
        Err(e) => Err(ServeError::Sync(e)),
    }
}

/// Tells the joiner why it is not getting further, and waits for it to
/// have read that: the connection is closed right after, and a close
/// racing the frame would leave the joiner with no reason at all. Best
/// effort — the session is ending either way.
async fn refuse(send: &mut SendStream, reason: &str) {
    let refused = Message::Refused(Refused {
        reason: reason.to_owned(),
    });
    let delivered = async {
        write_frame(send, &refused).await?;
        send.finish().map_err(io::Error::other)?;
        send.stopped().await.map_err(io::Error::other)?;
        Ok::<_, FrameError>(())
    };
    if let Err(e) = step(delivered).await {
        tracing::debug!(error = %e, "could not tell the joiner why it was refused");
    }
}

/// What a redeemed invite hands the joiner, gathered on the mainloop.
#[derive(Debug, Clone)]
pub(crate) struct Welcomed {
    pub(crate) root: Envelope,
    /// The checkpoint at the root, when the root is not an `Init`.
    pub(crate) state: Option<FullCheckpoint>,
    pub(crate) weight: u32,
}

// ---------------------------------------------------------------------
// The joiner's side.

/// Why a join did not end in a cluster on disk.
#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error(
        "the invite is format version {theirs}; this build speaks version {}",
        invite::VERSION
    )]
    InviteVersion { theirs: u32 },
    #[error("connecting to the sponsor")]
    Connect(#[source] ConnectError),
    #[error("opening a stream to the sponsor")]
    Open(#[source] StepError<ConnectionError>),
    #[error("on the control stream")]
    Frame(#[source] StepError<FrameError>),
    #[error("the sponsor refused: {0}")]
    Refused(String),
    #[error("expected {expected}, got {got}")]
    Unexpected {
        expected: &'static str,
        got: &'static str,
    },
    #[error("the sponsor sent root {got}, but the invite pinned {expected}")]
    RootMismatch { expected: String, got: String },
    #[error("the root envelope does not digest")]
    Undigestable(#[source] wire::Error),
    #[error("initializing the cluster on disk")]
    Init(#[source] InitError),
    #[error("pulling the chain")]
    Sync(#[source] SyncError),
    #[error("the sponsor shares no history with the root it handed over")]
    NoCommonHistory,
    #[error("the admission the sponsor announced is not on the chain")]
    AdmissionMissing,
    #[error("reading the chain after the join")]
    Chain(#[source] ChainError),
    #[error("the chain does not trust the sponsor's key")]
    SponsorNotTrusted,
    #[error("the chain does not trust this node's key after admission")]
    NotTrusted,
}

/// What a finished join leaves behind.
#[derive(Debug)]
pub struct Joined {
    /// The cluster, opened and caught up, ready for `lotusd run`.
    pub core: Core,
    /// The envelope that admitted this node.
    pub admitted: EnvelopeDigest,
}

/// Joins the cluster `invite` names, laying the chain down in
/// `state_dir` next to the keys [`Core::prepare_join`] put there.
///
/// `endpoint` must be bound with `keys`' iroh secret: the sponsor lists
/// the endpoint it was dialled from, and that must be the one the daemon
/// will later serve on.
pub async fn join(
    state_dir: std::path::PathBuf,
    keys: &NodeKeys,
    invite: &Invite,
    endpoint: &Endpoint,
) -> Result<Joined, JoinError> {
    if invite.version != invite::VERSION {
        return Err(JoinError::InviteVersion {
            theirs: invite.version,
        });
    }
    debug_assert_eq!(
        endpoint.id(),
        keys.iroh_secret().public(),
        "the endpoint must be the one the daemon will serve on"
    );

    let conn = endpoint
        .connect(invite.endpoint.clone(), ALPN)
        .await
        .map_err(JoinError::Connect)?;
    let (mut send, mut recv) = step(conn.open_bi()).await.map_err(JoinError::Open)?;

    step(write_frame(
        &mut send,
        &Message::Join(Join {
            version: PROTOCOL_VERSION,
            token: invite.token,
            key: keys.public_key(),
        }),
    ))
    .await
    .map_err(JoinError::Frame)?;

    let welcome = match step(read_frame(&mut recv))
        .await
        .map_err(JoinError::Frame)?
    {
        Message::Welcome(welcome) => *welcome,
        Message::Refused(refused) => return Err(JoinError::Refused(refused.reason)),
        other => {
            return Err(JoinError::Unexpected {
                expected: "Welcome",
                got: other.kind(),
            });
        }
    };
    let got = welcome.root.digest().map_err(JoinError::Undigestable)?;
    if got != invite.root {
        return Err(JoinError::RootMismatch {
            expected: invite.root.to_hex().as_ref().to_owned(),
            got: got.to_hex().as_ref().to_owned(),
        });
    }

    let mut core = Core::join_in_state_dir(state_dir, welcome.root, welcome.state)
        .await
        .map_err(JoinError::Init)?;
    pull(&conn, &mut core).await?;

    let admitted = match step(read_frame(&mut recv))
        .await
        .map_err(JoinError::Frame)?
    {
        Message::Admitted(admitted) => admitted.digest,
        Message::Refused(refused) => return Err(JoinError::Refused(refused.reason)),
        other => {
            return Err(JoinError::Unexpected {
                expected: "Admitted",
                got: other.kind(),
            });
        }
    };
    pull(&conn, &mut core).await?;

    if !core.contains(admitted).map_err(JoinError::Chain)? {
        return Err(JoinError::AdmissionMissing);
    }
    let trusted = core.trusted_keys().map_err(JoinError::Chain)?;
    if !trusted.contains_key(&invite.sponsor) {
        return Err(JoinError::SponsorNotTrusted);
    }
    if !trusted.contains_key(&keys.key_id()) {
        return Err(JoinError::NotTrusted);
    }

    // Finished, not dropped: the sponsor reads a clean end as the join
    // done, and the close carries the same.
    if let Err(e) = send.finish() {
        tracing::debug!(error = %e, "finishing the control stream");
    }
    conn.close(0u32.into(), b"joined");
    Ok(Joined { core, admitted })
}

/// Pulls whatever the sponsor has past this core's head, over a
/// bi-stream of its own.
async fn pull(conn: &Connection, core: &mut Core) -> Result<(), JoinError> {
    let (send, recv) = step(conn.open_bi()).await.map_err(JoinError::Open)?;
    match sync_driver::pull(tokio::io::join(recv, send), core)
        .await
        .map_err(JoinError::Sync)?
    {
        sync::PullOutcome::Synced { .. } | sync::PullOutcome::AlreadyCurrent => Ok(()),
        sync::PullOutcome::NoCommonHistory => Err(JoinError::NoCommonHistory),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(byte: u8) -> EnvelopeDigest {
        EnvelopeDigest::from_bytes([byte; 32])
    }

    fn token(byte: u8) -> Token {
        Token::from_bytes([byte; 32])
    }

    #[test]
    fn a_token_redeems_once() {
        let now = Instant::now();
        let mut invites = Invites::default();
        invites.issue(token(1), 3, Duration::from_secs(60), now, root(0));

        assert_eq!(invites.redeem(&token(1), now), Ok(Redeemed { weight: 3 }));
        assert_eq!(invites.redeem(&token(1), now), Err(RedeemError::Unknown));
        assert_eq!(invites.pending(), 0);
    }

    #[test]
    fn an_unknown_token_is_unknown_and_changes_nothing() {
        let now = Instant::now();
        let mut invites = Invites::default();
        invites.issue(token(1), 1, Duration::from_secs(60), now, root(0));

        assert_eq!(invites.redeem(&token(2), now), Err(RedeemError::Unknown));
        assert_eq!(invites.pending(), 1);
    }

    #[test]
    fn an_expired_token_says_so_once_then_is_gone() {
        let now = Instant::now();
        let mut invites = Invites::default();
        invites.issue(token(1), 1, Duration::from_secs(10), now, root(0));
        let later = now + Duration::from_secs(10);

        assert_eq!(invites.redeem(&token(1), later), Err(RedeemError::Expired));
        assert_eq!(invites.redeem(&token(1), later), Err(RedeemError::Unknown));
    }

    #[test]
    fn issuing_prunes_what_expired() {
        let now = Instant::now();
        let mut invites = Invites::default();
        invites.issue(token(1), 1, Duration::from_secs(1), now, root(0));
        invites.issue(
            token(2),
            1,
            Duration::from_secs(60),
            now + Duration::from_secs(5),
            root(0),
        );
        assert_eq!(invites.pending(), 1);
    }

    #[tokio::test]
    async fn control_frames_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let sent = Message::Admitted(Admitted {
            digest: EnvelopeDigest::from_bytes([4; 32]),
        });
        write_frame(&mut a, &sent).await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap(), sent);

        drop(a);
        assert!(matches!(read_frame(&mut b).await, Err(FrameError::Closed)));
    }
}
