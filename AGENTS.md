# iroh-lotus

iroh-lotus is a distributed ledger for slow-moving configuration and control data, built using a chain of signed
messages which are gossiped among all online nodes via iroh.

Think of it like a slow, high-integrity etcd.

Unlike etcd, it is possible to rewrite the chain of history to recover from a compromised node pushing malicious entries,
as long as compaction has not run on the oldest trustworthy message.

## Crate map

| Crate  | Role |
|--------|------|
| `wire` | Types for serializing messages on the wire. CBOR2 canonical used so messages have hash stability and can be signed. |
| `state` | The state a chain folds down to. `Ledger::apply` advances it one envelope at a time, like replaying a database log. `Chain` is like ledger except it resolves forks (multiple envelopes with the same parent) into the canonical path: at every fork the highest verified signature weight wins, ties broken by the highest envelope digest. |
| `storage` | Where ledger state lives: a content-addressed version store keyed by envelope digest, so many ledgers (forks, rewrites, old positions) share one backend, plus the envelope log those versions fold down from. The log also stamps each envelope with a `StoredAt` — when *this* node first saw it, for inspection only. Namespace/path-granular reads and writes, the in-memory backend, the SQLite backend (default feature `sqlite`), and the conformance suite every backend must pass. |
| `render` | How an envelope is shown to a person: one stanza format, optionally coloured. The value a message writes is previewed in the stanza — JSON-shaped, broken over lines and elided at a fixed width and line budget, so a small write reads whole and a checkpoint doesn't flood the screen. A genesis's namespaces share that one budget between them, an equal share each, so no one of them spends the lines the rest are shown in. |
| `sync` | Node-to-node sync: the peer wire protocol and sans-io session machines. A `Puller` catches a node up from one peer, a `Server` serves the peer's pull; both consume `Input`s and emit `Effect`s — storage access included, as `Ask`/`Ingest` effects the driver resolves — so sessions run without sockets, clocks, or a runtime. Each node offers only its own canonical path; fork resolution in `state` does all merging. |
| `lotusd-rpc` | The protocol lotusd speaks on its local socket. Length-prefixed canonical CBOR frames; one connection carries one request and the stream of responses to it. A `Method` pairs a request with the response type that answers it, so callers never name the response. `GetStatus` answers with everything `lotusctl status` prints — identity, endpoint, chain range, kept peers, inbound count — carrying iroh ids as strings so clients need not depend on iroh. |
| `lotusd` | The daemon: `Core` is the on-disk cluster (store, chain, signing keys), `Server` owns it on one mainloop task and is reached only by actor messages through a `ServerHandle`. Its child actors on the iroh endpoint are `peer_ingress`, `peer_egress` and `addr_publish`, over the per-connection logic in `peer_link` and the sans-io driver in `sync_driver`; `invite` and `bootstrap` join a node to a cluster. See [The daemon](#the-daemon). |

## The daemon

`Core` is the on-disk cluster — store, chain, signing keys. `Server` owns it on one mainloop task and is reached only by
actor messages through a `ServerHandle`; each local connection gets its own task and its own handle.

 - `sync_driver` drives the `sync` machines over any `AsyncRead + AsyncWrite` transport (a duplex pipe in tests, an iroh
   stream in the daemon), resolving their `Ask`/`Ingest` effects through the same actor messages.
 - `peer_ingress` accepts peer connections, one ALPN per protocol (`Protocol`), and serves each stream through a
   `WeakServerHandle` it upgrades per connection. A sync connection is served only when `cluster-nodes` lists an
   endpoint with the peer's id, read once at accept and refused when the ledger cannot be read; `bootstrap` is exempt,
   since being listed is what a join is for.
 - `peer_egress` subscribes to the `cluster-nodes` namespace and keeps one dialled connection per listed node (a task
   each), reconciling the whole set on every change rather than diffing it. It also subscribes to the head and announces
   each move over those connections (a `sync::Announce` on a uni-stream), which the far side answers by pulling back over
   the same connection when its head differs.
 - `peer_link` is the per-connection logic ingress and egress share: sessions on their own tasks, one pull at a time,
   announces in and out.
 - `addr_publish` is the one writer of the node's *own* `cluster-nodes` entry: it watches `Endpoint::watch_addr`, lets a
   moved address settle, then hands it to `Core::advertise`, which compares against the ledger under one borrow and
   writes only the transports that differ. Level-triggered off the address, the node's own listing path, and the trusted
   key set. It only maintains transports for the endpoint the ledger already names: a delisted node stays delisted, and
   one listed under another endpoint id is left alone (which endpoint a node *is* stays an operator's call — a daemon
   over a copied state dir must not capture the original's entry). `lotusctl status` reports where the listing stands.
 - `invite` is the one-word text (`lotus1…`) an operator carries from a running node to a blank one: sponsor id, endpoint
   address, pinned root digest, one-time token.
 - `bootstrap` is the join protocol under its own ALPN: the joiner redeems the token, gets the root envelope, pulls the
   chain (through `sync_driver` against a bare `Core` — there is no server yet), and only then is admitted by the
   sponsor's signature alone (`Core::admit`: trusted key, then `cluster-nodes` entry). Tokens live in the server
   mainloop's memory only, expire, and redeem once; an invite is refused up front when the sponsor could not sign an
   admission alone.

## Signature verification

If different nodes disagree on what signatures are valid, you get a permanent chain split: fork resolution picks the path with the highest
*verified* signature weight, so nodes that disagree about one signature pick different canonical chains and never
converge.

`wire` therefore verifies with `ed25519-zebra`, which implements [ZIP 215](https://zips.z.cash/zip-0215) — a precisely
specified rule set where individual verification agrees with batch verification.

Rules that follow:

 - Verify only through `wire`'s `Key::verify`. Never reach for `ed25519-dalek`'s `verify` or `verify_strict` on ledger
   signatures: those are different rule sets, and `verify_strict` disagrees with dalek's own batch verifier.
 - Keys and signatures are stored as the bytes that arrived and parsed only at verification time. A malformed key is a
   *failed verification*, never a decode error — an envelope one node cannot decode and another can is the same split
   by another name.
 - Signatures cover `Envelope::signature_digest`, not `Envelope::digest`; the latter covers the signatures themselves.
   Timestamps are inside the signed portion, so they must be attached before signing.
 - An envelope names its signing key by `KeyId` — blake3 over the *public key's* canonical encoding, never over the
   whole `Key` — and the trusted key set that resolves ids to keys is ordinary ledger state. Weight and metadata sit
   outside the id so a key can be re-weighted without orphaning the signatures naming it. The derivation is
   consensus-critical: nodes that derive different ids resolve different keys for the same signature.

## Development conventions and hard rules

 - Use **Conventional Commits** for the commit message. Don't commit unless asked.
 - Every change: run `cargo clippy --all-targets -- -D warnings`, `cargo test`. Justify any #[allow(...)] with a comment.

### Rust coding standards

#### Functional over Imperative

 - Iterator chains over manual loops. map, filter, collect, try_fold, flat_map instead of for with mutable accumulators. Use for only when side effects dominate or control flow makes a chain awkward.
 - Combinators on Option/Result. map, and_then, ok_or, unwrap_or_else, map_err, not match that reconstructs the same enum.
 - Immutable by default. Only mut when required. Building a Vec by push? Try .collect().
 - No index-based iteration. .iter(), .enumerate(), .zip(), .windows(), .chunks() over for i in 0..xs.len().

#### Idiomaticity

 - Cheapest reference that works. `&str` over `&String`, `&[T]` over `&Vec<T>`, `&Path` over `&PathBuf`, `impl AsRef<Path>` at boundaries.
 - `impl IntoIterator<Item = T>` for consuming a sequence; `impl Iterator<Item = T>` for returning one (avoid allocating).
 - Make illegal states unrepresentable. Encode invariants in the type system: enums for mutually exclusive states (not bool flags + Options), non-empty collections via Vec1 or `(T, Vec<T>)`, parsed types instead of
   validated-then-passed-as-string. If a function can't be called in some state, that state shouldn't typecheck.
 - **Never `usize`/`isize` in wire types.** Their width follows the host, so the same value encodes differently on a
   32- vs 64-bit node and an over-range value silently truncates. Pick an explicit width (`u32`, `u64`) and let decoding
   reject what doesn't fit. Newtypes on wire fields validate, never sanitize — rewriting a decoded value makes it
   re-encode to different bytes than it arrived as, and the digests depend on those bytes.
 - Newtypes for domain values (struct UserId(u64)) over bare primitives. Use the https://crates.io/crates/nutype crate when the type needs trivial invariants enforced (non-empty, range bounds, regex, trimmed, etc.), it generates the
   validating constructor and keeps the inner value unconstructable elsewhere.
 - Default only when the default is meaningful.
 - Builder pattern for types with more than a couple of fields or any optional config. Owned style: pub fn with_x(mut self, x: T) -> Self, never &mut self -> &mut Self.
 - Cloning discipline. .clone() is fine for Arc/Rc and small Copy-ish types; cloning a String/Vec/HashMap to dodge the borrow checker means restructure or borrow instead.
 - Captured-identifier formatting. format!("{path}") over format!("{}", path).
 - Display for users, Debug for developers. Don't reuse one for the other.

#### Error Handling

- Library/internal crates: Create an enum type for errors, either crate-wide or for specific operations where it makes sense to have a distinct error.
- Use `Option` for trivial cases such as getter methods where the return value is not applicable in a valid case/variant.
- Application crates: anyhow::Result for opaque propagation. Attach .context(...) / .with_context(|| ...) at layer boundaries. User-facing CLIs use color_eyre instead of anyhow for better-formatted reports.
- unwrap()/panic! only for broken invariants. unwrap() in tests only; in production use expect("why the invariant holds"). Never for recoverable conditions.
- Never swallow errors. No let _ = result; or .ok() discards without a comment justifying it.
- Preserve the source chain. Wrap, don't replace; errors trace back via source().
- Validate at the boundary, trust within.

#### Comments

 - Docstring should describe the method in idiomatic Go style. Otherwise, comments should be extremely terse, avoid talking about the problem at hand and only document
   footguns or really unintuitive invariants a developer is likely to stumble upon when working in that code.

#### Other

 - Logging: Use tracing. Structured fields and spans, not interpolated strings: tracing::info!(pkg = %name, "building"), not info!("building {name}").
 - unsafe requires a // SAFETY: comment covering every caller invariant.
 - Testing: behavior, not implementation; one concept per test; insta for snapshot-shaped output; integration tests under tests/ for cross-crate flows.
 - Dependencies: prefer std, then crates already in the workspace, then crates listed on https://blessed.rs before reaching elsewhere. Versions are pinned in the workspace Cargo.toml; crate-level Cargo.tomls inherit via workspace = true,
   never specifying their own version.
