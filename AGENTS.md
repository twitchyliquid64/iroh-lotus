# iroh-lotus

iroh-lotus is a distributed ledger for slow-moving configuration and control data, built using a chain of signed
messages which are gossiped among all online nodes via iroh.

Think of it like a slow, high-integrity etcd.

Unlike etcd, it is possible to rewrite the chain of history to recover from a compromised node pushing malicious entries,
as long as compaction has not run on the oldest trustworthy message.

## Crate map

| Crate  | Role |
|--------|------|
| `wire` | Types for serializing messages on the wire. CBOR2 canonical used so messages have hash stability and can be signed. The `Value` <-> iroh address conversions sit behind the `iroh` feature (on for `state` and `lotusd`, off for `lotusd-rpc`), so a control-socket client builds without a QUIC stack. |
| `state` | The state a chain folds down to. `Ledger::apply` advances it one envelope at a time, like replaying a database log. `Chain` is like ledger except it resolves forks (multiple envelopes with the same parent) into the canonical path: at every fork the highest verified signature weight wins, ties broken by the highest envelope digest. `Chain::compact` prunes the log and versions below a cut on the canonical path — the cut's version stands in for the pruned history — and `Chain::adopt` opens a chain on a blank node from a cut envelope plus the checkpoint of its state. The `_lotus_schema` namespace maps a namespace's name to a `Schema` (the `schema` crate's) that `Ledger::apply` holds every write to that namespace to; a write to `_lotus_schema` itself is refused unless the namespaces whose entries it adds or changes already conform, so schema'd state conforms at every head. That invariant is what lets a nested write (`SetNamespaceKey`, `AmendNamespaceKey`) be judged from the path it lands on (`Schema::check_set`/`check_amend` over a `Standing` view of the store) without materializing the namespace, which may be hundreds of MB; only a write to `_lotus_schema` reads whole namespaces, and only the ones whose entries it changes. |
| `schema` | The schema language alone, apart from the ledger that enforces it, so a client can read a schema without `state`'s iroh and storage backends (it takes `storage` without default features, for the pure value helpers). A `Schema` is a small closed language spelled as a plain `Value`, parsed strictly — an unknown type or keyword is refused, never ignored. `Schema::check` judges a whole value; `check_set`/`check_amend` judge a nested write from its path over a `Standing` view. `kind`, `description` and `at` walk a parsed schema for whoever shows it; `description` is the one keyword every type takes and nothing judges. Consensus-critical: extending the language changes what nodes accept, a keyword that judges nothing included — a node that predates it refuses the schema that uses it. |
| `storage` | Where ledger state lives: a content-addressed version store keyed by envelope digest, so many ledgers (forks, rewrites, old positions) share one backend, plus the envelope log those versions fold down from. The log also stamps each envelope with a `StoredAt` — when *this* node first saw it: inspection, and the clock compaction's retention floor runs on. Namespace/path-granular reads and writes, the in-memory backend, the SQLite backend (default feature `sqlite`), and the conformance suite every backend must pass. |
| `render` | How an envelope is shown to a person: one stanza format, optionally coloured. The value a message writes is previewed in the stanza — JSON-shaped, broken over lines and elided at a fixed width and line budget, so a small write reads whole and a checkpoint doesn't flood the screen. A genesis's namespaces share that one budget between them, an equal share each, so no one of them spends the lines the rest are shown in. |
| `sync` | Node-to-node sync: the peer wire protocol and sans-io session machines. A `Puller` catches a node up from one peer, a `Server` serves the peer's pull; both consume `Input`s and emit `Effect`s — storage access included, as `Ask`/`Ingest` effects the driver resolves — so sessions run without sockets, clocks, or a runtime. Each node offers only its own canonical path; fork resolution in `state` does all merging. Each side's `Hello` also names the software version it runs (optional, never compared — older nodes skip the key, so it needed no protocol bump); each machine keeps what its peer said. |
| `lotusd-rpc` | The protocol lotusd speaks on its local socket. Length-prefixed canonical CBOR frames; one connection carries one request and the stream of responses to it. A `Method` pairs a request with the response type that answers it, so callers never name the response, and says whether it is answered once (`AnsweredOnce`, all `call` accepts) or streams (read through `Call`, itself a `Stream`). `GetStatus` answers with everything `lotusctl status` prints — identity, endpoint, chain range, kept peers (each with its route: direct, relayed, or over a custom transport), inbound count, and the name `_lotus_nodes` gives this node and each peer where set — carrying iroh ids as strings so clients need not depend on iroh. |
| `lotus-sdk` | A running lotusd as a Rust API, for programs other than `lotusctl`. A `Client` names the control socket (`Client::discover` finds it where `lotusd` keeps it, falling back to the machine-wide `/var/lib/lotus` when the user's own state directory does not exist — clients only; `lotusd` never falls back) and opens one connection per request; every protocol method has a typed method on it, `call`/`stream` take any `Method`, and `Streaming` is the answers to a streaming request as a `tokio_stream::Stream`. Re-exports the request, response and `wire` value types a program touches, and `schema` for reading what `_lotus_schema` holds, so it depends on this crate alone. |
| `lotusweb` | A web view onto a running lotusd, over `lotus-sdk` and axum: a sidebar of namespaces beside a main pane walked like a file browser, with breadcrumbs, JSON editors for leaves, add/append/replace/delete forms for containers. Plain HTML over htmx 4 (vendored in `static/`): `hx-target` is inherited from `body` (htmx 4 inherits nothing implicitly), every link and form fetches the main pane alone and the sidebar rides along out of band; a plain navigation or history restore gets the whole document. A location's URL, `/ns/<namespace>/<path>`, spells the path exactly as `lotusctl` does (`servers[0].host`), and the method says what happens there: `GET` shows, `PUT` replaces, `POST` adds an entry, `PATCH` amends in place (adds to an integer, or renames a map entry: a set at the new key then a delete at the old, the chain having no move), `DELETE` removes. Values are plain JSON, as `lotusctl` speaks them, so a trusted key can be seen but not written from the page. Where `_lotus_schema` governs the namespace (read per page; one this build cannot parse counts as none), a location shows what its schema says of it — type, restrictions, `description` — a struct lists every declared field, set or not, and the forms are typed by it (`form`): an input per value in place of the JSON editor, and an add-entry form laid out in the page with an input per field. Typed fields are named `f`, `f.<field>`, and read back by the schema as it stands at submission; a blank optional field is left out. Whether a value conforms stays the ledger's call — the page only shapes what is typed. A user's entry in a namespace's `auth.users` map (`auth.users.<user>`) gets a set-password form; the server writes the argon2id hash (default params, fresh salt) of what is typed to `auth.users.<user>.password`, as a `PATCH` like the other amends. `/chain` is `lotusctl chain` as a page: one stanza per envelope, newest first, its targets linked into the browser, bounded by `?limit=` and `?since=` as that command is by its flags; reached from the bottom of the sidebar, apart from the namespaces. `/peers` beside it is `lotusctl status` as a page: this node's identity, endpoint and listing, and a dot per kept peer coloured by its connection (green connected, amber dialing, red backing off) beside the route its traffic takes; the pane polls itself every 5s, through failures too, so it recovers when the daemon does. |
| `lotusd` | The daemon: `Core` is the on-disk cluster (store, chain, signing keys), `Server` owns it on one mainloop task and is reached only by actor messages through a `ServerHandle`. Its child actors on the iroh endpoint are `peer_ingress`, `peer_egress` and `addr_publish`, over the per-connection logic in `peer_link` and the sans-io driver in `sync_driver`; `invite` and `bootstrap` join a node to a cluster. See [The daemon](#the-daemon). |
| `filer-proto` | The protocol a filer client speaks to `filerd`, directly over iroh, under its own ALPN: the client's `Hello` names a volume, the filer answers with a `Welcome` carrying the `Mode` (read-only or read-write) or closes with a `Close` code. Who the client is never travels in a frame — it is the endpoint id iroh authenticated. Takes `wire` for its codec alone — no iroh, no `lotus-sdk` — so a client needs neither a ledger nor a control socket. From then on each stream the client opens is one filesystem operation (`fs`): one `Request` frame, one `Reply` frame, the op set a FUSE filesystem needs minus open and release. There are no handles — every op names its file by `NodeId` — so the filer keeps nothing per connection and a client that reconnects carries on with the ids it has; an id the filer no longer knows answers `Errno::Stale` and is looked up again. A `Name` is validated at decode (no `/`, no `.`/`..`), so no request can spell a path. Ownership does not travel. Directory listings page by name (`after`), not by offset. |
| `filerd` | The filer daemon: serves volumes of files to clients over its *own* iroh endpoint (own key, in its own state dir) and reaches the ledger only through the local lotusd's control socket, via `lotus-sdk`. Which volumes it serves and from which directory is its own configuration (`filerd run --volume NAME=DIRECTORY`; `filerd ticket NAME` prints a volume's ticket from the ledger, on any node; `--settle SECONDS` is how long a moved address waits before it is written); the ledger is where it announces them and where an operator says who may connect. `filers.<volume>` holds `endpoint` (an iroh address spelled as `_lotus_nodes` spells one — filerd's to write) and `allowed_clients` (`<name>: { endpoint_id, mode: ro \| rw }` — an operator's). Three tasks over one `View` of the namespace: `view` follows it by watch (`Unreadable` while the daemon cannot be reached); `publish` claims a volume nobody is named for, keeps the listed transports current after a settle, never overwrites another filer's claim (`--takeover` does, once, at start), and installs the namespace's schema in `_lotus_schema` where there is none (a differing one is left alone); `serve` is the gate — a client is judged by endpoint id when it names its volume and again on every ledger change, hung up on only when its own grant goes or narrows. An unreadable ledger admits nobody new but keeps the connections already judged. A nested write creates nothing along its path, so `publish` writes the namespace or the entry whole when it is missing and only the field or the transports otherwise. `backing` is a volume's directory and the ops carried out against it, blocking, run by the gate through `spawn_blocking`, one task per stream; a read-only client's mutating op is refused at the gate (`Errno::ReadOnly`) before it reaches the directory. The root is held as a `cap_std::fs::Dir`, so every path resolves beneath it — not `..`, not a symlink a client planted — and the final component is never followed. A `NodeId` is the backing inode number (the root's swapped with 1) plus a generation — on Linux the file's creation time, since a freed number goes straight to the next file there; 0 on macOS, where APFS reuses none and a creation time can be moved. Only metadata read through the holding directory by a single name carries a creation time (`Backing::stat`), so every id is made that way or one file gets two. Where each node was last found (parent and name) is remembered as lookups and listings find it, and is the only state — lost on restart, never pruned, and checked against the inode on every use, so a name that changed hands answers `Stale` rather than reaching another file. Nothing on another filesystem mounted inside the volume is served. |
| `filer-client` | A filer from the side that mounts it; no ledger, no `lotus-sdk`. `key` is an endpoint's secret key in a file (0600, created on first use; `filerd` keeps its own the same way). A `Ticket` (`lotusfs1…`, one base32 word like an invite) names a volume and the filer's address, spelled as the ledger spells one; it carries no secret — a client is admitted by endpoint id, never by holding a ticket. A `Session` is one volume on one filer over a connection remade as often as it has to be: dialled on first use, redialled after a loss. An operation cut off before it was sent, or one that changes nothing, is sent again on a fresh connection; a mutating one cut off after it was sent is reported as failed, since the filer may have carried it out. |
| `lotusfs` | The client binary: `id` prints the endpoint id an operator lists under `allowed_clients`, `ls` and `cat` read a volume with no mount, `put` writes one (standard input or a local file, created or truncated as a shell's `>` would, into a directory under the file's own name as `cp` would) `mkdir` makes a directory in one (`-p` as `mkdir -p`) and `rm` removes a file or symlink from one (never a directory), and `mount` (Linux only — `fuser` without libfuse, mounting through `fusermount3`) serves it as a FUSE filesystem. The command itself is the library's `cli` (`execute`, taking what to read as standard input, where to print and when to stop), as `filerd`'s is, so `tests/commands.rs` runs both commands in one process as an operator and a user would — parsed from arguments, against a real lotusd and real endpoints on loopback — with no mount and nothing asked of the host. `fuse::Volume` is the FUSE layer apart from the kernel, by inode number, which that test drives directly; it builds on macOS too (`fuser`'s `macos-no-mount`), where it cannot mount. `fuse` is mostly translation, plus memory: the kernel names a file by inode number alone, so every node it has been told of is remembered with its full `NodeId` and the parent and name it was found under, and an op the filer answers `Stale` (it restarted and forgot where files are) is tried once more after looking the node up again from its parent, recursively to the root. The kernel's callbacks are synchronous, so each hands its reply to a task on the runtime. No open handles: `open` is the kernel's default no-op. A directory is read whole on its first `readdir` and held per handle so offsets stay put. Everything is shown as owned by the mountpoint's owner; a chown is accepted and changes nothing. Attributes are cached for a second, which is how stale another client's change can look. |

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
   the same connection when its head differs. It also pulls once on connect, which is where it learns the version the
   peer runs (`PeerState::Connected`'s `software`, shown by `lotusctl status` and `/peers`) — an in-sync peer otherwise
   never opens a session. `PeerState::Connected`'s `route` follows the connection's selected path (`paths_stream`):
   direct, relay, or a custom transport (the in-memory test network is one, so only a loopback-UDP test sees `Direct`).
 - `peer_link` is the per-connection logic ingress and egress share: sessions on their own tasks, one pull at a time,
   announces in and out.
 - `addr_publish` is the one writer of the node's *own* `cluster-nodes` entry: it watches `Endpoint::watch_addr`, lets a
   moved address settle, then hands it to `Core::advertise`, which compares against the ledger under one borrow and
   writes only the transports that differ. Level-triggered off the address, the node's own listing path, and the trusted
   key set. It only maintains transports for the endpoint the ledger already names: a delisted node stays delisted, and
   one listed under another endpoint id is left alone (which endpoint a node *is* stays an operator's call — a daemon
   over a copied state dir must not capture the original's entry). `lotusctl status` reports where the listing stands.
 - `ip_family` binds the endpoint where `--bind` says. Given one IP family only, it wraps the DNS resolver so the
   other family's lookups come back empty (relays are dialled over TCP, outside those sockets) and, for IPv6, turns
   port mapping off. Peer addresses of a family the endpoint has no socket for are dropped before dialling. It also
   sets the CA roots for the TLS iroh speaks to relays, pkarr servers and DNS-over-HTTPS resolvers — the host's store
   (`CaTlsConfig::system()`, iroh's `platform-verifier` feature), never a compiled-in snapshot, so a root the OS
   distrusts is distrusted without a rebuild. The two sit together because a custom resolver replaces the one iroh
   builds from those roots: the wrapped resolver must be handed the same config or its DNS-over-HTTPS silently falls
   back to webpki-roots.
 - `invite` is the one-word text (`lotus1…`) an operator carries from a running node to a blank one: sponsor id, endpoint
   address, pinned root digest, one-time token.
 - `bootstrap` is the join protocol under its own ALPN: the joiner redeems the token, gets the root envelope — plus the
   checkpoint of its state, when the sponsor's root is a compaction cut (`Chain::adopt`; the digest pins the envelope
   alone, the checkpoint rides on the sponsor's vouch) — pulls the chain (through `sync_driver` against a bare `Core` —
   there is no server yet), and only then is admitted by the sponsor's signature alone (`Core::admit`: trusted key,
   then `cluster-nodes` entry). Tokens live in the server mainloop's memory only, expire, and redeem once; an invite is
   refused up front when the sponsor could not sign an admission alone.
 - Compaction runs on the mainloop: an hourly pass — and `lotusctl compact`, eagerly — moves the oldest envelope forward
   (`Core::compact` over `Chain::compact`), pruning the log and versions below a cut on the canonical path. Kept
   regardless: the newest `--keep-envelopes` (default 32), everything held for less than the ledger's
   `_lotus_min_keep_minutes` floor (by `StoredAt`, this node's own clock — the floor promises how long *this* node keeps
   a message), and the roots pending invites pinned. The `oldest_envelope` file names the cut durably *before* the
   prune, so a crash mid-prune reopens at the cut and the next pass finishes the sweep. A peer that falls behind the
   horizon gets `NoCommonHistory` from sync and recovers by re-joining with an invite.

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
