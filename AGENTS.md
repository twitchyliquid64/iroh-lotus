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
| `state` | The state a chain folds down to. `Ledger::apply` advances it one envelope at a time, like replaying a database log. |
| `storage` | Where ledger state lives: a content-addressed version store keyed by envelope digest, so many ledgers (forks, rewrites, old positions) share one backend. Namespace/path-granular reads and writes, plus the in-memory backend and the conformance suite every backend must pass. |

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
