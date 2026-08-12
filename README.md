# iroh-lotus

A distributed ledger for slow-moving configuration and control data, built as a chain of signed
messages gossiped among all online nodes via [iroh](https://iroh.computer).

Think of it as a slow, high-integrity etcd.

Unlike etcd, the chain of history can be rewritten to recover from a compromised node pushing
malicious entries, as long as compaction has not yet run on the oldest trustworthy message.

> [!WARNING]
> Early development. The wire format is not stable and no compatibility is promised between
> versions.

## Development

Requires Rust 1.95 or newer.

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

Contributors — including agents — should read [AGENTS.md](AGENTS.md) for conventions and coding
standards.

## License

Apache-2.0
