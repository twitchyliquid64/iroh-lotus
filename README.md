# iroh-lotus

A distributed ledger for slow-moving configuration and control data, built as a chain of signed
messages gossiped among all online nodes via [iroh](https://iroh.computer).

Think of it as a slow, high-integrity etcd.

Unlike etcd, the chain of history can be rewritten to recover from a compromised node pushing
malicious entries, as long as compaction has not yet run on the oldest trustworthy message.

> [!WARNING]
> Early development. The wire format is not stable and no compatibility is promised between
> versions.

## Getting started

**1. Install the binaries.** Grab `lotusd` and `lotusctl` from the
[latest release](https://github.com/twitchyliquid64/iroh-lotus/releases/latest) and put them on your
`PATH`:

```sh
tar -xzf iroh-lotus-v*-linux-amd64.tar.gz
sudo install iroh-lotus-v*-linux-amd64/lotus{d,ctl} /usr/local/bin
```

**2. Start the first node.** `init` creates the cluster — keys, genesis, state directory — and
`run` serves it in the foreground:

```sh
lotusd init
lotusd run
```

State lives under `$XDG_STATE_HOME/iroh-lotus` (`~/.local/state/iroh-lotus`) unless `--state-dir`
or `LOTUS_STATE_DIR` says otherwise. With the daemon up, `lotusctl` talks to it over the control
socket in that directory:

```sh
lotusctl status
lotusctl set cfg '{"port": 443}'
lotusctl get cfg port
```

**3. Add more nodes.** On a node already in the cluster, mint a one-time invite:

```sh
lotusctl invite
```

Carry that word to the new machine — it is a credential, so hand it over privately — and join with
it instead of `init`. Bootstrap pulls the whole chain and waits to be admitted, then exits:

```sh
lotusd bootstrap lotus1...
lotusd run
```

Repeat for each additional node.

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
