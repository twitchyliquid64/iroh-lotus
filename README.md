# iroh-lotus

A distributed ledger for slow-moving configuration and control data, built as a chain of signed
messages gossiped among all online nodes via [iroh](https://iroh.computer).

Think of it as a slow, high-integrity etcd.

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

**2. Start the first node.** `init` creates a fresh cluster on the current machine, and
`run` serves it in the foreground:

```sh
lotusd init
lotusd run
```

With the daemon up, `lotusctl` talks to it over the control socket (See docs for `--state-dir`):

```sh
lotusctl status
lotusctl set cfg '{"port": 443}'
lotusctl get cfg port
```

**3. Add more nodes.** On a node already in the cluster, mint a one-time invite:

```sh
lotusctl invite
```

Copy-paste that command to the new machine - it is a credential, so keep it secret - and run
it to initialize the node from the other. You can then start the daemon as usual:

```sh
lotusd bootstrap lotus1...
lotusd run
```

Repeat for each additional node.

## Reading and writing values

You can think of data in lotus as JSON documents, stored in _namespaces_.

```sh
# Sets the `web` namespace to the provided object
lotusctl set web '{"port": 443, "hosts": ["a.example"], "replicas": 3}'

lotusctl get web       # Read whole namespace
lotusctl get web port  # Reads a field from the object in the namespace
```

```
head   dea1db8d…
value  443
```

When writing data, its important to scope the write as tightly as possible: update fields instead of whole
namespaces, use `append` or `increment` prolifically etc.

```sh
lotusctl set web port 8443               # replace one key
lotusctl append web hosts '"b.example"'  # append to an array
lotusctl increment web replicas 2        # add to an integer; a negative delta subtracts
```

Removing takes two forms: one value named outright, or whichever entries meet a condition.

```sh
lotusctl unset web port                           # remove the key `port` and its value
lotusctl unset web                                # delete the whole `web` namespace
lotusctl delete web hosts --where '="b.example"'  # delete every entry that matches
```

To follow changes as they land, until interrupted:

```sh
lotusctl watch web
```

```
changed  e3e6d2c3… -> 5e0475c7…
  web  port
```

Every command takes `--format json` for ease when scripting.

## Development

Requires Rust 1.95 or newer.

```sh
cargo fmt && cargo clippy --all-targets -- -D warnings
cargo test
```

Contributors — including agents — should read [AGENTS.md](AGENTS.md) for conventions and coding
standards.

## License

Apache-2.0
