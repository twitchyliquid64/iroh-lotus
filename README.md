# iroh-lotus

A distributed ledger for slow-moving configuration and control data, built as a chain of signed
messages gossiped among all online nodes via [iroh](https://iroh.computer).

Think of it as a slow, high-integrity etcd.

> [!WARNING]
> Early development. The wire format is not stable and no compatibility is promised between
> versions.

## Getting started

**1. Install the binaries.** Grab `lotusd`, `lotusctl` and `lotusweb` from the
[latest release](https://github.com/twitchyliquid64/iroh-lotus/releases/latest) and put them on your
`PATH`:

```sh
tar -xzf iroh-lotus-v*-linux-amd64.tar.gz
sudo install iroh-lotus-v*-linux-amd64/lotus{d,ctl,web} /usr/local/bin
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

The same data can be browsed and edited from a browser: `lotusweb` serves a page over the
control socket, on `127.0.0.1:8080` unless `--listen` says otherwise.

```sh
lotusweb
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

## Systemd service

[docs/systemd.md](docs/systemd.md) covers running it as a system service on Debian — the
`lotus` user, the one-shot join before the daemon will start, and which accounts reach
the control socket. `lotusctl` and `lotusweb` find a daemon in `/var/lib/lotus` on their
own when the account runs none of its own.

## Containers

Multi-arch images (`linux/amd64`, `linux/arm64`) are published to
`ghcr.io/twitchyliquid64/iroh-lotus`. A release is tagged with its version and `latest`;
every push to `main` is published too, as `main` and as an immutable `sha-<commit>`, so
what is on main can be run without waiting for a tag. `latest` only ever moves to a
release. The binaries are static, so the image is `distroless/static`: no shell, no
package manager.
All three are on `PATH`, and `LOTUS_STATE_DIR` points at `/var/lib/lotus`, so `lotusctl`
finds the daemon's control socket without being told where it is.

```sh
docker run --rm -v lotus:/var/lib/lotus ghcr.io/twitchyliquid64/iroh-lotus:latest
docker run --rm -v lotus:/var/lib/lotus ghcr.io/twitchyliquid64/iroh-lotus:latest lotusctl status
```

[docs/kubernetes.md](docs/kubernetes.md) covers running it on a cluster — joining once
from an invite, what the node's identity means for volumes and replicas, and serving
`lotusweb` alongside the daemon.

## Reading and writing values

You can think of data in lotus as JSON documents, stored in _namespaces_.

```sh
# Sets the `web` namespace to the provided object
lotusctl set web '{"port": 443, "hosts": ["a.example"], "replicas": 3}'

lotusctl get web         # Reads whole `web` namespace
lotusctl len web hosts   # Counts the entries in the container at the `hosts` JSONPath in the `web` namespace
lotusctl keys web        # Lists the keys in the `web` namespace

lotusctl get web port    # Reads the value in the `web` namespace at the `port` JSONPath
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

## Programming against lotusd

`lotus-sdk` gives you a nifty API to talk to lotusd to read/write/watch values.

```rust
use lotus_sdk::{Client, NamespaceKey, Value, WatchEvent, WatchSelector};

let client = Client::discover()?;
let web = NamespaceKey::try_new("web")?;

client.set(web.clone(), "port".parse()?, 8080).await?;
let at = client.read(web.clone(), None).await?;
println!("{:?} at {}", at.value, at.head.to_hex().as_ref());

let mut watch = client.watch(WatchSelector::Namespace(web)).await?;
while let Some(WatchEvent::Changed(changed)) = watch.next().await? {
    println!("moved to {}", changed.head.to_hex().as_ref());
}
```

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
