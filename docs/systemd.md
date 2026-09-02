# Running lotusd under systemd

Unit files for a Debian (or any systemd) host live in [`systemd/`](systemd/):

| File | Installs to | Role |
|------|-------------|------|
| `lotusd.service` | `/etc/systemd/system/` | The daemon, `lotusd run`, as the `lotus` user over `/var/lib/lotus`. |
| `lotusd-bootstrap.service` | `/etc/systemd/system/` | One-shot join from an invite, for every node but the first. |
| `lotusd.sysusers.conf` | `/usr/lib/sysusers.d/lotusd.conf` | The `lotus` system user and group. |
| `lotusd.default` | `/etc/default/lotusd` | Optional environment: relay, discovery, compaction, log level. |

Everything runs as the `lotus` user, and the state directory `/var/lib/lotus` is
`lotus:lotus` `0750`, so no operator account can write it directly. That is deliberate:
the two things that must happen there before `lotusd run` will stay up, minting a cluster
or joining one, are done *through* systemd, which has the access.

## 1. Install

```sh
tar -xzf iroh-lotus-v*-linux-amd64.tar.gz
sudo install iroh-lotus-v*-linux-amd64/lotus{d,ctl,web} /usr/local/bin
sudo install -m 0644 docs/systemd/lotusd.service docs/systemd/lotusd-bootstrap.service /etc/systemd/system/
sudo install -m 0644 docs/systemd/lotusd.sysusers.conf /usr/lib/sysusers.d/lotusd.conf
sudo install -m 0644 docs/systemd/lotusd.default /etc/default/lotusd
sudo systemd-sysusers
sudo systemctl daemon-reload
```

The default relay is n0's public network, reached over HTTPS, so the host needs the
`ca-certificates` package (present on any normal Debian install).

## 2. Bring the state directory to life

`lotusd run` opens the chain that is already on disk and exits immediately when there is
none, so `lotusd.service` carries `ConditionPathExists=/var/lib/lotus/oldest_envelope`:
starting it on a blank host does nothing rather than crash-looping. First give it a
cluster, one of two ways.

### The first node: `lotusd init`

`init` needs no secret, so a transient unit is all it takes. It runs as `lotus` with the
same `StateDirectory=` the service uses, which creates `/var/lib/lotus` with the right
owner and mode, and `--pipe` brings the `Initialized cluster …` line back to your terminal.

```sh
sudo systemd-run --wait --pipe --collect --unit=lotusd-init \
  -p User=lotus -p Group=lotus -p StateDirectory=lotus -p StateDirectoryMode=0750 \
  -E LOTUS_STATE_DIR=/var/lib/lotus \
  /usr/local/bin/lotusd init
```

### Every other node: `lotusd bootstrap` from an invite

On a node already in the cluster:

```sh
lotusctl invite
```

The invite is a credential that redeems once. On the new host, put it in a root-only file,
start the one-shot unit, and remove the file:

```sh
sudo install -d -m 0700 /etc/lotus
sudo sh -c 'umask 077; cat > /etc/lotus/invite'   # paste the lotus1… word, then ctrl-d
sudo systemctl start lotusd-bootstrap
sudo rm /etc/lotus/invite
```

The unit hands the file to `lotusd` as a systemd credential, so the invite never appears
on a command line, in `ps`, or in `systemctl show`. It joins with
`ConditionPathExists=!/var/lib/lotus/oldest_envelope`, so on a host that already holds a
cluster it is skipped instead of destroying the node's identity, and
`journalctl -u lotusd-bootstrap` shows what the join did.

## 3. Run

```sh
sudo systemctl enable --now lotusd
systemctl status lotusd
```

Two things in the unit are worth knowing about:

- **It stops with SIGINT.** `lotusd run` shuts down cleanly on SIGINT and treats nothing
  else, so the unit sets `KillSignal=SIGINT`. Leave that in place when adapting the unit.
- **`Restart=on-failure`** covers crashes and lost network, not a missing cluster, which
  the condition check turns into a quiet skip. If `systemctl start lotusd` seems to do
  nothing, `systemctl status lotusd` says the condition failed and step 2 was missed.

## 4. Talk to it with `lotusctl`

The control socket is `/var/lib/lotus/local.sock`, mode `0660` and owned by `lotus:lotus`.
An operator account reaches it by joining the group:

```sh
sudo usermod -aG lotus "$USER"        # takes effect on next login
lotusctl status
```

Nothing else is needed: when an account runs no daemon of its own, `lotusctl` and
`lotusweb` look in `/var/lib/lotus` after the account's own state directory. An account
that also runs a personal `lotusd` keeps talking to that one, and reaches the system
daemon with `lotusctl --sd /var/lib/lotus …` or `LOTUS_STATE_DIR=/var/lib/lotus`. Root
can always connect; anyone outside the group is refused with a permission error on the
socket.

Note that anyone in `lotus` can write to the ledger with this node's key. Keep the group
to operators, and if `lotusweb` is run as a service, run it as `lotus` and put an
authenticating proxy in front of it.

## Recovery

A node that has been offline longer than the cluster keeps history for is refused with
`NoCommonHistory` and must join again. Its identity is in the state directory, so this is
a new node as far as the cluster is concerned: stop the service, clear the directory, and
go back to step 2 with a fresh invite.

```sh
sudo systemctl stop lotusd
sudo rm -rf /var/lib/lotus
```

`systemctl start lotusd-bootstrap` then recreates the directory as it joins.
