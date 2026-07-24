# Overnet IRC server — podman deployment

This directory packages the Overnet IRC server (the frontend IRC clients
connect to) as a container image and a pair of
[Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
units, so it can run and be supervised as a rootless `systemd --user` service.

It deploys the `overnet-irc-server service` command — the same entrypoint
`deploy/systemd/overnet-irc.service` drives. The service is a supervisor: it
generates a signing key if one is not present, then runs the IRC listener as a
child process and reports readiness through a health file.

## Contents

| File | Purpose |
| --- | --- |
| `Containerfile` | Builds the image from sibling core-perl / relay-perl / adapter-irc-perl / irc-server checkouts. |
| `overnet-irc.container` | Quadlet unit that runs the IRC server as a `systemd --user` service. |
| `overnet-irc.volume` | Quadlet unit declaring the named volume for state (the signing key). |

## Prerequisites

- `podman` 4.4+ (Quadlet support) with a usable `systemd --user` session. For a
  login-independent service, enable lingering: `loginctl enable-linger`.
- A workspace containing sibling `core-perl/`, `relay-perl/`,
  `adapter-irc-perl/`, and `irc-server/` checkouts. Overnet core, the relay
  library, and the IRC adapter are used from their source trees (they are not on
  CPAN under the names the programs require), so all four must be present in the
  build context.

## Build the image

Run from the workspace directory that holds all four checkouts:

```bash
podman build \
  --file irc-server/deploy/podman/Containerfile \
  --tag overnet-irc:latest \
  .
```

## Install and start the service (rootless)

```bash
mkdir -p ~/.config/containers/systemd
cp irc-server/deploy/podman/overnet-irc.container \
   irc-server/deploy/podman/overnet-irc.volume \
   ~/.config/containers/systemd/

systemctl --user daemon-reload
systemctl --user start overnet-irc
```

Manage it like any user service:

```bash
systemctl --user status overnet-irc
journalctl --user -u overnet-irc -f
```

## Verify

The service records readiness in a health file inside the state volume:

```bash
podman exec overnet-irc cat /var/lib/overnet/irc/health.json   # "status":"ready"
```

The Quadlet unit also defines a podman health check that opens a TCP connection
to the listener; `podman healthcheck run overnet-irc` runs it on demand. To
connect with an IRC client (loopback by default):

```bash
# e.g. irssi -c 127.0.0.1 -p 6667
```

## Connecting to a relay (hosted channels)

By default the server runs standalone — it listens and serves, but hosts no
authoritative (NIP-29) channels. To serve hosted channels, add an authority
relay URL to the unit's `Exec=` line and reload:

```
--authority-relay-url ws://overnet-relay:7447
```

Point it at the `overnet-relay` deployment (see `relay-perl/deploy/podman/`).

## Configuration

Tuning knobs are the `overnet-irc-server service` arguments on the unit's
`Exec=` line. Edit them in place, then reload:

```bash
$EDITOR ~/.config/containers/systemd/overnet-irc.container
systemctl --user daemon-reload
systemctl --user restart overnet-irc
```

Commonly adjusted arguments:

| Argument | Meaning |
| --- | --- |
| `--server-name` | Server name announced to IRC clients. |
| `--network` | Overnet network name. |
| `--group-host` | Host suffix used when mapping channels to groups. |
| `--authority-relay-url` | Relay that backs hosted channels (see above). |
| `--signing-key-file` | Signing key path; must stay inside the mounted volume. |

Run `podman run --rm overnet-irc:latest --help` for the full argument list.

## State and identity

The `overnet-irc-state` named volume, mounted at `/var/lib/overnet/irc`, holds
the auto-generated signing key. **It must persist** — losing it changes the
server's Nostr identity. Inspect or back it up:

```bash
podman volume inspect overnet-irc-state
```

## TLS and public exposure

`PublishPort` defaults to `127.0.0.1:6667:6667`, so the server is reachable
only from the host. For public exposure, terminate TLS in a reverse proxy in
front of the loopback listener (recommended), or enable the service's built-in
TLS by adding `--tls` (with `--tls-cert-chain-file` / `--tls-private-key-file`,
or letting it self-sign) and publishing the TLS port.

## Updating

Rebuild the image and restart; the state volume is independent of the image, so
the signing key is retained:

```bash
podman build --file irc-server/deploy/podman/Containerfile --tag overnet-irc:latest .
systemctl --user restart overnet-irc
```
