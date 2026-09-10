# Overnet IRC server — podman deployment

This directory packages a private IRC deployment: the IRC frontend, its
authority relay, a shared network, and persistent state. After preparing the
images, install and start the deployment with one command:

```bash
./irc-server/deploy/podman/install.sh
```

The installer uses the complete, checked-in [Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
configuration in `stack/`. The services already agree on their network, relay
URL, and startup order. IRC is published on the server's loopback interface;
the relay is accessible only inside the container network.

It deploys the `overnet-irc-server service` command — the same entrypoint
`deploy/systemd/overnet-irc.service` drives. The service is a supervisor: it
generates a signing key if one is not present, then runs the IRC listener as a
child process and reports readiness through a health file.

## Contents

| File | Purpose |
| --- | --- |
| `Containerfile` | Builds the image from sibling core-perl / relay-perl / adapter-irc-perl / irc-server checkouts. |
| `install.sh` | Installs the deployment and starts both services. |
| `stack/` | Complete private deployment: two containers, two state volumes, and their shared network. |
| `overnet-irc.container` / `overnet-irc.volume` | Optional standalone frontend configuration, also used by the image smoke test. |

## Prerequisites

- `podman` 4.9+ (Quadlet support) with a usable `systemd --user` session. For a
  login-independent service, enable lingering: `loginctl enable-linger`.
- A workspace containing sibling `core-perl/`, `relay-perl/`,
  `adapter-irc-perl/`, and `irc-server/` checkouts. Overnet core, the relay
  library, and the IRC adapter are used from their source trees (they are not on
  CPAN under the names the programs require), so all four must be present in the
  build context.

For example, as your deployment user:

```bash
git clone https://github.com/overnet-project/overnet-perl.git
git clone https://github.com/overnet-project/irc-server.git overnet-perl/irc-server
cd overnet-perl
```

## Prepare the images

Run from the workspace directory that holds all four checkouts:

```bash
podman build \
  --file irc-server/deploy/podman/Containerfile \
  --tag localhost/overnet-irc:latest \
  .

podman pull quay.io/overnet/relay:main
```

## Install and start (rootless)

Run as the same unprivileged user that prepared the images:

```bash
./irc-server/deploy/podman/install.sh
```

The installer copies the packaged configuration to
`~/.config/containers/systemd/` (or `$XDG_CONFIG_HOME/containers/systemd/`),
reloads systemd, then restarts the authority relay followed by IRC. It uses the
images already present on the server. Startup errors are reported by systemd
and Podman. The installer does not wait for application readiness; the
configured container health checks monitor the listeners after startup.
The packaged units start with the user manager; enable lingering if they must
start at boot and survive logout. Re-running the installer refreshes these unit
files and restarts both services while retaining the existing state volumes.

Manage them like any user service:

```bash
systemctl --user status overnet-authority-relay overnet-irc
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

## Hosted channels

The packaged deployment runs the relay image's `authority` role. Both services
use `ws://overnet-authority-relay:7448`, and IRC sets the group host to
`groups.overnet.local`. These settings are already present in `stack/`; they
require no operator edits. The server announces `irc.overnet.local` on network
`overnet`; use those values when configuring your client's auth agent.

The installer establishes the services, not group membership. Admit test
identities to the hosted channels before testing channel access. If importing
group-metadata snapshots, configure the authority relay's trusted signers with
`--snapshot-pubkey`; it trusts none by default. See the authority-relay section
of `relay-perl/deploy/podman/README.md`.

For access from your workstation, keep the loopback binding and open an SSH
tunnel:

```bash
ssh -N -L 16667:127.0.0.1:6667 USER@HOME_SERVER
```

Point your local Overnet auth proxy at `127.0.0.1:16667`, then connect your IRC
client to that proxy. The main IRC README documents identity and proxy setup.

## Configuration

The installer owns the packaged unit files. Put local changes in Quadlet
drop-ins, such as `~/.config/containers/systemd/overnet-irc.container.d/`, so
re-running it preserves your overrides. When replacing `Exec=`, include the
complete argument list from the packaged unit. Then reload and restart:

```bash
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

Rebuild the IRC image, explicitly pull any desired relay update, and rerun the
installer. The state volumes are independent of the images, so the signing key
and event store are retained:

```bash
podman build --file irc-server/deploy/podman/Containerfile --tag localhost/overnet-irc:latest .
podman pull quay.io/overnet/relay:main
./irc-server/deploy/podman/install.sh
```

## Standalone frontend

For an IRC frontend without a hosted-channel relay, install only the original
`overnet-irc.container` and `overnet-irc.volume` files beside this README. The
default `install.sh` installs the complete hosted deployment instead.
