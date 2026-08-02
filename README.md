# Overnet IRC Server

This repo contains the Overnet-backed IRC server program and a small local demo client.

GitHub: <https://github.com/overnet-project/irc-server>

## Quick Start

Start the local demo server:

```bash
perl bin/overnet-irc-server local-server
```

That starts the real IRC server program under the Overnet runtime host and prints the port it bound to.

Then open two more terminals and connect two local accounts:

```bash
perl bin/overnet-irc-server chat-client --nick alice
perl bin/overnet-irc-server chat-client --nick bob
```

By default the client auto-joins `#overnet`. Plain text sends to the current target.

## Connecting to an authenticated server

An Overnet IRC server does not take a password. It asks your client to sign two
Nostr events: one proving which key you are, and one delegating limited
authority to the server for this session. Ordinary IRC clients cannot do that,
so a local proxy does it for you, signing through an auth agent that holds your
key.

You need three things: an identity, a config telling the agent what that
identity may authorize, and the two local processes. Start to finish:

```bash
# 1. Create your identity. Print it again later with --show.
overnet-irc-server keygen

# 2. Write the auth-agent config for the server you are joining.
#    --server-name and --network must match what the server announces.
overnet-irc-server auth init \
  --server-name irc.example.net --network overnet \
  --key-file ~/.local/state/overnet/id.pem

# 3. Run the agent and the proxy together (stays in the foreground).
overnet-irc-server connect \
  --server-host irc.example.net --server-port 6697 --server-tls
```

`connect` reads the socket from the config, starts the auth agent unless one is
already listening there, and runs the proxy against it. Stopping it with Ctrl-C
stops the agent it started, so your signing key does not stay loaded in a
process you have forgotten about. To run the two yourself instead:

```bash
overnet-auth-agent.pl --config-file ~/.local/state/overnet/auth-agent.json
# then, in another terminal:
export OVERNET_AUTH_SOCK=~/.local/state/overnet/auth.sock
overnet-irc-server proxy \
  --server-host irc.example.net --server-port 6697 --server-tls
```

Then point your IRC client at the proxy, with no SASL or scripts configured:

```
# irssi
/connect 127.0.0.1 16668

# weechat
/server add overnet 127.0.0.1/16668
/connect overnet
```

`keygen` prints your public key, and step 2 prints it again. That key is your
account: give it to the server operator so they can admit you to a channel, and
keep the private half safe, because every membership and operator right the
relay records is bound to it and can be recovered from nothing else.

Two things are worth knowing before they surprise you:

- The proxy serves **one client connection at a time**, and it hides IRCv3
  capabilities from the client, so `server-time`, `account-tag` and friends do
  not reach irssi or weechat.
- If the agent has no policy matching the request, it fails closed — it has no
  way to prompt you for approval. The failure now prints the exact
  `overnet-auth.pl policy-grant` command that would authorize it. `auth init`
  writes the policies the proxy needs, so this should only appear if the server
  name, network, or identity differs from what you configured.

## Authenticated IRC

The commands below are the manual and scripting-oriented flows, for bridging
auth into another client or debugging the handshake. For simply connecting,
use the proxy as above.

For authoritative IRC networks, start the local auth-agent daemon first:

```bash
overnet-auth-agent.pl --config-file ~/.config/overnet/auth-agent.json
```

Then point the helper at the auth socket either with `OVERNET_AUTH_SOCK`:

```bash
export OVERNET_AUTH_SOCK=/tmp/overnet-auth.sock
```

or explicitly with `--auth-sock`:

```bash
overnet-irc-server auth auth --auth-sock /tmp/overnet-auth.sock --scope irc://irc.example.test/overnet --challenge <challenge>
```

The normal manual flow is:

```bash
overnet-irc-server auth auth --scope irc://irc.example.test/overnet --challenge <challenge>
overnet-irc-server auth delegate --scope irc://irc.example.test/overnet --relay-url ws://127.0.0.1:7448 --delegate-pubkey <delegate_pubkey> --session-id <session_id> --expires-at <expires_at>
```

If you already have the full IRC notice line, bridge mode can translate it directly:

```bash
overnet-irc-server auth bridge --scope irc://irc.example.test/overnet --line '-server- OVERNETAUTH CHALLENGE <challenge>'
```

For client or ZNC scripting, bridge mode also works as a continuous stdin/stdout filter. It reads IRC lines from stdin, ignores unrelated lines, and emits auth commands on stdout for each matching `OVERNETAUTH` or SASL `NOSTR` challenge:

```bash
some-irc-line-source | overnet-irc-server auth bridge --scope irc://irc.example.test/overnet
```

The same continuous bridge mode also handles SASL `NOSTR` server challenges. Feed it IRC `AUTHENTICATE <chunk>` lines and it emits the matching client `AUTHENTICATE <chunk>` response lines:

```bash
some-irc-line-source | overnet-irc-server auth bridge
```

For normal IRC clients, run the local proxy instead of doing the auth commands
manually:

```bash
overnet-irc-server proxy --listen-port 16668 --server-host irc.example.test --server-port 6697 --server-tls
```

Then connect the IRC client to `127.0.0.1:16668`. The proxy handles upstream
SASL `NOSTR` authentication with the auth agent and hides the challenge/response
flow from the client. Relay delegation is automatic by default when the server
challenge asks for it. Use `--auto-delegate` or `--no-auto-delegate` to make
that behavior explicit.

## Client Commands

```text
/help
/join #channel
/target <target>
/msg <target> <text>
/notice <target> <text>
/topic <channel> <text>
/names [channel]
/part [channel] [reason]
/nick <newnick>
/raw <line>
/quit [reason]
```

## Notes

- The demo server defaults to `127.0.0.1:16667`.
- It auto-creates a Nostr signing key under the local state directory unless you pass `--signing-key-file`.
- The local demo client is intentionally small. It is a convenience terminal client for exercising the Overnet IRC server, not a full IRC client.
- `overnet-irc-server auth` uses the local auth agent. It does not read raw private keys directly.

## Related Repositories

- [spec](https://github.com/overnet-project/spec)
- [core-perl](https://github.com/overnet-project/core-perl)
- [relay-perl](https://github.com/overnet-project/relay-perl)
- [adapter-irc-perl](https://github.com/overnet-project/adapter-irc-perl)

## AI Usage

This code was developed in part with AI tooling such as Claude Code and Codex. We want to be upfront about that.
