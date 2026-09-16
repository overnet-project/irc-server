# Web IRC client

Use the existing [Kiwi IRC client and its WebSocket gateway](https://github.com/kiwiirc/kiwiirc/wiki/01.-Getting-Started).
The gateway serves the client files and forwards browser connections to one
configured IRC server. It does not hold users' Overnet identity keys.

The [upstream server archive](https://github.com/kiwiirc/kiwiirc/releases/tag/v1.7.1)
includes both components. The current deployment uses
`kiwiirc-server_v1.7.1-2_linux_amd64.zip`, extracted into
`~/.local/share/overnet-webchat/` under the `overnet` account. Make the `kiwiirc`
binary executable, copy `client.json` to `www/static/config.json`, and copy
`config.conf.example` to `config.conf`. Copy `overnet.js` to
`www/static/plugins/overnet.js` (create that directory if needed).

Set the gateway's upstream port to the host's published IRC port. For private
network access, change the HTTP bind address to the server's Tailscale address
and list the exact browser origins under `[allowed_origins]`. Keep
`[gateway] enabled = false` so clients cannot select other upstream servers.

Install `overnet-webchat.service` in `~/.config/systemd/user/`, then run as
`overnet`:

```sh
systemctl --user daemon-reload
systemctl --user enable --now overnet-webchat.service
```

Enable lingering once as an administrator (`loginctl enable-linger overnet`)
so the rootless IRC and webchat services survive logout and start at boot.

## debserver

The HTTP listener uses the server's Tailscale IPv4 address on port 7778. Its
upstream is `127.0.0.1:16667`, matching the existing IRC port override.
Open `http://debserver.tail529825.ts.net:7778/` from the tailnet.

Install the [Overnet browser extension](https://github.com/overnet-project/overnet-client)
first. It signs locally without a separate agent connector. Choose a nickname
and connect, then approve the sign-in in the extension window. That approval covers both identity proof and
the bounded IRC session delegation. No server password is needed and the gateway
never receives the user's identity key.

`overnet.js` uses Kiwi's plugin hooks to carry SASL NOSTR. It holds `CAP END`
until the server accepts the combined authentication and delegation response.
Missing extension, declined approval, malformed challenge, and server rejection
end the connection instead of registering a guest. Disconnecting or reconnecting
cancels the pending browser request. The client does not automatically join channels.

The browser binding is application-independent; this plugin alone handles IRC
capability negotiation and 400-character SASL framing. The shared exchange is
defined in [auth.md](https://github.com/overnet-project/spec/blob/main/docs/auth.md).
The extension asks for approval unless matching remembered access permits the
request, and uses provisional service locator trust. Tailnet access limits who
can reach this deployment; it does not replace Overnet authentication.

To check the plugin without installing npm dependencies:

```sh
node --test deploy/webchat/overnet.test.cjs
```

Configuration changes to `www/static/config.json` need a browser refresh.
Changes to `config.conf` need `systemctl --user restart overnet-webchat`.
Logs are available with `journalctl --user -u overnet-webchat`.
