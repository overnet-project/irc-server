#!/usr/bin/env bash
# Install the checked-in private IRC deployment as rootless user services.
set -euo pipefail

[[ $# -eq 0 ]] || { echo "Usage: $0" >&2; exit 1; }
[[ $EUID -ne 0 ]] || { echo "Run this as your deployment user, without sudo." >&2; exit 1; }

deploy_dir="$(cd "$(dirname "$0")" && pwd)"
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/containers/systemd"

systemctl --user show-environment >/dev/null
install -d "$unit_dir"
install -m 0644 "$deploy_dir"/stack/* "$unit_dir/"
systemctl --user daemon-reload
systemctl --user restart overnet-authority-relay.service
systemctl --user restart overnet-irc.service
echo "Services started. IRC is configured on 127.0.0.1:6667."
