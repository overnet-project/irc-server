#!/usr/bin/env bash
#
# Integrated end-to-end test: run the authority relay and the IRC frontend as
# two containers on a shared podman network, wire the frontend to the relay via
# --authority-relay-url, and prove a message crosses the WebSocket link between
# them.
#
# The proof is the OVERNETAUTH DELEGATE write round-trip: the frontend publishes
# a delegation grant (kind 14142) to the relay and only acknowledges the client
# if the relay ACCEPTED it. integration-client.pl exits 0 only on that ack, and
# the grant then appears in the relay's on-disk store -- both observable from
# outside the containers.
#
# Usage: integration-test.sh IRC_IMAGE RELAY_IMAGE
#
set -euo pipefail

IRC_IMAGE="${1:?usage: integration-test.sh IRC_IMAGE RELAY_IMAGE}"
RELAY_IMAGE="${2:?usage: integration-test.sh IRC_IMAGE RELAY_IMAGE}"

net="overnet-integ-$$"
relay="authority-relay-$$"
irc="irc-$$"
relay_url="ws://${relay}:7448"

# The IRC adapter path inside the frontend image and the store/state paths.
relay_store="/var/lib/overnet/authority-relay/store.json"
relay_health="/var/lib/overnet/authority-relay/health.json"
irc_health="/var/lib/overnet/irc/health.json"
client="/opt/overnet/irc-server/deploy/podman/integration-client.pl"

cleanup() {
  echo "----- relay logs -----";    podman logs "$relay" 2>&1 | sed 's/^/[relay] /' | tail -40 || true
  echo "----- frontend logs -----"; podman logs "$irc"   2>&1 | sed 's/^/[irc] /'   | tail -40 || true
  podman rm -f "$relay" "$irc" >/dev/null 2>&1 || true
  podman network rm "$net"     >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Poll `podman exec <container> cat <file>` until it contains "status":"ready".
wait_ready() {
  local container="$1" file="$2" what="$3" deadline=$(( SECONDS + 90 ))
  until podman exec "$container" cat "$file" 2>/dev/null | grep -q '"status":"ready"'; do
    if [[ "$(podman inspect -f '{{.State.Running}}' "$container" 2>/dev/null || echo false)" != true ]]; then
      echo "integration: $what exited before becoming ready" >&2
      return 1
    fi
    if (( SECONDS > deadline )); then
      echo "integration: timed out waiting for $what to become ready" >&2
      return 1
    fi
    sleep 2
  done
  echo "integration: $what is ready"
}

podman network create "$net" >/dev/null
echo "integration: network $net"

# --- authority relay: the same relay image, entrypoint overridden -----------
echo "integration: starting authority relay"
podman run --detach --name "$relay" --network "$net" \
  --entrypoint=perl \
  "$RELAY_IMAGE" \
  /opt/overnet/relay-perl/bin/overnet-authority-relay.pl \
  --host 0.0.0.0 --port 7448 \
  --relay-url "$relay_url" \
  --grant-kind 14142 \
  --store-file "$relay_store" \
  --health-file "$relay_health" >/dev/null
wait_ready "$relay" "$relay_health" "authority relay"

# --- IRC frontend: wired to the relay by its network DNS name ---------------
echo "integration: starting IRC frontend"
podman run --detach --name "$irc" --network "$net" \
  "$IRC_IMAGE" \
  --adapter-id irc.public --network overnet \
  --listen-host 0.0.0.0 --listen-port 6667 \
  --server-name irc.overnet.local \
  --authority-relay-url "$relay_url" \
  --authority-relay-poll-interval-ms 50 \
  --group-host groups.example.test \
  --channel-group '#ops=ops' \
  --signing-key-file /var/lib/overnet/irc/signing-key.pem \
  --health-file "$irc_health" >/dev/null
wait_ready "$irc" "$irc_health" "IRC frontend"

# --- drive the handshake client from inside the frontend container ----------
echo "integration: running the authenticated DELEGATE handshake"
if ! podman exec "$irc" perl "$client" \
     127.0.0.1 6667 irc.overnet.local overnet "$relay_url"; then
  echo "integration: FAIL -- the frontend did not complete the delegation round-trip" >&2
  exit 1
fi
echo "integration: client completed the DELEGATE round-trip"

# --- corroborate: the grant the frontend published landed in the relay store -
if ! podman exec "$relay" cat "$relay_store" 2>/dev/null | grep -q '"kind":14142'; then
  echo "integration: FAIL -- no kind-14142 grant found in the relay store" >&2
  exit 1
fi
echo "integration: relay store contains the published grant (kind 14142)"

echo "integration: PASS"
