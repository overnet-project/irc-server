#!/usr/bin/env bash
#
# Smoke-test an IRC server image built from this directory's Containerfile.
#
# The test drives the container with the SAME run arguments and health command
# declared in overnet-irc.container -- read out of that unit at run time rather
# than duplicated here -- so editing the unit automatically changes what this
# test exercises. It asserts only observable outcomes: the service starts,
# listens, records "ready" in its health file, and its health command passes.
# Retuning the image or the unit therefore does not require editing this script.
#
# Usage: smoke-test.sh IMAGE
#
set -euo pipefail

IMAGE="${1:?usage: smoke-test.sh IMAGE}"
HERE="$(cd "$(dirname "$0")" && pwd)"
UNIT="$HERE/overnet-irc.container"

[[ -f "$UNIT" ]] || { echo "smoke-test: missing $UNIT" >&2; exit 1; }

# --- read the deployment's own configuration out of the Quadlet unit ---------

joined_unit() { perl -0777 -pe 's/\\\n\s*/ /g' "$UNIT"; }

exec_line="$(joined_unit | sed -n 's/^Exec=//p')"
health_cmd="$(joined_unit | sed -n 's/^HealthCmd=//p')"
publish="$(grep -m1 '^PublishPort=' "$UNIT" | cut -d= -f2-)"

[[ -n "$exec_line" ]]  || { echo "smoke-test: no Exec= in unit"        >&2; exit 1; }
[[ -n "$health_cmd" ]] || { echo "smoke-test: no HealthCmd= in unit"   >&2; exit 1; }
[[ -n "$publish" ]]    || { echo "smoke-test: no PublishPort= in unit" >&2; exit 1; }

mapfile -t run_args < <(printf '%s' "$exec_line" | xargs printf '%s\n')

# The readiness signal is the health file the service writes; find its path in
# the run arguments so this test follows the unit rather than hard-coding it.
health_file=""
for ((i = 0; i < ${#run_args[@]}; i++)); do
  if [[ "${run_args[i]}" == "--health-file" ]]; then
    health_file="${run_args[i + 1]}"
    break
  fi
done
[[ -n "$health_file" ]] || { echo "smoke-test: unit does not set --health-file" >&2; exit 1; }

port="${publish##*:}"
name="overnet-irc-smoke-$$"
volume="overnet-irc-smoke-vol-$$"

cleanup() {
  echo "----- container logs -----"
  podman logs "$name" 2>&1 | sed 's/^/[irc] /' || true
  podman rm -f "$name"       >/dev/null 2>&1 || true
  podman volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "smoke-test: starting $IMAGE with the unit's own arguments"
# Mount a fresh named volume where the unit keeps its state, exercising the
# first-mount ownership (copy-up) path the real deployment relies on -- and the
# service's ability to generate its signing key there.
podman run --detach \
  --name "$name" \
  --publish "$publish" \
  --volume "$volume:/var/lib/overnet/irc" \
  --health-cmd="$health_cmd" \
  "$IMAGE" "${run_args[@]}" >/dev/null

# --- wait for the listener, failing fast if the container dies ---------------

deadline=$(( SECONDS + 120 ))
until timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/dev/null; do
  if [[ "$(podman inspect -f '{{.State.Running}}' "$name" 2>/dev/null || echo false)" != true ]]; then
    echo "smoke-test: container exited before it listened on $port" >&2
    exit 1
  fi
  if (( SECONDS > deadline )); then
    echo "smoke-test: timed out waiting for the IRC server to listen on $port" >&2
    exit 1
  fi
  sleep 2
done
echo "smoke-test: IRC server is listening on 127.0.0.1:$port"

# --- confirm the service recorded readiness and the health command passes ----

ready_deadline=$(( SECONDS + 45 ))
until podman exec "$name" cat "$health_file" 2>/dev/null | grep -q '"status":"ready"'; do
  if [[ "$(podman inspect -f '{{.State.Running}}' "$name" 2>/dev/null || echo false)" != true ]]; then
    echo "smoke-test: container exited before reporting readiness" >&2
    exit 1
  fi
  if (( SECONDS > ready_deadline )); then
    echo "smoke-test: IRC server never reported readiness in $health_file" >&2
    exit 1
  fi
  sleep 1
done
echo "smoke-test: IRC server reported ready"

if ! podman healthcheck run "$name"; then
  echo "smoke-test: the unit's health command failed against the running server" >&2
  exit 1
fi
echo "smoke-test: health command passed"

echo "smoke-test: PASS"
