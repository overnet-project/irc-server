#!/usr/bin/env bash
#
# Validate that the Quadlet units in this directory convert to systemd services,
# using podman's Quadlet generator in dry-run mode (no running systemd session
# required). This catches structural mistakes in the units -- a misspelled key,
# an unresolved .volume reference, a malformed Exec= -- that the behavioural
# smoke test does not exercise.
#
# It asserts that the units convert and that the generated mount resolves to the
# declared volume, not what the units otherwise contain, so it survives edits to
# the units without changes here.
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

quadlet=""
for cand in \
  /usr/libexec/podman/quadlet \
  /usr/lib/systemd/system-generators/podman-system-generator \
  /usr/lib/systemd/user-generators/podman-user-generator; do
  if [[ -x "$cand" ]]; then quadlet="$cand"; break; fi
done
[[ -n "$quadlet" ]] || { echo "quadlet-check: no Quadlet generator found" >&2; exit 1; }
echo "quadlet-check: using $quadlet"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
mkdir -p "$workdir/containers/systemd"
cp "$HERE"/*.container "$HERE"/*.volume "$workdir/containers/systemd/"

# The generator reads units from the user config search path (XDG_CONFIG_HOME).
output="$(XDG_CONFIG_HOME="$workdir" "$quadlet" -dryrun -user 2>&1 || true)"
printf '%s\n' "$output"

status=0

# The .container unit must convert to a runnable podman service. Asserting the
# generated ExecStart exists is a positive success signal: a unit that failed to
# convert produces no ExecStart at all.
if ! grep -qE 'ExecStart=.*podman .*overnet-irc' <<<"$output"; then
  echo "quadlet-check: the .container unit did not convert to a podman service" >&2
  status=1
fi

# The mount must resolve to the volume unit's declared VolumeName. If the
# .container's Volume= reference does not match the .volume unit's file name,
# Quadlet silently falls back to a `systemd-<name>` volume instead of linking
# the unit -- guard against that regression by reading the name from the unit.
volname="$(sed -n 's/^VolumeName=//p' "$HERE"/*.volume | head -n1)"
if [[ -n "$volname" ]]; then
  if ! grep -q "${volname}:/var/lib/overnet/irc" <<<"$output"; then
    echo "quadlet-check: mount does not use the declared volume name ($volname)" >&2
    status=1
  fi
  if grep -q "systemd-${volname}:" <<<"$output"; then
    echo "quadlet-check: Volume= reference did not resolve to the .volume unit (fell back to systemd-$volname)" >&2
    status=1
  fi
fi

if [[ $status -eq 0 ]]; then
  echo "quadlet-check: PASS"
fi
exit $status
