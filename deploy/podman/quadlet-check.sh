#!/usr/bin/env bash
# Validate both the standalone frontend and the complete private deployment.
# The generator only renders units; it does not start services or containers.
set -euo pipefail
shopt -s nullglob

HERE="$(cd "$(dirname "$0")" && pwd)"
quadlet=""
for cand in \
  /usr/libexec/podman/quadlet \
  /usr/lib/systemd/system-generators/podman-system-generator \
  /usr/lib/systemd/user-generators/podman-user-generator; do
  if [[ -x "$cand" ]]; then quadlet="$cand"; break; fi
done
[[ -n "$quadlet" ]] || { echo "quadlet-check: no Quadlet generator found" >&2; exit 1; }

# Quadlet searches subdirectories recursively. Isolate the two configurations
# so the standalone units cannot accidentally resolve references from stack/.
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
mkdir -p "$workdir/standalone" "$workdir/stack"
cp "$HERE"/*.container "$HERE"/*.volume "$workdir/standalone/"
cp "$HERE"/stack/* "$workdir/stack/"

status=0
for unit_dir in "$workdir/standalone" "$workdir/stack"; do
  echo "quadlet-check: validating $unit_dir"
  if ! output="$(QUADLET_UNIT_DIRS="$unit_dir" "$quadlet" -dryrun -user 2>&1)"; then
    printf '%s\n' "$output"
    status=1
    continue
  fi
  printf '%s\n' "$output"

  for unit in "$unit_dir"/*.container; do
    cname="$(sed -n 's/^ContainerName=//p' "$unit")"
    if [[ -z "$cname" ]] || ! grep -qE "ExecStart=.*podman run .*--name[ =]${cname}\b" <<<"$output"; then
      echo "quadlet-check: $unit did not convert to a container service" >&2
      status=1
    fi
  done

  for unit in "$unit_dir"/*.volume; do
    volname="$(sed -n 's/^VolumeName=//p' "$unit")"
    if [[ -z "$volname" ]] || ! grep -q "${volname}:/var/lib/overnet/" <<<"$output"; then
      echo "quadlet-check: no mount uses the volume declared by $unit" >&2
      status=1
    fi
    if grep -q "systemd-${volname}:" <<<"$output"; then
      echo "quadlet-check: a volume reference did not resolve to $unit" >&2
      status=1
    fi
  done

  for unit in "$unit_dir"/*.network; do
    network="$(sed -n 's/^NetworkName=//p' "$unit")"
    if [[ -z "$network" ]] || ! grep -qE "ExecStart=.*podman network create .*${network}" <<<"$output"; then
      echo "quadlet-check: $unit did not convert to a network service" >&2
      status=1
    fi
    count="$(grep -cE "ExecStart=.*podman run .*--network[ =]${network}\b" <<<"$output" || true)"
    if [[ "$count" -ne 2 ]]; then
      echo "quadlet-check: both IRC and its authority relay must join $network" >&2
      status=1
    fi
  done
done

if [[ $status -eq 0 ]]; then echo "quadlet-check: PASS"; fi
exit "$status"
