#!/usr/bin/env bash
# QEMU lives inside a bounded, network-none, capability-free container.
# Never run guest clock/power commands on this host or grant SYS_TIME/SYS_BOOT.
set -euo pipefail
vm_cpus=${VPNCTL_VM_CPUS:-1}
case "$vm_cpus" in
    1|0.5|0.25) ;;
    *) echo 'VPNCTL_VM_CPUS must be 1, 0.5 or 0.25 (container quota only)' >&2; exit 2 ;;
esac
external_binary=${VPNCTL_TEST_BINARY:-}
if [[ -n "$external_binary" ]]; then
    external_binary=$(realpath -- "$external_binary")
    [[ -f "$external_binary" && -x "$external_binary" ]] || { echo 'VPNCTL_TEST_BINARY must be executable' >&2; exit 2; }
fi
cd "$(dirname "${BASH_SOURCE[0]}")/.."
results=${VPNCTL_ARTIFACT_DIR:-$(mktemp -d /tmp/vpnctl-vm-results.XXXXXX)}
mkdir -p "$results"
results=$(realpath "$results")
python3 - "$results" <<'PY'
from pathlib import Path
import sys
if any(Path(sys.argv[1]).iterdir()):
    raise SystemExit('artifact directory must be empty; prior evidence is never overwritten')
PY
work=$(mktemp -d /tmp/vpnctl-vm.XXXXXX)
chmod 700 "$work"
boot_before=$(cat /proc/sys/kernel/random/boot_id)
run_id=${work##*.}
build_container="vpnctl-vm-image-$run_id"
test_container="vpnctl-vm-test-$run_id"
cleanup() {
    status=$?
    docker rm -f "$build_container" "$test_container" >/dev/null 2>&1 || true
    # Preserve only this invocation's private image on failure for diagnosis.
    # It may contain credentials; never copy it into the public artifact dir.
    if [[ "$status" == 0 && "${VPNCTL_KEEP_VM_WORK:-0}" != 1 ]]; then
        rm -rf -- "$work"
    else
        printf 'Private VM work directory: %s\n' "$work"
    fi
    if [[ "$(cat /proc/sys/kernel/random/boot_id)" != "$boot_before" ]]; then
        echo 'Host boot changed during execution; results cannot qualify isolation' >&2
        exit 1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
[[ -r /dev/kvm && -w /dev/kvm ]] || { echo 'KVM access required; no host changes attempted' >&2; exit 2; }
mkdir "$work/input" "$work/image" "$work/runtime"
chmod 700 "$work/runtime"
# The capability-free image builder runs as UID 0 and cannot bypass DAC.
# Only this child of the private 0700 mktemp directory is writable by it.
chmod 777 "$work/image"
binary_origin=checkout
if [[ -n "$external_binary" ]]; then
    cp -- "$external_binary" "$work/input/vpnctl"
    binary_origin=external
else
    GOMAXPROCS=2 go build -p=2 -o "$work/input/vpnctl" ./cmd/vpnctl
fi
GOMAXPROCS=2 go test -p=2 -tags=integration -c -o "$work/input/integration.test" ./tests/integration
# Last peer-apply implementation before kernel leases, for real downgrade and
# upgrade rejection tests. The historical source is a fixture, never main.
legacy_commit=6e2da45c89de2d3ad2e4c930f1037472e6440692
mkdir "$work/legacy-src"
git archive "$legacy_commit" | tar -x -C "$work/legacy-src"
GOMAXPROCS=2 go -C "$work/legacy-src" build -p=2 -o "$work/input/vpnctl-legacy" ./cmd/vpnctl
v1_commit=fb0ca2e9684af827ac2afc4dd0cb9afcb0ca3e8b
mkdir "$work/v1-src"
git archive "$v1_commit" | tar -x -C "$work/v1-src"
GOMAXPROCS=2 go -C "$work/v1-src" build -p=2 -o "$work/input/vpnctl-lease-v1" ./cmd/vpnctl
v2_commit=b4ba9e7793b123e4b47bd2fc5acfdf9b2698a26b
mkdir "$work/v2-src"
git archive "$v2_commit" | tar -x -C "$work/v2-src"
GOMAXPROCS=2 go -C "$work/v2-src" build -p=2 -o "$work/input/vpnctl-lease-v2" ./cmd/vpnctl
# The legacy builder honors these per-container bounds during apt/kernel setup.
if [[ -n "${VPNCTL_VM_IMAGE:-}" ]]; then
    image=$(docker image inspect "$VPNCTL_VM_IMAGE" --format '{{.Id}}')
else
    DOCKER_BUILDKIT=0 docker build --cpu-period=100000 --cpu-quota=100000 --memory=2g \
        --build-arg "VPNCTL_VM_MANAGERS=${VPNCTL_VM_MANAGERS:-0}" \
        --iidfile "$work/image-id" -f tests/vm/Dockerfile tests/vm
    image=$(cat "$work/image-id")
fi
docker run --rm --name "$build_container" --network none --cpus=1 --memory=2g --memory-swap=2g \
    --cap-drop ALL --security-opt no-new-privileges \
    --mount "type=bind,src=$work/input,dst=/input,readonly" \
    --mount "type=bind,src=$work/image,dst=/out" \
    --entrypoint python3 "$image" /opt/vpnctl-vm/make_image.py
manifest="$results/run-$(date -u +%Y%m%dT%H%M%SZ)-$$.txt"
{
    printf '%s\n' 'contract_version=1' "suite_commit=$(git rev-parse HEAD)" \
        "suite_dirty=$(test -z "$(git status --porcelain)" && echo false || echo true)" \
        'runner=qemu-in-container' "cpus=$vm_cpus" 'memory=2g' 'guest_memory=768M' \
        'container_network=none' 'container_capabilities=none' "image_id=$image" \
        "host_boot_id=$boot_before" "binary_origin=$binary_origin" "legacy_commit=$legacy_commit" "lease_v1_commit=$v1_commit" "lease_v2_commit=$v2_commit" 'suite_race=0'
    sha256sum "$work/input/vpnctl" "$work/input/integration.test" "$work/input/vpnctl-legacy" "$work/input/vpnctl-lease-v1" "$work/input/vpnctl-lease-v2"
    printf 'test_argument=%s\n' "$@"
    cat "$work/image/image.json"
} > "$manifest"
docker run --rm --name "$test_container" --network none --cpus="$vm_cpus" --memory=2g --memory-swap=2g --pids-limit=256 \
    --cap-drop ALL --security-opt no-new-privileges --device /dev/kvm \
    --read-only --tmpfs /tmp:rw,nosuid,nodev,size=128m \
    --user "$(id -u):$(id -g)" --group-add "$(stat -c %g /dev/kvm)" \
    --mount "type=bind,src=$work/image,dst=/input,readonly" \
    --mount "type=bind,src=$work/runtime,dst=/work" \
    --mount "type=bind,src=$results,dst=/results" \
    "$image" "$@" &
pid=$!
wait "$pid"
