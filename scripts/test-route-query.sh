#!/usr/bin/env bash
# All route mutations stay inside a fresh, network-none NET_ADMIN-only container.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
results=${VPNCTL_ARTIFACT_DIR:-$(mktemp -d /tmp/vpnctl-route-results.XXXXXX)}
mkdir -p "$results"
results=$(realpath "$results")
python3 - "$results" <<'PY'
from pathlib import Path
import sys
if any(Path(sys.argv[1]).iterdir()):
    raise SystemExit('artifact directory must be empty; prior evidence is retained')
PY
work=$(mktemp -d /tmp/vpnctl-route-build.XXXXXX)
container="vpnctl-route-query-${work##*.}"
cleanup() {
    docker rm -f "$container" >/dev/null 2>&1 || true
    rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
GOMAXPROCS=2 go test -p=2 -race -c -o "$work/route.test" ./internal/relayapply
if [[ -n "${VPNCTL_ROUTE_QUERY_IMAGE:-}" ]]; then
    image=$(docker image inspect "$VPNCTL_ROUTE_QUERY_IMAGE" --format '{{.Id}}')
else
    docker build --iidfile "$work/image-id" -f tests/integration/Dockerfile tests/integration \
        2>&1 | tee "$results/image-setup.log"
    image=$(cat "$work/image-id")
fi
{
    printf '%s\n' 'contract_version=1' "suite_commit=$(git rev-parse HEAD)" \
        "suite_dirty=$(test -z "$(git status --porcelain)" && echo false || echo true)" \
        'suite_race=1' 'container_network=none' 'container_capabilities=NET_ADMIN' \
        'cpus=1' 'memory=256m' 'swap=0' 'pids_limit=64' "image_id=$image" "kernel=$(uname -r)"
    sha256sum "$work/route.test"
} > "$results/manifest.txt"
docker run --rm --name "$container" --network none --cpus=1 \
    --memory=256m --memory-swap=256m --pids-limit=64 \
    --cap-drop ALL --cap-add NET_ADMIN --read-only --security-opt no-new-privileges \
    --tmpfs /tmp:rw,nosuid,nodev,size=32m \
    --mount "type=bind,src=$work/route.test,dst=/test/route.test,readonly" \
    -e VPNCTL_ROUTE_QUERY_TEST=1 -e GORACE=atexit_sleep_ms=0 \
    --entrypoint /test/route.test "$image" \
    -test.run '^TestLiveTargetRoute' -test.v -test.timeout=60s \
    2>&1 | tee "$results/contract.log"
