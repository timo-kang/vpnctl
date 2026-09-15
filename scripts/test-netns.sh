#!/usr/bin/env bash
# Run real kernel WireGuard tests entirely inside a disposable network namespace.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
build_dir=$(mktemp -d /tmp/vpnctl-netns-build.XXXXXX)
container_name="vpnctl-netns-$$"
cleanup() {
    docker rm -f "$container_name" >/dev/null 2>&1 || true
    rm -rf "$build_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
artifact_dir=${VPNCTL_ARTIFACT_DIR:-$(mktemp -d /tmp/vpnctl-netns-results.XXXXXX)}
mkdir -p "$artifact_dir"
artifact_dir=$(cd "$artifact_dir" && pwd)
# The container drops to read-only code; only this result directory is writable.
go build -race -o "$build_dir/vpnctl" ./cmd/vpnctl
go test -race -tags=integration -c -o "$build_dir/integration.test" ./tests/integration
docker build -t vpnctl-netns-test -f tests/integration/Dockerfile tests/integration
echo "Network test results: $artifact_dir"
docker run --rm --init --entrypoint /bin/sh --name "$container_name" --network none \
    --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
    --mount "type=bind,src=$build_dir,dst=/test,readonly" \
    --mount "type=bind,src=$artifact_dir,dst=/results" \
    -e VPNCTL_INTEGRATION=1 -e VPNCTL_BIN=/test/vpnctl \
    -e VPNCTL_ARTIFACT_DIR=/results -e VPNCTL_NETNS_SIZES="${VPNCTL_NETNS_SIZES:-1,3,8,32}" \
    -e GORACE=atexit_sleep_ms=0 -e VPNCTL_RESULT_UID="$(id -u)" -e VPNCTL_RESULT_GID="$(id -g)" \
    vpnctl-netns-test -c 'status=0; /test/integration.test "$@" || status=$?; chown -R "$VPNCTL_RESULT_UID:$VPNCTL_RESULT_GID" /results; exit "$status"' \
    sh -test.v -test.timeout=15m "$@"
