#!/usr/bin/env bash
# Run real kernel WireGuard tests entirely inside a disposable network namespace.
set -euo pipefail
# Resolve caller-relative paths before entering the suite checkout.
external_binary=${VPNCTL_TEST_BINARY:-}
if [[ -n "$external_binary" ]]; then
    external_binary=$(realpath -- "$external_binary")
    if [[ ! -f "$external_binary" || ! -x "$external_binary" ]]; then
        echo 'VPNCTL_TEST_BINARY must name an executable Linux vpnctl binary' >&2
        exit 2
    fi
fi
cd "$(dirname "${BASH_SOURCE[0]}")/.."
build_dir=$(mktemp -d /tmp/vpnctl-netns-build.XXXXXX)
work_dir=
image_id=
container_name="vpnctl-netns-$$"
cleanup() {
    docker rm -f "$container_name" >/dev/null 2>&1 || true
    rm -rf "$build_dir"
    if [[ -n "$work_dir" ]] && ! rm -rf -- "$work_dir" 2>/dev/null; then
        # Interrupted Go tests may leave root-owned private temp directories.
        # Only the mktemp directory created by this invocation is mounted.
        docker run --rm --network none --entrypoint chown \
            --mount "type=bind,src=$work_dir,dst=/cleanup" "$image_id" \
            -R "$(id -u):$(id -g)" /cleanup
        rm -rf -- "$work_dir"
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
artifact_dir=${VPNCTL_ARTIFACT_DIR:-$(mktemp -d /tmp/vpnctl-netns-results.XXXXXX)}
mkdir -p "$artifact_dir"
artifact_dir=$(cd "$artifact_dir" && pwd)
# Race overhead can saturate a small CI runner at 32 simultaneous TLS clients.
# Keep the default for local stress; CI runs production builds plus a separate
# full race job. Both profiles keep identical traffic/deadline assertions.
build_flags=()
case "${VPNCTL_RACE:-1}" in
    1) build_flags=(-race) ;;
    0) ;;
    *) echo 'VPNCTL_RACE must be 0 or 1' >&2; exit 2 ;;
esac
docker_limits=()
if [[ -n "${VPNCTL_TEST_CPUS:-}" ]]; then docker_limits=(--cpus "$VPNCTL_TEST_CPUS"); fi
if [[ -n "${VPNCTL_TEST_MEMORY:-}" ]]; then docker_limits+=(--memory "$VPNCTL_TEST_MEMORY" --memory-swap "$VPNCTL_TEST_MEMORY"); fi
work_mount=()
if [[ -n "${VPNCTL_TEST_WORK_ROOT:-}" ]]; then
    work_root=$(realpath -- "$VPNCTL_TEST_WORK_ROOT")
    work_dir=$(mktemp -d "$work_root/vpnctl-network-work.XXXXXX")
    chmod 700 "$work_dir"
    work_mount=(--mount "type=bind,src=$work_dir,dst=/work" -e TMPDIR=/work)
fi
binary_origin=checkout
if [[ -n "$external_binary" ]]; then
    cp -- "$external_binary" "$build_dir/vpnctl"
    binary_origin=external
else
    go build "${build_flags[@]}" -o "$build_dir/vpnctl" ./cmd/vpnctl
fi
go test "${build_flags[@]}" -tags=integration -c -o "$build_dir/integration.test" ./tests/integration
docker build --iidfile "$build_dir/image-id" -f tests/integration/Dockerfile tests/integration
image_id=$(cat "$build_dir/image-id")
# A plain-text manifest is deliberately independent of any reporting service.
# The immutable binary digest identifies external builds; the race flag controls
# the suite and only controls vpnctl when built from this checkout.
manifest="$artifact_dir/run-$(date -u +%Y%m%dT%H%M%SZ)-$$.txt"
{
    printf '%s\n' 'contract_version=1' "suite_commit=$(git rev-parse HEAD)" \
        "suite_dirty=$(test -z "$(git status --porcelain --untracked-files=no)" && echo false || echo true)" \
        "binary_origin=$binary_origin" "suite_race=${VPNCTL_RACE:-1}" \
        "cpus=${VPNCTL_TEST_CPUS:-unlimited}" "sizes=${VPNCTL_NETNS_SIZES:-1,3,8,32}" \
        "kernel=$(uname -r)"
    printf '%s\n' "memory=${VPNCTL_TEST_MEMORY:-unlimited}" \
        "soak_duration=${VPNCTL_SOAK_DURATION:-disabled}" \
        "soak_nodes=${VPNCTL_SOAK_NODES:-}" \
        "soak_phase_interval=${VPNCTL_SOAK_PHASE_INTERVAL:-}"
    if [[ -n "$work_dir" ]]; then findmnt -T "$work_dir" -o TARGET,SOURCE,FSTYPE,OPTIONS; fi
    sha256sum "$build_dir/vpnctl" "$build_dir/integration.test"
    docker image inspect "$image_id" --format 'image_id={{.Id}}'
    printf 'test_argument=%s\n' "$@"
} > "$manifest"
echo "Network test results: $artifact_dir"
docker run "${docker_limits[@]}" --rm --init --entrypoint /bin/sh --name "$container_name" --network none \
    --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
    --mount "type=bind,src=$build_dir,dst=/test,readonly" \
    --mount "type=bind,src=$artifact_dir,dst=/results" \
    "${work_mount[@]}" \
    -e VPNCTL_INTEGRATION=1 -e VPNCTL_BIN=/test/vpnctl \
    -e VPNCTL_ARTIFACT_DIR=/results -e VPNCTL_NETNS_SIZES="${VPNCTL_NETNS_SIZES:-1,3,8,32}" \
    -e VPNCTL_SOAK_DURATION="${VPNCTL_SOAK_DURATION:-}" -e VPNCTL_SOAK_NODES="${VPNCTL_SOAK_NODES:-}" \
    -e VPNCTL_SOAK_PHASE_INTERVAL="${VPNCTL_SOAK_PHASE_INTERVAL:-}" \
    -e GORACE=atexit_sleep_ms=0 -e VPNCTL_RESULT_UID="$(id -u)" -e VPNCTL_RESULT_GID="$(id -g)" \
    "$image_id" -c 'status=0; /test/integration.test "$@" || status=$?; chown -R "$VPNCTL_RESULT_UID:$VPNCTL_RESULT_GID" /results; if [ -d /work ]; then chown -R "$VPNCTL_RESULT_UID:$VPNCTL_RESULT_GID" /work; fi; exit "$status"' \
    sh -test.v -test.timeout=15m "$@" &
docker_pid=$!
wait "$docker_pid"
