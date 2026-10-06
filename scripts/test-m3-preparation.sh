#!/usr/bin/env bash
# Durable preparation and incremental rebuilding in owned disposable namespaces.
set -euo pipefail
export VPNCTL_RACE=${VPNCTL_RACE:-0}
export VPNCTL_TEST_CPUS=${VPNCTL_TEST_CPUS:-2}
export VPNCTL_TEST_MEMORY=${VPNCTL_TEST_MEMORY:-2g}
exec "$(dirname "${BASH_SOURCE[0]}")/test-netns.sh" \
    -test.run='^TestNetns_M3Preparation' -test.timeout=15m "$@"
