#!/usr/bin/env bash
# Controller placement and independent control/data-plane faults, container only.
set -euo pipefail
export VPNCTL_RACE=${VPNCTL_RACE:-0}
export VPNCTL_TEST_CPUS=${VPNCTL_TEST_CPUS:-2}
export VPNCTL_TEST_MEMORY=${VPNCTL_TEST_MEMORY:-2g}
exec "$(dirname "${BASH_SOURCE[0]}")/test-netns.sh" \
    -test.run='^TestNetns_M3ControlIsolation$' -test.timeout=6m "$@"
