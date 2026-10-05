#!/usr/bin/env bash
# Node approval lifetime, real TCP and process faults inside an owned container.
set -euo pipefail
export VPNCTL_RACE=${VPNCTL_RACE:-0}
export VPNCTL_TEST_CPUS=${VPNCTL_TEST_CPUS:-2}
export VPNCTL_TEST_MEMORY=${VPNCTL_TEST_MEMORY:-2g}
exec "$(dirname "${BASH_SOURCE[0]}")/test-netns.sh" \
    -test.run='^TestNetns_M3Node(Lease|LeasePressure|ApprovalExpiry|LeaseForeignState|LeaseCrash|ApprovalRevoked)$' -test.timeout=15m "$@"
