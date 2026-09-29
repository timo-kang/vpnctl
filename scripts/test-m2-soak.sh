#!/usr/bin/env bash
# Persistent real producers in the isolated lab; no deployment credentials used.
set -euo pipefail
export VPNCTL_SOAK_PROFILE=${VPNCTL_SOAK_PROFILE:-auto}
export VPNCTL_SOAK_DURATION=${VPNCTL_SOAK_DURATION:-24h}
export VPNCTL_SOAK_NODES=${VPNCTL_SOAK_NODES:-8}
export VPNCTL_SOAK_PHASE_INTERVAL=${VPNCTL_SOAK_PHASE_INTERVAL:-1h}
export VPNCTL_RACE=${VPNCTL_RACE:-0}
export VPNCTL_TEST_CPUS=${VPNCTL_TEST_CPUS:-2}
export VPNCTL_TEST_MEMORY=${VPNCTL_TEST_MEMORY:-2g}
export VPNCTL_TEST_WORK_ROOT=${VPNCTL_TEST_WORK_ROOT:-/tmp}
# Require Go's explicit duration syntax; the integration test validates bounds.
# The timeout includes provisioning, all requested wall time, final drain/check.
exec "$(dirname "${BASH_SOURCE[0]}")/test-netns.sh" \
    -test.run='^TestNetns_M2Soak$' -test.timeout=170h "$@"
