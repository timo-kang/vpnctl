#!/usr/bin/env bash
# Static, manually selected candidate paths inside the disposable network lab.
set -euo pipefail
export VPNCTL_TEST_CPUS=${VPNCTL_TEST_CPUS:-2}
export VPNCTL_TEST_MEMORY=${VPNCTL_TEST_MEMORY:-2g}
exec "$(dirname "${BASH_SOURCE[0]}")/test-netns.sh" \
    -test.run='^TestNetns_M3PathTopology$' -test.timeout=5m "$@"
