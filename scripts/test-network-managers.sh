#!/usr/bin/env bash
# Actual managers run ONLY inside the identity-guarded disposable guest.
set -euo pipefail
export VPNCTL_VM_MANAGERS=1
exec "$(dirname "${BASH_SOURCE[0]}")/test-vm.sh" --case managers "$@"
