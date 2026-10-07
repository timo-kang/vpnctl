#!/usr/bin/env bash
# All manager/route changes occur only in the identity-guarded disposable guest.
set -euo pipefail
export VPNCTL_VM_MANAGERS=1
if [[ $# == 0 ]]; then set -- --case manager-auto-4 manager-auto-8; fi
exec "$(dirname "${BASH_SOURCE[0]}")/test-vm.sh" "$@"
