#!/usr/bin/env bash
set -euo pipefail
umask 077
root=${VPNCTL_MATCHED_ROOT:?}
keyring="$RUNNER_TEMP/vpnctl-matched-public-keyring"
install -d -m 700 "$keyring"
gpg --homedir "$keyring" --batch --import scripts/ci/evidence-public-key.asc > "$root/encryption.log" 2>&1
# Only selected evidence paths: exclude source worktrees and VM disks.
python3 - "$root" "$root/evidence.tar" <<'PY'
from pathlib import Path
import sys, tarfile
root, target = map(Path, sys.argv[1:])
def regular_evidence(info):
    if not (info.isfile() or info.isdir()):
        raise ValueError('non-regular evidence member')
    return info
with tarfile.open(target, 'w') as archive:
    for path in sorted(root.iterdir()):
        if path == target:
            continue
        if path.is_dir() and not (path.name == 'binaries' or path.name.startswith('run-')):
            continue
        if path.is_symlink():
            raise SystemExit('refusing evidence symlink')
        archive.add(path, arcname=path.name, filter=regular_evidence)
PY
gpg --homedir "$keyring" --batch --trust-model always --recipient 073ACEF2026645A0D5CA33767D38E9FD0E4A0A8F \
  --compress-algo zlib --cipher-algo AES256 --output "$root/evidence.tar.gpg.partial" \
  --encrypt "$root/evidence.tar" >> "$root/encryption.log" 2>&1

mv -- "$root/evidence.tar.gpg.partial" "$RUNNER_TEMP/vpnctl-matched-evidence.tar.gpg"
rm -- "$root/evidence.tar"
