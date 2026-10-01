#!/usr/bin/env python3
"""Build an offline guest disk as an ordinary file; no mount/loop/host devices."""
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

root, out = Path('/guest-root'), Path('/out')
out.mkdir(exist_ok=True)
# COPY from a Docker build stage also includes its container marker and /run.
# A real guest must not misidentify itself as that build container.
assert not (root / '.dockerenv').exists() and not list((root / 'run').iterdir())
(root / 'etc/hostname').write_text('vpnctl-vm\n')
(root / 'etc/hosts').write_text('127.0.0.1 localhost\n127.0.1.1 vpnctl-vm\n')
(root / 'etc/machine-id').write_text('')
for name in ('vpnctl', 'integration.test', 'vpnctl-legacy', 'vpnctl-lease-v1'):
    shutil.copyfile('/input/' + name, root / 'opt/vpnctl-vm' / name)
    (root / 'opt/vpnctl-vm' / name).chmod(0o755)
kernels = sorted((root / 'boot').glob('vmlinuz-*'))
if len(kernels) != 1:
    raise SystemExit('exactly one guest kernel required')
kernel = kernels[0]
shutil.copyfile(kernel, out / 'vmlinuz')
shutil.copyfile(root / 'boot' / ('initrd.img-' + kernel.name.removeprefix('vmlinuz-')), out / 'initrd')
raw = out / 'guest.raw'
with raw.open('wb') as f:
    f.truncate(4 * 1024**3)
subprocess.run(['mkfs.ext4', '-q', '-F', '-L', 'vpnctl-vm', '-d', str(root), str(raw)], check=True)
subprocess.run(['qemu-img', 'convert', '-f', 'raw', '-O', 'qcow2', str(raw), str(out / 'guest.qcow2')], check=True)
raw.unlink()
def digest(p):
    with p.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()
(out / 'image.json').write_text(json.dumps({'kernel': kernel.name,
    'sha256': {n: digest(out / n) for n in ('vmlinuz', 'initrd', 'guest.qcow2')},
    'binaries': {n: digest(root / 'opt/vpnctl-vm' / n) for n in ('vpnctl', 'integration.test', 'vpnctl-legacy', 'vpnctl-lease-v1')}}, indent=2) + '\n')
