#!/usr/bin/env python3
"""Encrypt an explicit allowlist; never export mutable guest overlays or caches."""
import os
from pathlib import Path
import subprocess
import tarfile

from identical_image import BUNDLE_FILES, safe_file

MAX_BYTES = 12*1024**3
ROOT_FILES = ('bundle-manifest.json', 'host-before-preparation.json', 'host-after-preparation.json',
              'controller.log', 'runtime-build.log', 'runtime-id', 'builder-pull.log', 'compile.log', 'image.log')
RUN_FILES = ('host-before.json', 'host-after.json', 'pressure-before.json', 'pressure-after.json',
             'invocation.json', 'exit.json', 'run.log')
RECIPIENT = '50EF899B5D724D3699E3693312C4542EC99F48DA'


def members(root):
    names = [n for n in ROOT_FILES if (root/n).exists()]
    names += ['bundle/'+n for n in BUNDLE_FILES if (root/'bundle'/n).exists()]
    runs = root/'runs-ci'
    if runs.exists():
        names += ['runs-ci/'+n for n in ('host-initial.json', 'complete.json') if (runs/n).exists()]
        for cell in ('01', '02', '03', '04'):
            names += ['runs-ci/'+cell+'/'+n for n in RUN_FILES if (runs/cell/n).exists()]
            results = runs/cell/'results'
            if results.is_symlink():
                raise ValueError('symlink results directory')
            if results.exists():
                for path in results.rglob('*'):
                    if path.is_symlink() or not (path.is_dir() or path.is_file()):
                        raise ValueError('nonregular result')
                    if path.is_file():
                        names.append(path.relative_to(root).as_posix())
    names = sorted(names)
    if not names or len(names) > 20000:
        raise ValueError('empty or excessive evidence inventory')
    size = sum(safe_file(root, n).stat().st_size for n in names)
    if size > MAX_BYTES:
        raise ValueError('evidence exceeds fixed 12 GiB archive bound')
    return names


def encrypt(root, target, key, keyring):
    names = members(root)
    if target.exists() or target.with_suffix('.partial').exists():
        raise FileExistsError('never overwrite ciphertext')
    keyring.mkdir(mode=0o700)
    log_path = root/'encryption.log'
    partial = target.with_suffix('.partial')
    with log_path.open('xb') as log:
        subprocess.run(['gpg', '--homedir', str(keyring), '--batch', '--import', str(key)],
                       stdout=log, stderr=log, check=True)
        proc = subprocess.Popen(['gpg', '--homedir', str(keyring), '--batch', '--trust-model', 'always',
            '--recipient', RECIPIENT, '--compress-algo', 'zlib', '--cipher-algo', 'AES256',
            '--output', str(partial), '--encrypt'], stdin=subprocess.PIPE, stdout=log, stderr=log)
        try:
            with tarfile.open(fileobj=proc.stdin, mode='w|') as archive:
                for name in names:
                    path = safe_file(root, name)
                    # gettarinfo also rejects file-type changes between inventory and streaming.
                    info = archive.gettarinfo(str(path), arcname=name)
                    if not info.isfile():
                        raise ValueError('nonregular archive entry')
                    info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    info.mode = 0o600
                    with path.open('rb') as data:
                        archive.addfile(info, data)
            proc.stdin.close()
            if proc.wait(timeout=1200) != 0:
                raise RuntimeError('encryption failed')
        except BaseException:
            proc.kill(); proc.wait()
            raise
    partial.rename(target)


if __name__ == '__main__':
    os.umask(0o077)
    root = Path(os.environ['VPNCTL_IDENTICAL_ROOT'])
    encrypt(root, Path(os.environ['RUNNER_TEMP'])/'vpnctl-identical.tar.gpg',
            Path(__file__).with_name('evidence-public-key.asc'), Path(os.environ['RUNNER_TEMP'])/'vpnctl-identical-keyring')
