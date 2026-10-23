"""Encrypt only bounded diagnostic outputs; exclude guest images and build checkouts."""
import os
from pathlib import Path
import subprocess
import tarfile

RECIPIENT = '50EF899B5D724D3699E3693312C4542EC99F48DA'
ROOT_FILES = ('controller.log', 'protocol.json', 'product.json', 'product-build-info.txt', 'image-id', 'complete.json', 'diagnostic-inputs.json')


def safe_file(root, name):
    path = root / name
    if not path.is_file() or path.resolve() != path.absolute() or path.stat().st_nlink != 1:
        raise ValueError('regular non-linked evidence required')
    return path


def members(root):
    names = [name for name in ROOT_FILES if (root / name).exists()]
    for index in range(1, 5):
        cell = root / 'runs' / f'{index:02}'
        if not cell.exists():
            continue
        for path in cell.rglob('*'):
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                raise ValueError('nonregular evidence entry')
            if path.is_file():
                names.append(path.relative_to(root).as_posix())
    if not names or len(names) > 20000:
        raise ValueError('empty or excessive evidence inventory')
    if sum(safe_file(root, name).stat().st_size for name in names) > 1024**3:
        raise ValueError('evidence exceeds 1 GiB bound')
    return sorted(names)


def encrypt(root, target, key, keyring):
    names = members(root)
    partial = target.with_suffix('.partial')
    if target.exists() or partial.exists():
        raise FileExistsError('never overwrite ciphertext')
    keyring.mkdir(mode=0o700)
    with (root / 'encryption.log').open('xb') as log:
        subprocess.run(['gpg', '--homedir', str(keyring), '--batch', '--import', str(key)],
                       stdout=log, stderr=log, check=True)
        proc = subprocess.Popen(['gpg', '--homedir', str(keyring), '--batch', '--trust-model', 'always',
            '--recipient', RECIPIENT, '--compress-algo', 'zlib', '--cipher-algo', 'AES256',
            '--output', str(partial), '--encrypt'], stdin=subprocess.PIPE, stdout=log, stderr=log)
        try:
            with tarfile.open(fileobj=proc.stdin, mode='w|') as archive:
                for name in names:
                    path = safe_file(root, name)
                    info = archive.gettarinfo(str(path), arcname=name)
                    if not info.isfile():
                        raise ValueError('nonregular archive entry')
                    info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    info.mode = 0o600
                    with path.open('rb') as data:
                        archive.addfile(info, data)
            proc.stdin.close()
            if proc.wait(timeout=120) != 0:
                raise RuntimeError('encryption failed')
        except BaseException:
            proc.kill()
            proc.wait()
            raise
    partial.rename(target)


if __name__ == '__main__':
    os.umask(0o077)
    encrypt(Path(os.environ['VPNCTL_TRACE_ROOT']), Path(os.environ['RUNNER_TEMP']) / 'vpnctl-trace.tar.gpg',
            Path(__file__).with_name('evidence-public-key.asc'), Path(os.environ['RUNNER_TEMP']) / 'vpnctl-trace-keyring')
