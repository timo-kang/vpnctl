"""Existing private-evidence guards reused by the disposable validation runner."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def read_command(args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True, stderr=subprocess.PIPE).strip()

def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)

def checked_source(path, source):
    return (read_command(['git', 'rev-parse', 'HEAD'], path) == source
            and not read_command(['git', 'status', '--porcelain'], path))

def work_directories():
    return {str(path): (path.stat().st_dev, path.stat().st_ino)
            for path in Path('/tmp').glob('vpnctl-vm.*') if path.is_dir() and not path.is_symlink()}

def require_disposable_runner():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.environ.get('GITHUB_RUN_ATTEMPT') != '1'):
        raise RuntimeError('fresh_disposable_GitHub_runner_required')

def kvm_snapshot():
    started = time.monotonic_ns()
    info = Path('/dev/kvm').stat()
    acl = read_command(['getfacl', '-cp', '/dev/kvm'])
    readable = os.access('/dev/kvm', os.R_OK)
    writable = os.access('/dev/kvm', os.W_OK)
    return {'started_monotonic_ns': started, 'finished_monotonic_ns': time.monotonic_ns(),
            'character_device': stat.S_ISCHR(info.st_mode),
            'device': info.st_dev, 'inode': info.st_ino, 'rdev': info.st_rdev,
            'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid,
            'readable': readable, 'writable': writable,
            'acl': acl}

def prepare_kvm(destination):
    # Only the disposable CI runner, immediately before each planned invocation.
    # A lost ACL never causes a retry or alteration of an already-started test.
    require_disposable_runner()
    before = kvm_snapshot()
    record = {'before': before, 'refreshed': False}
    write_json(destination / 'kvm-access.json', record)
    if not before['character_device']:
        raise RuntimeError('KVM_character_device_required')
    if not before['readable'] or not before['writable']:
        record['refreshed'] = True
        write_json(destination / 'kvm-access.json', record)
        subprocess.run(['sudo', '-n', 'setfacl', '-m', f'u:{os.getuid()}:rw', '/dev/kvm'],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    after = kvm_snapshot()
    record['prepared'] = after
    write_json(destination / 'kvm-access.json', record)
    if (not after['character_device'] or not after['readable'] or not after['writable']
            or any(before[k] != after[k] for k in ('device', 'inode', 'rdev'))):
        raise RuntimeError('KVM_access_not_established')
