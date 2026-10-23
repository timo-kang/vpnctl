"""Only the bounded, non-root, capability-free VM observer may export disks."""
import hashlib
import os
from pathlib import Path
import socket


def digest(path):
    with Path(path).open('rb') as data:
        return hashlib.file_digest(data, 'sha256').hexdigest()


def outer_guard():
    if (os.geteuid() == 0 or not Path('/.dockerenv').exists() or
        {name for _, name in socket.if_nameindex()} != {'lo'} or
        'CapEff:\t0000000000000000' not in Path('/proc/self/status').read_text() or
        Path('/sys/fs/cgroup/cpu.max').read_text().split() != ['200000', '100000'] or
        Path('/sys/fs/cgroup/memory.max').read_text().strip() != str(2*1024**3) or
        Path('/sys/fs/cgroup/memory.swap.max').read_text().strip() != '0'):
        raise RuntimeError('bounded non-root isolated two-CPU container required')
