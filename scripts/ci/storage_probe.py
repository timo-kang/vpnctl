"""Read metadata only for the actual opened cache directory and state file."""
import json
import os
from pathlib import Path
import stat
import sys
import time


def bounded_read(path, limit):
    with open(path, 'rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('metadata size limit')
    return raw.decode('utf-8', errors='strict')


def mount_record(fdinfo, mountinfo):
    ids = [int(line.split(':', 1)[1].strip()) for line in fdinfo.splitlines() if line.startswith('mnt_id:')]
    if len(ids) != 1 or ids[0] <= 0:
        raise ValueError('mount identity missing or ambiguous')
    rows = []
    for line in mountinfo.splitlines():
        fields = line.split()
        if fields and fields[0] == str(ids[0]):
            sep = fields.index('-')
            if sep < 6 or len(fields) != sep + 4:
                raise ValueError('invalid mount record')
            rows.append({'mount_id': ids[0], 'device': fields[2], 'root': fields[3],
                         'target': fields[4], 'options': fields[5],
                         'filesystem': fields[sep + 1], 'source': fields[sep + 2],
                         'super_options': fields[sep + 3]})
    if len(rows) != 1:
        raise ValueError('mount record missing or ambiguous')
    return rows[0]


def fd_metadata(fd):
    info = os.fstat(fd)
    mount = mount_record(bounded_read('/proc/self/fdinfo/' + str(fd), 65536),
                         bounded_read('/proc/self/mountinfo', 32 * 1024**2))
    device = str(os.major(info.st_dev)) + ':' + str(os.minor(info.st_dev))
    if mount['device'] != device:
        raise ValueError('mount device differs from opened object')
    vfs = os.fstatvfs(fd)
    return {'mount': mount, 'device': device, 'inode': info.st_ino,
            'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid,
            'block_size': vfs.f_bsize, 'fragment_size': vfs.f_frsize,
            'total_blocks': vfs.f_blocks, 'available_blocks': vfs.f_bavail,
            'filesystem_id': vfs.f_fsid}


def inspect_path(path):
    # Opening descriptors pins the measured objects. Neither object is read or
    # written; mount identity comes from the descriptor, not longest path match.
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        state = os.open('state.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
        try:
            if not stat.S_ISREG(os.fstat(state).st_mode):
                raise ValueError('state is not a regular file')
            d, s = fd_metadata(directory), fd_metadata(state)
            return {'available': True, 'directory': d, 'state': s,
                    'same_mount': d['mount']['mount_id'] == s['mount']['mount_id']}
        finally:
            os.close(state)
    finally:
        os.close(directory)


if __name__ == '__main__':
    start = time.monotonic_ns()
    wall = time.time_ns()
    try:
        result = inspect_path(sys.argv[1])
    except (OSError, ValueError, UnicodeError) as error:
        result = {'available': False, 'error_class': type(error).__name__}
    result.update(started_monotonic_ns=start, finished_monotonic_ns=time.monotonic_ns(),
                  started_wall_ns=wall, finished_wall_ns=time.time_ns())
    print(json.dumps(result))
