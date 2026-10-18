"""Bounded private profiler transport; unavailable diagnostics never waive a gate."""
import base64
import hashlib
import os
import re
import stat

PROFILE_DIRECTORY = 'selector-profile-app2'
PROFILE_LIMIT = 256 * 1024
PROFILE_FILES = {'ready.json': 16384, 'result.json': 16384,
                 'cpu.pprof': PROFILE_LIMIT, 'allocs-before.pprof': PROFILE_LIMIT,
                 'allocs-after.pprof': PROFILE_LIMIT}


def selector_profile_env(request):
    value = request.get('selector_profile', False)
    if type(value) is not bool:
        raise ValueError('selector profile must be boolean')
    # Do not let an inherited producer path activate all worker descendants.
    return {'VPNCTL_CAPACITY_SELECTOR_PROFILE': '1' if value else '0',
            'VPNCTL_SELECTOR_PROFILE_DIR': ''}


def read_profile(root, fixture, name):
    if (not re.fullmatch(r'[A-Za-z0-9_.-]{1,200}', fixture) or fixture in ('.', '..')
            or name not in PROFILE_FILES):
        raise ValueError('invalid profile identity')
    # Pin every directory component below the known results root. Symlinks,
    # replaced paths, devices and FIFOs must never export unrelated data/block.
    fds = []
    try:
        fds.append(os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        for part in (fixture, PROFILE_DIRECTORY):
            fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1]))
        fds.append(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1]))
        info = os.fstat(fds[-1])
        if not stat.S_ISREG(info.st_mode) or info.st_size > PROFILE_FILES[name]:
            raise ValueError('profile type or byte limit')
        with os.fdopen(fds[-1], 'rb', closefd=False) as stream:
            raw = stream.read(PROFILE_FILES[name] + 1)
        if len(raw) > PROFILE_FILES[name]:
            raise ValueError('profile byte limit')
        return raw
    finally:
        for fd in reversed(fds):
            os.close(fd)


def collect_profiles(root, fixture):
    files, errors = {}, {}
    for name in PROFILE_FILES:
        try:
            raw = read_profile(root, fixture, name)
            files[name] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                           'base64': base64.b64encode(raw).decode('ascii')}
        except (OSError, ValueError):
            errors[name] = 'unavailable'
    return {'encoding': 'base64', 'files': files, 'errors': errors}
