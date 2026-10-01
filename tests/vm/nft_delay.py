#!/usr/bin/python3
"""Guest-only fault injector: hold a real renewal before its nft commit."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

args = dict(s.split('=', 1) if '=' in s else (s, '') for s in Path('/proc/cmdline').read_text().split())
if 'vpnctl_vm_test' not in args or args.get('vpnctl_host_boot') == Path('/proc/sys/kernel/random/boot_id').read_text().strip():
    raise SystemExit('disposable guest required')
real = '/usr/sbin/nft'
if sys.argv[1:] != ['-f', '/dev/stdin']:
    os.execv(real, [real] + sys.argv[1:])
script = sys.stdin.buffer.read(512 * 1024 + 1)
if len(script) > 512 * 1024:
    raise SystemExit('oversized nft input')
directory = Path(os.environ['VPNCTL_VM_NFT_DELAY'])
if b'add element inet vl' in script and not (directory / 'ready.json').exists():
    parent = os.getppid()
    if Path('/proc/' + str(parent) + '/exe').resolve() != Path('/opt/vpnctl-vm/vpnctl'):
        raise SystemExit('unexpected supervisor parent')
    os.kill(parent, signal.SIGSTOP)
    (directory / 'ready.json').write_text(json.dumps({'parent': parent, 'prepared_monotonic_ns': time.monotonic_ns(), 'script': script.decode()}))
    until = time.monotonic() + 60
    while not (directory / 'release').exists():
        if time.monotonic() > until:
            raise SystemExit('injection release timeout')
        time.sleep(0.02)
    p = subprocess.run([real] + sys.argv[1:], input=script)
    (directory / 'done.json').write_text(json.dumps({'exit': p.returncode, 'committed_monotonic_ns': time.monotonic_ns()}))
    raise SystemExit(p.returncode)
p = subprocess.run([real] + sys.argv[1:], input=script)
raise SystemExit(p.returncode)
