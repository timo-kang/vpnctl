#!/usr/bin/env python3
"""Test-only guest control. Never invoke this agent on a shared host."""
import json
import hashlib
import errno
import signal
import os
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path('/var/lib/vpnctl-vm')
ARGS = dict(s.split('=', 1) if '=' in s else (s, '') for s in Path('/proc/cmdline').read_text().split())
TOKEN = ARGS.get('vpnctl_vm_token', '')
WORKER = None
LOCK = threading.Lock()

def guard():
    if 'vpnctl_vm_test' not in ARGS or len(TOKEN) != 32:
        raise RuntimeError('not an explicitly provisioned disposable VM')
    host = ARGS.get('vpnctl_host_boot', '')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    product = Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()
    if not host or host == boot or product != ARGS.get('vpnctl_vm_uuid'):
        raise RuntimeError('VM isolation identity mismatch')

@lru_cache(maxsize=1)
def binary_hashes():
    result = {}
    for name in ('vpnctl', 'integration.test', 'vpnctl-legacy'):
        with (Path('/opt/vpnctl-vm') / name).open('rb') as f:
            result[name] = hashlib.file_digest(f, 'sha256').hexdigest()
    return result

def health():
    guard()
    return {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'wall_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns(),
            'boottime_ns': time.clock_gettime_ns(time.CLOCK_BOOTTIME),
            'kernel': os.uname().release, 'binaries': binary_hashes(),
            'power_states': Path('/sys/power/state').read_text().strip(),
            'mem_sleep': Path('/sys/power/mem_sleep').read_text().strip(),
            'systemd': subprocess.check_output(['systemd', '--version'], text=True).splitlines()[0],
            'nft': subprocess.check_output(['nft', '--version'], text=True).strip()}

def domain_check(replace_namespace=False):
    """Old boot's journal must not adopt/remove an identically named foreign link."""
    guard()
    meta = json.loads((ROOT / 'fixture.json').read_text())
    if not replace_namespace and meta['boot_id'] == health()['boot_id']:
        raise RuntimeError('domain check requires an actual new guest boot')
    outcomes = []
    for r in meta['recipients']:
        cache = Path(r['cache'])
        if not cache.is_relative_to(ROOT / 'work'):
            raise RuntimeError('unexpected private cache path')
        journal = cache / 'peers.json'
        before_journal = journal.read_bytes()
        if replace_namespace:
            subprocess.run(['ip', 'netns', 'del', r['namespace']], check=True)
        subprocess.run(['ip', 'netns', 'add', r['namespace']], check=True)
        prefix = ['ip', 'netns', 'exec', r['namespace']]
        for endpoint in r['endpoints']:
            iface = endpoint['interface']
            subprocess.run(prefix + ['ip', 'link', 'add', iface, 'type', 'dummy'], check=True)
            subprocess.run(prefix + ['ip', 'link', 'set', iface, 'alias', 'vm-foreign-resource'], check=True)
        def links():
            return subprocess.check_output(prefix + ['ip', '-j', 'link', 'show'], text=True)
        before_links = links()
        observed = []
        commands = [('inspect', []), ('recover', [])] + [('release', ['--endpoint-id', e['endpoint_id']]) for e in r['endpoints']]
        for action, extra in commands:
            p = subprocess.run(prefix + ['/opt/vpnctl-vm/vpnctl', 'relay', action, '--config', r['config'],
                                        '--relay-id', r['relay'], '--cache-dir', r['cache']] + extra,
                               capture_output=True, text=True, timeout=10)
            if p.returncode == 0 or 'kernel domain mismatch' not in p.stderr:
                raise RuntimeError('old journal accepted or wrong rejection: ' + action + ': ' + p.stderr[:2048])
            observed.append({'action': action, 'exit': p.returncode, 'reason': p.stderr.strip()})
        if links() != before_links or journal.read_bytes() != before_journal:
            raise RuntimeError('foreign resources or old journal changed')
        outcomes.append({'relay': r['relay'], 'old_journal_sha256': hashlib.sha256(before_journal).hexdigest(),
                         'foreign_links_unchanged': True, 'rejections': observed})
    return {'old_boot': meta['boot_id'], 'new_boot': health()['boot_id'], 'recipients': outcomes}

def validate_fsync_evidence(kind, trace, error):
    injected = [e for e in trace.get('events', []) if e.get('injected') and e.get('returned_errno') == errno.EIO]
    if not trace.get('injected') or trace.get('exit', 0) <= 0 or len(injected) != 1:
        raise RuntimeError('target fsync EIO was not exercised')
    row = injected[0]
    if kind == 'fsync' and not Path(row['path']).name.startswith('.pending-'):
        raise RuntimeError('fsync did not fail the newly written temporary file')
    if kind == 'fsync-dir' and (not row.get('after_rename') or 'file replaced but directory sync failed' not in error):
        raise RuntimeError('directory fsync did not fail after rename')

def storage_fault(kind):
    guard()
    if kind not in ('enospc', 'rename', 'fsync', 'fsync-dir'):
        raise ValueError('invalid storage fault')
    meta = json.loads((ROOT / 'fixture.json').read_text())
    evidence = {'kind': kind, 'recipients': []}
    if kind == 'enospc':
        if os.stat(ROOT / 'work').st_dev != os.stat('/dev/vdb').st_rdev or os.statvfs(ROOT / 'work').f_blocks * os.statvfs(ROOT / 'work').f_frsize > 64 * 1024**2:
            raise RuntimeError('ENOSPC requires the dedicated small guest state filesystem')
        # ext4's internal 2% reserve otherwise leaves space available to the
        # small atomic cache write after the large filler reports ENOSPC.
        reserved = Path('/sys/fs/ext4/vdb/reserved_clusters')
        evidence['reserved_clusters_before'] = int(reserved.read_text())
        reserved.write_text('0')
        size = 0
        block = os.statvfs(ROOT / 'work').f_frsize
        # Synchronous block-sized writes avoid delayed-allocation/preallocation
        # releasing enough space at close for the small atomic cache rewrite.
        fd = os.open(ROOT / 'work/enospc-fill', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_SYNC, 0o600)
        with os.fdopen(fd, 'wb', buffering=0) as f:
            try:
                for _ in range(64 * 1024**2 // block):
                    size += f.write(b'x' * block)
            except OSError as e:
                if e.errno != errno.ENOSPC:
                    raise
                evidence['errno'] = e.errno
        if evidence.get('errno') != errno.ENOSPC:
            raise RuntimeError('state filesystem did not fill within bound')
        evidence['written_bytes'] = size
        evidence['free_blocks'] = os.statvfs(ROOT / 'work').f_bfree
        if evidence['free_blocks'] != 0:
            raise RuntimeError('ENOSPC filler left allocatable filesystem blocks: ' + str(evidence))
    for r in meta['recipients']:
        command = ['ip', 'netns', 'exec', r['namespace']]
        trace = ROOT / ('fault-' + r['relay'] + '.trace')
        if kind.startswith('fsync'):
            command += ['python3', '/opt/vpnctl-vm/fsync_fault.py', kind, r['cache'], str(trace)]
        elif kind == 'rename':
            command += ['strace', '-f', '-qq', '-yy', '-o', str(trace), '-e', 'trace=rename,renameat,renameat2',
                        '-e', 'inject=rename,renameat,renameat2:error=EIO:when=1']
        command += ['/opt/vpnctl-vm/vpnctl', 'relay', 'refresh', '--config', r['config'], '--relay-id', r['relay'], '--cache-dir', r['cache']]
        p = subprocess.run(command, capture_output=True, text=True, timeout=15)
        if p.returncode == 0:
            raise RuntimeError('storage fault did not fail refresh')
        row = {'relay': r['relay'], 'exit': p.returncode, 'error': p.stderr[-2048:]}
        if kind.startswith('fsync'):
            row['syscalls'] = json.loads(trace.read_text())
            validate_fsync_evidence(kind, row['syscalls'], p.stderr)
        elif kind == 'rename':
            row['injected_syscalls'] = [line for line in trace.read_text().splitlines() if '(INJECTED)' in line]
            if not row['injected_syscalls']:
                raise RuntimeError('rename injection was not exercised')
        evidence['recipients'].append(row)
    return evidence

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        global WORKER
        try:
            guard()
            if self.headers.get('Authorization') != 'Bearer ' + TOKEN:
                self.send_error(403)
                return
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 <= size <= 16384:
                raise ValueError('request size')
            req = json.loads(self.rfile.read(size) or b'{}')
            action = self.path.removeprefix('/')
            later = None
            if action == 'health':
                result = health()
            elif action == 'probes':
                jobs = req.get('probes')
                if not isinstance(jobs, list) or not 1 <= len(jobs) <= 8:
                    raise ValueError('one to eight probe requests required')
                def probe(job):
                    with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:18081/probe', data=json.dumps(job).encode()), timeout=2) as r:
                        return json.load(r)
                with ThreadPoolExecutor(max_workers=8) as pool:
                    result = list(pool.map(probe, jobs))
            elif action == 'start':
                with LOCK:
                    if WORKER is not None and WORKER.poll() is None:
                        raise RuntimeError('fixture already running')
                    env = dict(os.environ, VPNCTL_VM_WORKER='1', VPNCTL_INTEGRATION='1',
                               VPNCTL_BIN='/opt/vpnctl-vm/vpnctl', VPNCTL_ARTIFACT_DIR=str(ROOT / 'results'),
                               TMPDIR=str(ROOT / 'work'))
                    with (ROOT / 'worker.log').open('wb') as log:
                        WORKER = subprocess.Popen(['/opt/vpnctl-vm/integration.test', '-test.run=^TestVMWorker$', '-test.v', '-test.timeout=0'],
                                                  env=env, stdout=log, stderr=log, start_new_session=True)
                result = {'started': True}
            elif action.startswith('fixture/'):
                url = 'http://127.0.0.1:18081/' + action.removeprefix('fixture/')
                data = json.dumps(req).encode()
                with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=40) as r:
                    result = json.load(r)
            elif action == 'clock':
                before = health()
                if 'delta' in req:
                    delta = float(req['delta'])
                    if abs(delta) > 3600:
                        raise ValueError('clock delta limit')
                    target = time.time() + delta
                else:
                    target = float(req['unix_ns']) / 1e9
                time.clock_settime(time.CLOCK_REALTIME, target)
                result = {'before': before, 'after': health()}
            elif action in ('reboot', 'suspend'):
                if action == 'suspend' and 'deep' not in Path('/sys/power/mem_sleep').read_text().split():
                    if '[deep]' not in Path('/sys/power/mem_sleep').read_text():
                        raise RuntimeError('guest S3/deep unsupported')
                result = {'accepted': action, 'before': health()}
                def power():
                    guard()
                    if action == 'suspend':
                        Path('/sys/power/mem_sleep').write_text('deep')
                    subprocess.run(['systemctl', action], check=True, timeout=60)
                later = power
            elif action == 'diagnostics':
                # No config/cache/private key export and no arbitrary command RPC.
                raw = (ROOT / 'worker.log').read_text(errors='replace')[-32768:] if (ROOT / 'worker.log').exists() else ''
                safe = '\n'.join('[redacted]' if any(x in line.lower() for x in ('token', 'private', 'key', 'credential')) else line for line in raw.splitlines())
                result = {'health': health(), 'worker_exit': WORKER.poll() if WORKER else None, 'worker_log': safe}
            elif action == 'domain':
                result = domain_check()
            elif action == 'namespace':
                if WORKER is None or WORKER.poll() is not None:
                    raise RuntimeError('owned fixture worker required')
                os.killpg(WORKER.pid, signal.SIGKILL)
                WORKER.wait(5)
                result = domain_check(replace_namespace=True)
            elif action == 'storage-fault':
                result = storage_fault(req['kind'])
            elif action == 'clear-storage-fault':
                (ROOT / 'work/enospc-fill').unlink(missing_ok=True)
                result = {'removed_own_filler': True}
            else:
                raise ValueError('unsupported action')
            data = json.dumps(result).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            if later:
                threading.Timer(0.2, later).start()
        except Exception as e:
            data = json.dumps({'error': str(e)}).encode()
            try:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

class ControlServer(ThreadingHTTPServer):
    # Eight simultaneous path/stream probes must not overflow HTTPServer's
    # default listen backlog of five and become false dataplane failures.
    request_queue_size = 64

if __name__ == '__main__':
    guard()
    subprocess.run(['modprobe', 'virtio_net'], check=True)
    interfaces = [p.name for p in Path('/sys/class/net').iterdir() if p.name != 'lo']
    if len(interfaces) != 1:
        raise RuntimeError('expected exactly one guest management NIC: ' + str(interfaces))
    subprocess.run(['ip', 'link', 'set', interfaces[0], 'up'], check=True)
    subprocess.run(['ip', 'addr', 'replace', '10.0.2.15/24', 'dev', interfaces[0]], check=True)
    subprocess.run(['ip', 'route', 'replace', 'default', 'via', '10.0.2.2'], check=True)
    ROOT.mkdir(exist_ok=True)
    # This is the VM's second virtual disk, never a host block device.
    if Path('/sys/block/vdb/size').read_text().strip() != '65536':
        raise RuntimeError('expected dedicated 32MiB guest state disk')
    p = subprocess.run(['blkid', '-s', 'TYPE', '-o', 'value', '/dev/vdb'], capture_output=True, text=True)
    if p.returncode == 2 and not p.stdout.strip():
        subprocess.run(['mkfs.ext4', '-q', '-F', '/dev/vdb'], check=True)
    elif p.returncode != 0 or p.stdout.strip() != 'ext4':
        raise RuntimeError('unexpected existing state disk format')
    subprocess.run(['mount', '/dev/vdb', str(ROOT / 'work')], check=True)
    (ROOT / 'work').chmod(0o700)
    ControlServer(('0.0.0.0', 18080), Handler).serve_forever()
