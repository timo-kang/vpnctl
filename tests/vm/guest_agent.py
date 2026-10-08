#!/usr/bin/env python3
"""Test-only guest control. Never invoke this agent on a shared host."""
import json
import hashlib
import errno
import signal
import os
import re
import stat
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from collections import deque
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path('/var/lib/vpnctl-vm')
ARGS = dict(s.split('=', 1) if '=' in s else (s, '') for s in Path('/proc/cmdline').read_text().split())
TOKEN = ARGS.get('vpnctl_vm_token', '')
WORKER = None
DIRECT_NODES = None
DIRECT_FAULT = 'outer-wg'
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
    for name in ('vpnctl', 'integration.test', 'vpnctl-legacy', 'vpnctl-lease-v1', 'vpnctl-lease-v2'):
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

def direct_nodes(req):
    nodes = req.get('nodes') if isinstance(req, dict) else None
    if type(nodes) is not int or nodes not in (2, 3, 8, 32):
        raise ValueError('one explicit direct node count (2, 3, 8, 32) required')
    return nodes

def direct_fault(req):
    fault = req.get('fault', 'outer-wg')
    if fault not in ('outer-wg', 'inner-nonce'):
        raise ValueError('direct fault must be outer-wg or inner-nonce')
    return fault

def direct_fixture_id(nodes, fault):
    return f'direct-inner-{nodes}' if fault == 'inner-nonce' else f'direct-{nodes}'

def start_direct(req):
    global WORKER, DIRECT_NODES, DIRECT_FAULT
    guard()
    nodes = direct_nodes(req)
    fault = direct_fault(req)
    with LOCK:
        if WORKER is not None:
            raise RuntimeError('only one fixture per direct VM')
        (ROOT / 'results').mkdir(mode=0o700, exist_ok=True)
        env = dict(os.environ, VPNCTL_VM_WORKER='1', VPNCTL_VM_DIRECT='1', VPNCTL_INTEGRATION='1',
                   VPNCTL_DIRECT_SIZES=str(nodes), VPNCTL_DIRECT_FAULT=fault, VPNCTL_BIN='/opt/vpnctl-vm/vpnctl',
                   VPNCTL_ARTIFACT_DIR=str(ROOT / 'results'), TMPDIR='/tmp', GORACE='atexit_sleep_ms=0')
        with (ROOT / 'worker.log').open('wb') as log:
            WORKER = subprocess.Popen(['/opt/vpnctl-vm/integration.test',
                '-test.run=^TestVMDirectDataplane$', '-test.v', '-test.timeout=15m'],
                env=env, stdout=log, stderr=log, start_new_session=True)
        DIRECT_NODES, DIRECT_FAULT = nodes, fault
    return {'started': True, 'fixture_id': direct_fixture_id(nodes, fault),
            'nodes': nodes, 'fault_mode': fault, 'test': 'TestVMDirectDataplane'}

def direct_artifact_guard(path, tail=False):
    # Never follow a named public artifact back into the fixture's private tree.
    allowed_root = ROOT if tail and path == ROOT / 'worker.log' else ROOT / 'results'
    if (path.is_symlink() or path.parent.is_symlink() or allowed_root.is_symlink()
            or not path.resolve().is_relative_to(allowed_root.resolve())):
        raise RuntimeError('unexpected direct artifact path')

def direct_artifact(path, limit, tail=False):
    direct_artifact_guard(path, tail)
    with path.open('rb') as stream:
        offset = max(0, path.stat().st_size - limit) if tail else 0
        stream.seek(offset)
        raw = stream.read(limit if tail else limit + 1)
    if len(raw) > limit:
        raise RuntimeError('direct artifact exceeds size limit: ' + path.name)
    if offset:
        # A cut line may omit the keyword that marks a secret; drop it whole.
        raw = raw.partition(b'\n')[2]
    text = raw.decode(errors='replace')
    if tail:
        text = '\n'.join('[redacted]' if any(word in line.lower() for word in
                         ('token', 'private', 'key', 'credential')) else line for line in text.splitlines())
        # Replacement markers and invalid UTF-8 can expand the bounded input.
        text = text.encode()[-limit:].decode(errors='ignore')
    return text

DIRECT_LIFECYCLE_SCAN_BYTES = 2 * 1024 * 1024
DIRECT_LIFECYCLE_SCAN_LINES = 65536
DIRECT_LIFECYCLE_EVENTS = 512
DIRECT_LIFECYCLE_LINE_BYTES = 8192
DIRECT_LIFECYCLE_PATTERN = re.compile(
    r'time=(?P<time>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]{8,18}(?:Z|[+-][0-9]{2}:[0-9]{2})) '
    r'level=(?:INFO|WARN) msg="direct dataplane" '
    r'peer=(?P<peer>node-(?:[0-9]|[12][0-9]|3[01])) '
    r'state=(?P<state>pending|blocked|relay_unverified|cooldown|handshaking|probing|active) '
    r'reason=(?P<reason>""|[a-z_]{1,64}|"[a-z_]{1,64}")'
    r'(?: generation=(?P<generation>[a-f0-9]{32}))?')

def direct_lifecycle(path):
    # Warning floods can evict all transitions from the ordinary 32 KiB tail.
    # Scan a bounded prefix separately and export only the lifecycle schema.
    # Keep both early and late transitions within that scan, with explicit loss
    # counts; this diagnostic never supplies evidence for a PASS verdict.
    if not re.fullmatch(r'agent-(?:[0-9]|[12][0-9]|3[01])\.log', path.name):
        raise RuntimeError('unexpected direct lifecycle artifact name')
    direct_artifact_guard(path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise RuntimeError('direct lifecycle artifact must be a regular file')
    first, last = [], deque(maxlen=DIRECT_LIFECYCLE_EVENTS // 2)
    count, scanned, lines = 0, 0, 0
    out = dict(events=[], source_bytes=0, scanned_bytes=0, scan_truncated=False,
               lines_scanned=0,
               events_truncated=False, events_omitted=0, long_lines_skipped=0,
               redacted_lines=0, malformed_lines=0)
    with os.fdopen(fd, 'rb') as stream:
        out['source_bytes'] = info.st_size
        budget = min(info.st_size, DIRECT_LIFECYCLE_SCAN_BYTES)
        dropping = False
        while scanned < budget and lines < DIRECT_LIFECYCLE_SCAN_LINES:
            raw = stream.readline(min(DIRECT_LIFECYCLE_LINE_BYTES + 1, budget - scanned))
            if not raw:
                break
            scanned += len(raw)
            if not dropping:
                lines += 1
            if dropping:
                dropping = not raw.endswith(b'\n')
                continue
            if len(raw) > DIRECT_LIFECYCLE_LINE_BYTES:
                out['long_lines_skipped'] += 1
                dropping = not raw.endswith(b'\n')
                continue
            if not raw.endswith(b'\n') and scanned < info.st_size:
                # A scan boundary must not turn a partial line into a record.
                break
            line = raw.decode(errors='replace').strip()
            if 'msg="direct dataplane"' not in line:
                continue
            if any(word in line.lower() for word in ('token', 'private', 'key', 'credential')):
                out['redacted_lines'] += 1
                continue
            match = DIRECT_LIFECYCLE_PATTERN.fullmatch(line)
            if not match:
                out['malformed_lines'] += 1
                continue
            event = {k: v.strip('"') for k, v in match.groupdict().items() if v is not None}
            count += 1
            if len(first) < DIRECT_LIFECYCLE_EVENTS - last.maxlen:
                first.append(event)
            else:
                last.append(event)
    out.update(events=first + list(last), scanned_bytes=scanned, lines_scanned=lines,
               scan_truncated=scanned < out['source_bytes'],
               events_truncated=count > DIRECT_LIFECYCLE_EVENTS,
               events_omitted=max(0, count - DIRECT_LIFECYCLE_EVENTS))
    return out

def direct_result(req):
    guard()
    nodes, fault = direct_nodes(req), direct_fault(req)
    if nodes != DIRECT_NODES or fault != DIRECT_FAULT:
        raise ValueError('direct result must match the started node count and fault')
    if WORKER is None:
        raise RuntimeError('direct fixture not started')
    result = {'exit': WORKER.poll(), 'fixture_id': direct_fixture_id(nodes, fault),
              'nodes': nodes, 'fault_mode': fault, 'test': 'TestVMDirectDataplane'}
    if result['exit'] is not None:
        worker_log = ROOT / 'worker.log'
        result['worker_log'] = direct_artifact(worker_log, 32768, tail=True) if worker_log.exists() else ''
        result['reports'] = []
        # Export exactly named public evidence. Configs, caches, PKI and private
        # fixture directories are never traversed. Extra reports remain visible
        # so the observer cannot qualify a duplicate or a mismatched fixture.
        for report in sorted((ROOT / 'results').glob('direct-dataplane-*/report.json')):
            if len(result['reports']) >= 4:
                raise RuntimeError('too many direct fixture reports')
            row = {'fixture': report.parent.name,
                   'report': json.loads(direct_artifact(report, 8 * 1024 * 1024)), 'logs': {}, 'lifecycle': {}}
            packets = report.parent / 'retry-packets.jsonl'
            if packets.exists() or packets.is_symlink():
                row['logs'][packets.name] = direct_artifact(packets, 512 * 1024)
            for name in ['controller.log'] + [f'agent-{i}.log' for i in range(nodes)]:
                path = report.parent / name
                if path.exists() or path.is_symlink():
                    row['logs'][name] = direct_artifact(path, 32768, tail=True)
                    if name.startswith('agent-'):
                        row['lifecycle'][name] = direct_lifecycle(path)
            result['reports'].append(row)
    return result

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
            elif action == 'direct-start':
                result = start_direct(req)
            elif action == 'direct-result':
                result = direct_result(req)
            elif action in ('application-mixed-start', 'application-preparation-start', 'application-approval-start', 'application-capacity-start'):
                with LOCK:
                    if WORKER is not None:
                        raise RuntimeError('only one fixture per VM')
                    # Go appends the long subtest name to TMPDIR. Keep the
                    # guest-only path short enough for Linux's Unix socket
                    # address limit (the controller admin socket lives below it).
                    env = dict(os.environ, VPNCTL_INTEGRATION='1', VPNCTL_VM_WORKER='1',
                               VPNCTL_BIN='/opt/vpnctl-vm/vpnctl', VPNCTL_ARTIFACT_DIR=str(ROOT / 'results'),
                               TMPDIR='/tmp', GORACE='atexit_sleep_ms=0')
                    if action == 'application-capacity-start':
                        paths, cpu = req.get('paths'), req.get('robot_cpus')
                        layout = req.get('cpu_layout', 'shared')
                        rebuild = req.get('rebuild', False)
                        startup = req.get('startup', False)
                        if type(paths) is not int or paths not in (4, 8) or cpu not in ('1', '0.5', '0.25') or layout not in ('shared', 'split') or type(rebuild) is not bool or type(startup) is not bool or startup and (rebuild or layout != 'split'):
                            raise ValueError('explicit bounded robot CPU and path profile required')
                        env.update(VPNCTL_CAPACITY_PATHS=str(paths), VPNCTL_CAPACITY_ROBOT_CPU=cpu, VPNCTL_CAPACITY_CPU_LAYOUT=layout,
                                   VPNCTL_CAPACITY_REBUILD='1' if rebuild else '0', VPNCTL_CAPACITY_STARTUP='1' if startup else '0')
                    with (ROOT / 'worker.log').open('wb') as log:
                        test = {'application-mixed-start': 'TestNetns_M3TargetApplicationMixedCandidates',
                                'application-preparation-start': 'TestNetns_M3PreparationCapacity',
                                'application-approval-start': 'TestNetns_M3TargetApplicationApproval',
                                'application-capacity-start': 'TestVMApplicationCapacity'}[action]
                        WORKER = subprocess.Popen(['/opt/vpnctl-vm/integration.test',
                            '-test.run=^' + test + '$', '-test.v', '-test.timeout=15m'],
                            env=env, stdout=log, stderr=log, start_new_session=True)
                result = {'started': True}
            elif action in ('application-mixed-result', 'application-preparation-result', 'application-approval-result', 'application-capacity-result'):
                if WORKER is None:
                    raise RuntimeError('mixed application fixture not started')
                result = {'exit': WORKER.poll()}
                if result['exit'] is not None:
                    reports, total = [], 0
                    filename = 'application-mixed-candidates.json' if action != 'application-approval-result' else 'application-approval.json'
                    for report in sorted((ROOT / 'results').glob('*/' + filename)):
                        total += report.stat().st_size
                        if total > 8 * 1024 * 1024:
                            raise RuntimeError('mixed application diagnostics exceed limit')
                        row = {'fixture': report.parent.name, 'report': json.loads(report.read_text()), 'logs': {}}
                        for name in ('capacity-app.jsonl', 'capacity-app2.jsonl', 'application-node-supervisor.jsonl', 'application-kernel.json'):
                            path = report.parent / name
                            if path.exists():
                                total += path.stat().st_size
                                if total > 8 * 1024 * 1024:
                                    raise RuntimeError('mixed application diagnostics exceed limit')
                                row['logs'][name] = path.read_text()
                        reports.append(row)
                    result['reports'] = reports
            elif action in ('managers-start', 'manager-auto-start'):
                automatic = action == 'manager-auto-start'
                paths = req.get('paths')
                if automatic and (type(paths) is not int or paths not in (4, 8)):
                    raise ValueError('automatic manager paths must be 4 or 8')
                installation = req.get('installation', False)
                if type(installation) is not bool or installation and not automatic:
                    raise ValueError('installation requires an automatic manager test')
                with LOCK:
                    if WORKER is not None:
                        raise RuntimeError('only one fixture per manager VM')
                    env = dict(os.environ, VPNCTL_VM_MANAGERS='1', VPNCTL_INTEGRATION='1',
                               VPNCTL_BIN='/opt/vpnctl-vm/vpnctl', VPNCTL_ARTIFACT_DIR=str(ROOT / 'results'),
                               TMPDIR=str(ROOT / 'work'))
                    if automatic:
                        env.update(VPNCTL_VM_MANAGER_AUTO='1', VPNCTL_VM_MANAGER_PATHS=str(paths), VPNCTL_VM_WORKER='1')
                        if installation:
                            env['VPNCTL_VM_RELAY_INSTALL'] = '1'
                    test = 'TestVMNetworkManagerAuto' if automatic else 'TestVMNetworkManagers'
                    timeout = '20m' if automatic else '12m'
                    with (ROOT / 'worker.log').open('wb') as log:
                        WORKER = subprocess.Popen(['/opt/vpnctl-vm/integration.test', '-test.run=^' + test + '$', '-test.v', '-test.timeout=' + timeout],
                                                  env=env, stdout=log, stderr=log, start_new_session=True)
                result = {'started': True}
            elif action in ('managers-result', 'manager-auto-result'):
                if WORKER is None:
                    raise RuntimeError('manager fixture not started')
                result = {'exit': WORKER.poll()}
                automatic = action == 'manager-auto-result'
                report = ROOT / ('manager-auto.json' if automatic else 'managers.json')
                if result['exit'] is not None and report.exists():
                    if report.stat().st_size > (32 if automatic else 1) * 1024 * 1024:
                        raise RuntimeError('manager report too large')
                    result['report'] = json.loads(report.read_text())
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
    # Dedicated guest-only mount, after the host/guest isolation guard.
    pins = Path('/run/vpnctl-bpf')
    pins.mkdir(mode=0o700, exist_ok=True)
    subprocess.run(['mount', '-t', 'bpf', '-o', 'mode=0700,nosuid,nodev,noexec', 'bpf', str(pins)], check=True)
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
