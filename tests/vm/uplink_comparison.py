"""Opt-in, fixed-budget production-build comparison inside the existing VM guard."""
import json
import os
import subprocess
import time

CASES = ['uplink-' + product + '-' + str(paths)
         for product in ('vpnctl', 'openvpn') for paths in (4, 8)]
FAULTS = {'link-down', 'endpoint-drop', 'relay-drop', 'uplink-drop', 'last-endpoint-only', 'app1-last-path'}

def faults(transport):
    return FAULTS if transport == 'vpnctl' else FAULTS - {'app1-last-path'}
KINDS = {'app', 'app2', 'existing'}


def start(root, req):
    # Called only under the guest agent's authenticated guard and worker lock.
    paths, product = req.get('paths'), req.get('transport')
    if type(paths) is not int or paths not in (4, 8) or product not in ('vpnctl', 'openvpn'):
        raise ValueError('explicit comparison product and 4/8 endpoints required')
    env = dict(os.environ, VPNCTL_INTEGRATION='1', VPNCTL_VM_WORKER='1',
               VPNCTL_BIN='/opt/vpnctl-vm/vpnctl', VPNCTL_ARTIFACT_DIR=str(root / 'results'),
               TMPDIR='/tmp', VPNCTL_UPLINK_PATHS=str(paths), VPNCTL_UPLINK_TRANSPORT=product)
    with (root / 'worker.log').open('wb') as log:
        return subprocess.Popen(['/opt/vpnctl-vm/integration.test',
                                 '-test.run=^TestVMUplinkBenchmark$', '-test.v', '-test.timeout=15m'],
                                env=env, stdout=log, stderr=log, start_new_session=True)


def collect(root, worker):
    if worker is None:
        raise RuntimeError('comparison not started')
    result = {'exit': worker.poll()}
    if result['exit'] is None:
        return result
    total = 0
    reports = []
    for report in sorted((root / 'results').glob('uplink-*/uplink.json')):
        total += report.stat().st_size
        if total > 32 * 1024 * 1024:
            raise RuntimeError('comparison evidence exceeds bound')
        row = {'report': json.loads(report.read_text()), 'logs': {}}
        for log in sorted(report.parent.iterdir()):
            if log.suffix not in ('.log', '.jsonl'):
                continue
            total += log.stat().st_size
            if total > 32 * 1024 * 1024:
                raise RuntimeError('comparison evidence exceeds bound')
            row['logs'][log.name] = log.read_text()
        reports.append(row)
    result['reports'] = reports
    # Private diagnostic only; never print to the terminal or publish verbatim.
    log = root / 'worker.log'
    if log.exists():
        with log.open('rb') as source:
            source.seek(max(0, log.stat().st_size - 512 * 1024))
            result['worker_log'] = source.read().decode(errors='replace')
    return result


def recompute(rows, kind, baseline, begin, end, stop):
    selected = [s for s in rows if s.get('kind') == kind]
    previous = None
    for s in selected:
        a, q, z = s['begin_ns'], s.get('attempt_ns', s['begin_ns']), s['end_ns']
        if (any(type(v) is not int for v in (a, q, z)) or not 0 <= a <= q <= z
                or previous and any(v < p for v, p in zip((a, q, z), previous))
                or type(s.get('ok')) is not bool
                or s['ok'] and s.get('relay') not in ('r0', 'r1')
                or not s['ok'] and s.get('failure') not in ('timeout', 'socket', 'protocol', 'unexpected_source')):
            raise RuntimeError('invalid application sample')
        previous = a, q, z
    pre = [s for s in selected if s.get('attempt_ns', s['begin_ns']) >= baseline and s['end_ns'] <= begin]
    post = [s for s in selected if end <= s.get('attempt_ns', s['begin_ns']) <= stop]
    completed = [s for s in post if s['end_ns'] <= stop]
    if not completed or not any(s['ok'] and s['begin_ns'] >= baseline for s in pre):
        raise RuntimeError('missing application baseline or observation')
    successes = [s['end_ns'] for s in completed if s['ok']]
    fresh = [s['end_ns'] for s in completed if s['ok'] and s['begin_ns'] >= end]
    def gap(values):
        boundaries = [end] + values + [stop]
        return max(b - a for a, b in zip(boundaries, boundaries[1:]))
    return dict(first_success_ns=min(fresh, default=0), failed_attempts=sum(not s['ok'] for s in completed),
                unrecovered_at_end=not fresh, observed_for_ns=stop-end,
                baseline_failures=sum(not s['ok'] for s in pre), baseline_samples=len(pre),
                samples=len(completed), max_success_gap_ns=gap(successes),
                max_sample_start_gap_ns=gap([s.get('attempt_ns', s['begin_ns']) for s in post]))


def validate(status, transport, paths):
    if status.get('exit') != 0:
        raise RuntimeError('comparison worker failed; private evidence retained')
    reports = status.get('reports', [])
    expected_faults = faults(transport)
    if len(reports) != len(expected_faults) or {r['report'].get('fault') for r in reports} != expected_faults:
        raise RuntimeError('missing comparison fault reports')
    for item in reports:
        r = item['report']
        if (r.get('schema_version') != 1 or r.get('completed') is not True
                or r.get('transport') != transport or r.get('paths') != paths or r.get('race') is not False):
            raise RuntimeError('comparison identity or completion mismatch')
        baseline, begin, end, stop = (r[k] for k in ('baseline_start_ns', 'fault_begin_ns', 'fault_end_ns', 'window_end_ns'))
        if not (0 < baseline < begin <= end < stop and stop - end == 45_000_000_000):
            raise RuntimeError('comparison observation budget changed')
        for role, cpu, cpuset in (('robot', '50000 100000', '0'), ('server', '100000 100000', '1')):
            for suffix in ('before', 'after'):
                profile = r[role + '_' + suffix]
                if (profile.get('cpu_max') != cpu or profile.get('cpuset_cpus_effective') != cpuset
                        or profile.get('guest_vcpus') != 2
                        or any(not profile.get(k) for k in ('cpu_stat', 'memory.current', 'memory.peak', 'memory.events'))):
                    raise RuntimeError('missing or altered role resource evidence')
        metrics = r.get('metrics', {})
        if set(metrics) != KINDS or not r.get('samples'):
            raise RuntimeError('missing application evidence')
        for kind, m in metrics.items():
            if (m['baseline_failures'] != 0 or m['baseline_samples'] < 20 or m['samples'] <= 0
                    or m['max_sample_start_gap_ns'] > 2_000_000_000
                    or m['observed_for_ns'] != stop - end):
                raise RuntimeError('baseline or observation completeness failed')
            if m != recompute(r['samples'], kind, baseline, begin, end, stop):
                raise RuntimeError('reported metrics do not match actual samples')


def exercise(vm, case, result):
    _, product, paths = case.split('-')
    paths = int(paths)
    vm.call('uplink-start', {'paths': paths, 'transport': product})
    until = time.monotonic() + 16 * 60
    while time.monotonic() < until:
        status = vm.call('uplink-result')
        if status.get('exit') is not None:
            result[case] = status
            vm.record(case + '-result', status)
            validate(status, product, paths)
            return result
        time.sleep(2)
    raise RuntimeError('comparison exceeded fixed worker deadline')
