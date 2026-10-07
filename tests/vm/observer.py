#!/usr/bin/env python3
"""External monotonic observer for one disposable VM in a bounded container."""
import argparse
import datetime
import hashlib
import json
import os
import socket
import subprocess
import time
import threading
import urllib.error
import urllib.request
import uuid
from pathlib import Path

def open_lease_guards(snapshot):
    """A TCP timeout alone can be caused by WireGuard rekeying after sleep.

    Independently detect a still-permissive owned nft gate. A positive rounded
    countdown proves it is live; zero is ambiguous and is not an active proof.
    """
    kernel = snapshot['kernel']
    now = datetime.datetime.fromisoformat(kernel['at'].replace('Z', '+00:00'))
    opened = []
    for relay in ('r0', 'r1'):
        rows = json.loads(kernel[relay]['nft -j -n -T list ruleset'])['nftables']
        tables = [r['table']['name'] for r in rows if 'table' in r and r['table']['name'].startswith('vl')]
        if not tables and kernel[relay]['wg show all allowed-ips'].strip():
            raise RuntimeError('relay peers exist without lease guard evidence')
        for table in tables:
            sets, cutoffs, selected = {}, set(), set()
            for row in rows:
                if 'set' in row and row['set']['table'] == table:
                    sets[row['set']['name']] = row['set']
                if 'rule' not in row or row['rule']['table'] != table:
                    continue
                for expr in row['rule']['expr']:
                    match = expr.get('match', {})
                    if match.get('left') == {'meta': {'key': 'time'}} and match.get('op') == '>=':
                        cutoffs.add(match['right'])
                    if isinstance(match.get('right'), str) and match['right'].startswith('@'):
                        selected.add(match['right'][1:])
            if len(cutoffs) != 1 or len(selected) != 1 or next(iter(selected)) not in sets:
                raise RuntimeError('incomplete lease guard evidence')
            cutoff = datetime.datetime.fromisoformat(next(iter(cutoffs))).replace(tzinfo=datetime.timezone.utc)
            timer = sets[next(iter(selected))]
            if now < cutoff and any(e['elem'].get('expires', 0) > 0 for e in timer.get('elem', [])):
                guard = kernel[relay].get('bpf_guards', {}).get('vd' + table[2:], {})
                boot = guard.get('state', {})
                # The read validates both attachments, code and map owner.
                if (not guard.get('error') and boot.get('program_id', 0) > 0
                        and boot.get('map_id', 0) > 0 and boot.get('observed_ns', 0) > 0
                        and 0 <= boot.get('deadline_ns', -1) <= boot['observed_ns']):
                    continue
                opened.append({'relay': relay, 'table': table, 'selected': timer['name'], 'cutoff': cutoff.isoformat(), 'elements': timer['elem']})
    return opened

class VM:
    def __init__(self, work, results, rtc='host'):
        self.work, self.results = Path(work), Path(results)
        self.token, self.uuid = uuid.uuid4().hex, str(uuid.uuid4())
        self.boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.rtc, self.process, self.qmp = rtc, None, None
        self.work.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.results.mkdir(parents=True, exist_ok=False)
        self.events = (self.results / 'observer.jsonl').open('w', buffering=1)
        self.event_lock = threading.Lock()

    def record(self, kind, data):
        with self.event_lock:
            self.events.write(json.dumps({'kind': kind, 'wall_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns(), 'data': data}) + '\n')

    def launch(self):
        disk = self.work / 'guest.qcow2'
        if not disk.exists():
            subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', '/input/guest.qcow2', str(disk)], check=True)
        state_disk = self.work / 'state.qcow2'
        if not state_disk.exists():
            subprocess.run(['qemu-img', 'create', '-q', '-f', 'qcow2', str(state_disk), '32M'], check=True)
        qmp = str(self.work / 'qmp.sock')
        Path(qmp).unlink(missing_ok=True)
        args = ['qemu-system-x86_64', '-enable-kvm', '-machine', 'pc', '-cpu', 'host', '-smp', '1', '-m', '768',
                '-uuid', self.uuid, '-display', 'none', '-monitor', 'none', '-no-shutdown',
                '-qmp', 'unix:' + qmp + ',server=on,wait=off',
                '-serial', 'file:' + str(self.results / 'console.log'),
                '-rtc', 'base=utc,clock=' + self.rtc, '-kernel', '/input/vmlinuz', '-initrd', '/input/initrd',
                '-append', 'root=/dev/vda rw console=ttyS0 net.ifnames=0 systemd.log_level=warning '
                           'vpnctl_vm_test vpnctl_vm_token=' + self.token + ' vpnctl_vm_uuid=' + self.uuid + ' vpnctl_host_boot=' + self.boot,
                '-drive', 'file=' + str(disk) + ',if=virtio,format=qcow2,cache=none',
                '-drive', 'file=' + str(state_disk) + ',if=virtio,format=qcow2,cache=none',
                '-netdev', 'user,id=n0,hostfwd=tcp:127.0.0.1:18080-:18080', '-device', 'virtio-net-pci,netdev=n0']
        with (self.results / 'qemu.log').open('ab') as log:
            self.process = subprocess.Popen(args, stdout=log, stderr=log)
        until = time.monotonic() + 30
        while not Path(qmp).exists():
            if self.process.poll() is not None or time.monotonic() > until:
                raise RuntimeError('QEMU did not open its private control socket')
            time.sleep(0.1)
        self.qmp = socket.socket(socket.AF_UNIX)
        self.qmp.settimeout(5)
        self.qmp.connect(qmp)
        self.qfile = self.qmp.makefile('rwb', buffering=0)
        self.record('qmp-greeting', json.loads(self.qfile.readline()))
        self.command('qmp_capabilities')
        self.wait_health()

    def command(self, action):
        if action not in ('qmp_capabilities', 'query-status', 'query-current-machine', 'stop', 'cont', 'system_reset', 'system_wakeup', 'quit'):
            raise ValueError('unsupported QMP command')
        self.qfile.write((json.dumps({'execute': action}) + '\n').encode())
        while True:
            line = self.qfile.readline()
            if not line:
                raise RuntimeError('QMP closed')
            reply = json.loads(line)
            if 'event' in reply:
                self.record('qmp-event', reply)
                continue
            self.record('qmp-' + action, reply)
            if 'error' in reply:
                raise RuntimeError(str(reply['error']))
            return reply['return']

    def call(self, action, data=None, timeout=45):
        req = urllib.request.Request('http://127.0.0.1:18080/' + action,
                                     data=json.dumps(data or {}).encode(), headers={'Authorization': 'Bearer ' + self.token})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return json.load(response)
        except urllib.error.HTTPError as e:
            raise RuntimeError(action + ': ' + e.read(4096).decode(errors='replace')) from e

    def wait_health(self, changed_boot=None):
        until = time.monotonic() + 90
        last_error = ''
        while time.monotonic() < until:
            if self.process.poll() is not None:
                raise RuntimeError('QEMU exited before guest readiness')
            try:
                r = self.call('health', timeout=2)
                assert r['boot_id'] != self.boot
                if r['binaries'] != json.loads(Path('/input/image.json').read_text())['binaries']:
                    raise RuntimeError('guest binary digests differ from the image manifest')
                if changed_boot and r['boot_id'] == changed_boot:
                    time.sleep(0.1)
                    continue
                self.record('guest-ready', r)
                return r
            except (OSError, ValueError, RuntimeError) as e:
                last_error = e.read().decode(errors='replace')[:2048] if isinstance(e, urllib.error.HTTPError) else str(e)
                time.sleep(0.2)
        raise RuntimeError('guest readiness timeout: ' + last_error)

    def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
        if self.qmp:
            self.qfile.close()
            self.qmp.close()
        console = self.results / 'console.log'
        if console.exists():
            console.write_text(console.read_text(errors='replace').replace(self.token, '[redacted-run-token]'))
        self.events.close()

    def start_fixture(self):
        self.call('start')
        until = time.monotonic() + 60
        while time.monotonic() < until:
            try:
                r = self.call('fixture/ready', timeout=2)
                if r.get('ready') and len(r['paths']) == 4:
                    self.paths = r['paths']
                    self.record('fixture-ready', r)
                    break
            except (OSError, ValueError, RuntimeError):
                time.sleep(0.2)
        else:
            raise RuntimeError('fixture readiness timeout')
        # Handshakes must converge before opening the never-reconnected stream.
        until = time.monotonic() + 10
        while True:
            if all(p['ok'] for p in self.probes(('new',))):
                break
            if time.monotonic() > until:
                raise RuntimeError('baseline new TCP did not converge')
            time.sleep(0.2)
        if not all(p['ok'] for p in self.probes(('existing',))):
            raise RuntimeError('baseline existing TCP unavailable')

    def probes(self, kinds=('new', 'existing')):
        # libslirp's host-forward listener has backlog 1. One control request
        # carries the concurrent guest probes, avoiding a hostfwd SYN burst.
        # The outside bracket conservatively covers every probe in the batch.
        jobs = [{'path': path, 'kind': kind, 'nonce': uuid.uuid4().hex[:16]}
                for path in self.paths for kind in kinds]
        started = time.monotonic_ns()
        results = self.call('probes', {'probes': jobs}, timeout=2)
        ended = time.monotonic_ns()
        if not isinstance(results, list) or len(results) != len(jobs):
            raise RuntimeError('missing authenticated probe results')
        for job, result in zip(jobs, results):
            path, kind, nonce = job['path'], job['kind'], job['nonce']
            # Control-plane unavailability is not proof that dataplane closed.
            if not isinstance(result, dict) or result.get('nonce') != nonce or result.get('kind') != kind or type(result.get('ok')) is not bool:
                raise RuntimeError('missing authenticated probe result: ' + str(result))
            if result.get('protocol_error'):
                raise RuntimeError('invalid TCP echo, not proof of a blocked path: ' + str(result))
            if result['ok'] and result['source'] != ('198.18.0.11' if path[1] == '0' else '198.18.0.12'):
                raise RuntimeError('probe bypassed its relay: ' + str(result))
            result.update(path=path, started_monotonic_ns=started, finished_monotonic_ns=ended)
            self.record('probe', result)
        return results

    def observe(self, seconds):
        rows = []
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            rows.extend(self.probes())
            time.sleep(0.1)
        return rows

    def closed(self):
        rows = self.probes()
        if any(p['ok'] for p in rows):
            raise RuntimeError('traffic passed a closed lease: ' + str(rows))
        return rows

    def recover(self):
        self.record('explicit-recovery', self.call('fixture/recover'))
        until = time.monotonic() + 12
        while time.monotonic() < until:
            try:
                rows = self.probes(('new',))
            except (ConnectionError, TimeoutError, urllib.error.URLError) as error:
                # A missing control response cannot qualify recovery. Record
                # the gap and request fresh nonces within the original bound.
                # Protocol/fixture failures remain fatal; no mutating action
                # is retried and blocked-path observations stay strict.
                self.record('recovery-control-gap', {'error': str(error)})
                time.sleep(0.2)
                continue
            if all(p['ok'] for p in rows):
                return rows
            time.sleep(0.2)
        raise RuntimeError('fresh approval and explicit reinstall did not recover')

    def cached_only(self):
        self.record('http-outage', self.call('fixture/outage'))
        self.call('fixture/stop')
        self.call('fixture/supervise')
        self.observe(3)
        self.closed()
        state = self.call('fixture/snapshot')
        # nft JSON includes the actual dropped packet counts in this table.
        self.record('cached-only-blocked', state)

def host_clock():
    return {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'wall_ns': time.time_ns(), 'monotonic_ns': time.monotonic_ns(),
            'boottime_ns': time.clock_gettime_ns(time.CLOCK_BOOTTIME)}

def validate_manager_result(status):
    report = status.get('report', {})
    if status.get('exit') != 0 or report.get('completed') is not True or report.get('schema_version') != 1:
        raise RuntimeError('manager test failed, skipped or omitted its completed report')
    expected = {'baseline', 'nm-reload', 'nm-restart', 'nm-disconnect-reconnect',
                'netplan-apply', 'networkd-reload', 'networkd-restart',
                'nm-shared-up', 'nm-shared-down', 'udev-recreate'}
    steps = report.get('steps', [])
    if len(steps) != len(expected) or {s.get('name') for s in steps} != expected or any(s.get('passed') is not True for s in steps):
        raise RuntimeError('missing or failed manager scenarios')

AUTO_MANAGER_STEPS = {
    'baseline', 'nm-down', 'relay0-down', 'all-relays-down', 'alternate-recovery',
    'preferred-recovery', 'nm-restart', 'netplan-apply', 'networkd-restart',
    'foreign-firewall-reload', 'flap-down-0', 'flap-up-0', 'flap-down-1', 'flap-up-1',
    'nm-shared-up', 'nm-shared-down', 'foreign-peer-conflict', 'foreign-peer-removed',
    'watch-restart', 'controller-offline-valid',
    'approval-expired-offline', 'fresh-approval-recovery',
}
AUTO_PACKET_KINDS = {'tcp-new', 'tcp-existing', 'udp', 'independent-app', 'rf-lan', 'gimbal-lan'}

def validate_manager_auto_result(status, paths):
    report = status.get('report', {})
    if (status.get('exit') != 0 or report.get('completed') is not True
            or report.get('schema_version') != 2 or report.get('paths') != paths
            or report.get('mode') != 'automatic' or report.get('trace_error') != ''):
        raise RuntimeError('automatic manager test failed or omitted complete evidence')
    steps = report.get('steps', [])
    if (len(steps) != len(AUTO_MANAGER_STEPS) or {s.get('name') for s in steps} != AUTO_MANAGER_STEPS
            or any(s.get('passed') is not True for s in steps)):
        raise RuntimeError('missing or failed automatic manager scenarios')
    for key in ('fresh_generation_confirmed', 'recovery_hysteresis_observed', 'foreign_policy_preserved', 'foreign_peer_preserved', 'fallback_positive_control'):
        if report.get(key) is not True:
            raise RuntimeError('missing automatic manager invariant: ' + key)
    packets, cycles = report.get('packets', []), report.get('cycles', [])
    if not cycles or {p.get('kind') for p in packets} != AUTO_PACKET_KINDS:
        raise RuntimeError('missing automatic manager packet/cycle evidence')
    for i, p in enumerate(packets, 1):
        if p.get('sequence') != i or not 0 < p.get('begin_monotonic_ns', 0) <= p.get('end_monotonic_ns', 0):
            raise RuntimeError('invalid packet sequence/clock')
    for c in cycles:
        d = c.get('diagnostics') or {}
        start, end = d.get('started_monotonic_ns', 0), d.get('finished_monotonic_ns', 0)
        if (d.get('monotonic_available') is not True or d.get('checkpoints_dropped', False)
                or not 0 < start <= end <= c.get('observed_monotonic_ns', 0)):
            raise RuntimeError('incomplete cycle clock evidence')
        last = start
        for m in d.get('checkpoints', []):
            at = m.get('monotonic_ns', 0)
            if not last <= at <= end:
                raise RuntimeError('unordered execution checkpoint')
            last = at
    samples = []
    for step in steps:
        if not 0 < step.get('begin_monotonic_ns', 0) <= step.get('action_completed_monotonic_ns', 0) <= step.get('ready_observed_monotonic_ns', 0) <= step.get('end_monotonic_ns', 0):
            raise RuntimeError('invalid scenario clock evidence')
        if set(step.get('traffic', {})) != AUTO_PACKET_KINDS:
            raise RuntimeError('missing per-scenario packet evidence')
        if step.get('metric') not in ('failover', 'no-uplink'):
            continue
        slo = step.get('slo', {})
        state = slo.get('status')
        if state not in ('pass', 'fail', 'unmeasured') or slo.get('limit_ms') != 10000:
            raise RuntimeError('missing SLO classification')
        if state != 'unmeasured' and (state == 'pass') != (0 <= slo.get('elapsed_ms', -1) <= 10000):
            raise RuntimeError('false SLO classification')
        samples.append(slo)
    summary = report.get('slo_summary', {})
    if (len(samples) != 5 or summary.get('samples') != len(samples)
            or summary.get('misses') != sum(s['status'] == 'fail' for s in samples)
            or summary.get('unmeasured') != sum(s['status'] == 'unmeasured' for s in samples)
            or summary.get('p95_status') != 'unqualified_insufficient_samples'
            or summary.get('required_samples_per_class') != 20):
        raise RuntimeError('incomplete or misleading SLO summary')

def exercise(vm, case, mode, delta, result):
    vm.launch()
    result.update(health=vm.call('health'), qemu_machine=vm.command('query-current-machine'))
    if case == 'boot':
        return result
    if case == 'managers' or case.startswith('manager-auto-'):
        automatic = case != 'managers'
        paths = int(case.rsplit('-', 1)[1]) if automatic else 4
        action = 'manager-auto' if automatic else 'managers'
        vm.call(action + '-start', {'paths': paths} if automatic else {})
        until = time.monotonic() + (21 if automatic else 13) * 60
        while time.monotonic() < until:
            status = vm.call(action + '-result')
            if status['exit'] is not None:
                result[action] = status
                vm.record(action + '-result', status)
                if automatic:
                    validate_manager_auto_result(status, paths)
                else:
                    validate_manager_result(status)
                return result
            time.sleep(2)
        raise RuntimeError('manager fixture timed out')
    vm.start_fixture()
    if case in ('lease', 'clock'):
        if mode == 'stopped':
            vm.record('supervision-stopped', vm.call('fixture/stop'))
        fault = time.monotonic_ns()
        if case == 'clock':
            result['clock_step'] = vm.call('clock', {'delta': delta})
            vm.record('clock-step', result['clock_step'])
        rows = vm.observe(12)
        must_close = mode == 'stopped' or delta < -30
        result['last_success'] = {p + '/' + k: max((r['finished_monotonic_ns'] for r in rows if r['path'] == p and r['kind'] == k and r['ok']), default=None)
                                  for p in vm.paths for k in ('new', 'existing')}
        result['first_failure'] = {p + '/' + k: min((r['finished_monotonic_ns'] for r in rows if r['path'] == p and r['kind'] == k and not r['ok']), default=None)
                                   for p in vm.paths for k in ('new', 'existing')}
        result['fault_monotonic_ns'] = fault
        if must_close:
            vm.closed()
            if any(v is not None and v > fault + 11_000_000_000 for v in result['last_success'].values()):
                raise RuntimeError('last observed pass exceeded the 10s lease plus 1s detection allowance')
            if any(v is None for v in result['first_failure'].values()):
                raise RuntimeError('missing failure observation')
            vm.cached_only()
        else:
            if not all(p['ok'] for p in vm.probes(('new',))):
                raise RuntimeError('valid approval did not recover under running supervision')
        if delta < 0:
            vm.record('clock-restored', vm.call('clock', {'unix_ns': time.time_ns()}))
        result['recovery'] = vm.recover()
    elif case in ('pause', 'pause-fenced', 'pause-expired', 'suspend'):
        if case == 'pause-expired':
            result['approval'] = vm.call('fixture/expiry')
        if case == 'pause-fenced':
            vm.record('pause-fence', vm.call('fixture/fence'))
            result['before_pause_blocked'] = vm.closed()
        else:
            vm.record('supervision-frozen', vm.call('fixture/freeze'))
            result['before_pause_probes'] = vm.probes()
            if not all(p['ok'] for p in result['before_pause_probes']):
                raise RuntimeError('pause requires live existing/new TCP after supervisors freeze')
        result['before'] = vm.call('health')
        if case != 'suspend':
            vm.command('stop')
        else:
            vm.record('guest-suspend-request', vm.call('suspend'))
        until = time.monotonic() + 15
        expected = 'suspended' if case == 'suspend' else 'paused'
        while vm.command('query-status')['status'] != expected:
            if time.monotonic() > until:
                raise RuntimeError('guest did not enter ' + expected)
            time.sleep(0.1)
        result['stopped_monotonic_ns'] = time.monotonic_ns()
        remaining = 70 if case == 'pause-expired' else 12
        while remaining:
            step = min(30, remaining)
            time.sleep(step)
            remaining -= step
            vm.record('pause-elapsed', {'remaining_seconds': remaining})
        vm.command('system_wakeup' if case == 'suspend' else 'cont')
        result['resumed_monotonic_ns'] = time.monotonic_ns()
        result['after'] = vm.wait_health()
        result['first_post_resume_probes'] = vm.probes()
        elapsed = (result['resumed_monotonic_ns'] - result['stopped_monotonic_ns']) / 1e9
        advances = {name: (result['after'][name] - result['before'][name]) / 1e9 for name in ('wall_ns', 'monotonic_ns', 'boottime_ns')}
        result['external_pause_seconds'], result['guest_clock_advance_seconds'] = elapsed, advances
        if case == 'pause-expired':
            expires = datetime.datetime.fromisoformat(result['approval']['expires_at'].replace('Z', '+00:00')).timestamp()
            result['external_approval_expired'] = time.time() > expires
            if not result['external_approval_expired']:
                raise RuntimeError('pause did not cross the approval expiry')
        if any(p['ok'] for p in result['first_post_resume_probes']):
            if case not in ('pause', 'pause-expired') or any(advance >= elapsed - 2 for advance in advances.values()):
                raise RuntimeError('traffic passed after an expired guard with advancing guest time')
            # Reproduce the unsupported condition explicitly. This is a completed
            # experiment, NOT a qualified deployment or a passing lease bound.
            result['qualified'] = False
            result['unsupported_reason'] = 'all_guest_clocks_frozen_external_deadline_unenforced'
            result['final'] = vm.call('fixture/snapshot')
            return result
        vm.cached_only()
        if case == 'pause-fenced':
            vm.record('external-clock-sync-before-reapproval', vm.call('clock', {'unix_ns': time.time_ns()}))
        result['recovery'] = vm.recover()
    elif case in ('delayed-prepare', 'delayed-commit', 'delayed-rearm', 'delayed-child', 'delayed-group', 'delayed-continuation', 'delayed-suspend'):
        if case == 'delayed-continuation':
            vm.call('fixture/stop')
            vm.call('fixture/outage')
            time.sleep(2)
        if case == 'delayed-rearm':
            vm.call('fixture/stop')
            time.sleep(12)
            if any(p['ok'] for p in vm.probes(('new',))):
                raise RuntimeError('rearm fixture was not expired before the fresh response')
        result['prepared'] = vm.call('fixture/delay-start', {
            'phase': 'prepare' if case == 'delayed-prepare' else 'activate',
            'target': 'child' if case == 'delayed-child' else 'group' if case == 'delayed-group' else 'parent'})
        vm.record('renewal-prepared-supervisors-stopped', result['prepared'])
        result['fault_monotonic_ns'] = time.monotonic_ns()
        if delta:
            result['clock_step'] = vm.call('clock', {'delta': delta})
        # Do not write to the existing stream while the gate is closed: retain
        # that exact TCP connection for the first post-commit probe.
        if case == 'delayed-child':
            time.sleep(4)
            result['child_cancellation'] = vm.call('fixture/delay-release')
            vm.call('fixture/stop')
        if case == 'delayed-suspend':
            result['before_suspend'] = vm.call('health')
            vm.call('suspend')
            until = time.monotonic() + 15
            while vm.command('query-status')['status'] != 'suspended':
                if time.monotonic() > until:
                    raise RuntimeError('guest did not suspend during delayed activation')
                time.sleep(0.1)
            time.sleep(35 if delta == -31 else 12)
            vm.command('system_wakeup')
            result['after_suspend'] = vm.wait_health()
        else:
            time.sleep(6 if case == 'delayed-continuation' else 12)
        result['before_commit'] = vm.call('fixture/snapshot')
        result['commit'] = result.get('child_cancellation') or vm.call('fixture/delay-release')
        vm.record('delayed-commit', result['commit'])
        result['after_commit'] = vm.call('fixture/snapshot')
        result['open_guards_after_commit'] = open_lease_guards(result['after_commit'])
        result['first_post_commit_probes'] = vm.probes()
        if result['open_guards_after_commit'] or any(p['ok'] for p in result['first_post_commit_probes']):
            result['defect_reason'] = 'delayed_commit_left_expired_guard_permissive' if result['open_guards_after_commit'] else 'delayed_commit_reopened_expired_gate'
            result['qualified'] = False
        else:
            vm.cached_only()
            if delta < 0:
                vm.record('clock-restored', vm.call('clock', {'unix_ns': time.time_ns()}))
            result['recovery'] = vm.recover()
    elif case in ('reboot', 'reset'):
        result['before'] = vm.call('health')
        if case == 'reboot':
            vm.record('reboot-request', vm.call('reboot'))
        else:
            vm.command('system_reset')
        result['after'] = vm.wait_health(changed_boot=result['before']['boot_id'])
        result['old_domain'] = vm.call('domain')
        vm.record('old-domain-rejected', result['old_domain'])
        # A new operator-owned cache/identity setup is explicit. Old journals
        # and their initialized markers remain intact in their private dirs.
        vm.start_fixture()
        result['fresh_install'] = vm.probes(('new',))
        if not all(p['ok'] for p in result['fresh_install']):
            raise RuntimeError('fresh installation after new boot failed')
    elif case in ('expiry', 'denied'):
        if case == 'expiry':
            result['approval'] = vm.call('fixture/expiry')
            result['forward_step'] = vm.call('clock', {'delta': 61})
        else:
            vm.record('approval-withdrawn', vm.call('fixture/deny'))
        vm.observe(12)
        result['blocked'] = vm.closed()
        vm.call('fixture/stop')
        result['rollback'] = vm.call('clock', {'delta': -61 if case == 'expiry' else -2})
        vm.cached_only()
        if case == 'expiry':
            vm.record('clock-restored', vm.call('clock', {'delta': 61}))
        else:
            vm.record('clock-restored', vm.call('clock', {'unix_ns': time.time_ns()}))
        result['recovery'] = vm.recover()
    elif case == 'namespace':
        vm.call('fixture/stop')
        result['old_domain'] = vm.call('namespace')
        vm.start_fixture()
        result['fresh_install'] = vm.probes(('new',))
        if not all(p['ok'] for p in result['fresh_install']):
            raise RuntimeError('fresh installation after namespace replacement failed')
    elif case in ('enospc', 'rename', 'fsync', 'fsync-dir'):
        vm.call('fixture/stop')
        result['fault'] = vm.call('storage-fault', {'kind': case})
        vm.record('storage-fault-injected', result['fault'])
        vm.observe(12)
        result['blocked'] = vm.closed()
        result['before_reboot'] = vm.call('health')
        vm.command('system_reset')
        result['after_reboot'] = vm.wait_health(changed_boot=result['before_reboot']['boot_id'])
        vm.call('clear-storage-fault')
        result['old_domain'] = vm.call('domain')
        vm.start_fixture()
        result['fresh_install'] = vm.probes(('new',))
        if not all(p['ok'] for p in result['fresh_install']):
            raise RuntimeError('fresh installation after storage failure/reboot failed')
    elif case in ('downgrade', 'legacy-upgrade', 'lease-v1-downgrade', 'lease-v1-upgrade', 'lease-v2-downgrade', 'lease-v2-upgrade'):
        result['version_check'] = vm.call('fixture/' + case)
        vm.record('journal-version-check', result['version_check'])
        if case in ('legacy-upgrade', 'lease-v1-upgrade', 'lease-v2-upgrade'):
            result['legacy_blocked'] = vm.closed()
            result['upgrade_recovery'] = vm.recover()
            vm.call('fixture/stop')
        result['before_reboot'] = vm.call('health')
        vm.command('system_reset')
        result['after_reboot'] = vm.wait_health(changed_boot=result['before_reboot']['boot_id'])
        result['old_domain'] = vm.call('domain')
        vm.start_fixture()
        result['fresh_install'] = vm.probes(('new',))
        if not all(p['ok'] for p in result['fresh_install']):
            raise RuntimeError('fresh installation after version check/reboot failed')
    result['final'] = vm.call('fixture/snapshot')
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', nargs='+', default=['boot'], choices=['manager-auto-4', 'manager-auto-8', 'managers', 'boot', 'lease', 'clock', 'pause', 'pause-fenced', 'pause-expired', 'suspend', 'reboot', 'reset', 'expiry', 'denied', 'namespace', 'enospc', 'rename', 'fsync', 'fsync-dir', 'downgrade', 'legacy-upgrade', 'lease-v1-downgrade', 'lease-v1-upgrade', 'lease-v2-downgrade', 'lease-v2-upgrade', 'delayed-prepare', 'delayed-commit', 'delayed-rearm', 'delayed-child', 'delayed-group', 'delayed-continuation', 'delayed-suspend', 'matrix'])
    parser.add_argument('--mode', default='stopped', choices=['stopped', 'running'])
    parser.add_argument('--delta', type=int, default=0, choices=[0, -2, -31, -600, 2, 600])
    parser.add_argument('--rtc', default='host', choices=['host', 'vm'])
    args = parser.parse_args()
    if not Path('/.dockerenv').exists() or set(os.listdir('/sys/class/net')) != {'lo'}:
        raise SystemExit('run only inside the dedicated network-none container')
    caps = next(s.split()[1] for s in Path('/proc/self/status').read_text().splitlines() if s.startswith('CapEff:'))
    if int(caps, 16) != 0:
        raise SystemExit('outer container must drop all capabilities')
    quota, period = Path('/sys/fs/cgroup/cpu.max').read_text().split()
    memory = Path('/sys/fs/cgroup/memory.max').read_text().strip()
    swap = Path('/sys/fs/cgroup/memory.swap.max').read_text().strip()
    if quota == 'max' or int(quota) > int(period) or memory == 'max' or int(memory) > 2 * 1024**3 or swap != '0':
        raise SystemExit('bounded CPU=1, memory<=2GiB, no-swap cgroup v2 required')
    image = json.loads(Path('/input/image.json').read_text())
    if set(image['sha256']) != {'vmlinuz', 'initrd', 'guest.qcow2'}:
        raise SystemExit('incomplete guest image manifest')
    for name, expected in image['sha256'].items():
        if name not in ('vmlinuz', 'initrd', 'guest.qcow2'):
            raise SystemExit('unexpected guest image manifest member')
        with (Path('/input') / name).open('rb') as f:
            if hashlib.file_digest(f, 'sha256').hexdigest() != expected:
                raise SystemExit('guest image digest mismatch: ' + name)
    Path('/results/runner.json').write_text(json.dumps({'qemu': subprocess.check_output(['qemu-system-x86_64', '--version'], text=True),
        'cpu_max': [quota, period], 'memory_max': memory, 'swap_max': swap, 'cap_eff': caps, 'image': image}, indent=2) + '\n')
    cases = [(case, args.mode, args.delta, args.rtc) for case in args.case]
    if 'matrix' in args.case:
        if args.case != ['matrix']:
            raise SystemExit('matrix cannot be combined with selected cases')
        cases = [('lease', 'stopped', 0, 'host')]
        cases += [('clock', mode, delta, 'host') for mode in ('stopped', 'running') for delta in (-2, -31, -600, 2, 600)]
        cases += [('pause', 'stopped', 0, rtc) for rtc in ('host', 'vm')]
        cases += [('pause-fenced', 'stopped', 0, rtc) for rtc in ('host', 'vm')]
        cases += [(case, 'stopped', 0, 'host') for case in ('suspend', 'reboot', 'reset', 'expiry', 'denied', 'namespace', 'enospc', 'rename', 'fsync', 'fsync-dir', 'downgrade', 'legacy-upgrade', 'lease-v1-downgrade', 'lease-v1-upgrade', 'lease-v2-downgrade', 'lease-v2-upgrade', 'pause-expired')]
        cases += [(case, 'stopped', delta, 'host') for case in ('delayed-prepare', 'delayed-commit', 'delayed-rearm', 'delayed-child', 'delayed-group', 'delayed-continuation', 'delayed-suspend') for delta in (0, -31)]
        cases += [('delayed-suspend', 'stopped', delta, 'host') for delta in (-2, -600)]
    verdicts = []
    host_before = host_clock()
    for case, mode, delta, rtc in cases:
        label = f'{case}-{mode}-{delta}-{rtc}'
        vm = VM('/work/vm-' + uuid.uuid4().hex[:8], '/results/' + label + '-' + uuid.uuid4().hex[:8], rtc)
        verdict = {'schema_version': 1, 'case': case, 'mode': mode, 'delta': delta, 'rtc': rtc, 'completed': False, 'qualified': False}
        try:
            exercise(vm, case, mode, delta, verdict)
            verdict['completed'] = True
            if 'unsupported_reason' not in verdict and 'defect_reason' not in verdict:
                verdict['qualified'] = True
        except Exception as e:
            verdict['error'] = str(e)
            try:
                vm.record('failure-diagnostics', vm.call('diagnostics', timeout=3))
            except Exception as diagnostic:
                verdict['diagnostic_error'] = str(diagnostic)
        finally:
            (vm.results / 'verdict.json').write_text(json.dumps(verdict, indent=2) + '\n')
            vm.close()
        summary = {k: verdict[k] for k in ('case', 'mode', 'delta', 'rtc', 'completed', 'qualified')}
        if 'unsupported_reason' in verdict:
            summary['unsupported_reason'] = verdict['unsupported_reason']
        if 'defect_reason' in verdict:
            summary['defect_reason'] = verdict['defect_reason']
        if 'error' in verdict:
            summary['error'] = verdict['error']
        summary['artifact'] = vm.results.name
        verdicts.append(summary)
        Path('/results/verdicts.json').write_text(json.dumps(verdicts, indent=2) + '\n')
        print(json.dumps(summary), flush=True)
    host_after = host_clock()
    host_evidence = {'before': host_before, 'after': host_after,
        'boot_unchanged': host_before['boot_id'] == host_after['boot_id'],
        'wall_minus_monotonic_drift_seconds': ((host_after['wall_ns'] - host_before['wall_ns']) - (host_after['monotonic_ns'] - host_before['monotonic_ns'])) / 1e9,
        'boottime_minus_monotonic_drift_seconds': ((host_after['boottime_ns'] - host_before['boottime_ns']) - (host_after['monotonic_ns'] - host_before['monotonic_ns'])) / 1e9}
    Path('/results/host-isolation.json').write_text(json.dumps(host_evidence, indent=2) + '\n')
    if not host_evidence['boot_unchanged']:
        raise SystemExit('host boot changed; isolation cannot qualify')
    if not all(v['completed'] for v in verdicts):
        raise SystemExit(1)
    if any('defect_reason' in v for v in verdicts):
        raise SystemExit(2)

if __name__ == '__main__':
    main()
