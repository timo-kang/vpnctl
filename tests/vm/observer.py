#!/usr/bin/env python3
"""External monotonic observer for one disposable VM in a bounded container."""
import argparse
import contextlib
import datetime
import hashlib
import json
import math
import os
import re
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
    def __init__(self, work, results, rtc='host', vcpus=1):
        if type(vcpus) is not int or vcpus not in (1, 2):
            raise ValueError('unsupported guest CPU count')
        self.vcpus = vcpus
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
        args = ['qemu-system-x86_64', '-enable-kvm', '-machine', 'pc', '-cpu', 'host', '-smp', str(self.vcpus), '-m', '768',
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

DIRECT_SCOPE = 'actual WG/overlay reachability and local relay fallback; not application target or multi-relay selection SLO'
DIRECT_FLAGS = ('completed', 'relay_probe_independent_process', 'initial_all_pairs_active',
                'startup_supervisor_recovered', 'fallback_overlay_ok', 'udp_success_not_dataplane_success',
                'offline_recovery_verified', 'foreign_routes_preserved', 'concurrent_writer_rejected',
                'corrupt_journal_preserves_kernel', 'offline_restart_recovers_owned_peers',
                'serve_restart_preserves_routes', 'foreign_peer_preserved', 'baseline_config_change_rejected')

def validate_direct_result(status, nodes, fault='outer-wg'):
    fixture_id = f'direct-inner-{nodes}' if fault == 'inner-nonce' else f'direct-{nodes}'
    fixture_prefix = f'direct-dataplane-inner-nonce-{nodes}-' if fault == 'inner-nonce' else f'direct-dataplane-{nodes}-'
    if (fault not in ('outer-wg', 'inner-nonce') or type(nodes) is not int or nodes not in (2, 3, 8, 32) or not isinstance(status, dict)
            or type(status.get('exit')) is not int or status['exit'] != 0
            or status.get('fixture_id') != fixture_id or status.get('fault_mode') != fault
            or status.get('test') != 'TestVMDirectDataplane'
            or type(status.get('nodes')) is not int or status['nodes'] != nodes):
        raise RuntimeError('direct test failed, skipped, or returned the wrong fixture identity')
    reports = status.get('reports')
    if (not isinstance(reports, list) or len(reports) != 1 or not isinstance(reports[0], dict)
            or not isinstance(reports[0].get('fixture'), str)
            or not re.fullmatch(re.escape(fixture_prefix) + r'[0-9]+', reports[0]['fixture'])):
        raise RuntimeError('direct fixture report missing, duplicated, or mismatched')
    row = reports[0]
    report = row.get('report')
    if (not isinstance(report, dict) or type(report.get('nodes')) is not int or report['nodes'] != nodes
            or report.get('fault_mode') != fault or report.get('scope') != DIRECT_SCOPE
            or any(report.get(flag) is not True for flag in DIRECT_FLAGS)):
        raise RuntimeError('direct completion, scope, recovery, or ownership evidence incomplete')
    if fault == 'inner-nonce':
        counters, transport = report.get('inner_fault_counters'), report.get('inner_fault_transport')
        installed = report.get('fault_installed_unix')
        if (report.get('inner_nonce_blackhole_verified') is not True
                or type(installed) is not int or installed <= 0
                or not isinstance(counters, dict) or set(counters) != {'node-0', 'node-1'}
                or not isinstance(transport, dict) or set(transport) != {'node-0', 'node-1'}):
            raise RuntimeError('inner nonce fault evidence incomplete')
        for node in ('node-0', 'node-1'):
            counts, observed = counters[node], transport[node]
            if (not isinstance(counts, dict) or set(counts) != {'payload_drop', 'keepalive_tx', 'keepalive_rx', 'handshake_rx'}
                    or any(type(value) is not int or value <= 0 for value in counts.values())
                    or not isinstance(observed, dict) or set(observed) != {'handshake_unix', 'rx_bytes', 'tx_bytes'}
                    or any(type(value) is not int or value <= 0 for value in observed.values())
                    or observed['handshake_unix'] <= installed):
                raise RuntimeError('inner nonce fault did not preserve fresh authenticated WG transport')
    for name, minimum, maximum in (('fallback_seconds', 0, 5), ('retry_max_observed_loss_seconds', 0, 5),
                                    ('retry_watch_seconds', 12, 15 * 60)):
        value = report.get(name)
        if type(value) not in (int, float) or not math.isfinite(value) or not minimum <= value <= maximum:
            raise RuntimeError('direct timing missing or outside the fixture contract: ' + name)
    if report['fallback_seconds'] == 0:
        raise RuntimeError('direct fallback interval was not measured')
    logs = row.get('logs')
    text = logs.get('retry-packets.jsonl') if isinstance(logs, dict) else None
    if not isinstance(text, str) or not text or len(text.encode()) > 512 * 1024:
        raise RuntimeError('direct retry packet evidence missing or oversized')
    packets = []
    for line in text.splitlines():
        # The unverbose Go worker emits PASS after its JSON samples.
        if not line.strip() or line == 'PASS':
            continue
        try:
            sample = json.loads(line)
        except (ValueError, TypeError) as error:
            raise RuntimeError('invalid direct retry packet evidence') from error
        if not isinstance(sample, dict):
            raise RuntimeError('invalid direct retry packet sample')
        packets.append(sample)
    if not packets:
        raise RuntimeError('direct retry packet evidence is empty')
    last_elapsed, last_good, failures, max_gap = -1, 0, 0, 0
    for index, sample in enumerate(packets, 1):
        elapsed, gap = sample.get('elapsed_ns'), sample.get('gap_ns')
        if (type(sample.get('sequence')) is not int or sample['sequence'] != index
                or type(elapsed) is not int or elapsed < 0 or elapsed < last_elapsed
                or type(gap) is not int or not 0 <= gap <= 5_000_000_000
                or gap != elapsed - last_good or type(sample.get('ok')) is not bool
                or sample.get('completed') is not (index == len(packets))):
            raise RuntimeError('direct retry sequence, interval, or completion evidence invalid')
        last_elapsed, max_gap = elapsed, max(max_gap, gap)
        if sample['ok']:
            last_good = elapsed
        else:
            failures += 1
    if not packets[0]['ok'] or not packets[-1]['ok'] or last_elapsed < 12_000_000_000:
        raise RuntimeError('direct retry fault exposure did not close after twelve seconds')
    if (type(report.get('retry_samples')) is not int or report['retry_samples'] != len(packets)
            or type(report.get('retry_failed_probes')) is not int or report['retry_failed_probes'] != failures
            or not math.isclose(report['retry_max_observed_loss_seconds'], max_gap / 1e9, rel_tol=0, abs_tol=1e-9)
            or not math.isclose(report['retry_watch_seconds'], last_elapsed / 1e9, rel_tol=0, abs_tol=1e-9)):
        raise RuntimeError('direct retry summary does not match packet evidence')

def validate_application_approval_result(status):
    reports = [row.get('report', {}) for row in status.get('reports', [])]
    if (status.get('exit') != 0 or len(reports) != 2
            or {row.get('fault') for row in reports} != {'expiry', 'revocation'}):
        raise RuntimeError('application approval matrix failed or omitted cases')
    for row in reports:
        if (row.get('completed') is not True or row.get('old_and_new_unbound_tcp_blocked') is not True
                or row.get('relay_approvals_live') is not True):
            raise RuntimeError('application approval enforcement evidence incomplete')
        if row['fault'] == 'expiry':
            generation = row.get('isolated_grant_generation')
            if (type(generation) is not int or generation <= 0
                    or row.get('applied_generation') != generation):
                raise RuntimeError('application expiry did not isolate the intended grant')


def validate_robot_capacity(row, paths, cpu, cpu_layout='shared'):
    quota = {'1': '100000 100000', '0.5': '50000 100000', '0.25': '25000 100000'}.get(cpu)
    if not quota or row.get('paths') != paths or row.get('role_placement_verified') is not True:
        raise RuntimeError('missing role capacity configuration or placement')
    if cpu_layout not in ('shared', 'split'):
        raise RuntimeError('unsupported CPU layout')
    validate_capacity_accounting(row, 'resource_profile', quota,
                                 'robot-supervisor-and-two-actuators', 2 if cpu_layout == 'split' else 1,
                                 '0' if cpu_layout == 'split' else None)
    if cpu_layout == 'split':
        validate_capacity_accounting(row, 'server_resource_profile', '100000 100000',
                                     'controller-relays-and-measurement', 2, '1')
        roles = {'supervisor': '0', 'app': '0', 'app2': '0', 'controller': '1',
                 'relay0': '1', 'relay1': '1', 'measurement': '1'}
        for suffix in ('', '_after'):
            placement = row.get('role_cpu_placement' + suffix, {})
            if (set(placement) != set(roles)
                    or any(placement[k].get('cpus') != cpus
                           or type(placement[k].get('threads')) is not int
                           or placement[k]['threads'] <= 0 for k, cpus in roles.items())
                    or row['server_resource_profile' + suffix]['cpu_model'] != row['resource_profile' + suffix]['cpu_model']):
                raise RuntimeError('incomplete or overlapping role CPU placement')


def validate_capacity_accounting(row, prefix, quota, scope, vcpus, cpus):
    stats = []
    models = set()
    for name in (prefix, prefix + '_after'):
        profile = row.get(name, {})
        if (profile.get('scope') != scope
                or profile.get('cpu_max') != quota
                or profile.get('initial_preparation_limited') is not (scope == 'controller-relays-and-measurement')
                or profile.get('controller_relay_measurement_limited') is not (scope == 'controller-relays-and-measurement')
                or not isinstance(profile.get('cpu_model'), str) or not profile['cpu_model'].strip()
                or type(profile.get('guest_vcpus')) is not int or profile['guest_vcpus'] != vcpus
                or cpus is not None and profile.get('cpuset_cpus_effective') != cpus
                or not profile.get('cpu_pressure', '').startswith('some ')):
            raise RuntimeError('incorrect role resource profile')
        models.add(profile['cpu_model'])
        try:
            values = dict(line.split() for line in profile['cpu_stat'].splitlines())
            values = {k: int(values[k]) for k in ('usage_usec', 'nr_periods', 'nr_throttled', 'throttled_usec')}
        except (KeyError, ValueError, AttributeError) as error:
            raise RuntimeError('incomplete role CPU accounting') from error
        if any(v < 0 for v in values.values()):
            raise RuntimeError('invalid role CPU accounting')
        stats.append(values)
    if (len(models) != 1 or stats[1]['usage_usec'] <= stats[0]['usage_usec']
            or any(stats[1][k] < stats[0][k] for k in stats[0])):
        raise RuntimeError('role CPU accounting did not advance')


def validate_application_mixed_result(status, preparation=False, paths=8, robot_cpu=None, cpu_layout='shared'):
    reports = [row.get('report', {}) for row in status.get('reports', [])]
    if (status.get('exit') != 0 or len(reports) != 3
            or paths not in (4, 8)
            or {row.get('healthy_index') for row in reports} != {0, paths // 2 - 1, paths - 1}):
        raise RuntimeError('mixed application matrix failed or omitted cases')
    for row in reports:
        cycles = row.get('steady_applied_cycles', {})
        gaps = row.get('maximum_fresh_observation_gap_seconds', {})
        if (row.get('completed') is not True or row.get('all_candidate_leases_active', row.get('all_eight_leases_active') if paths == 8 else None) is not True
                or row.get('two_actuators_and_payloads_verified') is not True
                or set(cycles) != {'app', 'app2'} or any(type(n) is not int or n < 3 for n in cycles.values())
                or set(gaps) != {'app', 'app2'} or any(not 0 < n <= 10 for n in gaps.values())
                or row.get('steady_seconds', 0) < 15):
            raise RuntimeError('mixed application continuity evidence incomplete')
        if robot_cpu is not None:
            validate_robot_capacity(row, paths, robot_cpu, cpu_layout)
        if preparation:
            path_ids = ('p00', 'p01', 'p02', 'p03', 'p10', 'p11', 'p12', 'p13')
            if (row.get('automatic_rebuild') is not True or row.get('rebuild_completed') is not True
                    or row.get('rebuilt_path') != path_ids[(row['healthy_index'] + 1) % 8]):
                raise RuntimeError('mixed application rebuild evidence incomplete')



def validate_lan_reconfiguration(step):
    lan = step.get('lan_reconfiguration', {})
    done, recovered = (lan.get(key, 0) for key in ('action_completed_monotonic_ns', 'recovered_monotonic_ns'))
    proof = lan.get('payload_verified_monotonic_ns', {})
    if (not 0 < step.get('begin_monotonic_ns', 0) <= done <= recovered
            or recovered - done > 5_000_000_000 or lan.get('watchdog_ms') != 5000
            or type(lan.get('failed_samples')) is not int or lan['failed_samples'] < 0
            or set(proof) != {'172.20.10.2', '172.20.20.2'}
            or any(not done <= at <= recovered for at in proof.values())):
        raise RuntimeError('missing bounded LAN reconfiguration recovery evidence')
    for key, device, source in [('rf_route', 'rf0', '172.20.10.1'), ('gimbal_route', 'gimbal0', '172.20.20.1')]:
        routes = lan.get(key, [])
        if len(routes) != 1 or routes[0].get('dev') != device or routes[0].get('prefsrc') != source:
            raise RuntimeError('LAN route/source not restored')
    return lan


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
    step = next(s for s in steps if s['name'] == 'netplan-apply')
    lan = validate_lan_reconfiguration(step)
    failures = 0
    for target in ('172.20.10.2', '172.20.20.2'):
        before = step.get('traffic_before', {}).get(target, {})
        recovered = step.get('traffic_after_lan_recovery', {}).get(target, {})
        after = step.get('traffic_after', {}).get(target, {})
        if (not all(type(r.get('failed')) is int for r in (before, recovered, after))
                or not before['failed'] <= recovered['failed'] == after['failed']):
            raise RuntimeError('LAN failures continued after manager recovery')
        failures += after['failed'] - before['failed']
    if failures != lan['failed_samples']:
        raise RuntimeError('LAN interruption count mismatch')

AUTO_MANAGER_STEPS = {
    'baseline', 'nm-down', 'relay0-down', 'all-relays-down', 'alternate-recovery',
    'preferred-recovery', 'nm-restart', 'netplan-apply', 'networkd-restart',
    'foreign-firewall-reload', 'flap-down-0', 'flap-up-0', 'flap-down-1', 'flap-up-1',
    'nm-shared-up', 'nm-shared-down', 'foreign-peer-conflict', 'foreign-peer-removed',
    'watch-restart', 'controller-offline-valid',
    'approval-expired-offline', 'fresh-approval-awaiting-relay-apply', 'fresh-approval-recovery',
}
INSTALL_MANAGER_STEPS = {'intent-enrolled', 'intent-controller-offline-valid', 'intent-expired-offline',
                         'intent-offline-relay-restart', 'intent-fresh-approval-recovery'}
AUTO_PACKET_KINDS = {'tcp-new', 'tcp-existing', 'udp', 'independent-app', 'rf-lan', 'gimbal-lan'}

def validate_manager_auto_result(status, paths, installation=False):
    report = status.get('report', {})
    if (status.get('exit') != 0 or report.get('completed') is not True
            or report.get('schema_version') != 2 or report.get('paths') != paths
            or report.get('mode') != 'automatic' or report.get('trace_error') != ''):
        raise RuntimeError('automatic manager test failed or omitted complete evidence')
    steps = report.get('steps', [])
    expected = AUTO_MANAGER_STEPS | (INSTALL_MANAGER_STEPS if installation else set())
    if report.get('installation_mode', False) is not installation:
        raise RuntimeError('incorrect installation test mode')
    if (len(steps) != len(expected) or {s.get('name') for s in steps} != expected
            or any(s.get('passed') is not True for s in steps)):
        raise RuntimeError('missing or failed automatic manager scenarios')
    if installation:
        before, offline, after = (report.get(key, {}) for key in ('installation_before_expiry',
                                  'installation_offline_restart', 'installation_after_recovery'))
        if set(before) != {'r0', 'r1'} or set(offline) != set(before) or set(after) != set(before):
            raise RuntimeError('missing relay installation evidence')
        for relay in before:
            old, new = before[relay].get('installations', []), after[relay].get('installations', [])
            stopped = offline[relay]
            retained = stopped.get('kernel', {}).get('installations', [])
            if (not old or len(old) != paths // 2 or len(new) != len(old)
                    or before[relay].get('kernel_ready') is not True
                    or stopped.get('approval_valid') is not False
                    or stopped.get('kernel', {}).get('endpoints') != []
                    or stopped.get('kernel', {}).get('kernel_ready') is not False
                    or len(retained) != len(old)
                    or len({p.get('endpoint_id') for p in old}) != len(old)
                    or after[relay].get('kernel_ready') is not True):
                raise RuntimeError('incomplete installation expiry/recovery proof')
            for previous, blocked, current in zip(old, retained, new):
                if (not previous.get('endpoint_id') or previous.get('enabled') is not True
                        or previous.get('phase') != 'applied' or previous.get('attempts') != 1
                        or blocked.get('endpoint_id') != previous['endpoint_id']
                        or blocked.get('revision') != previous.get('revision')
                        or blocked.get('enabled') is not True or blocked.get('phase') != 'waiting'
                        or blocked.get('attempts') != previous['attempts']
                        or current.get('endpoint_id') != previous['endpoint_id']
                        or not previous.get('revision') or current.get('revision') != previous['revision']
                        or current.get('enabled') is not True or current.get('phase') != 'applied'
                        or current.get('attempts') != previous.get('attempts', 0) + 1):
                    raise RuntimeError('installation intent changed or retries uncontrolled')
    for key in ('fresh_generation_confirmed', 'recovery_hysteresis_observed', 'foreign_policy_preserved', 'foreign_peer_preserved', 'fallback_positive_control'):
        if report.get(key) is not True:
            raise RuntimeError('missing automatic manager invariant: ' + key)
    if (report.get('committed_dwell_monotonic_ns', 0) < 15_000_000_000
            or report.get('health_hold_down_monotonic_ns', 0) < 10_000_000_000):
        raise RuntimeError('missing monotonic recovery policy evidence')
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
        if step['name'] == 'netplan-apply':
            lan = validate_lan_reconfiguration(step)
            recovered = lan['recovered_monotonic_ns']
            if (lan['action_completed_monotonic_ns'] != step['action_completed_monotonic_ns']
                    or recovered > step['ready_observed_monotonic_ns']):
                raise RuntimeError('LAN recovery clock mismatch')
            failures = 0
            for packet in packets:
                if (packet.get('kind') not in ('rf-lan', 'gimbal-lan')
                        or not step['begin_monotonic_ns'] <= packet['begin_monotonic_ns'] <= step['end_monotonic_ns']):
                    continue
                if packet.get('ok') is False:
                    failures += 1
                    if packet['end_monotonic_ns'] > recovered:
                        raise RuntimeError('LAN failure outside direct reconfiguration window')
            if (failures != lan['failed_samples']
                    or failures != sum(step['traffic'][kind].get('failed', 0) for kind in ('rf-lan', 'gimbal-lan'))):
                raise RuntimeError('LAN interruption count mismatch')
        if step.get('metric') not in ('failover', 'no-uplink'):
            continue
        slo = step.get('slo', {})
        state = slo.get('status')
        if state not in ('pass', 'fail', 'unmeasured') or slo.get('limit_ms') != 10000:
            raise RuntimeError('missing SLO classification')
        if state != 'unmeasured' and (state == 'pass') != (0 <= slo.get('elapsed_ms', -1) <= 10000):
            raise RuntimeError('false SLO classification')
        if state != 'unmeasured':
            failover = step['metric'] == 'failover'
            timeline = step.get('failover_timeline' if failover else 'no_uplink_timeline', {})
            begin = step['begin_monotonic_ns']
            finish = timeline.get('first_success' if failover else 'decision_complete', 0)
            if (not begin < finish <= step['end_monotonic_ns']
                    or timeline.get('decision_complete', 0) < begin
                    or (failover and (timeline.get('routes_completed', 0) < begin
                                      or not step.get('failover_path')
                                      or step['failover_path'] == step.get('previous_path')))
                    or (not failover and step.get('no_uplink_evidence_state') != 'no_verified_path')
                    or abs(slo['elapsed_ms'] - (finish - begin) / 1e6) > 1e-6):
                raise RuntimeError('SLO does not match measured restoration timeline')
        samples.append(slo)
    summary = report.get('slo_summary', {})
    if (len(samples) != 5 or summary.get('samples') != len(samples)
            or summary.get('misses') != sum(s['status'] == 'fail' for s in samples)
            or summary.get('unmeasured') != sum(s['status'] == 'unmeasured' for s in samples)
            or summary.get('p95_status') != 'unqualified_insufficient_samples'
            or summary.get('required_samples_per_class') != 20):
        raise RuntimeError('incomplete or misleading SLO summary')

def exercise(vm, case, mode, delta, result, robot_cpus='0.5', cpu_layout='shared'):
    vm.launch()
    result.update(health=vm.call('health'), qemu_machine=vm.command('query-current-machine'))
    if case == 'boot':
        return result
    if case in ('direct-2', 'direct-3', 'direct-8', 'direct-32', 'direct-inner-2', 'direct-inner-3', 'direct-inner-8', 'direct-inner-32'):
        nodes = int(case.rsplit('-', 1)[1])
        fault = 'inner-nonce' if case.startswith('direct-inner-') else 'outer-wg'
        request = {'nodes': nodes, 'fault': fault} if fault == 'inner-nonce' else {'nodes': nodes}
        vm.call('direct-start', request)
        until = time.monotonic() + 16 * 60
        while time.monotonic() < until:
            status = vm.call('direct-result', request)
            if status.get('exit') is not None:
                result[case] = status
                vm.record(case + '-result', status)
                validate_direct_result(status, nodes, fault=fault)
                return result
            time.sleep(2)
        raise RuntimeError('direct fixture timed out')
    if case in ('application-mixed', 'application-preparation', 'application-approval') or case.startswith('application-capacity-'):
        capacity = case.startswith('application-capacity-')
        action = 'application-capacity' if capacity else case
        paths = int(case.rsplit('-', 1)[1]) if capacity else 8
        vm.call(action + '-start', {'paths': paths, 'robot_cpus': robot_cpus, 'cpu_layout': cpu_layout} if capacity else {})
        until = time.monotonic() + 16 * 60
        while time.monotonic() < until:
            status = vm.call(action + '-result')
            if status['exit'] is not None:
                result[case] = status
                vm.record(case + '-result', status)
                if capacity or case in ('application-mixed', 'application-preparation'):
                    validate_application_mixed_result(status, preparation=case == 'application-preparation', paths=paths, robot_cpu=robot_cpus if capacity else None, cpu_layout=cpu_layout)
                else:
                    validate_application_approval_result(status)
                return result
            time.sleep(2)
        raise RuntimeError('mixed application fixture timed out')
    if case == 'managers' or case.startswith(('manager-auto-', 'manager-install-')):
        automatic = case != 'managers'
        paths = int(case.rsplit('-', 1)[1]) if automatic else 4
        action = 'manager-auto' if automatic else 'managers'
        installation = case.startswith('manager-install-')
        vm.call(action + '-start', {'paths': paths, 'installation': installation} if automatic else {})
        until = time.monotonic() + (21 if automatic else 13) * 60
        while time.monotonic() < until:
            status = vm.call(action + '-result')
            if status['exit'] is not None:
                result[action] = status
                vm.record(action + '-result', status)
                if automatic:
                    validate_manager_auto_result(status, paths, installation)
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

def container_resource_sample(root):
    # Read this QEMU container only. Guest robot counters have a different scope;
    # neither scope establishes a per-role CPU rate without an elapsed interval.
    sample = {'started_monotonic_ns': time.monotonic_ns(), 'unavailable': []}
    for name in ('cpu.max', 'cpu.stat', 'cpu.pressure'):
        try:
            with (root / name).open('rb') as file:
                raw = file.read(4097)
            if len(raw) > 4096:
                raise ValueError('oversized resource evidence')
            value = raw.decode('utf-8').strip()
            if not value:
                raise ValueError('empty resource evidence')
            sample[name.replace('.', '_')] = value
        except (OSError, UnicodeError, ValueError):
            # Diagnostic failure must not hide the original test result or stop
            # VM cleanup. Missing data is explicit, never a zero-usage sample.
            sample['unavailable'].append(name)
    sample['finished_monotonic_ns'] = time.monotonic_ns()
    return sample


@contextlib.contextmanager
def record_container_resources(verdict, root=Path('/sys/fs/cgroup')):
    evidence = {'scope': 'qemu-and-observer-container',
                'interval': 'exercise-including-boot-and-setup',
                'before': container_resource_sample(root)}
    verdict['container_resources'] = evidence
    try:
        yield
    finally:
        evidence['after'] = container_resource_sample(root)


def capacity_vcpus(layout, cases, quota, period):
    try:
        quota, period = int(quota), int(period)
    except ValueError as error:
        raise RuntimeError('finite outer CPU quota required') from error
    if quota <= 0 or period <= 0:
        raise RuntimeError('positive outer CPU quota required')
    if layout == 'shared' and quota <= period:
        return 1
    if (layout == 'split' and cases
            and set(cases) <= {'application-capacity-4', 'application-capacity-8'}
            and quota == 2 * period):
        return 2
    raise RuntimeError('shared layout requires <=1 outer CPU; split requires capacity cases and exactly 2 outer CPUs')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', nargs='+', default=['boot'], choices=['direct-2', 'direct-3', 'direct-8', 'direct-32', 'direct-inner-2', 'direct-inner-3', 'direct-inner-8', 'direct-inner-32', 'application-capacity-4', 'application-capacity-8', 'application-mixed', 'application-preparation', 'application-approval', 'manager-install-4', 'manager-install-8', 'manager-auto-4', 'manager-auto-8', 'managers', 'boot', 'lease', 'clock', 'pause', 'pause-fenced', 'pause-expired', 'suspend', 'reboot', 'reset', 'expiry', 'denied', 'namespace', 'enospc', 'rename', 'fsync', 'fsync-dir', 'downgrade', 'legacy-upgrade', 'lease-v1-downgrade', 'lease-v1-upgrade', 'lease-v2-downgrade', 'lease-v2-upgrade', 'delayed-prepare', 'delayed-commit', 'delayed-rearm', 'delayed-child', 'delayed-group', 'delayed-continuation', 'delayed-suspend', 'matrix'])
    parser.add_argument('--mode', default='stopped', choices=['stopped', 'running'])
    parser.add_argument('--delta', type=int, default=0, choices=[0, -2, -31, -600, 2, 600])
    parser.add_argument('--rtc', default='host', choices=['host', 'vm'])
    parser.add_argument('--robot-cpus', default='0.5', choices=['1', '0.5', '0.25'])
    parser.add_argument('--cpu-layout', default='shared', choices=['shared', 'split'])
    args = parser.parse_args()
    if not Path('/.dockerenv').exists() or set(os.listdir('/sys/class/net')) != {'lo'}:
        raise SystemExit('run only inside the dedicated network-none container')
    caps = next(s.split()[1] for s in Path('/proc/self/status').read_text().splitlines() if s.startswith('CapEff:'))
    if int(caps, 16) != 0:
        raise SystemExit('outer container must drop all capabilities')
    quota, period = Path('/sys/fs/cgroup/cpu.max').read_text().split()
    memory = Path('/sys/fs/cgroup/memory.max').read_text().strip()
    swap = Path('/sys/fs/cgroup/memory.swap.max').read_text().strip()
    vcpus = capacity_vcpus(args.cpu_layout, args.case, quota, period)
    if memory == 'max' or int(memory) > 2 * 1024**3 or swap != '0':
        raise SystemExit('bounded CPU layout, memory<=2GiB, no-swap cgroup v2 required')
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
        'cpu_max': [quota, period], 'cpu_layout': args.cpu_layout, 'guest_vcpus': vcpus, 'memory_max': memory, 'swap_max': swap, 'cap_eff': caps, 'image': image}, indent=2) + '\n')
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
        vm = VM('/work/vm-' + uuid.uuid4().hex[:8], '/results/' + label + '-' + uuid.uuid4().hex[:8], rtc, vcpus)
        verdict = {'schema_version': 1, 'case': case, 'mode': mode, 'delta': delta, 'rtc': rtc, 'completed': False, 'qualified': False}
        try:
            with record_container_resources(verdict):
                exercise(vm, case, mode, delta, verdict, args.robot_cpus, args.cpu_layout)
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
