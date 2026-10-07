#!/usr/bin/env python3
"""Host-safe regression tests: never launch QEMU or mutate any clock/power state."""
import io
import json
import unittest
from unittest import mock

import guest_agent
import observer

class IsolationTests(unittest.TestCase):
    def args(self):
        return {'vpnctl_vm_test': '', 'vpnctl_vm_token': 'a' * 32,
                'vpnctl_host_boot': 'host-boot', 'vpnctl_vm_uuid': 'guest-uuid'}

    def guard(self, boot, uuid, args=None):
        def read(path):
            return boot if str(path) == '/proc/sys/kernel/random/boot_id' else uuid
        with mock.patch.object(guest_agent, 'ARGS', self.args() if args is None else args), \
             mock.patch.object(guest_agent, 'TOKEN', 'a' * 32), \
             mock.patch.object(guest_agent.Path, 'read_text', read), \
             mock.patch.object(guest_agent.subprocess, 'run') as run:
            guest_agent.guard()
            run.assert_not_called()

    def test_refuses_same_boot_or_wrong_guest_before_commands(self):
        for boot, uuid in [('host-boot', 'guest-uuid'), ('guest-boot', 'wrong-uuid')]:
            with self.subTest(boot=boot, uuid=uuid), self.assertRaises(RuntimeError):
                self.guard(boot, uuid)

    def test_refuses_unprovisioned_environment(self):
        with self.assertRaises(RuntimeError):
            self.guard('guest-boot', 'guest-uuid', {})

    def test_accepts_only_matching_isolated_guest_identity(self):
        self.guard('guest-boot', 'guest-uuid')

class ObserverTests(unittest.TestCase):
    def test_permissive_gate_is_detected_even_when_tcp_is_blocked_elsewhere(self):
        rows = [{'table': {'name': 'vltest'}},
                {'set': {'table': 'vltest', 'name': 'lease_test', 'elem': [{'elem': {'expires': 4}}]}},
                {'rule': {'table': 'vltest', 'expr': [
                    {'match': {'left': {'meta': {'key': 'time'}}, 'op': '>=', 'right': '2026-10-01 00:00:10'}},
                    {'match': {'left': {'meta': {'key': 'iif'}}, 'op': '!=', 'right': '@lease_test'}}]}}]
        def snapshot():
            return {'kernel': {'at': '2026-10-01T00:00:01Z', 'r0': {'nft -j -n -T list ruleset': json.dumps({'nftables': rows})},
                               'r1': {'nft -j -n -T list ruleset': json.dumps({'nftables': []}), 'wg show all allowed-ips': ''}}}
        self.assertEqual(len(observer.open_lease_guards(snapshot())), 1)
        for extra, expected in [
                ({'state': {'program_id': 1, 'map_id': 2, 'observed_ns': 300, 'deadline_ns': 100}}, 0),
                ({'state': {'program_id': 1, 'map_id': 2, 'observed_ns': 50, 'deadline_ns': 100}}, 1),
                ({'error': 'missing egress', 'state': {'program_id': 1, 'map_id': 2, 'observed_ns': 300, 'deadline_ns': 100}}, 1),
                ({'state': {'observed_ns': 300, 'deadline_ns': 100}}, 1)]:
            evidence = snapshot()
            evidence['kernel']['r0']['bpf_guards'] = {'vdtest': extra}
            self.assertEqual(len(observer.open_lease_guards(evidence)), expected)
        rows[1]['set']['elem'] = []
        self.assertEqual(observer.open_lease_guards(snapshot()), [])
        rows[2]['rule']['expr'].pop()
        with self.assertRaisesRegex(RuntimeError, 'incomplete lease guard evidence'):
            observer.open_lease_guards(snapshot())

    def vm(self, call):
        vm = object.__new__(observer.VM)
        vm.paths = ['p00']
        def dispatch(action, data=None, **kw):
            if action == 'probes':
                return [call('fixture/probe', job, **kw) for job in data['probes']]
            return call(action, data, **kw)
        vm.call = dispatch
        vm.record = mock.Mock()
        return vm

    def test_control_failure_is_not_dataplane_blocked(self):
        vm = self.vm(lambda *a, **kw: {'ok': False, 'error': 'worker unavailable'})
        with self.assertRaisesRegex(RuntimeError, 'missing authenticated probe result'):
            vm.probes(('new',))

    def test_partial_batch_is_not_dataplane_blocked(self):
        vm = self.vm(None)
        vm.call = lambda *a, **kw: []
        with self.assertRaisesRegex(RuntimeError, 'missing authenticated probe results'):
            vm.probes(('new',))

    def test_stale_nonce_and_wrong_source_rejected(self):
        for change in ({'nonce': 'stale'}, {'source': '198.18.0.12'}):
            def call(_, req, **kw):
                return dict(req, ok=True, source='198.18.0.11') | change
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.vm(call).probes(('new',))

    def test_verified_closed_probe_keeps_external_monotonic_bracket(self):
        vm = self.vm(lambda _, req, **kw: dict(req, ok=False, error='timeout'))
        r = vm.probes(('new',))[0]
        self.assertFalse(r['ok'])
        self.assertLessEqual(r['started_monotonic_ns'], r['finished_monotonic_ns'])
        vm.record.assert_called_once()

    def test_corrupt_echo_cannot_qualify_as_blocked(self):
        vm = self.vm(lambda _, req, **kw: dict(req, ok=False, protocol_error=True, error='nonce mismatch'))
        with self.assertRaisesRegex(RuntimeError, 'invalid TCP echo'):
            vm.probes(('new',))

    def test_recovery_records_transport_gap_and_requires_new_evidence(self):
        vm = self.vm(lambda *a, **kw: {'explicit_reinstall': True})
        vm.probes = mock.Mock(side_effect=[ConnectionResetError('control reset'), [{'ok': True}]])
        self.assertEqual(vm.recover(), [{'ok': True}])
        self.assertEqual(vm.probes.call_count, 2)
        self.assertEqual(vm.record.call_args_list[1].args[0], 'recovery-control-gap')

    def test_recovery_does_not_retry_invalid_probe_results(self):
        vm = self.vm(lambda *a, **kw: {'explicit_reinstall': True})
        vm.probes = mock.Mock(side_effect=RuntimeError('missing authenticated probe result'))
        with self.assertRaises(RuntimeError):
            vm.recover()
        self.assertEqual(vm.probes.call_count, 1)

    def test_qmp_events_do_not_count_as_command_completion(self):
        vm = self.vm(None)
        class Stream:
            def __init__(self):
                self.read = io.BytesIO(b'{"event":"STOP"}\n{"return":{"status":"paused"}}\n')
            def write(self, _):
                pass
            def readline(self):
                return self.read.readline()
        vm.qfile = Stream()
        self.assertEqual(vm.command('query-status'), {'status': 'paused'})
        self.assertEqual(vm.record.call_count, 2)
        with self.assertRaises(ValueError):
            vm.command('human-monitor-command')

class StorageEvidenceTests(unittest.TestCase):
    def evidence(self, path, after=False):
        return {'injected': True, 'exit': 1, 'events': [{'path': path, 'injected': True, 'returned_errno': 5, 'after_rename': after}]}

    def test_open_directory_failure_does_not_qualify_atomic_commit(self):
        for kind in ('fsync', 'fsync-dir'):
            with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                guest_agent.validate_fsync_evidence(kind, self.evidence('/cache'), 'open cache: I/O error')

    def test_requires_actual_injection_evidence(self):
        with self.assertRaises(RuntimeError):
            guest_agent.validate_fsync_evidence('fsync', {'events': []}, '')

    def test_accepts_new_file_and_post_rename_failures(self):
        guest_agent.validate_fsync_evidence('fsync', self.evidence('/cache/.pending-abc'), 'I/O error')
        guest_agent.validate_fsync_evidence('fsync-dir', self.evidence('/cache', True), 'file replaced but directory sync failed: I/O error')

class ManagerEvidenceTests(unittest.TestCase):
    def valid(self):
        names = ['baseline', 'nm-reload', 'nm-restart', 'nm-disconnect-reconnect',
                 'netplan-apply', 'networkd-reload', 'networkd-restart',
                 'nm-shared-up', 'nm-shared-down', 'udev-recreate']
        return {'exit': 0, 'report': {'schema_version': 1, 'completed': True,
                'steps': [{'name': n, 'passed': True} for n in names]}}

    def test_skipped_empty_nonzero_and_incomplete_cannot_pass(self):
        for status in ({'exit': 0}, {'exit': 1, 'report': self.valid()['report']},
                       {'exit': None}, {'exit': 0, 'report': {'completed': True}}):
            with self.subTest(status=status), self.assertRaises(RuntimeError):
                observer.validate_manager_result(status)

    def test_duplicate_missing_or_failed_stage_cannot_pass(self):
        for mutation in ('duplicate', 'missing', 'failed', 'incomplete'):
            status = self.valid()
            steps = status['report']['steps']
            if mutation == 'duplicate':
                steps[-1] = steps[0]
            elif mutation == 'missing':
                steps.pop()
            elif mutation == 'failed':
                steps[-1]['passed'] = False
            else:
                status['report']['completed'] = False
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                observer.validate_manager_result(status)

    def test_complete_exact_matrix_passes(self):
        observer.validate_manager_result(self.valid())

class AutoManagerEvidenceTests(unittest.TestCase):
    def valid(self):
        metrics = {'nm-down': 'failover', 'relay0-down': 'failover', 'flap-down-0': 'failover',
                   'flap-down-1': 'failover', 'all-relays-down': 'no-uplink'}
        steps = []
        for name in observer.AUTO_MANAGER_STEPS:
            row = dict(name=name, passed=True, begin_monotonic_ns=1, action_completed_monotonic_ns=2,
                       ready_observed_monotonic_ns=3, end_monotonic_ns=4,
                       traffic={k: {'ok': 1} for k in observer.AUTO_PACKET_KINDS}, metric=metrics.get(name, 'other'))
            if name in metrics:
                row['slo'] = dict(status='pass', elapsed_ms=0.000002, limit_ms=10000)
                timeline = dict(decision_complete=3, routes_completed=3, first_success=3)
                row['timeline'] = timeline.copy()
                row['failover_timeline'] = timeline.copy()
                row['no_uplink_timeline'] = timeline.copy()
                row['no_uplink_evidence_state'] = 'no_verified_path'
                row['previous_path'], row['failover_path'] = 'p00', 'p02'
            steps.append(row)
        report = dict(schema_version=2, completed=True, paths=4, mode='automatic', trace_error='', steps=steps,
                      fresh_generation_confirmed=True, recovery_hysteresis_observed=True, foreign_policy_preserved=True,
                      foreign_peer_preserved=True, fallback_positive_control=True,
                      committed_dwell_monotonic_ns=15_000_000_000, health_hold_down_monotonic_ns=10_000_000_000,
                      packets=[dict(sequence=i, kind=k, begin_monotonic_ns=1, end_monotonic_ns=2)
                               for i, k in enumerate(observer.AUTO_PACKET_KINDS, 1)],
                      cycles=[dict(observed_monotonic_ns=3, diagnostics=dict(monotonic_available=True,
                              started_monotonic_ns=1, finished_monotonic_ns=2,
                              checkpoints=[dict(name='decision_complete', monotonic_ns=2)]))],
                      slo_summary=dict(samples=5, misses=0, unmeasured=0, p95_status='unqualified_insufficient_samples', required_samples_per_class=20))
        return dict(exit=0, report=report)

    def test_complete_functional_matrix_does_not_claim_p95(self):
        observer.validate_manager_auto_result(self.valid(), 4)

    def test_partial_evidence_is_rejected(self):
        mutations = [lambda r: r.update(completed=False), lambda r: r.update(paths=8),
                     lambda r: r.update(trace_error='capacity exceeded'), lambda r: r['steps'].pop(),
                     lambda r: r['packets'].pop(), lambda r: r.update(cycles=[]),
                     lambda r: r['packets'][0].update(sequence=0),
                     lambda r: r['cycles'][0]['diagnostics'].update(checkpoints_dropped=True),
                     lambda r: r['cycles'][0]['diagnostics'].update(monotonic_available=False),
                     lambda r: r['cycles'][0]['diagnostics']['checkpoints'][0].update(monotonic_ns=4),
                     lambda r: r['steps'][0].update(action_completed_monotonic_ns=5),
                     lambda r: r['slo_summary'].update(p95_status='pass'),
                     lambda r: r['steps'][0].update(traffic={}),
                     lambda r: r.update(committed_dwell_monotonic_ns=1),
                     lambda r: r.update(health_hold_down_monotonic_ns=1)]
        for i, mutation in enumerate(mutations):
            status = self.valid()
            mutation(status['report'])
            with self.subTest(i=i), self.assertRaises(RuntimeError):
                observer.validate_manager_auto_result(status, 4)

    def test_miss_is_recorded_but_never_disguised_as_slo_pass(self):
        status = self.valid()
        row = next(s for s in status['report']['steps'] if 'slo' in s)
        row['slo'].update(status='fail', elapsed_ms=51000)
        finish = row['begin_monotonic_ns'] + 51_000_000_000
        key = 'failover_timeline' if row['metric'] == 'failover' else 'no_uplink_timeline'
        row[key]['first_success' if row['metric'] == 'failover' else 'decision_complete'] = finish
        row['ready_observed_monotonic_ns'], row['end_monotonic_ns'] = finish, finish + 1
        status['report']['slo_summary']['misses'] = 1
        observer.validate_manager_auto_result(status, 4)
        row['slo']['status'] = 'pass'
        with self.assertRaisesRegex(RuntimeError, 'false SLO'):
            observer.validate_manager_auto_result(status, 4)

    def test_unmeasured_is_counted_and_never_qualifies_p95(self):
        status = self.valid()
        next(s for s in status['report']['steps'] if 'slo' in s)['slo'].update(status='unmeasured')
        status['report']['slo_summary']['unmeasured'] = 1
        observer.validate_manager_auto_result(status, 4)
        status['report']['slo_summary']['unmeasured'] = 0
        with self.assertRaisesRegex(RuntimeError, 'SLO summary'):
            observer.validate_manager_auto_result(status, 4)

    def test_slo_uses_restoration_instead_of_preferred_convergence(self):
        for change in (lambda s: s.pop('failover_timeline'),
                       lambda s: s.update(failover_path='p00'),
                       lambda s: s['slo'].update(elapsed_ms=1),
                       lambda s: s['failover_timeline'].update(routes_completed=0)):
            status = self.valid()
            row = next(s for s in status['report']['steps'] if s['metric'] == 'failover')
            change(row)
            with self.assertRaisesRegex(RuntimeError, 'restoration timeline'):
                observer.validate_manager_auto_result(status, 4)

    def test_unknown_quarantine_is_not_confirmed_no_uplink(self):
        status = self.valid()
        row = next(s for s in status['report']['steps'] if s['metric'] == 'no-uplink')
        row['no_uplink_evidence_state'] = 'unknown'
        with self.assertRaisesRegex(RuntimeError, 'restoration timeline'):
            observer.validate_manager_auto_result(status, 4)
        row['slo']['status'] = 'unmeasured'
        status['report']['slo_summary']['unmeasured'] = 1
        observer.validate_manager_auto_result(status, 4)

if __name__ == '__main__':
    unittest.main()
