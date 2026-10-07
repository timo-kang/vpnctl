#!/usr/bin/env python3
"""Host-safe regression tests: never launch QEMU or mutate any clock/power state."""
import io
import json
import tempfile
from pathlib import Path
import unittest
from unittest import mock

import guest_agent
import observer

def lan_reconfiguration_evidence():
    return dict(action_completed_monotonic_ns=2, recovered_monotonic_ns=3,
                watchdog_ms=5000, failed_samples=0,
                payload_verified_monotonic_ns={'172.20.10.2': 3, '172.20.20.2': 3},
                rf_route=[dict(dev='rf0', prefsrc='172.20.10.1')],
                gimbal_route=[dict(dev='gimbal0', prefsrc='172.20.20.1')])

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
        steps = [{'name': n, 'passed': True} for n in names]
        netplan = next(s for s in steps if s['name'] == 'netplan-apply')
        netplan.update(begin_monotonic_ns=1, lan_reconfiguration=lan_reconfiguration_evidence())
        for key in ('traffic_before', 'traffic_after_lan_recovery', 'traffic_after'):
            netplan[key] = {target: dict(failed=0) for target in ('172.20.10.2', '172.20.20.2')}
        return {'exit': 0, 'report': {'schema_version': 1, 'completed': True, 'steps': steps}}

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

    def test_lan_failure_is_measured_only_during_direct_reconfiguration(self):
        status = self.valid()
        step = next(s for s in status['report']['steps'] if s['name'] == 'netplan-apply')
        step['lan_reconfiguration']['failed_samples'] = 1
        for key in ('traffic_after_lan_recovery', 'traffic_after'):
            step[key]['172.20.20.2']['failed'] = 1
        observer.validate_manager_result(status)
        step['traffic_after']['172.20.20.2']['failed'] = 2
        with self.assertRaises(RuntimeError):
            observer.validate_manager_result(status)

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
            if name == 'netplan-apply':
                row['lan_reconfiguration'] = lan_reconfiguration_evidence()
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

    def test_lan_reconfiguration_records_losses_without_hiding_late_failure(self):
        status = self.valid()
        step = next(s for s in status['report']['steps'] if s['name'] == 'netplan-apply')
        sample = next(p for p in status['report']['packets'] if p['kind'] == 'gimbal-lan')
        sample['ok'] = False
        step['traffic']['gimbal-lan'] = dict(failed=1)
        step['lan_reconfiguration']['failed_samples'] = 1
        observer.validate_manager_auto_result(status, 4)
        sample['end_monotonic_ns'] = 4
        with self.assertRaisesRegex(RuntimeError, 'outside direct reconfiguration'):
            observer.validate_manager_auto_result(status, 4)

    def test_lan_recovery_needs_routes_payloads_and_bounded_clock(self):
        for mutate in (lambda r: r.pop('lan_reconfiguration'),
                       lambda r: r['lan_reconfiguration'].update(recovered_monotonic_ns=5_000_000_003),
                       lambda r: r['lan_reconfiguration'].update(payload_verified_monotonic_ns={}),
                       lambda r: r['lan_reconfiguration'].update(rf_route=[]),
                       lambda r: r['lan_reconfiguration'].update(gimbal_route=[dict(dev='wan0', prefsrc='172.20.20.1')]),
                       lambda r: r['lan_reconfiguration'].update(failed_samples=1)):
            status = self.valid()
            step = next(s for s in status['report']['steps'] if s['name'] == 'netplan-apply')
            mutate(step)
            with self.assertRaises(RuntimeError):
                observer.validate_manager_auto_result(status, 4)

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

class InstallationEvidenceTests(unittest.TestCase):
    def valid(self):
        status = AutoManagerEvidenceTests().valid()
        report = status['report']
        report['installation_mode'] = True
        report['steps'] += [dict(name=name, passed=True, begin_monotonic_ns=1, action_completed_monotonic_ns=2,
                            ready_observed_monotonic_ns=3, end_monotonic_ns=4, metric='authority',
                            traffic={k: {'ok': 1} for k in observer.AUTO_PACKET_KINDS})
                            for name in observer.INSTALL_MANAGER_STEPS]
        old = [dict(endpoint_id='ep'+str(i), revision='revision'+str(i), enabled=True, phase='applied', attempts=1)
               for i in range(2)]
        report['installation_before_expiry'] = {r: dict(kernel_ready=True, installations=[p.copy() for p in old]) for r in ('r0', 'r1')}
        report['installation_offline_restart'] = {r: dict(approval_valid=False,
                    kernel=dict(endpoints=[], kernel_ready=False, installations=[dict(p, phase='waiting') for p in old])) for r in ('r0', 'r1')}
        report['installation_after_recovery'] = {r: dict(kernel_ready=True,
                    installations=[dict(p, attempts=2) for p in old]) for r in ('r0', 'r1')}
        return status

    def test_complete_installation_matrix(self):
        observer.validate_manager_auto_result(self.valid(), 4, True)

    def test_manual_or_incomplete_evidence_does_not_qualify(self):
        mutations = [lambda r: r.pop('installation_mode'), lambda r: r['steps'].pop(),
                     lambda r: r['installation_before_expiry']['r0'].update(kernel_ready=False),
                     lambda r: r['installation_before_expiry']['r0']['installations'][0].update(attempts=0),
                     lambda r: r['installation_offline_restart']['r0']['kernel']['installations'][0].update(revision='new'),
                     lambda r: r['installation_offline_restart']['r0']['kernel']['installations'][0].update(attempts=2),
                     lambda r: r['installation_offline_restart']['r0']['kernel']['installations'][0].update(enabled=False),
                     lambda r: r['installation_offline_restart']['r0']['kernel']['installations'][0].update(phase='applied'),
                     lambda r: r['installation_offline_restart']['r0']['kernel'].update(endpoints=[{}]),
                     lambda r: r['installation_offline_restart']['r0'].update(approval_valid=True),
                     lambda r: r['installation_after_recovery']['r0']['installations'][0].update(revision='new'),
                     lambda r: r['installation_after_recovery']['r0']['installations'][0].update(attempts=3),
                     lambda r: r['installation_after_recovery']['r0'].update(kernel_ready=False)]
        for mutate in mutations:
            status = self.valid()
            mutate(status['report'])
            with self.assertRaises(RuntimeError):
                observer.validate_manager_auto_result(status, 4, True)
        with self.assertRaises(RuntimeError):
            observer.validate_manager_auto_result(self.valid(), 4)

class ApplicationMixedEvidenceTests(unittest.TestCase):
    def valid(self):
        return dict(exit=0, reports=[dict(report=dict(healthy_index=i, completed=True,
                    all_eight_leases_active=True, two_actuators_and_payloads_verified=True,
                    steady_seconds=15, steady_applied_cycles=dict(app=3, app2=3),
                    maximum_fresh_observation_gap_seconds=dict(app=2, app2=2))) for i in (0, 3, 7)])

    def test_complete_matrix(self):
        observer.validate_application_mixed_result(self.valid())

    def test_failure_partial_and_stale_cannot_pass(self):
        for change in (lambda s: s.update(exit=1), lambda s: s['reports'].pop(),
                       lambda s: s['reports'][2]['report'].update(healthy_index=0),
                       lambda s: s['reports'][0]['report'].update(completed=False),
                       lambda s: s['reports'][0]['report'].update(all_eight_leases_active=False),
                       lambda s: s['reports'][0]['report'].update(steady_seconds=14),
                       lambda s: s['reports'][0]['report'].update(steady_applied_cycles=dict(app=2, app2=3)),
                       lambda s: s['reports'][0]['report'].update(maximum_fresh_observation_gap_seconds=dict(app=10.01, app2=2))):
            status = self.valid()
            change(status)
            with self.assertRaises(RuntimeError):
                observer.validate_application_mixed_result(status)


class ApplicationRobotCapacityEvidenceTests(unittest.TestCase):
    def valid(self, paths):
        status = ApplicationMixedEvidenceTests().valid()
        for row, index in zip(status['reports'], (0, paths // 2 - 1, paths - 1)):
            report = row['report']
            report.update(paths=paths, healthy_index=index, all_candidate_leases_active=True,
                          role_placement_verified=True)
            for name, usage in (('resource_profile', 10), ('resource_profile_after', 20)):
                report[name] = dict(scope='robot-supervisor-and-two-actuators', cpu_max='50000 100000',
                                    cpu_model='test-cpu', guest_vcpus=1,
                                    initial_preparation_limited=False, controller_relay_measurement_limited=False,
                                    cpu_pressure='some avg10=0.0 total=0',
                                    cpu_stat=f'usage_usec {usage}\nnr_periods 5\nnr_throttled 0\nthrottled_usec 0')
        return status

    def test_both_path_profiles(self):
        for paths in (4, 8):
            observer.validate_application_mixed_result(self.valid(paths), paths=paths, robot_cpu='0.5')

    def test_unproven_or_wrong_resource_scope_fails(self):
        changes = [lambda r: r.update(role_placement_verified=False),
                   lambda r: r.update(paths=4),
                   lambda r: r.pop('resource_profile_after'),
                   lambda r: r['resource_profile'].update(cpu_max='max 100000'),
                   lambda r: r['resource_profile_after'].update(cpu_max='100000 100000'),
                   lambda r: r['resource_profile'].update(scope='whole-vm'),
                   lambda r: r['resource_profile'].pop('cpu_model'),
                   lambda r: r['resource_profile_after'].update(cpu_model='different'),
                   lambda r: r['resource_profile'].update(guest_vcpus=2),
                   lambda r: r['resource_profile'].update(initial_preparation_limited=True),
                   lambda r: r['resource_profile'].update(controller_relay_measurement_limited=True),
                   lambda r: r['resource_profile_after'].update(cpu_stat='usage_usec 20'),
                   lambda r: r['resource_profile_after'].update(cpu_stat=r['resource_profile']['cpu_stat']),
                   lambda r: r['resource_profile_after'].update(cpu_pressure='')]
        for change in changes:
            status = self.valid(8)
            change(status['reports'][0]['report'])
            with self.assertRaises(RuntimeError):
                observer.validate_application_mixed_result(status, paths=8, robot_cpu='0.5')
        with self.assertRaises(RuntimeError):
            observer.validate_application_mixed_result(self.valid(8), paths=8, robot_cpu='0.25')


class ApplicationPreparationEvidenceTests(ApplicationMixedEvidenceTests):
    def valid(self):
        status = super().valid()
        paths = ('p00', 'p01', 'p02', 'p03', 'p10', 'p11', 'p12', 'p13')
        for row in status['reports']:
            report = row['report']
            report.update(automatic_rebuild=True, rebuild_completed=True,
                          rebuilt_path=paths[(report['healthy_index'] + 1) % 8])
        return status

    def test_rebuild_complete_matrix(self):
        observer.validate_application_mixed_result(self.valid(), preparation=True)

    def test_rebuild_missing_wrong_path_or_manual_fails(self):
        for change in (lambda r: r.pop('rebuilt_path'),
                       lambda r: r.update(rebuilt_path='p00'),
                       lambda r: r.update(automatic_rebuild=False),
                       lambda r: r.update(rebuild_completed=False)):
            status = self.valid()
            change(status['reports'][0]['report'])
            with self.assertRaisesRegex(RuntimeError, 'rebuild evidence'):
                observer.validate_application_mixed_result(status, preparation=True)


class ApplicationApprovalEvidenceTests(unittest.TestCase):
    def valid(self):
        return dict(exit=0, reports=[dict(report=dict(fault=fault, completed=True,
                    old_and_new_unbound_tcp_blocked=True, relay_approvals_live=True,
                    isolated_grant_generation=12, applied_generation=12)) for fault in ('expiry', 'revocation')])

    def test_complete_approval_matrix(self):
        observer.validate_application_approval_result(self.valid())

    def test_missing_stale_or_false_evidence_fails(self):
        for change in (lambda s: s.update(exit=1), lambda s: s['reports'].pop(),
                       lambda s: s['reports'][0]['report'].update(fault='revocation'),
                       lambda s: s['reports'][0]['report'].update(completed=False),
                       lambda s: s['reports'][0]['report'].update(applied_generation=11),
                       lambda s: s['reports'][0]['report'].update(relay_approvals_live=False),
                       lambda s: s['reports'][1]['report'].update(old_and_new_unbound_tcp_blocked=False)):
            status = self.valid()
            change(status)
            with self.assertRaises(RuntimeError):
                observer.validate_application_approval_result(status)



class DirectEvidenceTests(unittest.TestCase):
    def valid(self, nodes=2):
        packets = [dict(sequence=i, elapsed_ns=elapsed, gap_ns=gap, ok=True, completed=i == 4)
                   for i, elapsed, gap in ((1, 1_000_000, 1_000_000), (2, 4_000_000_000, 3_999_000_000),
                                           (3, 8_000_000_000, 4_000_000_000), (4, 12_000_000_000, 4_000_000_000))]
        report = dict(nodes=nodes, fault_mode='outer-wg', completed=True,
                      scope='actual WG/overlay reachability and local relay fallback; not application target or multi-relay selection SLO',
                      fallback_seconds=2.5, retry_max_observed_loss_seconds=4,
                      retry_watch_seconds=12, retry_samples=4, retry_failed_probes=0,
                      relay_probe_independent_process=True, initial_all_pairs_active=True,
                      startup_supervisor_recovered=True, fallback_overlay_ok=True,
                      udp_success_not_dataplane_success=True, offline_recovery_verified=True,
                      foreign_routes_preserved=True, concurrent_writer_rejected=True,
                      corrupt_journal_preserves_kernel=True, offline_restart_recovers_owned_peers=True,
                      serve_restart_preserves_routes=True, foreign_peer_preserved=True,
                      baseline_config_change_rejected=True)
        return dict(exit=0, fixture_id=f'direct-{nodes}', test='TestVMDirectDataplane', nodes=nodes, fault_mode='outer-wg',
                    reports=[dict(fixture=f'direct-dataplane-{nodes}-12345', report=report,
                                  logs={'retry-packets.jsonl': '\n'.join(map(json.dumps, packets)) + '\nPASS\n'})])

    def test_all_explicit_profiles_pass(self):
        for nodes in (2, 3, 8, 32):
            with self.subTest(nodes=nodes):
                observer.validate_direct_result(self.valid(nodes), nodes)

    def test_exit_zero_does_not_qualify_missing_or_wrong_fixture(self):
        changes = [lambda s: s.update(exit=1), lambda s: s.update(exit=None),
                   lambda s: s.update(exit=False), lambda s: s.update(reports=[]),
                   lambda s: s['reports'].append(s['reports'][0]),
                   lambda s: s.update(fixture_id='direct-8'), lambda s: s.update(nodes=3),
                   lambda s: s.update(test='TestNetns_DirectDataplane'),
                   lambda s: s['reports'][0].update(fixture='direct-dataplane-8-12345'),
                   lambda s: s['reports'][0].update(fixture='../private'),
                   lambda s: s['reports'][0].update(report={})]
        for change in changes:
            status = self.valid()
            change(status)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                observer.validate_direct_result(status, 2)
        with self.assertRaises(RuntimeError):
            observer.validate_direct_result({'exit': 0}, 2)

    def test_every_completion_flag_and_exact_scope_are_required(self):
        original = self.valid()['reports'][0]['report']
        for key, value in original.items():
            if type(value) is not bool:
                continue
            for missing in (False, True):
                status = self.valid()
                report = status['reports'][0]['report']
                report.pop(key) if missing else report.update({key: False})
                with self.subTest(key=key, missing=missing), self.assertRaises(RuntimeError):
                    observer.validate_direct_result(status, 2)
        for key, value in (('nodes', 8), ('nodes', True), ('scope', 'application SLO')):
            status = self.valid()
            status['reports'][0]['report'][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                observer.validate_direct_result(status, 2)

    def test_invalid_or_missing_timing_cannot_qualify(self):
        for key in ('fallback_seconds', 'retry_max_observed_loss_seconds', 'retry_watch_seconds'):
            for value in (None, True, '4', float('nan'), float('inf'), -1):
                status = self.valid()
                status['reports'][0]['report'][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                    observer.validate_direct_result(status, 2)
        for key, value in (('fallback_seconds', 5.01), ('retry_max_observed_loss_seconds', 5.01),
                           ('retry_watch_seconds', 11.99), ('retry_samples', 0), ('retry_failed_probes', 1)):
            status = self.valid()
            status['reports'][0]['report'][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                observer.validate_direct_result(status, 2)

    def test_packet_sequence_completion_and_report_must_agree(self):
        changes = [lambda p: p.pop(), lambda p: p[0].update(ok=False),
                   lambda p: p[-1].update(ok=False), lambda p: p[-1].update(completed=False),
                   lambda p: p[1].update(completed=True), lambda p: p[1].update(sequence=1),
                   lambda p: p[2].update(elapsed_ns=2), lambda p: p[-1].update(elapsed_ns=11_000_000_000),
                   lambda p: p[-1].update(gap_ns=5_000_000_001), lambda p: p[-1].update(gap_ns=0),
                   lambda p: p[0].update(ok=1)]
        for change in changes:
            status = self.valid()
            logs = status['reports'][0]['logs']
            packets = [json.loads(line) for line in logs['retry-packets.jsonl'].splitlines() if line.startswith('{')]
            change(packets)
            logs['retry-packets.jsonl'] = '\n'.join(map(json.dumps, packets))
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                observer.validate_direct_result(status, 2)
        for text in ('', 'PASS', '{malformed', 'FAIL'):
            status = self.valid()
            status['reports'][0]['logs']['retry-packets.jsonl'] = text
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                observer.validate_direct_result(status, 2)

    def test_direct_case_dispatches_exact_profile_without_default_fixture(self):
        vm = mock.Mock()
        vm.call.side_effect = [{}, {'started': True}, self.valid(3)]
        result = observer.exercise(vm, 'direct-3', 'stopped', 0, {})
        self.assertEqual(vm.call.call_args_list[1], mock.call('direct-start', {'nodes': 3}))
        self.assertEqual(vm.call.call_args_list[2], mock.call('direct-result', {'nodes': 3}))
        vm.start_fixture.assert_not_called()
        self.assertEqual(result['direct-3']['fixture_id'], 'direct-3')

class DirectInnerEvidenceTests(unittest.TestCase):
    def valid(self, nodes=2):
        status = DirectEvidenceTests().valid(nodes)
        status.update(fixture_id=f'direct-inner-{nodes}', fault_mode='inner-nonce')
        row = status['reports'][0]
        row['fixture'] = f'direct-dataplane-inner-nonce-{nodes}-12345'
        row['report'].update(fault_mode='inner-nonce', inner_nonce_blackhole_verified=True,
                             fault_installed_unix=100,
                             inner_fault_counters={node: dict(payload_drop=3, keepalive_tx=2, keepalive_rx=1, handshake_rx=1)
                                                   for node in ('node-0', 'node-1')},
                             inner_fault_transport={node: dict(handshake_unix=101, rx_bytes=32, tx_bytes=64)
                                                    for node in ('node-0', 'node-1')})
        return status

    def test_each_size_requires_explicit_inner_fault_evidence(self):
        for nodes in (2, 3, 8, 32):
            observer.validate_direct_result(self.valid(nodes), nodes, fault='inner-nonce')
        with self.assertRaises(RuntimeError):
            observer.validate_direct_result(DirectEvidenceTests().valid(), 2, fault='inner-nonce')
        with self.assertRaises(RuntimeError):
            observer.validate_direct_result(self.valid(), 2)

    def test_missing_or_unexercised_inner_fault_is_rejected(self):
        changes = [lambda s: s.update(fault_mode='outer-wg'),
                   lambda s: s['reports'][0]['report'].update(fault_mode='outer-wg'),
                   lambda s: s['reports'][0]['report'].pop('inner_nonce_blackhole_verified'),
                   lambda s: s['reports'][0]['report'].update(inner_nonce_blackhole_verified=False),
                   lambda s: s['reports'][0]['report']['inner_fault_counters'].pop('node-1'),
                   lambda s: s['reports'][0]['report']['inner_fault_counters']['node-0'].update(payload_drop=0),
                   lambda s: s['reports'][0]['report']['inner_fault_counters']['node-0'].update(keepalive_rx=True),
                   lambda s: s['reports'][0]['report']['inner_fault_counters']['node-1'].pop('handshake_rx'),
                   lambda s: s['reports'][0]['report']['inner_fault_transport'].pop('node-1'),
                   lambda s: s['reports'][0]['report']['inner_fault_transport']['node-0'].update(handshake_unix=100),
                   lambda s: s['reports'][0]['report']['inner_fault_transport']['node-1'].update(rx_bytes=0),
                   lambda s: s['reports'][0]['report'].pop('fault_installed_unix')]
        for change in changes:
            status = self.valid()
            change(status)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                observer.validate_direct_result(status, 2, fault='inner-nonce')

    def test_inner_case_dispatches_explicit_fault(self):
        vm = mock.Mock()
        vm.call.side_effect = [{}, {'started': True}, self.valid(8)]
        observer.exercise(vm, 'direct-inner-8', 'stopped', 0, {})
        self.assertEqual(vm.call.call_args_list[1], mock.call('direct-start', {'nodes': 8, 'fault': 'inner-nonce'}))
        self.assertEqual(vm.call.call_args_list[2], mock.call('direct-result', {'nodes': 8, 'fault': 'inner-nonce'}))
        vm.start_fixture.assert_not_called()

class DirectGuestTests(unittest.TestCase):
    def lifecycle_line(self, state='handshaking', reason='relay_route_preserved', suffix=''):
        return ('time=2026-10-07T09:06:58.445Z level=INFO msg="direct dataplane" '
                f'peer=node-1 state={state} reason="{reason}" generation={"a" * 32}{suffix}\n')

    def test_lifecycle_export_preserves_initial_transition_after_warning_noise(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(guest_agent, 'ROOT', Path(root)), \
             mock.patch.object(guest_agent, 'guard'), mock.patch.object(guest_agent, 'DIRECT_NODES', 2), \
             mock.patch.object(guest_agent, 'WORKER') as worker:
            worker.poll.return_value = 1
            fixture = Path(root) / 'results/direct-dataplane-2-12345'
            fixture.mkdir(parents=True)
            (fixture / 'report.json').write_text('{"completed": false}')
            (fixture / 'agent-0.log').write_text(self.lifecycle_line() + 'controller offline warning\n' * 4000 +
                                                self.lifecycle_line('active', ''))
            result = guest_agent.direct_result({'nodes': 2})['reports'][0]
            self.assertNotIn('state=handshaking', result['logs']['agent-0.log'])
            lifecycle = result['lifecycle']['agent-0.log']
            self.assertEqual([e['state'] for e in lifecycle['events']], ['handshaking', 'active'])
            self.assertFalse(lifecycle['scan_truncated'])
            self.assertFalse(lifecycle['events_truncated'])
            self.assertEqual(lifecycle['scanned_bytes'], lifecycle['source_bytes'])

    def test_lifecycle_export_whitelists_fields_and_rejects_secret_lines(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(guest_agent, 'ROOT', Path(root)):
            log = Path(root) / 'results/direct-dataplane-2-12345/agent-0.log'
            log.parent.mkdir(parents=True)
            log.write_text(self.lifecycle_line() + self.lifecycle_line(suffix=' token=secret-token') +
                           self.lifecycle_line(reason='private_secret') + self.lifecycle_line(suffix=' unexpected=secret') +
                           self.lifecycle_line().replace('peer=node-1', 'peer=secret-name'))
            result = guest_agent.direct_lifecycle(log)
            self.assertEqual(len(result['events']), 1)
            self.assertEqual(set(result['events'][0]), {'time', 'peer', 'state', 'reason', 'generation'})
            self.assertNotIn('secret', json.dumps(result))
            self.assertEqual(result['redacted_lines'], 2)
            self.assertEqual(result['malformed_lines'], 2)

    def test_lifecycle_skips_entire_oversize_line_and_resumes(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(guest_agent, 'ROOT', Path(root)):
            log = Path(root) / 'results/direct-dataplane-2-12345/agent-0.log'
            log.parent.mkdir(parents=True)
            log.write_bytes(self.lifecycle_line().rstrip().encode() + b'x' * 20000 + b' token=secret\n' +
                            self.lifecycle_line('active', '').encode() + b'\xff malformed\n')
            result = guest_agent.direct_lifecycle(log)
            self.assertEqual([e['state'] for e in result['events']], ['active'])
            self.assertEqual(result['long_lines_skipped'], 1)
            self.assertNotIn('secret', json.dumps(result))

    def test_lifecycle_scan_bound_is_explicit_and_discards_cut_line(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(guest_agent, 'ROOT', Path(root)), \
             mock.patch.object(guest_agent, 'DIRECT_LIFECYCLE_SCAN_BYTES', 500):
            log = Path(root) / 'results/direct-dataplane-2-12345/agent-0.log'
            log.parent.mkdir(parents=True)
            log.write_text(self.lifecycle_line() + 'x' * 1000 + '\n' + self.lifecycle_line('active', ''))
            result = guest_agent.direct_lifecycle(log)
            self.assertTrue(result['scan_truncated'])
            self.assertEqual(result['scanned_bytes'], 500)
            self.assertEqual([e['state'] for e in result['events']], ['handshaking'])

    def test_lifecycle_event_bound_preserves_first_and_last_transitions(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(guest_agent, 'ROOT', Path(root)), \
             mock.patch.object(guest_agent, 'DIRECT_LIFECYCLE_EVENTS', 4):
            log = Path(root) / 'results/direct-dataplane-2-12345/agent-0.log'
            log.parent.mkdir(parents=True)
            states = ['handshaking', 'probing', 'active', 'relay_unverified', 'cooldown', 'handshaking']
            log.write_text(''.join(self.lifecycle_line(s) for s in states))
            result = guest_agent.direct_lifecycle(log)
            self.assertEqual([e['state'] for e in result['events']], states[:2] + states[-2:])
            self.assertTrue(result['events_truncated'])
            self.assertEqual(result['events_omitted'], 2)

    def test_lifecycle_tiny_line_flood_has_a_scan_work_bound(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(guest_agent, 'ROOT', Path(root)), \
             mock.patch.object(guest_agent, 'DIRECT_LIFECYCLE_SCAN_LINES', 4):
            log = Path(root) / 'results/direct-dataplane-2-12345/agent-0.log'
            log.parent.mkdir(parents=True)
            log.write_text('\n' * 10 + self.lifecycle_line())
            result = guest_agent.direct_lifecycle(log)
            self.assertEqual(result['lines_scanned'], 4)
            self.assertEqual(result['scanned_bytes'], 4)
            self.assertTrue(result['scan_truncated'])
            self.assertEqual(result['events'], [])

    def test_lifecycle_handles_unquoted_reasons_missing_generation_and_final_line(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(guest_agent, 'ROOT', Path(root)):
            log = Path(root) / 'results/direct-dataplane-2-12345/agent-0.log'
            log.parent.mkdir(parents=True)
            log.write_text('time=2026-10-07T09:06:58Z level=INFO msg="direct dataplane" '
                           'peer=node-31 state=pending reason=candidate_changed\n' +
                           self.lifecycle_line().replace('reason="relay_route_preserved"',
                                                         'reason=relay_route_preserved').rstrip())
            result = guest_agent.direct_lifecycle(log)
            self.assertEqual(len(result['events']), 2)
            self.assertNotIn('generation', result['events'][0])
            self.assertEqual(result['events'][1]['reason'], 'relay_route_preserved')
            self.assertFalse(result['scan_truncated'])

    def test_lifecycle_default_output_is_bounded_and_nonregular_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(guest_agent, 'ROOT', Path(root)):
            fixture = Path(root) / 'results/direct-dataplane-2-12345'
            fixture.mkdir(parents=True)
            log = fixture / 'agent-0.log'
            log.write_text(self.lifecycle_line(reason='x' * 64) * 2000)
            result = guest_agent.direct_lifecycle(log)
            self.assertEqual(len(result['events']), 512)
            self.assertLessEqual(len(json.dumps(result).encode()), 160 * 1024)
            directory = fixture / 'agent-1.log'
            directory.mkdir()
            with self.assertRaisesRegex(RuntimeError, 'regular file'):
                guest_agent.direct_lifecycle(directory)
            fifo = fixture / 'agent-2.log'
            guest_agent.os.mkfifo(fifo)
            with self.assertRaisesRegex(RuntimeError, 'regular file'):
                guest_agent.direct_lifecycle(fifo)

    def test_lifecycle_rejects_symlinks_and_nonpublic_names(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(guest_agent, 'ROOT', Path(root)):
            fixture = Path(root) / 'results/direct-dataplane-2-12345'
            fixture.mkdir(parents=True)
            private = Path(root) / 'private.log'
            private.write_text('token=secret')
            log = fixture / 'agent-0.log'
            log.symlink_to(private)
            for path in (log, private, fixture / 'node.yaml'):
                with self.subTest(path=path.name), self.assertRaises(RuntimeError):
                    guest_agent.direct_lifecycle(path)
            linked = Path(root) / 'results/direct-dataplane-2-linked'
            linked.symlink_to(fixture, target_is_directory=True)
            with self.assertRaises(RuntimeError):
                guest_agent.direct_lifecycle(linked / 'agent-0.log')

    def test_requires_one_explicit_supported_size_before_launch(self):
        with mock.patch.object(guest_agent, 'guard'), mock.patch.object(guest_agent.subprocess, 'Popen') as launch:
            for req in ({}, {'nodes': True}, {'nodes': 4}, {'nodes': '2'}, {'nodes': '2,8'}, {'nodes': [2, 8]}):
                with self.subTest(req=req), self.assertRaises(ValueError):
                    guest_agent.start_direct(req)
            launch.assert_not_called()

    def test_direct_worker_failure_log_is_bounded_and_sanitized(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(guest_agent, 'ROOT', Path(root)), \
             mock.patch.object(guest_agent, 'guard'), mock.patch.object(guest_agent, 'DIRECT_NODES', 2), \
             mock.patch.object(guest_agent, 'WORKER') as worker:
            worker.poll.return_value = 1
            (Path(root) / 'worker.log').write_text('x' * 40000 + '\noptional diagnostic unavailable\ntoken=secret\nFAIL\n')
            status = guest_agent.direct_result({'nodes': 2})
            self.assertEqual(status['exit'], 1)
            self.assertIn('optional diagnostic unavailable', status['worker_log'])
            self.assertIn('FAIL', status['worker_log'])
            self.assertNotIn('secret', status['worker_log'])
            self.assertLessEqual(len(status['worker_log'].encode()), 32768)

    def test_guest_launch_binds_inner_fault_mode(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(guest_agent, 'ROOT', Path(root)), \
             mock.patch.object(guest_agent, 'guard'), mock.patch.object(guest_agent, 'WORKER', None), \
             mock.patch.object(guest_agent, 'DIRECT_NODES', None), \
             mock.patch.object(guest_agent, 'DIRECT_FAULT', 'outer-wg'), \
             mock.patch.object(guest_agent.subprocess, 'Popen') as launch:
            result = guest_agent.start_direct({'nodes': 3, 'fault': 'inner-nonce'})
            self.assertEqual(result['fixture_id'], 'direct-inner-3')
            self.assertEqual(launch.call_args.kwargs['env']['VPNCTL_DIRECT_FAULT'], 'inner-nonce')
            with self.assertRaises(ValueError):
                guest_agent.direct_result({'nodes': 3})
            with self.assertRaises(ValueError):
                guest_agent.start_direct({'nodes': 3, 'fault': 'all'})

    def test_redacted_log_output_remains_bounded(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(guest_agent, 'ROOT', Path(root)):
            fixture = Path(root) / 'results/direct-dataplane-2-12345'
            fixture.mkdir(parents=True)
            log = fixture / 'agent-0.log'
            log.write_text('key\n' * 8192)
            safe = guest_agent.direct_artifact(log, 32768, tail=True)
            self.assertLessEqual(len(safe.encode()), 32768)
            self.assertNotIn('key', safe)

    def test_guard_blocks_launch_before_any_process_or_artifact_work(self):
        with mock.patch.object(guest_agent, 'guard', side_effect=RuntimeError('outside isolated guest')), \
             mock.patch.object(guest_agent.subprocess, 'Popen') as launch:
            with self.assertRaisesRegex(RuntimeError, 'outside isolated guest'):
                guest_agent.start_direct({'nodes': 2})
            launch.assert_not_called()

    def test_launch_selects_guarded_entry_and_single_size(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(guest_agent, 'ROOT', Path(root)), \
             mock.patch.object(guest_agent, 'guard'), mock.patch.object(guest_agent, 'WORKER', None), \
             mock.patch.object(guest_agent, 'DIRECT_NODES', None), \
             mock.patch.object(guest_agent.subprocess, 'Popen') as launch:
            guest_agent.start_direct({'nodes': 32})
            command = launch.call_args.args[0]
            env = launch.call_args.kwargs['env']
            self.assertIn('-test.run=^TestVMDirectDataplane$', command)
            self.assertIn('-test.timeout=15m', command)
            self.assertEqual(env['VPNCTL_DIRECT_SIZES'], '32')
            self.assertEqual(env['VPNCTL_VM_WORKER'], '1')
            self.assertEqual(env['VPNCTL_VM_DIRECT'], '1')
            with self.assertRaises(RuntimeError):
                guest_agent.start_direct({'nodes': 32})

    def test_results_export_only_named_public_artifacts_and_redacted_bounded_logs(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(guest_agent, 'ROOT', Path(root)), \
             mock.patch.object(guest_agent, 'guard'), mock.patch.object(guest_agent, 'DIRECT_NODES', 2), \
             mock.patch.object(guest_agent, 'WORKER') as worker:
            worker.poll.return_value = 0
            fixture = Path(root) / 'results/direct-dataplane-2-12345'
            fixture.mkdir(parents=True)
            (fixture / 'report.json').write_text('{"nodes":2,"completed":false}')
            (fixture / 'retry-packets.jsonl').write_text('packet evidence')
            (fixture / 'agent-0.log').write_text('x' * 40000 + '\nuseful state\nPrivateKey=secret-key\ncredential=secret-credential\n')
            (fixture / 'controller.log').write_text('bootstrap token=secret-token\ncontroller ready\n')
            (fixture / 'node.yaml').write_text('private configuration')
            (fixture / 'agent-2.log').write_text('unexpected node')
            status = guest_agent.direct_result({'nodes': 2})
            self.assertEqual(status['fixture_id'], 'direct-2')
            row = status['reports'][0]
            self.assertEqual(set(row['logs']), {'retry-packets.jsonl', 'agent-0.log', 'controller.log'})
            logs = row['logs']['agent-0.log'] + row['logs']['controller.log']
            self.assertIn('useful state', logs)
            self.assertNotIn('secret-', logs)
            self.assertLessEqual(len(row['logs']['agent-0.log']), 32768)
            with self.assertRaises(ValueError):
                guest_agent.direct_result({'nodes': 8})
            (fixture / 'agent-1.log').symlink_to(fixture / 'node.yaml')
            with self.assertRaises(RuntimeError):
                guest_agent.direct_result({'nodes': 2})

    def test_missing_report_is_explicit_and_oversized_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(guest_agent, 'ROOT', Path(root)), \
             mock.patch.object(guest_agent, 'guard'), mock.patch.object(guest_agent, 'DIRECT_NODES', 2), \
             mock.patch.object(guest_agent, 'WORKER') as worker:
            worker.poll.return_value = 0
            status = guest_agent.direct_result({'nodes': 2})
            self.assertEqual(status['reports'], [])
            self.assertEqual(status['test'], 'TestVMDirectDataplane')
            with self.assertRaises(RuntimeError):
                observer.validate_direct_result(status, 2)
            fixture = Path(root) / 'results/direct-dataplane-2-12345'
            fixture.mkdir(parents=True)
            (fixture / 'report.json').write_text('{}')
            (fixture / 'retry-packets.jsonl').write_bytes(b'x' * (512 * 1024 + 1))
            with self.assertRaises(RuntimeError):
                guest_agent.direct_result({'nodes': 2})


if __name__ == '__main__':
    unittest.main()
