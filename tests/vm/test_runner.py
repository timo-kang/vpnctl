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
    def vm(self, call):
        vm = object.__new__(observer.VM)
        vm.paths = ['p00']
        vm.call = call
        vm.record = mock.Mock()
        return vm

    def test_control_failure_is_not_dataplane_blocked(self):
        vm = self.vm(lambda *a, **kw: {'ok': False, 'error': 'worker unavailable'})
        with self.assertRaisesRegex(RuntimeError, 'missing authenticated probe result'):
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

if __name__ == '__main__':
    unittest.main()
