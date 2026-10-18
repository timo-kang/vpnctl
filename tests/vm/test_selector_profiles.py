import base64
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import guest_agent
import observer
import selector_profiles as profiles
import test_worker_failure_evidence


class SelectorProfileTests(unittest.TestCase):
    def test_guest_launch_scopes_and_overrides_inherited_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            for mode in (False, True, '1', 1):
                root = Path(directory)
                request = dict(paths=8, robot_cpus='0.5', cpu_layout='split', rebuild=False, selector_profile=mode)
                handler = object.__new__(guest_agent.Handler)
                handler.path = '/application-capacity-start'
                data = json.dumps(request).encode()
                handler.headers = {'Authorization': 'Bearer '+guest_agent.TOKEN, 'Content-Length': str(len(data))}
                handler.rfile, handler.wfile = io.BytesIO(data), io.BytesIO()
                handler.send_response, handler.send_header, handler.end_headers = mock.Mock(), mock.Mock(), mock.Mock()
                with mock.patch.object(guest_agent, 'ROOT', root), mock.patch.object(guest_agent, 'guard'), \
                     mock.patch.object(guest_agent, 'WORKER', None), mock.patch.object(guest_agent.subprocess, 'Popen') as launch, \
                     mock.patch.dict(os.environ, {'VPNCTL_SELECTOR_PROFILE_DIR': '/must-not-inherit', 'VPNCTL_CAPACITY_SELECTOR_PROFILE': '1'}):
                    handler.do_POST()
                    if type(mode) is not bool:
                        launch.assert_not_called()
                        handler.send_response.assert_called_once_with(500)
                    else:
                        handler.send_response.assert_called_once_with(200)
                        env = launch.call_args.kwargs['env']
                        self.assertEqual(env['VPNCTL_SELECTOR_PROFILE_DIR'], '')
                        self.assertEqual(env['VPNCTL_CAPACITY_SELECTOR_PROFILE'], '1' if mode else '0')

    def test_failed_worker_retains_available_profiles_and_missing_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / 'results' / 'fixture'
            profile = fixture / profiles.PROFILE_DIRECTORY
            profile.mkdir(parents=True)
            (fixture / 'application-mixed-candidates.json').write_text(json.dumps({'selector_profile': {'requested': True}}))
            (profile / 'cpu.pprof').write_bytes(b'partial\xff')
            result = test_worker_failure_evidence.CapacityWorkerFailureEvidenceTests().request(root, 1)
            self.assertEqual(result['exit'], 1)
            evidence = result['reports'][0]['selector_profiles']
            self.assertEqual(base64.b64decode(evidence['files']['cpu.pprof']['base64']), b'partial\xff')
            self.assertEqual(evidence['errors']['result.json'], 'unavailable')
            with self.assertRaises(RuntimeError):
                observer.validate_application_mixed_result(result)

    def test_typed_explicit_environment(self):
        for request, expected in (({}, '0'), ({'selector_profile': False}, '0'), ({'selector_profile': True}, '1')):
            self.assertEqual(profiles.selector_profile_env(request), {
                'VPNCTL_CAPACITY_SELECTOR_PROFILE': expected, 'VPNCTL_SELECTOR_PROFILE_DIR': ''})
        for value in ('1', 1, None, {}, []):
            with self.assertRaises(ValueError):
                profiles.selector_profile_env({'selector_profile': value})

    def test_safe_bounded_binary_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / 'fixture' / profiles.PROFILE_DIRECTORY
            profile.mkdir(parents=True)
            blob = b'\x1f\x8b\x00\xff'
            (profile / 'cpu.pprof').write_bytes(blob)
            got = profiles.collect_profiles(root, 'fixture')
            self.assertEqual(base64.b64decode(got['files']['cpu.pprof']['base64']), blob)
            self.assertEqual(got['errors']['result.json'], 'unavailable')
            (profile / 'cpu.pprof').write_bytes(b'x' * (profiles.PROFILE_LIMIT + 1))
            self.assertNotIn('cpu.pprof', profiles.collect_profiles(root, 'fixture')['files'])
            for fixture in ('..', '../fixture', '/fixture', ''):
                with self.assertRaises(ValueError):
                    profiles.read_profile(root, fixture, 'cpu.pprof')

    def test_rejects_links_and_special_files_without_fd_leaks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / 'fixture' / profiles.PROFILE_DIRECTORY
            profile.mkdir(parents=True)
            target = root / 'private'; target.write_text('never export')
            cpu = profile / 'cpu.pprof'
            before = len(os.listdir('/proc/self/fd'))
            for kind in ('symlink', 'fifo', 'directory'):
                if kind == 'symlink': cpu.symlink_to(target)
                elif kind == 'fifo': os.mkfifo(cpu)
                else: cpu.mkdir()
                self.assertEqual(profiles.collect_profiles(root, 'fixture')['files'], {})
                if cpu.is_dir(): cpu.rmdir()
                else: cpu.unlink()
            profile.rmdir(); profile.symlink_to(root)
            self.assertEqual(profiles.collect_profiles(root, 'fixture')['files'], {})
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_profile_mode_keeps_original_failed_verdict(self):
        vm = mock.Mock()
        terminal = {'exit': 1}
        vm.call.side_effect = lambda action, *args: terminal if action.endswith('-result') else {}
        result = {}
        with mock.patch.object(observer, 'validate_application_mixed_result', side_effect=RuntimeError('original failure')):
            with self.assertRaisesRegex(RuntimeError, 'original failure'):
                observer.exercise(vm, 'application-capacity-8', 'stopped', 0, result,
                                  '0.5', 'split', selector_profile=True)
        vm.call.assert_any_call('application-capacity-start', {
            'paths': 8, 'robot_cpus': '0.5', 'cpu_layout': 'split', 'rebuild': False, 'selector_profile': True})
        self.assertIs(result['application-capacity-8'], terminal)
        for case, mode in [('boot', True), ('application-capacity-rebuild-8', True),
                           ('application-capacity-4', True), ('application-capacity-8', 1)]:
            with self.assertRaises(ValueError):
                observer.exercise(mock.Mock(), case, 'stopped', 0, {}, selector_profile=mode)
