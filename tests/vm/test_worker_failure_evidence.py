#!/usr/bin/env python3
"""Bounded worker diagnostics without a VM or network worker."""
import io
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import guest_agent
import observer


class CapacityWorkerFailureEvidenceTests(unittest.TestCase):
    def request(self, root, exit_code):
        worker = mock.Mock()
        worker.poll.return_value = exit_code
        with mock.patch.object(guest_agent, 'ROOT', root), \
             mock.patch.object(guest_agent, 'guard'), \
             mock.patch.object(guest_agent, 'WORKER', worker), \
             mock.patch.object(guest_agent.subprocess, 'Popen') as launch:
            handler = object.__new__(guest_agent.Handler)
            handler.path = '/application-capacity-result'
            handler.headers = {'Authorization': 'Bearer ' + guest_agent.TOKEN,
                               'Content-Length': '2'}
            handler.rfile, handler.wfile = io.BytesIO(b'{}'), io.BytesIO()
            handler.send_response = mock.Mock()
            handler.send_header = mock.Mock()
            handler.end_headers = mock.Mock()
            handler.do_POST()
            handler.send_response.assert_called_once_with(200)
            launch.assert_not_called()
            return json.loads(handler.wfile.getvalue())

    def test_terminal_failure_keeps_bounded_redacted_worker_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # The leading fragment lacks its secret label once the tail is cut.
            raw = b'private key=' + b'S' * 40000 + b'\ncredential=hidden\n'
            raw += b'm3_capacity_role_test.go:88: lease check failed\n--- FAIL: TestVMApplicationCapacity/3\n'
            (root / 'worker.log').write_bytes(raw)
            result = self.request(root, 1)
            self.assertEqual(result['exit'], 1)
            self.assertEqual(result['reports'], [])
            self.assertIn('lease check failed', result['worker_log'])
            self.assertIn('--- FAIL:', result['worker_log'])
            self.assertNotIn('hidden', result['worker_log'])
            self.assertNotIn('SSSS', result['worker_log'])
            self.assertLessEqual(len(result['worker_log'].encode()), 32768)
            with self.assertRaises(RuntimeError):
                observer.validate_application_mixed_result(result)

    def test_unavailable_or_unsafe_log_does_not_erase_worker_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'worker.log'
            for state in ('missing', 'symlink'):
                if state == 'symlink':
                    private = root / 'private.txt'
                    private.write_text('sensitive contents')
                    log.symlink_to(private)
                with self.subTest(state=state):
                    result = self.request(root, 1)
                    self.assertEqual(result['exit'], 1)
                    self.assertEqual(result['reports'], [])
                    self.assertEqual(result.get('worker_log_error'), 'unavailable')
                    self.assertNotIn('sensitive', json.dumps(result))

    def test_fifo_log_does_not_block_terminal_result(self):
        # Bound the regression itself: the old blocking open must fail this
        # test without hanging the full suite or leaving a blocked thread.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.mkfifo(root / 'worker.log', 0o600)
            code = """
import json, sys
from pathlib import Path
from test_worker_failure_evidence import CapacityWorkerFailureEvidenceTests
result = CapacityWorkerFailureEvidenceTests().request(Path(sys.argv[1]), 1)
print(json.dumps(result))
"""
            try:
                child = subprocess.run([sys.executable, '-c', code, str(root)],
                                       cwd=Path(__file__).parent, capture_output=True,
                                       text=True, timeout=5, check=True)
            except subprocess.TimeoutExpired:
                self.fail('non-regular log blocked terminal worker result')
            result = json.loads(child.stdout)
            self.assertEqual(result['exit'], 1)
            self.assertEqual(result['reports'], [])
            self.assertEqual(result.get('worker_log_error'), 'unavailable')
            self.assertNotIn('worker_log', result)

    def test_directory_log_rejection_does_not_leak_descriptors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'worker.log').mkdir()
            before = len(os.listdir('/proc/self/fd'))
            for _ in range(10):
                result = self.request(root, 1)
                self.assertEqual(result.get('worker_log_error'), 'unavailable')
                self.assertEqual(result['exit'], 1)
            self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_log_replaced_after_guard_does_not_export_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log, private = root / 'worker.log', root / 'private.txt'
            log.write_text('original worker output')
            private.write_text('sensitive replacement contents')
            original_guard = guest_agent.direct_artifact_guard

            def swap_after_guard(path, tail=False):
                original_guard(path, tail)
                log.unlink()
                log.symlink_to(private)

            with mock.patch.object(guest_agent, 'direct_artifact_guard', swap_after_guard):
                result = self.request(root, 1)
            self.assertEqual(result['exit'], 1)
            self.assertEqual(result['reports'], [])
            self.assertEqual(result.get('worker_log_error'), 'unavailable')
            self.assertNotIn('sensitive replacement contents', json.dumps(result))

    def test_running_worker_does_not_read_partial_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'worker.log').write_text('still running')
            result = self.request(root, None)
            self.assertEqual(result, {'exit': None})
