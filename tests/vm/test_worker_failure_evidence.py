#!/usr/bin/env python3
"""Bounded worker diagnostics without a VM or network worker."""
import io
import json
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
                    self.assertEqual(result['worker_log_error'], 'unavailable')
                    self.assertNotIn('sensitive', json.dumps(result))

    def test_running_worker_does_not_read_partial_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'worker.log').write_text('still running')
            result = self.request(root, None)
            self.assertEqual(result, {'exit': None})
