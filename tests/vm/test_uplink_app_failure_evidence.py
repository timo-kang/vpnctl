#!/usr/bin/env python3
"""Uplink app worker diagnostics through the real result endpoint, without a VM."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import guest_agent


class UplinkAppWorkerFailureEvidenceTests(unittest.TestCase):
    def request(self, root, exit_code):
        worker = mock.Mock()
        worker.poll.return_value = exit_code
        with mock.patch.object(guest_agent, 'ROOT', root), \
             mock.patch.object(guest_agent, 'guard'), \
             mock.patch.object(guest_agent, 'WORKER', worker), \
             mock.patch.object(guest_agent.subprocess, 'Popen') as launch:
            handler = object.__new__(guest_agent.Handler)
            handler.path = '/uplink-apps-result'
            handler.headers = {'Authorization': 'Bearer ' + guest_agent.TOKEN,
                               'Content-Length': '2'}
            handler.rfile, handler.wfile = io.BytesIO(b'{}'), io.BytesIO()
            handler.send_response = mock.Mock()
            handler.send_header = mock.Mock()
            handler.end_headers = mock.Mock()
            handler.do_POST()
            handler.send_response.assert_called_once_with(200)
            worker.poll.assert_called_once_with()
            launch.assert_not_called()
            return json.loads(handler.wfile.getvalue())

    def report(self, root):
        report = {'schema_version': 1, 'paths': 4,
                  'fixture_assertion': 'api outage socket continuity failed',
                  'completed': False}
        destination = root / 'results' / 'uplink-fixture' / 'uplink-applications.json'
        destination.parent.mkdir(parents=True)
        destination.write_text(json.dumps(report))
        return [{'report': report}]

    def test_terminal_result_keeps_bounded_redacted_worker_tail_and_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = self.report(root)
            # Cutting into a long secret line must not retain an unlabeled
            # secret fragment at the beginning of the exported tail.
            raw = b'private key=' + b'S' * 40000 + b'\nTOKEN=hidden-token\n'
            raw += b'credential=hidden-credential\n'
            raw += b'uplink_application_test.go:412: API outage socket continuity failed\n'
            raw += b'--- FAIL: TestVMUplinkApplications/api_outage\n'
            (root / 'worker.log').write_bytes(raw)
            for exit_code in (1, -9, 0):
                with self.subTest(exit_code=exit_code):
                    result = self.request(root, exit_code)
                    self.assertEqual(result['exit'], exit_code)
                    self.assertEqual(result['reports'], reports)
                    self.assertIn('worker_log', result)
                    self.assertIn('API outage socket continuity failed', result['worker_log'])
                    self.assertIn('--- FAIL: TestVMUplinkApplications', result['worker_log'])
                    self.assertNotIn('hidden-token', result['worker_log'])
                    self.assertNotIn('hidden-credential', result['worker_log'])
                    self.assertNotIn('SSSS', result['worker_log'])
                    self.assertLessEqual(len(result['worker_log'].encode()), 32768)
                    self.assertNotIn('worker_log_error', result)

    def test_terminal_tail_remains_bounded_after_invalid_utf8_expansion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'worker.log').write_bytes(b'\n' + b'\xff' * 32700 + b'\nassertion: socket continuity failed\n')
            result = self.request(root, 1)
            self.assertEqual(result['exit'], 1)
            self.assertEqual(result['reports'], [])
            self.assertIn('worker_log', result)
            self.assertIn('assertion: socket continuity failed', result['worker_log'])
            self.assertLessEqual(len(result['worker_log'].encode()), 32768)

    def test_unavailable_or_unsafe_log_preserves_original_failure_and_reports(self):
        for state in ('missing', 'symlink', 'directory'):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                reports = self.report(root)
                log = root / 'worker.log'
                if state == 'symlink':
                    private = root / 'private.txt'
                    private.write_text('sensitive replacement contents')
                    log.symlink_to(private)
                elif state == 'directory':
                    log.mkdir()
                result = self.request(root, -9)
                self.assertEqual(result['exit'], -9)
                self.assertEqual(result['reports'], reports)
                self.assertEqual(result.get('worker_log_error'), 'unavailable')
                self.assertNotIn('worker_log', result)
                self.assertNotIn('sensitive replacement contents', json.dumps(result))

    def test_fifo_log_cannot_block_or_replace_original_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = self.report(root)
            log = root / 'worker.log'
            os.mkfifo(log, 0o600)
            original_open = os.open

            def nonblocking_open(path, flags, *args, **kwargs):
                # Fail before a potentially blocking FIFO open. No subprocess
                # or surviving blocked thread is needed to bound this test.
                if os.fspath(path) in ('worker.log', str(log)):
                    self.assertTrue(flags & os.O_NONBLOCK,
                                    'worker log FIFO would block without O_NONBLOCK')
                    self.assertTrue(flags & os.O_NOFOLLOW,
                                    'worker log must not follow a replacement symlink')
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(guest_agent.os, 'open', side_effect=nonblocking_open):
                result = self.request(root, 1)
            self.assertEqual(result['exit'], 1)
            self.assertEqual(result['reports'], reports)
            self.assertEqual(result.get('worker_log_error'), 'unavailable')
            self.assertNotIn('worker_log', result)

    def test_replaced_log_does_not_export_symlink_target_or_erase_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = self.report(root)
            log, private = root / 'worker.log', root / 'private.txt'
            log.write_text('original worker output')
            private.write_text('sensitive replacement contents')
            original_guard = guest_agent.direct_artifact_guard

            def swap_after_guard(path, tail=False):
                original_guard(path, tail)
                if path == log:
                    log.unlink()
                    log.symlink_to(private)

            with mock.patch.object(guest_agent, 'direct_artifact_guard', side_effect=swap_after_guard):
                result = self.request(root, 1)
            self.assertEqual(result['exit'], 1)
            self.assertEqual(result['reports'], reports)
            self.assertEqual(result.get('worker_log_error'), 'unavailable')
            self.assertNotIn('worker_log', result)
            self.assertNotIn('sensitive replacement contents', json.dumps(result))

    def test_running_worker_does_not_read_partial_log_or_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'worker.log').write_text('incomplete worker output')
            self.report(root)
            with mock.patch.object(guest_agent, 'direct_artifact',
                                   side_effect=AssertionError('partial log read')) as artifact, \
                 mock.patch.object(Path, 'glob',
                                   side_effect=AssertionError('partial report scan')) as reports:
                result = self.request(root, None)
            self.assertEqual(result, {'exit': None})
            artifact.assert_not_called()
            reports.assert_not_called()
