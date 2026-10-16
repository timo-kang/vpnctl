#!/usr/bin/env python3
"""Preparation evidence collection without launching a VM or network worker."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import guest_agent
import observer
import test_runner


class CapacityPreparationEvidenceTests(unittest.TestCase):
    def test_guest_preserves_preparation_failure_and_existing_logs(self):
        report = dict(healthy_index=0, completed=False, test_outcome='failed',
                      phase='preparation', preparation_completed=False,
                      sampled_qualification_status='not_started',
                      publication_continuity=dict(contract_version=2, status='not_started'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / 'results' / 'm3-authority-12345'
            fixture.mkdir(parents=True)
            (fixture / 'application-mixed-candidates.json').write_text(json.dumps(report))
            log = '{"state":"blocked"}\n'
            (fixture / 'application-node-supervisor.jsonl').write_text(log)
            worker = mock.Mock()
            worker.poll.return_value = 1
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
                result = json.loads(handler.wfile.getvalue())
            self.assertEqual(result['exit'], 1)
            self.assertEqual(result['reports'], [dict(fixture=fixture.name, report=report,
                             logs={'application-node-supervisor.jsonl': log})])
            with self.assertRaises(RuntimeError):
                observer.validate_application_mixed_result(result)

    def test_complete_case_count_never_turns_unmeasured_preparation_into_pass(self):
        for exit_code in (0, 1):
            with self.subTest(exit_code=exit_code):
                status = test_runner.ApplicationMixedEvidenceTests().valid()
                status['exit'] = exit_code
                status['reports'][0]['report'] = dict(
                    healthy_index=0, completed=False, test_outcome='failed',
                    phase='preparation', preparation_completed=False,
                    sampled_qualification_status='not_started',
                    publication_continuity=dict(contract_version=2, status='not_started'))
                with self.assertRaises(RuntimeError):
                    observer.validate_application_mixed_result(status)
