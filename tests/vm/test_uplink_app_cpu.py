# Copyright 2026 Jonghyeok Kang
# SPDX-License-Identifier: Apache-2.0
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import guest_agent
import observer
from test_app_recovery import fixture
import test_runner


class UplinkAppCPUTests(unittest.TestCase):
    def status(self, paths, cpu):
        row = fixture()
        row['paths'] = paths
        accounting = test_runner.SplitCapacityEvidenceTests().valid(paths, cpu)['reports'][0]['report']
        for suffix in ('', '_after'):
            for key in ('resource_profile', 'server_resource_profile'):
                row[key + suffix] = accounting[key + suffix]
            row['resource_profile' + suffix]['scope'] = 'robot-supervisor-two-actuators-and-two-apps'
        return dict(exit=0, reports=[dict(report=row)])

    def exercise(self, paths, cpu, status):
        vm = mock.Mock()
        vm.call.side_effect = [{}, {'started': True}, status]
        observer.exercise(vm, f'uplink-apps-{paths}', 'stopped', 0, {}, robot_cpus=cpu, cpu_layout='split')
        self.assertIn(mock.call('uplink-apps-start', dict(paths=paths, robot_cpus=cpu)), vm.call.call_args_list)

    def test_requested_quota_reaches_worker_and_qualifies_exact_accounting(self):
        for paths in (4, 8):
            for cpu in ('1', '0.5', '0.25'):
                with self.subTest(paths=paths, cpu=cpu):
                    self.exercise(paths, cpu, self.status(paths, cpu))

    def test_before_and_after_quota_mismatch_cannot_qualify_one_cpu(self):
        for paths in (4, 8):
            for key in ('resource_profile', 'resource_profile_after'):
                for quota in ('50000 100000', '25000 100000', 'max 100000'):
                    with self.subTest(paths=paths, key=key, quota=quota):
                        status = self.status(paths, '1')
                        status['reports'][0]['report'][key]['cpu_max'] = quota
                        with self.assertRaises(RuntimeError):
                            self.exercise(paths, '1', status)

    def test_guest_requires_explicit_supported_cpu_before_launch(self):
        for cpu in ('1', '0.5', '0.25', None, '', '2', 'max', 1, 0.5, True):
            with self.subTest(cpu=cpu), tempfile.TemporaryDirectory() as root, \
                 mock.patch.object(guest_agent, 'ROOT', Path(root)), \
                 mock.patch.object(guest_agent, 'guard'), \
                 mock.patch.object(guest_agent, 'WORKER', None), \
                 mock.patch.object(guest_agent.subprocess, 'Popen') as launch:
                body = json.dumps(dict(paths=4, robot_cpus=cpu)).encode()
                handler = object.__new__(guest_agent.Handler)
                handler.path = '/uplink-apps-start'
                handler.headers = {'Authorization': 'Bearer ' + guest_agent.TOKEN, 'Content-Length': str(len(body))}
                handler.rfile, handler.wfile = io.BytesIO(body), io.BytesIO()
                handler.send_response = mock.Mock()
                handler.send_header = mock.Mock()
                handler.end_headers = mock.Mock()
                handler.do_POST()
                if cpu in ('1', '0.5', '0.25'):
                    handler.send_response.assert_called_once_with(200)
                    self.assertEqual(launch.call_args.kwargs['env']['VPNCTL_APP_ROBOT_CPUS'], cpu)
                else:
                    handler.send_response.assert_called_once_with(500)
                    launch.assert_not_called()
