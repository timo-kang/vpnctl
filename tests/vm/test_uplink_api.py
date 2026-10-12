# Copyright 2026 Jonghyeok Kang
# SPDX-License-Identifier: Apache-2.0
import unittest
from unittest import mock
import observer
from test_runner import ApplicationRobotCapacityEvidenceTests


class UplinkAPIEvidenceTests(unittest.TestCase):
    def test_load_requires_both_clients_and_real_rejections(self):
        def valid():
            status = ApplicationRobotCapacityEvidenceTests().valid(4)
            for item in status['reports']:
                item['report']['uplink_api_load'] = {
                    'enabled': True, 'client_scope': 'server-measurement',
                    'parent_stopped': True, 'started_monotonic_ns': 1,
                    'window_started_monotonic_ns': 2, 'window_ended_monotonic_ns': 20_000_000_002,
                    'stopped_monotonic_ns': 20_000_000_003,
                    'app': {'responses': 10, 'limited': 1, 'fresh_reachable': 1},
                    'app2': {'responses': 10, 'limited': 1, 'fresh_reachable': 1}}
            return status
        observer.validate_application_mixed_result(valid(), paths=4, robot_cpu='0.5', uplink_api=True)
        for field in ('enabled', 'app', 'app2', 'client_scope', 'parent_stopped', 'started_monotonic_ns', 'window_started_monotonic_ns', 'window_ended_monotonic_ns', 'stopped_monotonic_ns'):
            data = valid()
            data['reports'][0]['report']['uplink_api_load'].pop(field)
            with self.assertRaises(RuntimeError):
                observer.validate_application_mixed_result(data, paths=4, robot_cpu='0.5', uplink_api=True)
        for field, value in (('parent_stopped', False), ('started_monotonic_ns', 3),
                             ('stopped_monotonic_ns', 20_000_000_001), ('window_ended_monotonic_ns', 3),
                             ('started_monotonic_ns', True)):
            data = valid()
            data['reports'][0]['report']['uplink_api_load'][field] = value
            with self.assertRaises(RuntimeError):
                observer.validate_application_mixed_result(data, paths=4, robot_cpu='0.5', uplink_api=True)
        for field in ('responses', 'limited', 'fresh_reachable'):
            data = valid()
            data['reports'][0]['report']['uplink_api_load']['app'][field] = 0
            with self.assertRaises(RuntimeError):
                observer.validate_application_mixed_result(data, paths=4, robot_cpu='0.5', uplink_api=True)

    def test_dispatch_does_not_silently_omit_requested_load(self):
        vm = mock.Mock()
        vm.call.side_effect = [{}, {'started': True}, {'exit': 1}]
        with self.assertRaises(RuntimeError):
            observer.exercise(vm, 'application-capacity-4', 'stopped', 0, {}, uplink_api=True)
        self.assertIn(mock.call('application-capacity-start', dict(paths=4, robot_cpus='0.5', cpu_layout='shared', rebuild=False, uplink_api=True)), vm.call.call_args_list)
