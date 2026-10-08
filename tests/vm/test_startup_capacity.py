import copy
import io
import json
import tempfile
from pathlib import Path
import unittest
from unittest import mock

import observer
import guest_agent
import test_runner as fixtures


class StartupCapacityEvidenceTests(unittest.TestCase):
    def valid(self, paths=8):
        status = fixtures.SplitCapacityEvidenceTests().valid()
        ids = [f'p{r}{u}' for r in range(2) for u in range(paths // 2)]
        for item, index in zip(status['reports'], (0, paths // 2 - 1, paths - 1)):
            row = item['report']
            row.update(paths=paths, healthy_index=index, actuator_modes={'app': 'auto', 'app2': 'auto'})
            for suffix in ('', '_after'):
                row['resource_profile' + suffix].update(scope='robot-startup-and-runtime', initial_preparation_limited=True)
                row['server_resource_profile' + suffix]['initial_preparation_limited'] = False
            phases = ['enroll', 'register', 'refresh', 'plan'] + ['prepare/' + p for p in ids] + ['reserve/app', 'reserve/app2']
            row['startup'] = dict(seconds=60, commands=[dict(phase=p, seconds=1, succeeded=True,
                                  placement_verified=True, cpus='0', retryable=False) for p in phases],
                                  ready_candidates=paths)
        return status

    def check(self, status, paths=8):
        observer.validate_application_mixed_result(status, paths=paths, robot_cpu='0.5', cpu_layout='split', startup=True)

    def test_complete_initial_preparation_and_two_auto_apps(self):
        for paths in (4, 8):
            self.check(self.valid(paths), paths)

    def test_cannot_qualify_prepared_runtime_or_missing_placement(self):
        changes = [
            lambda r: r.pop('startup'),
            lambda r: r['startup'].update(seconds=120.1),
            lambda r: r['startup'].update(seconds=float('nan')),
            lambda r: r['startup'].update(seconds=1),
            lambda r: r['startup'].update(ready_candidates=7),
            lambda r: r['startup']['commands'].pop(0),
            lambda r: r['startup']['commands'].append(copy.deepcopy(r['startup']['commands'][0])),
            lambda r: r['startup']['commands'][2].update(phase='release'),
            lambda r: r['startup']['commands'][0].update(placement_verified=False),
            lambda r: r['startup']['commands'][0].update(cpus='1'),
            lambda r: r['startup']['commands'][0].update(seconds=float('inf')),
            lambda r: r['startup']['commands'][0].update(succeeded=False),
            lambda r: r['resource_profile'].update(initial_preparation_limited=False),
            lambda r: r['server_resource_profile'].update(initial_preparation_limited=True),
            lambda r: r.update(actuator_modes={'app': 'auto', 'app2': 'manual'}),
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                status = self.valid()
                change(status['reports'][0]['report'])
                self.check(status)
        with self.assertRaises(RuntimeError):
            self.check(fixtures.SplitCapacityEvidenceTests().valid())

    def test_only_explicit_pre_admission_retry_can_precede_success(self):
        status = self.valid()
        commands = status['reports'][0]['report']['startup']['commands']
        retry = dict(commands[-1], succeeded=False, retryable=True)
        commands.insert(-1, retry)
        self.check(status)
        retry['retryable'] = False
        with self.assertRaises(RuntimeError):
            self.check(status)

    def test_dispatch_requires_startup_evidence(self):
        for paths in (4, 8):
            case = f'application-capacity-startup-{paths}'
            self.assertEqual(observer.capacity_vcpus('split', [case], '200000', '100000'), 2)
            vm = mock.Mock()
            vm.call.side_effect = [{}, {'started': True}, self.valid(paths)]
            observer.exercise(vm, case, 'stopped', 0, {}, robot_cpus='0.5', cpu_layout='split')
            self.assertIn(mock.call('application-capacity-start', dict(paths=paths, robot_cpus='0.5', cpu_layout='split', rebuild=False, startup=True)), vm.call.call_args_list)
            vm.call.side_effect = [{}, {'started': True}, fixtures.SplitCapacityEvidenceTests().valid()]
            with self.assertRaises(RuntimeError):
                observer.exercise(vm, case, 'stopped', 0, {}, robot_cpus='0.5', cpu_layout='split')

    def test_guest_rejects_ambiguous_or_combined_startup_profiles(self):
        for startup, rebuild, layout, valid in (
                (True, False, 'split', True), (False, False, 'split', True),
                ('true', False, 'split', False), (1, False, 'split', False),
                (None, False, 'split', False), (True, True, 'split', False),
                (True, False, 'shared', False)):
            with self.subTest(startup=startup, rebuild=rebuild, layout=layout), tempfile.TemporaryDirectory() as root, \
                 mock.patch.object(guest_agent, 'ROOT', Path(root)), \
                 mock.patch.object(guest_agent, 'guard'), \
                 mock.patch.object(guest_agent, 'WORKER', None), \
                 mock.patch.object(guest_agent.subprocess, 'Popen') as launch:
                req = json.dumps(dict(paths=4, robot_cpus='0.5', cpu_layout=layout, rebuild=rebuild, startup=startup)).encode()
                handler = object.__new__(guest_agent.Handler)
                handler.path = '/application-capacity-start'
                handler.headers = {'Authorization': 'Bearer ' + guest_agent.TOKEN, 'Content-Length': str(len(req))}
                handler.rfile, handler.wfile = io.BytesIO(req), io.BytesIO()
                handler.send_response = mock.Mock()
                handler.send_header = mock.Mock()
                handler.end_headers = mock.Mock()
                handler.do_POST()
                handler.send_response.assert_called_once_with(200 if valid else 500)
                if valid:
                    self.assertEqual(launch.call_args.kwargs['env']['VPNCTL_CAPACITY_STARTUP'], '1' if startup else '0')
                else:
                    launch.assert_not_called()
