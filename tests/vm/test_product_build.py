"""Host-safe contracts for same-image product selection; never launches a VM."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import guest_agent
import observer

PROFILE = dict(paths=8, robot_cpus='0.5', cpu_layout='split', rebuild=False, runtime_counters=True)


def product(build):
    binary = 'vpnctl' if build == 'baseline' else 'vpnctl-candidate'
    return dict(build=build, binary=binary, path='/opt/vpnctl-vm/'+binary, sha256='a'*64)


class ProductBuild(unittest.TestCase):
    def request(self, request, action='application-capacity-start'):
        data = json.dumps(request).encode()
        handler = object.__new__(guest_agent.Handler)
        handler.path = '/'+action
        handler.headers = {'Authorization': 'Bearer '+guest_agent.TOKEN, 'Content-Length': str(len(data))}
        handler.rfile, handler.wfile = io.BytesIO(data), io.BytesIO()
        handler.send_response = mock.Mock(); handler.send_header = mock.Mock(); handler.end_headers = mock.Mock()
        handler.do_POST()
        return handler

    def test_selection_reaches_worker_environment_and_retained_response(self):
        for build in ('baseline', 'candidate'):
            with tempfile.TemporaryDirectory() as name, mock.patch.object(guest_agent, 'ROOT', Path(name)), \
                 mock.patch.object(guest_agent, 'guard'), mock.patch.object(guest_agent, 'WORKER', None), \
                 mock.patch.object(guest_agent, 'runtime_accounting_ready'), \
                 mock.patch.object(guest_agent, 'capacity_product', return_value=product(build)) as select, \
                 mock.patch.object(guest_agent.subprocess, 'Popen') as launch:
                request = dict(PROFILE, product_build=build)
                handler = self.request(request)
                handler.send_response.assert_called_once_with(200)
                select.assert_called_once_with(request)
                self.assertEqual(launch.call_args.kwargs['env']['VPNCTL_BIN'], product(build)['path'])
                self.assertEqual(launch.call_args.kwargs['env']['VPNCTL_CAPACITY_ROBOT_CPU'], '0.5')
                self.assertEqual(json.loads(handler.wfile.getvalue()), dict(started=True, product=product(build)))

    def test_invalid_profiles_are_rejected_before_reading_or_launching(self):
        for change in (dict(product_build='../vpnctl'), dict(product_build=None), dict(product_build=1),
                       dict(paths=4), dict(robot_cpus='1'), dict(cpu_layout='shared'),
                       dict(runtime_counters=False), dict(runtime_counters=1), dict(rebuild=True)):
            request = dict(PROFILE, product_build='candidate'); request.update(change)
            with mock.patch.object(Path, 'open') as read, mock.patch.object(guest_agent, 'guard'), \
                 mock.patch.object(guest_agent, 'WORKER', None), mock.patch.object(guest_agent.subprocess, 'Popen') as launch:
                handler = self.request(request)
                handler.send_response.assert_called_once_with(500)
                launch.assert_not_called(); read.assert_not_called()
        with mock.patch.object(guest_agent, 'guard'), mock.patch.object(guest_agent.subprocess, 'Popen') as launch:
            handler = self.request(dict(PROFILE, product_build='candidate'), 'application-mixed-start')
            handler.send_response.assert_called_once_with(500); launch.assert_not_called()

    def test_selected_digest_is_read_from_the_fixed_binary(self):
        for build in ('baseline', 'candidate'):
            with mock.patch.object(Path, 'open', autospec=True, return_value=io.BytesIO(b'actual executable')) as read:
                result = guest_agent.capacity_product(dict(PROFILE, product_build=build))
                read.assert_called_once_with(Path(product(build)['path']), 'rb')
                self.assertEqual(result['path'], product(build)['path'])
                self.assertEqual(result['sha256'], guest_agent.hashlib.sha256(b'actual executable').hexdigest())

    def test_observer_bounds_before_vm_and_retains_original_verdict(self):
        for build in ('baseline', 'candidate'):
            observer.validate_product_profile(build, ['application-capacity-8'], 'split', '0.5', '1')
            for cases, layout, cpu, counters in ((['boot'], 'split','0.5','1'),
                    (['application-capacity-8'],'shared','0.5','1'),
                    (['application-capacity-8'],'split','1','1'),
                    (['application-capacity-8'],'split','0.5','0')):
                with self.assertRaises(ValueError): observer.validate_product_profile(build,cases,layout,cpu,counters)
            vm = mock.Mock()
            started = dict(started=True, product=product(build))
            original = {'exit': 1, 'reports': []}
            vm.call.side_effect = [{'binaries': {product(build)['binary']: 'a'*64}}, started, original, RuntimeError('export failed')]
            result = {}
            with mock.patch.object(observer, 'validate_application_mixed_result', side_effect=RuntimeError('original failure')) as validate:
                with self.assertRaisesRegex(RuntimeError, 'original failure'):
                    observer.exercise(vm, 'application-capacity-8', 'stopped', 0, result,
                                      robot_cpus='0.5', cpu_layout='split', runtime_counters=True, product_build=build)
                validate.assert_called_once()
                self.assertIs(result['application-capacity-8'], original)
                self.assertEqual(result['product_start'], started)
                self.assertIn(mock.call('application-capacity-start', dict(PROFILE,product_build=build)), vm.call.call_args_list)

    def test_observer_rejects_guest_that_selected_wrong_product(self):
        vm = mock.Mock()
        vm.call.side_effect = [{'binaries': {'vpnctl-candidate': 'a'*64}}, dict(started=True,product=product('baseline'))]
        result = {}
        with self.assertRaisesRegex(RuntimeError, 'identity differs'):
            observer.exercise(vm, 'application-capacity-8', 'stopped', 0, result,
                              robot_cpus='0.5', cpu_layout='split', runtime_counters=True, product_build='candidate')
        self.assertEqual(result['product_start']['product']['build'], 'baseline')


if __name__ == '__main__': unittest.main()
