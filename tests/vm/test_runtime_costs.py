"""Runtime samples are opt-in and cannot replace original capacity verdicts."""
import unittest
from unittest import mock
import guest_agent
import observer


class RuntimeCostTests(unittest.TestCase):
    def test_guest_control_explicitly_overrides_inherited_mode(self):
        for request, expected in (({}, '0'), ({'runtime_costs': False}, '0'), ({'runtime_costs': True}, '1')):
            self.assertEqual(guest_agent.runtime_cost_env(request), {'VPNCTL_RUNTIME_COSTS': expected})
        for value in ('1', 1, None, [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                guest_agent.runtime_cost_env({'runtime_costs': value})

    def test_mode_crosses_boundary_independently_without_waiving_failure(self):
        for details in (False, True):
            for runtime in (False, True):
                for failed in (False, True):
                    with self.subTest(details=details, runtime=runtime, failed=failed):
                        vm = mock.Mock()
                        terminal = {'exit': 1 if failed else 0}
                        vm.call.side_effect = lambda action, *args: terminal if action == 'application-capacity-result' else {}
                        result = {}
                        with mock.patch.object(observer, 'validate_application_mixed_result') as validate:
                            if failed:
                                validate.side_effect = RuntimeError('original failure')
                                with self.assertRaisesRegex(RuntimeError, 'original failure'):
                                    observer.exercise(vm, 'application-capacity-8', 'stopped', 0, result, '0.5', 'split', False, details, runtime)
                            else:
                                observer.exercise(vm, 'application-capacity-8', 'stopped', 0, result, '0.5', 'split', False, details, runtime)
                            validate.assert_called_once_with(terminal, preparation=False, paths=8, robot_cpu='0.5', cpu_layout='split', uplink_api=False)
                        expected = dict(paths=8, robot_cpus='0.5', cpu_layout='split', rebuild=False)
                        if details:
                            expected['cost_details'] = True
                        if runtime:
                            expected['runtime_costs'] = True
                        vm.call.assert_any_call('application-capacity-start', expected)
                        self.assertIs(result['runtime_costs'], runtime)
                        self.assertIs(result['application-capacity-8'], terminal)
                        self.assertNotIn('unsupported_reason', result)

    def test_bad_mode_or_unsupported_case_rejected_before_launch(self):
        for case, mode in [('boot', True), ('uplink-apps-8', True), ('application-mixed', True), ('application-capacity-8', '1')]:
            vm = mock.Mock()
            with self.subTest(case=case, mode=mode), self.assertRaises(ValueError):
                observer.exercise(vm, case, 'stopped', 0, {}, runtime_costs=mode)
            vm.launch.assert_not_called()
