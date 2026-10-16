"""Opt-in cost accounting must cross the VM boundary without changing verdicts."""
import unittest
from unittest import mock
import guest_agent
import observer

class CostDetailTests(unittest.TestCase):
    def test_guest_accepts_only_boolean_and_explicitly_disables_control(self):
        self.assertEqual(guest_agent.cost_detail_env({}), {'VPNCTL_COST_DETAILS':'0'})
        self.assertEqual(guest_agent.cost_detail_env({'cost_details':False}), {'VPNCTL_COST_DETAILS':'0'})
        self.assertEqual(guest_agent.cost_detail_env({'cost_details':True}), {'VPNCTL_COST_DETAILS':'1'})
        for value in ('1', 1, None, [], {}):
            with self.subTest(value=value),self.assertRaises(ValueError):
                guest_agent.cost_detail_env({'cost_details':value})

    def test_control_and_instrumented_use_same_capacity_validator(self):
        for details in (False,True):
            for failed in (False,True):
                with self.subTest(details=details,failed=failed):
                    vm=mock.Mock();terminal={'exit':1 if failed else 0}
                    vm.call.side_effect=lambda action,*args: terminal if action=='application-capacity-result' else {}
                    result={}
                    with mock.patch.object(observer,'validate_application_mixed_result') as validate:
                        if failed: validate.side_effect=RuntimeError('original failure')
                        if failed:
                            with self.assertRaisesRegex(RuntimeError,'original failure'):
                                observer.exercise(vm,'application-capacity-8','stopped',0,result,'0.5','split',False,details)
                        else:
                            observer.exercise(vm,'application-capacity-8','stopped',0,result,'0.5','split',False,details)
                        validate.assert_called_once_with(terminal,preparation=False,paths=8,robot_cpu='0.5',cpu_layout='split',uplink_api=False)
                    expected=dict(paths=8,robot_cpus='0.5',cpu_layout='split',rebuild=False)
                    if details: expected['cost_details']=True
                    vm.call.assert_any_call('application-capacity-start',expected)
                    self.assertEqual(result['cost_details'],details)
                    self.assertEqual(result['application-capacity-8'],terminal)
                    self.assertNotIn('unsupported_reason',result)

    def test_unsupported_profiles_refused_before_launch(self):
        for case in ('boot','uplink-apps-8','uplink-diag-api','application-mixed'):
            vm=mock.Mock()
            with self.subTest(case=case),self.assertRaises(ValueError):
                observer.exercise(vm,case,'stopped',0,{},'0.5','split',False,True)
            vm.launch.assert_not_called()
