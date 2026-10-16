"""Host-safe checks for experimental control cells; never qualifies app recovery."""
import unittest
from unittest import mock

import app_recovery
import observer
from test_app_recovery import fixture


def diagnostic(mode='api', cpu='0.5'):
    row = fixture()
    row.update(paths=8, diagnostic_mode=mode, diagnostic_robot_cpu=cpu, diagnostic_window_seconds=45)
    row['phases'] = row['phases'][:2]
    window = row['phases'][1]
    window['name'] = 'diagnostic_window'
    end = int(window['fault_completed_boot_ns']) + 45_000_000_001
    window['finished_boot_ns'] = str(end)
    for i, name in enumerate(('app', 'app2')):
        after = window['after'][i]
        after['snapshot_boot_ns'] = str(end-1)
        after['api']['api_available'] = mode != 'api'
        app = row[name]
        events = app['payload']['events'][:4]
        correct = [int(e['finished_boot_ns']) for e in events]
        app['payload'].update(events=events, attempts=4, dropped_events=0, correct=4,
            authenticated_connections=1, existing_socket_correct=3, new_socket_correct=1,
            outcome_unknown=0, invalid_responses=0, first_correct_boot_ns=str(correct[0]),
            last_correct_boot_ns=str(correct[-1]), max_correct_gap_ns=str(max(b-a for a,b in zip(correct,correct[1:]))))
        app.update(snapshot_boot_ns=str(end+1), response_age_ns=str(end+1-correct[-1]))
    return row


class AppDiagnosticTests(unittest.TestCase):
    def test_each_cell_is_diagnostic_and_original_recovery_validator_rejects_it(self):
        for mode in ('control','api'):
            for cpu in ('0.5','1'):
                row=diagnostic(mode,cpu)
                self.assertEqual(app_recovery.validate_diagnostic(row,mode,cpu), {'diagnostic_only':True,'qualification':False})
                with self.assertRaises(RuntimeError):
                    app_recovery.validate_report(row,8)

    def test_missing_window_wrong_intervention_and_reconnect_cannot_pass(self):
        mutations=[lambda r:r.update(completed=False),lambda r:r.update(diagnostic_robot_cpu='1'),
            lambda r:r.update(diagnostic_mode='control'),lambda r:r['phases'].pop(),
            lambda r:r['phases'][1].update(finished_boot_ns=r['phases'][1]['fault_completed_boot_ns']),
            lambda r:r['phases'][1]['after'][0]['api'].update(api_available=True),
            lambda r:r['phases'][1]['after'][1]['payload'].update(authenticated_connections=2),
            lambda r:r['phases'][1]['after'][0].update(snapshot_boot_ns='1'),
            lambda r:r['phases'][1]['routes'][0].update(applied=False),
            lambda r:r['app']['payload'].update(dropped_events=1)]
        for mutate in mutations:
            row=diagnostic();mutate(row)
            with self.subTest(mutate=mutate),self.assertRaises((RuntimeError,KeyError)):
                app_recovery.validate_diagnostic(row,'api','0.5')

    def test_dispatch_marks_success_nonqualifying_and_preserves_failure(self):
        for code in (0,1):
            vm=mock.Mock(); row=diagnostic();row['completed']=code==0
            terminal={'exit':code,'reports':[{'report':row}], 'worker_log':'original assertion'}
            vm.call.side_effect=lambda name,*args: terminal if name=='uplink-apps-result' else {}
            result={}
            with mock.patch.object(observer,'validate_capacity_accounting'):
                if code:
                    with self.assertRaises(RuntimeError):
                        observer.exercise(vm,'uplink-diag-api','stopped',0,result,'0.5','split')
                else:
                    observer.exercise(vm,'uplink-diag-api','stopped',0,result,'0.5','split')
            self.assertEqual(result['unsupported_reason'],'diagnostic_only_no_qualification')
            self.assertEqual(result['uplink-diag-api'],terminal)
            vm.record.assert_any_call('uplink-diag-api-result',terminal)

    def test_new_cases_still_require_two_outer_cpus(self):
        for case in observer.APP_DIAGNOSTICS:
            self.assertEqual(observer.capacity_vcpus('split',[case],'200000','100000'),2)
            with self.assertRaises(RuntimeError):
                observer.capacity_vcpus('split',[case],'100000','100000')
