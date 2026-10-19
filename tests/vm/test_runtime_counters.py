"""Host-safe accounting/export regression tests; no VM or kernel changes."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import guest_agent
import observer


class RuntimeCounters(unittest.TestCase):
    def test_guest_requires_boot_and_enabled_counters_without_mutations(self):
        for cmdline, switch, accepted in (
            ('delayacct schedstats=enable', '1', True),
            ('schedstats=enable', '1', False),
            ('delayacct', '1', False),
            ('delayacct schedstats=enable', '0', False),
        ):
            def read(path):
                return cmdline if str(path) == '/proc/cmdline' else switch
            with mock.patch.object(Path, 'read_text', read), mock.patch.object(Path, 'write_text') as write:
                if accepted:
                    guest_agent.runtime_accounting_ready()
                else:
                    with self.assertRaises(RuntimeError): guest_agent.runtime_accounting_ready()
                write.assert_not_called()

    def test_export_missing_running_and_symlink_are_not_zero_samples(self):
        with tempfile.TemporaryDirectory() as name, mock.patch.object(guest_agent, 'ROOT', Path(name)), \
             mock.patch.object(guest_agent, 'WORKER') as worker:
            worker.poll.return_value = None
            with self.assertRaises(RuntimeError): guest_agent.runtime_counter_result()
            worker.poll.return_value = 1
            self.assertEqual(guest_agent.runtime_counter_result(), {'files': [], 'expected_files': 3})
            fixture = Path(name)/'results/f1'; fixture.mkdir(parents=True)
            raw = '{"kind":"original_end"}\n'
            path = fixture/'runtime-counters.jsonl'; path.write_text(raw)
            self.assertEqual(guest_agent.runtime_counter_result()['files'], [{'fixture':'f1','jsonl':raw}])
            path.unlink(); path.symlink_to('/etc/hostname')
            with self.assertRaises(RuntimeError): guest_agent.runtime_counter_result()
            path.unlink(); path.write_bytes(b'x'*(4*1024*1024+1))
            with self.assertRaises(RuntimeError): guest_agent.runtime_counter_result()

    def test_scope_and_boolean_are_checked_before_worker_launch(self):
        for cpu in ('0.5', '1', '0.25'):
            for mode in (False, True, '0', 0, 1, None):
                with self.subTest(cpu=cpu,mode=mode), tempfile.TemporaryDirectory() as name, \
                     mock.patch.object(guest_agent, 'ROOT', Path(name)), \
                     mock.patch.object(guest_agent, 'guard'), \
                     mock.patch.object(guest_agent, 'WORKER', None), \
                     mock.patch.object(guest_agent, 'runtime_accounting_ready') as ready, \
                     mock.patch.object(guest_agent.subprocess, 'Popen') as launch:
                    data=json.dumps(dict(paths=8,robot_cpus=cpu,cpu_layout='split',rebuild=False,runtime_counters=mode)).encode()
                    handler=object.__new__(guest_agent.Handler)
                    handler.path='/application-capacity-start'
                    handler.headers={'Authorization':'Bearer '+guest_agent.TOKEN,'Content-Length':str(len(data))}
                    handler.rfile,handler.wfile=io.BytesIO(data),io.BytesIO()
                    handler.send_response=mock.Mock();handler.send_header=mock.Mock();handler.end_headers=mock.Mock()
                    handler.do_POST()
                    if type(mode) is bool and cpu in ('0.5', '1'):
                        handler.send_response.assert_called_once_with(200)
                        ready.assert_called_once()
                        env=launch.call_args.kwargs['env']
                        self.assertEqual(env['VPNCTL_VM_RUNTIME_COUNTERS'], '1' if mode else '0')
                        self.assertEqual(env['VPNCTL_CAPACITY_ROBOT_CPU'], cpu)
                    else:
                        handler.send_response.assert_called_once_with(500);launch.assert_not_called();ready.assert_not_called()
        for mode in ('0','1'):
            for cpu in ('0.5','1'):
                observer.validate_runtime_profile(mode,['application-capacity-8'],'split',cpu)
            for cases,layout,cpu in ((['boot'],'split','0.5'),(['application-capacity-8'],'shared','1'),(['application-capacity-8'],'split','0.25')):
                with self.assertRaises(ValueError): observer.validate_runtime_profile(mode,cases,layout,cpu)

    def test_export_failure_never_skips_original_failure_validation(self):
        for cpu in ('0.5','1'):
            for mode in (False,True):
                vm=mock.Mock()
                original={'exit':1,'reports':[]}
                vm.call.side_effect=[{}, {'started':True},original,RuntimeError('export failed')]
                result={}
                with mock.patch.object(observer, 'validate_application_mixed_result', side_effect=RuntimeError('original product failure')) as validate:
                    with self.assertRaisesRegex(RuntimeError,'original product failure'):
                        observer.exercise(vm,'application-capacity-8','stopped',0,result,robot_cpus=cpu,cpu_layout='split',runtime_counters=mode)
                    validate.assert_called_once()
                    self.assertEqual(validate.call_args.kwargs['robot_cpu'], cpu)
                    self.assertEqual(validate.call_args.kwargs['cpu_layout'], 'split')
                    self.assertIs(result['application-capacity-8'],original)
                    self.assertEqual(result['runtime_counter_export'],{'error':'RuntimeError'})
                    self.assertIn(mock.call('application-capacity-start',dict(paths=8,robot_cpus=cpu,cpu_layout='split',rebuild=False,runtime_counters=mode)),vm.call.call_args_list)


if __name__ == '__main__': unittest.main()
