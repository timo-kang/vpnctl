import importlib.util
from pathlib import Path
import unittest
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('lab_runner', Path(__file__).with_name('runner.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

class IsolationContract(unittest.TestCase):
    def test_actual_cpu_membership_is_required(self):
        with patch.object(runner.os, 'sched_getaffinity', return_value={2, 3, 6, 7}):
            self.assertEqual(runner.cpu_set('2-3'), '2-3')
            for value in ('0,1', '2', '2,2', '2,,3', '2; reboot', '2-99999'):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    runner.cpu_set(value)

    @patch.object(runner.os, 'stat', return_value=SimpleNamespace(st_gid=106))
    def test_runtime_has_only_kvm_and_own_data(self, unused_stat):
        args = runner.runtime_command(Path('/lab'), Path('/lab/runs/one'), 'sha256:'+'a'*64, '2,3', 'owned', ['boot', 'reboot'])
        text = ' '.join(args)
        for required in ('--network none', '--cap-drop ALL', '--read-only', '--memory=2g', '--memory-swap=2g', '--pids-limit=256', '--cpus=1', '--cpuset-cpus=2,3', '--security-opt no-new-privileges', '--device /dev/kvm'):
            self.assertIn(required, text)
        self.assertEqual(args.count('--device'), 1)
        for forbidden in ('--privileged', 'SYS_ADMIN', 'SYS_BOOT', 'SYS_TIME', '/var/run/docker.sock,dst=', '--network host', '--pid host', '--publish'):
            self.assertNotIn(forbidden, text)
        mounts = [args[i+1] for i, value in enumerate(args) if value == '--mount']
        self.assertEqual(len(mounts), 3)
        self.assertIn('type=bind,src=/lab/image,dst=/input,readonly', mounts)
        self.assertIn('type=bind,src=/lab/runs/one/work,dst=/work', mounts)
        self.assertIn('type=bind,src=/lab/runs/one/results,dst=/results', mounts)

    def test_preexisting_workloads_must_keep_identity(self):
        before = {'boot_id':'one', 'containers':{'service':'start1/restarts0'}}
        runner.verify_host(before, dict(before, containers=dict(before['containers'], experiment='start2/restarts0')))
        for after in ({'boot_id':'two','containers':before['containers']}, {'boot_id':'one','containers':{}}, {'boot_id':'one','containers':{'service':'start2/restarts1'}}):
            with self.assertRaises(RuntimeError):runner.verify_host(before, after)

    def test_cleanup_cannot_remove_foreign_container(self):
        with patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='someone-else\n')) as command:
            runner.cleanup('owned')
            self.assertEqual(command.call_count, 1)
        with patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='owned\n')) as command:
            runner.cleanup('owned')
            self.assertEqual(command.call_count, 2)
            self.assertEqual(command.call_args.args[0][-3:], ['rm', '-f', 'owned'])

    def test_host_change_does_not_publish_prepared_image(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'new'
            before = {'boot_id':'one','containers':{}}
            after = {'boot_id':'two','containers':{}}
            args = ['runner.py','prepare','--root',str(root),'--cpuset','2,3','--builder-image','builder','--runner-image','runner']
            with patch('sys.argv',args), patch.object(runner.os,'sched_getaffinity',return_value={2,3}), patch.object(runner,'clean_source',return_value='source'), patch.object(runner,'prepare',return_value={'source':'source'}), patch.object(runner,'host_snapshot',side_effect=[before,after]):
                with self.assertRaises(RuntimeError):runner.main()
            self.assertFalse((root/'prepared.json').exists())
            self.assertTrue((root/'host-before.json').exists())
            self.assertTrue((root/'host-after.json').exists())

    def test_mount_metacharacters_are_rejected(self):
        for path in ('/tmp/a,b', '/tmp/a\nb'):
            with self.assertRaises(ValueError):runner.mount_path(Path(path))

if __name__ == '__main__':
    unittest.main()
