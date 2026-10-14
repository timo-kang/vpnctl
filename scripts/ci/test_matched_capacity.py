import importlib.util
import json
from pathlib import Path
import tempfile
import shutil
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('matched', Path(__file__).with_name('matched_capacity.py'))
matched = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matched)


class MatchedScheduleTests(unittest.TestCase):
    def run_schedule(self, invoke):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            with patch.object(matched, 'checked_source', return_value=True):
                status = matched.execute_schedule(root, {'A': root, 'B': root}, 'image', invoke)
            rows = json.loads((root / 'progress.json').read_text())
            self.assertEqual(len(rows), 8)
            self.assertEqual(json.loads((root / 'complete.json').read_text())['invocations'], 8)
            self.assertEqual([r['arm'] for r in rows], list('ABBAABBA'))
            self.assertEqual([r['cases'] for r in rows], [[4, 8]]*2 + [[8, 4]]*2 + [[4, 8]]*2 + [[8, 4]]*2)
            for first, second in zip(rows, rows[1:]):
                self.assertLess(first['finish_monotonic_ns'], second['start_monotonic_ns'])
            return status, rows

    def test_test_failure_is_not_retried_or_short_circuited(self):
        visited = []
        def invoke(row, *_):
            visited.append(row['sequence'])
            return 1 if row['sequence'] == 2 else 0
        status, rows = self.run_schedule(invoke)
        self.assertEqual(status, 1)
        self.assertEqual(visited, list(range(1, 9)))
        self.assertEqual([r['exit_code'] for r in rows], [0, 1, 0, 0, 0, 0, 0, 0])

    def test_infrastructure_failure_remains_explicit(self):
        def invoke(row, *_):
            if row['sequence'] == 3:
                raise RuntimeError('private-marker-must-not-be-printed')
            return 0
        status, rows = self.run_schedule(invoke)
        self.assertEqual(status, 1)
        self.assertEqual(rows[2]['exit_code'], 125)
        self.assertEqual(rows[2]['infrastructure_error'], 'RuntimeError')
        self.assertNotIn('private-marker', json.dumps(rows))

    def test_success_keeps_the_full_schedule(self):
        status, rows = self.run_schedule(lambda *_: 0)
        self.assertEqual(status, 0)
        self.assertTrue(all(r['exit_code'] == 0 for r in rows))

    def test_source_drift_records_each_unexecuted_attempt(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            with patch.object(matched, 'checked_source', return_value=False):
                code = matched.execute_schedule(root, {'A': root, 'B': root}, 'image', lambda *_: self.fail('drifted source executed'))
            self.assertEqual(code, 1)
            rows = json.loads((root/'progress.json').read_text())
            self.assertEqual(len(rows), 8)
            self.assertTrue(all(r['exit_code'] == 125 for r in rows))

    def evidence(self, root):
        dest=root/'run';dest.mkdir();(dest/'artifacts').mkdir();(root/'binaries').mkdir()
        return dest

    def test_retention_rejects_manifest_without_new_work(self):
        with tempfile.TemporaryDirectory() as path:
            root=Path(path);dest=self.evidence(root)
            manifest=dest/'artifacts'/'run-test.txt'
            manifest.write_text('0'*64 + '  /tmp/unrelated/input/vpnctl\n')
            with self.assertRaisesRegex(ValueError, 'manifest_work_not_proven'):
                matched.retain_binaries(root, dest, {}, {})
            self.assertTrue(manifest.exists())

    def test_pre_manifest_failure_reclaims_only_new_work_after_byte_retention(self):
        with tempfile.TemporaryDirectory() as path:
            root=Path(path);dest=self.evidence(root)
            before=matched.work_directories()
            work=Path(tempfile.mkdtemp(prefix='vpnctl-vm.',dir='/tmp'))
            try:
                (work/'input').mkdir();(work/'image').mkdir()
                (work/'input'/'vpnctl').write_bytes(b'partial-executable-evidence')
                (work/'image'/'guest.raw').write_bytes(b'partial-image')
                after=matched.work_directories()
                matched.retain_binaries(root,dest,before,after)
                self.assertFalse(work.exists())
                self.assertTrue(all(Path(p).exists() for p in before))
                evidence=json.loads((dest/'retained-binaries.json').read_text())
                self.assertEqual((root/evidence['vpnctl']['retained_path']).read_bytes(),b'partial-executable-evidence')
            finally:
                if work.exists():shutil.rmtree(work)

    def test_existing_work_cannot_be_reclaimed(self):
        with tempfile.TemporaryDirectory() as path:
            root=Path(path);dest=self.evidence(root)
            work=Path(tempfile.mkdtemp(prefix='vpnctl-vm.',dir='/tmp'))
            try:
                before=matched.work_directories()
                matched.retain_binaries(root,dest,before,before)
                self.assertTrue(work.exists())
            finally:
                shutil.rmtree(work)


class DisposableKVMTests(unittest.TestCase):
    environment = {'GITHUB_ACTIONS':'true', 'RUNNER_ENVIRONMENT':'github-hosted', 'GITHUB_RUN_ATTEMPT':'1'}
    allowed = {'character_device':True, 'device':1, 'inode':2, 'rdev':3, 'readable':True, 'writable':True}

    def test_local_or_rerun_cannot_mutate_permissions(self):
        for env in ({}, dict(self.environment, RUNNER_ENVIRONMENT='self-hosted'), dict(self.environment, GITHUB_RUN_ATTEMPT='2')):
            with self.subTest(env=env), tempfile.TemporaryDirectory() as tmp:
                with patch.dict(matched.os.environ, env, clear=True), patch.object(matched, 'kvm_snapshot') as snapshot, patch.object(matched.subprocess, 'run') as run:
                    with self.assertRaisesRegex(RuntimeError, 'fresh_disposable'):
                        matched.prepare_kvm(Path(tmp))
                    snapshot.assert_not_called();run.assert_not_called()

    def test_existing_access_needs_no_privileged_command(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(matched.os.environ,self.environment,clear=True), patch.object(matched,'kvm_snapshot',return_value=self.allowed), patch.object(matched.subprocess,'run') as run:
            matched.prepare_kvm(Path(tmp));run.assert_not_called()
            self.assertFalse(json.loads((Path(tmp)/'kvm-access.json').read_text())['refreshed'])

    def test_failed_permission_grant_stays_an_error(self):
        denied=dict(self.allowed,writable=False)
        with tempfile.TemporaryDirectory() as tmp, patch.dict(matched.os.environ,self.environment,clear=True), patch.object(matched,'kvm_snapshot',return_value=denied), patch.object(matched.subprocess,'run') as run:
            with self.assertRaisesRegex(RuntimeError,'KVM_access_not_established'):
                matched.prepare_kvm(Path(tmp))
            run.assert_called_once()
            self.assertFalse(json.loads((Path(tmp)/'kvm-access.json').read_text())['prepared']['writable'])

    def test_permission_loss_between_invocations_is_prepared_without_test_retry(self):
        denied=dict(self.allowed,readable=False,writable=False)
        snapshots=[self.allowed,self.allowed,denied,denied,self.allowed,self.allowed]
        from subprocess import CompletedProcess
        commands=[]
        def invoke(args,**kwargs):
            commands.append(args)
            return CompletedProcess(args,1 if args[0]=='bash' and sum(c[0]=='bash' for c in commands)==1 else 0)
        previous_mask=matched.os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as tmp, patch.dict(matched.os.environ,self.environment,clear=True), patch.object(matched,'kvm_snapshot',side_effect=snapshots), patch.object(matched,'work_directories',return_value={}), patch.object(matched,'retain_binaries'), patch.object(matched.subprocess,'run',side_effect=invoke):
                root=Path(tmp);first=root/'first';second=root/'second';first.mkdir();second.mkdir()
                self.assertEqual(matched.invoke_vm(root,{'cases':[4,8]},first,root,'image'),1)
                self.assertEqual(matched.invoke_vm(root,{'cases':[4,8]},second,root,'image'),0)
                self.assertEqual(json.loads((first/'process-exit.json').read_text())['exit_code'],1)
                self.assertFalse(json.loads((first/'kvm-after.json').read_text())['writable'])
                self.assertTrue(json.loads((second/'kvm-access.json').read_text())['refreshed'])
                self.assertEqual(sum(c[0]=='bash' for c in commands),2)
                privileged=[c for c in commands if c[0]=='sudo']
                self.assertEqual(privileged,[['sudo','-n','setfacl','-m',f'u:{matched.os.getuid()}:rw','/dev/kvm']])
        finally:matched.os.umask(previous_mask)

    def test_retention_failure_preserves_original_exit_and_post_access(self):
        from subprocess import CompletedProcess
        with tempfile.TemporaryDirectory() as tmp, patch.dict(matched.os.environ,self.environment,clear=True), patch.object(matched,'kvm_snapshot',return_value=self.allowed), patch.object(matched,'work_directories',return_value={}), patch.object(matched,'retain_binaries',side_effect=ValueError('retention-test')), patch.object(matched.subprocess,'run',return_value=CompletedProcess([],1)) as run:
            root=Path(tmp)
            with self.assertRaisesRegex(RuntimeError,'post_invocation_evidence_incomplete'):
                matched.invoke_vm(root,{'cases':[4,8]},root,root,'image')
            run.assert_called_once()
            self.assertEqual(json.loads((root/'process-exit.json').read_text())['exit_code'],1)
            self.assertEqual(json.loads((root/'kvm-after.json').read_text()),self.allowed)
            self.assertEqual(json.loads((root/'post-invocation-errors.json').read_text())['errors'],[{'stage':'retention','exception':'ValueError'}])

    def test_post_snapshot_failure_does_not_skip_binary_retention(self):
        from subprocess import CompletedProcess
        snapshots=[self.allowed,self.allowed,RuntimeError('snapshot-test')]
        with tempfile.TemporaryDirectory() as tmp, patch.dict(matched.os.environ,self.environment,clear=True), patch.object(matched,'kvm_snapshot',side_effect=snapshots), patch.object(matched,'work_directories',return_value={}), patch.object(matched,'retain_binaries') as retain, patch.object(matched.subprocess,'run',return_value=CompletedProcess([],0)) as run:
            root=Path(tmp)
            with self.assertRaisesRegex(RuntimeError,'post_invocation_evidence_incomplete'):
                matched.invoke_vm(root,{'cases':[4,8]},root,root,'image')
            run.assert_called_once();retain.assert_called_once()
            self.assertEqual(json.loads((root/'process-exit.json').read_text())['exit_code'],0)
            self.assertEqual(json.loads((root/'post-invocation-errors.json').read_text())['errors'],[{'stage':'kvm_snapshot','exception':'RuntimeError'}])

    def test_snapshot_bracket_contains_access_checks(self):
        from types import SimpleNamespace
        info=SimpleNamespace(st_mode=matched.stat.S_IFCHR|0o660,st_dev=1,st_ino=2,st_rdev=3,st_uid=4,st_gid=5)
        calls=[]
        def clock():calls.append('clock');return len(calls)
        def access(*_):calls.append('access');return True
        with patch.object(matched.Path,'stat',return_value=info), patch.object(matched,'read_command',return_value='fixed-acl'), patch.object(matched.os,'access',side_effect=access), patch.object(matched.time,'monotonic_ns',side_effect=clock):
            result=matched.kvm_snapshot()
        self.assertEqual(calls,['clock','access','access','clock'])
        self.assertLess(result['started_monotonic_ns'],result['finished_monotonic_ns'])


if __name__ == '__main__':
    unittest.main()
