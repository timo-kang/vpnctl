"""Runner-contract tests: no VM, network, device access, or Docker execution."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import uplink_handoff as runner
from isolated_evidence import digest


class FixedUplinkValidationTests(unittest.TestCase):
    def test_arguments_preserve_case_layout_and_load(self):
        for row in runner.schedule():
            args = runner.arguments(row)
            self.assertEqual('--uplink-api-load' in args, row['api_load'])
            self.assertEqual(args[args.index('--case')+1], row['case'])
            self.assertEqual(args[args.index('--cpu-layout')+1], row['layout'])

    def test_failures_and_infrastructure_errors_do_not_retry_or_stop_schedule(self):
        seen = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def invoke(row, destination):
                seen.append(row['sequence'])
                if row['sequence'] == 2:
                    raise RuntimeError('unavailable image')
                return 1 if row['sequence'] == 1 else 0
            self.assertEqual(runner.execute_schedule(root, invoke), 1)
            self.assertEqual(seen, list(range(1,11)))
            progress = json.loads((root / 'progress.json').read_text())
            self.assertEqual([r['exit_code'] for r in progress], [1, 125]+[0]*8)
            self.assertEqual(json.loads((root / 'complete.json').read_text()), {'invocations': 10, 'all_exit_zero': False})
            with self.assertRaises(FileExistsError):
                runner.execute_schedule(root, invoke)

    def test_late_failure_is_preserved_not_converted_to_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            self.assertEqual(runner.execute_schedule(root, lambda row, destination: 1 if row['sequence']==10 else 0),1)
            progress=json.loads((root/'progress.json').read_text())
            self.assertEqual([row['exit_code'] for row in progress],[0]*9+[1])
            self.assertEqual(json.loads((root/'complete.json').read_text()),{'invocations':10,'all_exit_zero':False})

    def test_zero_exit_requires_explicit_diagnostic_nonqualification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = root / 'artifacts'
            artifacts.mkdir()
            row = runner.schedule()[2]
            prepared = {'image': {'fixed': 'hash'}}
            with self.assertRaises(ValueError):
                runner.validate_trial(root, row, prepared, 0)
            runner.validate_trial(root, row, prepared, 1)  # Retain early failure.
            evidence = {'image': prepared['image'], 'cpu_layout': 'split', 'guest_vcpus': 2, 'cpu_max': ['200000', '100000']}
            (artifacts / 'runner.json').write_text(json.dumps(evidence))
            verdict = {'case': row['case'], 'completed': True, 'qualified': False, 'unsupported_reason':'diagnostic_only_no_qualification'}
            for change in ({'qualified': True}, {'completed': False}, {'case': 'another-case'}, {'unsupported_reason': 'other'}):
                (artifacts / 'verdicts.json').write_text(json.dumps([dict(verdict, **change)]))
                with self.assertRaises(ValueError):
                    runner.validate_trial(root, row, prepared, 0)
            (artifacts / 'verdicts.json').write_text(json.dumps([verdict]))
            runner.validate_trial(root, row, prepared, 0)
            evidence['image'] = {'different': 'hash'}
            (artifacts / 'runner.json').write_text(json.dumps(evidence))
            with self.assertRaises(ValueError):
                runner.validate_trial(root, row, prepared, 0)

    def test_guest_bytes_and_identity_are_fixed(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / 'image').mkdir()
            disk = work / 'image/guest.qcow2'
            disk.write_bytes(b'original')
            image = {'sha256': {'guest.qcow2': digest(disk)}}
            (work / 'image/image.json').write_text(json.dumps(image))
            st = work.stat()
            prepared = dict(work=str(work), identity=(st.st_dev, st.st_ino), image=image)
            runner.verify_image(prepared)
            disk.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                runner.verify_image(prepared)
            disk.unlink()
            disk.symlink_to(work / 'image/image.json')
            with self.assertRaises(ValueError):
                runner.verify_image(prepared)

    def test_prepared_guest_requires_exact_source_manifest_and_binary_bytes(self):
        with tempfile.TemporaryDirectory(prefix='vpnctl-vm.', dir='/tmp') as directory, \
                tempfile.TemporaryDirectory() as evidence:
            work, root = Path(directory), Path(evidence)
            (work / 'image').mkdir()
            (root / 'binaries').mkdir()
            destination = root / 'run-01'
            (destination / 'artifacts').mkdir(parents=True)
            image = {'sha256': {}, 'binaries': {}}
            for name in ('vmlinuz', 'initrd', 'guest.qcow2'):
                path = work / 'image' / name
                path.write_text(name)
                image['sha256'][name] = digest(path)
            for name in runner.BINARIES:
                path = work / 'input' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(name)
                image['binaries'][name] = digest(path)
            (work / 'image/image.json').write_text(json.dumps(image))
            manifest = destination / 'artifacts/run-initial.txt'
            fields = f'suite_commit={runner.SOURCE}\nsuite_dirty=false\nsuite_race=1\nimage_id=sha256:' + 'a'*64 + '\n'
            manifest.write_text(fields)
            st = work.stat()
            with mock.patch.object(runner, 'work_directories', return_value={str(work): (st.st_dev, st.st_ino)}), \
                    mock.patch.object(runner, 'binary_build_info', return_value={'fixed': True}):
                prepared = runner.prepared_image(root, destination, {}, '1')
                self.assertEqual(prepared['image'], image)
                self.assertEqual(len(list((root / 'binaries').iterdir())), len(runner.BINARIES))
                manifest.write_text(fields.replace('suite_race=1', 'suite_race=0'))
                with self.assertRaises(ValueError):
                    runner.prepared_image(root, destination, {}, '1')
                manifest.write_text(fields)
                (work / 'input/vpnctl').write_text('other build')
                with self.assertRaises(ValueError):
                    runner.prepared_image(root, destination, {}, '1')

    def test_container_isolation_preserves_fixed_image_and_distinct_runtime(self):
        row = runner.schedule()[1]
        with mock.patch.object(Path, 'stat', return_value=mock.Mock(st_gid=123)):
            args = runner.container_command(row, Path('/results/run-02'),
                {'work': '/tmp/private', 'image_id': 'sha256:fixed'}, 'owned-trial', Path('/tmp/private/runtime-02'))
        for flag, value in (('--network', 'none'), ('--cap-drop', 'ALL'), ('--security-opt', 'no-new-privileges'),
                            ('--cpus', '2'), ('--memory', '2g'), ('--memory-swap', '2g'), ('--pids-limit', '256')):
            self.assertEqual(args[args.index(flag)+1], value)
        self.assertIn('--read-only', args)
        self.assertIn('type=bind,src=/tmp/private/image,dst=/input,readonly', args)
        self.assertIn('type=bind,src=/tmp/private/runtime-02,dst=/work', args)
        self.assertNotIn('--uplink-api-load', args)
        self.assertNotIn('--privileged', args)

    def test_runtime_is_retained_until_container_termination_is_confirmed(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / 'owned-runtime'
            runtime.mkdir()
            (runtime / 'disk').write_text('guest disk')
            with mock.patch.object(runner.subprocess, 'run'), \
                    mock.patch.object(runner, 'read_command', return_value='still-running'):
                with self.assertRaises(RuntimeError):
                    runner.cleanup_runtime(runtime, 'owned-trial', None)
            self.assertTrue((runtime / 'disk').exists())
            with mock.patch.object(runner.subprocess, 'run'), \
                    mock.patch.object(runner, 'read_command', return_value=''):
                runner.cleanup_runtime(runtime, 'owned-trial', None)
            self.assertFalse(runtime.exists())


if __name__ == '__main__':
    unittest.main()
