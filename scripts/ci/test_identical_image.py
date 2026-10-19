import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import identical_image as experiment
import seal_identical as seal


class Contracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def file(self, name, data='test'):
        path = self.root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)
        return path

    def test_archive_excludes_mutable_disks_caches_and_arbitrary_files(self):
        expected = ['bundle/image/guest.qcow2', 'controller.log', 'runs-ci/01/results/observer.jsonl']
        for name in expected + ['bundle/image/guest.raw', 'runs-ci/01/work/overlay.qcow2',
                                'source/configs/pki/private.key', 'cache/key', 'arbitrary.secret']:
            self.file(name)
        self.assertEqual(seal.members(self.root), sorted(expected))

    def test_archive_rejects_symlinks_and_hardlinks(self):
        target = self.file('private')
        link = self.root/'controller.log'; link.symlink_to(target)
        with self.assertRaises(ValueError): seal.members(self.root)
        link.unlink(); link.hardlink_to(target)
        with self.assertRaises(ValueError): seal.members(self.root)

    def test_archive_rejects_linked_ancestor(self):
        elsewhere = self.root/'elsewhere'; elsewhere.mkdir()
        (elsewhere/'runtime.tar').write_text('private')
        (self.root/'bundle').symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaises(ValueError): seal.members(self.root)

    def test_archive_bound_before_streaming(self):
        self.file('controller.log', '12345')
        with patch.object(seal, 'MAX_BYTES', 4), self.assertRaises(ValueError): seal.members(self.root)

    def test_inventory_rejects_missing_unexpected_and_symlink_files(self):
        with patch.object(experiment, 'BUNDLE_FILES', ['a']):
            with self.assertRaises(ValueError): experiment.inventory(self.root)
            self.file('a'); self.assertEqual(set(experiment.inventory(self.root)), {'a'})
            self.file('b')
            with self.assertRaises(ValueError): experiment.inventory(self.root)
            (self.root/'b').unlink(); (self.root/'a').unlink()
            (self.root/'a').symlink_to('/etc/hostname')
            with self.assertRaises(ValueError): experiment.inventory(self.root)

    def test_inventory_rejects_unexpected_symlink_directory(self):
        with patch.object(experiment, 'BUNDLE_FILES', ['a']):
            self.file('a'); (self.root/'escape').symlink_to('/tmp', target_is_directory=True)
            with self.assertRaises(ValueError): experiment.inventory(self.root)

    def test_manifest_rejects_changed_binary_image_controller_or_schedule(self):
        bundle = self.root/'bundle'
        for name in experiment.BUNDLE_FILES:
            self.file('bundle/'+name)
        image = {'sha256':{n:experiment.lab.digest(bundle/'image'/n) for n in experiment.IMAGE_FILES if n != 'image.json'},
                 'binaries':{n:experiment.lab.digest(bundle/'input'/n) for n in experiment.BINARIES}}
        (bundle/'image/image.json').write_text(json.dumps(image))
        (bundle/'build.json').write_text(json.dumps({'source':experiment.SOURCE, 'race':True, 'runner_image':'fixed'}))
        manifest = {'source':experiment.SOURCE, 'cells':[list(c) for c in experiment.CELLS],
                    'tools':{n:experiment.lab.digest(experiment.REPO/n) for n in experiment.TOOLS},
                    'files':experiment.inventory(bundle)}
        path = self.root/'bundle-manifest.json'; path.write_text(json.dumps(manifest))
        with patch.object(experiment.lab, 'image_id', return_value='fixed'):
            experiment.verify(self.root)
            for name in ('input/vpnctl', 'image/initrd', 'runtime.tar'):
                target = bundle/name; original = target.read_bytes(); target.write_bytes(b'changed')
                with self.assertRaises(ValueError): experiment.verify(self.root)
                target.write_bytes(original)
            for key, value in (('cells', []), ('tools', {}), ('source', '0'*40)):
                altered = dict(manifest, **{key:value}); path.write_text(json.dumps(altered))
                with self.assertRaises(ValueError): experiment.verify(self.root)
                path.write_text(json.dumps(manifest))
        with patch.object(experiment.lab, 'image_id', return_value='changed'), self.assertRaises(ValueError):
            experiment.verify(self.root)

    def test_actual_build_rejects_missing_race_dirty_and_wrong_source(self):
        text = 'binary: go1.25.0\n' + ''.join('\tbuild\t'+s+'\n' for s in
            ['-race=true', 'GOOS=linux', 'GOARCH=amd64', 'vcs.revision='+experiment.SOURCE, 'vcs.modified=false'])
        experiment.check_build(text, 'vpnctl')
        for bad in (text.replace('-race=true', '-race=false'), text.replace('modified=false', 'modified=true'),
                    text.replace(experiment.SOURCE, '0'*40)):
            with self.assertRaises(ValueError): experiment.check_build(bad, 'vpnctl')

    def test_disposable_attempt_guard(self):
        env = {'GITHUB_ACTIONS':'true', 'RUNNER_ENVIRONMENT':'github-hosted', 'GITHUB_RUN_ATTEMPT':'1'}
        with patch.dict('os.environ', env, clear=True): experiment.require_disposable()
        for key in env:
            with patch.dict('os.environ', dict(env, **{key:'wrong'}), clear=True), self.assertRaises(RuntimeError):
                experiment.require_disposable()

    def test_runtime_keeps_all_isolation_and_cpu_contracts(self):
        with patch.object(experiment.os, 'stat') as stat:
            stat.return_value.st_gid = 42
            for sequence, layout in experiment.CELLS:
                name, args = experiment.runtime_args(self.root, self.root/'runs-ci/01', {'runner_image':'sha256:fixed'}, '2,3', sequence, layout)
                for arg in ('--read-only', '--device', '/dev/kvm', '--cap-drop', 'ALL', '--network', 'none',
                            '--memory=2g', '--memory-swap=2g', '--pids-limit=256', 'no-new-privileges', '--group-add', '42',
                            '--cpuset-cpus=2,3', '--robot-cpus', '0.5', 'application-capacity-8', '--cpu-layout', layout):
                    self.assertIn(arg, args)
                self.assertIn('--cpus='+('2' if layout == 'split' else '1'), args)
                self.assertNotIn('--privileged', args)
                self.assertTrue(any('dst=/input,readonly' in arg for arg in args))

    def test_four_cells_preserve_product_and_infrastructure_failures(self):
        seen = []
        def invoke(sequence, destination):
            seen.append(sequence)
            if sequence == 2: raise TimeoutError()
            return 1 if sequence == 1 else 0
        baseline = {'boot_id':'same', 'containers':{'existing':'unchanged'}}
        with patch.object(experiment, 'verify', return_value={'runner_image':'fixed'}), \
             patch.object(experiment.lab, 'host_snapshot', return_value=baseline), \
             patch.object(experiment, 'host_context', return_value={}), \
             patch.object(experiment, 'runtime_args', return_value=('owned', ['fixed'])), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(experiment.run(self.root, '2,3', 'ci', invoke), 1)
            self.assertEqual(seen, [1,2,3,4])
            rows = json.loads((self.root/'runs-ci/complete.json').read_text())
            self.assertEqual([r['exit_code'] for r in rows], [1,125,0,0])
            self.assertEqual(rows[1]['infrastructure_error'], 'TimeoutError')
            self.assertEqual([r['layout'] for r in rows], ['shared','split','split','shared'])
            with self.assertRaises(FileExistsError): experiment.run(self.root, '2,3', 'ci', invoke)
            self.assertEqual(seen, [1,2,3,4])

    def test_host_isolation_failure_stops_and_retains_exit(self):
        baseline = {'boot_id':'same', 'containers':{}}
        changed = {'boot_id':'different', 'containers':{}}
        with patch.object(experiment, 'verify', return_value={'runner_image':'fixed'}), \
             patch.object(experiment.lab, 'host_snapshot', side_effect=[baseline, baseline, changed]), \
             patch.object(experiment, 'host_context', return_value={}), \
             patch.object(experiment, 'runtime_args', return_value=('owned', ['fixed'])):
            with self.assertRaises(RuntimeError): experiment.run(self.root, '2,3', 'ci', lambda *_: 0)
        self.assertTrue((self.root/'runs-ci/01/exit.json').is_file())
        self.assertFalse((self.root/'runs-ci/02').exists())


if __name__ == '__main__':
    unittest.main()
