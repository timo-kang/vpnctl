import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import passive_tcp
import passive_overlay

REPO = Path(__file__).resolve().parents[2]


class ProtocolTests(unittest.TestCase):
    def test_fixed_schedule_preserves_failure_without_retry(self):
        called = []
        def invoke(index):
            called.append(index)
            return {'index': index, 'exit': 1 if index == 2 else 0}
        rows = passive_tcp.schedule(invoke)
        self.assertEqual(called, [1, 2, 3, 4])
        self.assertEqual([row['exit'] for row in rows], [0, 1, 0, 0])
        self.assertEqual(passive_tcp.cell_args(), ['./scripts/test-vm.sh', '--case',
            'application-capacity-8', '--robot-cpus', '1', '--cpu-layout', 'split'])

    def test_shared_host_and_rerun_rejected(self):
        good = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'GITHUB_RUN_ATTEMPT': '1'}
        with patch.dict(os.environ, good, clear=True): passive_tcp.require_disposable()
        for key in good:
            with patch.dict(os.environ, {**good, key: 'other'}, clear=True), self.assertRaises(RuntimeError):
                passive_tcp.require_disposable()

    def test_product_identity_including_race_is_mandatory(self):
        settings = {'-race': 'true', 'GOOS': 'linux', 'GOARCH': 'amd64',
                    'vcs.revision': passive_tcp.SOURCE, 'vcs.modified': 'false'}
        def info(values): return 'vpnctl: go1.25.0\n'+''.join('\tbuild\t'+k+'='+v+'\n' for k,v in values.items())
        passive_tcp.check_build(info(settings))
        for key in settings:
            with self.subTest(key=key), self.assertRaises(ValueError):
                passive_tcp.check_build(info({**settings, key: 'wrong'}))

    def test_unchanged_acceptance_and_exact_instrumentation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Public controller contains candidate code unchanged except its CI.
            for name in ('observer.py', 'app_recovery.py', 'make_image.py'):
                expected = subprocess.check_output(['git', '-C', str(REPO), 'show',
                    passive_tcp.SOURCE+':tests/vm/'+name])
                self.assertEqual((REPO/'tests/vm'/name).read_bytes(), expected)
            context = passive_overlay.prepare_context(REPO, root)
            for name in ('observer.py', 'app_recovery.py', 'make_image.py'):
                self.assertEqual((context/name).read_bytes(), (REPO/'tests/vm'/name).read_bytes())
            self.assertEqual((context/'passive/mode').read_text(), '1\n')
            self.assertTrue((context/'passive/process_memory.py').is_file())
            overlay, _ = passive_overlay.prepare(REPO, root)
            mapping = json.loads(overlay.read_text())['Replace']
            self.assertEqual({Path(k).name for k in mapping}, {'m3_topology_test.go',
                'm3_observation_capacity_test.go','private_passive_test.go','private_passive_metadata_test.go'})
            original = (REPO/'tests/integration/m3_observation_capacity_test.go').read_text()
            changed = (root/'overlay/m3_observation_capacity_test.go').read_text()
            restored = changed.replace('\tprivatePassiveTrace(t, f, report)\n','')
            for address in ('"198.18.0.3"', 'm3Target', 'target'):
                restored = restored.replace(f'privatePayload(t, f, {address}, report)', f'applicationPayload(t, f, {address})')
            self.assertEqual(restored, original)

    def test_ambiguous_patch_anchor_rejected(self):
        for text in ('absent', 'target target'):
            with self.assertRaises(ValueError): passive_overlay.once(text, 'target', 'new')
