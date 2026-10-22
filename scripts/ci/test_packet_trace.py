import ast
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import packet_trace as runner
import seal_trace


class Contract(unittest.TestCase):
    def test_failures_do_not_stop_or_extend_schedule(self):
        seen = []
        def invoke(index, trace):
            seen.append((index, trace))
            return {'exit': 1 if index == 2 else 0}
        results = runner.schedule(invoke)
        self.assertEqual(seen, [(1, False), (2, True), (3, True), (4, False)])
        self.assertEqual([r['exit'] for r in results], [0, 1, 0, 0])

    def test_only_fresh_disposable_runner(self):
        expected = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'GITHUB_RUN_ATTEMPT': '1'}
        with patch.dict(os.environ, expected, clear=True):
            runner.require_disposable()
        for key in expected:
            with self.subTest(key=key), patch.dict(os.environ, {**expected, key: 'invalid'}, clear=True):
                with self.assertRaises(RuntimeError):
                    runner.require_disposable()

    def test_patch_is_only_opt_in_instrumentation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            overlay = runner.prepare_overlay(runner.REPO, root)
            document = json.loads(overlay.read_text())
            self.assertEqual(len(document['Replace']), 2)
            original = (runner.REPO / 'tests/integration/m3_observation_capacity_test.go').read_text()
            self.assertEqual((root / 'capacity.go').read_text().replace('\tprivatePacketTrace(t, f, report)\n', ''), original)
            context = runner.prepare_context(runner.REPO, root)
            for name in ('observer.py', 'guest_agent.py'):
                ast.parse((context / name).read_text())
            original_ast = ast.parse((runner.REPO / 'tests/vm/observer.py').read_text())
            changed_ast = ast.parse((context / 'observer.py').read_text())
            validators = lambda tree: {n.name: ast.dump(n) for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name.startswith('validate_')}
            self.assertEqual(validators(original_ast), validators(changed_ast))

    def test_capture_python_matches_compiled_literal(self):
        helper = (runner.REPO / 'scripts/ci/private_packet_trace_test.go').read_text()
        literal = helper.split('"-c",', 1)[1].split(')\n', 1)[0].strip()
        self.assertEqual(json.loads(literal), (runner.REPO / 'scripts/ci/capture.py').read_text())

    def test_archive_excludes_images_and_rejects_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'controller.log').write_text('bounded log')
            (root / 'guest.qcow2').write_text('private credentials')
            results = root / 'runs/01/results'
            results.mkdir(parents=True)
            (results / 'result.json').write_text('{}')
            self.assertEqual(seal_trace.members(root), ['controller.log', 'runs/01/results/result.json'])
            (results / 'escape').symlink_to(root / 'guest.qcow2')
            with self.assertRaises(ValueError):
                seal_trace.members(root)


if __name__ == '__main__':
    unittest.main()
