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


if __name__ == '__main__':
    unittest.main()
