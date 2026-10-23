import json
from pathlib import Path
import tempfile
import unittest
from run_observer import run


class OutcomeTests(unittest.TestCase):
    def invoke(self, original, export):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'exit.json'
            result = run(original, export, path)
            return result, json.loads(path.read_text())

    def test_original_failure_survives_successful_export(self):
        def original(): raise SystemExit(2)
        code, row = self.invoke(original, lambda: 0)
        self.assertEqual(code, 2)
        self.assertEqual(row, {'original_observer_exit': 2, 'extraction_exit': 0})

    def test_export_failure_cannot_turn_trial_green(self):
        code, row = self.invoke(lambda: None, lambda: 1)
        self.assertEqual(code, 1)
        self.assertEqual(row['original_observer_exit'], 0)

    def test_exception_still_exports_and_records_original_error(self):
        called = []
        def original(): raise RuntimeError('observer failed')
        def export(): called.append(True); return 0
        code, row = self.invoke(original, export)
        self.assertEqual(code, 1)
        self.assertEqual(called, [True])
        self.assertIn('observer failed', row['original_observer_error'])

    def test_export_exception_preserves_original_verdict(self):
        def export(): raise RuntimeError('copy failed')
        code, row = self.invoke(lambda: None, export)
        self.assertEqual(code, 1)
        self.assertEqual(row['original_observer_exit'], 0)
        self.assertIn('copy failed', row['extraction_error'])
