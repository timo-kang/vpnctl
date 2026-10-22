import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import kvm_access


class KVMAccess(unittest.TestCase):
    def snapshot(self, accessible=True):
        return {'character_device': True, 'readable': accessible, 'writable': accessible,
                'device': 1, 'inode': 2, 'rdev': 3}

    def test_shared_host_rejected_before_device_access(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(kvm_access, 'kvm_snapshot') as snapshot:
            with self.assertRaises(RuntimeError):
                kvm_access.prepare_kvm(Path('/unused'))
            snapshot.assert_not_called()

    def test_lost_access_is_restored_before_trial_only(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(kvm_access, 'require_disposable_runner'), \
                patch.object(kvm_access, 'kvm_snapshot', side_effect=[self.snapshot(False), self.snapshot()]), \
                patch.object(kvm_access.subprocess, 'run') as run:
            kvm_access.prepare_kvm(Path(tmp))
            self.assertEqual(run.call_args.args[0], ['sudo', '-n', 'setfacl', '-m', f'u:{os.getuid()}:rw', '/dev/kvm'])
            self.assertEqual(run.call_count, 1)

    def test_existing_access_needs_no_mutation(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(kvm_access, 'require_disposable_runner'), \
                patch.object(kvm_access, 'kvm_snapshot', return_value=self.snapshot()), \
                patch.object(kvm_access.subprocess, 'run') as run:
            kvm_access.prepare_kvm(Path(tmp))
            run.assert_not_called()

    def test_replaced_device_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(kvm_access, 'require_disposable_runner'), \
                patch.object(kvm_access, 'kvm_snapshot', side_effect=[self.snapshot(), {**self.snapshot(), 'inode': 4}]):
            with self.assertRaises(RuntimeError):
                kvm_access.prepare_kvm(Path(tmp))
