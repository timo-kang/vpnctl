from pathlib import Path
import tempfile
import unittest
from seal_trace import members


class EvidenceSelectionTests(unittest.TestCase):
    def test_raw_results_and_manifest_included_but_disks_and_checkouts_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = ('controller.log','diagnostic-inputs.json','runs/01/results/private-guest/raw.json',
                     'source/local-secret','vm-context/image.raw','guest.qcow2')
            for name in names:
                path = root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('test')
            self.assertEqual(set(members(root)), set(names[:3]))

    def test_linked_evidence_cannot_read_outside_the_declared_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'controller.log').symlink_to('/etc/hostname')
            with self.assertRaises(ValueError): members(root)

    def test_empty_capture_is_not_a_successful_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError): members(Path(directory))
