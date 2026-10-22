import os
from pathlib import Path
import tempfile
import unittest

import storage_probe as probe
import storage_overlay as overlay


class StorageProvenance(unittest.TestCase):
    def test_descriptor_mount_matches_real_objects_without_reading_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            path.write_text('not JSON: private state must never be read')
            before = path.read_bytes()
            row = probe.inspect_path(directory)
            self.assertTrue(row['available'])
            self.assertTrue(row['same_mount'])
            for key, expected in [('directory', Path(directory)), ('state', path)]:
                self.assertEqual(row[key]['inode'], expected.stat().st_ino)
                self.assertTrue(row[key]['mount']['filesystem'])
            self.assertEqual(path.read_bytes(), before)
            self.assertNotIn('private state', str(row))

    def test_mount_id_selects_bound_object_not_longest_path(self):
        rows = '3 1 0:4 / /tmp rw - tmpfs tmpfs rw\n7 1 8:2 / / rw - ext4 /dev/vda rw\n'
        self.assertEqual(probe.mount_record('mnt_id:\t7\n', rows)['filesystem'], 'ext4')
        for bad_info, bad_rows in [('mnt_id: 8\n', rows), ('', rows), ('mnt_id: 7\nmnt_id: 7\n', rows),
                                   ('mnt_id: 7\n', rows + rows), ('mnt_id: 7\n', '7 bad\n')]:
            with self.subTest(info=bad_info), self.assertRaises(ValueError):
                probe.mount_record(bad_info, bad_rows)

    def test_symlink_and_missing_state_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            with self.assertRaises(OSError):
                probe.inspect_path(path)
            (path / 'state.json').symlink_to('/dev/null')
            with self.assertRaises(OSError):
                probe.inspect_path(path)

    def test_additive_hook_has_identical_source_after_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, hashes = overlay.prepare(overlay.REPO, root)
            original = (overlay.REPO / 'tests/integration/m3_observation_capacity_test.go').read_text()
            self.assertEqual((root/'storage-capacity.go').read_text().replace(overlay.HOOK,''), original)
            self.assertEqual(len(hashes), 2)
            self.assertLess(original.index(overlay.ANCHOR), original.index('report["phase"] = "app2_activation"'))


if __name__ == '__main__':
    unittest.main()
