import unittest
from unittest.mock import patch
from process_memory import parse_status, sample_memory


class MemoryTests(unittest.TestCase):
    def test_explicit_current_and_peak_units(self):
        self.assertEqual(parse_status('VmHWM:\t12000 kB\nVmRSS:\t10000 kB\n'),
                         {'rss_kib': 10000, 'address_space_peak_rss_kib': 12000})

    def test_missing_duplicate_or_wrong_units_cannot_be_zero_memory(self):
        for text in ('', 'VmRSS: 10 kB', 'VmRSS: 10 B\nVmHWM: 11 kB',
                     'VmRSS: 10 kB\nVmHWM: 11 kB\nVmRSS: 12 kB'):
            with self.assertRaises(ValueError): parse_status(text)
        with patch('process_memory.Path.read_text', side_effect=OSError('gone')):
            self.assertEqual(sample_memory()['unavailable'], 'OSError')

    def test_own_process_can_be_sampled_without_privileges(self):
        result = sample_memory()
        self.assertNotIn('unavailable', result)
        self.assertGreater(result['rss_kib'], 0)


if __name__ == '__main__': unittest.main()
