import unittest
from export_contract import validate_mode, validate_raw


class ExportTests(unittest.TestCase):
    def test_off_requires_explicit_mode_and_absent_collector(self):
        validate_mode({'private_trace_requested': False}, '0', [])
        for report, files in [({}, []), ({'private_trace_requested': True}, []),
                              ({'private_trace_requested': False}, ['private-passive.json']),
                              ({'private_trace_requested': False, 'private_trace_summary': {}}, [])]:
            with self.assertRaises(ValueError): validate_mode(report, '0', files)

    def test_on_cannot_be_reclassified_as_off_when_collection_fails(self):
        for files in ([], ['private-passive.json']):
            with self.assertRaises(ValueError): validate_mode({'private_trace_requested': True}, '1', files)
        with self.assertRaises(ValueError):
            validate_mode({'private_trace_requested': True, 'private_trace_process_error': 'failed'}, '1',
                          ['private-passive.json', 'private-passive.ready', 'private-passive.log'])

    def test_raw_clock_and_counts_are_exact_with_number_preserving_fixture(self):
        raw = {'events': [1], 'wall_ns': 1792733623262739326, 'complete': True}
        summary = {'retained_events': 1, 'wall_ns': 1792733623262739326, 'complete': True}
        validate_raw(raw, summary)
        summary['wall_ns'] -= 126
        with self.assertRaises(ValueError): validate_raw(raw, summary)


if __name__ == '__main__': unittest.main()
