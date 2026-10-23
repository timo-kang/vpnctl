import sys
from pathlib import Path
import unittest
import tempfile
import json
from collections import Counter
from test_correlate import sample
from analyze import analyze, attribute, check_recording, EVENTS


class AttributionTests(unittest.TestCase):
    def row(self, connected=True, ok=True):
        tcp = {'private_pid': 10}
        if connected: tcp['connected_at'] = '2026-10-23T00:00:00Z'
        return {'target': '127.0.0.1', 'probe': {'tcp': tcp, 'ok': ok, 'failure': 'timeout' if not ok else ''}}

    def events(self, case='connected'):
        events,_ = sample(case)
        for e in events:
            if 'dport' in e: e['dport'] = 9192
        return events

    def test_kernel_established_go_timeout_is_preserved(self):
        f = attribute(self.events(), self.row(False, False))
        self.assertEqual(f['classification'], 'kernel_established_go_connect_failed')
        self.assertEqual(f['established_ns'], 130)

    def test_exchange_failure_is_not_connect_failure(self):
        self.assertEqual(attribute(self.events(), self.row(True,False))['classification'], 'post_connect_failure')

    def test_no_establishment_and_missing_evidence_are_distinct(self):
        self.assertEqual(attribute(self.events('timeout'), self.row(False,False))['classification'], 'kernel_not_established')
        with self.assertRaises(ValueError): attribute(self.events()[1:], self.row())
        with self.assertRaises(ValueError): attribute(self.events('timeout'), self.row())

    def test_counter_consistency_cannot_hide_missing_raw_records(self):
        counts = [dict(event=e,cpu=c,count=0,samples=0,lost=0,lost_records=0,
                       enabled_ns=20,running_ns=20,unexpected_records=[])
                  for e in EVENTS for c in (0,1)]
        r = dict(complete=True, errors=[], counts=counts, events=[])
        check_recording(r)
        counts[0].update(count=1,samples=1)
        with self.assertRaisesRegex(ValueError, 'retained records'): check_recording(r)

    def test_zero_counters_do_not_qualify_actual_payload_coverage(self):
        counts = [dict(event=e,cpu=c,count=0,samples=0,lost=0,lost_records=0,
                       enabled_ns=20,running_ns=20,unexpected_records=[])
                  for e in EVENTS for c in (0,1)]
        raw = dict(complete=True, errors=[], counts=counts, events=[])
        check_recording(raw)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'application-capacity-test').mkdir()
            (root/'application-capacity-test/verdict.json').write_text('{"completed":true,"qualified":true}')
            for index in (0,3,7):
                fixture = root/'private-guest/results'/('m3-authority-'+str(index))
                fixture.mkdir(parents=True)
                report = dict(healthy_index=index, private_payload_probes=[self.row()])
                (fixture/'application-mixed-candidates.json').write_text(json.dumps(report))
                (fixture/'private-passive.json').write_text(json.dumps(raw))
            result = analyze(root)
            self.assertFalse(result['integration_coverage_complete'])
            self.assertEqual(len(result['fixtures']), 3)
            self.assertTrue(all(f['attribution_errors'] for f in result['fixtures']))

    def test_missing_clock_metadata_cannot_leave_coverage_green(self):
        events = self.events()
        actual = Counter((e['event'],e['cpu']) for e in events)
        counts = [dict(event=e,cpu=c,count=actual[e,c],samples=actual[e,c],lost=0,lost_records=0,
                       enabled_ns=20,running_ns=20,unexpected_records=[])
                  for e in EVENTS for c in (0,1)]
        raw = dict(complete=True, errors=[], counts=counts, events=events)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'application-capacity-test').mkdir()
            (root/'application-capacity-test/verdict.json').write_text('{}')
            fixture = root/'private-guest/results/m3-authority-1'
            fixture.mkdir(parents=True)
            (fixture/'application-mixed-candidates.json').write_text(json.dumps(
                dict(healthy_index=0, private_payload_probes=[self.row()])))
            (fixture/'private-passive.json').write_text(json.dumps(raw))
            result = analyze(root)
            item = result['fixtures'][0]
            self.assertIn('diagnostic_error', item)
            self.assertFalse(item['diagnostic_complete'])


if __name__ == '__main__': unittest.main()
