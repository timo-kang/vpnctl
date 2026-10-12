# Copyright 2026 Jonghyeok Kang
# SPDX-License-Identifier: Apache-2.0
import unittest
from unittest.mock import Mock, patch

from probe import Probe


class ProbeTests(unittest.TestCase):
    def probe(self):
        with patch('probe.ssl.create_default_context'):
            return Probe(('127.0.0.1', 443), 'example.com', 'test-ca', interval=.05)

    def test_only_correct_payload_resets_backoff(self):
        p = self.probe()
        waits = []
        stop = Mock()
        stop.is_set.side_effect = lambda: len(waits) >= 4
        stop.wait.side_effect = waits.append
        with patch.object(p, '_connect', return_value=Mock()), patch.object(p, '_exchange', side_effect=[False, False, True, False]), patch('probe.random.uniform', side_effect=lambda lo, hi: hi):
            p.run(stop)
        self.assertEqual(waits, [.25, .5, .05, .25])
        view = p.snapshot()
        self.assertEqual(view['correct'], 1)
        self.assertEqual(view['outcome_unknown'], 3)
        self.assertEqual([x['request'] for x in view['events']], [1, 2, 3, 4])

    def test_storage_bound_and_missing_response(self):
        p = self.probe()
        for i in range(5000):
            p.record(dict(request=i+1, existing_socket=False, outcome_unknown=True, correct=False, finished_boot_ns='1'))
        view = p.snapshot()
        self.assertEqual(len(view['events']), 4096)
        self.assertEqual(view['dropped_events'], 904)
        self.assertEqual(view['attempts'], 5000)
        self.assertEqual(view['first_correct_boot_ns'], '0')

    def test_response_without_newline_is_bounded(self):
        p = self.probe()
        conn = Mock()
        conn.send.side_effect = len
        conn.recv.return_value = b'x'
        stop = Mock()
        stop.is_set.return_value = False
        self.assertFalse(p._exchange(conn, b'hello\n', stop))
        self.assertEqual(conn.recv.call_count, 256)


if __name__ == '__main__':
    unittest.main()
