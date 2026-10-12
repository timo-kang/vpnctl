# Copyright 2026 Jonghyeok Kang
# SPDX-License-Identifier: Apache-2.0
import threading
import unittest

from echo_server import serve


class ServerBoundsTest(unittest.TestCase):
    def test_invalid_bounds_rejected_before_loading_credentials(self):
        for kwargs in ({'session_seconds': 0}, {'session_seconds': 601},
                       {'session_seconds': float('nan')},
                       {'max_requests': 0}, {'max_requests': 12001},
                       {'max_requests': True}, {'max_requests': 1.5}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                serve(('127.0.0.1', 0), '/absent', '/absent',
                      threading.Event(), **kwargs)


if __name__ == '__main__':
    unittest.main()
