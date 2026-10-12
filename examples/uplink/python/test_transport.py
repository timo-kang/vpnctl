# Copyright 2026 Jonghyeok Kang
# SPDX-License-Identifier: Apache-2.0
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock

from transport import dial, stream, watch, _peer_uid
from vpnctl_uplink import State, MAX_UINT

HEADER = b'HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: close\r\n\r\n'


class TransportTests(unittest.TestCase):
    def test_watch_cancellation_during_backoff(self):
        stop = threading.Event()
        timer = threading.Timer(.02, stop.set)
        timer.start()
        self.addCleanup(timer.join)
        started = time.monotonic()
        watch('/nonexistent/vpnctl-test', os.geteuid(), State('app'), stop)
        self.assertLess(time.monotonic() - started, 1)

    def test_peer_uid_preserves_unsigned_range(self):
        for uid in (0, 2**31 - 1, 2**31, 2**32 - 1):
            conn = Mock()
            conn.getsockopt.return_value = struct.pack('iII', 123, uid, uid)
            self.assertEqual(_peer_uid(conn), uid)

    def server(self, wire, stall=False):
        directory = tempfile.TemporaryDirectory(prefix='uplink-test-')
        self.addCleanup(directory.cleanup)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(directory.name + '/uplink.sock')
        os.chmod(directory.name + '/uplink.sock', 0o660)
        sock.listen(1)
        sock.settimeout(2)
        done = threading.Event()
        def serve():
            try:
                with sock.accept()[0] as conn:
                    conn.settimeout(2)
                    conn.recv(512)
                    conn.sendall(wire)
                    if stall:
                        done.wait(2)
            except OSError:
                pass
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        def cleanup():
            done.set()
            sock.close()
            worker.join(3)
            self.assertFalse(worker.is_alive())
        self.addCleanup(cleanup)
        return directory.name

    def test_reject_malformed_and_truncated_input(self):
        fixture = json.loads((Path(__file__).resolve().parents[3] / 'internal/uplinkclient/testdata/consumer.json').read_text())
        for name, wire in {
            'truncated': HEADER + json.dumps(fixture['base']).encode(),
            'record_size': HEADER + b' ' * 4097 + b'\n',
            'duplicate': HEADER.replace(b'Connection:', b'CONTENT-TYPE: application/x-ndjson\r\nConnection:'),
            'chunked': HEADER.replace(b'Connection:', b'Transfer-Encoding: chunked\r\nConnection:'),
            'length': HEADER.replace(b'Connection:', b'Content-Length: 0\r\nConnection:'),
            'header_size': HEADER.replace(b'Connection:', b'X-Fill: '+ b'x' * 4096 + b'\r\nConnection:'),
            'many_headers': HEADER.replace(b'Connection:', b'X-Fill: x\r\n' * 512 + b'Connection:'),
            'bare_lf': HEADER.replace(b'\r\n', b'\n'),
            'status': HEADER.replace(b'200 OK', b'503 Service Unavailable'),
        }.items():
            with self.subTest(name=name):
                state = State('app')
                with self.assertRaises((ValueError, EOFError, OSError)):
                    stream(self.server(wire), os.geteuid(), state, threading.Event(), once=True)
                self.assertFalse(state.current()['api_available'])
                self.assertNotIn('revision', state.current())

    def test_cancel_during_partial_header(self):
        directory = self.server(b'HTTP/1.1 200', stall=True)
        stop = threading.Event()
        timer = threading.Timer(.05, stop.set)
        timer.start()
        self.addCleanup(timer.join)
        started = time.monotonic()
        with self.assertRaises(InterruptedError):
            stream(directory, os.geteuid(), State('app'), stop)
        self.assertLess(time.monotonic() - started, 1)

    def test_directory_symlink_and_wrong_owner_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            os.mkdir(parent + '/real', 0o700)
            os.symlink(parent + '/real', parent + '/link')
            for directory, uid in ((parent + '/link', os.geteuid()), (parent + '/real', os.geteuid() + 1)):
                with self.assertRaises(OSError):
                    dial(directory, uid)
            os.chmod(parent + '/real', 0o777)
            with self.assertRaises(OSError):
                dial(parent + '/real', os.geteuid())

    def test_exhaustion_retires_last_connection(self):
        s = State('app')
        s._epoch = MAX_UINT - 1
        old = s.begin()
        self.assertEqual(old, MAX_UINT)
        self.assertEqual(s.begin(), 0)
        self.assertFalse(s._active)
        with self.assertRaises(ValueError):
            s.accept(old, b'{}')


if __name__ == '__main__':
    unittest.main()
