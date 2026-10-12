# Copyright 2026 Jonghyeok Kang
# SPDX-License-Identifier: Apache-2.0
"""Read-only authenticated echo; never replay arbitrary business operations."""
from collections import deque
import copy
import ipaddress
import random
import secrets
import select
import socket
import ssl
import threading
import time


def boot_ns():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


class Probe:
    def __init__(self, address, server_name, roots_file, connect_timeout=1, io_timeout=1, interval=.25):
        if not server_name or not 0 < connect_timeout <= 30 or not 0 < io_timeout <= 30 or not .05 <= interval <= 10:
            raise ValueError('invalid probe configuration')
        ipaddress.ip_address(address[0])
        if type(address[1]) is not int or not 1 <= address[1] <= 65535:
            raise ValueError('nonzero port required')
        self.address, self.server_name = address, server_name
        self.connect_timeout, self.io_timeout, self.interval = connect_timeout, io_timeout, interval
        self.tls = ssl.create_default_context(cafile=roots_file)
        self.tls.minimum_version = ssl.TLSVersion.TLSv1_3
        self.lock = threading.Lock()
        self.events = deque(maxlen=4096)
        self.counts = dict(attempts=0, authenticated_connections=0, correct=0, new_socket_correct=0,
                           existing_socket_correct=0, outcome_unknown=0, invalid_responses=0,
                           first_correct_boot_ns='0', last_correct_boot_ns='0', max_correct_gap_ns='0', dropped_events=0)

    def record(self, event):
        with self.lock:
            v = self.counts
            v['attempts'] += 1
            v['authenticated_connections'] += event.get('authenticated_connect_boot_ns') is not None
            v['outcome_unknown'] += event['outcome_unknown']
            v['invalid_responses'] += event.get('failure') == 'unexpected_response'
            if event['correct']:
                v['correct'] += 1
                v['existing_socket_correct' if event['existing_socket'] else 'new_socket_correct'] += 1
                if v['first_correct_boot_ns'] == '0':
                    v['first_correct_boot_ns'] = event['finished_boot_ns']
                previous, now = int(v['last_correct_boot_ns']), int(event['finished_boot_ns'])
                if previous and now >= previous:
                    v['max_correct_gap_ns'] = str(max(int(v['max_correct_gap_ns']), now - previous))
                v['last_correct_boot_ns'] = event['finished_boot_ns']
            v['dropped_events'] += len(self.events) == self.events.maxlen
            self.events.append(event)

    def snapshot(self, events=True):
        with self.lock:
            return dict(self.counts, events=copy.deepcopy(list(self.events)) if events else None)

    @staticmethod
    def _wait_socket(conn, stop, deadline, writing=False):
        while not stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('payload deadline')
            read, write, _ = select.select([] if writing else [conn], [conn] if writing else [], [], min(.05, remaining))
            if read or write:
                return
        raise InterruptedError('probe stopped')

    def _connect(self, stop):
        # getaddrinfo itself has no cancellable stdlib deadline. Require a literal
        # IP in this reference CLI; TLS identity is independently server_name.
        host, port = self.address
        ip = ipaddress.ip_address(host)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        conn = socket.socket(family, socket.SOCK_STREAM)
        deadline = time.monotonic() + self.connect_timeout
        try:
            conn.setblocking(False)
            import errno
            code = conn.connect_ex((host, port))
            if code not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
                raise OSError('connect failed')
            self._wait_socket(conn, stop, deadline, True)
            if conn.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
                raise OSError('connect failed')
            conn = self.tls.wrap_socket(conn, server_hostname=self.server_name, do_handshake_on_connect=False)
            while True:
                try:
                    conn.do_handshake()
                    return conn
                except ssl.SSLWantReadError:
                    self._wait_socket(conn, stop, deadline)
                except ssl.SSLWantWriteError:
                    self._wait_socket(conn, stop, deadline, True)
        except BaseException:
            conn.close()
            raise

    def _exchange(self, conn, wire, stop):
        deadline, sent = time.monotonic() + self.io_timeout, 0
        while sent < len(wire):
            if stop.is_set() or time.monotonic() >= deadline:
                raise TimeoutError('payload write deadline')
            try:
                count = conn.send(wire[sent:])
                if count <= 0:
                    raise OSError('closed write')
                sent += count
            except ssl.SSLWantReadError:
                self._wait_socket(conn, stop, deadline)
            except (ssl.SSLWantWriteError, BlockingIOError):
                self._wait_socket(conn, stop, deadline, True)
        deadline, response = time.monotonic() + self.io_timeout, bytearray()
        while len(response) < 256:
            if stop.is_set() or time.monotonic() >= deadline:
                raise TimeoutError('payload read deadline')
            try:
                chunk = conn.recv(1)
                if not chunk:
                    raise EOFError('incomplete response')
                response.extend(chunk)
                if chunk == b'\n':
                    return bytes(response) == wire
            except ssl.SSLWantReadError:
                self._wait_socket(conn, stop, deadline)
            except ssl.SSLWantWriteError:
                self._wait_socket(conn, stop, deadline, True)
        return False

    def run(self, stop):
        conn, request, connection, retry = None, 0, 0, 0
        try:
            while not stop.is_set():
                request += 1
                e = dict(request=request, connection=0, started_boot_ns=str(boot_ns()), authenticated_connect_boot_ns=None,
                         existing_socket=conn is not None, correct=False, outcome_unknown=False)
                if conn is None:
                    try:
                        conn = self._connect(stop)
                        connection += 1
                        e['authenticated_connect_boot_ns'] = str(boot_ns())
                    except OSError:
                        e['failure'] = 'connect'
                if conn is not None:
                    e['connection'] = connection
                    wire = f'VPNCTL-ECHO/1 {request} {secrets.token_hex(16)}\n'.encode('ascii')
                    e['outcome_unknown'] = True
                    try:
                        if self._exchange(conn, wire, stop):
                            e.update(correct=True, outcome_unknown=False)
                        else:
                            e['failure'] = 'unexpected_response'
                    except (OSError, EOFError):
                        e['failure'] = 'io'
                e['finished_boot_ns'] = str(boot_ns())
                delay = self.interval
                if e['correct']:
                    retry = 0  # Only an authenticated exact echo resets payload retry.
                else:
                    if conn is not None:
                        conn.close()
                        conn = None
                    retry = .25 if not retry else min(8, retry * 2)
                    delay = random.uniform(retry / 2, retry)
                e['next_delay_ns'] = str(int(delay * 1e9))
                self.record(e)
                stop.wait(delay)
        finally:
            if conn is not None:
                conn.close()
