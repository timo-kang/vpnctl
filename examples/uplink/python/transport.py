# Copyright 2026 Jonghyeok Kang
# SPDX-License-Identifier: Apache-2.0
"""Bounded Linux Unix socket stream with independent server authentication."""
import os
import re
import random
import select
import socket
import stat
import struct
import time
from urllib.parse import quote


def dial(directory, server_uid):
    if (not isinstance(directory, str) or not directory.startswith('/')
            or os.path.normpath(directory) != directory or directory in ('/', '//')
            or directory.startswith('//') or type(server_uid) is not int or not 0 <= server_uid < 2**32):
        raise ValueError('canonical directory and server UID required')
    fd = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    conn = None
    try:
        parts = directory[1:].split('/')
        for i, part in enumerate(parts):
            next_fd = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            ds = os.fstat(fd)
            leaf = i == len(parts) - 1
            sticky_root = not leaf and ds.st_uid == 0 and ds.st_mode & stat.S_ISVTX
            if (ds.st_uid not in (0, server_uid) or ds.st_mode & 0o022 and not sticky_root
                    or leaf and (ds.st_uid != server_uid or stat.S_IMODE(ds.st_mode) not in (0o700, 0o750))):
                raise OSError('unsafe runtime directory')
        ss = os.stat('uplink.sock', dir_fd=fd, follow_symlinks=False)
        if (not stat.S_ISSOCK(ss.st_mode) or ss.st_uid != server_uid or ss.st_gid != ds.st_gid
                or stat.S_IMODE(ss.st_mode) != 0o660):
            raise OSError('untrusted uplink socket')
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(1)
        conn.connect(f'/proc/self/fd/{fd}/uplink.sock')
        uid = _peer_uid(conn)
        if uid != server_uid:
            raise OSError('untrusted uplink server UID')
        return conn
    except BaseException:
        if conn is not None:
            conn.close()
        raise
    finally:
        os.close(fd)


def _peer_uid(conn):
    # Linux ucred has signed pid_t but unsigned uid_t/gid_t.
    return struct.unpack('iII', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


class _Reader:
    def __init__(self, conn, stop):
        self.conn, self.stop = conn, stop
        self.buffer = bytearray()
        self.end = time.monotonic() + 35

    def line(self, seconds):
        deadline = min(self.end, time.monotonic() + seconds)
        while True:
            if self.stop.is_set():
                raise InterruptedError('stream cancelled')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('stream read deadline')
            at = self.buffer.find(b'\n')
            if at >= 0:
                line = bytes(self.buffer[:at+1])
                del self.buffer[:at+1]
                return line
            if len(self.buffer) >= 4097:
                raise ValueError('oversized stream line')
            ready, _, _ = select.select([self.conn], [], [], min(remaining, .1))
            if ready:
                data = self.conn.recv(4097 - len(self.buffer))
                if not data:
                    raise EOFError('incomplete or closed stream')
                self.buffer.extend(data)


def _header(reader):
    remaining, fields = 4096, {}
    deadline = time.monotonic() + 2
    first = True
    while True:
        line = reader.line(max(0, deadline - time.monotonic()))
        remaining -= len(line)
        if remaining < 0 or not line.endswith(b'\r\n'):
            raise ValueError('invalid HTTP header')
        line = line[:-2]
        if first:
            first = False
            if line != b'HTTP/1.1 200 OK':
                raise ValueError('unexpected HTTP status')
            continue
        if not line:
            break
        key, sep, value = line.partition(b':')
        if (not sep or not re.fullmatch(rb"[A-Za-z0-9!#$%&'*+.^_`|~-]+", key)
                or any(b != 9 and not 32 <= b <= 126 for b in value)):
            raise ValueError('invalid HTTP field')
        key = key.lower()
        if key in fields:
            raise ValueError('duplicate HTTP field')
        fields[key] = value.strip(b' \t')
    if (b'content-length' in fields or b'transfer-encoding' in fields
            or fields.get(b'content-type') != b'application/x-ndjson' or fields.get(b'connection') != b'close'):
        raise ValueError('unsupported HTTP framing')


def stream(directory, server_uid, state, stop, *, once=False):
    """Read one stream; the caller owns retry. No payload connection is touched."""
    epoch = state.begin()
    try:
        if not epoch:
            raise ValueError('stream epoch exhausted')
        if stop.is_set():
            raise InterruptedError('stream cancelled')
        with dial(directory, server_uid) as conn:
            path = '/v1/events'
            if state.cursor():
                path += '?after=' + quote(state.cursor(), safe='')
            conn.sendall(f'GET {path} HTTP/1.1\r\nHost: uplink\r\n\r\n'.encode('ascii'))
            conn.setblocking(False)
            reader = _Reader(conn, stop)
            _header(reader)
            remaining = 64 * 1024
            while remaining > 0:
                line = reader.line(6)
                remaining -= len(line)
                if remaining < 0:
                    raise ValueError('stream byte budget exceeded')
                state.accept(epoch, line[:-1])
                if once:
                    return
            raise ValueError('stream byte budget exhausted')
    finally:
        state.disconnect(epoch)


def watch(directory, server_uid, state, stop):
    """API-only retry; payload retry state must be owned by the application."""
    delay = 0
    while not stop.is_set():
        before = state.accepted_frames()
        try:
            stream(directory, server_uid, state, stop)
        except (OSError, EOFError, ValueError):
            pass
        delay = .25 if state.accepted_frames() != before or not delay else min(8, delay * 2)
        stop.wait(random.uniform(delay / 2, delay))
