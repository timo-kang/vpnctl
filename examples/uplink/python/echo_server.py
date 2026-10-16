# Copyright 2026 Jonghyeok Kang
# SPDX-License-Identifier: Apache-2.0
"""Disposable TLS echo endpoint for the reference clients; no business operations."""
import argparse
import re
import signal
import socket
import ssl
import threading
import time


def serve(address, cert, key, stop, *, ready=None, session_seconds=30,
          max_requests=256):
    if (type(session_seconds) not in (int, float) or not 0 < session_seconds <= 600
            or type(max_requests) is not int or not 1 <= max_requests <= 12000):
        raise ValueError('invalid session bounds')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(cert, key)
    slots = threading.BoundedSemaphore(8)
    workers = set()
    lock = threading.Lock()

    def handle(raw):
        try:
            raw.settimeout(2)
            with context.wrap_socket(raw, server_side=True) as conn:
                deadline = time.monotonic() + session_seconds
                buffer = bytearray()
                for _ in range(max_requests):
                    if stop.is_set() or time.monotonic() >= deadline:
                        return
                    read_deadline = min(deadline, time.monotonic() + 2)
                    while b'\n' not in buffer:
                        remaining = read_deadline - time.monotonic()
                        if stop.is_set() or remaining <= 0 or len(buffer) >= 256:
                            return
                        conn.settimeout(remaining)
                        data = conn.recv(256 - len(buffer))
                        if not data:
                            return
                        buffer.extend(data)
                    at = buffer.index(b'\n') + 1
                    line = bytes(buffer[:at])
                    del buffer[:at]
                    if not re.fullmatch(rb'VPNCTL-ECHO/1 [1-9][0-9]{0,19} [0-9a-f]{32}\n', line):
                        return
                    remaining = min(2, deadline - time.monotonic())
                    if stop.is_set() or remaining <= 0:
                        return
                    conn.settimeout(remaining)
                    conn.sendall(line)
        except OSError:
            pass
        finally:
            raw.close()
            slots.release()
            with lock:
                workers.discard(threading.current_thread())

    family = socket.AF_INET6 if ':' in address[0] else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(address)
        listener.listen(8)
        listener.settimeout(.1)
        if ready is not None:
            ready(listener.getsockname())
        while not stop.is_set():
            try:
                raw, _ = listener.accept()
            except TimeoutError:
                continue
            if not slots.acquire(blocking=False):
                raw.close()
                continue
            worker = threading.Thread(target=handle, args=(raw,))
            with lock:
                workers.add(worker)
            worker.start()
    with lock:
        remaining = list(workers)
    for worker in remaining:
        worker.join()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=9443)
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--duration', type=float, default=120)
    parser.add_argument('--session-seconds', type=float, default=30)
    parser.add_argument('--max-requests', type=int, default=256)
    args = parser.parse_args()
    if not 1 <= args.duration <= 600 or not 1 <= args.port <= 65535:
        raise ValueError('invalid duration or port')
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    timer = threading.Timer(args.duration, stop.set)
    timer.start()
    try:
        serve((args.host, args.port), args.cert, args.key, stop,
              session_seconds=args.session_seconds, max_requests=args.max_requests)
    finally:
        stop.set()
        timer.cancel()
        timer.join()


if __name__ == '__main__':
    main()
