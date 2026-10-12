# Copyright 2026 Jonghyeok Kang
# SPDX-License-Identifier: Apache-2.0
"""Measure one app's read-only TLS echo independently of uplink observations."""
import argparse
import json
import os
from pathlib import Path
import resource
import signal
import sys
import tempfile
import threading

from probe import Probe, boot_ns
from transport import watch
from vpnctl_uplink import State


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('address', 'server-name', 'ca', 'runtime'):
        parser.add_argument('--' + field, required=True)
    parser.add_argument('--server-uid', type=int, default=0)
    parser.add_argument('--target', default='app')
    parser.add_argument('--duration', type=float, default=60, help='seconds, 1–600')
    parser.add_argument('--connect-timeout', type=float, default=1, help='seconds')
    parser.add_argument('--io-timeout', type=float, default=1, help='seconds')
    parser.add_argument('--interval', type=float, default=.25, help='seconds')
    parser.add_argument('--progress', help='optional atomically replaced progress JSON')
    args = parser.parse_args()
    if not 1 <= args.duration <= 600 or not 0 <= args.server_uid < 2**32:
        raise ValueError('invalid bounded duration or UID')
    host, port = args.address.rsplit(':', 1)
    probe = Probe((host.strip('[]'), int(port)), args.server_name, args.ca,
                  args.connect_timeout, args.io_timeout, args.interval)
    state, stop = State(args.target), threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    before = resource.getrusage(resource.RUSAGE_SELF)

    def report(events):
        usage = resource.getrusage(resource.RUSAGE_SELF)
        payload, now = probe.snapshot(events), boot_ns()
        previous = int(payload['last_correct_boot_ns'])
        age = str(now - previous) if previous and now >= previous else None
        return dict(schema_version=1, language='python', target_id=args.target, snapshot_boot_ns=str(now),
                    api=state.current(), api_records=state.accepted_frames(), payload=payload,
                    no_correct_response=payload['correct'] == 0, response_age_ns=age,
                    cpu_user_ns=int((usage.ru_utime - before.ru_utime)*1e9),
                    cpu_system_ns=int((usage.ru_stime - before.ru_stime)*1e9), process_peak_rss_kib=usage.ru_maxrss,
                    publication_boot_ns=None, receipt_boot_ns=None)

    failures = []
    def progress():
        while not stop.wait(.25):
            filename = None
            try:
                with tempfile.NamedTemporaryFile(mode='w', dir=Path(args.progress).parent, prefix='.uplink-progress-', delete=False) as f:
                    filename = f.name
                    json.dump(report(False), f)
                os.replace(filename, args.progress)
            except (OSError, ValueError) as exc:
                failures.append(exc)
                stop.set()
            finally:
                if filename and os.path.exists(filename):
                    os.unlink(filename)

    timer = threading.Timer(args.duration, stop.set)
    threads = [threading.Thread(target=watch, args=(args.runtime, args.server_uid, state, stop))]
    if args.progress:
        threads.append(threading.Thread(target=progress))
    timer.start()
    for worker in threads:
        worker.start()
    try:
        probe.run(stop)
    finally:
        stop.set()
        timer.cancel()
        timer.join()
        for worker in threads:
            worker.join()
    if failures:
        raise OSError('progress report failed')
    json.dump(report(True), sys.stdout)
    print()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError):
        print('uplink example failed', file=sys.stderr)
        sys.exit(1)
