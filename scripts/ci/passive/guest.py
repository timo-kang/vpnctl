"""Private collector, admitted only inside the existing identity-guarded VM."""
import json
import os
from pathlib import Path
import platform
import re
import resource
from process_memory import sample_memory
import signal
import subprocess
import sys
import threading
import traceback


def guard():
    args = dict(x.split('=', 1) if '=' in x else (x, '')
                for x in Path('/proc/cmdline').read_text().split())
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    dmi = Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()
    if (os.geteuid() != 0 or platform.machine() != 'x86_64' or
        'vpnctl_vm_test' not in args or
        not re.fullmatch('[a-f0-9]{32}', args.get('vpnctl_vm_token', '')) or
        not args.get('vpnctl_host_boot') or args['vpnctl_host_boot'] == boot or
        not dmi or dmi != args.get('vpnctl_vm_uuid') or
        os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net') or
        Path('/sys/devices/system/cpu/online').read_text().strip() != '0-1'):
        raise RuntimeError('not the declared isolated two-CPU x86_64 guest')
    return boot


def main():
    boot = guard()
    out = Path(sys.argv[1])
    if not out.parent.is_relative_to('/var/lib/vpnctl-vm/results') or out.exists():
        raise RuntimeError('private fresh fixture output required')
    from perf_events import FIELDS, Recorder
    trace = Path('/sys/kernel/tracing')
    if not (trace/'events').exists():
        subprocess.run(['mount', '-t', 'tracefs', 'tracefs', str(trace)], check=True)
    caps = {'boot_id': boot, 'kernel': platform.release(), 'machine': platform.machine(),
            'cpus': [0, 1], 'collector_affinity': sorted(os.sched_getaffinity(0)),
            'formats': {event: {'id': int((trace/'events'/event/'id').read_text()),
                       'format': (trace/'events'/event/'format').read_text()} for event in FIELDS}}
    if caps['collector_affinity'] != [1]:
        raise RuntimeError('collector must share the existing measurement/server CPU')
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    result = {'capabilities': caps, 'complete': False, 'memory_before_capture': sample_memory()}
    recorder = None
    try:
        recorder = Recorder(caps)
        out.with_suffix('.ready').write_text('ready\n')
        if not stopped.wait(180):
            result['collector_error'] = 'bounded collector lifetime exceeded'
    except BaseException:
        result['collector_error'] = traceback.format_exc()
    finally:
        if recorder is not None:
            try:
                result.update(recorder.finish())
            except BaseException:
                # Preserve partial evidence even when finalization itself fails.
                result.update(events=recorder.rows, errors=recorder.errors,
                              complete=False, collector_error=traceback.format_exc())
        if result.get('collector_error'):
            result['complete'] = False
        # This excludes later JSON serialization and is not total overhead.
        usage = resource.getrusage(resource.RUSAGE_SELF)
        result['collector_before_export'] = {'rusage_maxrss_including_spawn_kib': usage.ru_maxrss,
            'user_seconds': usage.ru_utime, 'system_seconds': usage.ru_stime}
        result['memory_after_capture_before_export'] = sample_memory()
        with out.open('x') as f:
            json.dump(result, f, separators=(',', ':'))
    return 0 if result['complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
