import hashlib
import json
from collections import Counter
from pathlib import Path
import statistics
import sys
from correlate import correlate, require_complete, stamp_ns

EVENTS = {'syscalls/sys_enter_connect', 'syscalls/sys_exit_connect',
          'syscalls/sys_enter_getsockopt', 'syscalls/sys_exit_getsockopt',
          'syscalls/sys_enter_getpeername', 'syscalls/sys_exit_getpeername', 'sock/inet_sock_set_state'}


def check_recording(recording):
    require_complete(recording)
    wanted = {(event, cpu) for event in EVENTS for cpu in (0, 1)}
    if len(recording['counts']) != 14 or {(c['event'],c['cpu']) for c in recording['counts']} != wanted:
        raise ValueError('tracepoint/CPU coverage differs')
    actual = Counter((e['event'],e['cpu']) for e in recording['events'])
    if set(actual)-wanted or any(actual[c['event'],c['cpu']] != c['samples'] for c in recording['counts']):
        raise ValueError('retained records and counter samples differ')


def attribute(events, row):
    p = row['probe']; tcp = p['tcp']
    # One independently identified process performs exactly one application Dial.
    r = {'pid': tcp['private_pid'], 'index': 0, 'target': row['target']+':9192',
         'result': 'connected' if tcp.get('connected_at') else p.get('failure', 'unknown')}
    flows = correlate(events, [r], verify_outcome=False)
    if len(flows) != 1: raise ValueError('one payload call per process required')
    f = flows[0]
    f['go'] = p
    kernel, go = f['established_ns'] is not None, bool(tcp.get('connected_at'))
    if go and not kernel: raise ValueError('Go success without a complete kernel establishment')
    if kernel and not go: f['classification'] = 'kernel_established_go_connect_failed'
    elif not kernel: f['classification'] = 'kernel_not_established'
    elif not p['ok']: f['classification'] = 'post_connect_failure'
    else: f['classification'] = 'connected_and_payload_passed'
    if kernel:
        f['kernel_connect_to_established_ns'] = f['established_ns']-f['connect_enter_ns']
        exits = [c['exited_ns'] for c in f['calls'] if c['call']=='getpeername' and c['ret']==0]
        if exits: f['kernel_established_to_getpeername_exit_ns'] = min(exits)-f['established_ns']
    return f


def analyze(root):
    verdicts = list(root.glob('application-capacity-*/verdict.json'))
    if len(verdicts) != 1: raise ValueError('exactly one original trial required')
    verdict = json.loads(verdicts[0].read_text())
    extracted = next((n for n in ('private-verified', 'private-recovered', 'private-guest') if (root/n).exists()), 'private-guest')
    reports = list(root.glob(extracted+'/results/*/application-mixed-candidates.json'))
    out = {'original_observer': {k: verdict.get(k) for k in ('completed','qualified','error')},
           'source': '14ccf89cafd941b8d6fd2727bdbd69f8addc1c67', 'fixtures': [],
           'original_ci_failure_resolved': False, 'pr266_qualified': False, 'overhead_measured': False}
    for path in reports:
        report = json.loads(path.read_text())
        item = {'fixture': path.parent.name, 'healthy_index': report['healthy_index'],
                'phase': report.get('phase'), 'test_outcome': report.get('test_outcome'),
                'sampled_qualification_status': report.get('sampled_qualification_status'),
                'publication': {k: v.get('status') for k,v in report.get('publication_continuity',{}).items()},
                'payload_failure': report.get('payload_failure'), 'continuity_failure': report.get('continuity_failure'),
                'probes': [], 'attribution_errors': [], 'diagnostic_complete': False}
        rawpath = path.parent/'private-passive.json'
        if not rawpath.is_file():
            item['diagnostic_error'] = 'raw evidence missing'; out['fixtures'].append(item); continue
        recording = json.loads(rawpath.read_text())
        item['raw_sha256'] = hashlib.sha256(rawpath.read_bytes()).hexdigest()
        item['retained_events'] = len(recording.get('events', []))
        item['lost'] = sum(c['lost'] for c in recording.get('counts', []))
        item['reader_cpu_ms'] = recording.get('reader_cpu_ns', 0)/1e6
        item['recording_seconds'] = (recording.get('end_clock', {}).get('after_ns',0)-recording.get('start_clock',{}).get('before_ns',0))/1e9
        try:
            check_recording(recording)
            rows = report.get('private_payload_probes', [])
            pids = [r['probe']['tcp']['private_pid'] for r in rows]
            if not rows or len(set(pids)) != len(pids): raise ValueError('missing or reused process identity')
            for row in rows:
                try: item['probes'].append(attribute(recording['events'], row))
                except ValueError as error:
                    item['attribution_errors'].append({'pid': row['probe']['tcp']['private_pid'], 'error': str(error), 'probe': row})
            item['diagnostic_complete'] = not item['attribution_errors']
            item['reported_probes'] = len(rows)
            # Use a common offset only when both independent clock samples
            # intersect. Otherwise preserve monotonic kernel intervals alone.
            pairs = [recording['start_clock'], recording['end_clock']]
            lo = max(p['wall_ns']-p['after_ns'] for p in pairs)
            hi = min(p['wall_ns']-p['before_ns'] for p in pairs)
            item['clock_mapping'] = 'common_offset_intersection' if lo <= hi else 'no_common_offset'
            if lo <= hi:
                item['clock_offset_interval'] = [lo, hi]
                for flow in item['probes']:
                    at = flow['go']['tcp'].get('connected_at')
                    if at and flow['established_ns'] is not None:
                        wall = stamp_ns(at)
                        flow['kernel_to_go_wall_derived_ns_interval'] = [wall-hi-flow['established_ns'],wall-lo-flow['established_ns']]
        except (ValueError, KeyError) as error:
            item['diagnostic_complete'] = False
            item['diagnostic_error'] = str(error)
        out['fixtures'].append(item)
    out['integration_coverage_complete'] = (len(reports)==3 and
        {f['healthy_index'] for f in out['fixtures']}=={0,3,7} and
        all(f['diagnostic_complete'] for f in out['fixtures']))
    flows = [p for f in out['fixtures'] for p in f['probes']]
    out['correlated_payloads'] = len(flows)
    out['payload_successes'] = sum(p['go']['ok'] for p in flows)
    out['classification_counts'] = {k: sum(p['classification']==k for p in flows) for k in sorted({p['classification'] for p in flows})}
    return out


if __name__ == '__main__':
    print(json.dumps(analyze(Path(sys.argv[1])), indent=2))
