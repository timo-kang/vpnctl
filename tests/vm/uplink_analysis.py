"""Read private evidence; emit only validated scalar/enum comparison results."""
from pathlib import Path
import sys, json, re, hashlib
from types import ModuleType
from collections import Counter
import uplink_fault_evidence as fault_evidence
CASES = {f'uplink-{p}-{n}' for p in ('vpnctl', 'openvpn') for n in (4, 8)}
FAULTS = ('link-down', 'endpoint-drop', 'relay-drop', 'uplink-drop', 'last-endpoint-only', 'app1-last-path')
PHASES = {'setup', 'baseline', 'injecting', 'observing', 'measured'}


def counters(s):
 values = {}
 for line in s.splitlines():
  key, value = line.split()
  if key in values or not value.isdecimal():raise ValueError('invalid resource counter')
  values[key] = int(value)
 return values


def derive(r, product, paths):
 trial = {'fault':r['fault'], 'completed':r['completed'], 'phase':r['phase']}
 if trial['phase'] != 'measured':raise ValueError('incomplete phase')
 allowed_ids = {f'p{relay}{underlay}' for relay in range(2) for underlay in range(paths//2)}
 allowed_ids |= {'not_applied', 'not_connected'}
 selection = r['final_selection']
 if (set(selection) != ({'app', 'app2'} if product == 'vpnctl' else {'tunnel'})
     or any(type(v) is not str or v not in allowed_ids for v in selection.values())):
  raise ValueError('invalid selection enum')
 trial['final_selection'] = dict(selection)
 trial['fault_evidence'] = fault_evidence.check(r)
 trial['fault_install_ms']=(r['fault_end_ns']-r['fault_begin_ns'])/1e6
 trial['streams']={kind:{'first_response_ms':(m['first_success_ns']-r['fault_end_ns'])/1e6 if m['first_success_ns'] else None,'failed_attempts':m['failed_attempts'],'samples':m['samples'],'max_success_gap_ms':m['max_success_gap_ns']/1e6,'max_sample_start_gap_ms':m['max_sample_start_gap_ns']/1e6,'unrecovered_at_end':m['unrecovered_at_end']} for kind,m in r['metrics'].items()}
 for kind, stream in trial['streams'].items():
  m=r['metrics'][kind];first=m['first_success_ns']
  samples=[s for s in r['samples'] if s['kind']==kind and s['end_ns']<=r['window_end_ns'] and s.get('attempt_ns',s['begin_ns'])>=r['fault_end_ns']]
  successes=[s['end_ns'] for s in samples if s['ok'] and s['begin_ns']>=r['fault_end_ns']]
  stream['failed_after_first_response']=sum(not s['ok'] and s.get('attempt_ns',s['begin_ns'])>=first for s in samples) if first else None
  stream['last_response_age_ms']=(r['window_end_ns']-max(successes))/1e6 if successes else None
  if first:
   boundaries=[first]+[s['end_ns'] for s in samples if s['ok'] and s['end_ns']>first]+[r['window_end_ns']]
   stream['max_gap_after_first_response_ms']=max(b-a for a,b in zip(boundaries,boundaries[1:]))/1e6
  else:stream['max_gap_after_first_response_ms']=None
 trial['resources']={}
 for role in ('robot','server'):
  before,after=(r[role+'_'+which] for which in ('before','after'))
  cb,ca=counters(before['cpu_stat']),counters(after['cpu_stat'])
  mb,ma=counters(before['memory.events']),counters(after['memory.events'])
  trial['resources'][role]={'usage_us':ca['usage_usec']-cb['usage_usec'],'throttled_us':ca['throttled_usec']-cb['throttled_usec'],'throttled_periods':ca['nr_throttled']-cb['nr_throttled'],'memory_peak_bytes':int(after['memory.peak']),'oom_delta':ma['oom']-mb['oom'],'oom_kill_delta':ma['oom_kill']-mb['oom_kill']}

 for resource in trial['resources'].values():
  if any(type(v) is not int or v < 0 for v in resource.values()):
   raise ValueError('invalid resource delta')
 return trial


def analyze(root):
 root = Path(root)
 trusted = Path(__file__).with_name('uplink_comparison.py').read_bytes()
 if hashlib.sha256((root/'validator.py').read_bytes()).digest() != hashlib.sha256(trusted).digest():
  raise ValueError('validator copy differs from this repository revision')
 # Execute only the captured repository bytes. Artifact-path loaders may use
 # a forged timestamp/size-matching .pyc even when source hashes match.
 comparison = ModuleType('comparison')
 exec(compile(trusted, str(Path(__file__).with_name('uplink_comparison.py')), 'exec'), comparison.__dict__)
 result = {'complete':False, 'cases':[]}
 path = root/'artifacts'
 if not (path/'verdicts.json').exists():return result
 try:
  summaries = json.loads((path/'verdicts.json').read_text())
  if type(summaries) is not list:raise ValueError('invalid summary collection')
 except (OSError,ValueError):
  result['analysis_error']='invalid_summaries'
  return result
 counts = Counter(s.get('artifact') for s in summaries if type(s) is dict and type(s.get('artifact')) is str)
 for ordinal, summary in enumerate(summaries, 1):
  case = summary.get('case') if type(summary) is dict else None
  row = {'ordinal':ordinal, 'case':case if type(case) is str and case in CASES else 'invalid', 'valid':False, 'trials':[]}
  try:
   if type(case) is not str or case not in CASES:raise ValueError('unknown case')
   _, product, paths = case.split('-');paths=int(paths)
   expected = FAULTS if product == 'vpnctl' else FAULTS[:-1]
   row['trials'] = [{'fault':f, 'usable':False, 'phase':'missing'} for f in expected]
   artifact = summary['artifact']
   if type(artifact) is not str or not re.fullmatch(re.escape(case)+r'-stopped-0-host-[a-f0-9]{8}',artifact):
    raise ValueError('invalid artifact identity')
   if counts[artifact] != 1:raise ValueError('duplicate artifact is not an independent repeat')
   v = json.loads((path/artifact/'verdict.json').read_text())
   status = v[case]
   worker_exit = status.get('exit')
   row['worker_exit'] = worker_exit if type(worker_exit) is int else None
   reports = status.get('reports', [])
   row['reports_found'] = len(reports)
   for trial in row['trials']:
    matches = [item['report'] for item in reports if item.get('report',{}).get('fault') == trial['fault']]
    if len(matches) == 1:
     report = matches[0]
     phase = report.get('phase')
     trial['phase'] = phase if type(phase) is str and phase in PHASES else 'invalid'
     trial['completed'] = report.get('completed') is True
   comparison.validate(status, product, paths)
   if summary.get('completed') is not True or summary.get('qualified') is not True:
    raise ValueError('case not qualified')
   computed = [dict(derive(item['report'],product,paths),usable=True) for item in reports]
   row['trials'] = sorted(computed,key=lambda t:FAULTS.index(t['fault']))
   row['valid'] = True
  except Exception as error:
   # Never emit exception text or arbitrary evidence values. Preserve the entire
   # invalid case with explicit missing/unusable trials; no partial performance.
   row['validation_error'] = type(error).__name__ if type(error).__name__ in {
    'RuntimeError','ValueError','KeyError','TypeError','IndexError','AttributeError','OSError','FileNotFoundError','JSONDecodeError'
   } else 'validation_failed'
  result['cases'].append(row)
 try:
  result['complete'] = json.loads((root/'status.json').read_text()).get('state') == 'completed'
 except (OSError,ValueError,AttributeError):pass
 return result


if __name__ == '__main__':
 value = analyze(sys.argv[1])
 Path(sys.argv[1],'safe-analysis.json').write_text(json.dumps(value,indent=2)+'\n')
 print(json.dumps(value))
