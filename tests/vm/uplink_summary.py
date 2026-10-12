"""Descriptive fixed-plan aggregation; consumes only the sanitized frozen analysis."""
import json
from pathlib import Path
import statistics
import sys


def summarize(root):
    root=Path(root)
    plan=json.loads((root/'plan.json').read_text())
    analysis=json.loads((root/'safe-analysis.json').read_text())
    cases=analysis['cases']
    planned=plan['cases']
    observed=[r['case'] for r in cases]
    if observed != planned[:len(observed)]:
        raise ValueError('observed order differs from preregistered sequence')
    complete=analysis['complete'] and observed==planned
    rows=[]
    for paths in (4,8):
        for fault in plan['faults']+plan['vpnctl_reference']:
            for product in ('vpnctl','openvpn'):
                if product=='openvpn' and fault in plan['vpnctl_reference']:continue
                selected=[c for c in cases if c['case']==f'uplink-{product}-{paths}']
                for stream in ('app','app2','existing'):
                    samples=[]
                    for c in selected:
                        trial=next((t for t in c['trials'] if t['fault']==fault),None)
                        if not c['valid'] or not trial or not trial['usable']:
                            samples.append({'valid':False})
                        else:
                            m=trial['streams'][stream]
                            samples.append({'valid':True,'first_response_s':None if m['first_response_ms'] is None else m['first_response_ms']/1000,
                                            'failed_after_first_response':m['failed_after_first_response'],
                                            'failed_attempts':m['failed_attempts'],
                                            'max_gap_after_first_response_s':None if m['max_gap_after_first_response_ms'] is None else m['max_gap_after_first_response_ms']/1000,
                                            'max_success_gap_s':m['max_success_gap_ms']/1000,
                                            'max_sample_start_gap_s':m['max_sample_start_gap_ms']/1000,
                                            'last_response_age_s':None if m['last_response_age_ms'] is None else m['last_response_age_ms']/1000,
                                            'final_selection':trial['final_selection']})
                    values=[s['first_response_s'] for s in samples if s['valid'] and s['first_response_s'] is not None]
                    valid=sum(s['valid'] for s in samples)
                    rows.append(dict(paths=paths,product=product,fault=fault,stream=stream,planned=3,finished=len(selected),valid=valid,recovered=len(values),
                                     censored=valid-len(values),median_s=statistics.median(values) if len(values)==3 else None,
                                     range_s=[min(values),max(values)] if len(values)==3 else None,samples=samples))
    return {'complete':complete,'planned_cases':len(planned),'finished_cases':len(cases),'valid_cases':sum(c['valid'] for c in cases),
            'invalid_case_ordinals':[c['ordinal'] for c in cases if not c['valid']],'rows':rows}


if __name__=='__main__':
    root=Path(sys.argv[1]);result=summarize(root)
    (root/'comparison-summary.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='rows'}))
