"""Independent synthetic checks: no VM, secrets, or pilot artifacts required."""
import copy
import json
from pathlib import Path
import unittest
import uplink_fault_evidence as fault_evidence
import uplink_analysis as analyze

import test_uplink_comparison_review as review
import uplink_comparison as comparison


def fixture(fault):
    # Synthetic reports use documentation/test addresses; no private pilot data.
    r=review.UplinkEvidenceReviewTest().valid_censored_status()['reports'][0]['report']
    r.update(transport='openvpn',paths=8,fault=fault,phase='measured',final_selection={'tunnel':'p00'})
    r.update(fault_rules_before_observed_ns=r['fault_end_ns']+1,
             fault_rules_after_observed_ns=r['window_end_ns']+1,
             final_selection_begin_ns=r['window_end_ns']+2,
             final_selection_end_ns=r['window_end_ns']+3)
    r['candidate_ids']=[dict(id=f'p{relay}{underlay}',relay=relay,underlay=underlay,udp_port=1194)
                        for relay in range(2) for underlay in range(4)]
    for role in ('robot','server'):
        for when in ('before','after'):
            r[role+'_'+when]['cpu_stat']='usage_usec 1\nnr_throttled 0\nthrottled_usec 0'
            r[role+'_'+when]['memory.events']='oom 0\noom_kill 0'
    if fault=='link-down':
        r['fault_rules_before']={'robot':json.dumps([{'ifname':'wan0','flags':['BROADCAST','MULTICAST']}])}
    else:
        snapshots={}
        for role in (('r0','r1') if fault=='last-endpoint-only' else ('r0',)):
            rows=[{'table':{'family':'inet','name':'comparison_fault'}}]
            names=['input','output','forward'] if fault=='relay-drop' else ['forward' if fault=='uplink-drop' else 'input']
            for name in names:
                rows.append({'chain':dict(family='inet',table='comparison_fault',name=name,type='filter',hook=name,prio=-100,
                                          policy='drop' if fault=='relay-drop' else 'accept')})
            rules=[]
            if fault=='endpoint-drop':rules=[('192.0.2.11','udp',1194)]
            if fault=='uplink-drop':rules=[('198.18.0.2','tcp',9192)]
            if fault=='last-endpoint-only':
                relay=int(role[1]);prefixes=('192.0.2','198.51.100','203.0.113','198.19.0')
                rules=[(prefixes[u]+'.'+str(11+relay),'udp',1194) for u in range(4 if relay==0 else 3)]
            for addr,protocol,port in rules:
                rows.append({'rule':dict(family='inet',table='comparison_fault',chain=names[0],expr=[
                    {'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'daddr'}},'right':addr}},
                    {'match':{'op':'==','left':{'payload':{'protocol':protocol,'field':'dport'}},'right':port}},
                    {'counter':{'packets':2,'bytes':80}},{'drop':None}])})
            snapshots[role]=json.dumps({'nftables':rows})
        r['fault_rules_before']=snapshots
    r['fault_rules_after']=copy.deepcopy(r['fault_rules_before'])
    if fault=='uplink-drop':
        for sample in r['samples']:
            if sample['kind']=='app2':sample.update(ok=True,relay='r0');sample.pop('failure',None)
        r['metrics']['app2']=comparison.recompute(r['samples'],'app2',r['baseline_start_ns'],r['fault_begin_ns'],r['fault_end_ns'],r['window_end_ns'])
    return r


def make_root(root, change=lambda status:None, duplicate=False):
    import shutil
    (root/'artifacts').mkdir()
    shutil.copyfile(comparison.__file__,root/'validator.py')
    case='uplink-openvpn-8'
    status={'exit':0,'reports':[{'report':fixture(f),'logs':{}} for f in analyze.FAULTS[:-1]]}
    change(status)
    summaries=[]
    for suffix in ('abcdef12','abcdef12' if duplicate else 'abcdef34'):
        artifact=case+'-stopped-0-host-'+suffix
        folder=root/'artifacts'/artifact
        folder.mkdir(exist_ok=True)
        (folder/'verdict.json').write_text(json.dumps({case:status}))
        summaries.append(dict(case=case,artifact=artifact,completed=True,qualified=True))
    (root/'artifacts/verdicts.json').write_text(json.dumps(summaries))
    return analyze.analyze(root)


class FaultEvidenceTest(unittest.TestCase):
    def test_registered_synthetic_faults_have_exact_scope(self):
        for fault in ('link-down', 'endpoint-drop', 'relay-drop', 'uplink-drop', 'last-endpoint-only'):
            self.assertTrue(fault_evidence.check(fixture(fault))['fault_verified'])

    def test_restored_link_is_not_a_retained_fault(self):
        r = fixture('link-down')
        rows = json.loads(r['fault_rules_after']['robot'])
        rows[0]['flags'].append('UP')
        r['fault_rules_after']['robot'] = json.dumps(rows)
        with self.assertRaises(ValueError):fault_evidence.check(r)

    def test_extra_or_missing_rule_is_rejected(self):
        for add in (True, False):
            r = fixture('last-endpoint-only')
            table = json.loads(r['fault_rules_after']['r0'])
            rule = next(x for x in table['nftables'] if 'rule' in x)
            if add:table['nftables'].append(copy.deepcopy(rule))
            else:table['nftables'].remove(rule)
            r['fault_rules_after']['r0'] = json.dumps(table)
            with self.assertRaises(ValueError):fault_evidence.check(r)

    def test_counter_can_already_be_nonzero_at_first_snapshot(self):
        r = fixture('endpoint-drop')
        r['fault_rules_before'] = copy.deepcopy(r['fault_rules_after'])
        self.assertGreater(fault_evidence.check(r)['dropped_packets'], 0)

    def test_reset_or_absent_counter_does_not_prove_injection(self):
        for remove in (True, False):
            r = fixture('endpoint-drop')
            for side in ('fault_rules_before', 'fault_rules_after'):
                table = json.loads(r[side]['r0'])
                for row in table['nftables']:
                    for expr in row.get('rule', {}).get('expr', []):
                        if 'counter' in expr:
                            expr['counter']['packets'] = 0 if remove or side.endswith('after') else 1
                r[side]['r0'] = json.dumps(table)
            with self.assertRaises(ValueError):fault_evidence.check(r)

    def test_policy_only_relay_is_not_reported_as_no_drops(self):
        # Base-chain drop policy has no explicit packet counter in this fixture.
        self.assertIsNone(fault_evidence.check(fixture('relay-drop'))['dropped_packets'])

    def test_order_must_end_at_registered_endpoint(self):
        r = fixture('last-endpoint-only')
        r['candidate_ids'] = list(reversed(r['candidate_ids']))
        with self.assertRaises(ValueError):fault_evidence.check(r)

    def test_per_path_app_fault_requires_actual_distinct_interfaces(self):
        for count in (4,8):
            r=fixture('uplink-drop')
            r.update(transport='vpnctl',paths=count,fault='app1-last-path')
            r['candidate_ids']=[dict(id=f'p{relay}{u}',relay=relay,underlay=u,udp_port=51820+u,interface=f'wg{relay}{u}')
                                for relay in range(2) for u in range(count//2)]
            rows=[{'table':dict(family='inet',name='comparison_fault')},
                  {'chain':dict(family='inet',table='comparison_fault',name='output',type='filter',hook='output',prio=-100,policy='accept')}]
            template=next(x['rule'] for x in json.loads(r['fault_rules_before']['r0'])['nftables'] if 'rule' in x)
            for candidate in r['candidate_ids'][:-1]:
                rule=copy.deepcopy(template);rule['chain']='output'
                rule['expr'].insert(0,{'match':dict(op='==',left={'meta':{'key':'oifname'}},right=candidate['interface'])})
                rows.append({'rule':rule})
            r['fault_rules_before']={'robot':json.dumps({'nftables':rows})}
            r['fault_rules_after']=copy.deepcopy(r['fault_rules_before'])
            self.assertTrue(fault_evidence.check(r)['fault_verified'])
            r['candidate_ids'][-1]['interface']=r['candidate_ids'][0]['interface']
            with self.assertRaises(ValueError):fault_evidence.check(r)

    def test_snapshot_outside_observation_cannot_prove_retained_fault(self):
        r=fixture('endpoint-drop')
        r['fault_rules_before_observed_ns']=r['window_end_ns']
        with self.assertRaises(ValueError):fault_evidence.check(r)


class ContinuityEvidenceTest(unittest.TestCase):
    def test_recovered_and_censored_streams_remain_distinct(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:value=make_root(Path(d))
        case = next(x for x in value['cases'] if x['case']=='uplink-openvpn-8')
        trial = next(x for x in case['trials'] if x['fault']=='uplink-drop')
        self.assertIsNone(trial['streams']['app']['first_response_ms'])
        self.assertIsNone(trial['streams']['app']['failed_after_first_response'])
        self.assertIsNotNone(trial['streams']['app2']['first_response_ms'])
        self.assertEqual(trial['streams']['app2']['failed_after_first_response'], 0)



class ReviewRegressionTest(unittest.TestCase):
    def mutate_nft(self, change):
        r=fixture('endpoint-drop')
        table=json.loads(r['fault_rules_after']['r0'])
        change(table['nftables'])
        r['fault_rules_after']['r0']=json.dumps(table)
        with self.assertRaises(ValueError):fault_evidence.check(r)

    def test_duplicate_match_is_rejected(self):
        def change(rows):
            rule=next(x['rule'] for x in rows if 'rule' in x)
            rule['expr'].insert(0,copy.deepcopy(rule['expr'][0]))
        self.mutate_nft(change)

    def test_counter_before_predicate_is_rejected(self):
        def change(rows):
            rule=next(x['rule'] for x in rows if 'rule' in x)
            rule['expr'].insert(0,rule['expr'].pop(-2))
        self.mutate_nft(change)

    def test_wrong_family_or_table_rejected(self):
        for kind in ('table','chain','rule'):
            self.mutate_nft(lambda rows:next(x[kind] for x in rows if kind in x).__setitem__('family','ip6'))
        self.mutate_nft(lambda rows:next(x['table'] for x in rows if 'table' in x).__setitem__('name','other'))

    def temporary_analysis(self, change, duplicate=False):
        import tempfile
        with tempfile.TemporaryDirectory() as d:return make_root(Path(d),change,duplicate)

    def test_validator_copy_cannot_execute_arbitrary_artifact_code(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);make_root(root)
            (root/'validator.py').write_text("raise RuntimeError('untrusted code executed')")
            with self.assertRaisesRegex(ValueError,'validator copy'):
                analyze.analyze(root)

    def test_artifact_cached_bytecode_is_never_executed(self):
        import tempfile,py_compile,importlib.util,os
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);make_root(root)
            source=root/'validator.py';stat=source.stat()
            evil=root/'evil.py'
            evil.write_text("raise AssertionError('artifact bytecode executed')\n".ljust(stat.st_size))
            os.utime(evil,(stat.st_mtime,stat.st_mtime))
            cache=Path(importlib.util.cache_from_source(str(source)))
            cache.parent.mkdir(exist_ok=True)
            py_compile.compile(str(evil),cfile=str(cache),dfile=str(source),doraise=True,invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
            result=analyze.analyze(root)
            self.assertTrue(all(c['valid'] for c in result['cases']))

    def test_malformed_summary_values_preserve_failure_rows(self):
        import tempfile,shutil
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'artifacts').mkdir()
            shutil.copy(comparison.__file__,root/'validator.py')
            (root/'artifacts/verdicts.json').write_text(json.dumps([None,{'case':[]},{'case':{}}]))
            value=analyze.analyze(root)
            self.assertEqual(len(value['cases']),3)
            self.assertTrue(all(c['case']=='invalid' and not c['valid'] for c in value['cases']))

    def test_duplicate_artifact_is_not_an_independent_repeat(self):
        value=self.temporary_analysis(lambda s:None,duplicate=True)
        self.assertEqual(len(value['cases']),2)
        self.assertTrue(all(not c['valid'] for c in value['cases']))

    def test_invalid_metrics_preserve_both_failure_rows(self):
        value=self.temporary_analysis(lambda s:s['reports'][0]['report']['metrics']['app'].pop('first_success_ns'))
        self.assertEqual(len(value['cases']),2)
        for row in value['cases']:
            self.assertFalse(row['valid'])
            self.assertEqual(len(row['trials']),5)
            self.assertTrue(all(not t['usable'] and 'streams' not in t for t in row['trials']))

    def test_untrusted_selection_never_reaches_output(self):
        secret='SENSITIVE_TEST_SENTINEL'
        value=self.temporary_analysis(lambda s:s['reports'][0]['report']['final_selection'].__setitem__('tunnel',secret))
        self.assertNotIn(secret,json.dumps(value))
        self.assertFalse(value['cases'][0]['valid'])

    def test_recovery_then_failure_remains_visible(self):
        r=fixture('link-down');end=r['fault_end_ns']
        r['samples']=[s for s in r['samples'] if s['kind']!='app']
        for offset,ok in ((1,True),(2,False),(3,True)):
            r['samples'].append({'kind':'app','begin_ns':end+offset*10**9-1,'attempt_ns':end+offset*10**9-1,'end_ns':end+offset*10**9,'ok':ok})
        r['metrics']['app']['first_success_ns']=end+10**9
        trial=analyze.derive(r,'openvpn',8)
        self.assertEqual(trial['streams']['app']['failed_after_first_response'],1)
        self.assertEqual(trial['streams']['app']['last_response_age_ms'],42000)
        self.assertEqual(trial['streams']['app']['max_gap_after_first_response_ms'],42000)

if __name__=='__main__':unittest.main()
