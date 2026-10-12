"""Aggregation must keep missing, invalid and right-censored trials distinct."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import uplink_summary as summary


class UplinkSummaryTest(unittest.TestCase):
    def data(self):
        cases=[f'uplink-{p}-{n}' for order in (('vpnctl','openvpn'),('openvpn','vpnctl'),('vpnctl','openvpn')) for n in (4,8) for p in order]
        faults=['link-down','endpoint-drop','relay-drop','uplink-drop','last-endpoint-only']
        plan=dict(cases=cases,faults=faults,vpnctl_reference=['app1-last-path'])
        rows=[]
        for ordinal,case in enumerate(cases,1):
            trials=[]
            for fault in faults+(['app1-last-path'] if 'vpnctl' in case else []):
                streams={kind:dict(first_response_ms=1000,failed_after_first_response=0,failed_attempts=1,
                                   last_response_age_ms=100,max_gap_after_first_response_ms=200,
                                   max_success_gap_ms=1000,max_sample_start_gap_ms=200)
                         for kind in ('app','app2','existing')}
                trials.append(dict(fault=fault,usable=True,streams=streams,final_selection={'tunnel':'p00'}))
            rows.append(dict(ordinal=ordinal,case=case,valid=True,trials=trials))
        return plan,dict(complete=True,cases=rows)

    def run_summary(self,plan,data):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/'plan.json').write_text(json.dumps(plan))
            (root/'safe-analysis.json').write_text(json.dumps(data))
            return summary.summarize(root)

    def target(self,result):
        return next(r for r in result['rows'] if (r['paths'],r['product'],r['fault'],r['stream'])==(4,'vpnctl','link-down','app'))

    def test_three_complete_recoveries_have_descriptive_median(self):
        plan,data=self.data();result=self.run_summary(plan,data)
        self.assertTrue(result['complete'])
        self.assertEqual(result['valid_cases'],12)
        self.assertEqual(len(result['rows']),66)
        self.assertEqual(self.target(result)['median_s'],1)
        self.assertEqual(self.target(result)['samples'][0]['max_gap_after_first_response_s'],.2)

    def test_one_censored_trial_cannot_disappear_from_median(self):
        plan,data=self.data()
        data['cases'][0]['trials'][0]['streams']['app']['first_response_ms']=None
        row=self.target(self.run_summary(plan,data))
        self.assertEqual((row['valid'],row['recovered'],row['censored']),(3,2,1))
        self.assertIsNone(row['median_s'])
        self.assertEqual(len(row['samples']),3)

    def test_invalid_case_is_not_counted_as_censored(self):
        plan,data=self.data();data['cases'][0]['valid']=False
        row=self.target(self.run_summary(plan,data))
        self.assertEqual((row['valid'],row['recovered'],row['censored']),(2,2,0))
        self.assertIsNone(row['median_s'])
        self.assertFalse(row['samples'][0]['valid'])

    def test_missing_runs_and_reordered_runs_are_not_complete(self):
        plan,data=self.data();data['cases']=data['cases'][:2]
        self.assertFalse(self.run_summary(plan,data)['complete'])
        data['cases'].reverse()
        with self.assertRaises(ValueError):self.run_summary(plan,data)


if __name__=='__main__':unittest.main()
