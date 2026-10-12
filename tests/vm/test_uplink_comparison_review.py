"""Pure, independent checks of evidence acceptance; no guest or network calls."""
import copy
import unittest

import uplink_comparison as comparison


class UplinkEvidenceReviewTest(unittest.TestCase):
    def valid_censored_status(self):
        second = 1_000_000_000
        baseline, begin, end, stop = second, 11 * second, 12 * second, 57 * second
        samples = []
        metrics = {}
        for kind in comparison.KINDS:
            for at in range(baseline, begin, second // 5):
                samples.append(dict(kind=kind, begin_ns=at, attempt_ns=at,
                                    end_ns=at + 1, ok=True, relay='r0'))
            for at in range(end, stop, second // 5):
                samples.append(dict(kind=kind, begin_ns=at, attempt_ns=at,
                                    end_ns=at + 1, ok=False, failure='timeout'))
            metrics[kind] = dict(first_success_ns=0, failed_attempts=225,
                                 unrecovered_at_end=True, observed_for_ns=45 * second,
                                 baseline_failures=0, baseline_samples=50,
                                 samples=225, max_success_gap_ns=45 * second,
                                 max_sample_start_gap_ns=second // 5)
        report = dict(schema_version=1, completed=True, transport='vpnctl', paths=4,
                      race=False, baseline_start_ns=baseline, fault_begin_ns=begin,
                      fault_end_ns=end, window_end_ns=stop, samples=samples, metrics=metrics)
        for role, quota, cpu in (('robot', '50000 100000', '0'),
                                 ('server', '100000 100000', '1')):
            for suffix in ('before', 'after'):
                report[role + '_' + suffix] = dict(
                    cpu_max=quota, cpuset_cpus_effective=cpu, guest_vcpus=2,
                    cpu_stat='usage_usec 1\nnr_throttled 0',
                    **{'memory.current': '1', 'memory.peak': '1', 'memory.events': 'oom 0'})
        reports = []
        for fault in sorted(comparison.FAULTS):
            item = copy.deepcopy(report)
            item['fault'] = fault
            reports.append(dict(report=item, logs={}))
        return dict(exit=0, reports=reports)

    def test_complete_unrecovered_observation_is_valid(self):
        comparison.validate(self.valid_censored_status(), 'vpnctl', 4)

    def test_missing_application_stream_cannot_inherit_claimed_metrics(self):
        status = self.valid_censored_status()
        report = status['reports'][0]['report']
        report['samples'] = [s for s in report['samples'] if s['kind'] != 'existing']
        with self.assertRaises(RuntimeError):
            comparison.validate(status, 'vpnctl', 4)

    def test_missing_baseline_cannot_inherit_claimed_sample_count(self):
        status = self.valid_censored_status()
        report = status['reports'][0]['report']
        report['samples'] = [s for s in report['samples']
                             if s['begin_ns'] >= report['fault_end_ns']]
        with self.assertRaises(RuntimeError):
            comparison.validate(status, 'vpnctl', 4)

    def test_failed_attempt_count_must_match_raw_rows(self):
        status = self.valid_censored_status()
        status['reports'][0]['report']['metrics']['app']['failed_attempts'] = 0
        with self.assertRaises(RuntimeError):
            comparison.validate(status, 'vpnctl', 4)

    def test_invalid_sample_chronology_is_not_an_outage(self):
        status = self.valid_censored_status()
        sample = status['reports'][0]['report']['samples'][-1]
        sample['end_ns'] = sample['begin_ns'] - 1
        with self.assertRaises(RuntimeError):
            comparison.validate(status, 'vpnctl', 4)

    def test_truncated_tail_cannot_inherit_claimed_scheduling_gap(self):
        status = self.valid_censored_status()
        report = status['reports'][0]['report']
        report['samples'] = [s for s in report['samples']
                             if s['end_ns'] < report['fault_end_ns'] + 1_000_000_000]
        with self.assertRaises(RuntimeError):
            comparison.validate(status, 'vpnctl', 4)


if __name__ == '__main__':
    unittest.main()
