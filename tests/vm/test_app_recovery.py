# Copyright 2026 Jonghyeok Kang
# SPDX-License-Identifier: Apache-2.0
import copy
import unittest
from unittest import mock

import app_recovery as recovery
import observer


def fixture():
    row = dict(completed=True, schema_version=1, paths=4, cpu_layout='split',
               role_membership_verified=True, authenticated_default_fallback_baseline=True,
               app_slo_ns=None, phase_watchdog_seconds=75, blocked_window_seconds=20,
               server_session_seconds=600, server_max_requests=12000,
               selector_probe_port=9192, application_tls_port=9193,
               publication_boot_ns=None, receipt_boot_ns=None, route_applied_boot_ns=None, phases=[])
    histories = [[], []]
    connections = [0, 0]
    for index, name in enumerate(recovery.PHASES):
        start = 1_000_000_000 + index*30_000_000_000
        cutoff, end = start+1_000_000_000, start+23_000_000_000
        healthy = recovery.BLOCKED.get(name, (True, True))
        p = dict(name=name, started_boot_ns=str(start), fault_completed_boot_ns=str(cutoff),
                 finished_boot_ns=str(end), healthy=list(healthy), before=[], after=[], routes=[])
        if not all(healthy):
            p['server_check'] = dict(snapshot_boot_ns=str(end+2), payload=dict(correct=1, last_correct_boot_ns=str(end+1)))
        for i in (0, 1):
            state = dict(snapshot_boot_ns=str(end-1), payload={'authenticated_connections': 1},
                         api=dict(api_available=name not in ('api_outage', 'api_outage_payload'),
                                  producer_id='first' if index < 3 else 'second', availability='reachable'))
            p['before'].append(copy.deepcopy(state)); p['after'].append(state)
            path = {'underlay_change': 'p01', 'relay_change': 'p11'}.get(name, 'p00')
            p['routes'].append({'applied': True, 'selection': {'desired_path_id': path}})
            for offset in (4, 12):
                begin = cutoff+offset*1_000_000_000+i*100_000_000
                reuse = bool(histories[i] and histories[i][-1]['correct'])
                new = not reuse and healthy[i]
                if new:
                    connections[i] += 1
                histories[i].append(dict(request=len(histories[i])+1, connection=connections[i] if reuse or new else 0,
                    started_boot_ns=str(begin), finished_boot_ns=str(begin+1_000_000),
                    next_delay_ns='250000000', authenticated_connect_boot_ns=str(begin+1) if new else None,
                    correct=healthy[i], existing_socket=reuse, outcome_unknown=not healthy[i] and reuse,
                    failure='' if healthy[i] else ('read' if reuse else 'connect')))
            state['payload']['authenticated_connections'] = connections[i]
        row['phases'].append(p)
    for i, (name, language) in enumerate((('app', 'go'), ('app2', 'python'))):
        ev = histories[i]
        correct = [int(e['finished_boot_ns']) for e in ev if e['correct']]
        payload = dict(events=ev, attempts=len(ev), dropped_events=0, correct=len(correct),
                       authenticated_connections=connections[i], existing_socket_correct=sum(e['correct'] and e['existing_socket'] for e in ev),
                       new_socket_correct=sum(e['correct'] and not e['existing_socket'] for e in ev),
                       outcome_unknown=sum(e['outcome_unknown'] for e in ev), invalid_responses=0,
                       first_correct_boot_ns=str(correct[0]), last_correct_boot_ns=str(correct[-1]),
                       max_correct_gap_ns=str(max(b-a for a, b in zip(correct, correct[1:]))))
        snapshot = int(row['phases'][-1]['finished_boot_ns'])+1
        row[name] = dict(schema_version=1, language=language, target_id=name,
                         payload=payload, cpu_user_ns=10, cpu_system_ns=2, process_peak_rss_kib=100,
                         publication_boot_ns=None, receipt_boot_ns=None, no_correct_response=False,
                         snapshot_boot_ns=str(snapshot), response_age_ns=str(snapshot-correct[-1]))
    return row


class AppRecoveryEvidenceTests(unittest.TestCase):
    def test_dispatch_requires_explicit_split_profile(self):
        self.assertEqual(observer.capacity_vcpus('split', ['uplink-apps-4', 'uplink-apps-8'], '200000', '100000'), 2)
        for layout, cpu in (('shared', '1'), ('split', '2')):
            vm = mock.Mock()
            with self.assertRaises(RuntimeError):
                observer.exercise(vm, 'uplink-apps-4', 'stopped', 0, {}, cpu_layout=layout, robot_cpus=cpu)
            self.assertFalse(any(call.args[0] == 'uplink-apps-start' for call in vm.call.call_args_list))

    def test_measures_each_app_without_app_slo(self):
        result = recovery.validate_report(fixture(), 4)
        self.assertEqual(len(result), 15)
        self.assertNotEqual(result[0]['apps']['app']['fault_to_first_correct_ns'],
                            result[0]['apps']['app2']['fault_to_first_correct_ns'])
        self.assertFalse(result[-1]['apps']['app']['recovered'])

    def test_rejects_missing_or_misleading_evidence(self):
        changes = [lambda r: r.pop('app2'), lambda r: r['phases'].pop(),
                   lambda r: r.update(app_slo_ns='10000000000'),
                   lambda r: r['app'].pop('response_age_ns'),
                   lambda r: r['app']['payload'].update(dropped_events=1),
                   lambda r: r['app']['payload']['events'][1].update(request=1),
                   lambda r: r['app']['payload'].update(correct=999),
                   lambda r: r['phases'][2]['after'][0]['payload'].update(authenticated_connections=2),
                   lambda r: r['phases'][2]['after'][0]['api'].update(api_available=True),
                   lambda r: r['phases'][3]['after'][0]['api'].update(producer_id='first'),
                   lambda r: r['phases'][4]['after'][0]['api'].update(availability='unknown'),
                   lambda r: r['phases'][4].pop('server_check'),
                   lambda r: r['phases'][4]['server_check']['payload'].update(correct=0),
                   lambda r: r['phases'][6]['routes'][0]['selection'].update(desired_path_id='p00'),
                   lambda r: r['phases'][7]['after'][1].update(snapshot_boot_ns='1'),
                   lambda r: r['app']['payload']['events'][16].update(correct=True),
                   lambda r: r['app2']['payload']['events'][2].update(started_boot_ns='01')]
        for change in changes:
            data = fixture(); change(data)
            with self.subTest(change=change), self.assertRaises((RuntimeError, KeyError)):
                recovery.validate_report(data, 4)

    def test_a_prior_success_cannot_qualify_later_recovery(self):
        data = fixture()
        phase = data['phases'][6]
        phase['fault_completed_boot_ns'] = str(int(phase['finished_boot_ns'])-1)
        with self.assertRaises(RuntimeError):
            recovery.validate_report(data, 4)

    def test_blocked_new_nonce_success_is_never_a_buffered_reply(self):
        data = fixture()
        events = [data[name]['payload']['events'] for name in ('app', 'app2')]
        cutoff = int(data['phases'][4]['fault_completed_boot_ns'])
        events[0][8].update(started_boot_ns=str(cutoff+1), finished_boot_ns=str(cutoff+2), correct=True)
        # Isolate the phase rule: aggregate/lifecycle checks have their own tests.
        with mock.patch.object(recovery, 'app_events', side_effect=events), self.assertRaises(RuntimeError):
            recovery.validate_report(data, 4)

    def test_existing_failures_do_not_prove_default_fallback_retry(self):
        data = fixture()
        events = [data[name]['payload']['events'] for name in ('app', 'app2')]
        events[0][8]['existing_socket'] = events[0][9]['existing_socket'] = True
        with mock.patch.object(recovery, 'app_events', side_effect=events), self.assertRaises(RuntimeError):
            recovery.validate_report(data, 4)

    def test_failure_retires_socket_before_next_operation(self):
        data = fixture()
        data['app']['payload']['events'][9]['existing_socket'] = True
        with self.assertRaisesRegex(RuntimeError, 'socket reused'):
            recovery.app_events(data['app'], 'go', 'app')


if __name__ == '__main__':
    unittest.main()
