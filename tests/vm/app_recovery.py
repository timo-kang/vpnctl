# Copyright 2026 Jonghyeok Kang
# SPDX-License-Identifier: Apache-2.0
"""Validate per-app VM evidence; watchdogs never become recovery SLOs."""
import re

PHASES = ('baseline', 'api_outage', 'api_outage_payload', 'producer_restart',
          'one_app_down', 'one_app_recovered', 'underlay_change', 'relay_change',
          'all_uplinks_down', 'uplink_recovered', 'offline_valid',
          'approval_expired', 'approval_recovered', 'approval_revoked', 'denied_offline')
BLOCKED = {'one_app_down': (False, True), 'all_uplinks_down': (False, False),
           'approval_expired': (False, False), 'approval_revoked': (False, False),
           'denied_offline': (False, False)}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def ns(value):
    require(isinstance(value, str) and re.fullmatch(r'0|[1-9][0-9]{0,19}', value),
            'missing or noncanonical nanosecond boundary')
    result = int(value)
    require(result < 2**64, 'nanosecond overflow')
    return result


def count(value):
    require(type(value) is int and 0 <= value < 2**64, 'missing bounded counter')
    return value


def app_events(app, language, target):
    require(app.get('schema_version') == 1 and app.get('language') == language
            and app.get('target_id') == target, 'missing app identity')
    for key in ('cpu_user_ns', 'cpu_system_ns', 'process_peak_rss_kib'):
        count(app.get(key))
    require(app['process_peak_rss_kib'] > 0, 'missing app RSS')
    require(app.get('publication_boot_ns', 'missing') is None
            and app.get('receipt_boot_ns', 'missing') is None, 'unsupported app timing evidence')
    payload = app.get('payload', {})
    events = payload.get('events')
    require(isinstance(events, list) and 1 <= len(events) <= 4096
            and count(payload.get('dropped_events')) == 0
            and count(payload.get('attempts')) == len(events), 'incomplete transaction history')
    last, correct, existing, ambiguous, invalid, connections = 0, [], 0, 0, 0, 0
    socket_open = False
    for number, event in enumerate(events, 1):
        start, end = ns(event.get('started_boot_ns')), ns(event.get('finished_boot_ns'))
        require(event.get('request') == number and last <= start <= end, 'unordered or duplicate operation')
        require(type(event.get('correct')) is bool and type(event.get('existing_socket')) is bool
                and type(event.get('outcome_unknown')) is bool, 'missing response classification')
        delay = ns(event.get('next_delay_ns'))
        require(delay <= 8_000_000_000, 'retry budget exceeded')
        connected = event.get('authenticated_connect_boot_ns', 'missing')
        require(event['existing_socket'] is socket_open, 'socket reused after failure or silently replaced')
        if connected is not None:
            require(start <= ns(connected) <= end and not event['existing_socket'], 'invalid authenticated connect boundary')
            connections += 1
        authenticated = socket_open or connected is not None
        require(event.get('connection') == (connections if authenticated else 0), 'invalid socket identity')
        require(authenticated or event.get('failure') == 'connect', 'unclassified failed connect')
        if event['correct']:
            require(event.get('failure', '') == '' and not event['outcome_unknown'], 'contradictory correct response')
            require(event.get('connection') == connections and connections > 0, 'response without authenticated socket')
            correct.append(end)
            existing += int(event['existing_socket'])
        ambiguous += int(event['outcome_unknown'])
        invalid += int(event.get('failure') == 'unexpected_response')
        socket_open = event['correct']
        last = end
    expected = dict(correct=len(correct), authenticated_connections=connections,
                    existing_socket_correct=existing, new_socket_correct=len(correct)-existing,
                    outcome_unknown=ambiguous, invalid_responses=invalid)
    for key, value in expected.items():
        require(count(payload.get(key)) == value, 'aggregate disagrees with transactions: ' + key)
    require(correct and invalid == 0, 'missing valid payload or incorrect response')
    require(ns(payload.get('first_correct_boot_ns')) == correct[0]
            and ns(payload.get('last_correct_boot_ns')) == correct[-1], 'incorrect first/last response')
    require(ns(payload.get('max_correct_gap_ns')) == max((b-a for a, b in zip(correct, correct[1:])), default=0), 'incorrect completed gap')
    require(app.get('no_correct_response') is False
            and ns(app.get('response_age_ns')) == ns(app.get('snapshot_boot_ns')) - correct[-1], 'unrecovered tail omitted')
    require(ns(app['snapshot_boot_ns']) >= last, 'final report precedes transaction')
    return events


def validate_report(row, paths):
    require(row.get('completed') is True and row.get('schema_version') == 1
            and row.get('paths') == paths and paths in (4, 8), 'incomplete app VM trial')
    require(row.get('cpu_layout') == 'split' and row.get('role_membership_verified') is True,
            'missing split role placement')
    require(row.get('authenticated_default_fallback_baseline') is True, 'unproven fallback challenge')
    require(row.get('app_slo_ns', 'missing') is None and row.get('phase_watchdog_seconds') == 75
            and row.get('blocked_window_seconds') == 20, 'changed observation contract')
    require(row.get('server_session_seconds') == 600 and row.get('server_max_requests') == 12000
            and row.get('selector_probe_port') == 9192 and row.get('application_tls_port') == 9193,
            'unaccounted server closure or probe protocol')
    for key in ('publication_boot_ns', 'receipt_boot_ns', 'route_applied_boot_ns'):
        require(row.get(key, 'missing') is None, 'unsupported exact timing evidence')
    phases = row.get('phases', [])
    require([p.get('name') for p in phases] == list(PHASES), 'missing or reordered fault phases')
    events = [app_events(row.get(name, {}), language, name)
              for name, language in (('app', 'go'), ('app2', 'python'))]
    measurements, previous = [], 0
    for p in phases:
        name = p['name']
        start, cutoff, end = (ns(p.get(k)) for k in ('started_boot_ns', 'fault_completed_boot_ns', 'finished_boot_ns'))
        require(previous <= start <= cutoff < end, 'invalid fault ordering')
        previous = end
        healthy = BLOCKED.get(name, (True, True))
        require(p.get('healthy') == list(healthy), 'wrong expected fault scope')
        require(end-cutoff <= 78_000_000_000, 'phase exceeded declared watchdog')
        require(not any(not x for x in healthy) or end-cutoff >= 20_000_000_000, 'insufficient blocked window')
        if not all(healthy):
            service = p.get('server_check', {})
            require(ns(service.get('snapshot_boot_ns')) > end
                    and count(service.get('payload', {}).get('correct')) > 0
                    and ns(service['payload'].get('last_correct_boot_ns')) > end,
                    'blocked result lacks independently live TLS service')
        before, after = p.get('before', []), p.get('after', [])
        require(len(before) == len(after) == 2, 'missing per-app progress')
        measured = {'name': name, 'apps': {}}
        for i, app in enumerate(('app', 'app2')):
            fresh = [e for e in events[i] if ns(e['started_boot_ns']) >= cutoff and ns(e['finished_boot_ns']) <= end]
            successes = [e for e in fresh if e['correct']]
            require(cutoff < ns(after[i].get('snapshot_boot_ns')) <= end, 'stale progress qualified phase')
            if healthy[i]:
                require(len(successes) >= 1, 'app did not recover in observation window: ' + name + '/' + app)
            else:
                # These operations started after the fault and use new nonces.
                # None can be excused as a response buffered before the fault.
                require(len(fresh) >= 2 and not successes
                        and any(not e['existing_socket'] for e in fresh),
                        'blocked app bypassed or did not reconnect: ' + name + '/' + app)
            first = successes[0] if successes else None
            measured['apps'][app] = dict(
                fault_to_first_correct_ns=str(ns(first['finished_boot_ns'])-cutoff) if first else None,
                first_correct_boot_ns=first['finished_boot_ns'] if first else None,
                authenticated_connect_boot_ns=first['authenticated_connect_boot_ns'] if first else None,
                recovered=bool(first), existing_socket=first['existing_socket'] if first else None,
                attempts=len(fresh), uncertain_outcomes=sum(e['outcome_unknown'] for e in fresh))
        if name in ('api_outage', 'api_outage_payload'):
            require(all(r.get('api', {}).get('api_available') is False for r in after), 'API outage not observed')
        if name == 'api_outage_payload':
            require(all(after[i]['payload']['authenticated_connections'] == phases[0]['after'][i]['payload']['authenticated_connections'] for i in (0, 1)), 'API outage replaced a healthy socket')
        if name == 'producer_restart':
            require(all(after[i]['api']['api_available'] is True and after[i]['api']['producer_id']
                        and after[i]['api']['producer_id'] != phases[0]['after'][i]['api']['producer_id'] for i in (0, 1)), 'producer restart not consumed')
        if name == 'one_app_down':
            require(after[0]['api']['api_available'] is True and after[0]['api']['availability'] == 'reachable', 'service outage did not separate probe and app')
        path = {'underlay_change': 'p01', 'relay_change': 'p11'}.get(name)
        if path:
            routes = p.get('routes', [])
            require(len(routes) == 2 and all(r.get('applied') is True and r.get('selection', {}).get('desired_path_id') == path for r in routes), 'required route change unproven')
        measurements.append(measured)
    return measurements


def validate_diagnostic(row, mode, cpu):
    """Experimental two-phase evidence only; never a 15-phase qualification."""
    require(row.get('completed') is True and row.get('schema_version') == 1
            and row.get('paths') == 8 and row.get('diagnostic_mode') == mode
            and mode in ('control', 'api', 'stall') and cpu in ('0.5', '1')
            and row.get('diagnostic_robot_cpu') == cpu
            and row.get('diagnostic_window_seconds') == 45
            and row.get('role_membership_verified') is True, 'incomplete diagnostic identity')
    require(row.get('app_slo_ns', 'missing') is None, 'diagnostic is not an app SLO')
    phases = row.get('phases', [])
    require([p.get('name') for p in phases] == ['baseline', 'diagnostic_window'], 'wrong diagnostic phases')
    baseline, window = phases
    cutoff, end = ns(window.get('fault_completed_boot_ns')), ns(window.get('finished_boot_ns'))
    require(ns(baseline.get('finished_boot_ns')) <= ns(window.get('started_boot_ns')) <= cutoff
            and 45_000_000_000 <= end-cutoff <= 78_000_000_000, 'missing fixed diagnostic window')
    require(window.get('healthy') == [True, True], 'diagnostic payload scope changed')
    before, after = baseline.get('after', []), window.get('after', [])
    routes = window.get('routes', [])
    require(len(before) == len(after) == len(routes) == 2, 'missing app progress/route evidence')
    for i, (name, language) in enumerate((('app', 'go'), ('app2', 'python'))):
        events = app_events(row.get(name, {}), language, name)
        require(any(e['correct'] and cutoff < ns(e['started_boot_ns']) <= ns(e['finished_boot_ns']) <= end for e in events), 'no payload in diagnostic window')
        require(cutoff < ns(after[i].get('snapshot_boot_ns')) <= end, 'stale diagnostic progress')
        require(before[i].get('api', {}).get('api_available') is True
                and after[i].get('api', {}).get('api_available') is (mode != 'api'), 'API intervention not observed')
        require(count(after[i]['payload']['authenticated_connections']) == count(before[i]['payload']['authenticated_connections']), 'diagnostic socket replaced')
        require(routes[i].get('applied') is True and routes[i].get('selection', {}).get('desired_path_id') == 'p00', 'diagnostic route changed')
    return {'diagnostic_only': True, 'qualification': False}
