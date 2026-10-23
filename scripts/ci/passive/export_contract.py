"""Diagnostic mode is an explicit contract; OFF is not missing ON evidence."""
import copy


def validate_mode(report, mode, artifacts):
    if mode not in ('0', '1') or type(report.get('private_trace_requested')) is not bool:
        raise ValueError('missing explicit trace mode')
    if report['private_trace_requested'] != (mode == '1'):
        raise ValueError('executed trace mode differs')
    errors = ('private_trace_process_error', 'private_trace_evidence_error')
    if any(k in report for k in errors):
        raise ValueError('collector reported an error')
    if mode == '0':
        if artifacts or 'private_trace_summary' in report:
            raise ValueError('OFF trial produced collector evidence')
    elif not {'private-passive.json', 'private-passive.ready', 'private-passive.log'} <= set(artifacts):
        raise ValueError('ON trial missing collector artifacts')


def validate_raw(recording, summary):
    meta = copy.deepcopy(recording)
    events = meta.pop('events')
    if not isinstance(events, list): raise ValueError('invalid event collection')
    meta['retained_events'] = len(events)
    if meta != summary:
        raise ValueError('durable collector metadata differs from original response')
