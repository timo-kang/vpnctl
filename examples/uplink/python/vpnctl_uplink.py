# Copyright 2026 Jonghyeok Kang
# SPDX-License-Identifier: Apache-2.0
"""Linux local reference consumer. Observations never authorize routing or replay."""
import hashlib
import json
import os
import re
import threading
import time

MAX_RECORD = 4096
MAX_UINT = (1 << 64) - 1
ID = re.compile(r'[A-Za-z0-9_.-]{1,64}\Z')
HEX = re.compile(r'[0-9a-f]{32}\Z')
DOMAIN = re.compile(r'v1:[0-9a-f]{64}\Z')
FIELD = re.compile(r'[a-z][a-z0-9_]*\Z')


def _local_clock():
    with open('/proc/self/timens_offsets', encoding='ascii') as f:
        offsets = f.read(4096).splitlines()
    names = set()
    for line in offsets:
        name, seconds, nanos = line.split()
        if name not in ('monotonic', 'boottime') or name in names or int(seconds) != 0 or int(nanos) != 0:
            raise OSError('unsupported time namespace')
        names.add(name)
    if names != {'monotonic', 'boottime'}:
        raise OSError('clock offsets unavailable')
    with open('/proc/sys/kernel/random/boot_id', encoding='ascii') as f:
        boot = f.read(128).strip()
    ns = os.stat('/proc/self/ns/net')
    raw = f'vpnctl.uplink.clock.v1\0{boot}:{ns.st_dev}:{ns.st_ino}'.encode()
    return 'v1:' + hashlib.sha256(raw).hexdigest(), time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def local_clock():
    try:
        return _local_clock()
    except (OSError, ValueError, AttributeError, OverflowError) as exc:
        raise OSError('local boot clock unavailable') from exc


def _object(pairs):
    obj = {}
    for k, v in pairs:
        if not FIELD.fullmatch(k) or k in obj:
            raise ValueError('invalid JSON member')
        obj[k] = v
    return obj


def _depth(value, level=0):
    if level > 8:
        raise ValueError('frame depth exceeded')
    if isinstance(value, (dict, list)):
        for v in value.values() if isinstance(value, dict) else value:
            _depth(v, level + 1)


def _uint(value, quoted=False):
    if quoted:
        if not isinstance(value, str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', value):
            raise ValueError('noncanonical decimal string')
        value = int(value)
    if type(value) is not int or not 0 <= value <= MAX_UINT:
        raise ValueError('invalid unsigned integer')
    return value


def _json_int(text):
    if text == '-0':
        raise ValueError('noncanonical integer')
    return int(text)


def _decode(raw, target):
    if len(raw) > MAX_RECORD:
        raise ValueError('oversized frame')
    try:
        f = json.loads(raw.decode('utf-8'), object_pairs_hook=_object, parse_int=_json_int,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
        _depth(f)
        s = f['snapshot']
        if type(f['schema_version']) is not int or f['schema_version'] != 1 or type(s['schema_version']) is not int or s['schema_version'] != 1 or f['type'] not in ('snapshot', 'reset'):
            raise ValueError('unsupported schema')
        transport, sequence = f['cursor'].split(':')
        if not HEX.fullmatch(transport) or _uint(sequence, True) == 0:
            raise ValueError('invalid cursor')
        for key in ('target_id', 'producer_id', 'availability', 'freshness', 'reason', 'clock_domain', 'session_continuity'):
            if not isinstance(s[key], str):
                raise ValueError('invalid string')
        for key in ('path_id', 'evidence'):
            if key in s and not isinstance(s[key], str):
                raise ValueError('invalid optional string')
        for key in ('revision', 'path_revision', 'observed_boot_ns', 'valid_until_boot_ns'):
            if key in s or key in ('revision', 'path_revision'):
                _uint(s[key], True)
        _uint(s['remaining_validity_ms'])
        if 'observed_age_ms' in s:
            _uint(s['observed_age_ms'])
        if s['target_id'] != target or not HEX.fullmatch(s['producer_id']) or int(s['revision']) == 0 or not DOMAIN.fullmatch(s['clock_domain']) or s['session_continuity'] != 'not_established':
            raise ValueError('invalid snapshot identity')
        path, evidence = s.get('path_id', ''), s.get('evidence', '')
        if s['freshness'] == 'fresh':
            observed, until = int(s.get('observed_boot_ns', 0)), int(s.get('valid_until_boot_ns', 0))
            if not 0 < observed < until or until - observed > 30_000_000_000:
                raise ValueError('invalid observation budget')
            expected = {'reachable': ('unbound_tcp_connect_verified', 'unbound_tcp_connect'),
                        'unreachable': ('approved_candidates_unreachable', 'bound_tcp_connect'),
                        'blocked': ('approval_denied_or_expired', '')}
            if expected.get(s['availability']) != (s['reason'], evidence):
                raise ValueError('invalid evidence')
            if s['availability'] == 'reachable':
                if not ID.fullmatch(path) or int(s['path_revision']) == 0:
                    raise ValueError('missing applied path')
            elif path:
                raise ValueError('unexpected path')
        elif (s['freshness'] not in ('unknown', 'stale') or s['availability'] != 'unknown' or path or evidence
              or s['reason'] not in ('observation_unavailable', 'clock_unavailable', 'revision_exhausted', 'observation_expired', 'observation_invalidated')):
            raise ValueError('invalid unknown state')
        return f
    except (KeyError, TypeError, AttributeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise ValueError('invalid uplink frame') from exc


def _stable(frame):
    source = frame['snapshot']
    s = {k: source[k] for k in ('schema_version', 'target_id', 'producer_id', 'revision', 'availability', 'freshness', 'reason', 'clock_domain', 'path_revision', 'session_continuity')}
    s.update({k: source.get(k, '0') for k in ('observed_boot_ns', 'valid_until_boot_ns')})
    s.update({k: source.get(k, '') for k in ('path_id', 'evidence')})
    return frame['cursor'], s


class State:
    def __init__(self, target, clock=local_clock):
        if not isinstance(target, str) or not ID.fullmatch(target) or not callable(clock):
            raise ValueError('valid target and clock required')
        self._target, self._clock = target, clock
        self._lock = threading.Lock()
        self._epoch = self._last_clock = 0
        self._accepted = 0
        self._observed_high = 0
        self._first = self._api = self._invalid = self._reset = self._active = False
        self._last = None

    def begin(self):
        with self._lock:
            self._api, self._first = False, True
            self._active = False
            if self._epoch == MAX_UINT:
                self._invalid = True
                return 0
            self._epoch += 1
            self._active = True
            return self._epoch

    def cursor(self):
        with self._lock:
            return self._last['cursor'] if self._last else ''

    def accepted_frames(self):
        """Validated API records, not evidence of payload success/freshness."""
        with self._lock:
            return self._accepted

    def disconnect(self, epoch):
        with self._lock:
            if epoch == self._epoch:
                self._api = False
                self._active = False

    def accept(self, epoch, raw):
        with self._lock:
            if epoch == 0 or epoch != self._epoch or not self._active:
                raise ValueError('retired uplink stream')
            try:
                f = _decode(raw, self._target)
                s, old = f['snapshot'], self._last
                new_publication, reset = old is None, f['type'] == 'reset'
                if old:
                    b = old['snapshot']
                    transport, seq = f['cursor'].split(':')
                    prev_transport, prev = old['cursor'].split(':')
                    seq, prev = int(seq), int(prev)
                    changed = transport != prev_transport
                    if changed and not self._first or not changed and (seq < prev or seq == prev and _stable(f) != _stable(old)):
                        raise ValueError('out of order cursor')
                    same = s['producer_id'] == b['producer_id']
                    rev, prev_rev = int(s['revision']), int(b['revision'])
                    new_publication = not same or rev > prev_rev
                    if same:
                        if rev < prev_rev or int(s['path_revision']) < int(b['path_revision']):
                            raise ValueError('out of order revision')
                        if rev > prev_rev and s['freshness'] == 'fresh' and int(s['observed_boot_ns']) <= self._observed_high:
                            raise ValueError('reused observation timestamp')
                        if rev == prev_rev:
                            if any(s.get(k, '0') != b.get(k, '0') for k in ('observed_boot_ns', 'valid_until_boot_ns', 'path_revision')):
                                raise ValueError('changed observation budget')
                            if s['freshness'] == 'fresh' and (b['freshness'] != 'fresh' or any(s.get(k, '') != b.get(k, '') for k in ('availability', 'path_id', 'evidence', 'reason'))):
                                raise ValueError('changed publication')
                    reset = (reset and f['cursor'] != old['cursor']) or changed or not same or (not changed and seq > prev + 1) or (same and rev > prev_rev + 1)
                if new_publication:
                    self._invalid = False
                if old is None or s['producer_id'] != old['snapshot']['producer_id']:
                    self._observed_high = 0
                if s['freshness'] == 'fresh':
                    self._observed_high = max(self._observed_high, int(s['observed_boot_ns']))
                self._last, self._api, self._first, self._reset = f, True, False, reset
                self._accepted = min(MAX_UINT, self._accepted + 1)
                self._current()
            except ValueError:
                self._api, self._invalid = False, True
                raise

    def current(self):
        with self._lock:
            return self._current()

    def _current(self):
        v = dict(api_available=self._api, availability='unknown', freshness='unknown', reason='observation_unavailable', reset=self._reset)
        if not self._last:
            return v
        s = self._last['snapshot']
        v.update({k: s[k] for k in ('producer_id', 'revision', 'path_revision', 'availability', 'freshness', 'reason')})
        v['path_id'] = s.get('path_id', '')
        reason = ''
        try:
            domain, now = self._clock()
            if domain != s['clock_domain'] or now <= 0 or now < self._last_clock or s['freshness'] == 'fresh' and now < int(s['observed_boot_ns']):
                raise OSError('clock unavailable')
            self._last_clock = now
            if s['freshness'] == 'fresh' and now >= int(s['valid_until_boot_ns']):
                reason = 'observation_expired'
        except OSError:
            reason = 'clock_unavailable'
        if reason:
            self._invalid = True
        if self._invalid:
            v.update(availability='unknown', freshness='stale', path_id='', reason=reason or 'observation_invalidated')
        return v
