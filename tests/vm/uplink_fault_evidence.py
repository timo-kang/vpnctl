"""Independent scope/counter checks for the registered fixed network faults."""
import json

PREFIXES = ('192.0.2', '198.51.100', '203.0.113', '198.19.0')


def check(report):
    product, count, fault = report['transport'], report['paths'], report['fault']
    if product not in ('vpnctl', 'openvpn') or type(count) is not int or count not in (4, 8):
        raise ValueError('invalid profile')
    times = [report[k] for k in ('fault_end_ns', 'fault_rules_before_observed_ns', 'window_end_ns', 'fault_rules_after_observed_ns', 'final_selection_begin_ns', 'final_selection_end_ns')]
    if any(type(t) is not int for t in times) or times != sorted(times) or times[1] >= times[2]:
        raise ValueError('snapshot timing differs from observation window')
    paths = report['candidate_ids']
    expected_ids = [f'p{r}{u}' for r in range(2) for u in range(count // 2)]
    if [p['id'] for p in paths] != expected_ids:
        raise ValueError('candidate ordering differs from registered order')
    for i, p in enumerate(paths):
        r, u = divmod(i, count // 2)
        if (p['relay'], p['underlay'], p['udp_port']) != (r, u, 1194 if product == 'openvpn' else 51820 + u):
            raise ValueError('candidate endpoint differs from registered profile')
    before, after = report['fault_rules_before'], report['fault_rules_after']
    if fault == 'link-down':
        for state in (before, after):
            if set(state) != {'robot'}:
                raise ValueError('unexpected link snapshot role')
            rows = json.loads(state['robot'])
            if len(rows) != 1 or rows[0]['ifname'] != 'wan0' or 'UP' in rows[0]['flags']:
                raise ValueError('link-down was not retained')
        return {'fault_verified': True, 'dropped_packets': None}
    expected, chains = set(), set()
    def rule(role, chain, addr, protocol, port, interface=''):
        expected.add((role, chain, addr, protocol, port, interface))
        chains.add((role, chain, 'accept'))
    if fault == 'endpoint-drop':
        rule('r0', 'input', '192.0.2.11', 'udp', paths[0]['udp_port'])
    elif fault == 'uplink-drop':
        rule('r0', 'forward', '198.18.0.2', 'tcp', 9192)
    elif fault == 'relay-drop':
        chains = {('r0', x, 'drop') for x in ('input', 'output', 'forward')}
    elif fault == 'last-endpoint-only':
        for p in paths[:-1]:
            rule('r' + str(p['relay']), 'input', PREFIXES[p['underlay']] + '.' + str(11 + p['relay']), 'udp', p['udp_port'])
    elif fault == 'app1-last-path' and product == 'vpnctl':
        interfaces = [p.get('interface') for p in paths]
        if len(set(interfaces)) != count or not all(interfaces):
            raise ValueError('missing per-path interface identity')
        for p in paths[:-1]:
            rule('robot', 'output', '198.18.0.2', 'tcp', 9192, p['interface'])
    else:
        raise ValueError('unexpected fault')
    snapshots = []
    for snapshot in (before, after):
        seen_rules, seen_chains, counters = set(), set(), {}
        if set(snapshot) != {c[0] for c in chains}:
            raise ValueError('unexpected snapshot role')
        for role, raw in snapshot.items():
            table_count = 0
            for entry in json.loads(raw)['nftables']:
                if len(entry) != 1:
                    raise ValueError('ambiguous nft entry')
                if 'metainfo' in entry:
                    continue
                if 'table' in entry:
                    c = entry['table']
                    if c.get('family') != 'inet' or c.get('name') != 'comparison_fault' or c.get('flags'):
                        raise ValueError('altered fault table')
                    table_count += 1
                    continue
                if 'chain' in entry:
                    c = entry['chain']
                    key = (role, c['name'], c['policy'])
                    if (c.get('family') != 'inet' or c.get('table') != 'comparison_fault'
                            or c.get('type') != 'filter' or c.get('hook') != c['name']
                            or c.get('prio') != -100 or c.get('flags') or key in seen_chains):
                        raise ValueError('altered fault chain')
                    seen_chains.add(key)
                    continue
                if 'rule' not in entry:
                    raise ValueError('unexpected nft entry')
                r = entry['rule']
                if r.get('family') != 'inet' or r.get('table') != 'comparison_fault':
                    raise ValueError('foreign fault rule')
                exprs = r['expr']
                if (len(exprs) < 4 or exprs[-1] != {'drop': None}
                        or set(exprs[-2]) != {'counter'}):
                    raise ValueError('expected matches then counter then drop')
                counter = exprs[-2]['counter']
                if set(counter) != {'packets', 'bytes'} or any(type(v) is not int or v < 0 for v in counter.values()):
                    raise ValueError('invalid counter')
                fields = {}
                for expr in exprs[:-2]:
                    if set(expr) != {'match'}:
                        raise ValueError('unexpected fault action')
                    m = expr['match']
                    if set(m) != {'op', 'left', 'right'} or m['op'] != '==':
                        raise ValueError('unexpected fault predicate')
                    left = m['left']
                    if left == {'payload': {'protocol': 'ip', 'field': 'daddr'}}:
                        key, value = 'addr', m['right']
                    elif left in ({'payload': {'protocol': 'tcp', 'field': 'dport'}}, {'payload': {'protocol': 'udp', 'field': 'dport'}}):
                        key, value = 'port', (left['payload']['protocol'], m['right'])
                    elif left == {'meta': {'key': 'oifname'}}:
                        key, value = 'interface', m['right']
                    else:
                        raise ValueError('unexpected fault match')
                    if key in fields:
                        raise ValueError('duplicate match field')
                    fields[key] = value
                if set(fields) not in ({'addr', 'port'}, {'addr', 'port', 'interface'}):
                    raise ValueError('missing fault match')
                protocol, port = fields['port']
                key = role, r['chain'], fields['addr'], protocol, port, fields.get('interface', '')
                if key in seen_rules:
                    raise ValueError('duplicate rule')
                seen_rules.add(key)
                counters[key] = counter['packets']
            if table_count != 1:
                raise ValueError('missing or duplicate fault table')
        if seen_rules != expected or seen_chains != chains:
            raise ValueError('fault scope differs from registered rules')
        snapshots.append(counters)
    a, b = snapshots
    if any(b[k] < a[k] for k in a):
        raise ValueError('fault counters regressed')
    # Before is captured AFTER installation; it can already contain the first
    # dropped packet. Total positive evidence matters, not a strictly positive delta.
    total = sum(b.values())
    if expected and total == 0:
        raise ValueError('no observed blocked traffic')
    return {'fault_verified': True, 'dropped_packets': total if expected else None}
