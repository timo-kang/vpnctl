# Copyright 2026 Jonghyeok Kang
# SPDX-License-Identifier: Apache-2.0
import copy
import json
from pathlib import Path
import unittest

from vpnctl_uplink import State


class ConsumerContractTests(unittest.TestCase):
    def test_shared_contract(self):
        fixture = json.loads((Path(__file__).resolve().parents[3] / 'internal/uplinkclient/testdata/consumer.json').read_text())
        for case in fixture['cases']:
            with self.subTest(case=case['name']):
                now, fail = int(fixture['now']), False
                def clock():
                    if fail:
                        raise OSError('clock')
                    return fixture['clock_domain'], now
                state = State('app', clock)
                epoch = state.begin()
                for index, step in enumerate(case['steps']):
                    if step['op'] == 'clock':
                        now, fail = int(step.get('now', now)), step.get('fail', fail)
                    elif step['op'] == 'begin':
                        epoch = state.begin()
                    elif step['op'] == 'disconnect':
                        state.disconnect(epoch)
                    elif step['op'] == 'receive':
                        frame = copy.deepcopy(fixture['base'])
                        for key, value in step.get('patch', {}).items():
                            if key == 'snapshot':
                                for k, v in value.items():
                                    if v is None:
                                        frame[key].pop(k, None)
                                    else:
                                        frame[key][k] = v
                            else:
                                frame[key] = value
                        raw = step.get('raw', json.dumps(frame)).encode()
                        try:
                            state.accept(step.get('epoch', epoch), raw)
                            failed = False
                        except ValueError:
                            failed = True
                        self.assertEqual(failed, step['error'], (case['name'], index))
                    if 'expect' in step:
                        view = state.current()
                        for key, want in step['expect'].items():
                            self.assertEqual(view[key], want, (case['name'], index, key))


if __name__ == '__main__':
    unittest.main()
