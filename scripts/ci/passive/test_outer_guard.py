from pathlib import Path
import unittest
from unittest.mock import patch
import outer_guard


class OuterGuardTests(unittest.TestCase):
    def invoke(self, updates=None, uid=1001, interfaces=None, container=True):
        data = {'/proc/self/status': 'CapEff:\t0000000000000000\n',
                '/sys/fs/cgroup/cpu.max': '200000 100000',
                '/sys/fs/cgroup/memory.max': str(2*1024**3),
                '/sys/fs/cgroup/memory.swap.max': '0'}
        data.update(updates or {})
        with patch.object(Path, 'read_text', autospec=True, side_effect=lambda p: data[str(p)]), \
             patch.object(Path, 'exists', return_value=container), \
             patch.object(outer_guard.os, 'geteuid', return_value=uid), \
             patch.object(outer_guard.socket, 'if_nameindex', return_value=interfaces or [(1, 'lo')]):
            outer_guard.outer_guard()

    def test_declared_outer_container_only(self):
        self.invoke()
        for args in ({'uid': 0}, {'container': False}, {'interfaces': [(1, 'lo'), (2, 'eth0')]},
                     {'updates': {'/proc/self/status': 'CapEff:\t0000000000000001\n'}},
                     {'updates': {'/sys/fs/cgroup/cpu.max': 'max 100000'}},
                     {'updates': {'/sys/fs/cgroup/memory.max': 'max'}},
                     {'updates': {'/sys/fs/cgroup/memory.swap.max': '1024'}}):
            with self.subTest(args=args), self.assertRaises(RuntimeError): self.invoke(**args)
