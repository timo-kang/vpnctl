from pathlib import Path
import unittest
from unittest.mock import patch
import guest
import perf_events


class GuardTests(unittest.TestCase):
    def data(self):
        return {'/proc/cmdline': 'vpnctl_vm_test vpnctl_vm_token=' + 'a'*32 + ' vpnctl_vm_uuid=ab12 vpnctl_host_boot=host',
                '/proc/sys/kernel/random/boot_id': 'guest', '/sys/class/dmi/id/product_uuid': 'AB12',
                '/sys/devices/system/cpu/online': '0-1'}

    def invoke(self, data, uid=0, machine='x86_64', child=False):
        with patch.object(Path, 'read_text', autospec=True, side_effect=lambda p: data[str(p)]), \
             patch.object(guest.os, 'geteuid', return_value=uid), \
             patch.object(guest.platform, 'machine', return_value=machine), \
             patch.object(guest.os, 'readlink', side_effect=lambda p: 'child' if child and p == '/proc/self/ns/net' else 'root'):
            return guest.guard()

    def test_only_declared_guest_accepted(self):
        self.assertEqual(self.invoke(self.data()), 'guest')
        for key, value in [('/proc/cmdline', ''), ('/proc/sys/kernel/random/boot_id', 'host'),
                           ('/sys/class/dmi/id/product_uuid', 'different'), ('/sys/devices/system/cpu/online', '0')]:
            data = self.data(); data[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError): self.invoke(data)

    def test_arch_user_and_namespace_rejected(self):
        for kw in ({'uid': 1001}, {'machine': 'aarch64'}, {'child': True}):
            with self.subTest(kw=kw), self.assertRaises(RuntimeError): self.invoke(self.data(), **kw)

    def test_direct_ring_cannot_bypass_guard(self):
        with patch.object(guest, 'guard', side_effect=RuntimeError('host')), patch.object(perf_events.ctypes, 'CDLL') as libc:
            with self.assertRaises(RuntimeError): perf_events.Ring('unused', {}, 0)
            libc.assert_not_called()


if __name__ == '__main__': unittest.main()
