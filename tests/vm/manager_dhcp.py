#!/usr/bin/env python3
"""One DHCP DORA exchange in the disposable guest's shared client namespace.

This tests the real NM-started dnsmasq. It is not a general DHCP client and does
not touch host networking. The caller supplies an initial local test address so
standard UDP can broadcast; the validated ACK supplies the address used next.
"""
import ipaddress
import json
import os
import socket
import struct
import time
from pathlib import Path
from guest_agent import guard


def options(data):
    result = {}
    i = 240
    while i < len(data):
        kind = data[i]
        i += 1
        if kind == 255:
            return result
        if kind == 0:
            continue
        if i >= len(data) or i + 1 + data[i] > len(data):
            raise ValueError('truncated DHCP option')
        length = data[i]
        i += 1
        if kind in result:
            raise ValueError('duplicate DHCP option')
        result[kind] = data[i:i + length]
        i += length
    raise ValueError('missing DHCP end marker')


def exchange():
    guard()
    mac = bytes.fromhex(Path('/sys/class/net/lan0/address').read_text().strip().replace(':', ''))
    xid = os.urandom(4)
    header = struct.pack('!BBBB4sHH4s4s4s4s16s64s128s', 1, 1, 6, 0, xid, 0, 32768,
                         b'\0' * 4, b'\0' * 4, b'\0' * 4, b'\0' * 4, mac.ljust(16, b'\0'), b'', b'')
    cookie = bytes([99, 130, 83, 99])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'lan0\0')
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('0.0.0.0', 68))
        def request(kind, wanted, extra=b''):
            sock.sendto((header + cookie + bytes([53, 1, kind, 55, 4, 1, 3, 6, 51]) + extra + b'\xff').ljust(300, b'\0'), ('255.255.255.255', 67))
            until = time.monotonic() + 5
            while time.monotonic() < until:
                sock.settimeout(max(0.01, until - time.monotonic()))
                data, peer = sock.recvfrom(4096)
                if len(data) < 240 or data[0:3] != bytes([2, 1, 6]) or data[4:8] != xid or data[28:34] != mac or data[236:240] != cookie:
                    continue
                opt = options(data)
                if opt.get(53) != bytes([wanted]):
                    raise RuntimeError('unexpected DHCP response type')
                address = ipaddress.IPv4Address(data[16:20])
                if address not in ipaddress.ip_network('10.42.0.0/24') or address in (ipaddress.ip_address('10.42.0.0'), ipaddress.ip_address('10.42.0.1'), ipaddress.ip_address('10.42.0.255')) or opt.get(54) != socket.inet_aton('10.42.0.1') or peer != ('10.42.0.1', 67):
                    raise RuntimeError('unexpected DHCP authority or address')
                return address, opt
            raise RuntimeError('DHCP response missing')
        offer, opt = request(1, 2)
        address, opt = request(3, 5, bytes([50, 4]) + offer.packed + bytes([54, 4]) + opt[54])
        if address != offer or opt.get(1) != socket.inet_aton('255.255.255.0') or opt.get(3) != socket.inet_aton('10.42.0.1') or opt.get(6) != socket.inet_aton('10.42.0.1') or len(opt.get(51, b'')) != 4 or int.from_bytes(opt[51], 'big') <= 0:
            raise RuntimeError('DHCP ACK missing address/mask/router/DNS/lease contract')
        return {'address': str(address), 'prefix': 24, 'router': '10.42.0.1', 'dns': '10.42.0.1',
                'lease_seconds': int.from_bytes(opt[51], 'big'), 'exchange': 'discover-offer-request-ack'}

if __name__ == '__main__':
    print(json.dumps(exchange()))
