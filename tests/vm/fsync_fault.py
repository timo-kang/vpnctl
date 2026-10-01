#!/usr/bin/python3
"""Inject one EIO into the selected atomic-write phase of an owned guest child.

Linux x86-64 only. Never attach to an existing process; EXITKILL prevents the
child escaping if the tracer dies. Syscall-entry/exit metadata follows ptrace(2).
"""
import ctypes as C
import errno
import json
import os
from pathlib import Path
import signal
import struct
import sys

from guest_agent import guard, ROOT

class Registers(C.Structure):
    _fields_ = [(name, C.c_ulonglong) for name in (
        'r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax '
        'rip cs eflags rsp ss fs_base gs_base ds es fs gs').split()]

libc = C.CDLL(None, use_errno=True)
libc.ptrace.restype = C.c_long
libc.ptrace.argtypes = [C.c_uint, C.c_uint, C.c_void_p, C.c_void_p]

def ptrace(request, pid, addr=0, data=0):
    C.set_errno(0)
    result = libc.ptrace(request, pid, addr, data)
    if result == -1 and C.get_errno():
        raise OSError(C.get_errno(), 'ptrace')
    return result

def fd_path(pid, fd):
    try:
        return os.readlink(f'/proc/{pid}/fd/{fd}')
    except FileNotFoundError:
        return ''

def main():
    guard()
    mode, cache, output, *command = sys.argv[1:]
    if os.uname().machine != 'x86_64' or mode not in ('fsync', 'fsync-dir'):
        raise SystemExit('unsupported fault/platform')
    if not Path(cache).is_relative_to(ROOT / 'work') or not Path(output).is_relative_to(ROOT):
        raise SystemExit('private guest paths required')
    if command[:3] != ['/opt/vpnctl-vm/vpnctl', 'relay', 'refresh']:
        raise SystemExit('only the owned relay refresh child is supported')
    child = os.fork()
    if child == 0:
        ptrace(0, 0)  # TRACEME
        os.kill(os.getpid(), signal.SIGSTOP)
        os.execv(command[0], command)
    os.waitpid(child, 0)
    # TRACESYSGOOD, TRACECLONE, TRACEEXEC, EXITKILL.
    ptrace(0x4200, child, 0, 1 | 8 | 16 | (1 << 20))
    ptrace(24, child)  # SYSCALL
    pending, renames, events = {}, {}, []
    renamed, injected, exit_code = False, False, 125
    while True:
        try:
            pid, status = os.waitpid(-1, 0x40000000)  # __WALL: all owned threads
        except ChildProcessError:
            break
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            if pid == child:
                exit_code = os.waitstatus_to_exitcode(status)
            continue
        sig, forward = os.WSTOPSIG(status), 0
        if sig == (signal.SIGTRAP | 0x80):
            info = C.create_string_buffer(128)
            ptrace(0x420e, pid, 128, C.byref(info))  # GET_SYSCALL_INFO
            raw = info.raw
            if struct.unpack_from('I', raw, 4)[0] != 0xc000003e:
                raise SystemExit('tracee must use the Linux x86-64 syscall ABI')
            if raw[0] == 1:  # entry
                nr, *args = struct.unpack_from('7Q', raw, 24)
                if nr in (264, 316):  # renameat/renameat2: the cache dirfds
                    renames[pid] = fd_path(pid, args[0]) == cache and fd_path(pid, args[2]) == cache
                if nr == 74:  # fsync
                    path = fd_path(pid, args[0])
                    target = (mode == 'fsync' and Path(path).parent == Path(cache) and Path(path).name.startswith('.pending-')) or (mode == 'fsync-dir' and path == cache and renamed)
                    events.append({'tid': pid, 'syscall': 'fsync', 'path': path, 'after_rename': renamed, 'injected': target and not injected})
                    if target and not injected:
                        regs = Registers()
                        ptrace(12, pid, 0, C.byref(regs))  # GETREGS
                        regs.orig_rax = 2**64 - 1  # skip original syscall
                        ptrace(13, pid, 0, C.byref(regs))  # SETREGS
                        pending[pid], injected = events[-1], True
            elif raw[0] == 2:  # exit
                value = struct.unpack_from('q', raw, 24)[0]
                if renames.pop(pid, False) and value == 0:
                    renamed = True
                    events.append({'tid': pid, 'syscall': 'rename', 'completed': True})
                fault = pending.pop(pid, None)
                if fault is not None:
                    regs = Registers()
                    ptrace(12, pid, 0, C.byref(regs))
                    regs.rax = 2**64 - errno.EIO
                    ptrace(13, pid, 0, C.byref(regs))
                    fault['returned_errno'] = errno.EIO
        elif sig not in (signal.SIGSTOP, signal.SIGTRAP):
            forward = sig
        try:
            ptrace(24, pid, 0, forward)
        except ProcessLookupError:
            pass
    Path(output).write_text(json.dumps({'mode': mode, 'injected': injected, 'exit': exit_code, 'events': events}))
    raise SystemExit(exit_code if exit_code > 0 else 125)

if __name__ == '__main__':
    main()
