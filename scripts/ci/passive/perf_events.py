"""Bounded x86_64 guest-only perf tracepoint reader; no BPF/ptrace attachment."""
import ctypes
import fcntl
import mmap
import os
import re
import selectors
import struct
import threading
import time

FIELDS = {
    'syscalls/sys_enter_connect': ('fd',),
    'syscalls/sys_exit_connect': ('ret',),
    'syscalls/sys_enter_getsockopt': ('fd','level','optname'),
    'syscalls/sys_exit_getsockopt': ('ret',),
    'syscalls/sys_enter_getpeername': ('fd',),
    'syscalls/sys_exit_getpeername': ('ret',),
    'sock/inet_sock_set_state': ('skaddr','oldstate','newstate','sport','dport','family','protocol','saddr','daddr'),
}


def layouts(text, wanted):
    found = {}
    pattern = r'field:(.*?);\s*offset:(\d+);\s*size:(\d+);\s*signed:(\d+);'
    for decl, offset, size, signed in re.findall(pattern,text):
        name=decl.rsplit(' ',1)[-1].lstrip('*').split('[')[0]
        if name in wanted:
            found[name]=(int(offset),int(size),bool(int(signed)))
    if set(found) != set(wanted):
        raise ValueError('required tracepoint fields missing')
    return found


def decode_sample(data, fields):
    if len(data)<28:
        raise ValueError('truncated sample header')
    pid,tid,stamp,cpu,_,size=struct.unpack_from('<IIQIII',data)
    if size>len(data)-28:
        raise ValueError('truncated raw record')
    raw=data[28:28+size]
    result={'pid':pid,'tid':tid,'at_ns':stamp,'cpu':cpu}
    for name,(offset,width,signed) in fields.items():
        if offset+width>len(raw) or width not in (1,2,4,8):
            raise ValueError('unsupported/truncated field')
        value=raw[offset:offset+width]
        result[name]='.'.join(str(b) for b in value) if name in ('saddr','daddr') else int.from_bytes(value,'little',signed=signed)
    return result


def take_records(ring, tail, head):
    size=len(ring)
    if head<tail or head-tail>size:
        raise ValueError('ring overrun or backwards head')
    while tail<head:
        # Copy through wrap before parsing; never treat partial data as complete.
        at=tail%size
        def part(start,length):
            first=min(length,size-start)
            return bytes(ring[start:start+first])+bytes(ring[:length-first])
        header=part(at,8)
        if head-tail<8 or len(header)!=8:
            raise ValueError('truncated record header')
        kind,_,length=struct.unpack('<IHH',header)
        if length<8 or length>head-tail or length>size:
            raise ValueError('invalid record length')
        data=part(at,length)[8:]
        yield kind,data
        tail+=length


class Ring:
    def __init__(self,event,spec,cpu,pages=64):
        from guest import guard
        guard()
        if pages not in (1,64):raise ValueError('unsupported fixed ring capacity')
        self.event,self.cpu=event,cpu
        self.identity=spec['id']
        self.fields=layouts(spec['format'],('common_type','common_pid')+FIELDS[event])
        self.fd,self.memory=None,None
        self.samples,self.lost_records,self.unexpected=0,0,[]
        # perf_event_attr v7, sample every occurrence, explicit MONOTONIC clock.
        attr=ctypes.create_string_buffer(128)
        struct.pack_into('<IIQQQQQ',attr,0,2,128,spec['id'],1,2|4|128|1024,1|2|16,1|(1<<25))
        struct.pack_into('<I',attr,48,1)
        struct.pack_into('<i',attr,92,1)
        libc=ctypes.CDLL(None,use_errno=True)
        libc.syscall.restype=ctypes.c_long
        fd=libc.syscall(298,ctypes.byref(attr),-1,cpu,-1,8)
        if fd<0:
            raise OSError(ctypes.get_errno(),f'perf_event_open {event} cpu{cpu}')
        self.fd=fd
        try:
            self.memory=mmap.mmap(fd,(pages+1)*mmap.PAGESIZE,flags=mmap.MAP_SHARED,prot=mmap.PROT_READ|mmap.PROT_WRITE)
            self.offset,self.size=struct.unpack_from('<QQ',self.memory,1040)
            if self.offset!=mmap.PAGESIZE or self.size!=pages*mmap.PAGESIZE:
                raise ValueError('unsupported ring layout')
            self.tail=0
            fcntl.ioctl(fd,0x2400,0)
        except BaseException:
            self.close()
            raise

    def drain(self):
        # Supported only on x86_64, whose TSO ordering plus distinct Python/C
        # calls orders head-load -> payload copies -> tail-store. No ARM claim.
        head=struct.unpack_from('<Q',self.memory,1024)[0]
        if head==self.tail:
            return []
        rows=[]
        with memoryview(self.memory)[self.offset:self.offset+self.size] as ring:
            records=list(take_records(ring,self.tail,head))
        for kind,data in records:
            if kind==9:
                row=decode_sample(data,self.fields)
                if row['common_type']!=self.identity or row['common_pid']!=row['tid'] or row['cpu']!=self.cpu:
                    raise ValueError('perf metadata and raw identity differ')
                row['event']=self.event
                rows.append(row)
                self.samples+=1
            elif kind==2:
                if len(data)!=16:raise ValueError('invalid lost record')
                self.lost_records+=struct.unpack_from('<Q',data,8)[0]
            else:
                # Includes throttle/unthrottle: never silently call it complete.
                self.unexpected.append(kind)
        struct.pack_into('<Q',self.memory,1032,head)
        self.tail=head
        return rows

    def disable(self):
        fcntl.ioctl(self.fd,0x2401,0)

    def counts(self):
        data=os.read(self.fd,32)
        if len(data)!=32:raise ValueError('short perf counter read')
        count,enabled,running,lost=struct.unpack('<QQQQ',data)
        return {'event':self.event,'cpu':self.cpu,'count':count,'samples':self.samples,
                'enabled_ns':enabled,'running_ns':running,'lost':lost,
                'lost_records':self.lost_records,'unexpected_records':self.unexpected}

    def close(self):
        if self.memory is not None:self.memory.close();self.memory=None
        if self.fd is not None:os.close(self.fd);self.fd=None


def clock_pair():
    before=time.monotonic_ns()
    wall=time.time_ns()
    after=time.monotonic_ns()
    return {'before_ns':before,'wall_ns':wall,'after_ns':after}


class Recorder:
    def __init__(self,caps,pages=64,background=True):
        # Importing/parsing tests is safe locally; opening perf requires this
        # independently rechecked VM guard, even when invoked directly.
        from guest import guard
        guard()
        if caps['machine']!='x86_64' or caps['cpus']!=[0,1]:
            raise RuntimeError('only the declared two-CPU guest is supported')
        self.rings,self.rows,self.errors=[],[],[]
        self.stop=threading.Event()
        self.selector=selectors.DefaultSelector()
        self.start_clock=clock_pair()
        self.reader_cpu_ns=0
        self.background=background
        try:
            for event in FIELDS:
                for cpu in caps['cpus']:
                    r=Ring(event,caps['formats'][event],cpu,pages=pages)
                    self.rings.append(r)
                    self.selector.register(r.fd,selectors.EVENT_READ)
        except BaseException:
            for r in self.rings:r.close()
            self.selector.close()
            raise
        self.thread=threading.Thread(target=self.collect)
        if background:self.thread.start()

    def drain(self):
        for r in self.rings:
            self.rows.extend(r.drain())
            if len(self.rows)>30000:
                raise RuntimeError('fixed diagnostic event budget exceeded')

    def collect(self):
        began=time.thread_time_ns()
        try:
            while not self.stop.is_set():
                self.selector.select(0.05)
                self.drain()
        except BaseException as error:
            self.errors.append(type(error).__name__+': '+str(error))
        finally:
            self.reader_cpu_ns=time.thread_time_ns()-began

    def finish(self):
        try:
            for r in self.rings:r.disable()
            self.stop.set()
            if self.background:self.thread.join(2)
            if self.thread.is_alive():raise RuntimeError('reader did not stop')
            self.drain()
            counts=[r.counts() for r in self.rings]
            complete=not self.errors and all(c['count']==c['samples'] and c['lost']==0 and
                c['lost_records']==0 and not c['unexpected_records'] and c['enabled_ns']==c['running_ns'] for c in counts)
            return {'events':self.rows,'counts':counts,'errors':self.errors,'complete':complete,
                    'reader_cpu_ns':self.reader_cpu_ns,'start_clock':self.start_clock,'end_clock':clock_pair()}
        finally:
            self.selector.close()
            for r in self.rings:r.close()
