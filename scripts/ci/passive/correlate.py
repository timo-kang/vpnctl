"""Conservative reconstruction of the declared single-threaded-Dial fixtures.

Each Go process can move OS threads and reuse FDs, but issues its Dials serially.
Different processes run concurrently. General concurrent Dials in one process
need an independent call ID and are intentionally not claimed by this fixture.
"""
import datetime
import json



def require_complete(recording):
    if not recording['complete'] or recording['errors'] or not recording['counts']:
        raise ValueError('incomplete recording')
    for c in recording['counts']:
        if (c['count']!=c['samples'] or c['lost'] or c['lost_records'] or
            c['unexpected_records'] or c['enabled_ns']!=c['running_ns']):
            raise ValueError('loss, throttling or incomplete CPU coverage')


def correlate(events,rows, verify_outcome=True):
    pids={r['pid'] for r in rows}
    pending,syscalls,sockets,fds={},{},{},{}
    flows=[]
    seen=set()
    for e in sorted(events,key=lambda e:e['at_ns']):
        signature=json.dumps(e,sort_keys=True)
        if signature in seen:raise ValueError('duplicate event')
        seen.add(signature)
        own=e['pid'] in pids
        thread=(e['pid'],e['tid'])
        kind=e['event']
        if kind=='syscalls/sys_enter_connect' and own:
            if thread in pending:raise ValueError('overlapping connect on one thread')
            f={'id':f'{e["pid"]}/{e["fd"]}/{e["at_ns"]}', 'pid':e['pid'],'fd':e['fd'],
               'enter_tid':e['tid'],'connect_enter_ns':e['at_ns'], 'states':[],'calls':[],
               'established_ns':None,'closed_ns':None,'state_outside_owner':False,'state_thread_changed':False}
            pending[thread]=f
            fds[e['pid'],e['fd']]=f
            flows.append(f)
        elif kind=='syscalls/sys_exit_connect' and own:
            if thread not in pending:raise ValueError('connect exit without entry')
            f=pending.pop(thread)
            f['connect_exit_ns'],f['connect_return']=e['at_ns'],e['ret']
        elif kind=='sock/inet_sock_set_state':
            pointer=e['skaddr']
            if e['newstate']==2 and own:
                if thread not in pending or pointer in sockets:
                    raise ValueError('unattributed or overlapping socket lifetime')
                f=pending[thread]
                if 'socket_address' in f:raise ValueError('multiple sockets in one connect')
                f['socket_address']=pointer
                sockets[pointer]=f
            f=sockets.get(pointer)
            if f is None:continue  # Server/other socket, never inferred by time.
            if e['family']!=2 or e['protocol']!=6:raise ValueError('unexpected socket family')
            if f['states'] and f['states'][-1]['newstate']!=e['oldstate']:
                raise ValueError('state transition gap')
            f['states'].append(e)
            f['state_outside_owner'] |= e['pid']!=f['pid']
            f['state_thread_changed'] |= e['tid']!=f['enter_tid']
            if e['newstate']==1:
                if f['established_ns'] is not None:raise ValueError('repeated established transition')
                f['established_ns']=e['at_ns']
            if e['newstate'] in (6,7):
                f['closed_ns']=e['at_ns']
                del sockets[pointer]
        elif kind.startswith('syscalls/sys_enter_') and own:
            call=kind.removeprefix('syscalls/sys_enter_')
            key=thread+(call,)
            if key in syscalls:raise ValueError('syscall overlap')
            f=fds.get((e['pid'],e['fd']))
            if f is None:raise ValueError('syscall on untracked FD')
            syscalls[key]=(f,e)
        elif kind.startswith('syscalls/sys_exit_') and own:
            call=kind.removeprefix('syscalls/sys_exit_')
            key=thread+(call,)
            if key not in syscalls:raise ValueError('syscall exit without entry')
            f,began=syscalls.pop(key)
            f['calls'].append({'call':call,'tid':e['tid'],'entered_ns':began['at_ns'],'exited_ns':e['at_ns'],
                               'ret':e['ret'],'level':began.get('level'),'optname':began.get('optname')})
    if pending or syscalls or sockets:raise ValueError('unfinished lifecycle or syscall')
    if len(flows)!=len(rows):raise ValueError('probe and connect counts differ')
    for pid in pids:
        expected=sorted((r for r in rows if r['pid']==pid),key=lambda r:r['index'])
        actual=[f for f in flows if f['pid']==pid]
        if len(actual)!=len(expected) or [r['index'] for r in expected]!=list(range(len(expected))):
            raise ValueError('process-call identity differs')
        for f,r in zip(actual,expected):
            f['index'],f['result'],f['target']=r['index'],r['result'],r['target']
            if not f['states'] or f['states'][0]['newstate']!=2 or f['closed_ns'] is None or 'connect_exit_ns' not in f:
                raise ValueError('missing socket lifecycle')
            if not f['connect_enter_ns']<=f['states'][0]['at_ns']<=f['connect_exit_ns']:
                raise ValueError('state initiation outside connect syscall')
            if verify_outcome and (r['result']=='connected')!=(f['established_ns'] is not None):
                raise ValueError('kernel state contradicts fixture outcome')
            endpoints=set()
            for s in f['states']:
                if f'{s["daddr"]}:{s["dport"]}'!=r['target']:
                    raise ValueError('target mismatch')
                if s['sport']:endpoints.add(f'{s["saddr"]}:{s["sport"]}')
            if len(endpoints)!=1:raise ValueError('source endpoint missing or ambiguous')
            f['source']=endpoints.pop()
    return flows


def stamp_ns(value):
    whole,_,fraction=value.removesuffix('Z').partition('.')
    at=datetime.datetime.fromisoformat(whole).replace(tzinfo=datetime.timezone.utc)
    return int(at.timestamp())*10**9+int((fraction+'000000000')[:9])
