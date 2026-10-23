import copy
import unittest
from correlate import correlate, require_complete


def sample(case='connected',pid=10,sk=99,base=0):
    def e(t,event,**kw):return dict(pid=pid,tid=11,cpu=0,at_ns=base+t,event=event,**kw)
    def s(t,old,new,**kw):
        r=e(t,'sock/inet_sock_set_state',skaddr=sk,oldstate=old,newstate=new,
            sport=0 if new==2 else 12345,dport=8080,saddr='127.0.0.1',daddr='127.0.0.1',family=2,protocol=6)
        r.update(kw);return r
    events=[e(100,'syscalls/sys_enter_connect',fd=5),s(110,7,2),e(120,'syscalls/sys_exit_connect',ret=-115)]
    if case=='connected':
        events += [s(130,2,1,pid=0,tid=0,cpu=1),e(140,'syscalls/sys_enter_getpeername',fd=5),
                   e(150,'syscalls/sys_exit_getpeername',ret=0),s(160,1,7,pid=77,tid=78,cpu=1)]
    else:events += [s(160,2,7,tid=12,cpu=1)]
    rows=[{'pid':pid,'index':0,'result':case,'target':'127.0.0.1:8080'}]
    return events,rows


class CorrelationTests(unittest.TestCase):
    def test_async_completion_and_thread_migration(self):
        events,rows=sample()
        f=correlate(events,rows)[0]
        self.assertEqual(f['source'],'127.0.0.1:12345')
        self.assertEqual(f['established_ns'],130)
        self.assertTrue(f['state_outside_owner'])

    def test_receive_order_does_not_replace_kernel_timestamps(self):
        events,rows=sample()
        self.assertEqual(correlate(events[::-1],rows),correlate(events,rows))

    def test_refusal_and_timeout_endpoint(self):
        for case in ('refused','timeout'):
            events,rows=sample(case)
            f=correlate(events,rows)[0]
            self.assertIsNone(f['established_ns'])
            self.assertEqual(f['source'],'127.0.0.1:12345')

    def test_fd_and_socket_address_reuse_has_distinct_generations(self):
        a,rows=sample();b,_=sample(base=200)
        rows += [dict(rows[0],index=1)]
        flows=correlate(a+b,rows)
        self.assertEqual([f['connect_enter_ns'] for f in flows],[100,300])
        self.assertNotEqual(flows[0]['id'],flows[1]['id'])

    def test_missing_or_duplicate_edges_rejected(self):
        events,rows=sample()
        for changed in (events[1:],events[:-1],events[:2]+events[3:],events+[events[0]]):
            with self.subTest(changed=len(changed)),self.assertRaises(ValueError):correlate(changed,rows)

    def test_wrong_target_and_missing_source_port_rejected(self):
        events,rows=sample()
        with self.assertRaises(ValueError):correlate(events,[dict(rows[0],target='127.0.0.1:8081')])
        for e in events:
            if 'sport' in e:e['sport']=0
        with self.assertRaises(ValueError):correlate(events,rows)

    def test_incomplete_recording_never_becomes_no_network_loss(self):
        row={'count':3,'samples':3,'lost':0,'lost_records':0,'enabled_ns':50,'running_ns':50,'unexpected_records':[]}
        good={'complete':True,'errors':[],'counts':[row]}
        require_complete(good)
        for key,value in [('lost',1),('lost_records',1),('samples',2),('unexpected_records',[5]),('running_ns',40)]:
            bad=copy.deepcopy(good);bad['counts'][0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):require_complete(bad)


if __name__=='__main__':unittest.main()
