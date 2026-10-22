import collections,json,os,signal,socket,struct,time
from pathlib import Path

def header(data):
    if len(data)<40 or data[0]>>4!=4 or data[9]!=6:return None
    offset=(data[0]&15)*4
    total=struct.unpack_from('!H',data,2)[0]
    if offset<20 or len(data)<offset+20 or total<offset+20:return None
    if struct.unpack_from('!H',data,6)[0]&0x3fff:return None
    a,b,seq,ack=struct.unpack_from('!HHII',data,offset)
    tcp_len=(data[offset+12]>>4)*4
    if 9192 not in (a,b) or tcp_len<20 or total<offset+tcp_len:return None
    return {'src':socket.inet_ntoa(data[12:16]),'dst':socket.inet_ntoa(data[16:20]),'sport':a,'dport':b,'seq':seq,'ack':ack,'flags':data[offset+13],'length':total,'ip_id':struct.unpack_from('!H',data,4)[0]}

def main():
    assert 'vpnctl_vm_test' in Path('/proc/cmdline').read_text()
    records=collections.deque(maxlen=1024);state={'stop':False};seen=0
    signal.signal(signal.SIGTERM,lambda *_:state.update(stop=True))
    s=socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(0x0800));s.setsockopt(socket.SOL_SOCKET,35,1);s.settimeout(.1)
    print(json.dumps({'event':'ready','wall_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns()}),flush=True)
    while not state['stop']:
        try:data,anc,flags,address=s.recvmsg(128,128)
        except socket.timeout:continue
        h=header(data)
        if h is None:continue
        stamp=next((struct.unpack('ll',v) for level,kind,v in anc if level==socket.SOL_SOCKET and kind==35),None)
        h.update(interface=address[0],direction=address[2],kernel_wall_ns=stamp[0]*10**9+stamp[1] if stamp else None,read_monotonic_ns=time.monotonic_ns())
        records.append(h);seen+=1
    raw=s.getsockopt(263,6,12);packets,drops=struct.unpack_from('II',raw)
    print(json.dumps({'event':'capture','records':list(records),'matched':seen,'overwritten':max(0,seen-len(records)),'socket_packets':packets,'socket_drops':drops,'wall_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns()}),flush=True)
    s.close()
if __name__=='__main__':main()
