//go:build integration

package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func privatePacketTrace(t *testing.T, f *m3AuthorityFixture, report map[string]any) {
	if os.Getenv("VPNCTL_PRIVATE_TRACE") != "1" {
		return
	}
	requireIsolatedGuest(t)
	roles := []string{f.robot, f.recipients[0].ns, f.recipients[1].ns, f.target}
	logs := map[string]string{}
	report["private_packet_trace"] = logs
	for i, ns := range roles {
		role := fmt.Sprint(i)
		path := filepath.Join(f.results, "private-packet-"+role+".jsonl")
		p := startNetworkProcess(t, ns, path, nil, "python3", "-u", "-c", "import collections,json,os,signal,socket,struct,time\nfrom pathlib import Path\n\ndef header(data):\n    if len(data)<40 or data[0]>>4!=4 or data[9]!=6:return None\n    offset=(data[0]&15)*4\n    total=struct.unpack_from('!H',data,2)[0]\n    if offset<20 or len(data)<offset+20 or total<offset+20:return None\n    if struct.unpack_from('!H',data,6)[0]&0x3fff:return None\n    a,b,seq,ack=struct.unpack_from('!HHII',data,offset)\n    tcp_len=(data[offset+12]>>4)*4\n    if 9192 not in (a,b) or tcp_len<20 or total<offset+tcp_len:return None\n    return {'src':socket.inet_ntoa(data[12:16]),'dst':socket.inet_ntoa(data[16:20]),'sport':a,'dport':b,'seq':seq,'ack':ack,'flags':data[offset+13],'length':total,'ip_id':struct.unpack_from('!H',data,4)[0]}\n\ndef main():\n    assert 'vpnctl_vm_test' in Path('/proc/cmdline').read_text()\n    records=collections.deque(maxlen=1024);state={'stop':False};seen=0\n    signal.signal(signal.SIGTERM,lambda *_:state.update(stop=True))\n    s=socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(0x0800));s.setsockopt(socket.SOL_SOCKET,35,1);s.settimeout(.1)\n    print(json.dumps({'event':'ready','wall_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns()}),flush=True)\n    while not state['stop']:\n        try:data,anc,flags,address=s.recvmsg(128,128)\n        except socket.timeout:continue\n        h=header(data)\n        if h is None:continue\n        stamp=next((struct.unpack('ll',v) for level,kind,v in anc if level==socket.SOL_SOCKET and kind==35),None)\n        h.update(interface=address[0],direction=address[2],kernel_wall_ns=stamp[0]*10**9+stamp[1] if stamp else None,read_monotonic_ns=time.monotonic_ns())\n        records.append(h);seen+=1\n    raw=s.getsockopt(263,6,12);packets,drops=struct.unpack_from('II',raw)\n    print(json.dumps({'event':'capture','records':list(records),'matched':seen,'overwritten':max(0,seen-len(records)),'socket_packets':packets,'socket_drops':drops,'wall_ns':time.time_ns(),'monotonic_ns':time.monotonic_ns()}),flush=True)\n    s.close()\nif __name__=='__main__':main()\n")
		t.Cleanup(func() {
			_ = p.cmd.Process.Signal(syscall.SIGTERM)
			p.finishWithin(t, 2*time.Second)
			b, err := os.ReadFile(path)
			if err != nil {
				logs[role] = "unavailable"
			} else {
				logs[role] = string(b)
			}
		})
		eventually(t, 5*time.Second, "packet observer ready", func() error {
			b, _ := os.ReadFile(path)
			if strings.Contains(string(b), `"event": "ready"`) {
				return nil
			}
			return fmt.Errorf("not ready")
		})
	}
}
