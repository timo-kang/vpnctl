// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// A real TLS peer stays idle beyond the unchanged server read deadline. This
// distinguishes server policy from VPN/API failure without host network changes.
func TestPythonEchoIdleCloseEvidence(t *testing.T) {
	seed := httptest.NewTLSServer(nil)
	key, err := x509.MarshalPKCS8PrivateKey(seed.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	der := seed.Certificate().Raw
	seed.Close()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	module, _ := filepath.Abs("../python")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-B", "-c", `import sys,threading,queue,ssl,socket,time,json,contextlib,io
sys.path.insert(0,sys.argv[1])
from echo_server import serve
ready=queue.Queue(maxsize=1);stop=threading.Event();out=io.StringIO()
with contextlib.redirect_stdout(out):
    worker=threading.Thread(target=serve,args=(('127.0.0.1',0),sys.argv[2],sys.argv[3],stop),kwargs={'ready':ready.put,'session_seconds':60,'max_requests':512,'diagnostics':True})
    worker.start()
    try:
        address=ready.get(timeout=2)
        tls=ssl.create_default_context(cafile=sys.argv[2])
        with tls.wrap_socket(socket.create_connection(address,timeout=1),server_hostname='example.com') as conn:
            line=b'VPNCTL-ECHO/1 1 0123456789abcdef0123456789abcdef\n'
            conn.sendall(line);assert conn.recv(256)==line
            conn.settimeout(4)
            assert conn.recv(1)==b''
        until=time.monotonic()+1
        while not out.getvalue() and time.monotonic()<until:time.sleep(.01)
    finally:
        stop.set();worker.join(3)
assert not worker.is_alive()
rows=[json.loads(x) for x in out.getvalue().splitlines()]
assert len(rows)==1,rows
row=rows[0]
assert row['event']=='connection_closed' and row['reason']=='timeout' and row['stage']=='read',row
assert row['requests']==1 and row['connection']==1,row
assert 0<int(row['handler_started_boot_ns'])<=int(row['last_read_boot_ns'])<=int(row['last_write_boot_ns'])<int(row['closed_boot_ns']),row
assert int(row['closed_boot_ns'])-int(row['last_write_boot_ns'])>=1_900_000_000,row
assert '0123456789abcdef' not in out.getvalue() and sys.argv[3] not in out.getvalue()
`, module, certPath, keyPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatal("idle close diagnosis failed", err, string(output))
	}
}
