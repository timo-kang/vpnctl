//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Both modes retain probe identity in memory, after the existing measurement.
// No deadline, retry, socket option or payload behavior changes.
func privatePayload(t *testing.T, f *m3AuthorityFixture, target string, report map[string]any) m3Probe {
	t.Helper()
	p := applicationPayload(t, f, target)
	rows, _ := report["private_payload_probes"].([]map[string]any)
	if len(rows) >= 4096 {
		t.Fatal("private probe evidence budget exceeded")
	}
	report["private_payload_probes"] = append(rows, map[string]any{"target": target, "probe": p})
	return p
}

func privatePassiveTrace(t *testing.T, f *m3AuthorityFixture, report map[string]any) {
	t.Helper()
	mode := os.Getenv("VPNCTL_PRIVATE_TRACE")
	report["private_trace_requested"] = mode == "1"
	if mode != "1" {
		return
	}
	requireIsolatedGuest(t)
	path := filepath.Join(f.results, "private-passive.json")
	log, err := os.Create(filepath.Join(f.results, "private-passive.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "-u", "/opt/vpnctl-diag/guest.py", path)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-done:
			if err != nil {
				report["private_trace_process_error"] = err.Error()
			}
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			report["private_trace_process_error"] = "collector did not finish"
		}
		_ = log.Close()
		b, err := os.ReadFile(path)
		meta, decodeErr := privateTraceSummary(b)
		if err != nil || decodeErr != nil {
			report["private_trace_evidence_error"] = "collector result unavailable"
			return
		}
		report["private_trace_summary"] = meta
	})
	eventually(t, 5*time.Second, "private passive recorder ready", func() error {
		b, err := os.ReadFile(filepath.Join(f.results, "private-passive.ready"))
		if err != nil || string(b) != "ready\n" {
			return fmt.Errorf("recorder not ready")
		}
		return nil
	})
}

// Preserve integer nanoseconds when carrying metadata through a generic report.
func privateTraceSummary(b []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	var meta map[string]any
	if err := decoder.Decode(&meta); err != nil {
		return nil, err
	}
	if meta == nil {
		return nil, fmt.Errorf("missing collector metadata")
	}
	if events, ok := meta["events"].([]any); ok {
		meta["retained_events"] = len(events)
	}
	delete(meta, "events")
	return meta, nil
}
