//go:build integration

package integration

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTraceDistinguishesResponseWait(t *testing.T) {
	for _, stall := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "server_wait"}[stall], func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if stall {
					<-r.Context().Done()
					return
				}
				w.WriteHeader(200)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			ctx, trace := tracedProbe(ctx, time.Now())
			req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
			resp, err := server.Client().Do(req)
			if resp != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			snapshot := trace.snapshot()
			if snapshot.TLSDoneMS == nil || snapshot.WroteMS == nil || snapshot.ConnectDoneMS == nil || snapshot.Attempts != 1 {
				t.Fatalf("missing milestones: %+v", snapshot)
			}
			if stall {
				if err == nil || snapshot.FirstByteMS != nil {
					t.Fatal("server stall misclassified")
				}
			} else if err != nil || snapshot.FirstByteMS == nil {
				t.Fatal("success trace missing", err)
			}
		})
	}
}

func TestTelemetryFilterExcludesUnrelatedLabels(t *testing.T) {
	input := "vpnctl_pki_authority_seconds_bucket{stage=\"persist\",le=\"1\"} 2\n" +
		"vpnctl_pki_authority_seconds_secret{key=\"private-marker\"} 1\n" +
		"vpnctl_system_command_seconds_count{command=\"wg\",result=\"success\"} 1\n" +
		"vpnctl_controller_stage_seconds_sum{operation=\"identity\",stage=\"registry_wait\"} 0.01\n" +
		"vpnctl_controller_stage_seconds_secret{key=\"private-marker\"} 1\n" +
		"vpnctl_probe_total{peer=\"unrelated-marker\"} 5\n" +
		"process_cpu_seconds_total 2\n"
	got := diagnosticMetrics(input)
	if strings.Contains(got, "marker") || !strings.Contains(got, "process_cpu_seconds_total 2") || strings.Count(got, "\n") != 4 {
		t.Fatalf("incorrect diagnostic filtering: %s", got)
	}
}
