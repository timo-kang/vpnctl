//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnctl/internal/pki"
)

type telemetrySample struct {
	At          time.Time         `json:"at"`
	Phase       string            `json:"phase"`
	Resources   map[string]string `json:"resources,omitempty"`
	Unavailable []string          `json:"unavailable,omitempty"`
	Metrics     string            `json:"controller_metrics,omitempty"`
	Error       string            `json:"scrape_error,omitempty"`
}

func readResources() (map[string]string, []string) {
	values := map[string]string{"go_version": runtime.Version(), "cpu_count": fmt.Sprint(runtime.NumCPU()), "gomaxprocs": fmt.Sprint(runtime.GOMAXPROCS(0)), "race": "false"}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "-race" {
				values["race"] = setting.Value
			}
		}
	}
	var unavailable []string
	for _, name := range []string{"cpu.max", "cpu.stat", "cpu.pressure", "memory.current", "memory.max", "io.pressure"} {
		data, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", name))
		if err != nil {
			unavailable = append(unavailable, name)
			continue
		}
		values[name] = strings.TrimSpace(string(data))
	}
	return values, unavailable
}

// Export only fixed diagnostic metric families. Node identity labels, generated
// credentials, process command lines and the environment are never included.
func diagnosticMetrics(text string) string {
	var out strings.Builder
	for _, line := range strings.Split(text, "\n") {
		name := strings.FieldsFunc(line, func(r rune) bool { return r == '{' || r == ' ' })
		if len(name) == 0 {
			continue
		}
		switch name[0] {
		case "vpnctl_admin_admission_total", "vpnctl_pki_authority_seconds_bucket", "vpnctl_pki_authority_seconds_sum", "vpnctl_pki_authority_seconds_count",
			"vpnctl_controller_stage_seconds_bucket", "vpnctl_controller_stage_seconds_sum", "vpnctl_controller_stage_seconds_count",
			"vpnctl_system_command_seconds_bucket", "vpnctl_system_command_seconds_sum", "vpnctl_system_command_seconds_count",
			"process_cpu_seconds_total", "process_resident_memory_bytes", "go_goroutines", "go_memstats_alloc_bytes":
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	return out.String()
}

// ip netns exec remounts /sys and can hide the container's cgroup mount. Read
// resources in the coordinator's mount namespace, while HTTP scraping runs in
// the controller netns. Both streams carry UTC timestamps and phase markers.
func startResourceSampler(t *testing.T, dir, phasePath string) func() {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(dir, "resources.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	stop, done := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var writeErr error
	go func() {
		defer close(done)
		defer file.Close()
		encoder := json.NewEncoder(file)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			phase, _ := os.ReadFile(phasePath)
			sample := telemetrySample{At: time.Now().UTC(), Phase: string(phase)}
			sample.Resources, sample.Unavailable = readResources()
			if writeErr = encoder.Encode(sample); writeErr != nil {
				return
			}
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
		}
	}()
	closeSampler := func() {
		once.Do(func() {
			close(stop)
			<-done
			if writeErr != nil {
				t.Error(writeErr)
			}
		})
	}
	t.Cleanup(closeSampler)
	return closeSampler
}

func collectTelemetry() error {
	file, err := os.OpenFile(os.Getenv("VPNCTL_TELEMETRY"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		phase, _ := os.ReadFile(os.Getenv("VPNCTL_PHASE"))
		if string(phase) == "done" {
			return nil
		}
		sample := telemetrySample{At: time.Now().UTC(), Phase: string(phase)}
		sample.Metrics, err = scrapeControllerMetrics()
		if err != nil {
			sample.Error = err.Error()
		}
		if err := encoder.Encode(sample); err != nil {
			return err
		}
		<-ticker.C
	}
}

func scrapeControllerMetrics() (string, error) {
	credentials, err := pki.LoadCredentials(os.Getenv("VPNCTL_PKI"))
	if err != nil {
		return "", err
	}
	cfg, err := credentials.TLSConfig()
	if err != nil {
		return "", err
	}
	transport := &http.Transport{TLSClientConfig: cfg}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://10.77.0.1:8443/prom/metrics", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metrics status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	return diagnosticMetrics(string(data)), nil
}
