// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"vpnctl/internal/uplinkclient"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := runExample(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "uplink example failed")
		os.Exit(1)
	}
}
func runExample(parent context.Context, args []string, output io.Writer) error {
	f := flag.NewFlagSet("uplink-example", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var cfg probeConfig
	f.StringVar(&cfg.Address, "address", "", "TLS echo host:port")
	f.StringVar(&cfg.ServerName, "server-name", "", "expected TLS server identity")
	ca := f.String("ca", "", "trusted server CA PEM")
	directory := f.String("runtime", "", "private producer runtime directory")
	uid := f.Uint64("server-uid", 0, "expected producer UID")
	target := f.String("target", "app", "fixed target ID")
	duration := f.Duration("duration", time.Minute, "bounded measurement duration (1s–10m)")
	progress := f.String("progress", "", "optional atomically replaced progress JSON")
	f.DurationVar(&cfg.ConnectTimeout, "connect-timeout", time.Second, "TCP+TLS deadline")
	f.DurationVar(&cfg.IOTimeout, "io-timeout", time.Second, "per-write and per-read deadline")
	f.DurationVar(&cfg.Interval, "interval", 250*time.Millisecond, "healthy echo interval")
	if f.Parse(args) != nil || f.NArg() != 0 || *uid > 1<<32-1 || *directory == "" || *duration < time.Second || *duration > 10*time.Minute {
		return errors.New("invalid arguments")
	}
	pem, err := os.ReadFile(*ca)
	if err != nil {
		return errors.New("CA unavailable")
	}
	cfg.Roots = x509.NewCertPool()
	if !cfg.Roots.AppendCertsFromPEM(pem) {
		return errors.New("invalid CA")
	}
	state, err := uplinkclient.NewState(*target)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, *duration)
	defer cancel()
	stats := newProbeStats()
	var before syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &before)
	report := func(events bool) map[string]any {
		var payload probeSnapshot
		if events {
			payload = stats.snapshot()
		} else {
			stats.mu.Lock()
			payload = stats.value
			payload.Events = nil
			stats.mu.Unlock()
		}
		var usage syscall.Rusage
		syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
		now := bootNS()
		var responseAge *string
		if payload.LastCorrectNS > 0 && now >= payload.LastCorrectNS {
			age := strconv.FormatUint(now-payload.LastCorrectNS, 10)
			responseAge = &age
		}
		return map[string]any{"schema_version": 1, "language": "go", "target_id": *target, "snapshot_boot_ns": strconv.FormatUint(now, 10),
			"api": state.Current(), "api_records": state.AcceptedFrames(), "payload": payload,
			"no_correct_response": payload.Correct == 0, "response_age_ns": responseAge,
			"cpu_user_ns": usage.Utime.Nano() - before.Utime.Nano(), "cpu_system_ns": usage.Stime.Nano() - before.Stime.Nano(), "process_peak_rss_kib": usage.Maxrss,
			"publication_boot_ns": nil, "receipt_boot_ns": nil}
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = uplinkclient.Watch(ctx, uplinkclient.Options{Directory: *directory, ServerUID: uint32(*uid)}, state)
	}()
	progressError := make(chan error, 1)
	if *progress != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := writeProgress(*progress, report(false)); err != nil {
						progressError <- err
						cancel()
						return
					}
				}
			}
		}()
	}
	err = runProbe(ctx, cfg, stats)
	cancel()
	wg.Wait()
	select {
	case e := <-progressError:
		return e
	default:
	}
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return json.NewEncoder(output).Encode(report(true))
}
func writeProgress(path string, value any) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".uplink-progress-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = json.NewEncoder(f).Encode(value); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
