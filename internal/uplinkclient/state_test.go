// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package uplinkclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"
)

func TestSharedConsumerContract(t *testing.T) {
	b, err := os.ReadFile("testdata/consumer.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Domain string         `json:"clock_domain"`
		Now    string         `json:"now"`
		Base   map[string]any `json:"base"`
		Cases  []struct {
			Name  string
			Steps []map[string]any
		} `json:"cases"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			now, _ := strconv.ParseUint(fixture.Now, 10, 64)
			fail := false
			s, err := newState("app", func() (string, uint64, error) {
				if fail {
					return "", 0, errors.New("clock")
				}
				return fixture.Domain, now, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			epoch := s.Begin()
			for i, step := range tc.Steps {
				switch step["op"] {
				case "clock":
					if v, ok := step["now"].(string); ok {
						now, _ = strconv.ParseUint(v, 10, 64)
					}
					if v, ok := step["fail"].(bool); ok {
						fail = v
					}
				case "begin":
					epoch = s.Begin()
				case "disconnect":
					s.Disconnect(epoch)
				case "receive":
					raw := contractFrame(t, fixture.Base, step)
					e := epoch
					if v, ok := step["epoch"].(json.Number); ok {
						e, _ = strconv.ParseUint(string(v), 10, 64)
					}
					err := s.Accept(e, raw)
					if (err != nil) != (step["error"] == true) {
						t.Fatalf("step %d: acceptance error=%v", i, err)
					}
				}
				if expected, ok := step["expect"].(map[string]any); ok {
					b, _ := json.Marshal(s.Current())
					var got map[string]any
					json.Unmarshal(b, &got)
					for key, want := range expected {
						if got[key] != want {
							t.Fatalf("step %d %s: got %v want %v", i, key, got[key], want)
						}
					}
				}
			}
		})
	}
}

func contractFrame(t *testing.T, base, step map[string]any) []byte {
	t.Helper()
	if raw, ok := step["raw"].(string); ok {
		return []byte(raw)
	}
	b, _ := json.Marshal(base)
	var frame map[string]any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	d.Decode(&frame)
	for key, v := range step["patch"].(map[string]any) {
		if key == "snapshot" {
			for k, x := range v.(map[string]any) {
				if x == nil {
					delete(frame[key].(map[string]any), k)
				} else {
					frame[key].(map[string]any)[k] = x
				}
			}
		} else {
			frame[key] = v
		}
	}
	b, _ = json.Marshal(frame)
	return b
}
