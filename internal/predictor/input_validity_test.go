// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package predictor

import (
	"context"
	"errors"
	"testing"
	"time"
)

func inputModels() []Predictor {
	handoff := NewHandoffRule(time.Second, DefaultHandoffRuleParams)
	return []Predictor{NewPersistence(time.Second), NewAR2RTT(time.Second, 30), handoff,
		NewNATRule(time.Second, handoff, DefaultNATRuleParams)}
}

func TestExplicitInputValiditySurvivesEveryModel(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	for _, model := range inputModels() {
		t.Run(model.Name(), func(t *testing.T) {
			obs := Observation{Now: now, RTTHistory: []Sample{{At: now.Add(-time.Second), Value: 0}, {At: now, Value: 0}},
				LossHistory: []Sample{{At: now, Value: 99}}, BandwidthLast: Sample{At: now, Value: 100},
				Cell: CellInfo{CellID: "fixture", RSRP: -115}, RecentHandoffs: []time.Time{now},
				Known: &[SignalCount]bool{true, false, false, false, false}}
			f, err := model.Predict(context.Background(), obs)
			if err != nil {
				t.Fatal(err)
			}
			if f.Q[SignalRTT] != 0 || f.Health[SignalRTT] <= 0 {
				t.Fatalf("valid zero lost: %+v", f)
			}
			for i := 1; i < SignalCount; i++ {
				if f.Q[i] != 0 || f.QLo[i] != 0 || f.QHi[i] != 0 || f.Health[i] != 0 {
					t.Fatalf("unavailable signal %d acquired value/health: %+v", i, f)
				}
			}
			obs.Known[SignalLoss] = true
			obs.LossHistory = nil
			if _, err := model.Predict(context.Background(), obs); !errors.Is(err, ErrObservationInvalid) {
				t.Fatalf("empty declared loss accepted alongside valid RTT: %v", err)
			}
			obs.Known = &[SignalCount]bool{}
			if _, err := model.Predict(context.Background(), obs); !errors.Is(err, ErrObservationInvalid) {
				t.Fatalf("all unavailable accepted: %v", err)
			}
			obs.Known[SignalLoss] = true
			obs.LossHistory = nil
			if _, err := model.Predict(context.Background(), obs); !errors.Is(err, ErrObservationInvalid) {
				t.Fatalf("declared but absent measurement accepted: %v", err)
			}
		})
	}
}

func TestNATIgnoresUnavailableHandoff(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	obs := Observation{Now: now, RTTHistory: []Sample{{At: now, Value: 10}},
		Cell: CellInfo{CellID: "fixture", RSRP: -140}, RecentHandoffs: []time.Time{now},
		Known: &[SignalCount]bool{true, false, false, false, true}}
	m := NewNATRule(time.Second, NewHandoffRule(time.Second, DefaultHandoffRuleParams), DefaultNATRuleParams)
	f, err := m.Predict(context.Background(), obs)
	if err != nil {
		t.Fatal(err)
	}
	if f.Q[SignalNATStability] != 1 || f.Health[SignalHandoffProb] != 0 {
		t.Fatalf("unobserved handoff influenced NAT: %+v", f)
	}
}

func TestPartialMeasuredNetworkDimensions(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	for _, m := range inputModels() {
		for _, signal := range []int{SignalRTT, SignalLoss} {
			obs := Observation{Now: now, Known: new([SignalCount]bool)}
			obs.Known[signal] = true
			if signal == SignalRTT {
				obs.RTTHistory = []Sample{{At: now, Value: 0}}
			} else {
				obs.LossHistory = []Sample{{At: now, Value: 0}}
			}
			f, err := m.Predict(context.Background(), obs)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < SignalCount; i++ {
				if (f.Health[i] > 0) != (i == signal) {
					t.Fatalf("%s signal %d: %+v", m.Name(), signal, f)
				}
			}
		}
	}
}
