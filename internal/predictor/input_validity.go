// Copyright 2026 Jonghyeok Kang
// SPDX-License-Identifier: Apache-2.0
package predictor

func (o Observation) known(signal int) bool {
	return o.Known == nil || o.Known[signal]
}

// Applied after model-specific overrides as well as by the baseline: composing
// models must never turn an unavailable input dimension back into a forecast.
func maskUnavailable(o Observation, f Forecast) Forecast {
	for i := 0; i < SignalCount; i++ {
		if !o.known(i) {
			f.Q[i], f.QLo[i], f.QHi[i], f.Health[i] = 0, 0, 0, 0
		}
	}
	return f
}
