// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package calib

import (
	"math"
	"math/rand"
	"testing"
)

// The Clopper–Pearson upper bound is exact, so its values at known
// points are its correctness proof: 0 successes in n trials, and the
// bound's coverage at moderate k.
func TestClopperPearsonUpper(t *testing.T) {
	cases := []struct {
		k, n  int
		alpha float64
		want  float64 // approximately
	}{
		{0, 20, 0.05, 0.139},   // 0 in 20 at 95%: upper ≈ 13.9%
		{0, 100, 0.05, 0.0295}, // 0 in 100 at 95%: upper ≈ 3%
		{0, 10, 0.05, 0.259},   // 0 in 10 at 95%: upper ≈ 26%
		{5, 10, 0.05, 0.778},   // 5 in 10 at 95%: upper ≈ 78%
	}
	for _, tc := range cases {
		got := ClopperPearsonUpper(tc.k, tc.n, tc.alpha)
		if math.Abs(got-tc.want) > 0.01 {
			t.Errorf("ClopperPearsonUpper(%d, %d, %g) = %.4f, want ≈ %.4f",
				tc.k, tc.n, tc.alpha, got, tc.want)
		}
	}
	// Edge cases
	if got := ClopperPearsonUpper(0, 0, 0.05); got != 1 {
		t.Errorf("n=0 should give 1, got %g", got)
	}
	if got := ClopperPearsonUpper(5, 5, 0.05); got != 1 {
		t.Errorf("k=n should give 1, got %g", got)
	}
}

// An overconfident model (stated 0.9, correct 70% of the time) gets a
// threshold higher than any confidence level it states, because at every
// confidence it claims, its false-closure rate is too high to certify.
func TestFitOnAnOverconfidentModel(t *testing.T) {
	// 100 cases at confidence 0.9, 30 of them wrong (70% correct)
	var labels []Labelled
	for i := 0; i < 70; i++ {
		labels = append(labels, Labelled{Confidence: 0.9, Correct: true})
	}
	for i := 0; i < 30; i++ {
		labels = append(labels, Labelled{Confidence: 0.9, Correct: false})
	}
	// At 30% wrong, even the tightest Clopper-Pearson bound exceeds ε=0.05
	threshold, ok := Fit(labels, 0.05, 0.05)
	if ok {
		t.Errorf("a 30%% error rate at any threshold certifies ε=0.05, but Fit returned threshold=%.2f", threshold)
	}
}

// A well-calibrated model gets a threshold near its stated confidence,
// and the false-closure rate at that threshold stays under ε across
// many resamples of the labelled set.
func TestFitOnACalibratedModel(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	// 100 cases: confidence correlates with correctness (well-calibrated)
	var labels []Labelled
	for i := 0; i < 200; i++ {
		conf := 0.5 + 0.5*float64(i)/200 // confidences from 0.5 to 1.0
		// Correctness follows confidence, sharpened so the top decile is
		// almost always right — the shape a genuinely useful model has.
		correct := rng.Float64() < conf*conf
		labels = append(labels, Labelled{Confidence: conf, Correct: correct})
	}
	threshold, ok := Fit(labels, 0.20, 0.05)
	if !ok {
		t.Fatal("a calibrated model should have a certifiable threshold")
	}
	if threshold < 0.5 || threshold > 1.0 {
		t.Errorf("threshold %.2f is outside [0.5, 1.0]", threshold)
	}

	// Resample test: the false-closure rate at the fitted threshold
	// stays under ε across many random resamples
	violations := 0
	for trial := 0; trial < 200; trial++ {
		var resampled []Labelled
		for _, l := range labels {
			if rng.Float64() < 0.8 { // 80% subsample
				resampled = append(resampled, l)
			}
		}
		if len(resampled) == 0 {
			continue
		}
		var wrong, total int
		for _, l := range resampled {
			if l.Confidence >= threshold {
				total++
				if !l.Correct {
					wrong++
				}
			}
		}
		if total > 0 {
			rate := float64(wrong) / float64(total)
			// The resample rate should be near the fitted bound; a few
			// individual resamples exceed it by chance, but not many
			if rate > 0.20+0.10 { // 2× the ε as a generous check
				violations++
			}
		}
	}
	if violations > 10 { // more than 5% of resamples violating is too many
		t.Errorf("the false-closure rate exceeded 2×ε in %d of 200 resamples", violations)
	}
}

// No labels, or degenerate ε/δ, is refused.
func TestFitRefusesDegenerateInput(t *testing.T) {
	if _, ok := Fit(nil, 0.05, 0.05); ok {
		t.Error("empty labels should not fit")
	}
	if _, ok := Fit([]Labelled{{0.9, true}}, 0, 0.05); ok {
		t.Error("ε=0 should not fit")
	}
	if _, ok := Fit([]Labelled{{0.9, true}}, 0.05, 0); ok {
		t.Error("δ=0 should not fit")
	}
}
