// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package stats holds the few statistics more than one measurement here
// reports, so every document that states an interval states the same one.
//
// It is a leaf: it imports nothing from this module, so a package that
// needs an interval takes on no other package's concerns to get it. Three
// private copies of the Wilson interval existed before this one — the
// analyst benchmark's, the wind tunnel's and the detection tuner's — and
// two of them differed in whether they took a count or a proportion, which
// is the kind of difference that turns into two numbers for one sample.
package stats

import "math"

// z95 is the two-sided 95% standard normal quantile.
const z95 = 1.959963984540054

// Wilson is the 95% Wilson score interval for k successes in n trials.
//
// Wilson rather than the normal approximation, which gives an interval of
// zero width at 0 and at 100% — exactly where a small sample most needs
// one — and walks outside [0, 1] near them, reporting a rate no honest
// count can have. No trials is no evidence, so the interval is all of
// [0, 1] rather than a point.
//
// Counts rather than a proportion, so the caller cannot pass a rate
// computed over a different denominator from the n it passes beside it.
func Wilson(k, n int) (low, high float64) {
	if n <= 0 {
		return 0, 1
	}
	k = min(max(k, 0), n)
	p := float64(k) / float64(n)
	nn := float64(n)
	z2 := z95 * z95
	denom := 1 + z2/nn
	centre := (p + z2/(2*nn)) / denom
	half := (z95 / denom) * math.Sqrt(p*(1-p)/nn+z2/(4*nn*nn))
	return math.Max(0, centre-half), math.Min(1, centre+half)
}
