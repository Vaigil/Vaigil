// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package calib fits a decision threshold from labelled verdicts so that
// the false-closure rate stays below a stated bound with stated confidence.
//
// The analyst's fixed 0.8 confidence gate is a guess about a property of
// the model that varies by model, by prompt template, and by the family of
// findings being triaged. What the gate is for — deciding when the model's
// answer is trustworthy enough to act on — is a calibration question, and
// calibration is measured, not guessed.
//
// # What "calibrated" means here
//
// Given a labelled set (verdicts the model gave on findings whose true
// answer a person decided and signed), fit the smallest threshold T such
// that the false-closure rate — the proportion of real findings the model
// closed as false-positive or benign among all it was confident enough to
// close — is below ε with confidence 1−δ. The Clopper–Pearson upper
// bound guarantees the confidence statement regardless of the sample size;
// a threshold fitted from 20 cases is honest about how wide its interval
// is, which is why the certificate names its sample size.
//
// # The certificate
//
// The threshold travels as a signed proof (internal/proof): an in-toto
// Statement in a DSSE envelope, dual-signed, with predicate
// calibration/v1. The certificate names the model, the prompt template it
// was fitted for (by digest), ε, δ, the sample size, the threshold, and an
// expiry — because calibration drifts when the model, the template or the
// finding mix changes, and a certificate that did not expire would be a
// claim about a future it cannot speak for.
package calib

import (
	"math"
	"sort"
)

// ClopperPearsonUpper returns the exact upper bound of the confidence
// interval for a binomial proportion: given k successes in n trials, the
// true rate is below the returned value with confidence 1−alpha.
//
// This is the Clopper–Pearson interval, the conservative one: it
// guarantees coverage at every sample size rather than approximately at
// large ones. The bound is the p for which P(X ≤ k | n, p) = alpha/2,
// found by binary search on the binomial CDF — exact enough for the
// decisions it serves (the search runs to the float64's precision).
func ClopperPearsonUpper(k, n int, alpha float64) float64 {
	if n <= 0 || k < 0 || k > n || alpha <= 0 || alpha >= 1 {
		return 1
	}
	if k == n {
		return 1
	}
	// Binary search for the p where the binomial CDF equals alpha/2.
	// The CDF is monotonically decreasing in p (higher p means fewer
	// successes expected below k), so the search is well-conditioned.
	// One-sided: the question is "is the true rate below this?" — only
	// the upper tail matters, so the target is alpha, not alpha/2.
	target := alpha
	lo, hi := 0.0, 1.0
	for i := 0; i < 200; i++ {
		mid := (lo + hi) / 2
		cdf := binomialCDF(k, n, mid)
		if cdf > target {
			lo = mid
		} else {
			hi = mid
		}
	}
	return hi
}

// binomialCDF is P(X ≤ k | n, p) for the binomial distribution: the
// probability of at most k successes in n independent trials at rate p.
func binomialCDF(k, n int, p float64) float64 {
	if p <= 0 {
		return 1
	}
	if p >= 1 {
		if k >= n {
			return 1
		}
		return 0
	}
	// Sum the probability mass from 0 to k. For the small k this
	// package is used with (false closures are few), the sum is short.
	// The log-space computation avoids underflow for large n.
	q := 1 - p
	sum := 0.0
	logQ := math.Log(q)
	for i := 0; i <= k; i++ {
		// C(n,i) * p^i * q^(n-i) computed in log space
		logPM := logChoose(n, i) + float64(i)*math.Log(p) + float64(n-i)*logQ
		sum += math.Exp(logPM)
	}
	return sum
}

// logChoose returns ln(C(n,k)) — the log of the binomial coefficient —
// using the log-gamma function, which Go's math library provides.
func logChoose(n, k int) float64 {
	lgN, _ := math.Lgamma(float64(n + 1))
	lgK, _ := math.Lgamma(float64(k + 1))
	lgNK, _ := math.Lgamma(float64(n - k + 1))
	return lgN - lgK - lgNK
}

// Labelled is one verdict the model gave on a finding whose true answer a
// person decided: the model's confidence (stated or from logprobs) and
// whether closing on that answer would have been right.
type Labelled struct {
	Confidence float64 // the model's confidence in its answer
	Correct    bool    // whether the answer matched the person's decision
}

// Fit finds the smallest threshold T such that the false-closure rate at
// T is below ε with confidence 1−δ: among the verdicts the model was
// confident enough to close (confidence ≥ T), the proportion that were
// wrong is bounded by the Clopper–Pearson upper bound.
//
// Returns (threshold, ok): ok is false when no threshold in the labelled
// set achieves the bound — the model is not trustworthy enough at any
// confidence level the data shows, and the honest answer is to say so
// rather than to return a threshold that fails.
func Fit(labels []Labelled, epsilon, delta float64) (float64, bool) {
	if len(labels) == 0 || epsilon <= 0 || epsilon >= 1 || delta <= 0 || delta >= 1 {
		return 0, false
	}
	// Sort descending by confidence, so the threshold sweep visits the
	// most confident first and accumulates their correctness.
	sorted := make([]Labelled, len(labels))
	copy(sorted, labels)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Confidence > sorted[j].Confidence
	})
	// For each candidate threshold (each distinct confidence level),
	// count the closures at or above it and the false ones among them.
	// The bound the certificate needs is on the FALSE closure rate, so
	// we bound the proportion of wrong answers among the closures.
	var wrong, total int
	for i, l := range sorted {
		total++
		if !l.Correct {
			wrong++
		}
		// The candidate threshold is the NEXT confidence level (the
		// lowest confidence still included), because a threshold equal
		// to this label's confidence includes it.
		t := l.Confidence
		if i+1 < len(sorted) && sorted[i+1].Confidence == t {
			continue // skip duplicate confidence levels
		}
		upper := ClopperPearsonUpper(wrong, total, delta)
		if upper <= epsilon {
			return t, true
		}
	}
	return 0, false
}

// SampleSize returns how many labelled verdicts the fit used.
func SampleSize(labels []Labelled) int { return len(labels) }
