// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package stats

import (
	"math"
	"testing"
)

// wilsonIndependent is the interval written the textbook way, with the
// proportion carried rather than the count, so agreeing with Wilson is two
// derivations landing on one number rather than one derivation copied into
// its own test.
func wilsonIndependent(p float64, n int) (lo, hi float64) {
	z := 1.959963984540054
	den := 1 + z*z/float64(n)
	centre := (p + z*z/(2*float64(n))) / den
	spread := z * math.Sqrt(
		p*(1-p)/float64(n)+z*z/(4*float64(n)*float64(n))) / den
	return math.Max(0, centre-spread), math.Min(1, centre+spread)
}

func TestWilsonMatchesAnIndependentImplementation(t *testing.T) {
	for _, c := range []struct{ k, n int }{{10, 100}, {1, 3}, {0, 12}, {12, 12}, {7, 10}} {
		lo, hi := Wilson(c.k, c.n)
		ilo, ihi := wilsonIndependent(float64(c.k)/float64(c.n), c.n)
		if math.Abs(lo-ilo) > 1e-12 || math.Abs(hi-ihi) > 1e-12 {
			t.Errorf("Wilson(%d, %d) = [%v, %v], the independent form gives "+
				"[%v, %v]", c.k, c.n, lo, hi, ilo, ihi)
		}
	}
}

// The ends are where a small sample most needs width, and where the plain
// interval has none.
func TestTheIntervalHasWidthAtTheExtremes(t *testing.T) {
	if low, high := Wilson(10, 10); low > 0.75 || high < 0.999 {
		t.Errorf("10 of 10 is [%.2f, %.2f]; ten trials do not prove a rate "+
			"of one", low, high)
	}
	if low, high := Wilson(0, 10); low != 0 || high < 0.25 {
		t.Errorf("0 of 10 is [%.2f, %.2f]", low, high)
	}
}

// No trials is no evidence, and a count outside [0, n] is clamped rather
// than allowed to produce a bound outside [0, 1].
func TestNoEvidenceAndImpossibleCounts(t *testing.T) {
	if lo, hi := Wilson(0, 0); lo != 0 || hi != 1 {
		t.Errorf("no trials is [%v, %v], not [0, 1]", lo, hi)
	}
	for _, k := range []int{-3, 14} {
		if lo, hi := Wilson(k, 10); lo < 0 || hi > 1 {
			t.Errorf("Wilson(%d, 10) = [%v, %v] walks outside [0, 1]", k, lo, hi)
		}
	}
}
