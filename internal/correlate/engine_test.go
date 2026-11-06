// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package correlate

import (
	"testing"
	"time"
)

// observeAt is observe with the watermark said out loud, for events whose
// window closes between two passes.
func observeAt(t *testing.T, e *Engine, rule string, min int, wm time.Time) {
	t.Helper()
	if err := e.Observe(Seen{Rule: rule,
		Event: ev(t0.Add(time.Duration(min)*time.Minute), "ada")}, wm); err != nil {
		t.Fatal(err)
	}
}

// whys renders a run's hits for comparing one pass split against another.
func whys(hits []Hit) []string {
	out := make([]string, len(hits))
	for i, h := range hits {
		out[i] = h.Why()
	}
	return out
}

// TestEventsEitherSideOfABoundaryStillCorrelate is the pair of adjacent
// windows the fixed ones cannot see across on their own: recon at ten to
// eleven and execution at five past, inside the timespan of each other and
// in different epoch-aligned windows.
func TestEventsEitherSideOfABoundaryStillCorrelate(t *testing.T) {
	for _, c := range []struct {
		name string
		rule string
	}{
		{"temporal", temporalRule},
		{"temporal_ordered", orderedRule},
	} {
		e, err := New(read(t, c.rule))
		if err != nil {
			t.Fatal(err)
		}
		observeAt(t, e, "recon", 55, t0)
		observeAt(t, e, "execution", 65, t0)
		hits := e.Flush()
		if len(hits) != 1 {
			t.Fatalf("%s: %d hit(s) for a pair ten minutes apart straddling "+
				"the 11:00 boundary: %+v", c.name, len(hits), hits)
		}
		h := hits[0]
		if len(h.Rules) != 2 {
			t.Fatalf("%s: rules = %v", c.name, h.Rules)
		}
		if !h.From.Equal(t0.Add(55 * time.Minute)) {
			t.Fatalf("%s: the hit's span starts at %s, not at the earlier "+
				"event", c.name, h.From)
		}
	}
}

// TestAStraddleOutsideTheTimespanStillDoesNotCorrelate: two events either
// side of a boundary and fifty minutes apart, further than the 30-minute
// timespan. Fixing the boundary must not widen the rule.
func TestAStraddleOutsideTheTimespanStillDoesNotCorrelate(t *testing.T) {
	for _, c := range []struct {
		name string
		rule string
	}{
		{"temporal", temporalRule},
		{"temporal_ordered", orderedRule},
	} {
		e, err := New(read(t, c.rule))
		if err != nil {
			t.Fatal(err)
		}
		observeAt(t, e, "recon", 5, t0)
		observeAt(t, e, "execution", 55, t0)
		if hits := e.Flush(); len(hits) != 0 {
			t.Fatalf("%s: fired across %s: %+v", c.name,
				hits[0].To.Sub(hits[0].From), hits)
		}
	}
}

// TestStraddlesAreFoundTheSameWhateverThePassSplit: the same events under
// the same watermarks, closed one window at a time, after both events, and
// all at once, must give the same answers — that is what makes a live run
// and its replay agree.
func TestStraddlesAreFoundTheSameWhateverThePassSplit(t *testing.T) {
	run := func(closes func(e *Engine) []Hit) []string {
		e, err := New(read(t, temporalRule))
		if err != nil {
			t.Fatal(err)
		}
		// The 10:30 window closes while the 11:00 one is still open, which
		// is exactly the pass boundary the straddle has to survive.
		observeAt(t, e, "recon", 55, t0.Add(56*time.Minute))
		observeAt(t, e, "execution", 65, t0.Add(66*time.Minute))
		return whys(closes(e))
	}
	oneAtATime := run(func(e *Engine) []Hit {
		var out []Hit
		out = append(out, e.Close(t0.Add(66*time.Minute))...)
		out = append(out, e.Close(t0.Add(96*time.Minute))...)
		return out
	})
	bothAtOnce := run(func(e *Engine) []Hit {
		return e.Close(t0.Add(96 * time.Minute))
	})
	atTheEnd := run(func(e *Engine) []Hit { return e.Flush() })

	if len(oneAtATime) != 1 {
		t.Fatalf("closing as the watermark advanced gave %v", oneAtATime)
	}
	for _, split := range [][]string{bothAtOnce, atTheEnd} {
		if len(split) != len(oneAtATime) {
			t.Fatalf("a different pass split gave %v against %v", split,
				oneAtATime)
		}
		for i := range split {
			if split[i] != oneAtATime[i] {
				t.Fatalf("hit %d differs across pass splits:\n  %s\n  %s",
					i, split[i], oneAtATime[i])
			}
		}
	}
}

// TestEventsInsideTheClosingWindowStillCountBesideAPair: a window that
// closes beside a retained one must still fire on what is wholly its own —
// the pair evaluation may not swallow the ordinary case.
func TestEventsInsideTheClosingWindowStillCountBesideAPair(t *testing.T) {
	e, err := New(read(t, orderedRule))
	if err != nil {
		t.Fatal(err)
	}
	// execution at 10:25 in the 10:00 window; recon and execution both in
	// the 10:30 one. The ordered pair is wholly inside the closing window.
	observeAt(t, e, "execution", 25, t0)
	observeAt(t, e, "recon", 35, t0)
	observeAt(t, e, "execution", 40, t0)
	hits := e.Flush()
	if len(hits) != 1 {
		t.Fatalf("%d hit(s) for a sequence wholly inside one window: %+v",
			len(hits), hits)
	}
}

// TestAPairAlreadyReportedDoesNotFireAgainFromTheNextWindow: a window's
// events stay paired with it. Once its occurrence has fired, the next
// window closing must not report it a second time through the pair.
func TestAPairAlreadyReportedDoesNotFireAgainFromTheNextWindow(t *testing.T) {
	e, err := New(read(t, orderedRule))
	if err != nil {
		t.Fatal(err)
	}
	observeAt(t, e, "recon", 10, t0)
	observeAt(t, e, "execution", 15, t0)
	observeAt(t, e, "recon", 35, t0)
	hits := e.Flush()
	if len(hits) != 1 {
		t.Fatalf("%d hit(s): the pair in the 10:00 window fired again when "+
			"the 10:30 one closed, or did not fire at all: %+v", len(hits), hits)
	}

	// Unordered is different, on purpose: execution at 10:15 and recon at
	// 10:35 are a second, straddling pair the fixed windows used to miss.
	u, _ := New(read(t, temporalRule))
	observeAt(t, u, "recon", 10, t0)
	observeAt(t, u, "execution", 15, t0)
	observeAt(t, u, "recon", 35, t0)
	hits = u.Flush()
	if len(hits) != 2 {
		t.Fatalf("%d hit(s): the pair either side of the boundary is a "+
			"second occurrence, not a repeat of the first: %+v", len(hits), hits)
	}
}
