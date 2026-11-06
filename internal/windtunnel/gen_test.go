// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"strings"
	"testing"
	"time"
)

// The generators are a pure function of their inputs: same generator, seed
// and index, same bytes — on every machine, forever. A scorecard's scenario
// digest is only worth recording because this holds, so it is the first
// thing tested and the failure names the stake.
func TestGeneratorsAreByteDeterministic(t *testing.T) {
	for _, gen := range Gens() {
		for _, seed := range []int64{0, 1, 7, 21, 999999} {
			for _, i := range []int{0, 1, 5, 100} {
				a, err := Generate(gen, seed, i)
				if err != nil {
					t.Fatalf("%s: %v", gen, err)
				}
				b, err := Generate(gen, seed, i)
				if err != nil {
					t.Fatal(err)
				}
				if a != b {
					t.Fatalf("%s(seed %d, index %d) drew %q then %q; two "+
						"runs of the same draw differ, and a scorecard's "+
						"digest is worth the bytes it names only if this "+
						"never happens", gen, seed, i, a, b)
				}
			}
		}
	}
	// Different seeds draw different sessions — a seed that changed nothing
	// would be a flag that lied.
	a, _ := Generate(GenTraceID, 7, 0)
	b, _ := Generate(GenTraceID, 8, 0)
	if a == b {
		t.Fatalf("seeds 7 and 8 drew the same trace id %q", a)
	}
}

// The drawn ranges are disjoint from anything a live stream carries: the
// agent name carries the wt- prefix and the trace id the ff- first byte, so
// an overlap with recorded traffic is a finding about the recording, not a
// silent join.
func TestGeneratorsDrawFromDisjointRanges(t *testing.T) {
	agent, err := Generate(GenAgentName, 11, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(agent, "wt-") {
		t.Errorf("agent name %q lacks the wt- prefix; a generated identity "+
			"must be recognisably nobody else's", agent)
	}
	trace, err := Generate(GenTraceID, 11, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(trace) != 32 || !strings.HasPrefix(trace, "ff") {
		t.Errorf("trace id %q is not 32 hex characters starting ff; the ff "+
			"byte is the range no live SDK is issued", trace)
	}
	dest, err := Generate(GenDestCanary, 31, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := canary(dest); err != nil {
		t.Errorf("the canary generator drew %q and the canary check "+
			"refused it: %v. The generator and the check have drifted apart",
			dest, err)
	}
	if _, err := Generate("hostname", 1, 0); err == nil ||
		!strings.Contains(err.Error(), "is not a generator") {
		t.Errorf("an unknown generator gave %v; the closed set is the closed "+
			"set", err)
	}
}

// The binding expansion is a function of the file alone: the seed moves the
// clocks, never the session. Two loads of the same scenario produce the
// same identity, whatever run seed the splice later uses.
func TestGeneratorsExpandStableAcrossRunsAndSeeds(t *testing.T) {
	sc := copyScenario(t, "agent.trifecta-mailroom-exfil")
	first, err := Expand(sc)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Expand(sc)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range first {
		if second[k] != v {
			t.Errorf("binding %s expanded to %q then %q; a session's "+
				"identity is stable or its digest is not worth recording",
				k, v, second[k])
		}
	}
	// And the placeholders all resolve: validation promised they would.
	for _, s := range sc.Steps {
		e := Substitute(s.Emit, first)
		for _, v := range emitStrings(e) {
			if strings.Contains(v, "${") {
				t.Errorf("%q still carries a placeholder after expansion", v)
			}
		}
	}
}

// The default base stream is a function of nothing: no clock, no
// environment, no network. Two generations are the same bytes, which is
// what makes a scorecard's base-stream digest a name rather than a hope.
func TestFixtureBaseStreamIsByteIdenticalAcrossRuns(t *testing.T) {
	a, countA := BaseDigest(DefaultBase())
	b, countB := BaseDigest(DefaultBase())
	if a != b {
		t.Fatal("the default base stream digests differently on two " +
			"generations; a moving fixture is a different stream every run")
	}
	if countA != countB || countA < 20 {
		t.Fatalf("%d then %d events; the morning shrank between calls",
			countA, countB)
	}
}

// The default base stream is quiet in the ways a normal day is quiet and
// arrives the way traffic does: every event later than it happened, and at
// least one late enough to keep the lateness histogram honest — the honest
// tail the watermark exists to wait for.
func TestFixtureBaseStreamIsQuietAndArrivesLikeTraffic(t *testing.T) {
	base := DefaultBase()
	var late time.Duration
	for _, e := range base {
		if e.Lateness() <= 0 {
			t.Fatalf("an event at %s arrived at or before it happened; the "+
				"fixture must arrive like traffic or every spliced delay "+
				"draws from a lie", e.Time.Format(time.RFC3339))
		}
		if e.Lateness() > late {
			late = e.Lateness()
		}
	}
	if late < 30*time.Minute {
		t.Fatalf("the worst arrival delay in the fixture is %s; the honest "+
			"tail — the late cloud-audit batch — is what keeps a watermark "+
			"conservative", late)
	}
	h := latenessHistogram(base)
	if q := h.quantile(0.99); q < time.Minute {
		t.Fatalf("the fixture's own 99th-percentile delay is %s; a "+
			"watermark sized from this would close windows a real stream "+
			"still has events in", q)
	}
}
