// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/telemetry"
)

// delaylessBase is a stream that never arrived late: every event delivered
// the moment it happened. No real stream is shaped like this, which is
// exactly why the measured splice refuses it.
func delaylessBase(n int, at time.Time) []telemetry.Event {
	out := make([]telemetry.Event, n)
	for i := range out {
		when := at.Add(time.Duration(i) * time.Minute)
		out[i] = telemetry.Event{Source: "otel/genai",
			Class:       telemetry.ClassAPIActivity,
			Disposition: telemetry.DispositionAllowed,
			Actor:       telemetry.ID{Issuer: "otel", Value: "refunder"},
			Message:     "execute_tool", Time: when, Received: when,
			Raw: map[string]string{"operation": "execute_tool",
				"tool": "sql_query", "status": "ok",
				"trace_id": "00000000000000000000000000000001",
				"labels":   "sensitive-data"}}
	}
	return out
}

// The splice is deterministic end to end: the same base stream, scenario
// and seed place the same events on both clocks, byte for byte. This is
// what makes a scorecard's numbers comparable run against run.
func TestSpliceIsDeterministicEndToEnd(t *testing.T) {
	sc := copyScenario(t, "agent.trifecta-mailroom-exfil")
	base := DefaultBase()
	anchor, err := DefaultAnchor(base)
	if err != nil {
		t.Fatal(err)
	}
	first, err := Place(sc, sc.Steps, base, 7, anchor)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Place(sc, sc.Steps, base, 7, anchor)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first.Events)
	b, _ := json.Marshal(second.Events)
	if !bytes.Equal(a, b) {
		t.Fatal("the same scenario over the same base at the same seed " +
			"placed different bytes; the numbers a scorecard carries are " +
			"only comparable if this never happens")
	}

	// A different seed moves the clocks and nothing else: the session
	// identity — which the file, not the seed, owns — is unchanged.
	third, err := Place(sc, sc.Steps, base, 8, anchor)
	if err != nil {
		t.Fatal(err)
	}
	values, err := Expand(sc)
	if err != nil {
		t.Fatal(err)
	}
	for i := range third.Events {
		if third.Events[i].Actor.Value != values["agent"] ||
			third.Events[i].Raw["trace_id"] != values["trace"] {
			t.Fatalf("seed 8 moved the session identity at event %d; the "+
				"seed moves the clocks, never the session", i)
		}
	}
	sameDelays := true
	for i := range third.Delays {
		if third.Delays[i] != first.Delays[i] {
			sameDelays = false
		}
	}
	if sameDelays {
		t.Fatal("seeds 7 and 8 drew identical arrival delays; the seed is " +
			"a flag that does nothing")
	}
}

// Arrival synthesis draws from the base stream's own distribution: never
// zero — a zero-delay splice is trivially distinguishable from live traffic
// and flatters every windowed correlation — and never above the worst delay
// the base stream has shown.
func TestSpliceArrivalIsDrawnFromTheMeasuredDistribution(t *testing.T) {
	sc := copyScenario(t, "agent.cost-bomb-loop")
	base := DefaultBase()
	anchor, _ := DefaultAnchor(base)
	placed, err := Place(sc, sc.Steps, base, 7, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if len(placed.Events) != 130 {
		t.Fatalf("%d events placed; the loop expands to 130", len(placed.Events))
	}
	worst := latenessHistogram(base).quantile(1)
	for i, e := range placed.Events {
		d := e.Lateness()
		if d <= 0 {
			t.Fatalf("event %d arrived exactly when it happened; the "+
				"splicer's one rule is that no scenario event arrives at "+
				"the speed of a local function call", i)
		}
		if d > worst {
			t.Fatalf("event %d arrived %s late, and the base stream's worst "+
				"arrival is %s; the draws must stay inside what the stream "+
				"itself has shown", i, d, worst)
		}
		if !e.Time.Before(e.Received) {
			t.Fatalf("event %d's clocks are not both honoured", i)
		}
	}
}

// A base stream that arrived with no delay at all refuses the measured
// splice — the constant the whole arrival-synthesis step exists to refuse —
// and names the profiles that cover it.
func TestSpliceRefusesADelaylessBaseStream(t *testing.T) {
	at := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	instant := delaylessBase(6, at)
	sc := copyScenario(t, "agent.trifecta-mailroom-exfil")
	_, err := Place(sc, sc.Steps, instant, 7, at.Add(time.Hour))
	if err == nil || !strings.Contains(err.Error(), "local function call") {
		t.Fatalf("a base stream that never arrived late gave %v; the "+
			"refusal is the point, and it names the profiles", err)
	}

	// The declared profile covers exactly that fixture: cloud-audit's late
	// batches stand in for a history the stream does not carry.
	sc.Lateness = ProfileCloudAudit
	placed, err := Place(sc, sc.Steps, instant, 7, at.Add(time.Hour))
	if err != nil {
		t.Fatalf("the cloud-audit profile refused a delayless stream: %v", err)
	}
	for i, e := range placed.Events {
		if e.Lateness() <= 0 {
			t.Fatalf("profile event %d arrived instantly", i)
		}
	}
}

// Interleave is not a tail append: the session's events land among the base
// stream's arrivals where their synthesised arrivals put them, and the base
// stream keeps its own order. A tail append would hand the victim a stream
// whose every ending is in order — the classical replay determinism bug in
// different clothes.
func TestSpliceInterleavesRatherThanAppends(t *testing.T) {
	sc := copyScenario(t, "agent.trifecta-mailroom-exfil")
	base := DefaultBase()
	anchor, _ := DefaultAnchor(base)
	placed, err := Place(sc, sc.Steps, base, 7, anchor)
	if err != nil {
		t.Fatal(err)
	}
	merged := Interleave(base, placed.Events)
	if len(merged) != len(base)+len(placed.Events) {
		t.Fatalf("%d merged from %d and %d; the interleave lost events",
			len(merged), len(base), len(placed.Events))
	}
	for i := 1; i < len(merged); i++ {
		if merged[i].Received.Before(merged[i-1].Received) {
			t.Fatalf("the merged stream is out of arrival order at %d; the "+
				"victim's watermark is earned in this order", i)
		}
	}
	// A session event with a base event after it: the splice is genuinely
	// inside the stream, not stapled to its end.
	sessionAfter := false
	sessionEvents := 0
	for i, e := range merged {
		if e.Raw["trace_id"] == placed.Events[0].Raw["trace_id"] {
			sessionEvents++
			for _, later := range merged[i+1:] {
				if later.Raw["trace_id"] != placed.Events[0].Raw["trace_id"] {
					sessionAfter = true
				}
			}
		}
	}
	if sessionEvents != len(placed.Events) {
		t.Fatalf("%d session events in the merged stream, %d were placed",
			sessionEvents, len(placed.Events))
	}
	if !sessionAfter {
		t.Fatal("every session event is at the tail of the merged stream; " +
			"this is the tail append, and it flatters every windowed " +
			"correlation in the stack")
	}
}

// The scratch spool round-trips the merged stream through the store's own
// append path, so segmentation, sealing and the lateness histogram behave
// exactly as they do live.
func TestSpliceScratchSpoolRoundTrips(t *testing.T) {
	sc := copyScenario(t, "agent.cost-bomb-loop")
	base := DefaultBase()
	anchor, _ := DefaultAnchor(base)
	placed, err := Place(sc, sc.Twin.Steps, base, 7, anchor)
	if err != nil {
		t.Fatal(err)
	}
	stream := Interleave(base, placed.Events)
	dir := t.TempDir()
	sp, err := WriteScratch(dir, stream)
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	var seen int
	err = sp.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		seen++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen != len(stream) {
		t.Fatalf("the scratch spool holds %d of %d events", seen, len(stream))
	}
}
