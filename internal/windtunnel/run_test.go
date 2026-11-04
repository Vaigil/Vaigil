// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/telemetry"
)

// The corpus and the pack are each other's fixtures: every scenario fires
// what it expects, every twin stays quiet, and the two scenarios whose
// blinds declare the pack has no rule for them are recorded at the
// telemetry tier — caught-telemetry, never dressed up as caught.
func TestScenarioCorpusFiresExpectsAndKeepsTwinsQuiet(t *testing.T) {
	card, err := Run(RunOptions{Seed: 7,
		Now: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("the whole corpus over the default base stream refused: %v",
			err)
	}
	telemetryOnly := map[string]bool{
		"agent.slopsquat-install":     true,
		"agent.recorder-blind-window": true,
	}
	if len(card.Rows) != 6 {
		t.Fatalf("%d rows; the seed corpus is six scenarios", len(card.Rows))
	}
	for _, row := range card.Rows {
		for _, x := range row.Expects {
			if !x.Met {
				t.Errorf("%s: %s %s %s was not met (%s); the corpus and the "+
					"pack are each other's fixtures, and a pack change that "+
					"breaks this is a miss a scorecard would have to report",
					row.Scenario, x.Kind, x.ID, x.Verdict, x.Note)
			}
		}
		if row.Twin.Outcome != TwinQuiet {
			t.Errorf("%s: the benign twin %s %sd; the precision axis failed "+
				"and every catch above is noise until it is quiet again",
				row.Scenario, row.Twin.ID, row.Twin.Outcome)
		}
		if telemetryOnly[row.Scenario] {
			if row.Outcome != OutcomeCaughtTelemetry {
				t.Errorf("%s is %s; its blind says the pack carries no rule "+
					"for it, so the honest tier is caught-telemetry",
					row.Scenario, row.Outcome)
			}
			continue
		}
		if row.Outcome != OutcomeCaughtAlert {
			t.Errorf("%s is %s; the pack detects this family and the "+
				"corpus exists to prove it still does", row.Scenario,
				row.Outcome)
		}
	}
	if card.Aggregate.Missed != 0 || card.Aggregate.MustAlert != 4 {
		t.Fatalf("missed %d of %d must-alert scenarios; the shipped pack "+
			"catches the four it carries rules for", card.Aggregate.Missed,
			card.Aggregate.MustAlert)
	}
	if card.Aggregate.TwinFires != 0 {
		t.Fatalf("%d twin false fires", card.Aggregate.TwinFires)
	}
}

// Two runs of the same base, scenarios and seed produce the same rows and
// the same digests. The scratch path and the digest over it differ — a
// document names where its streams were written — so both are set aside and
// the rest is compared, then re-sealed: the comparison a CI gate makes.
func TestRunIsDeterministic(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	a, err := Run(RunOptions{Seed: 7, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Run(RunOptions{Seed: 7, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Scorecard{a, b} {
		c.Scratch = ""
		c.SHA256 = ""
		c.Signature = nil
		if err := c.seal(); err != nil {
			t.Fatal(err)
		}
	}
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if string(ab) != string(bb) {
		t.Fatal("two runs of the same seed produced different documents; a " +
			"scorecard gate over nondeterministic numbers gates nothing")
	}
}

// The calibration statement, made arithmetic: the same rules over the base
// stream alone raise nothing. Any alert in a spliced run is therefore the
// session's, which is what every count-above-ambient in the scorecard
// assumes.
func TestRunAmbientStreamRaisesNothing(t *testing.T) {
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	base := DefaultBase()
	sp, err := WriteScratch(t.TempDir(), base)
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	res, err := runPass(sp, ref, latenessHistogram(base).quantile(0.99))
	if err != nil {
		t.Fatal(err)
	}
	for id, n := range res.loud {
		if n > 0 {
			t.Errorf("the base stream alone raised %s %d time(s); the "+
				"fixture is not the quiet morning it claims to be", id, n)
		}
	}
	for id, hits := range res.hits {
		if len(hits) > 0 {
			t.Errorf("the base stream alone completed %s %d time(s); the "+
				"fixture's sessions must never complete a chain", id,
				len(hits))
		}
	}
}

// The two-clock edge, told apart by name. A completing event that lands
// after its window closed under the stream's own watermark is a lateness
// miss — a finding about the lateness budget — and the same session with
// the completing event simply absent from the pattern is a content miss.
// Conflating them is how a replay flatters its rules; the scorecard must
// say which kind of miss it was.
func TestSpliceLateCompletingEventIsALatenessMissNotAContentMiss(t *testing.T) {
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	base := DefaultBase()
	anchor, err := DefaultAnchor(base)
	if err != nil {
		t.Fatal(err)
	}
	sc := copyScenario(t, "agent.trifecta-mailroom-exfil")

	ambient, err := ambientPass(t, ref, base)
	if err != nil {
		t.Fatal(err)
	}

	// The lateness miss: the egress leg — the completing event — arrives
	// three hours after it happened, past its window's close under the
	// watermark the stream's own arrivals earned.
	placed, err := Place(sc, sc.Steps, base, 7, anchor)
	if err != nil {
		t.Fatal(err)
	}
	// By index: placed.Events[i] is a value, and a copy set to arrive late
	// would leave the real event on time — the bug this test exists to
	// catch, in the test's own clothes.
	completing := placed.Events[len(placed.Events)-1]
	completing.Received = completing.Time.Add(3 * time.Hour)
	placed.Events[len(placed.Events)-1] = completing
	row, attack := replayAndScore(t, sc, ref, base, placed, ambient)
	if row.Met {
		t.Fatal("the trifecta completed although its egress leg arrived " +
			"after the window had closed; a window that closed cannot " +
			"still be completing")
	}
	if row.MissKind != MissLateness {
		t.Fatalf("the miss kind is %q, not %q; an event the watermark "+
			"dropped is a lateness miss, and the scorecard's honesty about "+
			"misses is exactly this distinction", row.MissKind, MissLateness)
	}
	if !strings.Contains(row.Note, "after their window had closed") {
		t.Errorf("the note (%s) does not name the window closing; the "+
			"reader of the miss deserves the cause", row.Note)
	}
	// The quiet legs still fired: the content was seen; only the window
	// arithmetic lost it.
	for _, x := range []Expect{
		{Kind: ExpectRule, ID: "otel.untrusted-read", Verdict: VerdictFiresQuietly},
		{Kind: ExpectRule, ID: "otel.sensitive-read", Verdict: VerdictFiresQuietly},
	} {
		r := scoreExpect(sc, x, ref, attack, ambient, placed)
		if !r.Met {
			t.Errorf("%s did not fire; the legs were seen, and only the "+
				"completing event's arrival lost the window", x.ID)
		}
	}

	// The content miss, for contrast: same session, but the egress leg
	// travels under a trace the rest of the session does not carry, so the
	// ordered pattern never completes — and no arrival anywhere is late.
	placed2, err := Place(sc, sc.Steps, base, 7, anchor)
	if err != nil {
		t.Fatal(err)
	}
	egress := placed2.Events[len(placed2.Events)-1]
	egress.Raw["trace_id"] = strings.Repeat("ee", 16)
	placed2.Events[len(placed2.Events)-1] = egress
	row2, _ := replayAndScore(t, sc, ref, base, placed2, ambient)
	if row2.Met {
		t.Fatal("the trifecta completed across two traces; the group-by " +
			"should have kept them apart")
	}
	if row2.MissKind != MissContent {
		t.Fatalf("the miss kind is %q, not %q; a pattern that never formed "+
			"is a content miss — the finding about the rules", row2.MissKind,
			MissContent)
	}
}

// replayAndScore splices a placed session into the base stream, replays the
// reference pack over the scratch spool, and scores the trifecta's
// must-alert expectation — the three steps the edge test needs, without the
// rest of a whole run. The pass comes back too, so the caller can ask more
// of the same findings.
func replayAndScore(t *testing.T, sc *Scenario, ref *Reference,
	base []telemetry.Event, placed *Placed,
	ambient *passResult) (*ExpectRow, *passResult) {
	t.Helper()
	stream := Interleave(base, placed.Events)
	sp, err := WriteScratch(t.TempDir(), stream)
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	attack, err := runPass(sp, ref, latenessHistogram(stream).quantile(0.99))
	if err != nil {
		t.Fatal(err)
	}
	r := scoreExpect(sc, Expect{Kind: ExpectCorrelation,
		ID: "corr.lethal-trifecta", Verdict: VerdictMustAlert}, ref, attack,
		ambient, placed)
	return r, attack
}

// ambientPass is the calibration replay of the base stream alone.
func ambientPass(t *testing.T, ref *Reference, base []telemetry.Event) (*passResult, error) {
	t.Helper()
	sp, err := WriteScratch(t.TempDir(), base)
	if err != nil {
		return nil, err
	}
	defer sp.Close()
	return runPass(sp, ref, latenessHistogram(base).quantile(0.99))
}

// The honesty set. A rule or correlation the pack no longer carries is a
// miss the scorecard reports — never an error that stops the run — and the
// one verdict an absent detection must not satisfy is stays-quiet, because
// deleting rules would otherwise improve scorecards.
func TestRunDeletedDetectionIsAMissNotAnError(t *testing.T) {
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	base := DefaultBase()
	anchor, _ := DefaultAnchor(base)
	sc := copyScenario(t, "agent.trifecta-mailroom-exfil")
	placed, err := Place(sc, sc.Steps, base, 7, anchor)
	if err != nil {
		t.Fatal(err)
	}
	ambient, err := ambientPass(t, ref, base)
	if err != nil {
		t.Fatal(err)
	}

	deleted := &Reference{Name: ref.Name, Rules: ref.Rules, Corrs: ref.Corrs,
		Digest:    ref.Digest,
		ruleQuiet: map[string]bool{}, corrIDs: map[string]bool{}}
	for k, v := range ref.ruleQuiet {
		deleted.ruleQuiet[k] = v
	}
	for k, v := range ref.corrIDs {
		deleted.corrIDs[k] = v
	}
	delete(deleted.corrIDs, strings.ToLower("corr.lethal-trifecta"))
	delete(deleted.ruleQuiet, strings.ToLower("otel.untrusted-read"))

	// The deleted correlation: a must-alert that cannot be met, reported.
	r := scoreExpect(sc, Expect{Kind: ExpectCorrelation,
		ID: "corr.lethal-trifecta", Verdict: VerdictMustAlert}, deleted,
		ambient, ambient, placed)
	if r.Met {
		t.Fatal("a correlation outside the pack satisfied a must-alert; " +
			"nothing outside the pack can catch anything")
	}
	if !strings.Contains(r.Note, "not in the reference pack") {
		t.Errorf("the note (%s) does not say the pack no longer carries it",
			r.Note)
	}

	// The deleted rule, the other direction: stays-quiet must NOT be met by
	// absence, or deleting rules would improve scorecards.
	r = scoreExpect(sc, Expect{Kind: ExpectRule,
		ID: "otel.untrusted-read", Verdict: VerdictStaysQuiet}, deleted,
		ambient, ambient, placed)
	if r.Met {
		t.Fatal("a rule outside the pack satisfied stays-quiet; a rule " +
			"cannot fire from outside the pack, and letting its absence " +
			"count as quiet means deleting rules improves a scorecard")
	}
	if !strings.Contains(r.Note, "must not improve a scorecard") {
		t.Errorf("the note (%s) does not name the anti-gaming rule", r.Note)
	}

	// And the outcome folds a deleted must-alert into a miss, not a
	// wrongly-quiet and not a telemetry row.
	rows := []ExpectRow{*scoreExpect(sc, Expect{Kind: ExpectCorrelation,
		ID: "corr.lethal-trifecta", Verdict: VerdictMustAlert}, deleted,
		ambient, ambient, placed)}
	if got := outcomeOf(rows); got != OutcomeMissed {
		t.Fatalf("a scenario whose correlation was deleted folded into %q; "+
			"the honest tier is missed", got)
	}
}

// The live-target refusal, in code: a URL where a stream path belongs is
// somebody asking the wind tunnel to fire at a live collector, and every
// scenario this build loads is synthetic-only. The refusal is in Run, not
// the CLI, so no caller can route around it.
func TestRunRefusesALiveTargetInCode(t *testing.T) {
	for _, target := range []string{
		"https://staging.example.internal:4318/v1/logs",
		"http://collector.example.test",
		"otlp://staging.example.internal:4317",
		"grpc://staging.example.internal:4317",
	} {
		_, err := Run(RunOptions{Base: target, Scenarios: []string{
			"agent.trifecta-mailroom-exfil"}})
		if err == nil || !strings.Contains(err.Error(), "live endpoint") {
			t.Errorf("%s was not refused as a live endpoint (%v); the "+
				"refusal is replay's whole safety story, held by "+
				"construction", target, err)
		}
	}
}

// The phase-2 scoring modes are refused with their names and their phase,
// not silently fallen back to reference — a mode that half-runs would
// measure nothing while claiming to measure the organisation's controls.
func TestRunRefusesThePhaseTwoScoringModesHonestly(t *testing.T) {
	for _, mode := range []string{"their-sigma:./rules", "their-alerts:x.json"} {
		_, err := Run(RunOptions{ScoreMode: mode, Scenarios: []string{
			"agent.trifecta-mailroom-exfil"}})
		if err == nil || !strings.Contains(err.Error(), "phase 2") {
			t.Errorf("%s was not refused with its phase (%v)", mode, err)
		}
	}
	_, err := Run(RunOptions{ScoreMode: "vibes", Scenarios: []string{
		"agent.trifecta-mailroom-exfil"}})
	if err == nil || !strings.Contains(err.Error(), "not a scoring mode") {
		t.Errorf("an unknown scoring mode gave %v", err)
	}
}

// A run of only precision-claim scenarios — nothing carries a must-alert —
// has no primary number, and the document refuses to seal rather than
// rendering a 0% miss rate over nothing: the naked percentage this schema
// exists to refuse.
func TestRunRefusesARunWithNoMustAlertScenario(t *testing.T) {
	_, err := Run(RunOptions{Scenarios: []string{"agent.slopsquat-install",
		"agent.recorder-blind-window"}})
	if err == nil || !strings.Contains(err.Error(), "must-alert") {
		t.Fatalf("a run of quiet-leg-only scenarios gave %v; the honest "+
			"answer is a refusal to print a rate over no denominator", err)
	}
}

// A run naming a scenario the corpus does not carry refuses with the
// command that lists what does ship.
func TestRunRefusesAnUnknownScenario(t *testing.T) {
	_, err := Run(RunOptions{Scenarios: []string{"agent.stuxnet"}})
	if err == nil || !strings.Contains(err.Error(), "no scenario called") ||
		!strings.Contains(err.Error(), "list-scenarios") {
		t.Fatalf("an unknown scenario id gave %v", err)
	}
}

// A base stream the operator named is digested and counted, so a scorecard
// number is always about a stream somebody can identify — and the run over
// it works exactly as the fixture run does.
func TestRunOverAnOperatorNamedBaseStream(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "base.jsonl")
	var lines []string
	for _, e := range DefaultBase() {
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(b))
	}
	if err := writeLines(path, lines...); err != nil {
		t.Fatal(err)
	}
	card, err := Run(RunOptions{Base: path, Scenarios: []string{
		"agent.trifecta-mailroom-exfil"},
		Now: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("a run over a written-out base stream refused: %v", err)
	}
	if card.Base != "base.jsonl" || card.BaseEvents != len(DefaultBase()) {
		t.Errorf("the scorecard names base %q with %d events; the run was "+
			"over a file the operator named", card.Base, card.BaseEvents)
	}
	for _, row := range card.Rows {
		if row.Outcome != OutcomeCaughtAlert {
			t.Errorf("%s over the operator's stream is %s; the same bytes "+
				"as the fixture must score the same", row.Scenario,
				row.Outcome)
		}
	}
}
