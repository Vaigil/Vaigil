// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/telemetry"
)

// The regression diff's pairs, built the way a CI job builds them: two
// runs, one of which lost the detection or woke on the twin.

var diffNow = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

// diffRun is a reference run of the trifecta under a named instrument.
func diffRun(t *testing.T, ref *Reference) *Scorecard {
	t.Helper()
	card, err := Run(RunOptions{Reference: ref, Seed: 7, Now: diffNow,
		Scenarios: []string{"agent.trifecta-mailroom-exfil"}})
	if err != nil {
		t.Fatal(err)
	}
	return card
}

// dropTrifecta is the shipped pack minus the correlation that catches
// the trifecta: the doctored reference a regression pair needs, built the
// way run_test's deleted-detection test builds one.
func dropTrifecta(t *testing.T) *Reference {
	t.Helper()
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	doctored := &Reference{Name: ref.Name, Rules: ref.Rules,
		Digest: ref.Digest, ruleQuiet: map[string]bool{},
		corrIDs: map[string]bool{}}
	for k, v := range ref.ruleQuiet {
		doctored.ruleQuiet[k] = v
	}
	for k, v := range ref.corrIDs {
		doctored.corrIDs[k] = v
	}
	delete(doctored.corrIDs, "corr.lethal-trifecta")
	kept := ref.Corrs[:0]
	for _, c := range ref.Corrs {
		if c.ID != "corr.lethal-trifecta" {
			kept = append(kept, c)
		}
	}
	doctored.Corrs = kept
	return doctored
}

// wakeTheTwin is the shipped pack plus one loud rule that matches only
// the trifecta twin's case note: the precision axis failing in a run
// whose attack side still catches everything.
func wakeTheTwin(t *testing.T) *Reference {
	t.Helper()
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	waker := detect.Rule{
		ID: "test.twin-waker", Title: "A case note where no case note goes",
		Why:     "wakes on the twin's filesystem.write, which nothing else does",
		Sources: []string{"otel/genai"}, Severity: telemetry.SeverityLow,
		When: detect.Predicate{Match: &detect.Match{
			Field: "raw.path", Op: detect.Prefix, Values: []string{"cases/"}}},
	}
	if _, err := waker.Compile(); err != nil {
		t.Fatal(err)
	}
	ref.Rules = append(ref.Rules, waker)
	ref.ruleQuiet[strings.ToLower(waker.ID)] = false
	return ref
}

// The regression pair: caught then missed, named, and gated — the
// transition a CI job fails on.
func TestDiffNamesARegressionAndItIsTheExitCode(t *testing.T) {
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	before := diffRun(t, ref)
	after := diffRun(t, dropTrifecta(t))
	if after.Rows[0].Outcome != OutcomeMissed {
		t.Fatalf("the doctored run's row is %s; the pair needs a miss",
			after.Rows[0].Outcome)
	}
	report, err := Diff("before.json", before, "after.json", after)
	if err != nil {
		t.Fatal(err)
	}
	if report.Regressions != 1 || report.Fixes != 0 {
		t.Fatalf("%d regression(s), %d fix(es); one scenario went from "+
			"caught to missed", report.Regressions, report.Fixes)
	}
	s := report.Summarize()
	for _, want := range []string{
		"caught-alert → missed (regression)",
		"exit 1",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the report never says %q:\n%s", want, s)
		}
	}
}

// The fix pair, same two documents the other way round: missed then
// caught is a fix, reported, and the gate stays green — exit 0.
func TestDiffNamesAFixAndStaysClean(t *testing.T) {
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	after := diffRun(t, ref)
	before := diffRun(t, dropTrifecta(t))
	report, err := Diff("before.json", before, "after.json", after)
	if err != nil {
		t.Fatal(err)
	}
	if report.Regressions != 0 || report.Fixes != 1 {
		t.Fatalf("%d regression(s), %d fix(es); a miss that became a catch "+
			"is one fix and no regression", report.Regressions, report.Fixes)
	}
	s := report.Summarize()
	if !strings.Contains(s, "missed → caught-alert (fix)") {
		t.Errorf("the report never names the fix:\n%s", s)
	}
	if !strings.Contains(s, "exit 0") {
		t.Errorf("a fixed pair is not clean in the verdict:\n%s", s)
	}
}

// The twin axis is its own regression: a twin that was quiet and now
// false-fires fails the gate even though the attack side still catches
// everything — the precision axis, gated.
func TestDiffTwinNewlyFiringIsARegression(t *testing.T) {
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	before := diffRun(t, ref)
	after := diffRun(t, wakeTheTwin(t))
	if after.Rows[0].Twin.Outcome != TwinFalseFire {
		t.Fatalf("the waker run's twin is %s; the pair needs a false fire",
			after.Rows[0].Twin.Outcome)
	}
	if after.Rows[0].Outcome != OutcomeCaughtAlert {
		t.Fatalf("the attack side is %s; the regression pair isolates the "+
			"twin axis", after.Rows[0].Outcome)
	}
	report, err := Diff("before.json", before, "after.json", after)
	if err != nil {
		t.Fatal(err)
	}
	if report.Regressions != 1 {
		t.Fatalf("%d regression(s); the twin is the one thing that moved",
			report.Regressions)
	}
	s := report.Summarize()
	if !strings.Contains(s, "twin quiet → false-fire (regression)") {
		t.Errorf("the report never names the twin's transition:\n%s", s)
	}
	if !strings.Contains(s, "exit 1") {
		t.Errorf("a twin false-fire is not gated in the verdict:\n%s", s)
	}
}

// Identical documents are CI-clean: no transition, no counters, exit 0 —
// and the same two documents diff to the same bytes twice.
func TestDiffIdenticalCardsIsCICleanAndDeterministic(t *testing.T) {
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	a := diffRun(t, ref)
	b := diffRun(t, ref)
	report, err := Diff("a.json", a, "b.json", b)
	if err != nil {
		t.Fatal(err)
	}
	if report.Regressions != 0 || report.Fixes != 0 ||
		len(report.Scenarios) != 0 {
		t.Fatalf("identical rows produced %+v; a clean diff carries no "+
			"transitions", report)
	}
	s := report.Summarize()
	if !strings.Contains(s, "no scenario transition") ||
		!strings.Contains(s, "exit 0") {
		t.Errorf("the verdict is not clean-and-said-so:\n%s", s)
	}
	again, err := Diff("a.json", a, "b.json", b)
	if err != nil {
		t.Fatal(err)
	}
	if again.Summarize() != s {
		t.Fatal("two diffs of the same documents produced different " +
			"bytes; a CI diff over two diff runs would mean nothing")
	}
}

// Scenario sets that moved are reported as new and retired, never
// diffed as though the same corpus ran — and a scenario whose bytes
// changed between documents is named, because its transition is a fact
// about the edit as much as about the controls.
func TestDiffReportsSetMovesAndChangedBytes(t *testing.T) {
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	trifecta, err := Run(RunOptions{Reference: ref, Seed: 7, Now: diffNow,
		Scenarios: []string{"agent.trifecta-mailroom-exfil"}})
	if err != nil {
		t.Fatal(err)
	}
	costBomb, err := Run(RunOptions{Reference: ref, Seed: 7, Now: diffNow,
		Scenarios: []string{"agent.cost-bomb-loop"}})
	if err != nil {
		t.Fatal(err)
	}
	report, err := Diff("a.json", trifecta, "b.json", costBomb)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, s := range report.Scenarios {
		kinds[s.Scenario] = s.Kind
	}
	if kinds["agent.trifecta-mailroom-exfil"] != DiffRetired ||
		kinds["agent.cost-bomb-loop"] != DiffNew {
		t.Fatalf("the set moves were read as %v; a scenario that vanished "+
			"is retired and one that appeared is new, and neither is a "+
			"transition", kinds)
	}
	if report.Regressions != 0 {
		t.Fatalf("%d regression(s) over a changed scenario set; a set move "+
			"is not a finding", report.Regressions)
	}

	// Same id, different bytes: the digest names the edit.
	edited := diffRun(t, ref)
	edited.Rows[0].Digest = "deadbeefdeadbeef"
	if err := edited.seal(); err != nil {
		t.Fatal(err)
	}
	report, err = Diff("a.json", trifecta, "b.json", edited)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Scenarios) != 1 ||
		!strings.Contains(report.Scenarios[0].Note, "bytes changed") {
		t.Fatalf("a scenario whose bytes changed between documents "+
			"produced %+v; the note owes the reader the edit",
			report.Scenarios)
	}
}

// Ambient drift is told apart from rule findings: the base stream's own
// alerts moving between two runs is on the report with its counts, and
// the same-bytes case says the instrument changed rather than the
// estate.
func TestDiffReportsAmbientDrift(t *testing.T) {
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	before := diffRun(t, ref)
	if before.AmbientFires != 0 {
		t.Fatalf("the shipped pack raises %d on the base stream alone; the "+
			"fixture's quiet morning is the premise", before.AmbientFires)
	}
	// An instrument that raises on the base stream: a rule matching the
	// reporter's own webhook posts, three of them in the fixture.
	noisy := &Reference{Name: ref.Name, Corrs: ref.Corrs,
		Rules: append(append([]detect.Rule{}, ref.Rules...), detect.Rule{
			ID: "test.ambient-webhook", Title: "Every webhook post",
			Why:     "matches the base stream's reporter, and nothing else",
			Sources: []string{"otel/genai"}, Severity: telemetry.SeverityLow,
			When: detect.Predicate{Match: &detect.Match{
				Field: "raw.tool", Op: detect.Equals,
				Values: []string{"post_webhook"}}}}),
		Digest: ref.Digest, ruleQuiet: map[string]bool{},
		corrIDs: map[string]bool{}}
	for k, v := range ref.ruleQuiet {
		noisy.ruleQuiet[k] = v
	}
	for k, v := range ref.corrIDs {
		noisy.corrIDs[k] = v
	}
	after := diffRun(t, noisy)
	if after.AmbientFires != 3 {
		t.Fatalf("%d ambient fire(s) sealed; the reporter posts three "+
			"webhooks in the fixture", after.AmbientFires)
	}
	report, err := Diff("before.json", before, "after.json", after)
	if err != nil {
		t.Fatal(err)
	}
	if report.Ambient == nil || report.Ambient.FromFires != 0 ||
		report.Ambient.ToFires != 3 || report.Ambient.BaseDigestChanged {
		t.Fatalf("ambient drift %+v; 0 → 3 over the same base bytes",
			report.Ambient)
	}
	s := report.Summarize()
	flat := strings.Join(strings.Fields(s), " ")
	if !strings.Contains(flat, "ambient: 0 → 3 alert(s)") ||
		!strings.Contains(flat, "the instrument changed what it raises on them") {
		t.Errorf("the drift is not named with its cause:\n%s", s)
	}
}

// Documents that must never be pooled refuse with the reason: different
// engines, different scoring modes, different corpora. A transition
// between incomparable documents is a fact about the join, not about the
// controls.
func TestDiffRefusesIncomparableDocuments(t *testing.T) {
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	a := diffRun(t, ref)
	b := diffRun(t, ref)

	other := diffRun(t, ref)
	other.Engine = "windtunnel-0"
	if err := other.seal(); err != nil {
		t.Fatal(err)
	}
	_, err = Diff("a.json", a, "b.json", other)
	if err == nil || !strings.Contains(err.Error(),
		"only comparable against the engine") {
		t.Errorf("an engine mismatch diffed (%v)", err)
	}

	other = diffRun(t, ref)
	other.ScoreMode = ModeTheirSigma + ":elsewhere"
	if err := other.seal(); err != nil {
		t.Fatal(err)
	}
	_, err = Diff("a.json", a, "b.json", other)
	if err == nil || !strings.Contains(err.Error(), "never pooled") {
		t.Errorf("a cross-mode diff ran (%v)", err)
	}

	other = diffRun(t, ref)
	other.Corpus = "somebody's edit"
	if err := other.seal(); err != nil {
		t.Fatal(err)
	}
	_, err = Diff("a.json", a, "b.json", other)
	if err == nil || !strings.Contains(err.Error(), "different corpus bytes") {
		t.Errorf("a cross-corpus diff ran (%v)", err)
	}

	_ = b
}
