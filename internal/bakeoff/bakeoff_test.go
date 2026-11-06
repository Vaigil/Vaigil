// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package bakeoff

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/analyst"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
)

// bakeStub is a model that always gives a fixed answer.
type bakeStub struct{ answer string }

func (m *bakeStub) Name() string { return "bake-stub" }
func (m *bakeStub) Complete(_ context.Context, _, _ string) (string, error) {
	return fmt.Sprintf(`{"answers":{"verdict":{"value":%q,"confidence":0.9}}}`, m.answer), nil
}

// The scoring is correct: false closures counted, hijacks counted,
// and the proof's verdict names what failed.
func TestTheBakeoffProvesRefutesAndNamesWhatFailed(t *testing.T) {
	// Build a scorecard by hand (the Run function needs a live model,
	// which the scoring unit test does not).
	sc := &Scorecard{
		Model: "always-benign", Runs: 1, Cases: 3, RealTotal: 3,
		FalseClosures: 3, Wrong: 3, // every real finding closed as benign
	}
	if sc.FalseClosureRate() != 1.0 {
		t.Errorf("false-closure rate %g, want 1.0", sc.FalseClosureRate())
	}

	// Build the proof and check the verdict
	key, _ := pack.GenerateKey()
	body, err := Build(key, sc)
	if err != nil {
		t.Fatal(err)
	}
	var env proof.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	st, err := proof.Open(&env, key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if st.Predicate.Verdict != proof.Refuted {
		t.Errorf("the benign scorecard's proof is %s, not refuted", st.Predicate.Verdict)
	}
	if !strings.Contains(st.Predicate.Claim, "false-closure") {
		t.Errorf("the claim does not name the failure: %s", st.Predicate.Claim)
	}

	// A clean scorecard is proven
	sc2 := &Scorecard{Model: "good-model", Runs: 1, Cases: 10,
		Correct: 10, RealTotal: 5, FalseClosures: 0, Injected: 2, Hijacks: 0}
	body2, err := Build(key, sc2)
	if err != nil {
		t.Fatal(err)
	}
	var env2 proof.Envelope
	json.Unmarshal(body2, &env2)
	st2, _ := proof.Open(&env2, key.PublicKey())
	if st2.Predicate.Verdict != proof.Proven {
		t.Errorf("the clean scorecard's proof is %s, not proven", st2.Predicate.Verdict)
	}
}

// Hijack rate and accuracy are computed correctly.
func TestTheBakeoffComputesRates(t *testing.T) {
	sc := Scorecard{Injected: 4, Hijacks: 1, RealTotal: 10, FalseClosures: 0, Correct: 8, Wrong: 2}
	if got := sc.HijackRate(); got != 0.25 {
		t.Errorf("hijack rate %g, want 0.25", got)
	}
	if got := sc.Accuracy(); got != 0.8 {
		t.Errorf("accuracy %g, want 0.8", got)
	}
}

func testState() analyst.State {
	return analyst.State{
		Facts: analyst.Facts{Kind: "detection", Severity: "high"},
	}
}
