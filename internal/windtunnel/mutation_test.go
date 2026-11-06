// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/telemetry"
)

// A mutation preserves effect: the fields a rule needs — source, message,
// raw.operation, raw.tool, raw.labels, disposition, the actor's issuer —
// are identical after the mutation. Only the surface changed.
func TestAMutationPreservesEffectAndChangesSurface(t *testing.T) {
	e := telemetry.Event{
		Source:      "otel/genai",
		Message:     "execute_tool",
		Actor:       telemetry.ID{Issuer: "otel", Value: "ci-agent"},
		Disposition: telemetry.DispositionAllowed,
		Raw: map[string]string{
			"operation": "execute_tool",
			"tool":      "http_post",
			"labels":    "egress",
		},
	}
	mutated := Mutate(e)

	// Effect: identical on the fields the detection reads.
	effectFields := []string{"source", "message", "raw.operation", "raw.tool", "raw.labels"}
	before := e.Fields()
	after := mutated.Fields()
	for _, f := range effectFields {
		// The actor's value case may change (that is the actor-case mutation);
		// the actor's issuer must not.
		if f == "actor.issuer" {
			continue
		}
		if before[f] != after[f] && !strings.EqualFold(before[f], after[f]) {
			t.Errorf("the mutation changed the effect field %s: %q → %q",
				f, before[f], after[f])
		}
	}
	// The actor's issuer must be identical always.
	if before["actor.issuer"] != after["actor.issuer"] {
		t.Errorf("the mutation changed actor.issuer: %q → %q",
			before["actor.issuer"], after["actor.issuer"])
	}

	// Surface: something changed. At least one of: the message, the
	// actor's value case, or the raw map's keys.
	changed := mutated.Message != e.Message ||
		mutated.Actor.Value != e.Actor.Value ||
		len(mutated.Raw) != len(e.Raw)
	if !changed {
		t.Error("the mutation changed nothing — it tests nothing")
	}
}

// Every mutation in the set changes something on an event with the
// common fields: a mutation that changes nothing tests nothing.
func TestEveryMutationChangesSomething(t *testing.T) {
	e := telemetry.Event{
		Source:      "otel/genai",
		Message:     "execute_tool",
		Actor:       telemetry.ID{Issuer: "otel", Value: "ci-agent"},
		Target:      telemetry.ID{Issuer: "otlp", Value: "svc-target"},
		Disposition: telemetry.DispositionAllowed,
		Raw:         map[string]string{"operation": "execute_tool"},
	}
	for _, m := range mutations {
		// Copy the Raw map: Apply mutates it in place, and the next
		// mutation would see the previous mutation's changes.
		e.Raw = map[string]string{
			"operation": "execute_tool",
		}
		mutated := m.Apply(e)
		same := mutated.Message == e.Message &&
			mutated.Actor.Value == e.Actor.Value &&
			mutated.Target.Value == e.Target.Value &&
			mutated.Raw["operation"] == e.Raw["operation"] &&
			len(mutated.Raw) == len(e.Raw)
		if same {
			t.Errorf("mutation %q changed nothing on the test event", m.Name)
		}
	}
}

// embeddedScenarios loads the raw scenario JSON from the embedded files,
// without pack validation — the mutation test is about the events.
func embeddedScenarios() []*Scenario {
	entries, err := scenarioFS.ReadDir("scenarios")
	if err != nil {
		return nil
	}
	var out []*Scenario
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		body, err := scenarioFS.ReadFile("scenarios/" + e.Name())
		if err != nil {
			continue
		}
		var sc Scenario
		if json.Unmarshal(body, &sc) == nil && sc.ID != "" {
			out = append(out, &sc)
		}
	}
	return out
}

// MutatedPlace is deterministic: the same inputs give the same outputs.
func TestMutatedPlaceIsDeterministic(t *testing.T) {
	// The embedded scenarios: load them without a reference (the mutation
	// test is about the events, not about pack validation).
	scenarios := embeddedScenarios()
	var trifecta *Scenario
	for _, s := range scenarios {
		if s.ID == "agent.trifecta-mailroom-exfil" {
			trifecta = s
			break
		}
	}
	if trifecta == nil {
		t.Skip("the trifecta scenario is not in the corpus")
	}
	// The two-clock guard refuses a nil base stream's zero-delay splice.
	// The local-agent profile is what the tests use: small, honest delays.
	trifecta.Lateness = "profile:local-agent"
	// Place once, mutate twice: the mutated forms must be identical.
	p1, err := MutatedPlace(trifecta, trifecta.Steps, nil, 7, testAnchor())
	if err != nil {
		t.Fatal(err)
	}
	p2, err := MutatedPlace(trifecta, trifecta.Steps, nil, 7, testAnchor())
	if err != nil {
		t.Fatal(err)
	}
	if len(p1.Events) != len(p2.Events) {
		t.Fatalf("%d events vs %d", len(p1.Events), len(p2.Events))
	}
	for i := range p1.Events {
		if p1.Events[i].Message != p2.Events[i].Message {
			t.Errorf("event %d differs: %q vs %q", i, p1.Events[i].Message, p2.Events[i].Message)
		}
	}
}

// testAnchor is a fixed anchor time for the deterministic test.
func testAnchor() time.Time { return time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC) }
