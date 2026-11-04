// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"fmt"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/telemetry"
)

// benchSink keeps a match from being optimised away.
var benchSink bool

// benchRules is a realistic pack: most rules compare plain fields, one
// carries a regular expression, one a CIDR block, and none of them fire on
// more than a sliver of the corpus — the shape an estate actually produces.
// Fixtures are omitted because Compile, not Validate, is what a run feeds;
// the fixture discipline is about authoring, not evaluation.
func benchRules(n int) []Rule {
	rs := make([]Rule, 0, n)
	for i := range n {
		var when Predicate
		switch i % 5 {
		case 0:
			when = Predicate{All: []Predicate{
				{Match: &Match{Field: "class", Op: Equals,
					Values: []string{"3002"}}},
				{Match: &Match{Field: "disposition", Op: Equals,
					Values: []string{"failed"}}},
			}}
		case 1:
			when = Predicate{Match: &Match{Field: "actor.value", Op: Prefix,
				Values: []string{"admin-"}}}
		case 2:
			when = Predicate{Match: &Match{Field: "message", Op: Contains,
				Values: []string{"impossible sign-in"}}}
		case 3:
			when = Predicate{Match: &Match{Field: "ip", Op: Inside,
				Values: []string{"203.0.113.0/24"}}}
		case 4:
			when = Predicate{All: []Predicate{
				{Match: &Match{Field: "severity", Op: Above,
					Values: []string{"4"}}},
				{Match: &Match{Field: "raw.client", Op: Exists}},
			}}
		}
		if i%7 == 0 {
			// The operator of last resort is on plenty of real packs; it has
			// to be on this one or the benchmark measures a lie.
			when = Predicate{Match: &Match{Field: "message", Op: Matches,
				Values: []string{"sign-in from 203\\.0\\.113\\.[0-9]+"}}}
		}
		rs = append(rs, Rule{
			ID: fmt.Sprintf("bench.rule-%d", i), Title: "bench",
			Sources: []string{"okta/system"}, When: when,
			Severity: telemetry.SeverityLow,
		})
	}
	return rs
}

// benchEvents is n sign-ins over a spread of accounts, one in fifty from an
// address inside the CIDR the pack watches.
func benchEvents(n int) []telemetry.Event {
	out := make([]telemetry.Event, 0, n)
	for i := range n {
		e := event("okta/system", map[string]string{
			"client": fmt.Sprintf("ua-%d", i%40)})
		e.Time = at.Add(time.Duration(i) * time.Second)
		e.Received = e.Time.Add(2 * time.Second)
		e.Message = fmt.Sprintf("sign-in %d for user-%d from 198.51.100.%d",
			i, i%500, i%254+1)
		if i%50 == 0 {
			e.Message = fmt.Sprintf("sign-in %d for user-%d from 203.0.113.%d",
				i, i%500, i%254+1)
			e.Observables = []telemetry.Observable{{
				Kind: telemetry.ObservableIP, Value: fmt.Sprintf(
					"203.0.113.%d", i%254+1), Name: "dst"}}
		}
		if i%500 == 0 {
			e.Message = "impossible sign-in blocked"
		}
		out = append(out, e)
	}
	return out
}

// BenchmarkRuleMatches is a run's inner loop as it stands: every rule asks
// the event for its fields again, and every "matches" comparison compiles
// its expression again.
func BenchmarkRuleMatches(b *testing.B) {
	rules := benchRules(20)
	events := benchEvents(10_000)
	for b.Loop() {
		for _, e := range events {
			for _, r := range rules {
				benchSink = r.Matches(e)
			}
		}
	}
}
