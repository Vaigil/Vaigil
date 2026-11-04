// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aeroprove/aeroprove/internal/inbound"
)

// Every rule that ships validates, fires on the event it says it fires on,
// stays quiet on the one beside it, and says what it does not catch.
func TestEveryShippedRuleAgreesWithItsOwnFixtures(t *testing.T) {
	files, err := Pack()
	if err != nil {
		t.Fatal(err)
	}
	rules, quiet := 0, 0
	platforms := map[string]bool{}
	for _, f := range files {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		if f.Name == ToolLabelsFile {
			// The sensitivity table lives among the rules and is not one;
			// the loaders step over it, and so does their test.
			continue
		}
		var r Rule
		if err := json.Unmarshal(f.Body, &r); err != nil {
			t.Errorf("%s: %v", f.Name, err)
			continue
		}
		rules++
		if r.ID+".json" != f.Name {
			t.Errorf("%s holds the rule %s", f.Name, r.ID)
		}
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", f.Name, err)
			continue
		}
		for _, res := range r.Test() {
			if !res.OK() {
				t.Errorf("%s: %q should match=%v and matched=%v", r.ID,
					res.Fixture, res.Want, res.Got)
			}
		}
		if strings.TrimSpace(r.Blind) == "" {
			t.Errorf("%s does not say what it misses", r.ID)
		}
		if r.Quiet {
			quiet++
		}
		for _, s := range r.Sources {
			platforms[strings.SplitN(s, "/", 2)[0]] = true
		}
	}
	// Sixteen rules are quiet by design: the failed and succeeded
	// sign-ins, the push denials and approvals, the IAM user and its
	// access key, the two halves of the agent's behaviour, the agent
	// telemetry's tool call and failed model call, the mapped-host
	// config change the watch-then-call corridor counts, and the three
	// labelled legs — the untrusted read, the sensitive read, the
	// egress — that only the trifecta's sequence makes a finding of.
	// Each feeds a correlation rather than raising a finding of its own.
	if rules < 29 || quiet != 16 {
		t.Errorf("%d rules, %d of them quiet", rules, quiet)
	}
	for _, want := range []string{"okta", "entra", "workspace", "github",
		"aws", "evm", "aeroprove", "duo", "kubernetes", "snowflake",
		"auditd", "otel", "collector", "openai", "anthropic",
		strings.SplitN(inbound.StreamSource, "/", 2)[0]} {
		if !platforms[want] {
			t.Errorf("no rule reads %s", want)
		}
	}
}
