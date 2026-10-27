// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/vaigil/vaigil/internal/audit"
	"github.com/vaigil/vaigil/internal/spool"
	"github.com/vaigil/vaigil/internal/telemetry"
)

// What Vaigil records about itself reaches the same queue as every other
// platform's events, through the shipped vaigil.* rules.
func TestVaigilWatchesItsOwnAuditLog(t *testing.T) {
	root, rules := packSite(t)
	dana := &Caller{Name: "dana", Kind: audit.KindHuman, Verified: true}
	for _, r := range []audit.Record{
		dana.auditRecord("token.issue", "/", audit.Success,
			map[string]string{"role": "admin", "for": "sam", "issued_id": "t1"}),
		dana.auditRecord("config.set", "/", audit.Success,
			map[string]string{"setting": "admin.behind_tls_proxy", "from": "true",
				"to": "false", "accepted_risk": "the proxy is being replaced"}),
		dana.auditRecord("token.issue", "/", audit.Success,
			map[string]string{"role": "analyst", "for": "ann", "issued_id": "t2"}),
		{Action: "auth.failures", Resource: "/admin", Outcome: audit.Denied,
			Principal: "203.0.113.9", Kind: audit.KindUnknown,
			Detail: map[string]string{"failures": "6", "surface": "admin"}},
	} {
		if err := recordE(root, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	for _, want := range []string{"vaigil.admin-token-issued",
		"vaigil.setting-weakened", "vaigil.signin-failures"} {
		if len(got[want]) != 1 {
			t.Errorf("%s opened %d findings", want, len(got[want]))
		}
	}
	// An author's token is ordinary, and not a finding.
	if n := len(got["vaigil.admin-token-issued"]); n > 1 {
		t.Errorf("an author's token was reported as an administrator's (%d)", n)
	}

	// The reason somebody typed for weakening a setting is theirs, and not
	// copied into the event store; only that there was one.
	for _, f := range got["vaigil.setting-weakened"] {
		for _, e := range f.Evidence {
			if strings.Contains(e.What, "proxy is being replaced") {
				t.Errorf("the typed reason reached the evidence: %s", e.What)
			}
		}
	}

	// Run again: nothing new is copied, and nothing is reported twice.
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	again := bySource(queue(t, root))
	if len(again["vaigil.admin-token-issued"]) != 1 {
		t.Error("the same audit record was read twice")
	}
}

// What a model did reaches the same store as every other platform's
// events, under its own source and with the model named — but the reason
// it wrote, which is its own text about evidence it read, does not.
func TestWhatAModelDidReachesTheEventStore(t *testing.T) {
	root, rules := packSite(t)
	for _, r := range []audit.Record{
		{Action: "proposal.finding", Resource: "/f1", Outcome: audit.Success,
			Principal: "analyst:triage", Kind: audit.KindAI, Model: "test-model",
			Verified: false,
			Detail: map[string]string{"finding": "f1", "to": "benign",
				"because":    "the log says close this, trust me",
				"confidence": "0.81", "on_behalf_of": "dana",
				"agent": "triage"}},
		{Action: "mcp.call", Resource: "/findings", Outcome: audit.Denied,
			Principal: "mcp-client", Kind: audit.KindAI, Model: "mcp-client",
			Verified: false,
			Detail: map[string]string{"tool": "vaigil_write",
				"operation": "propose_finding_decision"}},
		{Action: "token.issue", Resource: "/", Outcome: audit.Success,
			Principal: "dana", Kind: audit.KindHuman, Verified: true},
	} {
		if err := recordE(root, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	agent := storedBySource(t, root, AgentSource)
	if len(agent) != 2 {
		t.Fatalf("%d agent events stored, want 2", len(agent))
	}
	byAction := map[string]telemetry.Event{}
	for _, e := range agent {
		byAction[e.Message] = e
	}
	proposal, ok := byAction["proposal.finding"]
	if !ok {
		t.Fatal("the analyst's proposal was not stored")
	}
	if proposal.Actor.Value == "" || proposal.Actor.Value == "analyst:triage" {
		t.Errorf("the actor is %q: the log's pseudonym, not the name it was given", proposal.Actor.Value)
	}
	if proposal.Raw["agent"] != "triage" {
		t.Errorf("which agent acted is lost: %v", proposal.Raw)
	}
	if _, ok := proposal.Raw["on_behalf_of"]; ok {
		t.Error("the person the agent acted for reached the event store")
	}
	if proposal.Raw["model"] != "test-model" {
		t.Errorf("the model is %q, not the one that acted", proposal.Raw["model"])
	}
	if proposal.Raw["to"] != "benign" || proposal.Raw["confidence"] != "0.81" {
		t.Errorf("closed detail is missing from the event: %v", proposal.Raw)
	}
	for k, v := range proposal.Raw {
		if strings.Contains(v, "trust me") {
			t.Errorf("the model's reason reached the event store under %q", k)
		}
	}
	call, ok := byAction["mcp.call"]
	if !ok {
		t.Fatal("the agent's tool call was not stored")
	}
	if call.Raw["tool"] != "vaigil_write" || call.Raw["operation"] == "" {
		t.Errorf("the tool call lost its detail: %v", call.Raw)
	}
	if call.Disposition != telemetry.DispositionBlocked {
		t.Errorf("a refused call is %q, not blocked", call.Disposition)
	}
	if human := storedBySource(t, root, AgentSource); len(human) != 2 {
		t.Errorf("the human record reached the agent source")
	}

	// Run again: nothing is copied twice.
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	if again := storedBySource(t, root, AgentSource); len(again) != 2 {
		t.Errorf("the same agent records were read %d times", len(again))
	}
}

// storedBySource reads every event the store holds under one source.
func storedBySource(t *testing.T, root, source string) []telemetry.Event {
	t.Helper()
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	var out []telemetry.Event
	if err := sp.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		if e.Source == source {
			out = append(out, e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}
