// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/vaigil/vaigil/internal/audit"
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
