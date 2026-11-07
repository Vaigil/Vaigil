// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/dual"
)

// The only administrator's request waits for its delay with nobody else's
// approval beside it, so it carries a reason: refused without one, naming
// the option this command takes for it, and waiting with one — the reason
// kept in the request and in the audit record, where the next reader
// looks.
func TestTheOnlyAdministratorsRequestNeedsAReason(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	seedPolicy(t, root, [2]string{"dana", "admin"})
	if _, err := updatePolicy(root, func(p *auth.Policy) error { return p.SetOwner("dana") }); err != nil {
		t.Fatal(err)
	}
	asOnly(t, root, "dana")

	if err := cmdAuth(root, []string{"grant", "lee", "admin", "--on", "/"}); err == nil ||
		!strings.Contains(err.Error(), "--note") {
		t.Fatalf("a grant made alone without a reason was not refused naming --note: %v", err)
	}
	// The store's first token is the bootstrap, which nobody could second;
	// the next administrator's token is a request.
	if err := cmdToken(root, []string{"issue", "first", "--principal", "dana", "--role", "viewer"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdToken(root, []string{"issue", "ci", "--principal", "dana", "--role", "admin"}); err == nil ||
		!strings.Contains(err.Error(), "--why") {
		t.Fatalf("an admin token asked for alone without a reason was not refused naming --why: %v", err)
	}
	if rs, _ := dualStore(root).Pending(time.Now()); len(rs) != 0 {
		t.Fatalf("a refused request was kept: %+v", rs)
	}

	if err := cmdAuth(root, []string{"grant", "lee", "admin", "--on", "/",
		"--note", "lee covers the night shift"}); err != nil {
		t.Fatal(err)
	}
	r := waiting(t, root)
	if r.Kind != dual.Grant || r.Why != "lee covers the night shift" {
		t.Fatalf("the request: %+v", r)
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "dual.proposed" && e.Detail["request"] == r.ID {
			found = e.Detail["why"] == "lee covers the night shift"
		}
	}
	if !found {
		t.Error("the audit record of the request does not carry its reason")
	}

	long := strings.Repeat("x", dual.MaxWhy+1)
	if err := cmdAuth(root, []string{"grant", "pat", "admin", "--on", "/",
		"--note", long}); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("a reason over the bound was kept: %v", err)
	}
}

// The only administrator approving their own request from the command line
// after its delay: a long-lived token is not a proof of the person, nor is
// a passkey session signed in to six minutes ago; one signed in to just now
// is.
func TestApprovingYourOwnRequestOnTheCommandLineNeedsAFreshPasskey(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	seedPolicy(t, root, [2]string{"dana", "admin"})
	if _, err := updatePolicy(root, func(p *auth.Policy) error { return p.SetOwner("dana") }); err != nil {
		t.Fatal(err)
	}
	req, err := dualStore(root).Propose(dual.Grant, "make lee admin on /",
		dual.GrantChange{Bindings: []auth.Binding{{Principal: "lee", Role: auth.RoleAdmin, Resource: "/"}}},
		"lee covers nights", "dana", true, time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	asOnly(t, root, "dana")
	if err := cmdPending(root, []string{"approve", req.ID}); err == nil ||
		!strings.Contains(err.Error(), "People screen of the console") {
		t.Fatalf("a long-lived token approved its own request: %v", err)
	}
	asPasskey(t, root, "dana")
	ts, _ := loadTokens(root)
	for i := range ts.Tokens {
		if ts.Tokens[i].Name == "passkey:dana" {
			ts.Tokens[i].AuthAt = time.Now().Add(-6 * time.Minute).Unix()
		}
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	if err := cmdPending(root, []string{"approve", req.ID}); err == nil {
		t.Fatal("a six-minute-old passkey session approved its own request")
	}
	if p, _ := loadPolicy(root); p.Evaluate("lee", auth.ActGrant, "/").Allowed {
		t.Fatal("lee became an administrator on a refused approval")
	}
	asPasskey(t, root, "dana")
	if err := cmdPending(root, []string{"approve", req.ID}); err != nil {
		t.Fatalf("a fresh passkey session could not approve its own request: %v", err)
	}
	if p, _ := loadPolicy(root); !p.Evaluate("lee", auth.ActGrant, "/").Allowed {
		t.Fatal("approved, and lee is not an administrator")
	}
}
