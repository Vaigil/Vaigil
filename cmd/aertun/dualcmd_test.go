// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/dual"
)

func waiting(t *testing.T, root string) dual.Request {
	t.Helper()
	pend, err := dualStore(root).Pending(time.Now())
	if err != nil || len(pend) != 1 {
		t.Fatalf("waiting: %+v %v", pend, err)
	}
	return pend[0]
}

// seedPolicy grants straight into the policy, as a test's setup does: a
// second administrator granted by a command waits for a third.
func seedPolicy(t *testing.T, root string, grants ...[2]string) {
	t.Helper()
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		for _, g := range grants {
			if err := p.Grant(auth.Binding{Principal: g[0], Role: auth.Role(g[1]), Resource: "/"}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// asOnly acts as who, with a token of their own, for a test whose store
// they alone administer.
func asOnly(t *testing.T, root, who string) {
	t.Helper()
	ts, _ := loadTokens(root)
	secret, _, err := ts.Issue(who, who, auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(tokensPath(root), ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AERTUN_TOKEN", secret)
}

// An agent acting for the only administrator may not approve a privileged
// change, even after the delay that lets the administrator approve it
// alone: otherwise an agent would ask, wait, and approve in their name.
func TestAnAgentNeverApprovesAPrivilegedChange(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	seedPolicy(t, root, [2]string{"dana", "admin"})
	register(t, root, "helper", "aertun_read")
	_, agentSecret := agentToken(t, root, "helper", "dana", auth.RoleAdmin)
	long := time.Now().Add(-2 * time.Hour)
	r, err := dualStore(root).Propose(dual.Setting, "weaken x", dual.SettingChange{Key: "x", Value: "y"},
		"", "dana", true, long)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AERTUN_TOKEN", agentSecret)
	if err := cmdPending(root, []string{"approve", r.ID}); err == nil ||
		!strings.Contains(err.Error(), "approved by a person, never by an agent") {
		t.Fatalf("an agent approved a privileged change: %v", err)
	}
	if got, _ := dualStore(root).Get(r.ID); got.State != dual.Waiting {
		t.Fatalf("the request moved: %+v", got)
	}
	// The person it acts for may, now the delay has passed.
	asOnly(t, root, "dana")
	if _, err := dualStore(root).Decide(r.ID, "dana", true, onlyAdministrator(root, "dana"), time.Now()); err != nil {
		t.Errorf("the only administrator, after the delay: %v", err)
	}
}
