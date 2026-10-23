// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"

	"github.com/quilzo/vaigil/internal/auth"
	"github.com/quilzo/vaigil/internal/dual"
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
	t.Setenv("VAIGIL_TOKEN", secret)
}
