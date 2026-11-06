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

// ownedStore is a store whose Owner is dana, with lee a second
// administrator, made the way init makes one.
func ownedStore(t *testing.T) string {
	t.Helper()
	windtunnelOutput(t)
	root := t.TempDir()
	seedPolicy(t, root, [2]string{"dana", "admin"}, [2]string{"lee", "admin"})
	if _, err := updatePolicy(root, func(p *auth.Policy) error { return p.SetOwner("dana") }); err != nil {
		t.Fatal(err)
	}
	return root
}

// Another administrator cannot revoke or deny the Owner, on any surface,
// because every surface writes through updatePolicy.
func TestAnotherAdministratorCannotRemoveTheOwner(t *testing.T) {
	root := ownedStore(t)
	asOnly(t, root, "lee")
	if err := cmdAuth(root, []string{"revoke", "dana", "admin"}); err == nil ||
		!strings.Contains(err.Error(), "always administers the whole store") {
		t.Errorf("the Owner was revoked: %v", err)
	}
	if err := cmdAuth(root, []string{"deny", "dana", "viewer", "--on", "/@log"}); err == nil ||
		!strings.Contains(err.Error(), "nothing denies the Owner") {
		t.Errorf("the Owner was denied: %v", err)
	}
	if p, _ := loadPolicy(root); p.Evaluate("dana", auth.ActGrant, "/").Allowed != true {
		t.Error("the Owner lost the store")
	}
}

// Ownership moves when the Owner confirms it a day after asking; only the
// Owner can ask or confirm, nobody else can make it happen, and an agent
// can do neither.
func TestOwnershipMovesOnlyByTheOwnersConfirmedTransfer(t *testing.T) {
	root := ownedStore(t)

	asOnly(t, root, "lee")
	if err := cmdAuth(root, []string{"owner", "transfer", "lee"}); err == nil ||
		!strings.Contains(err.Error(), "only the Owner, dana") {
		t.Fatalf("an administrator took ownership: %v", err)
	}

	register(t, root, "helper", "aertun_read")
	_, agentSecret := agentToken(t, root, "helper", "dana", auth.RoleAdmin)
	t.Setenv("AERTUN_TOKEN", agentSecret)
	if err := cmdAuth(root, []string{"owner", "transfer", "lee"}); err == nil ||
		!strings.Contains(err.Error(), "never by an agent") {
		t.Fatalf("an agent moved ownership: %v", err)
	}

	asOnly(t, root, "dana")
	if err := cmdAuth(root, []string{"owner", "transfer", "pat"}); err == nil {
		t.Fatal("ownership was offered to somebody who administers nothing")
	}
	if err := cmdAuth(root, []string{"owner", "transfer", "lee", "--note", "dana is leaving"}); err != nil {
		t.Fatal(err)
	}
	r := waiting(t, root)
	if r.Kind != dual.Owner || r.NotBefore.Sub(r.At) != 24*time.Hour {
		t.Fatalf("the request: %+v", r)
	}
	if err := cmdPending(root, []string{"approve", r.ID}); err == nil ||
		!strings.Contains(err.Error(), "may be confirmed from") {
		t.Fatalf("confirmed within the day: %v", err)
	}
	asOnly(t, root, "lee")
	if err := cmdPending(root, []string{"approve", r.ID}); err == nil ||
		!strings.Contains(err.Error(), "dana, who asked, confirms it") {
		t.Fatalf("the recipient confirmed it: %v", err)
	}

	// A day on: the same request, asked a day ago, confirmed by dana.
	old, err := dualStore(root).Propose(dual.Owner, "make lee the Owner", dual.OwnerChange{To: "lee"},
		"", "dana", false, time.Now().Add(-25*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	asOnly(t, root, "dana")
	if err := cmdPending(root, []string{"approve", old.ID}); err != nil {
		t.Fatalf("the Owner confirming after a day: %v", err)
	}
	if p, _ := loadPolicy(root); p.OwnerName() != "lee" {
		t.Fatalf("the Owner is %q", p.OwnerName())
	}
	// The earlier request, asked by somebody who no longer owns the store,
	// cannot land as well.
	if err := applyOwner(root, r, dual.OwnerChange{To: "lee"}); err == nil {
		t.Error("a transfer asked for by a former Owner was applied")
	}
}
