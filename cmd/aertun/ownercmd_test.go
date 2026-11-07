// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
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
	// The Owner's own confirmation is the only approval a transfer gets,
	// so a command-line token is not enough: it takes a passkey sign-in.
	if err := cmdPending(root, []string{"approve", r.ID}); err == nil ||
		!strings.Contains(err.Error(), "needs a passkey sign-in") {
		t.Fatalf("a long-lived token confirmed the Owner's own request: %v", err)
	}
	asPasskey(t, root, "dana")
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
	asPasskey(t, root, "dana")
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

// The first run, as the README and the deploy guide write it: init makes
// the Owner, the store's first token is issued at once — there is nobody to
// be a second administrator to — and the second token is not.
func TestTheFirstRunGivesTheOwnerACommandLine(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir() + "/st"
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AERTUN_TOKEN", "")
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := initAdmin(root, []string{"--owner", "you@example.com"}, true); err != nil {
		t.Fatal(err)
	}
	if err := authoriseCommand(root, "token", []string{"issue", "cli", "--principal", "you@example.com", "--role", "admin"}); err != nil {
		t.Fatalf("the first token was refused at the gate: %v", err)
	}
	if err := tokenIssue(root, []string{"cli", "--principal", "you@example.com", "--role", "admin"}); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(root)
	if len(ts.Tokens) != 1 || ts.Tokens[0].Role != auth.RoleAdmin {
		t.Fatalf("the first token was not issued: %+v", ts.Tokens)
	}
	if pend, _ := dualStore(root).Pending(time.Now()); len(pend) != 0 {
		t.Fatalf("the first token waited for a second administrator: %+v", pend)
	}
	// The bootstrap closes once a token exists.
	if err := authoriseCommand(root, "token", []string{"issue", "second", "--principal", "you@example.com", "--role", "admin"}); err == nil {
		t.Error("a second token was issued without presenting the first")
	}
	// And the server starts with no token at all: it authorises each
	// request itself.
	if err := authoriseCommand(root, "serve", nil); err != nil {
		t.Errorf("serve needed a token: %v", err)
	}
}

// The container image ships the store's directory empty, so init finds it
// made: the shipped rules must still arrive, or nothing is detected until
// the server has started once.
func TestInitIntoAnEmptyDirectoryInstallsTheRules(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if !dirExists(filepath.Join(root, "detections")) {
		t.Fatal("init into an empty directory installed no rules")
	}
}

// A store made in an empty directory — the container image ships one — is
// new: two factors from its first day, not the grace an older installation
// gets. A directory that already holds a store keeps whatever it had.
func TestInitIntoAnEmptyDirectoryHasTwoFactorsFromTheStart(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir() // exists, and is empty
	if err := runInit(root, []string{"--owner", "you@example.com"}); err != nil {
		t.Fatal(err)
	}
	from, ok := mfaFromIfSet(root)
	if !ok || time.Since(from) > time.Minute || time.Until(from) > time.Minute {
		t.Fatalf("two factors start at %s (set %v), not now", from, ok)
	}
	// Run again on the store it made: nothing about the date moves.
	if err := runInit(root, nil); err != nil {
		t.Fatal(err)
	}
	if again, _ := mfaFromIfSet(root); !again.Equal(from) {
		t.Errorf("a second init moved two factors from %s to %s", from, again)
	}
}
