// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"strings"
	"testing"
	"time"
)

// The delegation chain: written by the agent mint, capped by the same mint,
// and carried on the stored token so revocation and audit can see who acted
// for whom without re-deriving it from anything.
func TestTheActChainIsCappedWhereItIsWritten(t *testing.T) {
	ts := &TokenStore{}
	now := time.Now()

	// The honest chain: a person and one agent.
	secret, _, err := ts.IssueForAgent("agent:watcher/obo-gr1", "dana",
		RoleAnalyst, Scope{}, "watcher", "gr1", "https://here/mcp", "",
		[]string{"dana", "watcher"}, "", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ts.AuthenticateFor(secret, "https://here/mcp", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Act) != MaxActChain || got.Act[0] != "dana" || got.Act[1] != "watcher" {
		t.Fatalf("the chain is not who consented then who acted: %v", got.Act)
	}
	if got.IsSession() {
		// A consented token is nobody's session: signing out of the
		// browser disconnects no agent.
		t.Error("a consented app token was minted as a session")
	}
	if got.Parent != "" {
		t.Errorf("a first mint named a parent: %q", got.Parent)
	}

	// A third link — an agent acting for an agent — is refused by the
	// mint, not truncated by it. A truncated chain would record a
	// delegation that never happened; the refusal records the attempt.
	_, _, err = ts.IssueForAgent("agent:second/obo-gr1", "watcher",
		RoleAnalyst, Scope{}, "second", "gr1", "https://here/mcp", "",
		[]string{"dana", "watcher", "second"}, "", time.Hour, now)
	if err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("a third link was minted: %v", err)
	}

	// An empty link names nobody, and a chain of empty names is not a
	// chain a record can read.
	_, _, err = ts.IssueForAgent("agent:watcher/obo-gr1", "dana",
		RoleAnalyst, Scope{}, "watcher", "gr1", "https://here/mcp", "",
		[]string{"", "watcher"}, "", time.Hour, now)
	if err == nil {
		t.Fatal("a chain with an empty link was minted")
	}

	// The on-behalf-of shape: parented to the consented token, so the
	// revocation cascade reaches it, and judged by that parent's lifetime.
	_, second, err := ts.IssueForAgent("agent:watcher/obo-gr1", "dana",
		RoleAnalyst, Scope{}, "watcher", "gr1", "https://here/mcp", got.ID,
		[]string{"dana", "watcher"}, "", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if !second.IsSession() || second.Parent != got.ID || second.Inherits == 0 {
		t.Errorf("the delegated token is not session-shaped on its parent: %+v", second)
	}
	// And revoking the parent reaches the child, which is the whole reason
	// the parent is named.
	if _, err := ts.Revoke(got.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.AuthenticateFor(secret, "https://here/mcp", now.Add(time.Second)); err == nil {
		t.Error("the parent's revocation did not reach the child")
	}
}
