// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"testing"
	"time"
)

// A read-only scope must refuse an action it has never heard of, or the scope
// widens every time somebody adds one.
func TestReadOnlyRefusesUnknownActions(t *testing.T) {
	if (Scope{ReadOnly: true}).AllowsAction(Action("some-action-added-later")) {
		t.Error("a read-only token permitted an unknown action; the scope " +
			"would widen every time an action is added")
	}
}

// A read-only token reads and writes nothing, whatever its role.
func TestAReadOnlyTokenOnlyReads(t *testing.T) {
	ro := Scope{ReadOnly: true}
	if err := CheckCredential(RoleAdmin, "/", ro, ActView, AreaSecurity); err != nil {
		t.Errorf("a read-only administrator's token could not read: %v", err)
	}
	for _, a := range []Action{ActTriage, ActRespond, ActApprove, ActTune, ActAssess, ActGrant} {
		if err := CheckCredential(RoleAdmin, "/", ro, a, AreaSecurity); err == nil {
			t.Errorf("a read-only token may %s", a)
		}
	}
}

// A session exchanged from a read-only token stays read-only: narrowing
// only ever narrows.
func TestASessionKeepsItsParentsScope(t *testing.T) {
	ts := &TokenStore{}
	secret, _, err := ts.IssueScoped("ro", "dana", RoleResponder, "/", time.Hour, RoleAdmin, Scope{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := (Scope{ReadOnly: true}).Narrow(Scope{}); !got.ReadOnly {
		t.Error("narrowing a read-only scope widened it")
	}
	_, child, err := ts.Exchange(secret, RoleResponder, "/", time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !child.Scope.ReadOnly {
		t.Error("a session exchanged from a read-only token can write")
	}
}
