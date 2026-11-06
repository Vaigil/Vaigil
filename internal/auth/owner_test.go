// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"strings"
	"testing"
)

func ownedBy(t *testing.T, owner string) *Policy {
	t.Helper()
	p := &Policy{}
	for _, b := range []Binding{
		{Principal: owner, Role: RoleAdmin, Resource: "/"},
		{Principal: "lee", Role: RoleAdmin, Resource: "/"},
	} {
		if err := p.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.SetOwner(owner); err != nil {
		t.Fatal(err)
	}
	return p
}

// Nothing another administrator can do to the policy removes the Owner.
func TestTheOwnerCannotBeTakenAway(t *testing.T) {
	cases := map[string]func(p *Policy){
		"revoked": func(p *Policy) { p.Revoke("dana", RoleAdmin, "/") },
		"denied": func(p *Policy) {
			_ = p.Grant(Binding{Principal: "dana", Role: RoleViewer, Resource: "/@log", Deny: true})
		},
		"given an end date": func(p *Policy) {
			p.Revoke("dana", RoleAdmin, "/")
			_ = p.Grant(Binding{Principal: "dana", Role: RoleAdmin, Resource: "/", Expires: 1})
		},
		"narrowed to one area": func(p *Policy) {
			p.Revoke("dana", RoleAdmin, "/")
			_ = p.Grant(Binding{Principal: "dana", Role: RoleAdmin, Resource: "/@security"})
		},
	}
	for name, change := range cases {
		p := ownedBy(t, "dana")
		change(p)
		if err := p.CheckOwner(); err == nil || !strings.Contains(err.Error(), "Owner") {
			t.Errorf("the Owner %s: %v", name, err)
		}
	}
	// Changing anybody else is untouched by the rule.
	p := ownedBy(t, "dana")
	p.Revoke("lee", RoleAdmin, "/")
	if err := p.CheckOwner(); err != nil {
		t.Errorf("revoking somebody else: %v", err)
	}
}

// Ownership goes only to somebody who already administers everything, with
// no end date, and a refused SetOwner leaves the Owner as it was.
func TestOwnershipGoesOnlyToAWholeStoreAdministrator(t *testing.T) {
	p := ownedBy(t, "dana")
	_ = p.Grant(Binding{Principal: "pat", Role: RoleAnalyst, Resource: "/"})
	if err := p.SetOwner("pat"); err == nil {
		t.Fatal("an analyst was made the Owner")
	}
	if p.OwnerName() != "dana" {
		t.Errorf("a refused transfer changed the Owner to %q", p.OwnerName())
	}
	if err := p.SetOwner("lee"); err != nil || p.OwnerName() != "lee" {
		t.Errorf("to another administrator: %v %q", err, p.OwnerName())
	}
	// A store with no Owner has nothing to keep.
	if err := (&Policy{}).CheckOwner(); err != nil {
		t.Errorf("no Owner: %v", err)
	}
}
