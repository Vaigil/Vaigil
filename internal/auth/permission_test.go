// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"strings"
	"testing"
	"time"
)

// With no permission granted, each follows the rung that holds it.
func TestAPermissionFollowsItsRungByDefault(t *testing.T) {
	p := &Policy{}
	p.Grant(Binding{Principal: "ana", Role: RoleAnalyst, Resource: "/"})
	p.Grant(Binding{Principal: "res", Role: RoleResponder, Resource: "/"})
	p.Grant(Binding{Principal: "ed", Role: RoleAdmin, Resource: "/"})
	for _, c := range []struct {
		who    string
		action Action
		want   bool
	}{
		{"ana", ActApprove, false}, {"ana", ActTune, false}, {"ana", ActAssess, false},
		{"res", ActApprove, true}, {"res", ActTune, false}, {"res", ActAssess, false},
		{"ed", ActApprove, true}, {"ed", ActTune, true}, {"ed", ActAssess, true},
	} {
		if got := p.Evaluate(c.who, c.action, AreaSecurity).Allowed; got != c.want {
			t.Errorf("%s %s: %v", c.who, c.action, got)
		}
	}
}

// Granted alone, a permission reaches what it was granted on and nothing
// else.
func TestAPermissionGrantedAloneReachesOnlyItsResource(t *testing.T) {
	p := &Policy{}
	if err := p.Grant(Binding{Principal: "mo", Permission: ActTune, Resource: AreaSecurity}); err != nil {
		t.Fatal(err)
	}
	d := p.Evaluate("mo", ActTune, AreaSecurity)
	if !d.Allowed || !strings.Contains(d.Reason, "the tune permission on /@security") {
		t.Fatalf("%+v", d)
	}
	for _, c := range []struct {
		action   Action
		resource string
	}{
		{ActTune, AreaLog},
		{ActApprove, AreaSecurity},
		{ActView, "/"},
		{ActTriage, AreaSecurity},
	} {
		if p.Evaluate("mo", c.action, c.resource).Allowed {
			t.Errorf("tune on the security area allowed %s on %s", c.action, c.resource)
		}
	}
}

// A permission is a binding like any other: it ends, it can be denied, and
// it reaches a guarded area only when granted on the area.
func TestAPermissionEndsIsDeniedAndRespectsGuardedAreas(t *testing.T) {
	p := &Policy{}
	p.Grant(Binding{Principal: "mo", Permission: ActApprove, Resource: AreaSecurity,
		Expires: time.Now().Add(-time.Minute).Unix()})
	if p.Evaluate("mo", ActApprove, AreaSecurity).Allowed {
		t.Error("an expired permission allowed")
	}
	p.Grant(Binding{Principal: "ed", Role: RoleAdmin, Resource: "/"})
	p.Grant(Binding{Principal: "ed", Permission: ActApprove, Resource: AreaSecurity, Deny: true})
	if p.Evaluate("ed", ActApprove, AreaSecurity).Allowed {
		t.Error("a denied permission did not stop an administrator")
	}
	if !p.Evaluate("ed", ActTune, AreaSecurity).Allowed || !p.Evaluate("ed", ActRespond, AreaSecurity).Allowed {
		t.Error("a denied permission stopped more than itself")
	}
	p.Grant(Binding{Principal: "sus", Role: RoleViewer, Resource: "/", Deny: true})
	p.Grant(Binding{Principal: "sus", Permission: ActApprove, Resource: AreaSecurity})
	if p.Evaluate("sus", ActApprove, AreaSecurity).Allowed {
		t.Error("a suspended person kept a permission")
	}
	p.Grant(Binding{Principal: "gi", Permission: ActApprove, Resource: "/"})
	if p.Evaluate("gi", ActApprove, AreaLog+"/2026").Allowed {
		t.Error("a permission over everything reached the guarded log")
	}
}

func TestAPermissionIsGrantedAndRevokedByName(t *testing.T) {
	p := &Policy{}
	for _, b := range []Binding{
		{Principal: "mo", Permission: "fly"},
		{Principal: "mo", Permission: ActApprove, Role: RoleViewer},
		{Principal: "mo", Permission: ActView},
	} {
		if err := p.Grant(b); err == nil {
			t.Errorf("%+v was granted", b)
		}
	}
	p.Grant(Binding{Principal: "mo", Permission: ActAssess, Resource: AreaSecurity})
	if err := p.Grant(Binding{Principal: "mo", Permission: ActAssess, Resource: AreaSecurity}); err == nil {
		t.Error("the same permission was granted twice")
	}
	if n := p.RevokeNamed("mo", "assess", AreaSecurity); n != 1 || p.Evaluate("mo", ActAssess, AreaSecurity).Allowed {
		t.Errorf("revoked %d", n)
	}
	if _, ok := PermissionNamed("tune"); !ok {
		t.Error("a permission was not found by name")
	}
}

// A credential caps a permission granted on its own by its path and its
// limits; a permission that comes from a role is capped by the role, as
// everything else is.
func TestATokenCapsAPermissionByItsPathAndLimits(t *testing.T) {
	p := &Policy{}
	p.Grant(Binding{Principal: "ria", Role: RoleViewer, Resource: "/"})
	p.Grant(Binding{Principal: "ria", Permission: ActApprove, Resource: AreaSecurity})
	p.Grant(Binding{Principal: "ed", Role: RoleAdmin, Resource: "/"})
	d := p.Evaluate("ria", ActApprove, AreaSecurity)
	if err := CheckGranted(d, RoleViewer, "/", Scope{}, ActApprove, AreaSecurity); err != nil {
		t.Errorf("ria's own viewer token could not use what she was granted: %v", err)
	}
	if err := CheckGranted(d, RoleViewer, "/", Scope{ReadOnly: true}, ActApprove, AreaSecurity); err == nil {
		t.Error("a read-only token approved")
	}
	if err := CheckGranted(d, RoleViewer, AreaLog, Scope{}, ActApprove, AreaSecurity); err == nil {
		t.Error("a token scoped to the log reached the security area")
	}
	d = p.Evaluate("ed", ActApprove, AreaSecurity)
	if err := CheckGranted(d, RoleViewer, "/", Scope{}, ActApprove, AreaSecurity); err == nil {
		t.Error("an administrator's viewer token approved")
	}
}
