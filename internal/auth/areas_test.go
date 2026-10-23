// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"testing"
	"time"
)

func withJob(t *testing.T, p *Policy, who, job string) {
	t.Helper()
	j, ok := JobNamed(job)
	if !ok {
		t.Fatalf("no job %q", job)
	}
	for _, b := range j.Bindings {
		b.Principal = who
		if err := p.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
}

// A job is its bindings and nothing else: an engineer tunes and reads the
// queue, and decides no finding and grants nobody anything.
func TestAJobCoversItsAreaAndNothingElse(t *testing.T) {
	p := &Policy{}
	withJob(t, p, "sam", "engineer")
	for _, ok := range []struct {
		act Action
		res string
	}{{ActTune, AreaSecurity}, {ActView, AreaSecurity}} {
		if !p.Evaluate("sam", ok.act, ok.res).Allowed {
			t.Errorf("an engineer cannot %s on %s", ok.act, ok.res)
		}
	}
	for _, no := range []struct {
		act Action
		res string
	}{{ActTriage, AreaSecurity}, {ActApprove, AreaSecurity}, {ActAssess, AreaSecurity},
		{ActView, AreaLog}, {ActGrant, "/"}, {ActToken, "/"}} {
		if p.Evaluate("sam", no.act, no.res).Allowed {
			t.Errorf("an engineer may %s on %s", no.act, no.res)
		}
	}

	withJob(t, p, "lee", "vuln-manager")
	if !p.Evaluate("lee", ActAssess, AreaSecurity).Allowed || !p.Evaluate("lee", ActView, AreaSecurity).Allowed {
		t.Error("a vulnerability manager cannot decide vulnerabilities or read the queue")
	}
	if p.Evaluate("lee", ActTune, AreaSecurity).Allowed || p.Evaluate("lee", ActTriage, AreaSecurity).Allowed {
		t.Error("a vulnerability manager holds more than it was given")
	}
}

// A role over everything covers the security area, and the ladder decides
// how far: a viewer reads, an analyst triages, a responder acts and
// approves, and only an administrator grants.
func TestTheLadderCoversTheSecurityArea(t *testing.T) {
	p := &Policy{}
	for _, r := range Roles {
		_ = p.Grant(Binding{Principal: string(r), Role: r, Resource: "/"})
	}
	for _, c := range []struct {
		who  Role
		may  []Action
		mayn []Action
	}{
		{RoleViewer, []Action{ActView}, []Action{ActTriage, ActRespond, ActApprove, ActTune, ActAssess, ActGrant}},
		{RoleAnalyst, []Action{ActView, ActTriage}, []Action{ActRespond, ActApprove, ActTune, ActAssess, ActGrant}},
		{RoleResponder, []Action{ActView, ActTriage, ActRespond, ActApprove}, []Action{ActTune, ActAssess, ActGrant}},
		{RoleAdmin, []Action{ActView, ActTriage, ActRespond, ActApprove, ActTune, ActAssess, ActGrant}, nil},
	} {
		for _, a := range c.may {
			if !p.Evaluate(string(c.who), a, AreaSecurity).Allowed {
				t.Errorf("a %s cannot %s", c.who, a)
			}
		}
		for _, a := range c.mayn {
			if p.Evaluate(string(c.who), a, AreaSecurity).Allowed {
				t.Errorf("a %s may %s", c.who, a)
			}
		}
	}
	// And a deny on everything denies the area with it.
	_ = p.Grant(Binding{Principal: "admin", Role: RoleAdmin, Resource: "/", Deny: true})
	if p.Evaluate("admin", ActGrant, AreaSecurity).Allowed {
		t.Error("a deny on everything left the area open")
	}
}

func TestAGrantEndsWhenItExpires(t *testing.T) {
	p := &Policy{}
	_ = p.Grant(Binding{Principal: "cy", Role: RoleAdmin, Resource: AreaSecurity,
		Expires: time.Now().Add(-time.Minute).Unix()})
	_ = p.Grant(Binding{Principal: "di", Role: RoleAdmin, Resource: AreaSecurity,
		Expires: time.Now().Add(time.Hour).Unix()})
	if p.Evaluate("cy", ActView, AreaSecurity).Allowed {
		t.Error("an expired grant still works")
	}
	if !p.Evaluate("di", ActView, AreaSecurity).Allowed {
		t.Error("a grant that has not expired does not work")
	}
	// An expired deny no longer denies.
	_ = p.Grant(Binding{Principal: "di", Role: RoleViewer, Resource: "/", Deny: true,
		Expires: time.Now().Add(-time.Minute).Unix()})
	if !p.Evaluate("di", ActView, AreaSecurity).Allowed {
		t.Error("an expired deny still denies")
	}
}

// The audit log is reached from everything only as administrator. A viewer
// reads the queue, not the record of who did what; somebody who should read
// it is granted the area itself, and an auditor's access ends.
func TestAWholeRoleBelowAdministratorDoesNotReachTheLog(t *testing.T) {
	p := &Policy{}
	for _, r := range []Role{RoleViewer, RoleAnalyst, RoleResponder} {
		_ = p.Grant(Binding{Principal: string(r), Role: r, Resource: "/"})
		for _, area := range []string{AreaLog, AreaLog + "/2026"} {
			if d := p.Evaluate(string(r), ActView, area); d.Allowed {
				t.Errorf("a %s over everything reads %s: %s", r, area, d.Reason)
			}
		}
		if !p.Evaluate(string(r), ActView, AreaSecurity).Allowed {
			t.Errorf("a %s over everything cannot read the queue", r)
		}
	}
	withJob(t, p, "aud", "auditor")
	if !p.Evaluate("aud", ActView, AreaLog).Allowed || !p.Evaluate("aud", ActView, AreaSecurity).Allowed {
		t.Error("an auditor cannot read the log and the queue")
	}
	for _, c := range []struct {
		act Action
		on  string
	}{{ActTriage, AreaSecurity}, {ActTriage, AreaLog}, {ActGrant, "/"}} {
		if p.Evaluate("aud", c.act, c.on).Allowed {
			t.Errorf("an auditor may %s on %s", c.act, c.on)
		}
	}
	if j, _ := JobNamed("auditor"); !j.Ends {
		t.Error("an auditor's access does not end by itself")
	}
	// A deny over everything still covers the log: suspension must
	// outrank a grant on the area itself.
	_ = p.Grant(Binding{Principal: "aud", Role: RoleViewer, Resource: "/", Deny: true})
	if p.Evaluate("aud", ActView, AreaLog).Allowed {
		t.Error("a deny over everything left the log open")
	}
}
