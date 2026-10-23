// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/vaigil/internal/auth"
	"github.com/quilzo/vaigil/internal/automate"
	"github.com/quilzo/vaigil/internal/dual"
	"github.com/quilzo/vaigil/internal/incident"
)

// waitingCase is a case with an act on another platform waiting, asked for
// by dana.
func waitingCase(t *testing.T, srv *Server, token string) map[string]*incident.Incident {
	t.Helper()
	kept := wireCases(srv)
	caseAct(t, srv, token, url.Values{"do": {"declare"}, "title": {"Stolen laptop"}, "grade": {"sev2"}})
	for _, i := range kept {
		i.Acts = append(i.Acts, incident.Act{ID: 1, Action: "okta-suspend-user", Title: "Suspend in Okta",
			Target: "okta:00u1", State: incident.ActRequested,
			Requested: incident.Moment{By: "dana", At: time.Now().UTC(), Why: "sessions from two countries"}})
	}
	return kept
}

// Approvals lists what waits for the person looking: an act somebody else
// asked for, a run an automation held, a change waiting for a second
// administrator, each linked to where it is decided.
func TestApprovalsListsWhatWaitsForThisPerson(t *testing.T) {
	srv, token := setup(t)
	waitingCase(t, srv, token)
	e := wireAutomations(t, srv)
	e.Save(automate.Rule{Name: "leaver", Enabled: true, Mode: "ask", When: "finding",
		Then: []automate.Step{{Action: "end-sessions"}}}, "boss")
	if _, err := e.Handle(automate.Event{Kind: "finding", Subject: "dee", Summary: "dee left in March"}); err != nil {
		t.Fatal(err)
	}
	srv.Policy.Grant(auth.Binding{Principal: "lee", Role: auth.RoleAdmin, Resource: "/"})
	if _, err := srv.Dual.Store.Propose(dual.Grant, "make sam an administrator", nil, "cover", "lee", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	page := getPage(t, srv, "/approvals", token)
	for _, want := range []string{"Suspend in Okta on okta:00u1", "asked by dana", "Let leaver act",
		"dee left in March", "make sam an administrator", "/people#pending"} {
		if !strings.Contains(page, want) {
			t.Errorf("Approvals does not show %q", want)
		}
	}
}

// Nobody is offered what they asked for themselves, and a viewer is offered
// nothing to decide.
func TestApprovalsOffersNobodyTheirOwnRequest(t *testing.T) {
	srv, token := setup(t)
	waitingCase(t, srv, token)
	srv.Policy.Grant(auth.Binding{Principal: "dana", Role: auth.RoleResponder, Resource: "/"})
	dana, _, _ := srv.Tokens.IssueSession("d", "dana", auth.RoleResponder, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if page := getPage(t, srv, "/approvals", dana); strings.Contains(page, "Suspend in Okta") {
		t.Error("dana is offered approving the act she asked for")
	}
	srv.Policy.Grant(auth.Binding{Principal: "vi", Role: auth.RoleViewer, Resource: "/"})
	vi, _, _ := srv.Tokens.IssueSession("v", "vi", auth.RoleViewer, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if page := getPage(t, srv, "/approvals", vi); strings.Contains(page, "Suspend in Okta") || !strings.Contains(page, "Nothing is waiting for you") {
		t.Error("a viewer is offered something to decide")
	}
}

// Today puts what is waiting first, then what is wrong, each figure a link
// to its records.
func TestTodayShowsWhatWaitsThenWhatIsWrong(t *testing.T) {
	srv, token := fullyWired(t)
	waitingCase(t, srv, token)
	page := getPage(t, srv, "/today", token)
	waiting, wrong := strings.Index(page, "Waiting for you"), strings.Index(page, "In your parts of the estate")
	if waiting < 0 || wrong < 0 || waiting > wrong {
		t.Fatal("Today does not put what is waiting before what is wrong")
	}
	for _, want := range []string{"Suspend in Okta on okta:00u1", `href="/findings"`, "Finding to triage", `href="/security/cases"`, "Case open"} {
		if !strings.Contains(page, want) {
			t.Errorf("Today does not show %q", want)
		}
	}
	// A signed message from the last thing done shows.
	if body := get(t, srv, signFlash(srv.flashKey, "/today?m=Approved."), token).Body.String(); !strings.Contains(body, "Approved.") {
		t.Error("Today does not show the message it was sent with")
	}
}
