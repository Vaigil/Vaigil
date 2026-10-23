// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vaigil/vaigil/internal/auth"
)

// Each job opens its own screens and no others.
func TestAJobOpensItsScreensAndNoOthers(t *testing.T) {
	for _, c := range []struct {
		job    string
		open   []string
		closed []string
	}{
		{"engineer",
			[]string{"/today", "/findings", "/security/cases", "/security/detections", "/security/automations"},
			[]string{"/people", "/settings", "/logs", "/security/events", "/security/hunt", "/workforce"}},
		{"vuln-manager",
			[]string{"/today", "/findings", "/security/vulns"},
			[]string{"/people", "/settings", "/logs", "/security/hunt", "/workforce"}},
		{"auditor",
			[]string{"/today", "/findings", "/security/cases", "/logs"},
			[]string{"/people", "/settings", "/security/hunt", "/security/signins", "/workforce"}},
	} {
		t.Run(c.job, func(t *testing.T) {
			srv, token := asJob(t, c.job)
			for _, path := range c.open {
				if w := get(t, srv, path, token); w.Code != http.StatusOK {
					t.Errorf("%s cannot open %s: %d", c.job, path, w.Code)
				}
			}
			for _, path := range c.closed {
				if w := get(t, srv, path, token); w.Code == http.StatusOK {
					t.Errorf("%s opened %s", c.job, path)
				}
			}
		})
	}
}

// Granting is a whole-store decision, whatever job somebody holds.
func TestAJobHolderCannotGrant(t *testing.T) {
	srv, token := asJob(t, "engineer")
	postForm(t, srv, "/people/grant", token, "principal=mallory&role=admin&resource=/")
	if srv.Policy.Evaluate("mallory", auth.ActView, "/").Allowed {
		t.Fatal("an engineer granted somebody the whole store")
	}
	postForm(t, srv, "/people/grant", token, "principal=mallory&role=admin&resource=/@security")
	if srv.Policy.Evaluate("mallory", auth.ActView, auth.AreaSecurity).Allowed {
		t.Error("an engineer granted somebody the security area")
	}
}

// The People screen grants a job, with an end, and shows it.
func TestThePeopleScreenGrantsAJobUntilADay(t *testing.T) {
	srv, token := setup(t)
	day := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	postForm(t, srv, "/people/grant", token, "new_principal=lee&role=job%3Aengineer&until="+day)
	if !srv.Policy.Evaluate("lee", auth.ActTune, auth.AreaSecurity).Allowed ||
		srv.Policy.Evaluate("lee", auth.ActTriage, auth.AreaSecurity).Allowed {
		t.Fatal("the engineer job was not granted as its bindings alone")
	}
	for _, b := range srv.Policy.Bindings {
		if b.Principal == "lee" && b.Expires == 0 {
			t.Errorf("a grant with an end day never ends: %+v", b)
		}
	}
	if body := get(t, srv, "/people", token).Body.String(); !strings.Contains(body, "until ") {
		t.Error("the People screen does not say when the grant ends")
	}
	// A day already gone is refused, not granted forever.
	postForm(t, srv, "/people/grant", token, "new_principal=old&role=viewer&until=2020-01-01")
	if srv.Policy.Evaluate("old", auth.ActView, "/").Allowed {
		t.Error("a grant ending in the past was made")
	}
}

// An auditor reads the log and the queue and changes nothing.
func TestAnAuditorReadsAndChangesNothing(t *testing.T) {
	srv, token := asJob(t, "auditor")
	if w := get(t, srv, "/logs", token); w.Code != http.StatusOK {
		t.Errorf("an auditor cannot read the log: %d", w.Code)
	}
	for _, path := range []string{"/findings/decide", "/security/cases/act", "/security/vulns/act"} {
		if w := postForm(t, srv, path, token, "id=x&do=note&text=x"); w.Code != http.StatusForbidden {
			t.Errorf("an auditor posted to %s: %d", path, w.Code)
		}
	}
}

// A viewer over everything reads the queue, not the audit log: the log
// needs an administrator, or an auditor granted it.
func TestAViewerDoesNotReadTheLog(t *testing.T) {
	srv, token := asRole(t, auth.RoleViewer)
	if w := get(t, srv, "/logs", token); w.Code == http.StatusOK {
		t.Error("a viewer opened the audit log")
	}
	if w := get(t, srv, "/findings", token); w.Code != http.StatusOK {
		t.Errorf("a viewer cannot read the queue: %d", w.Code)
	}
}

// An auditor's access has to end: the People screen will not grant it for ever.
func TestTheAuditorJobIsOnlyGrantedUntilADay(t *testing.T) {
	srv, token := setup(t)
	postForm(t, srv, "/people/grant", token, "new_principal=assessor&role=job%3Aauditor")
	if srv.Policy.Evaluate("assessor", auth.ActView, auth.AreaLog).Allowed {
		t.Fatal("an auditor was granted with no end")
	}
	day := time.Now().AddDate(0, 0, 30).Format("2006-01-02")
	postForm(t, srv, "/people/grant", token, "new_principal=assessor&role=job%3Aauditor&until="+day)
	if !srv.Policy.Evaluate("assessor", auth.ActView, auth.AreaLog).Allowed {
		t.Error("an auditor with an end day was not granted")
	}
}

// A permission is granted from the People screen like a role, shown as a
// permission, and removed the same way.
func TestAPermissionIsGrantedAndRemovedOnThePeopleScreen(t *testing.T) {
	srv, token := setup(t)
	w := postForm(t, srv, "/people/grant", token, "principal=ria&role=permission:approve&resource=/@security")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if !srv.Policy.Evaluate("ria", auth.ActApprove, auth.AreaSecurity).Allowed ||
		srv.Policy.Evaluate("ria", auth.ActView, "/").Allowed {
		t.Fatal("the grant was not one permission on one area")
	}
	body := get(t, srv, "/people", token).Body.String()
	if !strings.Contains(body, `approve <span class="hint">permission</span>`) || !strings.Contains(body, "<code>/@security</code>") ||
		!strings.Contains(body, "permission:tune") {
		t.Errorf("the screen does not show or offer permissions")
	}
	postForm(t, srv, "/people/grant", token, "principal=ria&role=permission:fly&resource=/")
	if srv.Policy.Evaluate("ria", auth.ActTune, auth.AreaSecurity).Allowed {
		t.Error("a made-up permission granted something")
	}
	postForm(t, srv, "/people/revoke", token, "principal=ria&role=approve&resource=/@security")
	if srv.Policy.Evaluate("ria", auth.ActApprove, auth.AreaSecurity).Allowed {
		t.Error("the permission was not removed")
	}
}

// A permission granted alone works through the person's own session, whose
// credential carries only their role; an administrator's credential capped
// to viewer does not gain what their role gives.
func TestAPermissionWorksThroughThePersonsOwnSession(t *testing.T) {
	srv, _ := setup(t)
	srv.Policy.Grant(auth.Binding{Principal: "ria", Role: auth.RoleViewer, Resource: "/"})
	srv.Policy.Grant(auth.Binding{Principal: "ria", Permission: auth.ActApprove, Resource: auth.AreaSecurity})
	tok, _, err := srv.Tokens.IssueSession("ria", "ria", auth.RoleViewer, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	approve := "id=x&do=act-approve&act=1"
	if w := postForm(t, srv, "/security/cases/act", tok, approve); w.Code == http.StatusForbidden {
		t.Errorf("approve did not reach approving an act: %d", w.Code)
	}
	if w := get(t, srv, "/people", tok); w.Code != http.StatusForbidden {
		t.Errorf("approve opened People: %d", w.Code)
	}
	capped, _, err := srv.Tokens.IssueSession("capped", "editor", auth.RoleViewer, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if w := postForm(t, srv, "/security/cases/act", capped, approve); w.Code != http.StatusForbidden {
		t.Errorf("an administrator's viewer credential approved an act: %d", w.Code)
	}
}
