// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/vaigil/internal/auth"
)

// Each role gets what it needs to do its job, and nothing above it.
//
// The new screens were gated one at a time, by hand, and nothing checked the
// result. That is the same shape as every gap this project has had: a decision
// made correctly in nineteen places and forgotten in the twentieth, invisible
// because the twentieth still renders.
//
// So the expectation is written out per role, and the test drives a real
// server as that role. A screen added later fails here until somebody decides
// which roles it is for — which is the point.
func TestEachRoleReachesItsOwnWorkAndNoMore(t *testing.T) {
	// What each role should be able to open. Cumulative: the ladder means a
	// responder gets everything an analyst gets, so each row lists only what
	// that rung adds.
	adds := map[auth.Role][]string{
		auth.RoleViewer: {
			"/today", "/approvals", "/findings", "/security/cases", "/security/risk",
			"/security/indicators", "/security/detections", "/security/automations",
			"/security/feeds", "/security/vulns", "/passkeys", "/profile", "/start", "/find",
		},
		auth.RoleAnalyst:   {"/security/events", "/security/hunt", "/security/signins"},
		auth.RoleResponder: {},
		auth.RoleAdmin:     {"/workforce", "/people", "/provisioning", "/sso", "/settings", "/logs"},
	}

	// Everything, so "and no more" can be checked rather than assumed.
	var everything []string
	for _, paths := range adds {
		everything = append(everything, paths...)
	}

	ladder := []auth.Role{
		auth.RoleViewer, auth.RoleAnalyst, auth.RoleResponder, auth.RoleAdmin,
	}
	for i, role := range ladder {
		want := map[string]bool{}
		for _, r := range ladder[:i+1] {
			for _, path := range adds[r] {
				want[path] = true
			}
		}

		t.Run(string(role), func(t *testing.T) {
			srv, token := asRole(t, role)
			for _, path := range everything {
				w := get(t, srv, path, token)
				allowed := w.Code == http.StatusOK ||
					w.Code == http.StatusServiceUnavailable
				switch {
				case want[path] && !allowed:
					t.Errorf("a %s cannot open %s (%d), and needs to",
						role, path, w.Code)
				case !want[path] && allowed:
					t.Errorf("a %s can open %s and should not", role, path)
				}
			}
		})
	}
}

// The navigation shows a person only what they can open.
//
// The other half of the same rule. A menu entry that answers "you cannot do
// that here" is a door drawn on a wall, and it is also a list of the
// administrative screens worth going after.
func TestTheNavigationOffersNothingThatWouldBeRefused(t *testing.T) {
	for _, role := range []auth.Role{
		auth.RoleViewer, auth.RoleAnalyst, auth.RoleResponder, auth.RoleAdmin,
	} {
		t.Run(string(role), func(t *testing.T) {
			srv, token := asRole(t, role)
			body := get(t, srv, "/profile", token).Body.String()

			for _, d := range destinations {
				offered := strings.Contains(body, `href="`+d.Path+`"`)
				w := get(t, srv, d.Path, token)
				reachable := w.Code == http.StatusOK ||
					w.Code == http.StatusServiceUnavailable
				if offered && !reachable {
					t.Errorf("the navigation offers %s to a %s and it answers %d",
						d.Path, role, w.Code)
				}
				if !offered && reachable {
					t.Errorf("a %s can open %s and is never shown a link to it",
						role, d.Path)
				}
			}
		})
	}
}

// A viewer cannot write, by any route.
//
// Checked against the write endpoints rather than the screens, because the
// screens hiding a button is presentation and the handler refusing is the
// control. A product that only hides the button has no control at all.
func TestAReaderIsRefusedByEveryWriteEndpoint(t *testing.T) {
	srv, token := asRole(t, auth.RoleViewer)

	writes := []string{
		"/findings/decide", "/security/cases/act", "/security/automations/act",
		"/security/detections/act", "/security/feeds/act", "/security/indicators/act",
		"/security/vulns/act", "/security/signins/act", "/security/signins/unlock",
		"/workforce/sync", "/workforce/reminders/act",
		"/people/grant", "/people/revoke", "/people/enrol", "/people/pending",
		"/sessions/revoke", "/sso/act", "/provisioning/act", "/settings/save",
	}
	sort.Strings(writes)

	for _, path := range writes {
		w := post(t, srv, path, token)
		if w.Code == http.StatusOK || w.Code == http.StatusSeeOther {
			t.Errorf("a viewer posted to %s and was not refused (%d)",
				path, w.Code)
		}
	}
}

// A read-only token cannot write, whatever its principal may do.
func TestAReadOnlyTokenCannotWriteThroughTheInterface(t *testing.T) {
	srv, _ := setup(t)

	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{
		Principal: "ada", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	ts := &auth.TokenStore{}
	// Issued scoped, not issued and then mutated: the store holds the token and
	// a copy returned to the caller is not it.
	secret, _, err := ts.IssueScoped("ci", "ada", auth.RoleAdmin, "/",
		time.Hour, auth.RoleAdmin, auth.Scope{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	srv.Policy, srv.Tokens = pol, ts
	// In the grace before two factors are compulsory, the one time a token
	// alone reaches the admin, its limits still hold.
	srv.MFAFrom = time.Now().Add(time.Hour)

	// Reading is what it is for.
	if w := get(t, srv, "/today", secret); w.Code != http.StatusOK {
		t.Fatalf("a read-only token could not read: %d", w.Code)
	}

	// Writing is what it is not for. Every one of these is an action an admin
	// may take and this credential may not.
	for _, path := range []string{
		"/people/grant", "/settings/save", "/findings/decide",
		"/security/cases/act", "/security/automations/act",
	} {
		w := post(t, srv, path, secret)
		if w.Code != http.StatusForbidden {
			t.Errorf("POST %s with a read-only token answered %d, want 403",
				path, w.Code)
		}
	}

	// And the refusal says why.
	w := post(t, srv, "/people/grant", secret)
	if !strings.Contains(w.Body.String(), "read-only") {
		t.Error("the refusal does not say the token is read-only, so somebody " +
			"will go asking for a wider role they already have")
	}
}

// A narrow token stays narrow in the browser, too.
//
// Every decision asks about the credential as well as the person: a token
// issued `--role viewer` to an administrator reads, and grants nobody
// anything.
func TestANarrowTokenCannotEscalateThroughTheInterface(t *testing.T) {
	srv, _ := setup(t)

	// "editor" is an admin in the policy. This token is not.
	reader, _, err := srv.Tokens.IssueSession("ci", "editor", auth.RoleViewer, "/",
		time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}

	// Reading is what a viewer may do.
	if w := get(t, srv, "/today", reader); w.Code != http.StatusOK {
		t.Fatalf("a viewer token could not read Today: %d", w.Code)
	}

	// Everything above reading is not, whatever the principal holds.
	for _, path := range []string{"/people", "/settings"} {
		if w := get(t, srv, path, reader); w.Code != http.StatusForbidden {
			t.Errorf("GET %s with a viewer token gave %d, want 403 — the "+
				"screen is an administration screen and the credential is "+
				"not an administrator's", path, w.Code)
		}
	}

	// And the write that made it an escalation rather than a disclosure.
	form := url.Values{
		"new_principal": {"mallory"},
		"role":          {"admin"},
		"resource":      {"/"},
	}
	req := httptest.NewRequest(http.MethodPost, "/people/grant",
		strings.NewReader(form.Encode()))
	req.Header.Set("Authorization", "Bearer "+reader)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code == http.StatusSeeOther {
		t.Error("a viewer token was allowed to grant a role")
	}
	for _, b := range srv.Policy.Snapshot() {
		if b.Principal == "mallory" {
			t.Fatalf("a viewer token granted %s the %s role — the policy was "+
				"asked about the person and never about the credential",
				b.Principal, b.Role)
		}
	}
}

// The area a token is issued for is honoured here as well: a token for the
// security area works the queue and administers nothing.
func TestATokenScopedToAnAreaDoesNotReachTheWholeStore(t *testing.T) {
	srv, _ := setup(t)

	scoped, _, err := srv.Tokens.IssueSession("soc-bot", "editor", auth.RoleAdmin,
		auth.AreaSecurity, time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	// The administration screens are asked about the root, which the
	// security area does not cover.
	if w := get(t, srv, "/people", scoped); w.Code != http.StatusForbidden {
		t.Errorf("a token scoped to the security area reached /people with %d, want 403",
			w.Code)
	}
}
