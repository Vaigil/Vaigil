// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quilzo/vaigil/internal/auth"
)

// Signing in for the first time lands on the getting started screen.
func TestSigningInTheFirstTimeLandsOnGettingStarted(t *testing.T) {
	srv, token := setup(t)

	r := httptest.NewRequest(http.MethodPost, "/signin",
		strings.NewReader("token="+token))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if got := w.Header().Get("Location"); got != "/start" {
		t.Errorf("signing in sent them to %q, want /start", got)
	}
}

// And having finished with it, they land on Today.
//
// The redirect hangs off signing in rather than off "/": making the landing
// page answer differently depending on a cookie means a bookmark, a shared
// link and every script that fetches the root get a redirect instead of the
// thing they asked for.
func TestSigningInAfterwardsLandsOnToday(t *testing.T) {
	srv, token := setup(t)
	r := httptest.NewRequest(http.MethodPost, "/signin",
		strings.NewReader("token="+token))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.AddCookie(&http.Cookie{Name: StartDismissedCookie, Value: "1"})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if got := w.Header().Get("Location"); got != "/today" {
		t.Errorf("a returning person was sent to %q, want /today", got)
	}
}

// The root is Today, whatever the onboarding cookie says.
func TestTheLandingPageIsNotConditional(t *testing.T) {
	srv, token := setup(t)
	if w := get(t, srv, "/", token); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/today" {
		t.Errorf("GET / gave %d to %q; the root is Today", w.Code, w.Header().Get("Location"))
	}
}

// The checklist reports what is in the store, not a fixed script.
//
// The whole reason this screen reads the store is that a tour cannot say
// anything true about an installation it has not looked at.
func TestTheChecklistReadsTheStore(t *testing.T) {
	srv, token := setup(t)
	srv.Feeds = &FeedsAdmin{List: func() ([]FeedView, error) {
		return []FeedView{{Name: "okta"}, {Name: "old", Off: true}}, nil
	}}
	body := get(t, srv, "/start", token).Body.String()
	if !strings.Contains(body, "1 feed") {
		t.Error("the first step does not report the one feed switched on")
	}
	// Nobody else holds a role, so that step is not done.
	if strings.Contains(body, "other person") {
		t.Error("the people step reports done with nobody else in the policy")
	}
	if err := srv.Policy.Grant(auth.Binding{Principal: "sam", Role: auth.RoleViewer, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	if body := get(t, srv, "/start", token).Body.String(); !strings.Contains(body, "1 other person") {
		t.Error("the people step does not count somebody granted a role")
	}
	// And what will refuse them is named before they meet it.
	for _, gate := range []string{"A second factor", "Two people for an act", "Two administrators"} {
		if !strings.Contains(body, gate) {
			t.Errorf("the screen never mentions %q, so the first refusal "+
				"will be a surprise", gate)
		}
	}
}

// Dismissing it is a state change on this origin, so it is POST-only and
// authenticated.
func TestDismissingGettingStartedIsGuarded(t *testing.T) {
	srv, _ := setup(t)

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/start/done", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /start/done gave %d, want 405", w.Code)
	}

	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/start/done", nil))
	for _, c := range w.Result().Cookies() {
		if c.Name == StartDismissedCookie {
			t.Error("an unauthenticated request dismissed the screen")
		}
	}
}
