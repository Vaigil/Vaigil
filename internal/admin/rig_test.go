// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/vaigil/internal/auth"
	"github.com/quilzo/vaigil/internal/config"
	"github.com/quilzo/vaigil/internal/dual"
	"github.com/quilzo/vaigil/internal/telemetry"
)

// The rig every console test starts from.

// setup is a console with one administrator, editor, signed in with a
// passkey: the console takes two factors on every request, and a test not
// about signing in should not be stopped at the door.
func setup(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{
		Principal: "editor", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	ts := &auth.TokenStore{}
	secret, _, err := ts.IssueSession("test", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(pol, ts)
	if err != nil {
		t.Fatal(err)
	}
	srv.Dual = &Dual{Store: &dual.Store{Path: filepath.Join(dir, "dual.json")}}
	return srv, secret
}

// fullyWired is setup with the capabilities a screen test reads connected,
// the way the command line connects them, with fixtures in place of
// subsystems that would need a network.
func fullyWired(t *testing.T) (*Server, string) {
	t.Helper()
	srv, token := setup(t)
	srv.Passkeys = &Passkeys{Save: func(*Passkeys) error { return nil }}
	cfg := config.New()
	srv.Settings = &Settings{
		Load: func() (*config.Config, error) { return cfg, nil },
		Save: func(*config.Config) error { return nil },
	}
	// A queue with something in it, so the findings screens render rows,
	// filters and a detail page rather than only their empty states.
	srv.Findings = newFakeRegister(
		detectionFinding("admin-dana", "failed sign-in", telemetry.SeverityHigh),
	).wire()
	return srv, token
}

// tokenSignIn is setup for a test about signing in with a token, or about
// holding one: the token is a long-lived one for editor, and the store is
// in the grace before two factors are compulsory, the one state in which a
// token alone still reaches the admin.
func tokenSignIn(t *testing.T) (*Server, string) {
	t.Helper()
	srv, _ := setup(t)
	secret, _, err := srv.Tokens.Issue("cli", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	srv.MFAFrom = time.Now().Add(14 * 24 * time.Hour)
	return srv, secret
}

func get(t *testing.T, srv *Server, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func stylesheet(t *testing.T) string {
	t.Helper()
	b, err := assets.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// asJob signs in as somebody holding one job and nothing else.
func asJob(t *testing.T, job string) (*Server, string) {
	t.Helper()
	srv, _ := fullyWired(t)
	j, ok := auth.JobNamed(job)
	if !ok {
		t.Fatalf("no job %q", job)
	}
	pol := &auth.Policy{}
	top := auth.RoleViewer
	for _, b := range j.Bindings {
		b.Principal = "worker"
		if err := pol.Grant(b); err != nil {
			t.Fatal(err)
		}
		if b.Role.AtLeast(top) {
			top = b.Role
		}
	}
	ts := &auth.TokenStore{}
	secret, _, err := ts.IssueSession("test", "worker", top, "/", time.Hour, top, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	srv.Policy, srv.Tokens = pol, ts
	return srv, secret
}

func getPage(t *testing.T, srv *Server, path, token string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w.Body.String()
}

// asRole builds a server and a credential for one rung of the ladder.
func asRole(t *testing.T, role auth.Role) (*Server, string) {
	t.Helper()
	srv, _ := fullyWired(t)

	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{
		Principal: "someone", Role: role, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	ts := &auth.TokenStore{}
	secret, _, err := ts.IssueSession("test", "someone", role, "/", time.Hour, role, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	srv.Policy, srv.Tokens = pol, ts
	return srv, secret
}

// post makes a state-changing request the way a browser would.
//
// Sec-Fetch-Site is set because the CSRF middleware refuses anything without
// it, and a test that got 403 from the middleware would pass while telling us
// nothing about the permission underneath.
func post(t *testing.T, srv *Server, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path,
		strings.NewReader("name=x&type=x&page=x&key=x&id=x&to=dark"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// cookieFrom returns the session cookie a response set.
func cookieFrom(w *httptest.ResponseRecorder) string {
	for _, c := range w.Result().Cookies() {
		if c.Name == "vaigil_token" {
			return c.Value
		}
	}
	return ""
}

// signInPost submits the form from one address, as a browser on this site.
func signInPost(srv *Server, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/signin",
		strings.NewReader("token="+url.QueryEscape(token)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.RemoteAddr = "203.0.113.9:5555"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func postForm(t *testing.T, srv *Server, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}
