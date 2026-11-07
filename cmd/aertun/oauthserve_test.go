// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/config"
	"github.com/aertun/aertun/internal/dpop"
	"github.com/aertun/aertun/internal/macaroon"
	"github.com/aertun/aertun/internal/oauthas"
)

// The origin the OAuth server names is the one the operator chose, not the
// one the process listens on. The authorization-server metadata, the
// protected-resource metadata and the audience the exchange accepts all
// derive from the same function, so behind a proxy they cannot disagree.
func TestTheOAuthOriginFollowsTheOperatorNotTheListener(t *testing.T) {
	cases := []struct {
		name     string
		baseURL  string
		tlsProxy bool
		addr     string
		want     string
	}{
		{"laptop", "", false, "localhost:8080", "http://localhost:8080"},
		{"behind proxy", "", true, "127.0.0.1:8080", "https://127.0.0.1:8080"},
		{"named origin", "https://aertun.example.com", false, "127.0.0.1:8080",
			"https://aertun.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.New()
			if tc.baseURL != "" {
				cfg.Set("admin.base_url", tc.baseURL, "test", "test")
			}
			if tc.tlsProxy {
				cfg.Set("admin.behind_tls_proxy", "true", "test", "test")
			}
			got := publicOrigin(cfg, tc.addr)
			if got != tc.want {
				t.Errorf("publicOrigin = %q, want %q", got, tc.want)
			}
		})
	}
}

// Behind a proxy that hands requests on to 127.0.0.1:8080, with
// admin.base_url set, every place an origin is named names that one: the
// authorization server's issuer, the protected resource, the audience the
// exchange mints, the resource /mcp checks a token against, and the
// console's enrolment link. Without the setting, /mcp would check the
// proxied address, and the token minted for the public one would not open
// it — the disagreement this closes.
func TestOneOriginIsNamedEverywhereBehindAProxy(t *testing.T) {
	const base = "https://aertun.example.com"
	const inside = "http://127.0.0.1:8080"
	root, srv, _ := exchangeSite(t)
	cfg := config.New()
	cfg.Set("admin.base_url", base, "test", "test")
	srv.Origin = base

	mux := http.NewServeMux()
	mountMCP(mux, root, cfg, "127.0.0.1:8080")
	mountOAuthAS(mux, root, cfg, "127.0.0.1:8080", srv)
	get := func(path string) map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, inside+path, nil))
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
		return out
	}
	if iss := get(oauthas.MetadataPath)["issuer"]; iss != base {
		t.Errorf("the authorization server's issuer is %v", iss)
	}
	if res := get(wellKnownMCP)["resource"]; res != base+"/mcp" {
		t.Errorf("the protected resource is %v", res)
	}

	// The consented token, as the authorization server's token endpoint
	// mints it for its own resource; the exchange, reached at the proxied
	// address.
	person, _ := consentFor(t, root, srv, base, "triage")
	run := mintRun(t, root, "run-o", []string{"aertun_read"}, "", 0, -1)
	got := exchange(t, srv, inside, run, person)
	token, _ := got["access_token"].(string)
	if token == "" {
		t.Fatalf("the exchange: %v", got)
	}
	if _, ok := macaroon.Split(token); !ok {
		t.Fatalf("the exchange did not mint a run-shaped token: %q", token)
	}
	toks, _ := loadTokens(root)
	var audiences []string
	for _, tk := range toks.Tokens {
		if strings.HasPrefix(tk.Name, "agent:watcher/obo-") {
			audiences = append(audiences, tk.Audience)
		}
	}
	if len(audiences) != 1 || audiences[0] != base+"/mcp" {
		t.Fatalf("the exchanged token's audience is %v", audiences)
	}
	req := httptest.NewRequest(http.MethodPost, inside+"/mcp", nil)
	var proofs dpop.Replays
	if _, err := agentCaller(root, req, token, &proofs, base); err != nil {
		t.Errorf("/mcp behind the proxy refused a token minted for its public origin: %v", err)
	}
	if _, err := agentCaller(root, req, token, &proofs, ""); err == nil {
		t.Error("/mcp checked nothing: a token for one origin opened another")
	}

	// The console's enrolment link names the public origin, not the Host
	// the request arrived with.
	if err := srv.Policy.Grant(auth.Binding{Principal: "pat", Role: auth.RoleViewer, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	srv.Enrol = enrolStore(root)
	admin, _, err := srv.Tokens.IssueSession("s", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Policy.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, srv.Tokens); err != nil {
		t.Fatal(err)
	}
	form := httptest.NewRequest(http.MethodPost, inside+"/people/enrol", strings.NewReader("principal=pat"))
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	form.Header.Set("Sec-Fetch-Site", "same-origin")
	form.Header.Set("Authorization", "Bearer "+admin)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, form)
	if body := rec.Body.String(); !strings.Contains(body, base+"/enrol/") || strings.Contains(body, "127.0.0.1:8080/enrol/") {
		t.Errorf("the enrolment link does not name the public origin: %d %s", rec.Code, body)
	}
}
