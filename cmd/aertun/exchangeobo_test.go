// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/admin"
	"github.com/aertun/aertun/internal/agentreg"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/config"
	"github.com/aertun/aertun/internal/dpop"
	"github.com/aertun/aertun/internal/macaroon"
	"github.com/aertun/aertun/internal/oauthas"
	"github.com/aertun/aertun/internal/out"
)

// The delegation phase, end to end (docs/research/02-access-control.md
// §8.2): a consent made through the authorization server, an on-behalf-of
// token exchanged from it, and the exchanged token carried through the real
// agent interface — the same gates a stdio or HTTP caller reaches, caveat
// gate included — with the audit trail and the resource metadata holding up
// their ends.

// exchangeSite is a store where the whole story can happen: dana holds the
// ladder, the agent is registered for the read and write tools, and the
// exchange's three hooks are wired the way serve wires them.
func exchangeSite(t *testing.T) (string, *admin.Server, string) {
	t.Helper()
	if w == nil {
		w = out.New(false)
	}
	root := caveatSite(t)
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	toks, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := admin.New(pol, toks)
	if err != nil {
		t.Fatal(err)
	}
	// The wiring serve gives it, so what is under test is the deployed
	// shape rather than a hand-made near miss of it.
	admin.AgentRegistry = agentStore(root)
	srv.Consents = consentStore(root)
	srv.RunKey = func() ([]byte, error) { return loadRunKey(root) }
	srv.AuditAgent = func(action, resource, agent string, detail map[string]string) {
		record(root, audit.Record{
			Action: action, Resource: resource, Outcome: audit.Success,
			Principal: agent, Kind: audit.KindAI, Model: agent, Verified: true,
			Detail: detail,
		})
	}
	srv.SaveTokens = func(ts *auth.TokenStore) error { return saveTokens(root, ts) }
	// The console's own reloader, because the run credential the exchange
	// will be offered is minted to the file after this server was built —
	// exactly the race the reloader exists for in production.
	srv.ReloadTokens = tokenReloader(root, toks)
	return root, srv, "http://127.0.0.1:8080"
}

// consentFor mints a consent row and the person's consented token, exactly
// as the authorization server's token endpoint leaves them: agent-named,
// audience-bound, grant-bound, carrying the bundle's role.
func consentFor(t *testing.T, root string, srv *admin.Server, origin, scope string) (string, string) {
	t.Helper()
	id, err := oauthas.NewID()
	if err != nil {
		t.Fatal(err)
	}
	if err := consentStore(root).Record(oauthas.Consent{ID: id,
		Agent: "watcher", Scope: scope, Principal: "dana@acme.example"},
		time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	bundle, _ := oauthas.BundleFor(scope)
	secret, _, err := srv.Tokens.IssueForAgent(agentreg.TokenPrefix+"watcher",
		"dana@acme.example", bundle.Role,
		auth.Scope{ReadOnly: bundle.ReadOnly}, "watcher", id,
		origin+"/mcp", "", nil, "", oauthas.AccessTokenTTL, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, srv.Tokens); err != nil {
		t.Fatal(err)
	}
	return secret, id
}

// exchange offers the on-behalf-of exchange over the console's own handler.
func exchange(t *testing.T, srv *admin.Server, origin, actor, subject string) map[string]any {
	t.Helper()
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":        {actor},
	}
	req := httptest.NewRequest(http.MethodPost, origin+"/token/exchange",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+actor)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	return out
}

// TestExchangeOnBehalfOfRunsTheWholeDelegation. The agent holds a run
// credential narrowed to reading; the person consented to triage through
// the authorization server; the registry allows both tools. The exchanged
// token reads, is refused the write by the caveat the exchange minted, and
// carries the act chain into the audit log as the agent's own act.
func TestExchangeOnBehalfOfRunsTheWholeDelegation(t *testing.T) {
	root, srv, origin := exchangeSite(t)
	person, grant := consentFor(t, root, srv, origin, "triage")
	// The agent's run credential: the registry allows read and write, the
	// run narrows to read — the third bound in the intersection.
	run := mintRun(t, root, "run-9", []string{"aertun_read"}, "", 0, -1)

	got := exchange(t, srv, origin, run, person)
	token, _ := got["access_token"].(string)
	if token == "" || got["scope"] != "triage" || got["token_type"] != "Bearer" {
		t.Fatalf("the answer is not what was exchanged for: %v", got)
	}

	// The real agent interface path: the transport's own resolver, the
	// same buildMCP, the handlers' own authoriseTool — caveat gate
	// included, because the exchanged token is run-shaped and the gate
	// reads its chain.
	req := httptest.NewRequest(http.MethodPost, origin+"/mcp", nil)
	var proofs dpop.Replays
	caller, err := agentCaller(root, req, token, &proofs)
	if err != nil {
		t.Fatalf("the agent interface refused the exchanged token: %v", err)
	}
	if caller.Agent != "watcher" || caller.Run != "obo-"+grant {
		t.Fatalf("the caller is not the agent on its exchanged run: %+v", caller)
	}
	if caller.Name != "dana@acme.example" || caller.RunToken != token {
		t.Fatalf("the caller does not act for the person who consented: %+v", caller)
	}
	if caller.Kind != audit.KindAI || caller.Model != "watcher" {
		t.Fatalf("the acts are not recorded as the agent's: %+v", caller)
	}
	srv2 := buildMCP(root, caller)
	text, merr := callTool(t, srv2, "aertun_read", "list_findings", nil)
	if merr != nil {
		t.Fatalf("the read the intersection left was refused: %s", merr.Message)
	}
	if !strings.Contains(text, "total") {
		t.Fatalf("the queue did not answer: %s", text)
	}

	// The write nobody allowed in: the registry would, the consent would,
	// the run would not — and the caveat the exchange minted is the one
	// that says so, through the same gate every run token answers to.
	msg := refused(t, srv2, "aertun_write", "propose_finding_decision",
		map[string]any{"id": "x", "to": "fixed", "because": "y"})
	if !strings.Contains(msg, "not in this run's tool set") {
		t.Errorf("the refusal does not name the caveat: %s", msg)
	}

	// The audit trail: the exchange is the agent's own act, an AI
	// principal under its own name, with closed words — the record the
	// aertun/agent telemetry reads.
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var exchanged *audit.Event
	for i := range events {
		if events[i].Action == "agent.exchanged" {
			exchanged = &events[i]
		}
	}
	if exchanged == nil {
		t.Fatal("no agent.exchanged record; the exchange left no trail")
	}
	// The principal is a pseudonym — the log's own property, and the
	// reason the test resolves it forward rather than expecting a name —
	// and the record's own fields say whose act it was.
	if exchanged.Kind != audit.KindAI || exchanged.Model != "watcher" || !exchanged.Verified {
		t.Fatalf("the record is not the agent's own: %+v", exchanged)
	}
	l, err := openAudit(root)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Matches(exchanged.Principal, "watcher") {
		t.Errorf("the pseudonym does not resolve to the agent")
	}
	for _, word := range []string{"scope", "depth", "tools"} {
		if exchanged.Detail[word] == "" {
			t.Errorf("the detail has no %s: %v", word, exchanged.Detail)
		}
	}
	if exchanged.Detail["tools"] != "aertun_read" {
		t.Errorf("the detail does not carry the intersection: %v", exchanged.Detail)
	}
}

// TestExchangeOnBehalfOfDiesWithTheConsent: revoking through the CLI kills
// the tokens and refuses the next exchange — the review is the register,
// and the register is the thing that gets revoked.
func TestExchangeOnBehalfOfDiesWithTheConsent(t *testing.T) {
	root, srv, origin := exchangeSite(t)
	person, grant := consentFor(t, root, srv, origin, "triage")
	run := mintRun(t, root, "run-10", []string{"aertun_read"}, "", 0, -1)
	got := exchange(t, srv, origin, run, person)
	first, _ := got["access_token"].(string)

	captureOutput(t)
	if err := cmdAgent(root, []string{"consents", "revoke", grant}); err != nil {
		t.Fatal(err)
	}
	// The minted token is dead at the store: revoking the consent revoked
	// the grant, which is what the consent's tokens were issued under.
	// Read from the file, which is where the CLI's revocation landed.
	secret, _ := macaroon.Split(first)
	fresh, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.AuthenticateFor(secret, origin+"/mcp", time.Now()); err == nil {
		t.Error("the exchanged token outlived the consent that legitimated it")
	}
	// And no new one may be minted.
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {person},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":        {run},
	}
	req := httptest.NewRequest(http.MethodPost, origin+"/token/exchange",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+run)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
	// The revocation is on the record.
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "consent.revoke" && e.Detail["grant"] == grant {
			found = true
		}
	}
	if !found {
		t.Error("the revocation left no record")
	}
}

// TestAgentConsentsListsTheRegister: the review surface reads what the
// authorization server wrote — who authorised which agent for which bundle
// until when — live rows first, and says where consent comes from when
// there is none.
func TestAgentConsentsListsTheRegister(t *testing.T) {
	root := caveatSite(t)
	buf := captureOutput(t)
	if err := cmdAgent(root, []string{"consents"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no agent has been consented to") {
		t.Errorf("an empty register did not say so:\n%s", buf)
	}
	srv, origin := exchangeSiteOf(t, root)
	consentFor(t, root, srv, origin, "observe")
	buf = captureOutput(t)
	if err := cmdAgent(root, []string{"consents"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"watcher", "dana@acme.example", "observe", "live"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the listing does not show %q:\n%s", want, buf)
		}
	}
	if !strings.Contains(buf.String(), "aertun agent consents revoke") {
		t.Errorf("the listing does not say how to end one:\n%s", buf)
	}
}

// exchangeSiteOf wires a store that already exists, for tests that build
// their site first and their console second.
func exchangeSiteOf(t *testing.T, root string) (*admin.Server, string) {
	t.Helper()
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	toks, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := admin.New(pol, toks)
	if err != nil {
		t.Fatal(err)
	}
	admin.AgentRegistry = agentStore(root)
	srv.Consents = consentStore(root)
	srv.RunKey = func() ([]byte, error) { return loadRunKey(root) }
	srv.SaveTokens = func(ts *auth.TokenStore) error { return saveTokens(root, ts) }
	srv.ReloadTokens = tokenReloader(root, toks)
	return srv, "http://127.0.0.1:8080"
}

// TestOAuthASAndTheResourceMetadataNameEachOther: a 401 from /mcp points
// at the resource document, the resource document names the issuer, and
// the issuer's metadata says exactly what serve mounted — the chain a
// client walks to find the door, with no door named that is not there.
func TestOAuthASAndTheResourceMetadataNameEachOther(t *testing.T) {
	root := caveatSite(t)
	pol, _ := loadPolicy(root)
	toks, _ := loadTokens(root)
	srv, err := admin.New(pol, toks)
	if err != nil {
		t.Fatal(err)
	}
	addr := "127.0.0.1:8080"
	origin := "http://" + addr
	mux := http.NewServeMux()
	cfg := config.New()
	mountMCP(mux, root, cfg, addr)
	mountOAuthAS(mux, root, cfg, addr, srv)

	// The resource document names the authorization server.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, wellKnownMCP, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	servers, _ := doc["authorization_servers"].([]any)
	if len(servers) != 1 || servers[0] != origin {
		t.Fatalf("the resource document does not name this issuer: %v", doc)
	}

	// And the issuer's metadata is served at the path it is named by, and
	// the resource it issues for is the agent interface.
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, oauthas.MetadataPath, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var meta map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	if meta["issuer"] != origin || meta["resource"] != origin+"/mcp" {
		t.Fatalf("the issuer is not the resource's own deployment: %v", meta)
	}
	if meta["token_endpoint"] != origin+oauthas.TokenPath {
		t.Fatalf("the metadata names a token endpoint that is not mounted: %v", meta)
	}
	// And the paths are real: the endpoints answer, not just the document.
	for _, path := range []string{oauthas.AuthorizePath, oauthas.TokenPath} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code == http.StatusNotFound {
			t.Errorf("%s is advertised and not mounted", path)
		}
	}
}

// TestExchangeOnBehalfOfRefusesWhatTheStoreRefuses: the narrower exchange
// this endpoint has always offered still works beside the new one, and the
// two do not mix — a consented token is not narrowed as though it were a
// plain credential, and an on-behalf-of exchange still needs both halves.
func TestExchangeOnBehalfOfRefusesWhatTheStoreRefuses(t *testing.T) {
	root, srv, origin := exchangeSite(t)
	person, _ := consentFor(t, root, srv, origin, "triage")

	// The consented token is /mcp-bound, so the narrowing exchange — which
	// mints a token for anywhere — refuses it: only the on-behalf-of path
	// consumes a consent.
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {person},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"scope":              {"viewer"},
	}
	req := httptest.NewRequest(http.MethodPost, origin+"/token/exchange",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a consented token was narrowed like a plain credential: %d %s",
			rec.Code, rec.Body)
	}

	// And the on-behalf-of exchange without the agent's credential in the
	// header is not an agent asking.
	form.Set("actor_token", "vg_"+"nobody-ever-minted-this")
	form.Del("scope")
	req = httptest.NewRequest(http.MethodPost, origin+"/token/exchange",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_client") {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
}
