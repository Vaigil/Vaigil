// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vaigil/vaigil/internal/agentreg"
	"github.com/vaigil/vaigil/internal/auth"
	"github.com/vaigil/vaigil/internal/macaroon"
	"github.com/vaigil/vaigil/internal/oauthas"
)

// The on-behalf-of half of the exchange: an agent presents its own
// credential and a person's consented token, and what it leaves with is the
// intersection of three allowlists nobody combined before. The rig here is
// the console's (rig_test.go) plus the three things the flow composes: a
// registry entry, a consent row, and a run key.
type oboRig struct {
	srv      *Server
	consents oauthas.Store
	agents   agentreg.Store
	runKey   []byte
	aud      string
	person   string // the consented token, as the AS mints one
	agent    string // watcher's run credential
	plain    string // watcher's plain bearer
	grant    string // the consent row both tokens name
}

func onBehalf(t *testing.T, allow []string, scope string) *oboRig {
	t.Helper()
	dir := t.TempDir()
	srv, _ := setup(t)
	agents := agentreg.Store{Path: filepath.Join(dir, "agents.json")}
	if err := agents.Add(agentreg.Agent{Name: "watcher", Owner: "editor",
		Allow: allow, CreatedBy: "editor"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	AgentRegistry = agents
	consents := oauthas.Store{Path: filepath.Join(dir, "consents.json")}
	runKey := make([]byte, 32)
	if _, err := rand.Read(runKey); err != nil {
		t.Fatal(err)
	}
	srv.Consents = consents
	srv.RunKey = func() ([]byte, error) { return runKey, nil }

	r := &oboRig{srv: srv, consents: consents, agents: agents, runKey: runKey,
		aud: "http://example.com/mcp"}
	// The person's consented token, exactly as the authorization server
	// mints one: agent-named (so the gates treat it as the agent's),
	// audience-bound, grant-bound, issued for the bundle's role.
	id, err := oauthas.NewID()
	if err != nil {
		t.Fatal(err)
	}
	if err := consents.Record(oauthas.Consent{ID: id, Agent: "watcher",
		Scope: scope, Principal: "editor"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	bundle, _ := oauthas.BundleFor(scope)
	secret, _, err := srv.Tokens.IssueForAgent(agentreg.TokenPrefix+"watcher",
		"editor", bundle.Role, auth.Scope{ReadOnly: bundle.ReadOnly}, "watcher",
		id, r.aud, "", nil, "", oauthas.AccessTokenTTL, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	r.person, r.grant = secret, id

	// The agent's own credentials: a plain bearer, and a run token whose
	// caveat tool set is the whole registry allow.
	plain, _, err := srv.Tokens.IssueScoped(agentreg.TokenPrefix+"watcher",
		"watcher", auth.RoleAnalyst, "/", time.Hour, auth.RoleAdmin, auth.Scope{})
	if err != nil {
		t.Fatal(err)
	}
	r.plain = plain
	tool, err := macaroon.ToolCaveat(allow...)
	if err != nil {
		t.Fatal(err)
	}
	run, err := macaroon.Mint(plain, runKey, agentreg.TokenPrefix+"watcher/run-1",
		tool, macaroon.ExpCaveat(time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	r.agent = run
	return r
}

// offer exchanges with the given actor credential as both the Authorization
// header and the actor_token: the honest shape of an agent asking.
func (r *oboRig) offer(t *testing.T, actor, subject string) *httptest.ResponseRecorder {
	t.Helper()
	return r.offerSplit(t, actor, actor, subject)
}

// offerSplit lets the header and the parameter name different credentials,
// for the test that says they may not.
func (r *oboRig) offerSplit(t *testing.T, header, actor, subject string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type":         {grantTokenExchange},
		"subject_token":      {subject},
		"subject_token_type": {typeAccessToken},
		"actor_token":        {actor},
	}
	req := httptest.NewRequest(http.MethodPost, "/token/exchange", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+header)
	w := httptest.NewRecorder()
	r.srv.Handler().ServeHTTP(w, req)
	return w
}

func toolsOf(t *testing.T, token string) map[string]bool {
	t.Helper()
	parsed, ok := macaroon.Parse(token)
	if !ok {
		t.Fatalf("the answer is not a run-shaped token: %q", token)
	}
	out := map[string]bool{}
	for _, cv := range parsed.Caveats() {
		if cv.Kind == macaroon.KindTool {
			for _, tool := range cv.Tools() {
				out[tool] = true
			}
		}
	}
	return out
}

// The intersection, in both directions and with the third bound: wider
// consent than registry → registry wins; wider registry than consent →
// consent wins; a run credential narrower than both → the run wins.
func TestOnBehalfIsTheIntersectionOfAllThreeBounds(t *testing.T) {
	// Wider consent than registry: the consent carries triage, the registry
	// allows reading only. What is issued reads.
	r := onBehalf(t, []string{"vaigil_find", "vaigil_read"}, "triage")
	w := r.offer(t, r.plain, r.person)
	var got exchangeAnswer
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if got.Scope != "triage" {
		t.Errorf("the answer's scope word is the consent's: %+v", got)
	}
	if tools := toolsOf(t, got.AccessToken); len(tools) != 2 || !tools["vaigil_read"] || tools["vaigil_write"] {
		t.Errorf("the registry's narrowness did not win: %v", tools)
	}

	// Wider registry than consent: the registry allows everything, the
	// consent carries observe. What is issued reads.
	r = onBehalf(t, agentreg.Tools(), "observe")
	w = r.offer(t, r.plain, r.person)
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if tools := toolsOf(t, got.AccessToken); len(tools) != 2 || tools["vaigil_write"] {
		t.Errorf("the consent's narrowness did not win: %v", tools)
	}

	// The credential narrows below both: a run token carrying one tool,
	// inside a registry and a consent that allow three. What is issued is
	// that one tool.
	r = onBehalf(t, agentreg.Tools(), "triage")
	narrow := narrowRun(t, r, "vaigil_read")
	w = r.offer(t, narrow, r.person)
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if tools := toolsOf(t, got.AccessToken); len(tools) != 1 || !tools["vaigil_read"] {
		t.Errorf("the credential's narrowness did not win: %v", tools)
	}

	// Nothing in common: a refusal, in the spec's word, naming the three
	// bounds so the operator can widen the right one.
	r = onBehalf(t, []string{"vaigil_read"}, "triage")
	w = r.offer(t, narrowRun(t, r, "vaigil_write"), r.person)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_scope") ||
		!strings.Contains(w.Body.String(), "three bounds") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
}

// narrowRun mints the agent a run credential carrying exactly one tool,
// over its plain bearer, the way `vaigil agent token` does.
func narrowRun(t *testing.T, r *oboRig, tool string) string {
	t.Helper()
	toolCaveat, err := macaroon.ToolCaveat(tool)
	if err != nil {
		t.Fatal(err)
	}
	run, err := macaroon.Mint(r.plain, r.runKey, agentreg.TokenPrefix+"watcher/run-2",
		toolCaveat, macaroon.ExpCaveat(time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	return run
}

// The chain is capped at two: the person and one agent. An exchanged token
// cannot act, and cannot be acted for.
func TestOnBehalfCapsTheChainAtTwo(t *testing.T) {
	r := onBehalf(t, agentreg.Tools(), "triage")
	w := r.offer(t, r.plain, r.person)
	var got exchangeAnswer
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}

	// The chain, on the stored token: the person first, the agent last.
	secret, _ := macaroon.Split(got.AccessToken)
	tok, err := r.srv.Tokens.AuthenticateFor(secret, r.aud, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(tok.Act) != auth.MaxActChain || tok.Act[0] != "editor" || tok.Act[1] != "watcher" {
		t.Fatalf("the chain is not person-then-agent: %v", tok.Act)
	}
	if tok.Parent == "" || tok.Grant != r.grant || tok.Audience != r.aud {
		t.Errorf("the binding fields: %+v", tok)
	}

	// The exchanged token as the actor: refused. Which gate refuses first
	// is layering, not policy — an audience-bound credential cannot
	// authenticate as an agent's own, and a token carrying a chain cannot
	// act again — and the property under test is that no second hop is
	// minted whatever order the gates run in.
	if w := r.offer(t, got.AccessToken, r.person); w.Code != http.StatusBadRequest {
		t.Errorf("a second hop was minted: %d %s", w.Code, w.Body)
	}
	// The exchanged token as the subject: extending from the other end,
	// refused the same way.
	if w := r.offer(t, r.plain, got.AccessToken); w.Code != http.StatusBadRequest {
		t.Errorf("a chain was extended through its subject: %d %s", w.Code, w.Body)
	}
}

// Revoking the consent kills the tokens it minted and refuses every
// exchange that would draw on it again.
func TestARevokedConsentRefusesAndKills(t *testing.T) {
	r := onBehalf(t, agentreg.Tools(), "triage")
	w := r.offer(t, r.plain, r.person)
	var got exchangeAnswer
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if _, err := r.consents.Revoke(r.grant, "editor", time.Now()); err != nil {
		t.Fatal(err)
	}
	if n := r.srv.Tokens.RevokeGrant(r.grant); n < 2 {
		t.Fatalf("revoking the grant killed %d tokens; the consented token and the exchanged one were both minted under it", n)
	}
	// The exchanged token is dead.
	secret, _ := macaroon.Split(got.AccessToken)
	if _, err := r.srv.Tokens.AuthenticateFor(secret, r.aud, time.Now()); err == nil {
		t.Error("the exchanged token outlived the consent it was minted under")
	}
	// And no new one may be minted.
	if w := r.offer(t, r.plain, r.person); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "invalid_grant") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
}

// The actor is the agent that made the request: its credential
// authenticates the request, the parameter names it, and the two must be
// the same stored token.
func TestTheActorIsTheCredentialThatAuthenticatedTheRequest(t *testing.T) {
	r := onBehalf(t, agentreg.Tools(), "triage")
	// No Authorization header at all.
	form := url.Values{"grant_type": {grantTokenExchange},
		"subject_token": {r.person}, "actor_token": {r.plain}}
	req := httptest.NewRequest(http.MethodPost, "/token/exchange", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_client") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
	// A different credential in the parameter than in the header: the
	// claim and its proof disagree, and neither is taken over the other.
	// (A run token and the bearer it wraps are one credential in two
	// forms, so the mismatched one here is a genuinely separate token.)
	other, _, err := r.srv.Tokens.IssueScoped(agentreg.TokenPrefix+"watcher",
		"watcher", auth.RoleAnalyst, "/", time.Hour, auth.RoleAdmin, auth.Scope{})
	if err != nil {
		t.Fatal(err)
	}
	if w := r.offerSplit(t, r.plain, other, r.person); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "invalid_client") {
		t.Errorf("two credentials named one actor: %d %s", w.Code, w.Body)
	}
}

// The consented token is a person's delegation, not an agent credential:
// swapping the roles is refused.
func TestTheTwoHalvesCannotBeSwapped(t *testing.T) {
	r := onBehalf(t, agentreg.Tools(), "triage")
	w := r.offer(t, r.person, r.plain)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("the person's token acted: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), `"access_token"`) {
		t.Errorf("the swap minted something: %s", w.Body)
	}
}

// A disabled agent exchanges nothing, even holding a live consent and a
// live credential.
func TestADisabledAgentExchangesNothing(t *testing.T) {
	r := onBehalf(t, agentreg.Tools(), "triage")
	if err := r.agents.Disable("watcher", "test", "editor", time.Now()); err != nil {
		t.Fatal(err)
	}
	if w := r.offer(t, r.plain, r.person); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "registry") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
}

// The exchange writes the agent's own audit record: an AI principal acting
// under its name, with closed words in the detail.
func TestTheExchangeWritesTheAgentsOwnRecord(t *testing.T) {
	r := onBehalf(t, agentreg.Tools(), "triage")
	var gotAction, gotAgent string
	var gotDetail map[string]string
	r.srv.AuditAgent = func(action, resource, agent string, detail map[string]string) {
		gotAction, gotAgent, gotDetail = action, agent, detail
	}
	if w := r.offer(t, r.plain, r.person); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if gotAction != "agent.exchanged" || gotAgent != "watcher" {
		t.Fatalf("%q by %q", gotAction, gotAgent)
	}
	for _, word := range []string{"scope", "depth", "tools"} {
		if gotDetail[word] == "" {
			t.Errorf("the detail has no %s: %v", word, gotDetail)
		}
	}
	if gotDetail["depth"] != "2" || gotDetail["scope"] != "triage" {
		t.Errorf("the detail is not the closed words: %v", gotDetail)
	}
}
