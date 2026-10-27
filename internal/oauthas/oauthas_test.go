// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package oauthas

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vaigil/vaigil/internal/agentreg"
	"github.com/vaigil/vaigil/internal/auth"
	"github.com/vaigil/vaigil/internal/dpop"
	"github.com/vaigil/vaigil/internal/macaroon"
)

// A test rig: one agent in the registry, one person signed in, one policy
// that lets them delegate triage, and a token store that lives in memory.
// The point of every test below is what the server refuses, so the rig
// starts permissive and each test takes one permission away.
type rig struct {
	srv     *Server
	root    string
	agents  agentreg.Store
	tokens  *auth.TokenStore
	persist bool
	key     *ecdsa.PrivateKey
	person  string
}

const issuer = "http://127.0.0.1:8080"

func newRig(t *testing.T, allow ...string) *rig {
	t.Helper()
	root := t.TempDir()
	agents := agentreg.Store{Path: filepath.Join(root, "agents.json")}
	if len(allow) == 0 {
		allow = agentreg.Tools()
	}
	if err := agents.Add(agentreg.Agent{Name: "watcher", Owner: "dana",
		Allow: allow, CreatedBy: "dana"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	ts := &auth.TokenStore{}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{srv: &Server{
		Issuer: issuer, Resource: issuer + "/mcp",
		Consents: Store{Path: filepath.Join(root, "consents.json")},
		Agents:   agents,
		Identity: func(*http.Request) (string, bool) { return "dana", true },
		Can: func(p string, act auth.Action, res string) bool {
			return p == "dana" && act != auth.ActGrant
		},
		Tokens: func() (*auth.TokenStore, func(*auth.TokenStore) error, error) {
			return ts, func(*auth.TokenStore) error { return nil }, nil
		},
	}, root: root, agents: agents, tokens: ts, key: key, person: "dana"}
	return r
}

func (r *rig) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r.srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func (r *rig) postForm(t *testing.T, path string, form url.Values, proof string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	w := httptest.NewRecorder()
	r.srv.ServeHTTP(w, req)
	return w
}

// ask is a valid authorization request for the scope given, with a fresh
// verifier whose challenge is derived here and returned with the ask.
func (r *rig) ask(scope string) (url.Values, string) {
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"watcher"},
		"redirect_uri":          {"http://127.0.0.1:49152/cb"},
		"scope":                 {scope},
		"state":                 {"st-1"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
		"resource":              {r.srv.Resource},
	}
	return q, verifier
}

func (r *rig) thumb(t *testing.T) string {
	t.Helper()
	pub, err := dpop.PublicJWK(&r.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	thumb, err := dpop.Thumbprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	return thumb
}

func (r *rig) proof(t *testing.T) string {
	t.Helper()
	p, err := dpop.Prove(r.key, http.MethodPost, r.srv.Issuer+TokenPath, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// consent walks the whole flow up to a redeemed token, so a test can start
// from the interesting part.
func (r *rig) consent(t *testing.T, scope string) (code, verifier string) {
	t.Helper()
	q, verifier := r.ask(scope)
	w := r.get(t, AuthorizePath+"?"+q.Encode())
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "watcher") {
		t.Fatalf("the ask did not reach the screen: %d %s", w.Code, w.Body)
	}
	// The consent POST carries the same words plus the person's answer.
	q.Set("approve", "yes")
	w = r.postForm(t, AuthorizePath, q, "")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("the approval did not redirect: %d %s", w.Code, w.Body)
	}
	back, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if back.Query().Get("state") != "st-1" {
		t.Errorf("the state came back as %q", back.Query().Get("state"))
	}
	return back.Query().Get("code"), verifier
}

func (r *rig) redeem(t *testing.T, code, verifier, proof string) *httptest.ResponseRecorder {
	t.Helper()
	return r.postForm(t, TokenPath, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"watcher"},
		"redirect_uri":  {"http://127.0.0.1:49152/cb"},
		"code_verifier": {verifier},
	}, proof)
}

type tokenAnswer struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	ExpiresIn   int64  `json:"expires_in"`
}

func isError(w *httptest.ResponseRecorder, kind string) bool {
	var e struct {
		Error string `json:"error"`
	}
	return json.Unmarshal(w.Body.Bytes(), &e) == nil && e.Error == kind
}

// The metadata is the honesty contract: exactly the grants, scopes and
// methods this server implements, and nothing it refuses.
func TestTheMetadataAdvertisesExactlyWhatItImplements(t *testing.T) {
	r := newRig(t)
	w := r.get(t, MetadataPath)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string][]string{
		"grant_types_supported":                 {"authorization_code"},
		"response_types_supported":              {"code"},
		"code_challenge_methods_supported":      {"S256"},
		"scopes_supported":                      {"observe", "triage"},
		"token_endpoint_auth_methods_supported": {"none"},
	} {
		got, _ := doc[field].([]any)
		var words []string
		for _, v := range got {
			words = append(words, fmt.Sprint(v))
		}
		if strings.Join(words, ",") != strings.Join(want, ",") {
			t.Errorf("%s says %v and the server implements exactly %v — a client "+
				"believes this document, and each direction of the disagreement "+
				"is a client that breaks or a grant nobody checks", field, words, want)
		}
	}
	if doc["issuer"] != issuer || doc["token_endpoint"] != issuer+TokenPath ||
		doc["authorization_endpoint"] != issuer+AuthorizePath {
		t.Errorf("the endpoints do not name this issuer: %v", doc)
	}
	if doc["resource"] != issuer+"/mcp" {
		t.Errorf("the one resource is /mcp: %v", doc["resource"])
	}
	for _, lying := range []string{"refresh", "revocation", "registration", "client_credentials"} {
		if strings.Contains(w.Body.String(), lying) {
			t.Errorf("the metadata mentions %q, which this server refuses — the "+
				"document is where a client learns that", lying)
		}
	}
}

// The whole code flow, end to end: a signed-in person approves, the code
// arrives at a loopback redirect, and the token endpoint — under a DPoP
// proof and the right verifier — mints a /mcp-bound token in the agent's
// name under the consent's grant.
func TestTheCodeFlowEndsInAnMcpBoundConsentedToken(t *testing.T) {
	r := newRig(t)
	code, verifier := r.consent(t, "triage")
	w := r.redeem(t, code, verifier, r.proof(t))
	var got tokenAnswer
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if got.TokenType != "DPoP" || got.Scope != "triage" {
		t.Errorf("%+v", got)
	}
	// Bound to the key that proved, and to /mcp and nowhere else: a copy
	// of the token without the key is a copy that opens nothing, which is
	// the whole point of demanding the proof at the token endpoint.
	thumb := r.thumb(t)
	if _, err := r.tokens.AuthenticateFor(got.AccessToken, issuer+"/mcp", time.Now()); err == nil {
		t.Error("a bound token answered as a bearer")
	}
	tok, err := r.tokens.AuthenticateProved(got.AccessToken, issuer+"/mcp", thumb, time.Now())
	if err != nil {
		t.Fatalf("at its resource, proved: %v", err)
	}
	if tok.Name != "agent:watcher" || tok.Principal != "dana" || tok.Role != auth.RoleAnalyst {
		t.Errorf("the token does not say who consented to whom: %+v", tok)
	}
	if tok.Grant == "" || tok.Audience != issuer+"/mcp" || tok.Client != "watcher" {
		t.Errorf("the binding fields: %+v", tok)
	}
	// The consent row exists and says who authorised what.
	rows, err := r.srv.Consents.Load()
	if err != nil || len(rows) != 1 {
		t.Fatalf("%v %v", rows, err)
	}
	if rows[0].Agent != "watcher" || rows[0].Principal != "dana" || rows[0].Scope != "triage" {
		t.Errorf("the row does not say who authorised what: %+v", rows[0])
	}
	if left := rows[0].ExpiresAt - time.Now().Unix(); left > int64(MaxConsentTTL/time.Second)+1 || left < int64(MaxConsentTTL/time.Second)-1 {
		t.Errorf("the consent runs %ds, not %s", left, MaxConsentTTL)
	}
}

// The wrong verifier is refused, and the refusal is the spec's word.
func TestAWrongPKCEVerifierIsRefused(t *testing.T) {
	r := newRig(t)
	code, _ := r.consent(t, "observe")
	w := r.redeem(t, code, strings.Repeat("w", 43), r.proof(t))
	if w.Code != http.StatusBadRequest || !isError(w, "invalid_grant") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "verifier") {
		t.Errorf("the refusal does not say which leg failed: %s", w.Body)
	}
}

// A code is single-use, and its second use kills the token its first use
// minted — the single-use rule made good rather than preferred.
func TestAReplayedCodeIsRefusedAndRevokesItsToken(t *testing.T) {
	r := newRig(t)
	code, verifier := r.consent(t, "observe")
	first := r.redeem(t, code, verifier, r.proof(t))
	if first.Code != http.StatusOK {
		t.Fatalf("%d %s", first.Code, first.Body)
	}
	var got tokenAnswer
	_ = json.Unmarshal(first.Body.Bytes(), &got)
	if _, err := r.tokens.AuthenticateProved(got.AccessToken, issuer+"/mcp", r.thumb(t), time.Now()); err != nil {
		t.Fatal(err)
	}
	second := r.redeem(t, code, verifier, r.proof(t))
	if second.Code != http.StatusBadRequest || !isError(second, "invalid_grant") {
		t.Fatalf("%d %s", second.Code, second.Body)
	}
	if _, err := r.tokens.AuthenticateProved(got.AccessToken, issuer+"/mcp", r.thumb(t), time.Now()); err == nil {
		t.Fatal("the token from the first use is still live")
	}
}

// Everything the endpoint refuses arrives in the spec's error shape, with a
// reason that says where the honest alternative is.
func TestRefusedGrantsAreAnsweredInTheSpecsWords(t *testing.T) {
	r := newRig(t)
	for _, grant := range []string{"client_credentials", "refresh_token",
		"urn:ietf:params:oauth:grant-type:token-exchange", "password", ""} {
		form := url.Values{"grant_type": {grant}}
		if grant == "" {
			form = url.Values{}
		}
		w := r.postForm(t, TokenPath, form, r.proof(t))
		if w.Code != http.StatusBadRequest || !isError(w, "unsupported_grant_type") {
			t.Errorf("grant %q: %d %s", grant, w.Code, w.Body)
		}
	}
	// The refusals say why in the terms a client can act on.
	w := r.postForm(t, TokenPath, url.Values{"grant_type": {"refresh_token"}}, r.proof(t))
	if !strings.Contains(w.Body.String(), "no refresh tokens") {
		t.Errorf("the refresh refusal does not say there are none: %s", w.Body)
	}
	w = r.postForm(t, TokenPath, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}}, r.proof(t))
	if !strings.Contains(w.Body.String(), "/token/exchange") {
		t.Errorf("the exchange refusal does not say where the exchange lives: %s", w.Body)
	}
}

// Plain PKCE is refused at the door, and no proof is refused at the token
// endpoint: the two protections are not advertised and then waived.
func TestPlainPKCEAndAMissingProofAreRefused(t *testing.T) {
	r := newRig(t)
	q, _ := r.ask("observe")
	q.Set("code_challenge_method", "plain")
	if w := r.get(t, AuthorizePath+"?"+q.Encode()); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "S256") {
		t.Errorf("plain was not refused by name: %d %s", w.Code, w.Body)
	}
	q.Set("code_challenge_method", "S256")
	q.Del("code_challenge")
	if w := r.get(t, AuthorizePath+"?"+q.Encode()); w.Code != http.StatusBadRequest {
		t.Errorf("a missing challenge was accepted: %d", w.Code)
	}
	// A token request without the DPoP proof is not a client anybody
	// authenticated.
	code, verifier := r.consent(t, "observe")
	w := r.redeem(t, code, verifier, "")
	if w.Code != http.StatusBadRequest || !isError(w, "invalid_client") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
}

// The client is a registered, active agent — before the screen, before the
// code, and again before the token.
func TestTheClientIsARegisteredActiveAgent(t *testing.T) {
	r := newRig(t)
	q, _ := r.ask("observe")
	q.Set("client_id", "stranger")
	if w := r.get(t, AuthorizePath+"?"+q.Encode()); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "no agent") {
		t.Errorf("an unregistered client got as far as %d: %s", w.Code, w.Body)
	}
	// The kill switch reaches the token endpoint: disabled between the
	// consent and the redemption, nothing is issued.
	code, verifier := r.consent(t, "observe")
	if err := r.agents.Disable("watcher", "test", "tester", time.Now()); err != nil {
		t.Fatal(err)
	}
	w := r.redeem(t, code, verifier, r.proof(t))
	if w.Code != http.StatusBadRequest || !isError(w, "invalid_grant") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
}

// A scope is one bundle the registry carries whole: no invented words, no
// half-covered bundles, and no cross-product of words.
func TestAScopeIsOneBundleTheRegistryCarriesWhole(t *testing.T) {
	r := newRig(t, "vaigil_find", "vaigil_read") // no vaigil_write
	q, _ := r.ask("triage")
	if w := r.get(t, AuthorizePath+"?"+q.Encode()); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "whole") {
		t.Errorf("a bundle the allowlist does not carry was shown: %d %s", w.Code, w.Body)
	}
	for _, word := range []string{"email", "observe triage", "offline_access", ""} {
		q, _ = r.ask(word)
		if w := r.get(t, AuthorizePath+"?"+q.Encode()); w.Code != http.StatusBadRequest {
			t.Errorf("scope %q reached the screen: %d", word, w.Code)
		}
	}
	// A registry narrowed between the consent and the redemption refuses
	// there too, rather than issuing a token for part of a word.
	fresh := newRig(t)
	code, verifier := fresh.consent(t, "triage")
	if err := fresh.agents.Allow("watcher", nil, []string{"vaigil_write"}, "tester", time.Now()); err != nil {
		t.Fatal(err)
	}
	w := fresh.redeem(t, code, verifier, fresh.proof(t))
	if w.Code != http.StatusBadRequest || !isError(w, "invalid_scope") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
}

// A person cannot consent to what they do not hold.
func TestAConsentDelegatesOnlyWhatThePersonHolds(t *testing.T) {
	r := newRig(t)
	r.srv.Can = func(string, auth.Action, string) bool { return false }
	q, _ := r.ask("observe")
	w := r.get(t, AuthorizePath+"?"+q.Encode())
	if w.Code != http.StatusForbidden {
		t.Fatalf("a person who holds nothing was asked: %d", w.Code)
	}
	// And nobody signed in is not asked at all.
	r.srv.Identity = func(*http.Request) (string, bool) { return "", false }
	if w := r.get(t, AuthorizePath+"?"+q.Encode()); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), "signed in") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
}

// A refusal is redirected in the spec's shape, with the state, and recorded
// as a denial — the register is the review, and "who said no" is a fact it
// keeps beside "who said yes".
func TestARefusalRedirectsAndIsRecorded(t *testing.T) {
	r := newRig(t)
	q, _ := r.ask("observe")
	q.Set("approve", "no")
	w := r.postForm(t, AuthorizePath, q, "")
	if w.Code != http.StatusSeeOther {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	back, _ := url.Parse(w.Header().Get("Location"))
	if back.Query().Get("error") != "access_denied" || back.Query().Get("state") != "st-1" {
		t.Errorf("the refusal was not the spec's: %v", back.Query())
	}
	rows, err := r.srv.Consents.Load()
	if err != nil || len(rows) != 0 {
		t.Errorf("a refusal wrote a consent: %v %v", rows, err)
	}
}

// A cross-site page may not post the person's answer for them.
func TestAnotherSitesPageCannotAnswerForYou(t *testing.T) {
	r := newRig(t)
	q, _ := r.ask("observe")
	q.Set("approve", "yes")
	req := httptest.NewRequest(http.MethodPost, AuthorizePath, strings.NewReader(q.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://evil.example")
	w := httptest.NewRecorder()
	r.srv.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("a page from another site answered: %d %s", w.Code, w.Body)
	}
}

// The redirect is loopback only: this server has no web-app registry, and
// pretending it did would be an open door with a metadata document behind
// it.
func TestTheRedirectIsLoopbackOnly(t *testing.T) {
	r := newRig(t)
	for _, bad := range []string{
		"https://app.example/cb",         // not loopback
		"http://127.0.0.1:49152/cb?x=1",  // a query to smuggle
		"http://127.0.0.1:49152/cb#frag", // a fragment
		"ftp://127.0.0.1/cb",             // not http(s)
		"http://eva@127.0.0.1:49152/cb",  // userinfo
	} {
		q, _ := r.ask("observe")
		q.Set("redirect_uri", bad)
		if w := r.get(t, AuthorizePath+"?"+q.Encode()); w.Code != http.StatusBadRequest {
			t.Errorf("redirect %q reached the screen: %d", bad, w.Code)
		}
	}
}

// The register: a row that cannot be read back is refused at the door, a
// revoked or ended row is refused by Live, and the bundle words and the
// macaroon purposes are the same vocabulary.
func TestTheConsentRegisterRefusesWhatItCannotHonour(t *testing.T) {
	s := Store{Path: filepath.Join(t.TempDir(), "consents.json")}
	now := time.Now()
	if err := s.Record(Consent{ID: "one", Agent: "watcher", Scope: "triage",
		Principal: "dana"}, now); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.Load()
	if rows[0].ExpiresAt != now.Add(MaxConsentTTL).Unix() {
		t.Errorf("the TTL is a cap, not a suggestion: %d", rows[0].ExpiresAt-now.Unix())
	}
	if _, err := s.Live("one", now); err != nil {
		t.Errorf("a live row refused: %v", err)
	}
	if _, err := s.Live("one", now.Add(MaxConsentTTL+time.Minute)); err == nil {
		t.Error("an ended row lived on")
	}
	if _, err := s.Revoke("one", "tester", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Live("one", now); err == nil {
		t.Error("a revoked row lived on")
	}
	for _, bad := range []Consent{
		{Agent: "watcher", Scope: "triage", Principal: "dana"},        // no id
		{ID: "two", Scope: "triage", Principal: "dana"},               // no agent
		{ID: "two", Agent: "watcher", Principal: "dana"},              // no scope word
		{ID: "two", Agent: "watcher", Scope: "email", Principal: "d"}, // no such bundle
		{ID: "two", Agent: "watcher", Scope: "triage"},                // no person
	} {
		if err := s.Record(bad, now); err == nil {
			t.Errorf("a row that could not be read back was written: %+v", bad)
		}
	}
	// The vocabulary is one: every scope word is a purpose a run credential
	// can carry, and every bundle's tools are tools the registry knows.
	for _, b := range Bundles() {
		if !macaroon.ValidPurpose(b.Name) {
			t.Errorf("%q is not a purpose the run credentials know", b.Name)
		}
		for _, tool := range b.Tools {
			if !agentreg.ValidTool(tool) {
				t.Errorf("%q is not a tool the registry knows", tool)
			}
		}
		if got := ScopesSupported(); len(got) != len(Bundles()) {
			t.Errorf("the metadata's scopes and the bundles disagree: %v", got)
		}
	}
}
