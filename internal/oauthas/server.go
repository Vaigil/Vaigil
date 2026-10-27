// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package oauthas

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/vaigil/vaigil/internal/agentreg"
	"github.com/vaigil/vaigil/internal/auth"
	"github.com/vaigil/vaigil/internal/dpop"
)

// The endpoints. The metadata document lives at RFC 8414's path for an
// issuer with no path of its own — this server's issuer is the deployment's
// origin, whole — and the flow itself is under /oauth/, its own namespace so
// it can never collide with a console route and a console route can never be
// mistaken for part of a grant.
const (
	MetadataPath  = "/.well-known/oauth-authorization-server"
	AuthorizePath = "/oauth/authorize"
	TokenPath     = "/oauth/token"
)

// CodeTTL is how long an authorization code lives: two minutes, one use.
//
// Short because a code is a bearer for the last step of one flow, carried
// from a browser to a process on the same machine. The lifetime is the
// window in which a code lifted from a browser history, a log or a referrer
// header is worth anything, and nothing in this flow needs more of it than
// the round trip.
const CodeTTL = 2 * time.Minute

// AccessTokenTTL is how long an access token the consent flow issues lasts.
// An hour: shorter than the consent (which outlives it and is what the
// client re-asks against), longer than the minutes of a session exchange,
// because the holder of this token is a program that cannot be asked to
// re-authorize mid-run. It is always capped by the consent's own remaining
// life.
const AccessTokenTTL = time.Hour

// Server is the authorization server. Everything it needs about the store it
// stands beside comes in as hooks, because this package owns a protocol, not
// a filesystem: the console's sessions, the policy, the token store, the
// audit log and the agent registry all stay where they already live, and a
// nil hook is refused rather than read as empty.
type Server struct {
	// Issuer is this deployment's origin, as the operator chose to listen
	// on — the same origin the agent interface names in its RFC 9728
	// document. Resource is the one audience tokens are issued for,
	// Issuer + "/mcp".
	Issuer   string
	Resource string

	// Consents is the register the flow writes (consent.go).
	Consents Store
	// Agents is the registry that decides who the client is.
	Agents agentreg.Store

	// Identity resolves the person a browser request is signed in as: the
	// console session, verified. Nil or false refuses — an authorization
	// endpoint that could not tell who was approving would be a consent
	// screen for whoever asked.
	Identity func(r *http.Request) (string, bool)
	// Can is the policy: whether the person holds the action the bundle
	// needs, on the agent interface's area. A person cannot consent to
	// more than they hold — consent delegates, it does not create.
	Can func(principal string, act auth.Action, resource string) bool
	// Tokens loads the token store and returns how to persist what the
	// flow minted. Nil means no tokens can be issued, which is a startup
	// error the host should have refused, not a quiet empty flow.
	Tokens func() (*auth.TokenStore, func(*auth.TokenStore) error, error)
	// Audit records what the flow did. Nil records nothing, which is only
	// right in a test.
	Audit func(action, resource string, detail map[string]string)
	// SameOrigin reports whether a browser Origin header may post the
	// consent form. A request with no Origin is not from a page and is not
	// affected.
	SameOrigin func(origin string) bool

	// Now is the clock, overridable in tests.
	Now func() time.Time

	// One replay window for the endpoint's life, and one code store: a
	// code is minutes-short and single-use, and both of those are
	// per-process memories by design. A restart forgets the codes in
	// flight — every one of them is dead within CodeTTL anyway — and two
	// processes behind one address share nothing, which is why the mount
	// is one handler, not a constructor called twice.
	proofs dpop.Replays
	codes  codeStore
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// codeStore holds the authorization codes this process issued, single-use,
// with the id of the token a code's first redemption minted — the one thing
// RFC 6749 §4.1.2 asks for beyond refusal: a code used twice must revoke
// what its first use issued, or the single-use rule is a preference.
type codeStore struct {
	mu    sync.Mutex
	codes map[string]pendingCode
}

// pendingCode is one issued code: everything the token endpoint re-checks.
type pendingCode struct {
	client    string // the agent, from the registry
	consent   string // the consent row the answer wrote
	scope     string // the bundle word
	challenge string
	redirect  string
	person    string // who consented
	expires   time.Time
	used      bool
	issued    string // token id from the first redemption
}

// keep remembers a code, sweeping entries past their use on the way in: a
// map that only grows is a memory leak with a protocol name. Used codes are
// kept a while past their expiry, because the replay that must be answered
// with a revocation does not politely arrive within the code's own life.
func (c *codeStore) keep(code string, p pendingCode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.codes == nil {
		c.codes = map[string]pendingCode{}
	}
	cutoff := time.Now().Add(-time.Hour)
	for k, old := range c.codes {
		if old.expires.Before(cutoff) {
			delete(c.codes, k)
		}
	}
	c.codes[code] = p
}

// take redeems a code. The first return is the code's grant, empty when the
// code is unknown, expired, or was used before; the second is the token id a
// first redemption issued, non-empty exactly when the code was replayed, so
// the caller can revoke what the first use minted.
func (c *codeStore) take(code string, now time.Time) (pendingCode, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.codes[code]
	if !ok || now.After(p.expires) {
		return pendingCode{}, ""
	}
	if p.used {
		return pendingCode{}, p.issued
	}
	p.used = true
	c.codes[code] = p
	return p, ""
}

// remember notes which token a code's first redemption issued, after the
// mint has happened. A replay racing between the two is still refused — only
// its revocation of the just-minted token waits for this line — and the
// token's own short life bounds that gap.
func (c *codeStore) remember(code, tokenID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p, ok := c.codes[code]; ok {
		p.issued = tokenID
		c.codes[code] = p
	}
}

// Handler is the server as one handler, routing its three paths. Anything
// else is a 404: this server has no routes it has not declared.
func (s *Server) Handler() http.Handler {
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	switch r.URL.Path {
	case MetadataPath:
		s.serveMetadata(w, r)
	case AuthorizePath:
		s.serveAuthorize(w, r)
	case TokenPath:
		s.serveToken(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveMetadata is RFC 8414's document, and it is the honesty contract: a
// client believes what this says and nothing else. Every member names
// something this server implements, and nothing it refuses is listed.
func (s *Server) serveMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "the authorization server's metadata is read with GET", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                s.Issuer,
		"authorization_endpoint":                s.Issuer + AuthorizePath,
		"token_endpoint":                        s.Issuer + TokenPath,
		"scopes_supported":                      ScopesSupported(),
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"dpop_signing_algs_supported":           strings.Split(dpop.AlgorithmNames(), " "),
		"resource":                              s.Resource,
	})
}

// -- /oauth/authorize ---------------------------------------------------------

// ask is one authorization request, parsed once and checked once, shared by
// the screen that shows it and the post that answers it — the two must see
// the same request or the second never runs.
type ask struct {
	client    string
	scope     string
	redirect  string
	state     string
	challenge string
}

// check validates an authorization request. why is for the person reading
// the screen when the request cannot be honoured at all (a redirect nobody
// could be trusted with an error); a checked request's later failures use
// the spec's own shapes instead.
func (s *Server) check(q url.Values) (a ask, why string, ok bool) {
	bad := func(why string) (ask, string, bool) { return ask{}, why, false }
	a = ask{
		client:    q.Get("client_id"),
		scope:     q.Get("scope"),
		redirect:  q.Get("redirect_uri"),
		state:     q.Get("state"),
		challenge: q.Get("code_challenge"),
	}
	if a.client == "" || a.redirect == "" || a.state == "" {
		return bad("the request names its client, its redirect and a state")
	}
	// The redirect is checked before it is ever used, including for
	// errors: an open redirect is the classic authorization-server bug,
	// and a loopback-only rule is the honest scope of a server whose
	// clients are programs on the same machine as the person's browser
	// (RFC 8252). A web app needing a public redirect would need a client
	// registry, a secret per client and a review of who may register —
	// none of which exists here, so none of which is pretended to.
	u, err := url.Parse(a.redirect)
	if err != nil || u.Fragment != "" || u.User != nil || u.RawQuery != "" {
		return bad("the redirect is a bare address: no query, fragment or userinfo")
	}
	host := u.Hostname()
	if u.Scheme != "http" && u.Scheme != "https" {
		return bad("the redirect is http or https")
	}
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return bad("the redirect is loopback: a native client's own server, not a web app this server has registered")
	}
	if q.Get("response_type") != "code" {
		return bad("the response type is code; there is no other this server issues")
	}
	// The registry decides who the client is, before anything is shown or
	// agreed to: an unregistered or disabled agent is nobody, at this door
	// as at every other — the kill switch reaches a flow mid-flight too.
	entry, found, gerr := s.Agents.Get(a.client)
	if gerr != nil {
		return bad("the agent registry could not be read, so nobody can be asked anything: " + gerr.Error())
	}
	if !found {
		return bad("there is no agent \"" + a.client + "\" in the registry; an unregistered agent is nobody")
	}
	if entry.Status != agentreg.Active {
		return bad("agent \"" + a.client + "\" is disabled, so it may not be consented to")
	}
	bundle, known := BundleFor(a.scope)
	if !known {
		return bad("the scope is one word: observe or triage")
	}
	// The bundle must fit the registry's allowlist whole. The narrowing
	// half of this design lives at the exchange, where a run credential's
	// caveats are intersected with the consent; here a word means what it
	// says or it is refused.
	if !bundle.Covers(entry.Allow) {
		return bad("the registry allows \"" + a.client + "\" only " + strings.Join(entry.Allow, ", ") +
			", which does not carry the " + a.scope + " bundle whole")
	}
	// The resource, when a client names one, must be the one this server
	// issues for. Absent means ours: there is no other answer to give.
	if res := q.Get("resource"); res != "" && res != s.Resource {
		return bad("the resource this server issues for is " + s.Resource)
	}
	if a.challenge == "" || q.Get("code_challenge_method") != "S256" {
		// S256, and only S256: plain is what PKCE exists to replace, and a
		// server that accepted it would be advertising the protection
		// while permitting its bypass.
		return bad("the proof key is S256 (code_challenge and code_challenge_method=S256)")
	}
	return a, "", true
}

var consentTmpl = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Vaigil — agent consent</title></head>
<body>
<h1>Agent {{.Agent}}, acting for you</h1>
<p>The agent <strong>{{.Agent}}</strong>, owned by {{.Owner}}, asks to {{.Reach}}
at {{.Resource}}, for up to {{.Hours}} hours. You are {{.Person}}.</p>
<p>What you allow here is one of the three bounds on what the agent gets: this
consent, what the registry allows the agent, and whatever credential the agent
presents. It may end up narrower. It never ends up wider.</p>
<p>Reviewing and revoking: <code>vaigil agent consents</code> lists what exists;
<code>vaigil agent consents revoke ID</code> ends one, and every token minted
under it dies with it.</p>
<form method="post" action="{{.Action}}">
<input type="hidden" name="response_type" value="code">
<input type="hidden" name="client_id" value="{{.ClientID}}">
<input type="hidden" name="redirect_uri" value="{{.Redirect}}">
<input type="hidden" name="scope" value="{{.Scope}}">
<input type="hidden" name="state" value="{{.State}}">
<input type="hidden" name="code_challenge" value="{{.Challenge}}">
<input type="hidden" name="code_challenge_method" value="S256">
{{with .ResourceParam}}<input type="hidden" name="resource" value="{{.}}">{{end}}
<p><button name="approve" value="yes">Allow</button>
<button name="approve" value="no">Refuse</button></p>
</form>
</body></html>`))

func (s *Server) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.showAsk(w, r, r.URL.Query())
	case http.MethodPost:
		if origin := r.Header.Get("Origin"); origin != "" && (s.SameOrigin == nil || !s.SameOrigin(origin)) {
			// The consent POST is a person's answer; a page elsewhere
			// driving their browser at it is not. The same rule the
			// agent interface applies to its own surface.
			http.Error(w, "a page from another site may not answer for you", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			refusePage(w, http.StatusBadRequest, "the consent answer is a form")
			return
		}
		s.answerAsk(w, r, r.PostForm)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "the authorization endpoint takes GET (to show the ask) and POST (to answer it)", http.StatusMethodNotAllowed)
	}
}

// reach is the one-line description of a bundle's reach, in the words the
// run-credential mint uses for the same words.
func reach(b Bundle) string {
	if b.Name == "triage" {
		return "read the security queue and propose decisions on what it reads"
	}
	return "read the security queue"
}

func (s *Server) showAsk(w http.ResponseWriter, r *http.Request, q url.Values) {
	a, why, ok := s.check(q)
	if !ok {
		refusePage(w, http.StatusBadRequest, why)
		return
	}
	if s.Identity == nil {
		refusePage(w, http.StatusServiceUnavailable, "this server cannot establish who is signed in, so it cannot ask anybody anything")
		return
	}
	person, signedIn := s.Identity(r)
	if !signedIn {
		refusePage(w, http.StatusForbidden,
			"nobody is signed in to the console in this browser. Sign in — a passkey, two factors — and the agent's ask will be here")
		return
	}
	bundle, _ := BundleFor(a.scope)
	if !s.holds(person, a.scope) {
		refusePage(w, http.StatusForbidden,
			"you do not hold what this asks for. The "+a.scope+" bundle needs "+string(bundle.Action)+
				" on the security area, and the policy does not grant that to "+person+
				". A consent delegates what a person holds; it does not create it.")
		return
	}
	entry, _, _ := s.Agents.Get(a.client)
	_ = consentTmpl.Execute(w, map[string]any{
		"Agent": a.client, "Owner": entry.Owner, "Person": person,
		"Reach": reach(bundle), "Resource": s.Resource,
		"Hours":  int(MaxConsentTTL / time.Hour),
		"Action": AuthorizePath, "ClientID": a.client, "Redirect": a.redirect,
		"Scope": a.scope, "State": a.state, "Challenge": a.challenge,
		"ResourceParam": q.Get("resource"),
	})
}

// answerAsk is the POST: the person's answer to the ask. Everything is
// checked again — the POST is a request of its own, carrying its own words —
// and the answer is written into the register before any code is minted, so
// a code can never exist without the consent row that explains it.
func (s *Server) answerAsk(w http.ResponseWriter, r *http.Request, f url.Values) {
	a, why, ok := s.check(f)
	if !ok {
		refusePage(w, http.StatusBadRequest, why)
		return
	}
	if s.Identity == nil {
		refusePage(w, http.StatusServiceUnavailable, "this server cannot establish who is signed in, so nobody has answered anything")
		return
	}
	person, signedIn := s.Identity(r)
	if !signedIn {
		refusePage(w, http.StatusForbidden, "the session that was asked is gone; start again from the agent")
		return
	}
	if f.Get("approve") != "yes" {
		s.audit("consent.deny", "/agents/"+a.client, map[string]string{
			"by": person, "agent": a.client, "scope": a.scope})
		redirectError(w, r, a.redirect, "access_denied",
			"the person refused", a.state)
		return
	}
	if !s.holds(person, a.scope) {
		// Re-checked at the answer, not only at the showing: a grant
		// removed while the screen sat open must not be delegated by a
		// click that pre-dates its removal.
		refusePage(w, http.StatusForbidden,
			"you no longer hold what this asks for; the consent is not recorded")
		return
	}
	id, err := NewID()
	if err != nil {
		refusePage(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := s.now()
	if err := s.Consents.Record(Consent{
		ID: id, Agent: a.client, Scope: a.scope, Principal: person,
	}, now); err != nil {
		refusePage(w, http.StatusInternalServerError, "the consent could not be recorded: "+err.Error())
		return
	}
	s.audit("consent.grant", "/agents/"+a.client, map[string]string{
		"by": person, "agent": a.client, "scope": a.scope, "grant": id})

	code := codeSecret()
	s.codes.keep(code, pendingCode{
		client: a.client, consent: id, scope: a.scope, challenge: a.challenge,
		redirect: a.redirect, person: person, expires: now.Add(CodeTTL),
	})
	http.Redirect(w, r, a.redirect+"?code="+url.QueryEscape(code)+
		"&state="+url.QueryEscape(a.state), http.StatusSeeOther)
}

// holds is the policy half of a consent: the person must hold the bundle's
// action on the agent interface's area, or there is nothing to delegate.
// No policy hook is no consent — the fail-closed answer, not the permissive
// one, because a consent recorded against nobody's authority is a lie with
// a row in a register.
func (s *Server) holds(person, scope string) bool {
	bundle, ok := BundleFor(scope)
	if !ok || s.Can == nil {
		return false
	}
	return s.Can(person, bundle.Action, auth.AreaSecurity)
}

// -- /oauth/token ---------------------------------------------------------------

func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, kind, why string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": kind, "error_description": why})
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		fail(http.StatusMethodNotAllowed, "invalid_request", "a token is requested with POST")
		return
	}
	if err := r.ParseForm(); err != nil {
		fail(http.StatusBadRequest, "invalid_request", "the body is a form")
		return
	}
	f := r.PostForm
	switch f.Get("grant_type") {
	case "authorization_code":
	case "client_credentials":
		fail(http.StatusBadRequest, "unsupported_grant_type",
			"there is no client-credentials grant: the store's own credentials (vaigil token issue, vaigil agent token) are the machine-to-machine path, issued by an administrator and revocable by id")
		return
	case "refresh_token":
		fail(http.StatusBadRequest, "unsupported_grant_type",
			"there are no refresh tokens: a code is minutes-short and single-use, the consent lives on so a client asks again, and the run credential is the durable thing an agent holds")
		return
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		fail(http.StatusBadRequest, "unsupported_grant_type",
			"the exchange this deployment offers is on-behalf-of, at /token/exchange, where an agent presents its credential and a person's consented token together")
		return
	default:
		fail(http.StatusBadRequest, "unsupported_grant_type", "the grant type is authorization_code")
		return
	}

	// The client is public and authenticates with a key: one DPoP proof,
	// made for this request. No proof, no tokens — a client that cannot
	// sign is a client whose tokens would work for whoever copied them,
	// and sender-constraining every token this server issues is the point
	// of requiring it.
	proofs := r.Header.Values("DPoP")
	if len(proofs) != 1 {
		fail(http.StatusBadRequest, "invalid_client",
			"a public client proves itself with exactly one DPoP proof, made for this request")
		return
	}
	thumb, err := dpop.Check(proofs[0], http.MethodPost, s.Issuer+TokenPath, "", s.now(), &s.proofs)
	if err != nil {
		fail(http.StatusBadRequest, "invalid_client", err.Error())
		return
	}

	code := f.Get("code")
	grant, replayed := s.codes.take(code, s.now())
	if replayed != "" {
		// A code used twice: the first use's token is revoked, as RFC
		// 6749 requires, because the second use is the one signal that
		// the code was lifted, and a token minted on a lifted code is
		// the lifter's, not the client's.
		if ts, save, terr := s.loadTokens(); terr == nil && save != nil {
			if _, rerr := ts.Revoke(replayed); rerr == nil {
				_ = save(ts)
			}
		}
		fail(http.StatusBadRequest, "invalid_grant",
			"this code was used before, so the token it minted has been revoked")
		return
	}
	if grant.client == "" {
		fail(http.StatusBadRequest, "invalid_grant", "the code is not one this server issued, or it has expired")
		return
	}
	if f.Get("client_id") != grant.client {
		fail(http.StatusBadRequest, "invalid_grant", "the code was issued to a different client")
		return
	}
	if f.Get("redirect_uri") != grant.redirect {
		fail(http.StatusBadRequest, "invalid_grant", "the redirect does not match the one the code was issued under")
		return
	}
	verifier := f.Get("code_verifier")
	if !validVerifier(verifier) {
		fail(http.StatusBadRequest, "invalid_request", "the code_verifier is 43 to 128 characters of the PKCE alphabet")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(grant.challenge)) != 1 {
		fail(http.StatusBadRequest, "invalid_grant", "the verifier does not match the challenge the code was issued under")
		return
	}

	// The kill switch and the policy, re-checked at the moment of issue.
	// A consent made minutes ago is not a promise that the agent is still
	// welcome, or that the person still holds what they delegated.
	entry, found, gerr := s.Agents.Get(grant.client)
	if gerr != nil || !found || entry.Status != agentreg.Active {
		fail(http.StatusBadRequest, "invalid_grant",
			"the agent is not active in the registry, so nothing is issued for it")
		return
	}
	if !s.holds(grant.person, grant.scope) {
		fail(http.StatusBadRequest, "invalid_grant",
			"the person who consented no longer holds what they consented to")
		return
	}
	consent, cerr := s.Consents.Live(grant.consent, s.now())
	if cerr != nil {
		fail(http.StatusBadRequest, "invalid_grant", cerr.Error())
		return
	}
	bundle, _ := BundleFor(grant.scope)
	if !bundle.Covers(entry.Allow) {
		// The allowlist was narrowed between consent and redemption; the
		// bundle no longer fits whole, and a token for part of a word
		// would be a token whose scope lies.
		fail(http.StatusBadRequest, "invalid_scope",
			"the registry no longer allows "+grant.client+" the "+grant.scope+" bundle whole; widen the agent's allowlist or ask again for a smaller bundle")
		return
	}

	ts, save, terr := s.loadTokens()
	if terr != nil {
		fail(http.StatusInternalServerError, "server_error", terr.Error())
		return
	}
	ttl := AccessTokenTTL
	if left := time.Unix(consent.ExpiresAt, 0).Sub(s.now()); left < ttl {
		ttl = left
	}
	now := s.now()
	secret, tok, ierr := ts.IssueForAgent(agentreg.TokenPrefix+grant.client, grant.person,
		bundle.Role, auth.Scope{ReadOnly: bundle.ReadOnly}, grant.client,
		consent.ID, s.Resource, "", nil, thumb, ttl, now)
	if ierr != nil {
		fail(http.StatusInternalServerError, "server_error", ierr.Error())
		return
	}
	if err := save(ts); err != nil {
		fail(http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	s.codes.remember(code, tok.ID)
	s.audit("consent.token", "/agents/"+grant.client, map[string]string{
		"by": grant.person, "agent": grant.client, "scope": grant.scope,
		"grant": consent.ID, "credential": tok.ID, "bound": "true",
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":      secret,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        "DPoP",
		"expires_in":        tok.ExpiresAt - now.Unix(),
		"scope":             grant.scope,
	})
}

func (s *Server) loadTokens() (*auth.TokenStore, func(*auth.TokenStore) error, error) {
	if s.Tokens == nil {
		return nil, nil, fmt.Errorf("this server was started without a token store")
	}
	return s.Tokens()
}

func (s *Server) audit(action, resource string, detail map[string]string) {
	if s.Audit != nil {
		s.Audit(action, resource, detail)
	}
}

// codeSecret is an authorization code: 256 bits of the CSPRNG, base64url —
// a string no client guesses and no log summarizes.
func codeSecret() string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		// A server that cannot draw randomness cannot issue single-use
		// anything. Failing the process is honest; continuing would issue
		// codes off a broken read, and a weak code is a consent anyone
		// could redeem.
		panic(fmt.Sprintf("cannot generate an authorization code: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// validVerifier is RFC 7636's verifier: 43 to 128 characters of the
// unreserved set, plus the four sub-delims the spec names.
func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, c := range v {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' || c == '.' || c == '_' || c == '~':
		default:
			return false
		}
	}
	return true
}

// redirectError is the error response a validated redirect receives: the
// spec's shape, in the query, with the state echoed so the client can tie
// the refusal to its request.
func redirectError(w http.ResponseWriter, r *http.Request, redirect, kind, why, state string) {
	http.Redirect(w, r, redirect+"?error="+url.QueryEscape(kind)+
		"&error_description="+url.QueryEscape(why)+
		"&state="+url.QueryEscape(state), http.StatusSeeOther)
}

// refusePage is a refusal a person reads, not one a client parses: the
// authorization endpoint's failures that cannot be sent to a redirect (an
// unvalidated redirect, a person who is not signed in) are pages, because
// the only reader they have is the person holding the browser.
func refusePage(w http.ResponseWriter, status int, why string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
		"<title>Vaigil — refused</title></head><body><h1>Refused</h1><p>" +
		template.HTMLEscapeString(why) + "</p></body></html>"))
}
