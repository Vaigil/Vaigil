// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/vaigil/internal/auth"
	"github.com/quilzo/vaigil/internal/oidc"
)

// The admin is checked by the same engine it uses on your content.
//
// ATAG has two halves: Part B is whether the tool helps you produce accessible
// content, and Part A is whether the tool is itself usable by a disabled author.
// Part A is the half that gets skipped, because the people who build admin
// panels are rarely the people locked out of them. Running our own checker over
// our own output is the cheapest way to stop that being true here, and it means
// a regression in the interface fails the build rather than waiting for someone
// to complain.

func TestEveryPageHasASkipLinkAndLandmarks(t *testing.T) {
	srv, token := setup(t)
	body := get(t, srv, "/today", token).Body.String()

	for _, want := range []string{
		`class="skip"`,             // 2.4.1 Bypass Blocks
		`id="main"`,                // the skip target
		"<nav", "<main", "<header", // landmarks to navigate by
		`aria-label="Sections"`, // a named nav, since there is more than one region
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page is missing %s", want)
		}
	}
}

// WCAG 2.2 3.3.8: authentication must not be a cognitive function test. Pasting
// a token is not; a puzzle or a transcription would be.
func TestSignInHasNoPuzzle(t *testing.T) {
	srv, _ := setup(t)
	body := strings.ToLower(get(t, srv, "/today", "").Body.String())

	// Look for the mechanism, not the word. The first version of this grepped
	// for "solve" and flagged the sentence "no puzzle to solve" — copy that
	// exists to say the thing is absent. A test that fails on an accurate
	// description of compliance is a test that gets deleted.
	for _, bad := range []string{
		"captcha",         // any of the usual widgets
		"<img",            // image recognition in the auth form
		"data-sitekey",    // recaptcha/hcaptcha/turnstile hook
		"type=\"number\"", // a code to transcribe
	} {
		if strings.Contains(body, bad) {
			t.Errorf("the sign-in form contains %q, which suggests a cognitive "+
				"function test", bad)
		}
	}
	// And the thing that should be there.
	if !strings.Contains(body, "type=\"password\"") {
		t.Error("sign-in should accept a pasted token")
	}
}

// The admin's only script is its own file, by nonce. Since October 2026 the
// interface carries one first-party script, for the command palette and
// shortcuts; it is never inline and every screen works without it.
func TestNoScriptAnywhere(t *testing.T) {
	srv, token := setup(t)
	tag := regexp.MustCompile(`(?i)<script\b[^>]*>`)
	for _, path := range []string{
		"/", "/page/index", "/review", "/access", "/provenance", "/history",
	} {
		body := get(t, srv, path, token).Body.String()
		for _, s := range tag.FindAllString(body, -1) {
			if !strings.Contains(s, `src="/admin.js"`) || !strings.Contains(s, `nonce="`) {
				t.Errorf("%s carries a script other than its own: %s", path, s)
			}
		}
		if strings.Contains(strings.ToLower(body), "<script>") {
			t.Errorf("%s contains an inline script", path)
		}
		if strings.Contains(body, "onclick=") || strings.Contains(body, "onload=") {
			t.Errorf("%s uses an inline event handler", path)
		}
	}
}

func TestSecurityHeadersAreSet(t *testing.T) {
	srv, token := setup(t)
	h := get(t, srv, "/today", token).Header()
	csp := h.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP should deny by default, got %q", csp)
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Error("CSP must not permit inline script")
	}
	if h.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}
}

// Authorisation is enforced server-side. Hiding a button is presentation; the
// handler refusing is the control.
func TestPermissionsAreEnforcedNotJustHidden(t *testing.T) {
	srv, _ := setup(t)

	// A reader may look, and may not change who may do what.
	if err := srv.Policy.Grant(auth.Binding{
		Principal: "watcher", Role: auth.RoleViewer, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	secret, _, err := srv.Tokens.IssueSession("w", "watcher", auth.RoleViewer, "/",
		time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	w := postForm(t, srv, "/people/grant", secret, "principal=watcher&role=admin&resource=/")
	if w.Code != http.StatusForbidden {
		t.Fatalf("a reader granting themselves admin should get 403, got %d", w.Code)
	}
	// The refusal has to say what was missing, or people ask for more access
	// than they need just to make the error go away.
	if !strings.Contains(w.Body.String(), "admin") {
		t.Error("the refusal should name the role required")
	}
}

func TestBadTokenIsRefused(t *testing.T) {
	srv, _ := setup(t)
	if w := get(t, srv, "/today", "vg_not_a_real_token"); w.Code != http.StatusUnauthorized {
		t.Errorf("a bad token should give 401, got %d", w.Code)
	}
}

func TestStylesheetIsServedAndSelfContained(t *testing.T) {
	srv, _ := setup(t)
	w := get(t, srv, "/style.css", "")
	if w.Code != http.StatusOK {
		t.Fatalf("stylesheet returned %d", w.Code)
	}
	css := stripCSSComments(w.Body.String())

	// Declarations only. Checking the raw text flagged two comments that exist
	// to say outlines are never removed — the same mistake as grepping the
	// sign-in page for "solve" and finding "no puzzle to solve". Prose about the
	// absence of a thing is not the thing.
	if strings.Contains(css, "outline: none") || strings.Contains(css, "outline:none") {
		t.Error("the stylesheet removes a focus outline somewhere")
	}
	if strings.Contains(css, "http://") || strings.Contains(css, "https://") {
		t.Error("the stylesheet fetches something external; it should be self-contained")
	}
	if !strings.Contains(css, "prefers-reduced-motion") {
		t.Error("the stylesheet should honour prefers-reduced-motion")
	}
}

// stripCSSComments removes /* ... */ so assertions apply to declarations.
func stripCSSComments(css string) string {
	var b strings.Builder
	for {
		i := strings.Index(css, "/*")
		if i < 0 {
			b.WriteString(css)
			return b.String()
		}
		b.WriteString(css[:i])
		j := strings.Index(css[i:], "*/")
		if j < 0 {
			return b.String()
		}
		css = css[i+j+2:]
	}
}

func TestMain(m *testing.M) { os.Exit(m.Run()) }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// A server that answers from what it read at startup lets a revoked credential
// keep working until somebody restarts the process — revocation that does not
// revoke, with a window as long as the server's uptime.
func TestRevokedTokensStopWorkingWithoutARestart(t *testing.T) {
	srv, token := setup(t)
	srv.Reload = func() (*auth.Policy, *auth.TokenStore, error) {
		return srv.Policy, srv.Tokens, nil
	}

	if w := get(t, srv, "/today", token); w.Code != http.StatusOK {
		t.Fatalf("the token should work first: %d", w.Code)
	}

	// Revoke it in the store the server reads from.
	if _, err := srv.Tokens.Revoke(srv.Tokens.Tokens[0].ID); err != nil {
		t.Fatal(err)
	}

	if w := get(t, srv, "/today", token); w.Code != http.StatusUnauthorized {
		t.Errorf("a revoked token still worked: %d", w.Code)
	}
}

// The same staleness in the other direction: a newly granted role should apply
// without a restart, which is the half people notice and report.
func TestNewlyIssuedTokensWorkWithoutARestart(t *testing.T) {
	srv, _ := setup(t)
	srv.Reload = func() (*auth.Policy, *auth.TokenStore, error) {
		return srv.Policy, srv.Tokens, nil
	}

	if err := srv.Policy.Grant(auth.Binding{
		Principal: "newcomer", Role: auth.RoleViewer, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	secret, _, err := srv.Tokens.IssueSession("late", "newcomer", auth.RoleViewer, "/",
		time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if w := get(t, srv, "/today", secret); w.Code != http.StatusOK {
		t.Errorf("a token issued after startup did not work: %d", w.Code)
	}
}

// -- vulnerabilities found by audit, kept fixed by these ---------------------

// The sign-in form was a GET, so submitting put the token in the URL — and from
// there into browser history, the access log, and the Referer of every outbound
// link. A credential in a URL is a credential in several places nobody clears.
func TestSignInIsAPostAndNeverPutsTheTokenInAURL(t *testing.T) {
	srv, _ := setup(t)
	body := get(t, srv, "/signin", "").Body.String()

	if strings.Contains(body, `method="get"`) {
		t.Error("the sign-in form is a GET; the token would land in the URL")
	}
	if !strings.Contains(body, `method="post"`) {
		t.Fatal("the sign-in form should POST")
	}
}

func TestSignInSetsAHardenedCookie(t *testing.T) {
	srv, token := setup(t)

	req := httptest.NewRequest(http.MethodPost, "/signin",
		strings.NewReader("token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected a redirect after sign-in, got %d", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session cookie was set; the form did not actually sign anyone in")
	}
	c := cookies[0]
	if !c.HttpOnly {
		t.Error("the session cookie should be HttpOnly")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Error("SameSite=Strict is the primary CSRF defence and is missing")
	}
}

func TestSignInRefusesABadToken(t *testing.T) {
	srv, _ := setup(t)
	req := httptest.NewRequest(http.MethodPost, "/signin",
		strings.NewReader("token=vg_nonsense"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Refused by sending the browser back to the form, so there is no page
	// answering the POST for a reload to resubmit.
	if w.Code != http.StatusSeeOther ||
		unsigned(w.Header().Get("Location")) != "/signin?e=refused" {
		t.Errorf("a bad token should be refused with a redirect to the form, "+
			"got %d to %q", w.Code, unsigned(w.Header().Get("Location")))
	}
	if len(w.Result().Cookies()) > 0 {
		t.Error("a rejected sign-in must not set a session cookie")
	}
}

// Cookie authentication means the browser attaches credentials to any request
// to this origin, including a form on someone else's page posting to /publish.
func TestCrossSitePostsCannotChangeAnything(t *testing.T) {
	srv, token := setup(t)

	for _, path := range []string{"/publish", "/save", "/rollback", "/provenance/set"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			// What a browser sends when another site submits a form here.
			req.Header.Set("Sec-Fetch-Site", "cross-site")
			req.Header.Set("Origin", "https://evil.example")

			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("a cross-site POST reached %s: %d", path, w.Code)
			}
		})
	}
}

func TestSameOriginPostsStillWork(t *testing.T) {
	srv, token := setup(t)
	req := httptest.NewRequest(http.MethodPost, "/publish", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Origin", "http://"+req.Host)

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code == http.StatusForbidden {
		t.Error("the CSRF check is refusing legitimate same-origin requests")
	}
}

func TestAnOriginFromAnotherHostIsRefused(t *testing.T) {
	srv, token := setup(t)
	req := httptest.NewRequest(http.MethodPost, "/publish", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	// No Sec-Fetch-Site, as an older client would send. Origin has to catch it.
	req.Header.Set("Origin", "https://evil.example")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("an Origin from another host reached the handler: %d", w.Code)
	}
}

// An unbounded body lets one request make the process allocate until it dies,
// which needs no credential and no cleverness.
func TestOversizedRequestsAreRefused(t *testing.T) {
	srv, token := setup(t)
	huge := strings.Repeat("a", MaxRequestBody+1024)

	req := httptest.NewRequest(http.MethodPost, "/save",
		strings.NewReader("__name=index&body="+huge))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code == http.StatusSeeOther || w.Code == http.StatusOK {
		t.Errorf("a body past the limit was accepted: %d", w.Code)
	}
}

// -- content types -----------------------------------------------------------

func fp(v float64) *float64 { return &v }

func save(t *testing.T, srv *Server, token string, form url.Values,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/save",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// -- security posture --------------------------------------------------------

// -- OIDC sign-in ------------------------------------------------------------

// The decision that matters most in this whole path. A verified ID token proves
// the provider knows this person; it does not say they may edit anything.
// Creating a principal on first sign-in would mean everybody with an account at
// the provider — which for a public provider is everybody — becomes a user.
func TestAVerifiedSignInForAnUnknownPrincipalIsRefused(t *testing.T) {
	srv, _ := setup(t)
	srv.OIDC = &OIDC{ClientID: "c", Claim: "email"}

	if srv.knownPrincipal("stranger@example.com") {
		t.Fatal("a principal nobody granted anything to is known")
	}
	if !srv.knownPrincipal("editor") {
		t.Error("the principal from the access policy is not known")
	}
	if srv.knownPrincipal("") {
		t.Error("an empty principal is known")
	}
}

// An unverified address is a claim by whoever signed up. Honouring it would let
// somebody choose which principal to be.
func TestAnUnverifiedEmailIsRefusedByDefault(t *testing.T) {
	o := &OIDC{Claim: "email", RequireVerifiedEmail: true}

	_, err := o.principalFor(oidcClaims("dana@example.com", false))
	if err == nil {
		t.Fatal("an unverified address was mapped to a principal")
	}
	if !strings.Contains(err.Error(), "choose which principal") {
		t.Errorf("the refusal does not say what the risk is: %v", err)
	}

	got, err := o.principalFor(oidcClaims("dana@example.com", true))
	if err != nil || got != "dana@example.com" {
		t.Errorf("a verified address was refused: %q %v", got, err)
	}

	// sub is the stable identifier and carries no verification question.
	o.Claim = "sub"
	if got, err := o.principalFor(oidcClaims("", false)); err != nil ||
		got != "subject-1" {
		t.Errorf("the subject claim was not used: %q %v", got, err)
	}
}

// A state parameter must be single-use, or a callback URL in somebody's history
// is a replay.
func TestAStateIsConsumedExactlyOnce(t *testing.T) {
	o := &OIDC{RedirectURI: "https://cms.example/auth/callback"}
	req, err := oidc.NewRequest(o.RedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	o.pending = map[string]*oidcPending{req.State: {req: req}}

	if got := o.take(req.State); got == nil {
		t.Fatal("a valid state was not found")
	}
	if got := o.take(req.State); got != nil {
		t.Error("the same state was accepted twice; a callback URL in a " +
			"browser's history would be a replay")
	}
	if got := o.take("something-else"); got != nil {
		t.Error("an unknown state resolved")
	}
}

// Without a provider configured the routes must not exist, rather than
// half-existing and erroring.
func TestTheOIDCRoutesAreAbsentWhenNoProviderIsConfigured(t *testing.T) {
	srv, _ := setup(t)
	for _, path := range []string{"/signin/oidc", "/auth/callback"} {
		w := get(t, srv, path, "")
		if w.Code != http.StatusNotFound {
			t.Errorf("%s returned %d with no provider configured", path, w.Code)
		}
	}
}

func oidcClaims(email string, verified bool) *oidc.Claims {
	return &oidc.Claims{
		Subject: "subject-1", Email: email, EmailVerified: verified,
	}
}

// The session a sign-in mints cannot exceed what the policy already grants: it
// is a session, not a promotion.
func TestTheSessionRoleComesFromThePolicy(t *testing.T) {
	srv, _ := setup(t)
	if got := srv.roleFor("editor"); got != auth.RoleAdmin {
		t.Errorf("the admin in the policy got %q", got)
	}
	// Somebody with no bindings falls to the lowest role rather than to
	// whatever the caller asked for.
	if got := srv.roleFor("stranger"); got != auth.RoleViewer {
		t.Errorf("an unknown principal got %q", got)
	}
	// The highest role held anywhere: a responder on the security area
	// alone gets a responder's session, or it would refuse them the very
	// screens their grant is for. A deny counts as it does anywhere.
	srv.Policy.Grant(auth.Binding{Principal: "res", Role: auth.RoleResponder, Resource: auth.AreaSecurity})
	if got := srv.roleFor("res"); got != auth.RoleResponder {
		t.Errorf("a responder on the security area got %q", got)
	}
	srv.Policy.Grant(auth.Binding{Principal: "res", Role: auth.RoleResponder, Resource: auth.AreaSecurity, Deny: true})
	if got := srv.roleFor("res"); got != auth.RoleViewer {
		t.Errorf("a denied grant still raised the session to %q", got)
	}
}
