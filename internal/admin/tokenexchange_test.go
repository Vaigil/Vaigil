// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/vaigil/internal/auth"
	"github.com/quilzo/vaigil/internal/dpop"
)

func programKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := dpop.PublicJWK(&k.PublicKey)
	thumb, _ := dpop.Thumbprint(pub)
	return k, thumb
}

func proved(t *testing.T, key *ecdsa.PrivateKey, method, url, token string) string {
	t.Helper()
	p, err := dpop.Prove(key, method, url, token, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A token bound to a key is not a bearer token: it opens nothing in the
// console, whoever presents it.
func TestABoundTokenOpensNothingAsABearerToken(t *testing.T) {
	srv, _ := setup(t)
	_, thumb := programKey(t)
	secret, tok, err := srv.Tokens.IssueSession("program", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Tokens.BindKey(tok.ID, thumb); err != nil {
		t.Fatal(err)
	}
	if w := get(t, srv, "/today", secret); w.Code == http.StatusOK {
		t.Error("a bound token opened the console")
	}
}

func exchange(t *testing.T, srv *Server, form url.Values, proof string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/token/exchange", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// A token is exchanged for a narrower one that lasts minutes, bound to the
// key that proved when one did; it never widens.
func TestATokenIsExchangedForANarrowerShortOne(t *testing.T) {
	srv, token := tokenSignIn(t)
	form := url.Values{"grant_type": {grantTokenExchange}, "subject_token": {token},
		"subject_token_type": {typeAccessToken}, "scope": {"viewer"}, "resource": {"/@security"}}
	w := exchange(t, srv, form, "")
	var got exchangeAnswer
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if got.TokenType != "Bearer" || got.ExpiresIn > int64(auth.DefaultSessionTTL/time.Second) || got.IssuedTokenType != typeAccessToken {
		t.Errorf("%+v", got)
	}
	short, err := srv.Tokens.Authenticate(got.AccessToken, time.Now())
	if err != nil || short.Role != auth.RoleViewer || short.Resource != "/@security" {
		t.Fatalf("%+v %v", short, err)
	}
	key, thumb := programKey(t)
	w = exchange(t, srv, form, proved(t, key, "POST", "http://example.com/token/exchange", ""))
	json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != http.StatusOK || got.TokenType != "DPoP" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if _, err := srv.Tokens.Authenticate(got.AccessToken, time.Now()); !errors.Is(err, auth.ErrKeyBound) {
		t.Errorf("the bound session worked as a bearer token: %v", err)
	}
	if _, err := srv.Tokens.AuthenticateProved(got.AccessToken, "", thumb, time.Now()); err != nil {
		t.Errorf("the bound session does not answer to its key: %v", err)
	}
	form.Set("scope", "admin")
	reader := url.Values{"grant_type": {grantTokenExchange}, "subject_token": {short.ID}, "subject_token_type": {typeAccessToken}}
	if w := exchange(t, srv, reader, ""); w.Code == http.StatusOK {
		t.Error("something that is not a token was exchanged")
	}
	if w := exchange(t, srv, url.Values{"grant_type": {"password"}}, ""); w.Code != http.StatusBadRequest ||
		!strings.Contains(w.Body.String(), "unsupported_grant_type") {
		t.Errorf("%d %s", w.Code, w.Body)
	}
}
