// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package ssf

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/oidc"
)

// The transmitter half, proved the only way that means anything here: a
// token this half builds is read by the receiver half above — the same
// Verify every inbound event already passes through, keys fetched from the
// JWKS this half publishes. If the shape drifts, the roundtrip is the test
// that cannot pretend otherwise.

const (
	site = "https://aertun.acme.example"  // this deployment, as the issuer
	part = "https://partner.example/caep" // one receiver, as the audience
)

func emitter(t *testing.T) *Emitter {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEmitter(key, site)
	if err != nil {
		t.Fatal(err)
	}
	e.Now = func() time.Time { return now }
	return e
}

// receiverFor is a receiving platform configured with nothing but what the
// transmitter publishes: its issuer, the address it listens on, and the JWKS.
func receiverFor(t *testing.T, e *Emitter, audience string) *Receiver {
	t.Helper()
	ks, err := oidc.NewKeySet(site+"/jwks", func(context.Context, string) ([]byte, error) {
		return e.JWKS(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return &Receiver{Issuer: site, Audience: audience,
		Algorithms: []oidc.Algorithm{oidc.ES256}, Keys: ks,
		Now: func() time.Time { return now }}
}

// TestATransmittedRevocationVerifiesThroughThisReceiver.
//
// The shape proof. A kill-switch token verifies through Receiver.Verify —
// the code path that reads Okta's and Google's events — and says exactly
// what was put in it: one CAEP session-revoked event, about the agent by its
// registry name, with the operator's reason for the receiving admins.
func TestATransmittedRevocationVerifiesThroughThisReceiver(t *testing.T) {
	e := emitter(t)
	token, jti, err := e.SessionRevoked("watcher", part, "proposing nonsense on closed findings")
	if err != nil {
		t.Fatal(err)
	}
	if jti == "" || len(jti) != 32 {
		t.Fatalf("an event carries a usable id; this one is %q", jti)
	}
	set, err := receiverFor(t, e, part).Verify(token)
	if err != nil {
		t.Fatalf("a token this transmitter built did not verify through the "+
			"receiver's own path: %v", err)
	}
	if set.Short != "session-revoked" || set.Family != "caep" {
		t.Errorf("read as %s/%s, not a CAEP session-revoked", set.Family, set.Short)
	}
	if set.Issuer != site || set.JTI != jti {
		t.Errorf("the token's issuer (%s) or id (%s) did not survive the trip", set.Issuer, set.JTI)
	}
	if set.Subject.Format != "iss_sub" || set.Subject.Iss != site || set.Subject.Ref() != "watcher" {
		t.Errorf("the subject is %+v; an agent is named by its registry name in this site's namespace",
			set.Subject)
	}
	// An agent is not a person, and the reading side must not be able to
	// mistake it for one: no email, so Person() is empty and the rules fall
	// back to the transmitter's own identifier.
	if set.Subject.Person() != "" {
		t.Errorf("the agent subject resolved to a person, %q", set.Subject.Person())
	}
	if set.Subject.Sub != "agent:watcher" && set.Subject.Sub != "watcher" {
		// Reading what was sent, not what was expected: the registry name.
		t.Errorf("the subject's sub is %q", set.Subject.Sub)
	}
	sig := set.Signal()
	if sig.Type != "session-revoked" || sig.Severity != "medium" {
		t.Errorf("the signal is %+v", sig)
	}
	if sig.Reason != "proposing nonsense on closed findings" {
		t.Errorf("the operator's reason did not arrive for the receiving admins: %q", sig.Reason)
	}
	if sig.Fields["initiating_entity"] != "admin" {
		t.Errorf("the event says %q initiated it, not an administrator", sig.Fields["initiating_entity"])
	}
}

// TestEachReceiverIsAddressedAlone.
//
// One event, one token per receiver: the audience names who it is for, so a
// token taken to a second receiver fails that receiver's audience check —
// the push cannot be replayed somewhere it was never meant for.
func TestEachReceiverIsAddressedAlone(t *testing.T) {
	e := emitter(t)
	other := "https://other.example/events"
	first, jti1, err := e.SessionRevoked("watcher", part, "")
	if err != nil {
		t.Fatal(err)
	}
	second, jti2, err := e.SessionRevoked("watcher", other, "")
	if err != nil {
		t.Fatal(err)
	}
	if jti1 == jti2 || first == second {
		t.Error("two receivers got one token; each push is its own event")
	}
	if _, err := receiverFor(t, e, other).Verify(first); err == nil {
		t.Error("a token addressed to one receiver verified at another, so the " +
			"audience check on the reading side is decoration")
	}
}

// TestATamperedRevocationDoesNotVerify: the signature covers the segments
// exactly as they travel, so a payload edited after signing is refused by
// the same receiver that took the original.
func TestATamperedRevocationDoesNotVerify(t *testing.T) {
	e := emitter(t)
	token, _, err := e.SessionRevoked("watcher", part, "reason")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(claims, &c); err != nil {
		t.Fatal(err)
	}
	c["sub_id"] = map[string]any{"format": "iss_sub", "iss": site, "sub": "somebody-else"}
	forged, _ := json.Marshal(c)
	parts[1] = base64.RawURLEncoding.EncodeToString(forged)
	if _, err := receiverFor(t, e, part).Verify(strings.Join(parts, ".")); err == nil {
		t.Error("a payload naming a different subject verified; the signature " +
			"is not covering what is read")
	}
}

// TestAnEmitterWithoutAnIdentityRefusesToSign: no issuer, no events — a
// token that names nobody as its maker is one no receiver should compare
// against a value it chose.
func TestAnEmitterWithoutAnIdentityRefusesToSign(t *testing.T) {
	key, _ := GenerateKey()
	if _, err := NewEmitter(key, ""); err == nil {
		t.Error("an empty issuer was accepted")
	}
	if _, err := NewEmitter(key, "not a url"); err == nil {
		t.Error("a non-URL issuer was accepted")
	}
	if _, err := NewEmitter(key, "ftp://aertun.example"); err == nil {
		t.Error("a non-https issuer was accepted")
	}
	if _, err := NewEmitter(nil, site); err == nil {
		t.Error("a missing key was accepted")
	}
	if _, _, err := (&Emitter{Key: key, Issuer: site}).SessionRevoked("", part, ""); err == nil {
		t.Error("an event about no agent was signed")
	}
}

// TestDeliveryTakesATwoxxAndReportsTheRest: RFC 8935 answers — any 2xx is a
// delivery, and a refusal arrives as the receiver's own words, in the error
// shape this program's receiver uses.
func TestDeliveryTakesATwoxxAndReportsTheRest(t *testing.T) {
	e := emitter(t)
	token, _, err := e.SessionRevoked("watcher", part, "reason")
	if err != nil {
		t.Fatal(err)
	}
	var gotPath, gotType, gotAuth string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotType, gotAuth = r.URL.Path, r.Header.Get("Content-Type"), r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		switch gotPath {
		case "/accepted":
			w.WriteHeader(http.StatusAccepted)
		case "/busy":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"err":"access_denied","description":"busy; send it again"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client := srv.Client()
	ctx := context.Background()

	if err := e.Deliver(ctx, client, srv.URL+"/accepted", token, "the-agreed-secret"); err != nil {
		t.Fatalf("a 202 is a delivery: %v", err)
	}
	if gotPath != "/accepted" || gotType != SecEventJWT {
		t.Errorf("the push went to %s as %s", gotPath, gotType)
	}
	if gotAuth != "Bearer the-agreed-secret" {
		t.Errorf("the receiver's token went as %q", gotAuth)
	}
	if string(gotBody) != token {
		t.Error("the body is not the token itself")
	}
	err = e.Deliver(ctx, client, srv.URL+"/busy", token, "")
	if err == nil || !strings.Contains(err.Error(), "access_denied") ||
		!strings.Contains(err.Error(), "busy; send it again") {
		t.Errorf("a refusal should carry the receiver's words: %v", err)
	}
	if err := e.Deliver(ctx, client, srv.URL+"/nowhere", token, ""); err == nil {
		t.Error("a 404 was counted as a delivery")
	}
	// A receiver that is not there: the connection itself fails, and the
	// error names the address so the record says which receiver it was.
	if err := e.Deliver(ctx, client, "http://127.0.0.1:1/caep", token, ""); err == nil {
		t.Error("an unreachable receiver was counted as a delivery")
	}
}
