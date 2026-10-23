// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/vaigil/internal/spool"
	"github.com/quilzo/vaigil/internal/telemetry"
)

func shownSecret(t *testing.T, shown []string, prefix string) string {
	t.Helper()
	for _, s := range shown {
		if v, ok := strings.CutPrefix(s, prefix); ok {
			return strings.TrimSpace(v)
		}
	}
	t.Fatalf("no %q in %v", prefix, shown)
	return ""
}

func sessionState(t *testing.T, root, who string) (live, held int) {
	t.Helper()
	ts, _ := loadTokens(root)
	for _, tok := range ts.Snapshot() {
		if tok.Principal != who || tok.Revoked {
			continue
		}
		live++
		if tok.StepUp != "" {
			held++
		}
	}
	return
}

func storedFrom(t *testing.T, root, src string) int {
	t.Helper()
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Release()
	n := 0
	_ = sp.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		if e.Source == src {
			n++
		}
		return nil
	})
	return n
}

func oktaLogEvent(uuid, typ, actor, target string) map[string]any {
	ev := map[string]any{"uuid": uuid, "published": time.Now().UTC().Format(time.RFC3339), "eventType": typ,
		"displayMessage": typ, "outcome": map[string]any{"result": "SUCCESS"},
		"actor":  map[string]any{"id": "00u-" + actor, "type": "User", "alternateId": actor},
		"client": map[string]any{"ipAddress": "81.2.69.9"}}
	if target != "" {
		ev["target"] = []any{map[string]any{"id": "00u-" + target, "type": "User", "alternateId": target}}
	}
	return ev
}

func oktaPost(t *testing.T, inb *inboundServer, secret, eventID string, events ...map[string]any) int {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"eventType": "com.okta.event_hook", "eventId": eventID,
		"data": map[string]any{"events": events}})
	r := httptest.NewRequest(http.MethodPost, "/feeds/okta", strings.NewReader(string(b)))
	r.Header.Set("Authorization", secret)
	w := httptest.NewRecorder()
	inb.ServeHTTP(w, r)
	return w.Code
}

func standardHeaders(secret, id string, ts int64, body string) http.Header {
	key, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	m := hmac.New(sha256.New, key)
	fmt.Fprintf(m, "%s.%d.%s", id, ts, body)
	h := http.Header{}
	h.Set("webhook-id", id)
	h.Set("webhook-timestamp", fmt.Sprint(ts))
	h.Set("webhook-signature", "v1,"+base64.StdEncoding.EncodeToString(m.Sum(nil)))
	return h
}

// -- shared signals -----------------------------------------------------------

type transmitter struct{ k *rsa.PrivateKey }

func (tr transmitter) jwks() []byte {
	b, _ := json.Marshal(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(tr.k.PublicKey.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(tr.k.PublicKey.E)).Bytes())}}})
	return b
}

func (tr transmitter) set(t *testing.T, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "k1", "typ": "secevent+jwt"})
	cb, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, tr.k, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

const (
	ssfIss = "https://acme.okta.com"
	ssfAud = "https://admin.acme.example/feeds/signals"
)

func event(jti, uri string, sub map[string]any, ev map[string]any) map[string]any {
	return map[string]any{"iss": ssfIss, "aud": ssfAud, "jti": jti, "iat": time.Now().Unix(),
		"sub_id": sub, "events": map[string]any{uri: ev}}
}
