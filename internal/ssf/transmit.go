// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package ssf

// The transmitter half: this deployment as the sender, not the receiver.
//
// Everything above this file in the package is about reading what other
// platforms say. The other direction is the agent kill switch's outward half
// (docs/research/02-access-control.md §8.5): a session-revoked event about an
// agent, pushed to every platform configured to hear it, so a kill here is a
// kill everywhere that trusted the agent — AC-2(3), the flagship gap in the
// NIST map.
//
// # The subject is named, not pseudonymised
//
// The audit log records people as pseudonyms because it is read by many and
// a name in it is a disclosure. An SSF subject is the opposite: the receiver
// can only act on an event if it can tell who the event is about, so the
// agent's registry name goes in the clear, as an iss_sub subject in this
// deployment's own namespace. That is the honest choice for an agent rather
// than a person — a registry name is a clear identifier by design, and
// pseudonymising it would send the receiver a subject it could never resolve.
// No person is named: the reason an operator typed travels as reason_admin
// for the receiving administrators, which is who CAEP writes it for.
//
// # Why ES256 and not the audit head's Ed25519
//
// The research note suggests signing with the existing Ed25519 head key. The
// receiver this package already ships cannot verify that: oidc.VerifyJWS —
// the same code that checks ID tokens, and the whole argument for reusing it —
// holds a closed algorithm list and EdDSA is not on it. A SET no SSF receiver
// can read is a letter posted unsigned; ES256 is on every receiver's list,
// including this one's (inboundserve accepts RS256, ES256 and PS256), and the
// key machinery is the same as the rest of this program's: a P-256 key made
// on the operator's machine, its public half published for whoever verifies.
// The token is built and signed by hand — encoding/base64 and crypto, no JWT
// library — exactly as the receiver's tests build theirs, so the shape this
// emits is the shape that side proves.
//
// # One token per receiver
//
// The audience claim names the receiver being addressed, so two receivers get
// two tokens: one event, minted per destination. A token addressed to
// everybody is a token nobody can tell was meant for them, and the audience
// check on the receiving side is what stops a captured push being replayed to
// a third platform.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SecEventJWT is the content type a push carries (RFC 8417, delivered per
// RFC 8935): the token alone, as the body.
const SecEventJWT = "application/secevent+jwt"

// GenerateKey makes the transmitter's P-256 key.
//
// ES256 rather than RS256 because a stateless token verified by many is the
// case short signatures were for, and rather than EdDSA because of the
// algorithm list above. The private half never leaves the machine it is made
// on; the public half travels as a JWK (JWKS below).
func GenerateKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("no key could be made: %w", err)
	}
	return key, nil
}

// Emitter is this deployment as a transmitter: one key, one issuer, and the
// events it may send about the subjects it owns.
type Emitter struct {
	Key    *ecdsa.PrivateKey
	KeyID  string
	Issuer string
	Now    func() time.Time
}

func (e *Emitter) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// KeyID is the name a receiver knows the transmitter's public key by: a
// fingerprint over the key itself, so the id in a token's header resolves to
// exactly one key and a rotated key is a new id rather than a new meaning
// for an old one.
func KeyID(pub *ecdsa.PublicKey) string {
	size := (pub.Curve.Params().BitSize + 7) / 8
	sum := sha256.Sum256(append(pub.X.FillBytes(make([]byte, size)),
		pub.Y.FillBytes(make([]byte, size))...))
	return "aertun-ssf-" + hex.EncodeToString(sum[:])[:12]
}

// NewEmitter checks what a transmitter has to have: a P-256 key, and an
// issuer that is an https address (http only on this machine, for a
// deployment trying the receiving half out against itself). The issuer is
// this deployment's own address — the same one the console publishes —
// because it is the one string every receiver agrees to compare exactly.
func NewEmitter(key *ecdsa.PrivateKey, issuer string) (*Emitter, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("the transmitter signs with a P-256 key (ES256)")
	}
	issuer = strings.TrimSpace(issuer)
	u, err := url.Parse(issuer)
	if err != nil || issuer == "" || u.Host == "" || u.User != nil ||
		(u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname()))) {
		return nil, fmt.Errorf("%q is not an issuer an https receiver would "+
			"compare exactly. Give this deployment's own address, the one "+
			"set as admin.base_url", issuer)
	}
	return &Emitter{Key: key, KeyID: KeyID(&key.PublicKey), Issuer: issuer}, nil
}

func loopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// agentSub is the subject claim for a registered agent: the registry name in
// this deployment's namespace, an iss_sub subject the receiving side can
// resolve to this store's register.
func (e *Emitter) agentSub(agent string) Subject {
	return Subject{Format: "iss_sub", Iss: e.Issuer, Sub: agent}
}

// SessionRevoked builds and signs the event the kill switch sends: CAEP
// session-revoked about one agent, addressed to one receiver. It returns the
// token and its jti, so the caller can record both.
//
// The token is a compact JWS built by hand: the header and the claims are
// marshalled once, the signature covers the two base64url segments exactly
// as they will travel, and the ECDSA signature is JWS's fixed-width r||s
// rather than ASN.1 — the two encodings silently fail against each other,
// which is worth saying because this is the one place in the program that
// writes that form rather than reading it.
func (e *Emitter) SessionRevoked(agent, audience, reason string) (token, jti string, err error) {
	agent = strings.TrimSpace(agent)
	if agent == "" || len(agent) > 128 {
		return "", "", fmt.Errorf("an event is about one named agent")
	}
	audience = strings.TrimSpace(audience)
	if u, aerr := url.Parse(audience); aerr != nil || audience == "" || u.Host == "" || u.User != nil {
		return "", "", fmt.Errorf("%q is not an address a receiver listens on", audience)
	}
	raw := make([]byte, 16)
	if _, err = rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("no randomness for an event id: %w", err)
	}
	jti = hex.EncodeToString(raw)
	now := e.now()

	// reason_admin is for the receiving administrators, and CAEP allows it as
	// text or as a language map; a map with one language is the form every
	// implementation reads. The kill switch's --why is a sentence a person
	// typed under pressure, so it travels as written rather than paraphrased.
	event := map[string]any{
		"initiating_entity": "admin",
		"event_timestamp":   now.Unix(),
	}
	if r := strings.TrimSpace(reason); r != "" {
		event["reason_admin"] = map[string]any{"en": r}
	}
	claims := struct {
		Iss    string         `json:"iss"`
		Aud    string         `json:"aud"`
		Iat    int64          `json:"iat"`
		JTI    string         `json:"jti"`
		Txn    string         `json:"txn,omitempty"`
		SubID  Subject        `json:"sub_id"`
		Events map[string]any `json:"events"`
	}{
		Iss: e.Issuer, Aud: audience, Iat: now.Unix(), JTI: jti,
		Txn:   "agent-disable/" + agent,
		SubID: e.agentSub(agent),
		Events: map[string]any{
			caepPrefix + "session-revoked": event,
		},
	}
	header := struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}{Alg: "ES256", Kid: e.KeyID, Typ: "secevent+jwt"}

	var hb, cb []byte
	if hb, err = json.Marshal(header); err != nil {
		return "", "", err
	}
	if cb, err = json.Marshal(claims); err != nil {
		return "", "", err
	}
	in := base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(cb)
	digest := sha256.Sum256([]byte(in))
	r, s, serr := ecdsa.Sign(rand.Reader, e.Key, digest[:])
	if serr != nil {
		return "", "", fmt.Errorf("the event could not be signed: %w", serr)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return in + "." + base64.RawURLEncoding.EncodeToString(sig), jti, nil
}

// JWKS is the transmitter's public half, as the document a receiver's key
// source reads: one EC key, named by the same kid a token's header carries.
// Nothing in it is secret; it is what an operator hands the receiving side.
func (e *Emitter) JWKS() []byte {
	pub := &e.Key.PublicKey
	size := (pub.Curve.Params().BitSize + 7) / 8
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	out, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": e.KeyID, "use": "sig",
		"x": b64(pub.X.FillBytes(make([]byte, size))),
		"y": b64(pub.Y.FillBytes(make([]byte, size))),
	}}})
	return out
}

// Deliver pushes one token to one receiver (RFC 8935): the token as the
// body, the content type saying what it is, and the receiver's bearer token
// when one was agreed. Any 2xx is a delivery — receivers answer 202 Accepted
// when the event is taken but not yet acted on, which is their right and not
// a failure.
//
// The client is the caller's, so the address rules and the network mode are
// decided where the configuration is known (internal/fetch, internal/egress);
// this side has no dialler of its own.
func (e *Emitter) Deliver(ctx context.Context, client *http.Client, receiver, token, bearer string) error {
	if client == nil {
		return fmt.Errorf("no HTTP client was given to deliver with")
	}
	body := strings.NewReader(token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, receiver, body)
	if err != nil {
		return fmt.Errorf("%s is not an address: %w", receiver, err)
	}
	req.Header.Set("Content-Type", SecEventJWT)
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(bearer) != "" {
		// The receiver's own secret, sent to the receiver and nowhere else;
		// this client does not follow redirects, so it cannot be carried
		// anywhere the configuration did not name.
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(bearer))
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(res.Body, 4<<10))
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("%s answered %d (%s)", receiver, res.StatusCode, refusal(msg))
}

// refusal reads a receiver's no in the shapes this program's own receiver
// and the framework's error answers use, so a failure is the receiver's
// words rather than a bare status.
func refusal(msg []byte) string {
	var e struct {
		Err         string `json:"err"`
		Description string `json:"description"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
		Message     string `json:"message"`
	}
	_ = json.Unmarshal(msg, &e)
	why := strings.Join(strings.Fields(e.Err+" "+e.Description+" "+
		e.Error+" "+e.ErrorDesc+" "+e.Message), " ")
	if len(why) > 200 {
		why = why[:200]
	}
	if why == "" {
		why = "no reason given"
	}
	return why
}
