// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package macaroon is the caveat half of a run credential: the limits a
// run's token carries — which tools, until when, how many calls, for what
// purpose, at what autonomy — signed when the token is minted.
//
// # What a token here is
//
// A token is one string, in two halves:
//
//	<credential>.aet1.<base64url(payload)>
//
// The credential half is an ordinary Aertun token secret (internal/auth): it
// is what the token store hashes, so revocation, expiry, the registry gate
// and the kill switch reach a run token exactly as they reach any
// credential, with no second store and no other issuer. The payload names
// the run the token was minted for and its caveats, and ends in an Ed25519
// signature by the store's minting key over a domain string, the run and
// every caveat, in order.
//
// # Who can do what to a token
//
//   - The minter (aertun agent token, and the token exchange) holds the
//     minting key (agents.key) and the token store. It mints: a fresh secret, a run id, the caveats, the signature.
//   - The verifier (the agent interface's tool gate) holds only the public
//     half (agents.pub). It checks the signature, then hands each caveat to
//     a discharge function that knows what the call is: which tool, what
//     time, how many calls already made. The package decides the token's
//     integrity; the caller's discharge decides its meaning. Holding the
//     public half lets a process check tokens and never make one.
//   - The holder can do nothing to the caveats. Removing one, adding one,
//     reordering them or changing a value changes the signed bytes, and the
//     signature no longer verifies. They cannot present the bare credential
//     in place of the token either: the store entry's name carries the run,
//     and the gate that checks caveats refuses a run-bound credential that
//     arrives without its payload (cmd/aertun, authoriseTool).
//
// A narrower token is minted, never derived. An earlier format let a holder
// append caveats to an HMAC chain; with the chain's start computable from
// the token itself, the same holder could also remove them, so narrowing a
// token in hand bought nothing and its appearance of safety was worse than
// its absence. The token exchange mints the narrower token instead, with
// the minting key, and records that it did.
//
// # Why first-party only
//
// Every caveat this program mints is a predicate the verifying process can
// settle itself, because it already holds what settling needs: the
// registry, the clock and the counter. Third-party caveats would add a
// discharge protocol and replay state on both sides and would buy this
// deployment nothing; the set of kinds is closed and every one is
// first-party.
//
// # What this does not do
//
// The calls caveat states a budget; the verifying process counts calls
// against it in a ledger kept on disk under a lock (cmd/aertun), so a
// restart does not reset it. And the caveats bind the tool surface: on the
// command line, which has no tools, a run token is an ordinary scoped
// credential, and the mint narrows the credential's role and read-only
// scope to match its caveats so the two bindings never disagree.
package macaroon

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// marker separates the credential half from the caveat payload, with the
// format's version in it, so a change to the grammar cannot be misread as
// the thing it replaced. It never appears in a token secret (the store's
// alphabet has no dots), so the first occurrence is the separator.
const marker = ".aet1."

// signDomain is signed ahead of every payload, so a signature made for a run
// token can never be presented as one made for anything else this key could
// sign; the version rides in the string for the same reason as the marker.
const signDomain = "aertun/macaroon/run-token/v1"

const (
	sigLength     = ed25519.SignatureSize
	maxSecret     = 200
	maxID         = 128
	maxCaveats    = 16
	maxTools      = 16
	maxToolName   = 40
	maxToolValue  = 300
	maxCallsValue = 1 << 30
	maxPayload    = 1024
	maxToken      = 2048
)

// MintKey is the Ed25519 private key that mints run tokens. Whoever holds
// it can create tokens; the public half is all a verifier needs.
type MintKey = ed25519.PrivateKey

// VerifyKey is the Ed25519 public key that verifies run tokens. Whoever
// holds it can check a token was minted by the matching private key, and
// nothing else — they cannot mint, and they cannot forge a root signature.
type VerifyKey = ed25519.PublicKey

// GenerateMintKey makes a new minting key pair.
func GenerateMintKey() (MintKey, VerifyKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// Kind is what a caveat constrains. A closed set, and refusing anything else
// is the point rather than a limitation: an allowlist that accepted a kind
// nothing enforces would be a decoration — a caveat nobody checks is a
// promise the token makes to nobody.
type Kind string

const (
	// KindTool bounds which tools the holder may call. The value is the
	// allowed set, comma-joined; the call's tool must be in it.
	KindTool Kind = "tool"
	// KindExp is a deadline: the value is unix seconds, and a call after it
	// is refused.
	KindExp Kind = "exp"
	// KindCalls is a budget: at most this many calls under the token. The
	// counting is the verifier's (see the package comment).
	KindCalls Kind = "calls"
	// KindPurpose is why the run exists, as one word of a closed vocabulary,
	// so a run minted to watch the queue cannot be spent proposing verdicts.
	KindPurpose Kind = "purpose"
	// KindLevel is an autonomy bound. L0 reads, L1 proposes;
	// a tool that needs more autonomy than the token allows is refused.
	KindLevel Kind = "level"
)

// Kinds lists the closed set, in the order the mint writes them.
func Kinds() []string {
	return []string{string(KindTool), string(KindPurpose), string(KindLevel),
		string(KindExp), string(KindCalls)}
}

// The purposes a run may be minted for, and what they reach. Two words, not
// a free field: a purpose nobody can define in a sentence is a purpose no
// operator can refuse with confidence. observe reads; triage reads and
// proposes. Anything a later phase needs is a word to add here, with its
// reach written beside it — not a string to mint unchecked.
const (
	PurposeObserve = "observe"
	PurposeTriage  = "triage"
)

// ValidPurpose says whether p is a word of the vocabulary.
func ValidPurpose(p string) bool {
	return p == PurposeObserve || p == PurposeTriage
}

// LevelMax is the highest autonomy a caveat may bound: L3. Narrow
// autonomous containment above it is not minted at a command line; "never"
// is not a level at all but the backstops that already refuse it.
const LevelMax = 3

// Caveat is one restriction: a kind from the closed set and a value whose
// grammar the kind fixes. Built through the constructors, which validate, so
// a Caveat that exists is a Caveat that means something.
type Caveat struct {
	Kind  Kind
	Value string
}

// ToolCaveat is the allowed set, canonical (sorted, deduplicated) however it
// was typed, so two spellings of one set are one set.
func ToolCaveat(tools ...string) (Caveat, error) {
	seen := make([]string, 0, len(tools))
	for _, t := range tools {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !toolName(t) {
			return Caveat{}, fmt.Errorf("%q is not a tool name a caveat can "+
				"carry: 1 to 40 letters, digits, hyphens and underscores", t)
		}
		if !contains(seen, t) {
			seen = append(seen, t)
		}
	}
	if len(seen) == 0 {
		return Caveat{}, fmt.Errorf("a tool caveat needs at least one tool")
	}
	if len(seen) > maxTools {
		return Caveat{}, fmt.Errorf("a tool caveat lists at most %d tools", maxTools)
	}
	sort.Strings(seen)
	v := strings.Join(seen, ",")
	if len(v) > maxToolValue {
		return Caveat{}, fmt.Errorf("the tool set is too long for a caveat")
	}
	return Caveat{Kind: KindTool, Value: v}, nil
}

// ExpCaveat is a deadline. An expiry in the past is allowed on purpose: it
// is how a token is minted dead for a test, and how the minter retires a
// run early — the verifier refuses it either way.
func ExpCaveat(at time.Time) Caveat {
	return Caveat{Kind: KindExp, Value: strconv.FormatInt(at.Unix(), 10)}
}

// CallsCaveat is a budget of at least one call. Zero is refused because a
// budget of zero is not a budget but a refusal, and writing it as a caveat
// would let a token that can do nothing look like a token that may do
// something.
func CallsCaveat(n int) (Caveat, error) {
	if n < 1 || n > maxCallsValue {
		return Caveat{}, fmt.Errorf("a calls caveat is at least 1 and at most "+
			"%d calls, not %d", maxCallsValue, n)
	}
	return Caveat{Kind: KindCalls, Value: strconv.Itoa(n)}, nil
}

// PurposeCaveat is the run's purpose, one word of the vocabulary.
func PurposeCaveat(p string) (Caveat, error) {
	if !ValidPurpose(p) {
		return Caveat{}, fmt.Errorf("%q is not a purpose this program has; "+
			"the words are %s and %s", p, PurposeObserve, PurposeTriage)
	}
	return Caveat{Kind: KindPurpose, Value: p}, nil
}

// LevelCaveat bounds autonomy at n. L0–L3; see LevelMax for where L4 lives.
func LevelCaveat(n int) (Caveat, error) {
	if n < 0 || n > LevelMax {
		return Caveat{}, fmt.Errorf("an autonomy caveat is 0 to %d, not %d",
			LevelMax, n)
	}
	return Caveat{Kind: KindLevel, Value: strconv.Itoa(n)}, nil
}

// Tools splits a tool caveat's value. Honest only after Parse, which
// validated the grammar; on anything else it is a split of an arbitrary
// string.
func (c Caveat) Tools() []string { return strings.Split(c.Value, ",") }

// Int reads an exp, calls or level value. The same honesty as Tools: the
// grammar was checked by Parse, so this fails only on a value that was never
// parsed.
func (c Caveat) Int() (int64, error) {
	n, err := strconv.ParseInt(c.Value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("caveat %s carries %q, which is not a number",
			c.Kind, c.Value)
	}
	return n, nil
}

// Token is a parsed run token. Parsing checks its shape; only Verify says
// whether it was minted by a key this store trusts.
type Token struct {
	secret  string
	id      string
	caveats []Caveat
	sig     []byte
}

// ID is the run the token was minted for.
func (t Token) ID() string { return t.id }

// Caveats is a copy of the token's caveats, in minted order.
func (t Token) Caveats() []Caveat { return append([]Caveat(nil), t.caveats...) }

// Mint makes a run token: the credential secret, the run id and the caveats,
// signed with the minting key. At least one caveat, each kind at most once.
func Mint(secret string, mint MintKey, id string, caveats ...Caveat) (string, error) {
	if secret == "" || len(secret) > maxSecret || strings.ContainsAny(secret, ".") {
		return "", fmt.Errorf("a run token wraps a credential secret: short, " +
			"and dot-free so the halves cannot be confused")
	}
	if len(mint) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("the minting key is an Ed25519 private key "+
			"(%d bytes), not %d bytes", ed25519.PrivateKeySize, len(mint))
	}
	if !runID(id) {
		return "", fmt.Errorf("%q is not a run id: 1 to 128 letters, digits, "+
			"hyphens, slashes and colons", id)
	}
	if len(caveats) == 0 {
		return "", fmt.Errorf("a run token is minted with at least one caveat; " +
			"a caveat-free one is just a credential wearing a suffix")
	}
	if len(caveats) > maxCaveats {
		return "", fmt.Errorf("a run token carries at most %d caveats", maxCaveats)
	}
	seen := map[Kind]bool{}
	for _, c := range caveats {
		if !validCaveat(c) {
			return "", fmt.Errorf("caveat %s=%s is not one this program mints",
				c.Kind, c.Value)
		}
		if seen[c.Kind] {
			return "", fmt.Errorf("caveat %s appears twice; a token states each "+
				"kind once, and a narrower token is minted, not appended to", c.Kind)
		}
		seen[c.Kind] = true
	}
	b := body(id, caveats)
	sig := ed25519.Sign(mint, signed(b))
	return secret + marker + base64.RawURLEncoding.EncodeToString(append(b, sig...)), nil
}

// Split returns the credential half of a presented token, for the paths
// that authenticate the credential and leave the caveats to the tool gate.
func Split(presented string) (string, bool) {
	secret, _, ok := halves(presented)
	return secret, ok
}

// Parse reads a token's shape: the halves, the run id, each caveat's kind
// and value, and the signature's length. It does not check the signature.
func Parse(token string) (Token, bool) {
	secret, enc, ok := halves(token)
	if !ok {
		return Token{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil || len(raw) > maxPayload {
		return Token{}, false
	}
	id, caveats, sig, err := frame(raw)
	if err != nil || !runID(id) {
		return Token{}, false
	}
	for _, c := range caveats {
		if !validCaveat(c) {
			return Token{}, false
		}
	}
	return Token{secret: secret, id: id, caveats: caveats, sig: sig}, true
}

// Verify checks a token's signature against the store's public key, then
// asks discharge about each caveat in order. Every caveat must hold.
func Verify(token string, verifyKey VerifyKey, discharge func(Caveat) error) error {
	t, ok := Parse(token)
	if !ok {
		return fmt.Errorf("the token is not shaped like something this " +
			"program minted: the halves, a kind or a value is wrong")
	}
	if len(verifyKey) != ed25519.PublicKeySize {
		return fmt.Errorf("the verification key is an Ed25519 public key "+
			"(%d bytes)", ed25519.PublicKeySize)
	}
	if !ed25519.Verify(verifyKey, signed(body(t.id, t.caveats)), t.sig) {
		return fmt.Errorf("the signature does not verify under this store's " +
			"key, so the token is not as it was minted, or was not minted here")
	}
	for _, c := range t.caveats {
		if err := discharge(c); err != nil {
			return fmt.Errorf("caveat %s: %v", c.Kind, err)
		}
	}
	return nil
}

// -- the frame -------------------------------------------------------------

// body frames the run id and the caveats with explicit lengths, so no two
// different tokens frame to the same bytes:
//
//	u16 id length | id | u8 count | (u8 kind length | kind | u16 value
//	length | value)*
//
// The payload is the body followed by the 64-byte signature.
func body(id string, caveats []Caveat) []byte {
	b := make([]byte, 0, len(id)+len(caveats)*16)
	b = append(b, byte(len(id)>>8), byte(len(id)))
	b = append(b, id...)
	b = append(b, byte(len(caveats)))
	for _, c := range caveats {
		b = append(b, byte(len(c.Kind)))
		b = append(b, c.Kind...)
		b = append(b, byte(len(c.Value)>>8), byte(len(c.Value)))
		b = append(b, c.Value...)
	}
	return b
}

// signed is what the signature covers: the domain, a NUL, then the body.
func signed(b []byte) []byte {
	return append(append([]byte(signDomain), 0), b...)
}

// frame reads a payload back into its parts, refusing anything that does
// not end exactly in a signature.
func frame(raw []byte) (id string, caveats []Caveat, sig []byte, err error) {
	if len(raw) < 2+1+1+1+sigLength {
		return "", nil, nil, fmt.Errorf("shorter than a token can be")
	}
	n := 0
	idLen := int(raw[0])<<8 | int(raw[1])
	n = 2
	if idLen == 0 || idLen > maxID || n+idLen > len(raw) {
		return "", nil, nil, fmt.Errorf("the id does not fit")
	}
	id = string(raw[n : n+idLen])
	n += idLen
	count := int(raw[n])
	n++
	if count == 0 || count > maxCaveats {
		return "", nil, nil, fmt.Errorf("%d caveats is not a count this program writes", count)
	}
	caveats = make([]Caveat, 0, count)
	for i := 0; i < count; i++ {
		if n >= len(raw) {
			return "", nil, nil, fmt.Errorf("a caveat ends mid-frame")
		}
		kindLen := int(raw[n])
		n++
		if kindLen == 0 || n+kindLen+2 > len(raw) {
			return "", nil, nil, fmt.Errorf("a kind does not fit")
		}
		kind := Kind(raw[n : n+kindLen])
		n += kindLen
		valLen := int(raw[n])<<8 | int(raw[n+1])
		n += 2
		if n+valLen > len(raw) {
			return "", nil, nil, fmt.Errorf("a value does not fit")
		}
		caveats = append(caveats, Caveat{Kind: kind, Value: string(raw[n : n+valLen])})
		n += valLen
	}
	if len(raw)-n != sigLength {
		return "", nil, nil, fmt.Errorf("the payload does not end in a signature")
	}
	return id, caveats, raw[n:], nil
}

// halves splits a presented string at the marker and checks only what the
// loosest reader — the credential path — needs: both halves present, both
// within their caps, the payload decodable. Shared by Split and Parse so the
// two can never disagree about where the halves are.
func halves(presented string) (secret, enc string, ok bool) {
	if len(presented) == 0 || len(presented) > maxToken {
		return "", "", false
	}
	i := strings.Index(presented, marker)
	if i <= 0 || i > maxSecret {
		return "", "", false
	}
	secret, enc = presented[:i], presented[i+len(marker):]
	if enc == "" {
		return "", "", false
	}
	if raw, err := base64.RawURLEncoding.DecodeString(enc); err != nil || len(raw) == 0 || len(raw) > maxPayload {
		return "", "", false
	}
	return secret, enc, true
}

// -- validation ------------------------------------------------------------

// validCaveat says whether kind and value are ones this program writes.
// Refusing is the closed-set rule: an unknown kind in a parsed token is a
// forged or future token, and this program's answer to both is no.
func validCaveat(c Caveat) bool {
	switch c.Kind {
	case KindTool:
		tools := c.Tools()
		if len(tools) == 0 || len(tools) > maxTools || len(c.Value) > maxToolValue {
			return false
		}
		for i, t := range tools {
			if !toolName(t) {
				return false
			}
			// Canonical order: two spellings of one set are one set, and a
			// set out of order is a set this program did not write.
			if i > 0 && tools[i-1] >= t {
				return false
			}
		}
		return true
	case KindExp, KindCalls, KindLevel:
		if len(c.Value) == 0 || len(c.Value) > 11 || !digits(c.Value) {
			return false
		}
		if c.Kind == KindLevel {
			return c.Value == "0" || c.Value == "1" || c.Value == "2" || c.Value == "3"
		}
		if c.Kind == KindCalls {
			n, err := strconv.Atoi(c.Value)
			return err == nil && n >= 1 && n <= maxCallsValue
		}
		return true
	case KindPurpose:
		return ValidPurpose(c.Value)
	}
	return false
}

func toolName(s string) bool {
	if len(s) == 0 || len(s) > maxToolName {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// runID is the shape of a minter's name: agent name, a slash, a run id —
// but the package only fixes the alphabet and the length, because which
// minter names a run is the minter's grammar, not the token's.
func runID(s string) bool {
	if len(s) == 0 || len(s) > maxID {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' ||
			r == '-' || r == '/' || r == ':') {
			return false
		}
	}
	return true
}

func digits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
