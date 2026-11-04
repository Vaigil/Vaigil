// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

// Package macaroon is the caveat half of a run credential: an HMAC-SHA256
// chain over an ordered list of caveats, in the shape of a v2 macaroon and
// first-party only.
//
// # What a token here is
//
// A token is one string, in two halves:
//
//	<credential>.vgt1.<base64url(payload)>
//
// The credential half is an ordinary aertun token secret (internal/auth): it
// is what the token store hashes, so revocation, expiry, the registry gate
// and the kill switch reach a run token exactly as they reach any credential,
// with no second store and no other issuer. The payload half names the run it
// was minted for and the caveats bound to it, and ends in a tag: the last
// link of a chain that started under the store's run key (agents.key, held
// by whoever mints and whoever verifies, and by nobody else).
//
// The chain is the v2 macaroon construction. The first signature is
// HMAC-SHA256(run key, "aertun/macaroon/root/v1" || id); each caveat is
// signed with the signature before it, so appending one needs nothing but
// the tag it follows — which is in the token — and forging or removing one
// needs the run key, which is not. Verification recomputes the chain from
// the run key and compares the last link in constant time (hmac.Equal, the
// compare internal/audit already uses for pseudonyms).
//
// # Why first-party only
//
// A v2 macaroon can carry third-party caveats: ones a named discharger
// answers with a proof the verifier checks. There is no third party here.
// Every caveat this program mints — a tool set, a deadline, a call budget, a
// purpose, an autonomy level — is a predicate the verifying process can
// settle itself, because it already holds what settling needs: the registry,
// the clock and the counter. Third-party caveats would add a discharge
// protocol, caveat-key escrow at the discharger, and replay state on both
// sides, and would buy this deployment nothing it does not already have. The
// design keeps the door open (docs/research/02-access-control.md §8.4); the
// honest position until a discharger exists is that the set of kinds is
// closed and every one of them is first-party.
//
// # Who can do what to a token
//
//   - The minter (aertun agent token) holds the run key and the token store.
//     It mints: a fresh secret, a run id, caveats, the chain.
//   - The holder can attenuate (Attenuate): append a caveat, signed with the
//     tag already in the token. They cannot widen — not by appending (every
//     caveat must hold, so appending only intersects) and not by editing
//     (any change to the payload breaks the chain, which only the run key
//     can re-make). They cannot strip the caveats and present the bare
//     credential either: the store entry's name carries the run, and the one
//     gate that checks caveats refuses a run-bound credential that arrives
//     without its payload (cmd/aertun, authoriseTool).
//   - The verifier (the agent interface's tool gate) holds the run key and
//     checks the chain, then hands each caveat to a discharge function that
//     knows what the call is: which tool, what time, how many calls already
//     made. The package decides the token's integrity; the caller's
//     discharge decides its meaning.
//
// # Honesty about the two things this does not do
//
// The calls caveat is verified statelessly; the budget itself is counted by
// the verifying process, per token, in memory. A restart of that process
// resets every budget, and two processes each honour the full budget — the
// deadline and the credential's own expiry are what bound that. A durable,
// cross-process ledger is the design's later phase (§6.12), not something to
// half-build inside a verifier.
//
// And the caveats bind the tool surface. On a surface that has no tools —
// the command line — a run token is an ordinary scoped credential: its role,
// its resource, its read-only scope, its expiry and its revocation all hold,
// but there is no "tool" there for a tool caveat to speak about. The mint
// narrows the credential's coarse bounds to match its caveats (viewer-grade,
// read-only, when the caveats say no writing), so the fine binding and the
// coarse one never disagree.
package macaroon

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// marker is what separates the credential half from the caveat payload, with
// a version in it so a change to the grammar cannot be misread as the thing
// it replaced. It never appears in a token secret (the store's alphabet has
// no dots), so the first occurrence is the separator.
const marker = ".vgt1."

// Domain separation, the same discipline the audit head signatures use
// (internal/audit/sign.go): a MAC made for one purpose must not be a MAC
// made for another, and the version rides in the string so a change to what
// is signed is not confused with the thing it replaced.
const (
	rootDomain    = "aertun/macaroon/root/v1"
	caveatDomain  = "aertun/macaroon/caveat/v1"
	runKeyLength  = 32
	maxSecret     = 200
	maxID         = 128
	maxCaveats    = 16 // at mint; attenuation may take it to maxTotal
	maxTotal      = 32
	maxTools      = 16
	maxToolName   = 40
	maxToolValue  = 300
	maxCallsValue = 1 << 30
	maxPayload    = 1024
	maxToken      = 2048
)

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
	// KindLevel is an autonomy bound (research §6.9). L0 reads, L1 proposes;
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

// PurposeNarrowsTo says whether candidate reaches no more than older —
// observe narrows triage, nothing narrows observe but itself, and a word
// outside the vocabulary narrows nothing.
func PurposeNarrowsTo(candidate, older string) bool {
	switch candidate {
	case PurposeObserve:
		return ValidPurpose(older)
	case PurposeTriage:
		return older == PurposeTriage
	}
	return false
}

// LevelMax is the highest autonomy a caveat may bound: L3. L4 — narrow
// autonomous containment — is the interpreter's to grant when that phase
// exists, behind the calibrated gates and the global kill switch the design
// requires first (§6.9); a caveat minted at a command line is not the place
// L4 is born, and "never" is not a level at all but the backstops that
// already refuse it.
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
// is how a token is minted dead for a test, and how attenuation retires one
// early — the verifier refuses it either way.
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

// Token is a parsed caveat payload. The credential half is carried but not
// exposed: the package's job is the caveats, and a caller wanting the
// credential a run token wraps has Split, which says what it is for.
type Token struct {
	secret  string
	id      string
	caveats []Caveat
	tag     []byte
}

// ID is the minter's name for the run — agent name and run id — which is
// what an audit record cites when a caveat refuses a call.
func (t Token) ID() string { return t.id }

// Caveats lists what the token binds, in chain order. A copy: the chain is
// append-only and a caller must not be able to rearrange what it will be
// verified against.
func (t Token) Caveats() []Caveat { return append([]Caveat(nil), t.caveats...) }

// Mint builds a run token: the given credential half, the run's id, and
// caveats signed into a chain under rootSecret.
//
// The id names its minter — agent name and run id — because the audit trail
// has to answer "which run was this minted for" from the token alone, with
// no store lookup that revocation could break.
func Mint(secret string, rootSecret []byte, id string, caveats ...Caveat) (string, error) {
	if secret == "" || len(secret) > maxSecret || strings.ContainsAny(secret, ".") {
		return "", fmt.Errorf("a run token wraps a credential secret: short, " +
			"and dot-free so the halves cannot be confused")
	}
	if len(rootSecret) != runKeyLength {
		return "", fmt.Errorf("the run key is %d bytes; a chain under anything "+
			"else is a chain under a key nobody agreed on", runKeyLength)
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
			return "", fmt.Errorf("caveat %s appears twice; a minted token "+
				"states each kind once and attenuation narrows it after", c.Kind)
		}
		seen[c.Kind] = true
	}
	sig := rootSig(rootSecret, id)
	for _, c := range caveats {
		sig = bindSig(sig, c)
	}
	return envelope(secret, payload(id, caveats, sig)), nil
}

// Split is the credential half of a presented run token, and whether the
// string is shaped like one at all.
//
// Deliberately loose: it checks the marker, the sizes and that the payload
// decodes, and nothing else. The token store authenticates the credential
// half without knowing the payload exists, and it must keep doing so even
// when the payload is garbage a tampered string carries — the bearer is
// still the bearer, and the caveat gate, not the store, is where a payload
// that does not verify is refused. Parsing the payload is Parse's job.
func Split(presented string) (string, bool) {
	secret, _, ok := halves(presented)
	return secret, ok
}

// Parse is a strict read: the halves, the framing, the closed set of kinds,
// every value's grammar, no trailing bytes. A token that does not parse is
// not one this program minted, and the caller treats that as a refusal
// rather than a puzzle.
func Parse(token string) (Token, bool) {
	secret, enc, ok := halves(token)
	if !ok {
		return Token{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil || len(raw) > maxPayload {
		return Token{}, false
	}
	id, caveats, tag, err := frame(raw)
	if err != nil {
		return Token{}, false
	}
	if !runID(id) {
		return Token{}, false
	}
	for _, c := range caveats {
		if !validCaveat(c) {
			return Token{}, false
		}
	}
	return Token{secret: secret, id: id, caveats: caveats, tag: tag}, true
}

// Attenuate appends caveats to a token, returning the narrowed token.
//
// Only narrows, and says so when asked to do anything else: a wider tool
// set, a later deadline, a larger budget, a higher level or a purpose that
// reaches further are each refused rather than clamped, because a caller
// told "done" with a silently narrower token believes it holds what it asked
// for, and the refusal is the only honest answer.
//
// No run key is needed and none is taken: appending signs with the tag the
// token already carries, which is the property that makes attenuation
// cheap — the holder can narrow what they hold without a round trip to
// anybody. The result still verifies only if the token it came from did,
// because the head of the chain is the run key either way.
func Attenuate(token string, more ...Caveat) (string, error) {
	t, ok := Parse(token)
	if !ok {
		return "", fmt.Errorf("only a token that parses can be attenuated; " +
			"this one is not shaped like something this program minted")
	}
	if len(more) == 0 {
		return "", fmt.Errorf("attenuation needs a caveat to add")
	}
	if len(t.caveats)+len(more) > maxTotal {
		return "", fmt.Errorf("a run token carries at most %d caveats, counted "+
			"through attenuation", maxTotal)
	}
	for _, c := range more {
		if !validCaveat(c) {
			return "", fmt.Errorf("caveat %s=%s is not one this program mints",
				c.Kind, c.Value)
		}
		why, ok := narrows(c, t.caveats)
		if !ok {
			return "", fmt.Errorf("refusing to attenuate: caveat %s=%s does not "+
				"narrow this token (%s); attenuation only ever narrows, and a "+
				"wider token is minted, not attenuated", c.Kind, c.Value, why)
		}
	}
	cs := append(t.Caveats(), more...)
	sig := append([]byte(nil), t.tag...)
	for _, c := range more {
		sig = bindSig(sig, c)
	}
	return envelope(t.secret, payload(t.id, cs, sig)), nil
}

// Verify checks a run token end to end: parse, recompute the chain under
// rootSecret, compare the tag in constant time, then hand every caveat to
// discharge, which answers for the call being made — which tool, what time,
// how many calls so far. A discharge refusal names its caveat; the chain
// failure names nobody, because a token that does not verify is not a
// decision about the call but a string.
func Verify(token string, rootSecret []byte, discharge func(Caveat) error) error {
	t, ok := Parse(token)
	if !ok {
		return fmt.Errorf("the token is not shaped like something this " +
			"program minted: the halves, a kind or a value is wrong")
	}
	if len(rootSecret) != runKeyLength {
		return fmt.Errorf("the run key is not the %d bytes this store mints "+
			"with, so nothing minted by it can be verified here", runKeyLength)
	}
	sig := rootSig(rootSecret, t.id)
	for _, c := range t.caveats {
		sig = bindSig(sig, c)
	}
	if !hmac.Equal(sig, t.tag) {
		return fmt.Errorf("the caveat chain does not verify under this " +
			"store's run key, so the token is not as it was minted")
	}
	for _, c := range t.caveats {
		if err := discharge(c); err != nil {
			return fmt.Errorf("caveat %s: %v", c.Kind, err)
		}
	}
	return nil
}

// -- the chain ------------------------------------------------------------

func rootSig(rootSecret []byte, id string) []byte {
	m := hmac.New(sha256.New, rootSecret)
	m.Write([]byte(rootDomain))
	m.Write([]byte(id))
	return m.Sum(nil)
}

func bindSig(prev []byte, c Caveat) []byte {
	m := hmac.New(sha256.New, prev)
	m.Write([]byte(caveatDomain))
	m.Write([]byte(c.Kind))
	m.Write([]byte{0})
	m.Write([]byte(c.Value))
	return m.Sum(nil)
}

// -- serialization ---------------------------------------------------------

// payload frames id, the caveats and the tag with explicit lengths, so a
// reader never guesses where anything ends:
//
//	u16 id length | id | u8 count | (u8 kind length | kind | u16 value
//	length | value)* | 32-byte tag
//
// Lengths, not separators, because every other field of a caveat is a
// string that could contain any separator a simpler grammar might choose.
func payload(id string, caveats []Caveat, tag []byte) []byte {
	b := make([]byte, 0, len(id)+len(caveats)*12+64)
	b = append(b, byte(len(id)>>8), byte(len(id)))
	b = append(b, id...)
	b = append(b, byte(len(caveats)))
	for _, c := range caveats {
		b = append(b, byte(len(c.Kind)))
		b = append(b, c.Kind...)
		b = append(b, byte(len(c.Value)>>8), byte(len(c.Value)))
		b = append(b, c.Value...)
	}
	return append(b, tag...)
}

func frame(raw []byte) (id string, caveats []Caveat, tag []byte, err error) {
	if len(raw) < 2+1+1+1+32 {
		return "", nil, nil, fmt.Errorf("shorter than a token can be")
	}
	n := 0
	idLen := int(raw[0])<<8 | int(raw[1])
	n = 2
	if idLen == 0 || n+idLen > len(raw) {
		return "", nil, nil, fmt.Errorf("the id does not fit")
	}
	id = string(raw[n : n+idLen])
	n += idLen
	count := int(raw[n])
	n++
	if count == 0 || count > maxTotal {
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
	if len(raw)-n != 32 {
		return "", nil, nil, fmt.Errorf("the tag is not the 32 bytes a chain ends in")
	}
	return id, caveats, raw[n:], nil
}

// halves splits a presented string at the marker and checks only what the
// loosest reader — the credential path — needs: both halves present, both
// within their caps, the payload decodable. Shared by Split and Parse so
// the two can never disagree about where the halves are.
func halves(presented string) (secret, enc string, ok bool) {
	if len(presented) == 0 || len(presented) > maxToken {
		return "", "", false
	}
	i := strings.Index(presented, marker)
	if i <= 0 || i > maxSecret {
		return "", "", false
	}
	secret, enc = presented[:i], presented[i+len(marker):]
	if enc == "" || len(enc) > maxToken {
		return "", "", false
	}
	if raw, err := base64.RawURLEncoding.DecodeString(enc); err != nil || len(raw) > maxPayload || len(raw) == 0 {
		return "", "", false
	}
	return secret, enc, true
}

func envelope(secret string, p []byte) string {
	return secret + marker + base64.RawURLEncoding.EncodeToString(p)
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

// narrows says whether c is within every existing caveat of its kind, and
// fills in why not when it is not — the refusal a caller reads has to name
// the bound that was exceeded, or it is a shrug.
func narrows(c Caveat, existing []Caveat) (string, bool) {
	for _, x := range existing {
		if x.Kind != c.Kind {
			continue
		}
		switch c.Kind {
		case KindTool:
			have := set(x.Tools())
			for _, t := range c.Tools() {
				if !have[t] {
					return fmt.Sprintf("%s is not in the allowed %s", t, x.Value), false
				}
			}
		case KindExp, KindCalls, KindLevel:
			cn, err1 := c.Int()
			xn, err2 := x.Int()
			if err1 != nil || err2 != nil || cn > xn {
				return fmt.Sprintf("this token bound it at %s", x.Value), false
			}
		case KindPurpose:
			if !PurposeNarrowsTo(c.Value, x.Value) {
				return fmt.Sprintf("this token's purpose is %s", x.Value), false
			}
		default:
			return fmt.Sprintf("%s is not a kind this program knows", c.Kind), false
		}
	}
	return "", true
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

func set(list []string) map[string]bool {
	out := make(map[string]bool, len(list))
	for _, s := range list {
		out[s] = true
	}
	return out
}
