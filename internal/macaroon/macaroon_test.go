// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package macaroon

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// The signature, the closed set of kinds, and the shapes — the properties
// everything else in this program leans on when it refuses a call.
//
// The matrix this file holds, each row at the package boundary the gate
// itself calls:
//
//	minted with each kind              verifies, and the discharge saw it
//	any payload byte changed           refused by the signature
//	a caveat removed, widened, added   refused by the signature
//	or reordered, under the old one
//	an unknown kind                    refused at mint, at parse, everywhere
//	the shapes                         size-capped, halves unconfusable

// aKeyPair is the Ed25519 pair every test in this file mints and verifies
// with, generated once so the tests are deterministic within a run.
var aKeyPair = func() struct {
	priv MintKey
	pub  VerifyKey
} {
	priv, pub, err := GenerateMintKey()
	if err != nil {
		panic(err)
	}
	return struct {
		priv MintKey
		pub  VerifyKey
	}{priv, pub}
}()

// aKey is the private half, what a minter holds.
func aKey() MintKey { return aKeyPair.priv }

// aPub is the public half, what a verifier holds.
func aPub() VerifyKey { return aKeyPair.pub }

// minted builds a token carrying one of every kind, the shape the command
// mints when an operator names every bound there is.
func minted(t *testing.T) string {
	t.Helper()
	exp := ExpCaveat(time.Now().Add(time.Hour).UTC())
	calls, err := CallsCaveat(5)
	if err != nil {
		t.Fatal(err)
	}
	purpose, err := PurposeCaveat(PurposeTriage)
	if err != nil {
		t.Fatal(err)
	}
	level, err := LevelCaveat(1)
	if err != nil {
		t.Fatal(err)
	}
	tools, err := ToolCaveat("aertun_read", "aertun_write")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := Mint("aet_testsecret", aKey(), "agent:watcher/run-1",
		tools, purpose, level, exp, calls)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestMintVerifyRoundTripEachKind: the row that must succeed. Every caveat
// reaches the discharge function in the order it was minted, and a discharge that says
// yes to everything ends in yes.
func TestMintVerifyRoundTripEachKind(t *testing.T) {
	tok := minted(t)
	parsed, ok := Parse(tok)
	if !ok {
		t.Fatal("a token this package minted does not parse")
	}
	if got, want := parsed.ID(), "agent:watcher/run-1"; got != want {
		t.Fatalf("the id is %q, not %q", got, want)
	}
	kinds := ""
	for _, c := range parsed.Caveats() {
		kinds += string(c.Kind) + " "
	}
	for _, want := range Kinds() {
		if !strings.Contains(kinds, want) {
			t.Errorf("the minted token does not carry a %s caveat: %s", want, kinds)
		}
	}
	seen := 0
	err := Verify(tok, aPub(), func(c Caveat) error {
		seen++
		return nil
	})
	if err != nil {
		t.Fatalf("a minted token did not verify: %v", err)
	}
	if seen != len(Kinds()) {
		t.Fatalf("the discharge saw %d caveats, not one of each kind (%d)",
			seen, len(Kinds()))
	}
}

// TestMintedUnderOneKeyFailsUnderAnother: the signature is keyed, so a token is
// bound to the store that minted it. A run key is not a formality another
// store's verifier can waive.
func TestMintedUnderOneKeyFailsUnderAnother(t *testing.T) {
	_, otherPub, _ := GenerateMintKey()
	if err := Verify(minted(t), otherPub, func(Caveat) error { return nil }); err == nil {
		t.Fatal("a token verified under a public key it was not minted with")
	}
}

// TestAnyChangedPayloadByteIsRefused: the signature covers the whole payload, so
// there is no byte whose change keeps the token verifiable — except the
// don't-care bits of base64's final character, which change the string and
// not the bytes, and are asserted to be the only such place.
func TestAnyChangedPayloadByteIsRefused(t *testing.T) {
	tok := minted(t)
	_, enc, ok := halves(tok)
	if !ok {
		t.Fatal("the minted token has no halves")
	}
	skipped := 0
	for i := 0; i < len(enc); i++ {
		for _, sub := range "AZaz09" {
			forged := enc[:i] + string(sub) + enc[i+1:]
			if forged == enc {
				continue
			}
			before, _ := decode(enc)
			after, derr := decode(forged)
			if derr == nil && string(before) == string(after) {
				// Same bytes in a different spelling: base64url leaves
				// unused low bits in the final character. Only the tail
				// can do this; a mid-payload match means the alphabet
				// check has a hole in it.
				if i != len(enc)-1 {
					t.Fatalf("changing character %d left the payload "+
						"identical; only the final character carries "+
						"don't-care bits", i)
				}
				skipped++
				continue
			}
			if err := Verify(tok[:len(tok)-len(enc)]+forged, aPub(),
				func(Caveat) error { return nil }); err == nil {
				t.Fatalf("changing payload character %d to %c left the "+
					"token verifying", i, sub)
			}
		}
	}
	if skipped > 4 {
		t.Fatalf("%d characters decoded identically when changed; the tail "+
			"is at most a few bits wide", skipped)
	}
}

// decode is halves' decoder, shared so the test changes bytes the same way
// the package reads them.
func decode(enc string) ([]byte, error) {
	return b64decode(enc)
}

// TestTamperedFramingIsRefused: changes inside the framing rather than the
// alphabet — a truncated tail, a stretched head, a marker moved — none of it
// parses, so none of it verifies.
func TestTamperedFramingIsRefused(t *testing.T) {
	tok := minted(t)
	for _, mangle := range []struct {
		name, tok string
	}{
		{"truncated payload", tok[:len(tok)-4]},
		{"no payload", "aet_testsecret" + marker},
		{"no credential half", strings.TrimPrefix(tok, "aet_testsecret")},
		{"payload not base64", "aet_testsecret" + marker + "!!!!"},
		{"marker misspelled", strings.Replace(tok, marker, ".aet9.", 1)},
		{"the retired format's marker", strings.Replace(tok, marker, ".vgt2.", 1)},
		{"empty", ""},
	} {
		if _, ok := Parse(mangle.tok); ok {
			t.Errorf("%s parsed; a mangled token is not one this program "+
				"minted", mangle.name)
		}
		if err := Verify(mangle.tok, aPub(), func(Caveat) error { return nil }); err == nil {
			t.Errorf("%s verified", mangle.name)
		}
	}
	// A forged kind inside otherwise-valid framing: built with this
	// package's own writer, so the refusal is the closed set's and not the
	// alphabet's.
	rogue := Caveat{Kind: "admin", Value: "yes"}
	forged := resigned("aet_testsecret", "agent:watcher/run-1", []Caveat{rogue})
	if _, ok := Parse(forged); ok {
		t.Error("a caveat of an unknown kind parsed; the set is closed")
	}
	if err := Verify(forged, aPub(), func(Caveat) error { return nil }); err == nil {
		t.Error("a caveat of an unknown kind verified; the set is closed")
	}
}

// TestDischargeRefusalNamesTheCaveat: Verify wraps the discharge error with
// the caveat's kind, because the gate's message — and the audit record
// under it — has to say which bound refused the call.
func TestDischargeRefusalNamesTheCaveat(t *testing.T) {
	tools, err := ToolCaveat("aertun_read")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := Mint("aet_testsecret", aKey(), "agent:watcher/run-1", tools)
	if err != nil {
		t.Fatal(err)
	}
	err = Verify(tok, aPub(), func(c Caveat) error {
		return errRefused("aertun_write is not in the allowed set")
	})
	if err == nil || !strings.Contains(err.Error(), "caveat tool:") ||
		!strings.Contains(err.Error(), "aertun_write") {
		t.Fatalf("the refusal does not name the caveat and the reason: %v", err)
	}
}

// TestMintRefusesWhatItCannotMean: the mint's own refusals — no caveats, a
// duplicate kind, a bad id, a dot in the credential half, a key of the
// wrong length — each named, because they are operator errors, not
// forgeries.
func TestMintRefusesWhatItCannotMean(t *testing.T) {
	tools, err := ToolCaveat("aertun_read")
	if err != nil {
		t.Fatal(err)
	}
	for _, mangle := range []struct {
		name  string
		mint  func() (string, error)
		wants []string
	}{
		{"no caveats", func() (string, error) {
			return Mint("aet_s", aKey(), "agent:watcher/run-1")
		}, []string{"at least one caveat"}},
		{"a duplicate kind", func() (string, error) {
			return Mint("aet_s", aKey(), "agent:watcher/run-1", tools, tools)
		}, []string{"appears twice"}},
		{"a dotted credential", func() (string, error) {
			return Mint("aet.s", aKey(), "agent:watcher/run-1", tools)
		}, []string{"dot-free"}},
		{"a bad id", func() (string, error) {
			return Mint("aet_s", aKey(), "Agent Watcher!", tools)
		}, []string{"not a run id"}},
		{"a short key", func() (string, error) {
			return Mint("aet_s", aKey()[:31], "agent:watcher/run-1", tools)
		}, []string{"bytes"}},
	} {
		tok, err := mangle.mint()
		if err == nil {
			t.Errorf("%s was minted (%s)", mangle.name, tok)
			continue
		}
		for _, want := range mangle.wants {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s refusal says %q, which does not name %q",
					mangle.name, err, want)
			}
		}
	}
}

// TestConstructorsRefuseWhatTheyCannotCarry: the value grammars, so a
// caveat that exists is a caveat that means one thing.
func TestConstructorsRefuseWhatTheyCannotCarry(t *testing.T) {
	if _, err := ToolCaveat(); err == nil {
		t.Error("an empty tool set was built")
	}
	if _, err := ToolCaveat("aertun_read", "AERTUN_READ"); err == nil {
		t.Error("an uppercase tool name was built")
	}
	if _, err := ToolCaveat("no/slashes"); err == nil {
		t.Error("a tool name with a separator was built")
	}
	if _, err := CallsCaveat(0); err == nil {
		t.Error("a budget of zero was built")
	}
	if _, err := CallsCaveat(-1); err == nil {
		t.Error("a negative budget was built")
	}
	if _, err := LevelCaveat(LevelMax + 1); err == nil {
		t.Error("a level above the maximum was built")
	}
	if _, err := LevelCaveat(-1); err == nil {
		t.Error("a negative level was built")
	}
	if _, err := PurposeCaveat("vibing"); err == nil {
		t.Error("a word outside the vocabulary was built")
	}
	// Canonical order: two spellings of one set are one set.
	a, err := ToolCaveat("aertun_write", "aertun_read")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ToolCaveat("aertun_read", "aertun_write")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("the same set minted two spellings: %q and %q", a, b)
	}
	if _, ok := Parse(resigned("aet_s", "agent:watcher/run-1",
		[]Caveat{{Kind: KindTool, Value: "aertun_write,aertun_read"}})); ok {
		t.Error("an out-of-order tool set parsed; this program writes one order")
	}
}

// TestSplitIsLooseParseIsStrict: the credential path must accept a payload
// it cannot check (the bearer is still the bearer), and the caveat gate
// must refuse it. Split and Parse are those two answers, and they must
// never swap.
func TestSplitIsLooseParseIsStrict(t *testing.T) {
	rogue := Caveat{Kind: "admin", Value: "yes"}
	tok := resigned("aet_testsecret", "agent:watcher/run-1", []Caveat{rogue})
	if secret, ok := Split(tok); !ok || secret != "aet_testsecret" {
		t.Fatalf("Split refused a token whose halves are sound: %q %v", secret, ok)
	}
	if _, ok := Parse(tok); ok {
		t.Fatal("Parse accepted a kind the set does not contain")
	}
	// And a plain credential — no marker at all — is not a run token to
	// either of them.
	if _, ok := Split("aet_plainsecret"); ok {
		t.Error("a plain credential split as a run token")
	}
}

// TestCaveatReaders: Tools and Int, the two readers the gate uses, on the
// grammars Parse guarantees.
func TestCaveatReaders(t *testing.T) {
	tools, _ := ToolCaveat("aertun_read", "aertun_write")
	if got := tools.Tools(); len(got) != 2 || got[0] != "aertun_read" {
		t.Fatalf("Tools() = %v", got)
	}
	exp := ExpCaveat(time.Unix(1_700_000_000, 0).UTC())
	if n, err := exp.Int(); err != nil || n != 1_700_000_000 {
		t.Fatalf("Int() = %d, %v", n, err)
	}
	c, _ := CallsCaveat(7)
	if n, err := c.Int(); err != nil || n != 7 {
		t.Fatalf("Int() = %d, %v", n, err)
	}
	if _, err := (Caveat{Kind: KindCalls, Value: "seven"}).Int(); err == nil {
		t.Error("Int() accepted a word; the grammar is digits")
	}
}

// errRefused keeps the discharge stubs reading like decisions.
type errRefused string

func (e errRefused) Error() string { return string(e) }

// b64decode and enc use the package's own codec, so a hand-built token and
// a minted one share one alphabet.
func b64decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func enc(p []byte) string { return base64.RawURLEncoding.EncodeToString(p) }

// resigned builds a token by hand with this package's own frame, signed by
// the test key, so a refusal is the closed set's or the signature's and not
// the alphabet's.
func resigned(secret, id string, caveats []Caveat) string {
	b := body(id, caveats)
	sig := ed25519.Sign(aKey(), signed(b))
	return secret + marker + enc(append(b, sig...))
}

// replay builds a token from another token's signature over a different set
// of caveats: what somebody holding a token, and not the key, can do.
func replay(t *testing.T, tok, id string, caveats []Caveat) string {
	t.Helper()
	parsed, ok := Parse(tok)
	if !ok {
		t.Fatal("the original does not parse")
	}
	b := body(id, caveats)
	return parsed.secret + marker + enc(append(b, parsed.sig...))
}

// TestAHolderCannotChangeTheCaveats: whoever holds a token, and not the
// minting key, cannot remove a caveat, widen one, add one or reorder them,
// even keeping the original signature — the attack an earlier format, whose
// HMAC chain started from bytes in the token, allowed.
func TestAHolderCannotChangeTheCaveats(t *testing.T) {
	tok := minted(t)
	orig, _ := Parse(tok)
	cs := orig.Caveats()
	wider, _ := ToolCaveat("aertun_admin", "aertun_read", "aertun_write")
	more, _ := LevelCaveat(3)
	cases := map[string][]Caveat{
		"every caveat removed": {cs[0]},
		"the budget removed":   cs[:len(cs)-1],
		"the tools widened":    append([]Caveat{wider}, cs[1:]...),
		"a caveat added":       append(append([]Caveat(nil), cs...), more),
		"the order changed":    append([]Caveat{cs[1], cs[0]}, cs[2:]...),
	}
	for name, changed := range cases {
		forged := replay(t, tok, orig.ID(), changed)
		if err := Verify(forged, aPub(), func(Caveat) error { return nil }); err == nil {
			t.Errorf("%s verified under the original signature", name)
		}
	}
	if err := Verify(replay(t, tok, "agent:other/run-9", cs), aPub(), func(Caveat) error { return nil }); err == nil {
		t.Error("the same caveats under another run id verified")
	}
}

// TestTheSignatureIsBoundToItsDomain: a signature over the same bytes
// without the domain — what this key would make for some other purpose —
// does not verify as a run token.
func TestTheSignatureIsBoundToItsDomain(t *testing.T) {
	tools, _ := ToolCaveat("aertun_read")
	b := body("agent:watcher/run-1", []Caveat{tools})
	sig := ed25519.Sign(aKey(), b)
	tok := "aet_testsecret" + marker + enc(append(b, sig...))
	if err := Verify(tok, aPub(), func(Caveat) error { return nil }); err == nil {
		t.Error("a signature made without the domain verified")
	}
}

// TestAVerifierWithOnlyThePublicKeyVerifies: the public half is all a
// verifier needs, and Mint refuses anything but a private key.
func TestAVerifierWithOnlyThePublicKeyVerifies(t *testing.T) {
	if err := Verify(minted(t), aPub(), func(Caveat) error { return nil }); err != nil {
		t.Fatal(err)
	}
	tools, _ := ToolCaveat("aertun_read")
	if _, err := Mint("aet_testsecret", MintKey(aPub()), "agent:watcher/run-1", tools); err == nil {
		t.Error("a token was minted with a public key")
	}
}
