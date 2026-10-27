// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package macaroon

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// The chain, the closed set of kinds, and the algebra that attenuation only
// narrows — the three properties everything else in this program leans on
// when it refuses a call (docs/research/02-access-control.md §8.4).
//
// The matrix this file holds, each row at the package boundary the gate
// itself calls:
//
//	minted with each kind            verifies, and the discharge saw it
//	any payload byte changed         refused by the chain
//	a narrower caveat appended       verifies, and both are enforced
//	a wider one appended             REFUSED, not clamped
//	an unknown kind                  refused at mint, at parse, everywhere
//	the shapes                       size-capped, halves unconfusable

// aKey is a run key of the one length Mint and Verify accept.
func aKey() []byte {
	k := make([]byte, runKeyLength)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

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
	tools, err := ToolCaveat("vaigil_read", "vaigil_write")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := Mint("vg_testsecret", aKey(), "agent:watcher/run-1",
		tools, purpose, level, exp, calls)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestMintVerifyRoundTripEachKind: the row that must succeed. Every caveat
// reaches the discharge function in chain order, and a discharge that says
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
	err := Verify(tok, aKey(), func(c Caveat) error {
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

// TestMintedUnderOneKeyFailsUnderAnother: the chain is keyed, so a token is
// bound to the store that minted it. A run key is not a formality another
// store's verifier can waive.
func TestMintedUnderOneKeyFailsUnderAnother(t *testing.T) {
	other := aKey()
	other[0] ^= 0xff
	if err := Verify(minted(t), other, func(Caveat) error { return nil }); err == nil {
		t.Fatal("a token verified under a run key it was not minted with")
	}
}

// TestAnyChangedPayloadByteIsRefused: the chain covers the whole payload, so
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
			if err := Verify(tok[:len(tok)-len(enc)]+forged, aKey(),
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
		{"no payload", "vg_testsecret" + marker},
		{"no credential half", strings.TrimPrefix(tok, "vg_testsecret")},
		{"payload not base64", "vg_testsecret" + marker + "!!!!"},
		{"marker misspelled", strings.Replace(tok, marker, ".vgt2.", 1)},
		{"empty", ""},
	} {
		if _, ok := Parse(mangle.tok); ok {
			t.Errorf("%s parsed; a mangled token is not one this program "+
				"minted", mangle.name)
		}
		if err := Verify(mangle.tok, aKey(), func(Caveat) error { return nil }); err == nil {
			t.Errorf("%s verified", mangle.name)
		}
	}
	// A forged kind inside otherwise-valid framing: built with this
	// package's own writer, so the refusal is the closed set's and not the
	// alphabet's.
	rogue := Caveat{Kind: "admin", Value: "yes"}
	sig := rootSig(aKey(), "agent:watcher/run-1")
	sig = bindSig(sig, rogue)
	forged := envelope("vg_testsecret", payload("agent:watcher/run-1",
		[]Caveat{rogue}, sig))
	if _, ok := Parse(forged); ok {
		t.Error("a caveat of an unknown kind parsed; the set is closed")
	}
	if err := Verify(forged, aKey(), func(Caveat) error { return nil }); err == nil {
		t.Error("a caveat of an unknown kind verified; the set is closed")
	}
}

// TestAttenuationNarrows: every narrowing append verifies, carries both the
// old bound and the new, and — the property the whole design rests on —
// the parent keeps working unchanged beside its child.
func TestAttenuationNarrows(t *testing.T) {
	parent := minted(t)
	earlier := ExpCaveat(time.Unix(1, 0).UTC())
	narrower, err := ToolCaveat("vaigil_read")
	if err != nil {
		t.Fatal(err)
	}
	quieter, err := PurposeCaveat(PurposeObserve)
	if err != nil {
		t.Fatal(err)
	}
	child, err := Attenuate(parent, earlier, narrower, quieter)
	if err != nil {
		t.Fatalf("a narrowing attenuation was refused: %v", err)
	}
	seen := map[Kind]int{}
	if err := Verify(child, aKey(), func(c Caveat) error {
		seen[c.Kind]++
		switch c.Kind {
		case KindTool:
			if c.Value != "vaigil_read" && c.Value != "vaigil_read,vaigil_write" {
				t.Errorf("a tool caveat became %q", c.Value)
			}
		case KindPurpose:
			if c.Value != PurposeObserve && c.Value != PurposeTriage {
				t.Errorf("a purpose caveat became %q", c.Value)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("the attenuated token did not verify: %v", err)
	}
	if seen[KindTool] != 2 || seen[KindPurpose] != 2 {
		t.Fatalf("the child carries %v; both bounds must survive attenuation", seen)
	}
	if err := Verify(parent, aKey(), func(Caveat) error { return nil }); err != nil {
		t.Fatalf("attenuating a token changed the parent: %v", err)
	}
	// Attenuating the child narrows past its bounds, which is the algebra
	// compounding: the intersection of three tool sets.
	if _, err := Attenuate(child, earlier); err != nil {
		t.Fatalf("attenuating the attenuated was refused: %v", err)
	}
}

// TestAttenuationNeverWidens: each widening attempt is REFUSED, with a
// message naming the bound it tried to pass — never clamped into something
// quieter, because a caller told "done" believes they got what they typed.
func TestAttenuationNeverWidens(t *testing.T) {
	tools, err := ToolCaveat("vaigil_read")
	if err != nil {
		t.Fatal(err)
	}
	exp := ExpCaveat(time.Unix(1_700_000_000, 0).UTC())
	calls, err := CallsCaveat(3)
	if err != nil {
		t.Fatal(err)
	}
	level, err := LevelCaveat(1)
	if err != nil {
		t.Fatal(err)
	}
	purpose, err := PurposeCaveat(PurposeObserve)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := Mint("vg_testsecret", aKey(), "agent:watcher/run-1",
		tools, exp, calls, level, purpose)
	if err != nil {
		t.Fatal(err)
	}
	for _, mangle := range []struct {
		name  string
		more  func() (Caveat, error)
		wants []string
	}{
		{"a wider tool set", func() (Caveat, error) {
			return ToolCaveat("vaigil_read", "vaigil_write")
		}, []string{"vaigil_write", "refusing to attenuate"}},
		{"a later expiry", func() (Caveat, error) {
			return ExpCaveat(time.Unix(1_800_000_000, 0).UTC()), nil
		}, []string{"refusing to attenuate", "1700000000"}},
		{"a larger budget", func() (Caveat, error) {
			return CallsCaveat(4)
		}, []string{"refusing to attenuate"}},
		{"a higher level", func() (Caveat, error) {
			return LevelCaveat(2)
		}, []string{"refusing to attenuate"}},
		{"a further-reaching purpose", func() (Caveat, error) {
			return PurposeCaveat(PurposeTriage)
		}, []string{"refusing to attenuate", PurposeObserve}},
		{"a kind nobody mints", func() (Caveat, error) {
			return Caveat{Kind: "admin", Value: "yes"}, nil
		}, []string{"not one this program mints"}},
	} {
		more, err := mangle.more()
		if err != nil {
			t.Fatal(err)
		}
		_, aerr := Attenuate(parent, more)
		if aerr == nil {
			t.Errorf("%s was attenuated without a word; widening must be "+
				"refused, not clamped", mangle.name)
			continue
		}
		for _, want := range mangle.wants {
			if !strings.Contains(aerr.Error(), want) {
				t.Errorf("%s refusal says %q, which does not name %q",
					mangle.name, aerr, want)
			}
		}
	}
	// An equal bound is not a widening: re-stating what is already bound
	// changes nothing, and refusing it would make a holder unable to prove
	// what they hold.
	for _, same := range []func() (Caveat, error){
		func() (Caveat, error) { return ToolCaveat("vaigil_read") },
		func() (Caveat, error) { return CallsCaveat(3) },
		func() (Caveat, error) { return LevelCaveat(1) },
		func() (Caveat, error) { return PurposeCaveat(PurposeObserve) },
	} {
		c, err := same()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Attenuate(parent, c); err != nil {
			t.Errorf("restating a bound was refused: %v", err)
		}
	}
	// And a token that does not parse attenuates to nothing, because
	// appending to garbage legitimises garbage.
	if _, err := Attenuate("not-a-token", tools); err == nil {
		t.Error("a string that does not parse was attenuated")
	}
}

// TestDischargeRefusalNamesTheCaveat: Verify wraps the discharge error with
// the caveat's kind, because the gate's message — and the audit record
// under it — has to say which bound refused the call.
func TestDischargeRefusalNamesTheCaveat(t *testing.T) {
	tools, err := ToolCaveat("vaigil_read")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := Mint("vg_testsecret", aKey(), "agent:watcher/run-1", tools)
	if err != nil {
		t.Fatal(err)
	}
	err = Verify(tok, aKey(), func(c Caveat) error {
		return errRefused("vaigil_write is not in the allowed set")
	})
	if err == nil || !strings.Contains(err.Error(), "caveat tool:") ||
		!strings.Contains(err.Error(), "vaigil_write") {
		t.Fatalf("the refusal does not name the caveat and the reason: %v", err)
	}
}

// TestMintRefusesWhatItCannotMean: the mint's own refusals — no caveats, a
// duplicate kind, a bad id, a dot in the credential half, a key of the
// wrong length — each named, because they are operator errors, not
// forgeries.
func TestMintRefusesWhatItCannotMean(t *testing.T) {
	tools, err := ToolCaveat("vaigil_read")
	if err != nil {
		t.Fatal(err)
	}
	for _, mangle := range []struct {
		name  string
		mint  func() (string, error)
		wants []string
	}{
		{"no caveats", func() (string, error) {
			return Mint("vg_s", aKey(), "agent:watcher/run-1")
		}, []string{"at least one caveat"}},
		{"a duplicate kind", func() (string, error) {
			return Mint("vg_s", aKey(), "agent:watcher/run-1", tools, tools)
		}, []string{"appears twice"}},
		{"a dotted credential", func() (string, error) {
			return Mint("vg.s", aKey(), "agent:watcher/run-1", tools)
		}, []string{"dot-free"}},
		{"a bad id", func() (string, error) {
			return Mint("vg_s", aKey(), "Agent Watcher!", tools)
		}, []string{"not a run id"}},
		{"a short key", func() (string, error) {
			return Mint("vg_s", aKey()[:31], "agent:watcher/run-1", tools)
		}, []string{"32 bytes"}},
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
	if _, err := ToolCaveat("vaigil_read", "VAIGIL_READ"); err == nil {
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
	a, err := ToolCaveat("vaigil_write", "vaigil_read")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ToolCaveat("vaigil_read", "vaigil_write")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("the same set minted two spellings: %q and %q", a, b)
	}
	if _, ok := Parse("vg_s" + marker + enc(payload("agent:watcher/run-1",
		[]Caveat{{Kind: KindTool, Value: "vaigil_write,vaigil_read"}},
		rootSig(aKey(), "agent:watcher/run-1")))); ok {
		t.Error("an out-of-order tool set parsed; this program writes one order")
	}
}

// TestSplitIsLooseParseIsStrict: the credential path must accept a payload
// it cannot check (the bearer is still the bearer), and the caveat gate
// must refuse it. Split and Parse are those two answers, and they must
// never swap.
func TestSplitIsLooseParseIsStrict(t *testing.T) {
	rogue := Caveat{Kind: "admin", Value: "yes"}
	sig := bindSig(rootSig(aKey(), "agent:watcher/run-1"), rogue)
	tok := envelope("vg_testsecret", payload("agent:watcher/run-1",
		[]Caveat{rogue}, sig))
	if secret, ok := Split(tok); !ok || secret != "vg_testsecret" {
		t.Fatalf("Split refused a token whose halves are sound: %q %v", secret, ok)
	}
	if _, ok := Parse(tok); ok {
		t.Fatal("Parse accepted a kind the set does not contain")
	}
	// And a plain credential — no marker at all — is not a run token to
	// either of them.
	if _, ok := Split("vg_plainsecret"); ok {
		t.Error("a plain credential split as a run token")
	}
}

// TestPurposesHaveAnOrder: observe narrows triage and never the other way
// round, which is the lattice the mint and the attenuation check both use.
func TestPurposesHaveAnOrder(t *testing.T) {
	if !PurposeNarrowsTo(PurposeObserve, PurposeTriage) {
		t.Error("observe does not narrow triage")
	}
	if PurposeNarrowsTo(PurposeTriage, PurposeObserve) {
		t.Error("triage narrows observe; a purpose cannot reach further by attenuating")
	}
	if !PurposeNarrowsTo(PurposeObserve, PurposeObserve) {
		t.Error("a purpose does not narrow itself")
	}
	if PurposeNarrowsTo("vibing", PurposeTriage) {
		t.Error("a word outside the vocabulary narrowed something")
	}
	for _, p := range []string{PurposeObserve, PurposeTriage} {
		if !ValidPurpose(p) {
			t.Errorf("%q is not a valid purpose", p)
		}
	}
	if ValidPurpose("TRIAGE") {
		t.Error("the vocabulary is case-sensitive and TRIAGE is not in it")
	}
}

// TestCaveatReaders: Tools and Int, the two readers the gate uses, on the
// grammars Parse guarantees.
func TestCaveatReaders(t *testing.T) {
	tools, _ := ToolCaveat("vaigil_read", "vaigil_write")
	if got := tools.Tools(); len(got) != 2 || got[0] != "vaigil_read" {
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
