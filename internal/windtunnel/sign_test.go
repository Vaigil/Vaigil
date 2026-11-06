// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/pack"
)

// b64 is the wire form both halves of a signature travel in.
func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// A run to sign, made once and shared by the signing tests: signing the
// same sealed document is deterministic, and one document under them all is
// what makes the tamper and context tests say something.
func signedRun(t *testing.T) (*Scorecard, *pack.Key) {
	t.Helper()
	card, err := Run(RunOptions{Seed: 7,
		Now: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	k, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return card, k
}

// The scorecard is signed with both algorithms, always, and both verify —
// and a document carrying one half is refused with its name in the error,
// because one of them is the half that survives whichever algorithm turns
// out to be broken.
func TestSignScorecardSignsTwiceAndRequiresBoth(t *testing.T) {
	card, k := signedRun(t)

	// Unsealed first: a run seals its own document, so the refusal is
	// asked for by clearing the digest a signature would stand on.
	card.SHA256 = ""
	if sig, err := SignScorecard(card, k); err == nil ||
		!strings.Contains(err.Error(), "not sealed") {
		t.Fatalf("signing an unsealed document gave (%v, %v); there is no "+
			"digest to sign yet", sig, err)
	}

	if err := card.seal(); err != nil {
		t.Fatal(err)
	}
	sig, err := SignScorecard(card, k)
	if err != nil {
		t.Fatal(err)
	}
	again, err := SignScorecard(card, k)
	if err != nil {
		t.Fatal(err)
	}
	if sig != again {
		t.Error("signing twice produced different bytes; a scorecard is a " +
			"commitment, and two signatures over one body invite the " +
			"question of which is real")
	}
	pub := k.PublicKey()
	if err := VerifyScorecard(card, sig, pub); err != nil {
		t.Fatalf("both signatures over the sealed document failed to "+
			"verify: %v", err)
	}

	half := sig
	half.MLDSA65 = ""
	if err := VerifyScorecard(card, half, pub); err == nil ||
		!strings.Contains(err.Error(), "no ML-DSA-65 signature") {
		t.Errorf("a single-signature document verified (%v); there is no "+
			"accept-one shape anywhere in this codebase", err)
	}
	half.MLDSA65, half.Ed25519 = sig.MLDSA65, ""
	if err := VerifyScorecard(card, half, pub); err == nil ||
		!strings.Contains(err.Error(), "no Ed25519 signature") {
		t.Errorf("the other single-signature document verified (%v)", err)
	}

	// A different key's id is named, so a verifier holding several knows
	// which was asked of them.
	foreign, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyScorecard(card, sig, foreign.PublicKey()); err == nil ||
		!strings.Contains(err.Error(), "signed by key") {
		t.Errorf("a foreign key verified the signature (%v)", err)
	}
}

// The signature covers the numbers: a document edited after signing fails
// verification even when its digest field is left to lie — the signature is
// over the canonical bytes, not over the digest's claim about them.
func TestSignScorecardRefusesATamperedDocument(t *testing.T) {
	card, k := signedRun(t)
	if err := card.seal(); err != nil {
		t.Fatal(err)
	}
	sig, err := SignScorecard(card, k)
	if err != nil {
		t.Fatal(err)
	}
	// Restore the digest's lie: edit a row, then re-seal, so the document
	// is internally consistent again — and the signature still fails,
	// because it covers the bytes as they were signed.
	card.Rows[0].Outcome = OutcomeCaughtTelemetry
	if err := card.seal(); err != nil {
		t.Fatal(err)
	}
	if err := card.Verify(); err != nil {
		t.Fatalf("the re-sealed tampered document fails its own digest: %v", err)
	}
	if err := VerifyScorecard(card, sig, k.PublicKey()); err == nil {
		t.Fatal("a re-sealed, re-digested edit of a signed scorecard " +
			"verified; the signature must cover the bytes, not the digest " +
			"field's claim about them")
	}
}

// The context is the domain separation: a signature made in the content
// plane's context can never be re-presented as a scorecard signature, and
// the separation lives in the signed bytes themselves.
func TestSignScorecardContextSeparationHolds(t *testing.T) {
	card, k := signedRun(t)
	if err := card.seal(); err != nil {
		t.Fatal(err)
	}
	body, err := card.digestBytes()
	if err != nil {
		t.Fatal(err)
	}
	// The same key signing the same document, but in the pack-metadata
	// context — the signature an attacker with a pack signature would hold.
	packContext := "aertun/pack-metadata/v1"
	msg := append(append([]byte(packContext), 0), body...)
	edSig, mlSig, err := k.DualSign(msg, packContext)
	if err != nil {
		t.Fatal(err)
	}
	cross := ScorecardSignature{KeyID: "", Ed25519: b64(edSig),
		MLDSA65: b64(mlSig)}
	if err := VerifyScorecard(card, cross, k.PublicKey()); err == nil {
		t.Fatal("a signature made in the pack-metadata context verified as " +
			"a scorecard signature; a signature made for one purpose must " +
			"never be presentable as one for another")
	}

	// And the honest one still does.
	honest, err := SignScorecard(card, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyScorecard(card, honest, k.PublicKey()); err != nil {
		t.Fatalf("the scorecard-context signature failed: %v", err)
	}
	if honest.KeyID == "" {
		t.Error("the signature carries no key id; a verifier holding " +
			"several keys has no way to know which to try")
	}
}

// The public-key file round-trips, and refuses to be half a key: a
// verifier needs both halves, and a file that carries one is a document
// with half its argument.
func TestSignPublicKeyFileRoundTripsAndRefusesHalf(t *testing.T) {
	_, k := signedRun(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "scorecard-pub.json")
	if err := pack.WritePublicKey(path, k.PublicKey()); err != nil {
		t.Fatal(err)
	}
	pub, err := pack.LoadPublicKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if pub != k.PublicKey() {
		t.Fatal("the public half changed between writing and reading")
	}
	if err := os.WriteFile(path, []byte(`{"ed25519":"AAAA"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pack.LoadPublicKey(path); err == nil ||
		!strings.Contains(err.Error(), "half a dual key") {
		t.Errorf("a public key with one half loaded (%v)", err)
	}
}
