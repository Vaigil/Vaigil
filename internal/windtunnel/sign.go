// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aertun/aertun/internal/pack"
)

// Signing a scorecard, twice, with algorithms that fail differently.
//
// This is internal/pack's signing discipline (internal/pack/sign.go), which
// is internal/audit's, applied to a third domain. Ed25519 because it is the
// algorithm everything else here uses; ML-DSA-65 (FIPS 204) because it is
// the post-quantum half, standardised and in the standard library. Both
// signatures are made and both are required — no AcceptSingle shape exists
// anywhere in this codebase, and a verifier that could be talked into one
// signature is the property an attacker buys a key for.
//
// The key material is the content plane's, reused: the same dual key a
// store's keygen made, the same seeds-on-disk format, the same release key
// the operator already holds. The context below is new and versioned, so a
// scorecard signature can never be re-presented as a pack signature or an
// audit head — a signature made for one purpose must never be presentable
// as one for another, and the separation lives in the signed bytes
// themselves.

// ScorecardContext is the domain every windtunnel-scorecard signature is
// made and checked in. Versioned, so a change to what gets signed cannot be
// confused with the thing it replaced.
const ScorecardContext = "aertun/windtunnel-scorecard/v1"

// ScorecardSignature is both signatures over one sealed scorecard — the
// same shape as the content plane's Signature, in this domain.
type ScorecardSignature struct {
	// KeyID identifies the dual key that signed, so a verifier holding
	// several knows which to try rather than trying all of them.
	KeyID string `json:"key_id"`
	// Ed25519 and MLDSA65 are base64. Both required: a document carrying
	// one is a document with half its argument.
	Ed25519 string `json:"ed25519"`
	MLDSA65 string `json:"mldsa_65"`
}

// ScorecardKeyID is a short fingerprint of a dual public key: sha256 over
// this context and both halves, first 16 hex characters — pack.KeyID's
// recipe over this domain, so the same key halves are a different identity
// here than they are in the content plane, and neither borrows the other's
// name.
func ScorecardKeyID(pub pack.KeyPublic) (string, error) {
	ed, err := base64.StdEncoding.DecodeString(pub.Ed25519)
	if err != nil || len(ed) != ed25519.PublicKeySize {
		return "", fmt.Errorf("the Ed25519 public key is not readable base64")
	}
	ml, err := base64.StdEncoding.DecodeString(pub.MLDSA65)
	if err != nil {
		return "", fmt.Errorf("the ML-DSA public key is not readable base64")
	}
	h := sha256.New()
	h.Write([]byte(ScorecardContext))
	h.Write([]byte{0})
	h.Write(ed)
	h.Write([]byte{0})
	h.Write(ml)
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

// scorecardMessage is the exact bytes both algorithms sign: the context, a
// NUL, then the sealed document's canonical bytes — the digest included, so
// the signature covers both the numbers and the check on the numbers. The
// NUL ends the context so it cannot bleed into the payload.
func scorecardMessage(card *Scorecard) ([]byte, error) {
	body, err := card.digestBytes()
	if err != nil {
		return nil, err
	}
	return append(append([]byte(ScorecardContext), 0), body...), nil
}

// SignScorecard produces both signatures over a sealed scorecard, using the
// content plane's dual key. Deterministic on both algorithms, so signing
// the same document twice produces the same bytes — a scorecard is a
// commitment, and two different signatures over one body invite the
// question of which is real.
func SignScorecard(card *Scorecard, k *pack.Key) (ScorecardSignature, error) {
	if card.SHA256 == "" {
		return ScorecardSignature{}, fmt.Errorf("the scorecard is not " +
			"sealed: an unsealed document has no digest to sign, and a " +
			"signature over nothing verifies nothing")
	}
	msg, err := scorecardMessage(card)
	if err != nil {
		return ScorecardSignature{}, err
	}
	edSig, mlSig, err := k.DualSign(msg, ScorecardContext)
	if err != nil {
		return ScorecardSignature{}, err
	}
	id, err := ScorecardKeyID(k.PublicKey())
	if err != nil {
		return ScorecardSignature{}, err
	}
	return ScorecardSignature{
		KeyID:   id,
		Ed25519: base64.StdEncoding.EncodeToString(edSig),
		MLDSA65: base64.StdEncoding.EncodeToString(mlSig),
	}, nil
}

// VerifyScorecard checks both signatures over a sealed document against a
// dual public key. Both, always: a signature carrying one half is refused
// with its name in the error, and there is no option to accept one.
func VerifyScorecard(card *Scorecard, sig ScorecardSignature,
	pub pack.KeyPublic) error {

	id, err := ScorecardKeyID(pub)
	if err != nil {
		return err
	}
	if sig.KeyID != "" && sig.KeyID != id {
		return fmt.Errorf("this was signed by key %s and the key trusted "+
			"here is %s", sig.KeyID, id)
	}
	if sig.Ed25519 == "" || sig.MLDSA65 == "" {
		missing := "neither signature"
		switch {
		case sig.Ed25519 != "":
			missing = "no ML-DSA-65 signature"
		case sig.MLDSA65 != "":
			missing = "no Ed25519 signature"
		}
		return fmt.Errorf("this scorecard carries %s. Both are required: one "+
			"of them is the half that survives whichever algorithm turns "+
			"out to be broken", missing)
	}
	if card.SHA256 == "" {
		return fmt.Errorf("the scorecard is not sealed, so what a signature " +
			"would verify against is undefined")
	}
	msg, err := scorecardMessage(card)
	if err != nil {
		return err
	}
	edSig, err := base64.StdEncoding.DecodeString(sig.Ed25519)
	if err != nil {
		return fmt.Errorf("the Ed25519 signature is not base64: %w", err)
	}
	edKey, err := base64.StdEncoding.DecodeString(pub.Ed25519)
	if err != nil || len(edKey) != ed25519.PublicKeySize {
		return fmt.Errorf("the trusted Ed25519 public key is unreadable")
	}
	if !ed25519.Verify(ed25519.PublicKey(edKey), msg, edSig) {
		return fmt.Errorf("the Ed25519 signature does not verify")
	}
	mlSig, err := base64.StdEncoding.DecodeString(sig.MLDSA65)
	if err != nil {
		return fmt.Errorf("the ML-DSA signature is not base64: %w", err)
	}
	mlKey, err := base64.StdEncoding.DecodeString(pub.MLDSA65)
	if err != nil {
		return fmt.Errorf("the trusted ML-DSA public key is not base64")
	}
	mlPub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), mlKey)
	if err != nil {
		return fmt.Errorf("the trusted ML-DSA public key is unreadable: %w",
			err)
	}
	if err := mldsa.Verify(mlPub, msg, mlSig, &mldsa.Options{
		Context: ScorecardContext}); err != nil {
		return fmt.Errorf("the ML-DSA-65 signature does not verify: %w", err)
	}
	return nil
}

// LoadPublicKey reads a published dual public key — the file a verifier is
// handed, holding both halves and no secrets.
func LoadPublicKey(path string) (pack.KeyPublic, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return pack.KeyPublic{}, err
	}
	var pub pack.KeyPublic
	if err := json.Unmarshal(body, &pub); err != nil {
		return pack.KeyPublic{}, fmt.Errorf("%s is not a public key file: %w",
			path, err)
	}
	if pub.Ed25519 == "" || pub.MLDSA65 == "" {
		return pack.KeyPublic{}, fmt.Errorf("%s carries only half a dual "+
			"key. A verifier needs both halves: one of them is the half "+
			"that survives whichever algorithm turns out to be broken", path)
	}
	return pub, nil
}

// WritePublicKey writes a published dual public key, for the operator who
// hands a verifier something to verify with.
func WritePublicKey(path string, pub pack.KeyPublic) error {
	body, err := json.MarshalIndent(pub, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0o644)
}
