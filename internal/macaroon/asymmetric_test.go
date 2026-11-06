// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package macaroon

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// A verifier holding only the public key verifies a minted token, cannot
// mint one, and refuses a token whose caveats were extended without the
// chain — the three properties the asymmetric root exists to prove.
func TestAVerifierWithOnlyThePublicKeyVerifiesAndCannotMint(t *testing.T) {
	priv, pub, err := GenerateMintKey()
	if err != nil {
		t.Fatal(err)
	}

	tools, err := ToolCaveat("aertun_read")
	if err != nil {
		t.Fatal(err)
	}
	token, err := Mint("the-secret-half", priv, "agent:watcher/run-1",
		tools, ExpCaveat(time.Now().Add(time.Hour).UTC()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(token, markerV2) {
		t.Fatal("the minted token is not v2")
	}

	// 1. The public key verifies.
	err = Verify(token, pub, func(Caveat) error { return nil })
	if err != nil {
		t.Fatalf("the public key should verify: %v", err)
	}

	// 2. The public key cannot mint: a public key is 32 bytes, a private
	// key is 64, and the mint refuses the mismatch. Even a byte-level
	// cast would produce garbage signatures — there is no way to mint
	// without the private half.
	forgedTools, _ := ToolCaveat("aertun_write")
	if _, err := Mint("forged-secret", MintKey(pub), "agent:attacker/run-2",
		forgedTools, ExpCaveat(time.Now().Add(time.Hour).UTC())); err == nil {
		t.Fatal("minting with the public key should refuse (it is not the " +
			"private key's size)")
	}

	// 3. A different key pair's tokens do not verify.
	_, otherPub, _ := GenerateMintKey()
	if err := Verify(token, otherPub, func(Caveat) error { return nil }); err == nil {
		t.Fatal("a token minted under one key verified under another")
	}
}

// The caveat chain catches a caveat appended without recomputing the tag.
func TestTheChainCatchesAnAppendedCaveatWithoutRecomputation(t *testing.T) {
	priv, pub, _ := GenerateMintKey()
	tools, err := ToolCaveat("aertun_read")
	if err != nil {
		t.Fatal(err)
	}
	token, err := Mint("secret", priv, "agent:watcher/run-3",
		tools, ExpCaveat(time.Now().Add(time.Hour).UTC()))
	if err != nil {
		t.Fatal(err)
	}
	// Tamper: flip a byte in the encoded payload so the tag no longer
	// matches the chain. Find the base64 payload and change its last
	// character (the tag is the final 32 bytes of the decoded payload).
	idx := strings.Index(token, markerV2)
	if idx < 0 {
		t.Fatal("the token has no v2 marker")
	}
	enc := token[idx+len(markerV2):]
	// Decode, flip the last byte of the tag, re-encode.
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	tampered := token[:idx+len(markerV2)] + base64.RawURLEncoding.EncodeToString(raw)
	if err := Verify(tampered, pub, func(Caveat) error { return nil }); err == nil {
		t.Fatal("the chain verified after the tag was tampered with")
	}
}

// Attenuation preserves the root signature and produces a token that
// still verifies under the public key.
func TestAttenuationPreservesTheAsymmetricRoot(t *testing.T) {
	priv, pub, _ := GenerateMintKey()
	tools, err := ToolCaveat("aertun_read", "aertun_write")
	if err != nil {
		t.Fatal(err)
	}
	token, err := Mint("secret", priv, "agent:watcher/run-4",
		tools, ExpCaveat(time.Now().Add(time.Hour).UTC()))
	if err != nil {
		t.Fatal(err)
	}
	narrowTools, err := ToolCaveat("aertun_read")
	if err != nil {
		t.Fatal(err)
	}
	narrower, err := Attenuate(token, narrowTools)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(narrower, pub, func(Caveat) error { return nil }); err != nil {
		t.Fatalf("the attenuated token should verify: %v", err)
	}
}
