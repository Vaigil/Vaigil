// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aeroprove/aeroprove/internal/atomicfile"
)

// The metadata side of a pack: a minimal TUF-shaped chain of three roles,
// each a JSON file with a body and a dual signature.
//
//	root.json       signed by the OFFLINE root key; names the online release
//	                key; version and expiry. The trust anchor. A rotated root
//	                (version 2 and up) carries two signatures — the outgoing
//	                key's and its own — so trust is continuous across a
//	                rotation: the old key vouches for its replacement, and
//	                the replacement proves it can sign.
//	targets.json    signed by the release key; pins manifest.json's exact
//	                bytes and carries the pack's monotonic integer version —
//	                the only thing rollback protection reasons about.
//	timestamp.json  signed by the release key; pins targets.json's exact
//	                bytes and version. The freeze defence: the freshest thing
//	                a producer re-signs, so stale state is caught by expiry
//	                rather than by anybody noticing.
//
// There is no snapshot role: with one producer and one release key (the
// single-key argument in the design's §4.1 — a shared online key can at
// worst replay old consistent state, which the version counters catch),
// targets and timestamp are enough to bind manifest bytes, version and
// freshness. The `_type` field inside each body binds the role into the
// signed bytes themselves, so a targets document can never be re-presented
// as a root or a timestamp: the signature covers the type name.

// KeyPublic is a published dual public key: both halves, base64.
type KeyPublic struct {
	Ed25519 string `json:"ed25519"`
	MLDSA65 string `json:"mldsa_65"`
}

// RootBody is the signed half of root.json.
type RootBody struct {
	Type    string `json:"_type"`
	Version int    `json:"version"`
	Expires string `json:"expires"`
	// RootKey is the public half of the offline key that signed this root,
	// self-described the way TUF roots list their own keys: an anchor is
	// what a store trusts by placement, and it has to be able to say who
	// it is without anything outside itself.
	RootKey KeyPublic `json:"root_key"`
	// ReleaseKey is the online key trusted to sign targets and timestamp.
	// The slot is a single key in this slice of the design; a root
	// rotation carries it forward unchanged (the online key is rotated,
	// cheaply, by signing a new root that names a new one — a different
	// act from rotating trust itself).
	ReleaseKey KeyPublic `json:"release_key"`
}

// TargetsBody is the signed half of targets.json.
type TargetsBody struct {
	Type string `json:"_type"`
	// Pack is the pack id, bound into the signature so metadata made for
	// one pack cannot be presented with another's manifest.
	Pack    string `json:"pack"`
	Version int    `json:"version"`
	Expires string `json:"expires"`
	// Manifest pins manifest.json's bytes.
	Manifest Digest `json:"manifest"`
}

// TimestampBody is the signed half of timestamp.json.
type TimestampBody struct {
	Type    string `json:"_type"`
	Version int    `json:"version"`
	Expires string `json:"expires"`
	// Targets pins targets.json's bytes.
	Targets Digest `json:"targets"`
}

// Digest pins a file's exact bytes: length and sha256, hex.
type Digest struct {
	SHA256 string `json:"sha256"`
	Length int64  `json:"length"`
}

// Role type names, inside the signed bytes.
const (
	rootType      = "aeroprove-content-root-v1"
	targetsType   = "aeroprove-content-targets-v1"
	timestampType = "aeroprove-content-timestamp-v1"
)

// SignedRoot is root.json.
type SignedRoot struct {
	Signed    RootBody  `json:"signed"`
	Signature Signature `json:"signature"`
	// Previous is the OUTGOING root key's signature over the same body.
	// Present on every rotated root (version 2 and up) and absent from a
	// first one: a rotation is real only when both keys signed it — the
	// old key because trust in the old key is the only thing that can
	// vouch for its replacement (the continuity), the new key because a
	// store that anchors the rotated root verifies every later root
	// against it, and a key that cannot sign is not a key (the handover).
	// A pointer so first roots serialize exactly as they always have; an
	// older binary meeting a rotated root refuses it as an unknown field
	// rather than loading half its meaning, which is the negotiated rule
	// everywhere in this format.
	Previous *Signature `json:"previous,omitempty"`
}

// SignedTargets is targets.json.
type SignedTargets struct {
	Signed    TargetsBody `json:"signed"`
	Signature Signature   `json:"signature"`
}

// SignedTimestamp is timestamp.json.
type SignedTimestamp struct {
	Signed    TimestampBody `json:"signed"`
	Signature Signature     `json:"signature"`
}

// canonicalBody is the exact bytes a metadata signature covers: the JSON
// encoding of the body, re-derived from the decoded struct at verification
// time. Go's encoder is deterministic — fields in declaration order, no
// insignificant whitespace — so the bytes a producer signed and the bytes a
// verifier re-derives from the same document agree, and any valid encoding
// of the same body verifies. There is no canonicalisation step to get
// subtly wrong, which is the usual way signed JSON breaks.
func canonicalBody(body any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// HTML escaping off, so a body containing `<` (a title can) encodes
	// the same way on every side of a sign/verify pair.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		return nil, err
	}
	// Encode appends a newline; trimmed, so the signed bytes are exactly
	// the document.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// loadMetadata reads and strictly decodes one metadata file. Unknown fields
// refused, as everywhere: metadata written for a newer format must fail
// loudly here rather than load with half its meaning.
func loadMetadata(dir, name string, into any) error {
	body, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	if len(body) > MaxFileBytes {
		return fmt.Errorf("%s is %d bytes; it is at most %d", name,
			len(body), MaxFileBytes)
	}
	if err := decodeStrict(body, into); err != nil {
		return fmt.Errorf("%s is not readable: %w", name, err)
	}
	return nil
}

// LoadRoot reads root.json from a pack directory.
func LoadRoot(dir string) (*SignedRoot, error) {
	var r SignedRoot
	if err := loadMetadata(dir, RootName, &r); err != nil {
		return nil, err
	}
	if r.Signed.Type != rootType {
		return nil, fmt.Errorf("%s says it is a %q and not a root", RootName,
			r.Signed.Type)
	}
	return &r, nil
}

// LoadTargets reads targets.json from a pack directory.
func LoadTargets(dir string) (*SignedTargets, error) {
	var t SignedTargets
	if err := loadMetadata(dir, TargetsName, &t); err != nil {
		return nil, err
	}
	if t.Signed.Type != targetsType {
		return nil, fmt.Errorf("%s says it is a %q and not targets",
			TargetsName, t.Signed.Type)
	}
	return &t, nil
}

// LoadTimestamp reads timestamp.json from a pack directory.
func LoadTimestamp(dir string) (*SignedTimestamp, error) {
	var t SignedTimestamp
	if err := loadMetadata(dir, TimestampName, &t); err != nil {
		return nil, err
	}
	if t.Signed.Type != timestampType {
		return nil, fmt.Errorf("%s says it is a %q and not a timestamp",
			TimestampName, t.Signed.Type)
	}
	return &t, nil
}

// WriteRoot writes a signed root to a file, for keygen (the store's trusted
// copy) and for the signer (the copy each pack carries).
func WriteRoot(path string, r *SignedRoot) error {
	return writeJSON(path, r)
}

// writeJSON writes a metadata document as indented JSON with a trailing
// newline, through atomicfile so a reader never sees half of it.
func writeJSON(path string, v any) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, append(body, '\n'), 0o644)
}
