// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"fmt"
	"os"
	"time"
)

// Keygen: making the two halves of the trust split.
//
// The split is Uptane's, applied to one producer: an OFFLINE root key,
// which signs root.json and nothing else, and an ONLINE release key, which
// signs every pack's targets and timestamp and lives in the store. Stealing
// the release key lets somebody sign new releases — bad, and bounded by the
// verification gates every installer runs. Stealing the root key is the
// disaster case, so the root key is written to a path the OPERATOR chose
// and must move away, and nothing in this program reads it again except a
// rotation: the operator brings it back for the ceremony, and the anchor
// it re-signs moves up one version, both keys on it.
//
// Refusing to run twice is the quiet-part safety: a keygen over an existing
// anchor would silently re-anchor trust — every previously-installed pack
// would start failing verification against a root it never knew — so the
// second run is an error that says what to do instead. Rotation is the
// deliberate answer to that refusal: the same act, done under the old
// root's signature, so every pack either root signed keeps verifying.

// KeygenResult is what a keygen produced, for the fingerprints a person
// writes down and checks.
type KeygenResult struct {
	// RootKeyPath is where the offline root key was written. The
	// operator's to move away; the message says so.
	RootKeyPath string
	// RootKeyID and ReleaseKeyID are the fingerprints, over both halves of
	// each pair.
	RootKeyID, ReleaseKeyID string
	// AnchorPath is the trusted root inside the store.
	AnchorPath string
}

// Keygen writes the offline root key to outPath, the release key into the
// store at 0600, and the signed root.json both sides verify against. It
// refuses if any of the three would overwrite something that is already
// there.
func Keygen(root, outPath string, now time.Time) (*KeygenResult, error) {
	for _, path := range []string{outPath, ReleaseKeyPath(root), TrustedRootPath(root)} {
		if _, err := os.Stat(path); err == nil {
			return nil, fmt.Errorf("%s already exists. A second keygen would "+
				"silently re-anchor trust, and every pack already signed "+
				"would fail verification against a root it never knew; "+
				"move the old files aside deliberately first", path)
		}
	}

	rootKey, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	releaseKey, err := GenerateKey()
	if err != nil {
		return nil, err
	}

	// The offline key first, 0600 like everything that can sign: a file
	// that can be moved away is also a file that can be copied without
	// noticing.
	if err := SaveKey(outPath, rootKey, 0o600); err != nil {
		return nil, fmt.Errorf("writing the offline root key: %w", err)
	}
	if err := SaveKey(ReleaseKeyPath(root), releaseKey, 0o600); err != nil {
		return nil, fmt.Errorf("writing the release key: %w", err)
	}
	signedRoot, err := MakeRoot(rootKey, releaseKey, now)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(ContentDir(root), 0o700); err != nil {
		return nil, err
	}
	if err := WriteRoot(TrustedRootPath(root), signedRoot); err != nil {
		return nil, fmt.Errorf("writing the trusted root: %w", err)
	}

	rootID, err := KeyID(rootKey.PublicKey())
	if err != nil {
		return nil, err
	}
	releaseID, err := KeyID(releaseKey.PublicKey())
	if err != nil {
		return nil, err
	}
	return &KeygenResult{RootKeyPath: outPath, RootKeyID: rootID,
		ReleaseKeyID: releaseID, AnchorPath: TrustedRootPath(root)}, nil
}

// LoadAnchor reads the store's trusted root, for verification.
func LoadAnchor(root string) (*SignedRoot, error) {
	return LoadRoot(ContentDir(root))
}

// RotationResult is what a rotation produced, for the fingerprints a
// person checks against the ones written down at keygen.
type RotationResult struct {
	// FromVersion and ToVersion are the anchor's root version before and
	// after. The difference is 1; a ceremony that could jump versions
	// would be a ceremony that could skip the chain's continuity.
	FromVersion, ToVersion int
	// FromKeyID is the outgoing root's fingerprint — the one the operator
	// wrote down at keygen and just checked against the key they brought
	// back. ToKeyID is the incoming root's, to write down now: it is what
	// an installer checks before trusting the next rotation.
	FromKeyID, ToKeyID string
	// NewKeyPath is where the incoming offline key was written. The
	// operator's to move away, exactly like keygen's.
	NewKeyPath string
	// AnchorPath is the trusted root, now at ToVersion.
	AnchorPath string
}

// RotateStoreRoot is the rotation ceremony: the operator brings the
// offline root key back (oldKeyPath — the file keygen wrote and told them
// to move away), a fresh root key is generated and written to newKeyPath,
// and the store's anchor moves to version N+1 carrying both keys'
// signatures. Producing stores run this rarely and deliberately — annually,
// or on suspicion (design §4.3) — and everything about the refusal shape
// below is that rarity made mechanical.
//
// The refusals are the ceremony, not paranoia: an old key that is not the
// anchor's root key would sign a "rotation" no client's anchor can walk —
// a new trust anchor wearing a rotation's clothes — and refusing it here
// says so in the operator's terms rather than in every installer's. A
// new-key path that already exists is keygen's refusal again: overwriting
// a key file with a file operation is re-anchoring trust without a
// signature. The anchor itself is replaced atomically, and nothing here
// can move the root version down.
func RotateStoreRoot(root, oldKeyPath, newKeyPath string, now time.Time) (*RotationResult, error) {
	anchor, err := LoadAnchor(root)
	if err != nil {
		return nil, fmt.Errorf("this store has no trusted root to rotate: %w\n"+
			"  aertun content keygen makes the first one", err)
	}
	oldKey, err := LoadKey(oldKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading the outgoing root key: %w", err)
	}
	if oldKey.PublicKey() != anchor.Signed.RootKey {
		from, _ := KeyID(anchor.Signed.RootKey)
		got, gerr := KeyID(oldKey.PublicKey())
		if gerr != nil {
			got = "an unreadable key"
		}
		return nil, fmt.Errorf("the key at %s is %s, and this store's anchor "+
			"names %s as its root key. A rotation is signed by the root being "+
			"rotated — the old key's signature is the continuity every "+
			"installer walks — so anything else would be a new trust anchor "+
			"wearing a rotation's clothes. Bring the root key keygen wrote, "+
			"or re-anchor deliberately with a copy of the producer's "+
			"root.json", oldKeyPath, got, from)
	}
	if _, err := os.Stat(newKeyPath); err == nil {
		return nil, fmt.Errorf("%s already exists. A rotation writes the "+
			"incoming root key once and never overwrites one; move the old "+
			"file aside deliberately first, as at keygen", newKeyPath)
	}
	newKey, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	rotated, err := RotateRoot(anchor, oldKey, newKey, now)
	if err != nil {
		return nil, err
	}
	// The incoming key first, then the anchor: if the anchor write fails,
	// the operator still holds the key that signed the root they do not
	// yet trust, and the ceremony can be run again with a fresh
	// --new-root-key path. The other order could leave a store anchored
	// to a root whose key was never written anywhere at all.
	if err := SaveKey(newKeyPath, newKey, 0o600); err != nil {
		return nil, fmt.Errorf("writing the incoming root key: %w", err)
	}
	if err := WriteRoot(TrustedRootPath(root), rotated); err != nil {
		return nil, fmt.Errorf("writing the rotated root: %w", err)
	}
	from, err := KeyID(anchor.Signed.RootKey)
	if err != nil {
		return nil, err
	}
	to, err := KeyID(newKey.PublicKey())
	if err != nil {
		return nil, err
	}
	return &RotationResult{FromVersion: anchor.Signed.Version,
		ToVersion: rotated.Signed.Version, FromKeyID: from, ToKeyID: to,
		NewKeyPath: newKeyPath, AnchorPath: TrustedRootPath(root)}, nil
}

// LoadReleaseKey reads the store's release key. 0600 by construction; the
// permission is asserted at keygen and the file is never re-opened for
// writing, so it cannot drift.
func LoadReleaseKey(root string) (*Key, error) {
	return LoadKey(ReleaseKeyPath(root))
}
