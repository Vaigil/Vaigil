// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The chain walk: everything a pack must pass, in the order it must pass
// it, before anything is installed.
//
// The order is load-bearing, the same way §5.1 of the design is: each early
// gate removes a class of input the later gates would otherwise be trusted
// with. Signatures first, so nothing parses until it is authenticated;
// version counters next, so nothing is examined that the store has already
// moved past (the rollback defence — the counters live in this store's
// installed state, not in anything the pack carries, which is why serving
// an old pack again refuses no matter what the mirror says); digests then,
// which is where transport integrity comes free (the trust was never in the
// copy); bounds before interpretation; and the content last, through the
// shipping loaders, so the only thing that ever validated a pack is the
// engine that will run it.
//
// Nothing here disables installed content. Expiry is a property of the
// update path: an expired pack is refused as a candidate, and an expired
// installed pack is untouched, because the run path never consults this
// metadata at all.
//
// A root one version ahead of the anchor is a rotation in flight, and it
// passes only with BOTH signatures — the outgoing root's over the new body
// (the continuity: trust in the old key is the only thing that can vouch
// for its replacement) and the incoming root's own (the handover: every
// later root is checked against the incoming key, so it must be able to
// sign). A root that drops the old signature mid-chain fails the first
// check; a root from the wrong key fails the second. More than one version
// ahead refuses — the chain walks forward one step at a time, or a person
// re-anchors deliberately — and a root that goes down is the same rollback
// it always was.

// Check is one named step of the walk, recorded so a listing can show every
// check and a refusal can name the one that failed.
type Check struct {
	// Name is the check, short: "root.json signature".
	Name string `json:"name"`
	// OK is whether it passed.
	OK bool `json:"ok"`
	// Note says what was checked, or precisely what failed and why.
	Note string `json:"note"`
}

// Verified is a pack that passed the walk, with the checks it passed.
type Verified struct {
	Dir       string
	Manifest  Manifest
	Root      SignedRoot
	Targets   SignedTargets
	Timestamp SignedTimestamp
	Checks    []Check
}

// VerifyOptions is what the walk needs beyond the pack directory.
type VerifyOptions struct {
	// Now is the clock. A parameter rather than time.Now so a test can
	// stand on either side of an expiry without sleeping, and so a caller
	// can never be accused of freezing time: the pack's dates are
	// compared, not the host's.
	Now time.Time
	// Anchor is this store's trusted root.json (written at keygen, or
	// copied in from a producer this store chose to trust). Nil refuses:
	// without an anchor there is nothing to verify against, and guessing
	// one would make "verified" a word this package cannot say.
	Anchor *SignedRoot
	// Installed maps pack id to the metadata version this store has
	// installed. A candidate at or below it is a rollback and refuses.
	Installed map[string]int
	// BinaryVersion is the running binary's version, for the manifest's
	// minimum_binary floor. Unparseable (a dev build) skips the floor
	// rather than refusing: a dev binary knows the schemas it was built
	// with, which is what the floor is a proxy for.
	BinaryVersion string
}

// Verify walks the chain and returns the verified pack, or the first failed
// check as an error that names it. The error is what install refuses with;
// the checks are what a person reads.
func Verify(dir string, opts VerifyOptions) (*Verified, error) {
	v := &Verified{Dir: dir}
	fail := func(name string, format string, args ...any) (*Verified, error) {
		note := fmt.Sprintf(format, args...)
		v.Checks = append(v.Checks, Check{Name: name, OK: false, Note: note})
		return v, fmt.Errorf("%s: %s", name, note)
	}
	pass := func(name, note string) {
		v.Checks = append(v.Checks, Check{Name: name, OK: true, Note: note})
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	if opts.Anchor == nil {
		return fail("root of trust",
			"this store has no trusted root.json under its content "+
				"directory. Run aertun content keygen on the producing "+
				"store, or copy that store's root.json here; a pack is "+
				"only as verified as the anchor it is checked against")
	}

	// 1. The pack's root, against the anchor. Two shapes pass:
	//
	//   the same version — signed, with both algorithms, by the root key
	//   the anchor names, naming the same keys the anchor names; or
	//
	//   exactly one version ahead — a rotation, carrying both signatures:
	//   the outgoing root's over the same body (continuity) and the
	//   incoming root's own (the handover). The rotated root names the
	//   release key from here on, so the anchor's release key is not
	//   compared at a version boundary — the whole point of the boundary
	//   is that the new root may name new keys, on the old root key's
	//   authority.
	//
	// A root that skips a version refuses, and a root that goes down is
	// the rollback it always was.
	root, err := LoadRoot(dir)
	if err != nil {
		return fail("root.json", "%v", err)
	}
	anchorID, aerr := KeyID(opts.Anchor.Signed.RootKey)
	if aerr != nil {
		return fail("root of trust", "the anchor is unreadable: %v", aerr)
	}
	var releaseID string
	switch {
	case root.Signed.Version == opts.Anchor.Signed.Version:
		if root.Signed.RootKey != opts.Anchor.Signed.RootKey {
			return fail("root.json signature",
				"the pack's root names a different root key than the "+
					"anchor it claims to be. A root describes itself; one "+
					"that misnames its own key is not the document this "+
					"store trusts")
		}
		if err := VerifyMetadata(root.Signed, root.Signature,
			opts.Anchor.Signed.RootKey); err != nil {
			return fail("root.json signature", "%v", err)
		}
		releaseID, err = KeyID(root.Signed.ReleaseKey)
		if err != nil {
			return fail("root.json", "the release key it names is unreadable: %v", err)
		}
		if trusted, _ := KeyID(opts.Anchor.Signed.ReleaseKey); trusted != releaseID {
			return fail("root.json release key",
				"the pack's root trusts release key %s and this store's anchor "+
					"trusts %s; the online key cannot be changed without a new "+
					"root, which is the point of having an offline one",
				releaseID, trusted)
		}
		pass("root.json signature",
			"signed with Ed25519 and ML-DSA-65 by the trusted root key "+
				anchorID+", version "+fmt.Sprint(root.Signed.Version))

	case root.Signed.Version == opts.Anchor.Signed.Version+1:
		// The continuity: the outgoing root key's signature over the new
		// body. Missing is the belt half dropped — a new root that
		// replaces its signer without the old signer's word refuses here,
		// whatever its own signature says.
		if root.Previous == nil {
			return fail("root.json continuity signature",
				"root version %d carries no signature from the root "+
					"version %d key. A rotation is signed by BOTH keys — "+
					"the outgoing one because trust in it is the only thing "+
					"that can vouch for its replacement — so a new root "+
					"that drops the old signature mid-chain refuses",
				root.Signed.Version, opts.Anchor.Signed.Version)
		}
		if err := VerifyMetadata(root.Signed, *root.Previous,
			opts.Anchor.Signed.RootKey); err != nil {
			return fail("root.json continuity signature",
				"%v. This root is one version ahead of the trusted one, "+
					"and the outgoing root key's signature over it — the "+
					"continuity every rotation walks — does not verify",
				err)
		}
		// The handover: the incoming root key's own signature. The anchor
		// follows this key after the install, so it signs its own root or
		// nothing does.
		if err := VerifyMetadata(root.Signed, root.Signature,
			root.Signed.RootKey); err != nil {
			return fail("root.json signature", "%v", err)
		}
		newID, nerr := KeyID(root.Signed.RootKey)
		if nerr != nil {
			return fail("root.json", "the root key it names is unreadable: %v", nerr)
		}
		releaseID, err = KeyID(root.Signed.ReleaseKey)
		if err != nil {
			return fail("root.json", "the release key it names is unreadable: %v", err)
		}
		pass("root.json signature",
			fmt.Sprintf("root rotation: version %d signed by the outgoing "+
				"root %s (the continuity) and the incoming %s (the handover), "+
				"naming release key %s", root.Signed.Version, anchorID,
				newID, releaseID))

	case root.Signed.Version > opts.Anchor.Signed.Version+1:
		return fail("root.json version",
			"the pack carries root version %d and this store trusts "+
				"version %d. The root chain moves one version at a time — "+
				"every step is a rotation the old key signed — so a root "+
				"that skips versions cannot be walked. Copy the producer's "+
				"current root.json into this store deliberately, or update "+
				"aertun",
			root.Signed.Version, opts.Anchor.Signed.Version)

	default:
		return fail("root.json version",
			"the pack carries root version %d and this store trusts "+
				"version %d: an older root is a rollback and refuses",
			root.Signed.Version, opts.Anchor.Signed.Version)
	}

	// 2. Root expiry — on the update path only. The message says what
	// expiry does and does not do, because that rule is the one an
	// operator must not have to look up mid-incident.
	if exp, ok := expiryOf(root.Signed.Expires, now); !ok {
		return fail("root.json expiry",
			"the trusted root expired %s. Updates are refused; installed "+
				"content keeps running. Re-anchor deliberately: aertun "+
				"content keygen, or copy the producer's current root.json",
			exp)
	}
	pass("root.json expiry", "fresh until "+root.Signed.Expires)

	// 3. Targets: the release key's word on the manifest's bytes, at a
	// monotonic integer version.
	targets, err := LoadTargets(dir)
	if err != nil {
		return fail("targets.json", "%v", err)
	}
	if err := VerifyMetadata(targets.Signed, targets.Signature,
		root.Signed.ReleaseKey); err != nil {
		return fail("targets.json signature", "%v", err)
	}
	pass("targets.json signature",
		"signed with both algorithms by release key "+releaseID)

	if targets.Signed.Version < 1 {
		return fail("targets.json version",
			"the metadata version is %d; it counts up from 1",
			targets.Signed.Version)
	}
	if have, was := opts.Installed[targets.Signed.Pack]; was &&
		targets.Signed.Version <= have {
		return fail("targets.json version",
			"this store has metadata version %d of %s installed and the "+
				"pack is version %d. An update at or below what is "+
				"installed is a rollback — the CrowdStrike-shaped attack "+
				"this plane refuses — and the counters live here, not in "+
				"the pack", have, targets.Signed.Pack, targets.Signed.Version)
	}
	pass("targets.json version",
		fmt.Sprintf("metadata version %d", targets.Signed.Version))
	if exp, ok := expiryOf(targets.Signed.Expires, now); !ok {
		return fail("targets.json expiry",
			"the pack's targets metadata expired %s. Updates are refused; "+
				"installed content keeps running", exp)
	}
	pass("targets.json expiry", "fresh until "+targets.Signed.Expires)

	// 4. Timestamp: pins targets.json's exact bytes. A stale or swapped
	// targets refuses here, by digest, before anything else reads it.
	ts, err := LoadTimestamp(dir)
	if err != nil {
		return fail("timestamp.json", "%v", err)
	}
	if err := VerifyMetadata(ts.Signed, ts.Signature,
		root.Signed.ReleaseKey); err != nil {
		return fail("timestamp.json signature", "%v", err)
	}
	pass("timestamp.json signature",
		"signed with both algorithms by release key "+releaseID)
	tbody, err := os.ReadFile(filepath.Join(dir, TargetsName))
	if err != nil {
		return fail("timestamp.json", "reading %s: %v", TargetsName, err)
	}
	if got := sha256Hex(tbody); got != ts.Signed.Targets.SHA256 ||
		int64(len(tbody)) != ts.Signed.Targets.Length {
		return fail("targets.json pinned bytes",
			"timestamp.json pins %s at %d bytes and the file hashes to %s "+
				"at %d: the targets metadata is not what was signed",
			ts.Signed.Targets.SHA256, ts.Signed.Targets.Length,
			got, len(tbody))
	}
	pass("targets.json pinned bytes",
		"exactly the bytes timestamp.json pins")
	if exp, ok := expiryOf(ts.Signed.Expires, now); !ok {
		return fail("timestamp.json expiry",
			"the pack's timestamp expired %s, which is the freeze signal: "+
				"updates are refused; installed content keeps running", exp)
	}
	pass("timestamp.json expiry", "fresh until "+ts.Signed.Expires)

	// 5. The manifest, pinned by targets: its exact bytes must be what the
	// release key signed.
	mbody, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return fail("manifest.json", "reading it: %v", err)
	}
	if got := sha256Hex(mbody); got != targets.Signed.Manifest.SHA256 ||
		int64(len(mbody)) != targets.Signed.Manifest.Length {
		return fail("manifest.json digest",
			"targets.json pins %s at %d bytes and the manifest hashes to "+
				"%s at %d: the manifest is not the one that was signed",
			targets.Signed.Manifest.SHA256, targets.Signed.Manifest.Length,
			got, len(mbody))
	}
	pass("manifest.json digest", "exactly the bytes targets.json pins")

	// 6. The pack itself: manifest validity, per-file digests, bounds, no
	// unlisted files. Read refuses with the file and the reason.
	p, err := Read(dir)
	if err != nil {
		return fail("content bounds and digests", "%v", err)
	}
	if p.Manifest.ID != targets.Signed.Pack {
		return fail("pack id",
			"the metadata was signed for %q and the manifest says %q",
			targets.Signed.Pack, p.Manifest.ID)
	}
	pass("content bounds and digests",
		fmt.Sprintf("%d file(s), every digest matching the manifest, "+
			"nothing unlisted", len(p.Manifest.Files)))

	// 7. Version negotiation: a pack written for a newer binary refuses
	// whole, rather than loading half-meaningful content.
	if p.Manifest.Engine.MinimumBinary != "" && opts.BinaryVersion != "" {
		if got, gerr := ParseVersion(opts.BinaryVersion); gerr == nil {
			if floor, ferr := ParseVersion(p.Manifest.Engine.MinimumBinary); ferr == nil &&
				CompareVersions(got, floor) < 0 {
				return fail("minimum binary version",
					"the pack needs aertun %s and this binary reports %s",
					p.Manifest.Engine.MinimumBinary, opts.BinaryVersion)
			}
		}
	}
	pass("minimum binary version",
		firstClaimed(p.Manifest.Engine.MinimumBinary, opts.BinaryVersion))

	// 8. The content, through the shipping loaders — the same Validate and
	// fixtures `aertun detect run` would apply. There is no second
	// validator to disagree with the engine; that disagreement is the
	// exact shape of the CrowdStrike failure.
	if err := p.ValidateContent(); err != nil {
		return fail("content validation", "%v", err)
	}
	rules, corrs := p.Counts()
	pass("content validation",
		fmt.Sprintf("%d rule(s) and %d correlation file(s) load and pass "+
			"their fixtures under this binary's own validators", rules, corrs))

	v.Manifest = p.Manifest
	v.Root = *root
	v.Targets = *targets
	v.Timestamp = *ts
	return v, nil
}

// expiryOf reports whether a metadata expiry is still ahead of now, and the
// date either way for the message. Malformed dates fail closed: an expiry
// that cannot be read cannot be relied on, and metadata that carries one
// was not written by this signer.
func expiryOf(expires string, now time.Time) (string, bool) {
	t, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		return expires, false
	}
	return t.UTC().Format("2 Jan 2006"), now.Before(t)
}

// firstClaimed is the note for the binary-floor check.
func firstClaimed(floor, binary string) string {
	if floor == "" {
		return "the pack claims no minimum binary"
	}
	if _, err := ParseVersion(binary); err != nil {
		return fmt.Sprintf("the pack needs aertun %s; this binary reports "+
			"an unparseable version %q, so the floor is taken on trust as a "+
			"dev build", floor, binary)
	}
	return fmt.Sprintf("the pack needs aertun %s and this binary is %s",
		floor, binary)
}
