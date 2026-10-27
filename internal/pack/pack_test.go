// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vaigil/vaigil/internal/spool"
	"github.com/vaigil/vaigil/internal/telemetry"
)

// A rule the shipping validators accept: one it must match, one it must
// refuse, every field it reads exercised. The same shape the command-line
// tests use, because the point of content validation is that this is the
// same rule the run would load.
const testRule = `{
  "id": "vaigil.test-privileged-failed",
  "title": "Failed sign-in to a privileged account",
  "why": "a guessed or sprayed administrator password",
  "sources": ["okta/system"],
  "severity": 4,
  "technique": ["T1110"],
  "when": {"all": [
    {"match": {"field": "class", "op": "equals", "values": ["3002"]}},
    {"match": {"field": "disposition", "op": "equals", "values": ["failed"]}},
    {"match": {"field": "actor.value", "op": "prefix", "values": ["admin-"]}}
  ]},
  "fixtures": [
    {"name": "an admin fails", "match": true, "event": {
      "source": "okta/system", "time": "2026-09-01T00:00:00Z",
      "received": "2026-09-01T00:00:01Z", "class": 3002, "disposition": 4,
      "actor": {"issuer": "okta", "value": "admin-dana"}}},
    {"name": "an admin succeeds", "match": false, "event": {
      "source": "okta/system", "time": "2026-09-01T00:00:00Z",
      "received": "2026-09-01T00:00:01Z", "class": 3002, "disposition": 1,
      "actor": {"issuer": "okta", "value": "admin-dana"}}}
  ]
}`

// testRuleTuned is v2 of the same rule: a different match, so an install
// over v1 and a rollback back are distinguishable by bytes on disk.
const testRuleTuned = `{
  "id": "vaigil.test-privileged-failed",
  "title": "Failed sign-in to a privileged account",
  "why": "a guessed or sprayed administrator password, narrowed to two failures",
  "sources": ["okta/system"],
  "severity": 4,
  "when": {"all": [
    {"match": {"field": "class", "op": "equals", "values": ["3002"]}},
    {"match": {"field": "disposition", "op": "equals", "values": ["failed"]}},
    {"match": {"field": "actor.value", "op": "prefix", "values": ["admin-"]}},
    {"match": {"field": "actor.value", "op": "suffix", "values": ["-ops"]}}
  ]},
  "fixtures": [
    {"name": "an ops admin fails", "match": true, "event": {
      "source": "okta/system", "time": "2026-09-01T00:00:00Z",
      "received": "2026-09-01T00:00:01Z", "class": 3002, "disposition": 4,
      "actor": {"issuer": "okta", "value": "admin-dana-ops"}}},
    {"name": "a plain admin fails", "match": false, "event": {
      "source": "okta/system", "time": "2026-09-01T00:00:00Z",
      "received": "2026-09-01T00:00:01Z", "class": 3002, "disposition": 4,
      "actor": {"issuer": "okta", "value": "admin-dana"}}}
  ]
}`

const testCorrelation = `title: One privileged account failed to sign in many times
id: corr.test-privileged-failures
correlation:
    type: event_count
    rules:
        - vaigil.test-privileged-failed
    group-by:
        - actor.value
    timespan: 15m
    condition:
        gte: 5
level: high
`

// writePack lays out a pack directory with the given rule body and version.
func writePack(t *testing.T, rule string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, TypeDetection), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, TypeCorrelation), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, TypeDetection,
		"vaigil.test-privileged-failed.json"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, TypeCorrelation,
		"test.yml"), []byte(testCorrelation), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// signedStore is a store that has run keygen, with its offline root key
// kept at offline for the rotation ceremony the tests run through it.
type signedStore struct {
	root    string
	offline string
}

func keygenStore(t *testing.T) *signedStore {
	t.Helper()
	s := &signedStore{root: t.TempDir()}
	offline := filepath.Join(t.TempDir(), "offline.key")
	if _, err := Keygen(s.root, offline, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	s.offline = offline
	return s
}

// buildAndSign builds and signs a pack directory at the next producer
// version, returning the metadata version used.
func (s *signedStore) buildAndSign(t *testing.T, dir, id, version string) int {
	t.Helper()
	p, err := Build(dir, BuildOptions{ID: id, Version: version,
		Channel: Stable, About: "test pack"})
	if err != nil {
		t.Fatal(err)
	}
	release, err := LoadReleaseKey(s.root)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := LoadAnchor(s.root)
	if err != nil {
		t.Fatal(err)
	}
	produced, err := LoadProduced(s.root)
	if err != nil {
		t.Fatal(err)
	}
	meta := produced.NextVersion(id)
	if err := SignPack(dir, p, release, anchor, meta, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := produced.RecordEmitted(s.root, id, meta); err != nil {
		t.Fatal(err)
	}
	return meta
}

func (s *signedStore) verify(t *testing.T, dir string, now time.Time) (*Verified, error) {
	t.Helper()
	anchor, err := LoadAnchor(s.root)
	if err != nil {
		t.Fatal(err)
	}
	st, err := LoadInstalled(s.root)
	if err != nil {
		t.Fatal(err)
	}
	return Verify(dir, VerifyOptions{Anchor: anchor,
		Installed: st.VersionMap(), Now: now, BinaryVersion: "0.9.0"})
}

// everyCheckPassed is the roundtrip's other half: not just "no error" but
// every named check present and green, so a check silently dropped from the
// walk fails here rather than quietly narrowing the gate.
func everyCheckPassed(t *testing.T, v *Verified) {
	t.Helper()
	want := []string{
		"root.json signature", "root.json expiry",
		"targets.json signature", "targets.json version", "targets.json expiry",
		"timestamp.json signature", "targets.json pinned bytes",
		"timestamp.json expiry", "manifest.json digest",
		"content bounds and digests", "minimum binary version",
		"content validation",
	}
	var got []string
	for _, c := range v.Checks {
		if !c.OK {
			t.Fatalf("check %s failed: %s", c.Name, c.Note)
		}
		got = append(got, c.Name)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
			}
		}
		if !found {
			t.Errorf("the walk did not run %q; checks were %v. A check "+
				"dropped from the order is a gate quietly removed", w, got)
		}
	}
}

// TestSignVerifyRoundtrip is the happy path: build, sign, and every check
// green, with both algorithms on every role.
func TestSignVerifyRoundtrip(t *testing.T) {
	s := keygenStore(t)
	dir := writePack(t, testRule)
	meta := s.buildAndSign(t, dir, "vaigil.test", "2026.11.0")
	if meta != 1 {
		t.Fatalf("the first signing is metadata version 1, not %d", meta)
	}
	v, err := s.verify(t, dir, time.Now().UTC())
	if err != nil {
		t.Fatalf("a pack this store signed itself must verify: %v", err)
	}
	everyCheckPassed(t, v)
	if v.Manifest.ID != "vaigil.test" || v.Manifest.Version != "2026.11.0" {
		t.Fatalf("wrong pack came back: %s %s", v.Manifest.ID, v.Manifest.Version)
	}
	// Both algorithms really are on every role: a signature block missing
	// a half is a different test, and this one asserts the positive.
	for name, sig := range map[string]Signature{
		RootName: v.Root.Signature, TargetsName: v.Targets.Signature,
		TimestampName: v.Timestamp.Signature,
	} {
		if sig.Ed25519 == "" || sig.MLDSA65 == "" {
			t.Errorf("%s was signed with one algorithm and the walk accepted "+
				"it earlier; both are required", name)
		}
	}
}

// TestTamperedContentFailsNamingTheDigest: a rule file edited after
// signing. The manifest's digest is what catches it, and the failure names
// the file and both hashes — the precise failed check, not a shrug.
func TestTamperedContentFailsNamingTheDigest(t *testing.T) {
	s := keygenStore(t)
	dir := writePack(t, testRule)
	s.buildAndSign(t, dir, "vaigil.test", "2026.11.0")
	rulePath := filepath.Join(dir, TypeDetection, "vaigil.test-privileged-failed.json")
	if err := os.WriteFile(rulePath,
		[]byte(strings.Replace(testRule, "admin-dana", "admin-mallory", -1)),
		0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.verify(t, dir, time.Now().UTC())
	if err == nil {
		t.Fatal("a tampered pack verified")
	}
	if !strings.Contains(err.Error(), "does not match its manifest digest") {
		t.Fatalf("the failure must name the digest mismatch, and said: %v", err)
	}
	if !strings.Contains(err.Error(), TypeDetection+"/") {
		t.Fatalf("the failure must name the file, and said: %v", err)
	}
}

// TestTamperedManifestFails: editing the manifest after signing — the
// targets pin catches it, before the manifest's own claims are even read.
func TestTamperedManifestFails(t *testing.T) {
	s := keygenStore(t)
	dir := writePack(t, testRule)
	s.buildAndSign(t, dir, "vaigil.test", "2026.11.0")
	mpath := filepath.Join(dir, ManifestName)
	body, err := os.ReadFile(mpath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mpath,
		[]byte(strings.Replace(string(body), "test pack", "better pack", 1)),
		0o644); err != nil {
		t.Fatal(err)
	}
	_, err = s.verify(t, dir, time.Now().UTC())
	if err == nil {
		t.Fatal("a pack with an edited manifest verified")
	}
	if !strings.Contains(err.Error(), "manifest.json digest") {
		t.Fatalf("the failed check must be the manifest digest, and said: %v", err)
	}
}

// TestMissingSecondSignatureFails: a metadata file carrying one signature
// is refused with the missing algorithm named. No accept-single option
// exists to test, which is the property.
func TestMissingSecondSignatureFails(t *testing.T) {
	s := keygenStore(t)
	dir := writePack(t, testRule)
	s.buildAndSign(t, dir, "vaigil.test", "2026.11.0")

	tpath := filepath.Join(dir, TargetsName)
	body, err := os.ReadFile(tpath)
	if err != nil {
		t.Fatal(err)
	}
	var st SignedTargets
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	st.Signature.MLDSA65 = ""
	out, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	// The timestamp pins targets' bytes, so the walk reaches the signature
	// failure only if the pin is refreshed too — an attacker re-signing the
	// timestamp would still fail on the missing ML-DSA half there. For this
	// test the signature failure comes first either way: re-write targets
	// and let the pin fail for the honest pack, or strip both. Strip the
	// timestamp's ML-DSA too, so the named failure is the one under test.
	if err := os.WriteFile(tpath, out, 0o644); err != nil {
		t.Fatal(err)
	}
	spath := filepath.Join(dir, TimestampName)
	sbody, err := os.ReadFile(spath)
	if err != nil {
		t.Fatal(err)
	}
	var ts SignedTimestamp
	if err := json.Unmarshal(sbody, &ts); err != nil {
		t.Fatal(err)
	}
	ts.Signature.MLDSA65 = ""
	sout, err := json.Marshal(ts)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spath, sout, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err = s.verify(t, dir, time.Now().UTC())
	if err == nil {
		t.Fatal("metadata with one signature verified")
	}
	if !strings.Contains(err.Error(), "no ML-DSA-65 signature") {
		t.Fatalf("the failure must name the missing algorithm, and said: %v", err)
	}
	if !strings.Contains(err.Error(), "Both are required") {
		t.Fatalf("the refusal must say both are required, and said: %v", err)
	}
}

// TestVersionRollbackRefused: install v2, then present v1 again. The
// counters live in the installed state, so the old pack refuses no matter
// how intact its signatures are.
func TestVersionRollbackRefused(t *testing.T) {
	s := keygenStore(t)
	rules := t.TempDir()

	v2dir := writePack(t, testRuleTuned)
	v2 := s.buildAndSign(t, v2dir, "vaigil.test", "2026.11.1")
	ver, err := s.verify(t, v2dir, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Install(ver, s.root, rules, nil, OverridesRefuse); err != nil {
		t.Fatal(err)
	}

	// v1, signed after v2 by the same honest producer (metadata version 2)
	// but presented as an update to a store on 2.
	v1dir := writePack(t, testRule)
	s.buildAndSign(t, v1dir, "vaigil.test", "2026.11.0")
	// Re-sign at metadata version 1 by hand: rewind the producer's counter,
	// which is what a mirror serving the old release back looks like.
	produced, err := LoadProduced(s.root)
	if err != nil {
		t.Fatal(err)
	}
	produced.Last["vaigil.test"] = 0
	if err := produced.RecordEmitted(s.root, "vaigil.test", 1); err != nil {
		t.Fatal(err)
	}
	p, err := Read(v1dir)
	if err != nil {
		t.Fatal(err)
	}
	release, err := LoadReleaseKey(s.root)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := LoadAnchor(s.root)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignPack(v1dir, p, release, anchor, 1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	_, err = s.verify(t, v1dir, time.Now().UTC())
	if err == nil {
		t.Fatal("a rollback verified against a store on a later version")
	}
	if !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("the refusal must say it is a rollback, and said: %v", err)
	}
	if v2 != 1 {
		t.Fatalf("the store should be on metadata version 1, not %d", v2)
	}
}

// TestExpiryRefusesUpdatesNeverDisablesContent: an expired pack refuses as
// an update; an expired installed pack keeps working — its files stay where
// the run reads them and the installed record still lists it. Expiry is a
// property of the update path only.
func TestExpiryRefusesUpdatesNeverDisablesContent(t *testing.T) {
	s := keygenStore(t)
	rules := t.TempDir()
	now := time.Now().UTC()

	dir := writePack(t, testRule)
	s.buildAndSign(t, dir, "vaigil.test", "2026.11.0")
	v, err := s.verify(t, dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Install(v, s.root, rules, nil, OverridesRefuse); err != nil {
		t.Fatal(err)
	}

	// A hundred days later, a NEW pack arrives — signed back when the
	// store was fresh, carried forward since. Its timestamp (14 days) and
	// targets (90 days) have both expired, and the update refuses: expiry
	// is the freeze defence, on the update path only.
	d2 := writePack(t, testRuleTuned)
	s.buildAndSign(t, d2, "vaigil.test", "2026.11.1")
	if _, err := s.verify(t, d2, now.Add(100*24*time.Hour)); err == nil {
		t.Fatal("an expired pack verified as an update")
	} else if !strings.Contains(err.Error(), "expired") ||
		!strings.Contains(err.Error(), "installed content keeps running") {
		t.Fatalf("the refusal must say what expiry does, and said: %v", err)
	}

	// And the installed pack: still listed, still stale-visible, its files
	// still exactly where the detection run loads them.
	st, err := LoadInstalled(s.root)
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := st.Packs["vaigil.test"]
	if !ok {
		t.Fatal("the expired installed pack vanished from the record; " +
			"expiry must never uninstall content")
	}
	if _, stale := rec.StaleSince(now.Add(100 * 24 * time.Hour)); !stale {
		t.Fatal("the installed pack's staleness is not reported; a freeze " +
			"that passed silently would be the failure this note exists for")
	}
	for _, f := range v.Manifest.Files {
		if _, err := os.Stat(filepath.Join(rules, rulePath(f.Path))); err != nil {
			t.Fatalf("the expired pack's %s is gone from the rules "+
				"directory: %v. Installed content keeps running", f.Path, err)
		}
	}
	// Before expiry, the newer pack verifies, and the installed staleness
	// is not raised.
	if _, err := s.verify(t, d2, now); err != nil {
		t.Fatalf("the fresh pack refuses: %v", err)
	}
	if _, stale := rec.StaleSince(now); stale {
		t.Fatal("a pack whose expiry has not passed is reported stale")
	}
}

// TestInstallPlacesWhatTheRunLoadsAndRollsBack: the files land at the
// paths the loaders walk (detections/*.json, correlations/*.yml), a second
// install replaces them, rollback restores the first set byte for byte —
// and a file the pack never owned is untouched throughout.
func TestInstallPlacesWhatTheRunLoadsAndRollsBack(t *testing.T) {
	s := keygenStore(t)
	rules := t.TempDir()
	unowned := filepath.Join(rules, "vaigil.orgs-own-rule.json")
	if err := os.WriteFile(unowned, []byte(testRule), 0o600); err != nil {
		t.Fatal(err)
	}

	d1 := writePack(t, testRule)
	s.buildAndSign(t, d1, "vaigil.test", "2026.11.0")
	v1, err := s.verify(t, d1, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Install(v1, s.root, rules, nil, OverridesRefuse); err != nil {
		t.Fatal(err)
	}
	rulePath := filepath.Join(rules, "vaigil.test-privileged-failed.json")
	got, err := os.ReadFile(rulePath)
	if err != nil || string(got) != testRule {
		t.Fatalf("the rule was not placed where the run loads it: %v", err)
	}

	// v2 over v1.
	d2 := writePack(t, testRuleTuned)
	s.buildAndSign(t, d2, "vaigil.test", "2026.11.1")
	v2, err := s.verify(t, d2, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	res, err := Install(v2, s.root, rules, nil, OverridesRefuse)
	if err != nil {
		t.Fatal(err)
	}
	if res.Replaced != len(v2.Manifest.Files) {
		t.Fatalf("%d file(s) replaced, expected every one of %d",
			res.Replaced, len(v2.Manifest.Files))
	}
	got, err = os.ReadFile(rulePath)
	if err != nil || string(got) != testRuleTuned {
		t.Fatal("the update did not replace the rule")
	}

	// Rollback: v1 back, the addition-less set restored whole, the
	// unowned file never touched.
	rb, err := Rollback(s.root, rules)
	if err != nil {
		t.Fatal(err)
	}
	if rb.Restored != len(v2.Manifest.Files) || rb.Removed != 0 {
		t.Fatalf("rollback restored %d and removed %d", rb.Restored, rb.Removed)
	}
	got, err = os.ReadFile(rulePath)
	if err != nil || string(got) != testRule {
		t.Fatal("rollback did not restore the previous bytes")
	}
	if got, err := os.ReadFile(unowned); err != nil || string(got) != testRule {
		t.Fatal("rollback touched a file the pack never owned")
	}
	st, err := LoadInstalled(s.root)
	if err != nil {
		t.Fatal(err)
	}
	if st.Packs["vaigil.test"].Version != "2026.11.0" ||
		st.Packs["vaigil.test"].MetaVersion != 1 {
		t.Fatalf("the state pointer did not move back: %+v",
			st.Packs["vaigil.test"])
	}

	// And rolling back again undoes the rollback, because the set being
	// left was itself kept.
	if _, err := Rollback(s.root, rules); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(rulePath); err != nil || string(got) != testRuleTuned {
		t.Fatal("the rollback of the rollback did not restore v2")
	}
}

// TestFirstInstallRollbackRemovesAdditions: rolling back a FIRST install
// takes the pack's files out again and drops it from the record.
func TestFirstInstallRollbackRemovesAdditions(t *testing.T) {
	s := keygenStore(t)
	rules := t.TempDir()
	dir := writePack(t, testRule)
	s.buildAndSign(t, dir, "vaigil.test", "2026.11.0")
	v, err := s.verify(t, dir, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Install(v, s.root, rules, nil, OverridesRefuse); err != nil {
		t.Fatal(err)
	}
	rb, err := Rollback(s.root, rules)
	if err != nil {
		t.Fatal(err)
	}
	if rb.Prior != nil {
		t.Fatal("the first install had nothing prior; the rollback must say so")
	}
	if rb.Removed != len(v.Manifest.Files) {
		t.Fatalf("%d file(s) removed, expected all %d", rb.Removed,
			len(v.Manifest.Files))
	}
	if _, err := os.Stat(filepath.Join(rules,
		"vaigil.test-privileged-failed.json")); !os.IsNotExist(err) {
		t.Fatal("the first install's rule is still on disk after rollback")
	}
	st, err := LoadInstalled(s.root)
	if err != nil {
		t.Fatal(err)
	}
	if _, still := st.Packs["vaigil.test"]; still {
		t.Fatal("the rolled-back first install is still in the record")
	}
}

// TestKeygenPermissionsAndRefusal: the release key is 0600 in the store,
// the offline key 0600 wherever it was written, and a second keygen
// refuses rather than silently re-anchoring trust.
func TestKeygenPermissionsAndRefusal(t *testing.T) {
	root := t.TempDir()
	offline := filepath.Join(t.TempDir(), "offline.key")
	if _, err := Keygen(root, offline, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{ReleaseKeyPath(root), offline} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s is %v, not 0600: a key file readable by others is "+
				"a signing oracle left open", path, fi.Mode().Perm())
		}
	}
	// The anchor is public — nothing in it is secret, and an installer has
	// to be able to read it.
	fi, err := os.Stat(TrustedRootPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("the trusted root is %v, not 0644", fi.Mode().Perm())
	}
	if _, err := Keygen(root, filepath.Join(t.TempDir(), "again.key"),
		time.Now().UTC()); err == nil {
		t.Fatal("a second keygen succeeded and would have re-anchored trust")
	}
}

// TestBuildRefusesInvalidContent: the producer's gate. A rule without
// fixtures — the kind that never fires and nobody can tell — is refused
// before anything is signed, with the shipping validator's own reasoning.
func TestBuildRefusesInvalidContent(t *testing.T) {
	dir := writePack(t, testRule)
	if err := os.WriteFile(filepath.Join(dir, TypeDetection,
		"vaigil.broken.json"), []byte(`{
      "id": "vaigil.broken", "title": "Broken", "sources": ["okta/system"],
      "severity": 4, "when": {"all": [
        {"match": {"field": "class", "op": "equals", "values": ["3002"]}}]},
      "fixtures": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Build(dir, BuildOptions{ID: "vaigil.test", Version: "2026.11.0",
		Channel: Stable})
	if err == nil {
		t.Fatal("a rule with no fixtures was signed")
	}
	if !strings.Contains(err.Error(), "fixture") {
		t.Fatalf("the refusal should carry the validator's reasoning: %v", err)
	}
}

// TestBuildRefusesNonContent: anything that is not detections/*.json or
// correlations/*.yml has no place in a pack — a pack is data, and only
// data, and the format's job is to say no.
func TestBuildRefusesNonContent(t *testing.T) {
	dir := writePack(t, testRule)
	if err := os.WriteFile(filepath.Join(dir, "install.sh"),
		[]byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Build(dir, BuildOptions{ID: "vaigil.test", Version: "2026.11.0",
		Channel: Stable})
	if err == nil {
		t.Fatal("a pack carrying a script was built")
	}
	if !strings.Contains(err.Error(), "only data") {
		t.Fatalf("the refusal should say what a pack is: %v", err)
	}
}

// TestExtraFileRefusedAfterSigning: an unlisted file in a signed pack —
// the shape of somebody adding something and not re-signing.
func TestExtraFileRefusedAfterSigning(t *testing.T) {
	s := keygenStore(t)
	dir := writePack(t, testRule)
	s.buildAndSign(t, dir, "vaigil.test", "2026.11.0")
	if err := os.WriteFile(filepath.Join(dir, TypeDetection,
		"vaigil.snuck-in.json"), []byte(testRule), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.verify(t, dir, time.Now().UTC())
	if err == nil {
		t.Fatal("a pack with an unlisted file verified")
	}
	if !strings.Contains(err.Error(), "vaigil.snuck-in.json") {
		t.Fatalf("the refusal must name the file, and said: %v", err)
	}
}

// TestManifestValidation: the claims a manifest makes about itself.
func TestManifestValidation(t *testing.T) {
	base := Manifest{ID: "vaigil.test", Version: "1.2.3", Channel: Stable,
		Files: []File{{Path: "detections/a.json", Type: TypeDetection,
			SHA256: strings.Repeat("a", 64), Size: 10}}}
	cases := []struct {
		name string
		mut  func(*Manifest)
		want string
	}{
		{"bad id", func(m *Manifest) { m.ID = "Vaigil Test!" }, "pack id"},
		{"bad version", func(m *Manifest) { m.Version = "november" }, "version"},
		{"bad channel", func(m *Manifest) { m.Channel = "nightly" }, "channel"},
		{"traversal", func(m *Manifest) {
			m.Files[0].Path = "detections/../../../etc/passwd"
		}, "not"},
		{"wrong type for path", func(m *Manifest) {
			m.Files[0].Path = "sources/a.json"
		}, "detections/*.json"},
		{"bad digest", func(m *Manifest) { m.Files[0].SHA256 = "xyz" }, "sha256"},
		{"no files", func(m *Manifest) { m.Files = nil }, "no files"},
		{"duplicate", func(m *Manifest) {
			m.Files = append(m.Files, m.Files[0])
		}, "twice"},
	}
	for _, c := range cases {
		// A fresh copy each time, files and all: `m := base` would share
		// the slice's backing array, and one case's mutation would leak
		// into the next — which is how "bad digest" came to report a path
		// a earlier case had set.
		m := base
		m.Files = append([]File(nil), base.Files...)
		c.mut(&m)
		err := m.Validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, wanted the refusal to mention %q", c.name,
				err, c.want)
		}
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("the base manifest is valid: %v", err)
	}
}

// TestVersionsOrder: the comparison the manifest floor and the listing
// rely on.
func TestVersionsOrder(t *testing.T) {
	a, _ := ParseVersion("2026.11.0")
	b, _ := ParseVersion("2026.11.1")
	c, _ := ParseVersion("2026.12.0")
	d, _ := ParseVersion("2027.1.0")
	if CompareVersions(a, b) >= 0 || CompareVersions(b, c) >= 0 ||
		CompareVersions(c, d) >= 0 {
		t.Fatal("version ordering is wrong")
	}
	e, _ := ParseVersion("2026.11.0")
	if CompareVersions(a, e) != 0 {
		t.Fatal("equal versions do not compare equal")
	}
	for _, bad := range []string{"1.2", "1.2.x", "1.2.3.4", "1"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Errorf("%q parsed as a version", bad)
		}
	}
}

// TestMinimumBinaryFloor: a pack written for a newer binary refuses whole.
func TestMinimumBinaryFloor(t *testing.T) {
	s := keygenStore(t)
	dir := writePack(t, testRule)
	p, err := Build(dir, BuildOptions{ID: "vaigil.test", Version: "2026.11.0",
		Channel: Stable, MinBinary: "0.10.0"})
	if err != nil {
		t.Fatal(err)
	}
	release, err := LoadReleaseKey(s.root)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := LoadAnchor(s.root)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignPack(dir, p, release, anchor, 1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	_, err = s.verify(t, dir, time.Now().UTC()) // the helper says this binary is 0.9.0
	if err == nil {
		t.Fatal("a pack needing a newer binary verified on an older one")
	}
	if !strings.Contains(err.Error(), "minimum binary version") {
		t.Fatalf("the refusal must name the floor, and said: %v", err)
	}
}

// TestWrongAnchorRefused: a pack from a different producer — correct
// signatures under the wrong key — refuses at the first check.
func TestWrongAnchorRefused(t *testing.T) {
	s := keygenStore(t)
	dir := writePack(t, testRule)
	s.buildAndSign(t, dir, "vaigil.test", "2026.11.0")

	other := keygenStore(t)
	_, err := other.verify(t, dir, time.Now().UTC())
	if err == nil {
		t.Fatal("a pack signed by one store verified against another's anchor")
	}
	if !strings.Contains(err.Error(), "root.json signature") {
		t.Fatalf("the refusal must name the root signature, and said: %v", err)
	}
}

// TestNoAnchorRefused: with no anchor there is nothing to verify against,
// and Verify says so rather than trusting the pack's own root.
func TestNoAnchorRefused(t *testing.T) {
	dir := writePack(t, testRule)
	if _, err := Verify(dir, VerifyOptions{Now: time.Now().UTC(),
		BinaryVersion: "0.9.0"}); err == nil ||
		!strings.Contains(err.Error(), "root of trust") {
		t.Fatalf("a pack verified with no anchor: %v", err)
	}
}

// The shadow replay: the gate between verification and placement, measured
// against a spool of real telemetry shape rather than asserted on its own
// arithmetic. Every test below seeds events the way the estate would have
// stored them (arrival stamped, sealed) and asks what the gate would have
// said, so the numbers refused and reported are the numbers a store of those
// events actually produces.

// shadowFailure is one okta/system failed sign-in by an admin — the shape
// testRule and testRuleTuned are written for. Arrived two seconds after it
// happened, the way a live source delivers.
func shadowFailure(who string, at time.Time) telemetry.Event {
	return telemetry.Event{
		Source: "okta/system", Class: telemetry.ClassAuthentication,
		Disposition: telemetry.DispositionFailed,
		Actor:       telemetry.ID{Issuer: "okta", Value: who},
		Message:     "sign-in", Time: at, Received: at.Add(2 * time.Second),
	}
}

// shadowFailures is n failures by one account, span apart from start.
func shadowFailures(who string, start time.Time, n int,
	span time.Duration) []telemetry.Event {

	out := make([]telemetry.Event, n)
	for i := range out {
		out[i] = shadowFailure(who, start.Add(time.Duration(i)*span))
	}
	return out
}

// shadowWindow is the start of a fifteen-minute correlation window that
// closed well before now, so the watermark has passed it — the same shape
// detectcorrelate_test.go's closedWindow gives the live run.
func shadowWindow() time.Time {
	return time.Now().UTC().Add(-3 * time.Hour).Truncate(15 * time.Minute)
}

// seededSpool writes events into a spool under dir, seals it, and returns
// the handle the gate would be given: the store as a live one presents it.
func seededSpool(t *testing.T, dir string,
	events ...telemetry.Event) *spool.Spool {

	t.Helper()
	sp, err := spool.Open(dir, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if _, err := sp.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	sealed, err := spool.Open(dir, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

// shadowRow finds one id's row in a result.
func shadowRow(t *testing.T, res *ShadowResult, id string) ShadowCount {
	t.Helper()
	for _, rows := range [][]ShadowCount{res.Rules, res.Correlations} {
		for _, c := range rows {
			if c.ID == id {
				return c
			}
		}
	}
	t.Fatalf("no row for %s in the shadow result", id)
	return ShadowCount{}
}

// TestShadowRefusesAFloodNamingCountsWindowAndFlags: thirty would-be
// findings from one rule over a quiet week is past the floor of twenty, and
// the refusal names the count, the window, the budget and the flag that
// overrides it — the operator who knows better must be told how to say so.
// The thirty failures sit inside one closed correlation window, so the
// correlation adds exactly one would-be finding and every number below is
// deterministic.
func TestShadowRefusesAFloodNamingCountsWindowAndFlags(t *testing.T) {
	s := keygenStore(t)
	dir := writePack(t, testRule)
	s.buildAndSign(t, dir, "vaigil.test", "2026.11.0")
	v, err := s.verify(t, dir, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	rules := t.TempDir()
	sp := seededSpool(t, t.TempDir(),
		shadowFailures("admin-dana", shadowWindow(), 30, 20*time.Second)...)

	res, err := Shadow(v, sp, ShadowOptions{Now: time.Now().UTC(),
		RulesDir: rules})
	if err != nil {
		t.Fatal(err)
	}
	if res.Held() {
		t.Fatal("a rule that would fire thirty times in a week this quiet " +
			"passed a floor of twenty")
	}
	row := shadowRow(t, res, "vaigil.test-privileged-failed")
	if row.Fired != 30 || row.Installed != 0 || row.Cap != 20 || !row.Over {
		t.Fatalf("the rule's row is %+v; want 30 fired, 0 installed, cap 20, "+
			"over", row)
	}
	corr := shadowRow(t, res, "corr.test-privileged-failures")
	if corr.Fired != 1 {
		t.Fatalf("the correlation counted %d window(s), want the one the "+
			"thirty failures fell in", corr.Fired)
	}
	if res.Total.Fired != 31 || res.Total.Over {
		t.Fatalf("the totals are %+v; the flood is one rule's, not the "+
			"pack's", res.Total)
	}
	refusal := strings.Join(res.Refused, " | ")
	if len(res.Refused) != 1 {
		t.Fatalf("%d refusal(s), want exactly the rule's:\n%s",
			len(res.Refused), refusal)
	}
	for _, want := range []string{"vaigil.test-privileged-failed",
		"would fire 30 time(s)", "over the last 7 day(s)",
		"the budget for it is", "--max-fires-per-rule"} {
		if !strings.Contains(refusal, want) {
			t.Errorf("the refusal must name %q, and said:\n%s", want, refusal)
		}
	}
	// Refused, so placed nothing: the rules directory the pack would have
	// installed into is exactly as it was.
	entries, derr := os.ReadDir(rules)
	if derr != nil {
		t.Fatal(derr)
	}
	if len(entries) != 0 {
		t.Fatalf("a refused pack placed %d file(s)", len(entries))
	}
}

// TestShadowOverrideIsAbsoluteNotAFloor: the same flood under an
// operator-named cap installs — the cap replaces the number, it does not
// raise a floor — and a cap the operator set LOWER than the default refuses
// a pack the defaults would have taken. The operator who knows better
// states the number, in either direction.
func TestShadowOverrideIsAbsoluteNotAFloor(t *testing.T) {
	s := keygenStore(t)
	dir := writePack(t, testRule)
	s.buildAndSign(t, dir, "vaigil.test", "2026.11.0")
	v, err := s.verify(t, dir, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	sp := seededSpool(t, t.TempDir(),
		shadowFailures("admin-dana", shadowWindow(), 30, 20*time.Second)...)

	res, err := Shadow(v, sp, ShadowOptions{Now: time.Now().UTC(),
		RulesDir: t.TempDir(), MaxPerRule: 40})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Held() {
		t.Fatalf("an operator who named forty was refused anyway: %v",
			res.Refused)
	}
	if row := shadowRow(t, res, "vaigil.test-privileged-failed"); row.Cap != 40 {
		t.Fatalf("the cap is %d, not the operator's 40", row.Cap)
	}
	if !res.OverDefaultBudget() {
		t.Fatal("the record must be able to say the defaults would have " +
			"refused this; that is what makes an override a decision")
	}

	// The same authority in the other direction: a total cap below the
	// pack's count refuses on the operator's own figure. Fifteen fires
	// twenty minutes apart — no correlation window reaches five — is a
	// pack the defaults would have taken, so the refusal is the
	// operator's and the record must not call it an override.
	quiet := seededSpool(t, t.TempDir(),
		shadowFailures("admin-dana", shadowWindow(), 15, 20*time.Minute)...)
	res, err = Shadow(v, quiet, ShadowOptions{Now: time.Now().UTC(),
		RulesDir: t.TempDir(), MaxTotal: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res.Held() {
		t.Fatal("a total cap of ten did not refuse a pack that would fire " +
			"fifteen times")
	}
	if res.Total.Cap != 10 {
		t.Fatalf("the total cap is %d, not the operator's 10", res.Total.Cap)
	}
	if res.OverDefaultBudget() {
		t.Fatal("a pack the defaults would have passed is recorded as over " +
			"them; the record names what let content in, never what the " +
			"defaults alone would have allowed")
	}
}

// TestShadowBudgetIsTheDeltaAgainstTheInstalledEquivalent: the budget is
// not a constant, it is a comparison — a rule replacing one that fired
// fifty times may fire up to a hundred and fifty, so two hundred refuses
// and sixty passes. Both sides are read over the same window from the same
// events, twenty minutes apart so no correlation window reaches its count
// and the rows are the rules' alone.
func TestShadowBudgetIsTheDeltaAgainstTheInstalledEquivalent(t *testing.T) {
	now := time.Now().UTC()
	// The installed rule is the tuned one: ops accounts only.
	rules := t.TempDir()
	if err := os.WriteFile(filepath.Join(rules,
		"vaigil.test-privileged-failed.json"), []byte(testRuleTuned),
		0o600); err != nil {
		t.Fatal(err)
	}
	// Fifty failures both rules catch, and as many more as the case wants
	// that only the broad replacement catches — spaced so that neither
	// side's correlation ever reaches five in a window.
	// back starts n events of 20 minutes each before now, so the batch
	// ends inside the window however large it is.
	back := func(n int) time.Time {
		return now.Add(-time.Duration(n+2) * 20 * time.Minute)
	}
	both := shadowFailures("admin-dana-ops", back(50), 50, 20*time.Minute)
	caseFor := func(t *testing.T, extra int, wantHeld bool) {
		t.Helper()
		// A fresh pack per case: the same pack id cannot verify twice at
		// one metadata version against a store that installed nothing, but
		// two stores can.
		cs := keygenStore(t)
		dir := writePack(t, testRule)
		cs.buildAndSign(t, dir, "vaigil.test", "2026.11.0")
		v, err := cs.verify(t, dir, now)
		if err != nil {
			t.Fatal(err)
		}
		// The fifty both catch, and `extra` failures only the broad
		// replacement catches.
		mine := append([]telemetry.Event{}, both...)
		mine = append(mine, shadowFailures("admin-dana", back(extra),
			extra, 20*time.Minute)...)
		sp := seededSpool(t, t.TempDir(), mine...)
		res, err := Shadow(v, sp, ShadowOptions{Now: now, RulesDir: rules})
		if err != nil {
			t.Fatal(err)
		}
		row := shadowRow(t, res, "vaigil.test-privileged-failed")
		wantFired := 50 + extra
		if row.Fired != wantFired || row.Installed != 50 {
			t.Fatalf("the row is %+v; want %d fired against the installed 50",
				row, wantFired)
		}
		if row.Cap != 150 {
			t.Fatalf("the cap is %d; three times the installed fifty is 150",
				row.Cap)
		}
		if res.Held() != wantHeld {
			t.Fatalf("%d fires against a budget of 150: held=%v, refusals %v",
				row.Fired, res.Held(), res.Refused)
		}
	}
	// Two hundred would fire where fifty did: three times louder than its
	// equivalent is a rewrite wearing the same id.
	caseFor(t, 150, false)
	// Sixty where fifty did: a tune, not a rewrite.
	caseFor(t, 10, true)
}

// TestShadowQuietPackPassesNotingTheUnexercised: a pack whose rules match
// nothing in the window passes — silence is not a refusal — and the result
// says the rules were unexercised by this estate's week, which is the
// honest thing to say about content nobody asked any question of.
func TestShadowQuietPackPassesNotingTheUnexercised(t *testing.T) {
	s := keygenStore(t)
	dir := writePack(t, testRule)
	s.buildAndSign(t, dir, "vaigil.test", "2026.11.0")
	v, err := s.verify(t, dir, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	// A week with traffic in it — from a source the rule does not read, so
	// the window is exercised and the rules are not.
	noise := make([]telemetry.Event, 5)
	for i := range noise {
		e := shadowFailure("admin-dana", shadowWindow().Add(
			time.Duration(i)*time.Minute))
		e.Source = "github/audit"
		noise[i] = e
	}
	sp := seededSpool(t, t.TempDir(), noise...)

	res, err := Shadow(v, sp, ShadowOptions{Now: time.Now().UTC(),
		RulesDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Held() {
		t.Fatalf("a pack that would fire nothing was refused: %v", res.Refused)
	}
	if res.Events != 5 {
		t.Fatalf("the window held %d event(s), not the five stored", res.Events)
	}
	if row := shadowRow(t, res, "vaigil.test-privileged-failed"); row.Fired != 0 {
		t.Fatalf("the rule counted %d on events it does not read", row.Fired)
	}
	if res.Unexercised != 1 {
		t.Fatalf("%d rule(s) unexercised, want the one the pack carries",
			res.Unexercised)
	}
	if res.Total.Fired != 0 {
		t.Fatalf("a quiet pack would fire %d time(s)", res.Total.Fired)
	}
}

// TestShadowCountsACorrelationTheQueueWouldSee: a quiet rule raises nothing
// itself — its loudness reaches the budget only through the correlation
// that counts it, exactly as it would live. Five failures in one closed
// window meet the correlation's condition once.
func TestShadowCountsACorrelationTheQueueWouldSee(t *testing.T) {
	s := keygenStore(t)
	dir := writePack(t, strings.Replace(testRule,
		`"sources": ["okta/system"],`, `"sources": ["okta/system"], "quiet": true,`, 1))
	s.buildAndSign(t, dir, "vaigil.test", "2026.11.0")
	v, err := s.verify(t, dir, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	sp := seededSpool(t, t.TempDir(),
		shadowFailures("admin-dana", shadowWindow(), 5, time.Minute)...)

	res, err := Shadow(v, sp, ShadowOptions{Now: time.Now().UTC(),
		RulesDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if row := shadowRow(t, res, "vaigil.test-privileged-failed"); row.Fired != 0 {
		t.Fatalf("a quiet rule would fire %d time(s) on its own", row.Fired)
	}
	corr := shadowRow(t, res, "corr.test-privileged-failures")
	if corr.Fired != 1 {
		t.Fatalf("the correlation would fire %d time(s), want the one window "+
			"five failures make", corr.Fired)
	}
	if res.Total.Fired != 1 {
		t.Fatalf("the queue would see %d finding(s), want the correlation's "+
			"one", res.Total.Fired)
	}
	// A quiet rule that matched is not unexercised — it was counted, just
	// not by itself.
	if res.Unexercised != 0 {
		t.Fatalf("%d rule(s) counted as unexercised; a quiet rule the "+
			"correlation counted is exercised", res.Unexercised)
	}
}

// TestShadowNeedsTheEstateTelemetry: the gate cannot run on a store with
// nothing in its window — an unexercised gate is a decorative one — and the
// refusal says so, naming the wider window and the flag that skips the
// gate. A store whose events are all older than the window is the same
// refusal: the week being asked about is empty either way.
func TestShadowNeedsTheEstateTelemetry(t *testing.T) {
	s := keygenStore(t)
	dir := writePack(t, testRule)
	s.buildAndSign(t, dir, "vaigil.test", "2026.11.0")
	v, err := s.verify(t, dir, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for name, events := range map[string][]telemetry.Event{
		"an empty store": nil,
		"a week with nothing in it": {shadowFailure("admin-dana",
			time.Now().UTC().Add(-30*24*time.Hour))},
	} {
		sp := seededSpool(t, t.TempDir(), events...)
		_, err := Shadow(v, sp, ShadowOptions{Now: time.Now().UTC(),
			RulesDir: t.TempDir()})
		if !errors.Is(err, ErrNoTelemetry) {
			t.Fatalf("%s: the gate must refuse rather than pass unexercised, "+
				"and said: %v", name, err)
		}
		for _, want := range []string{"--days", "--no-shadow"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the refusal must point at %q, and said: %v",
					name, want, err)
			}
		}
	}
}

// TestShadowRecordsNothingOnEitherOutcome: trial-ring semantics, held to.
// A refusing replay and a passing one must both leave the event store and
// the rules directory byte for byte as they were — no cursor, no finding,
// no suppression counter, nothing. The read-path sidecar indexes (the .idx
// cache the spool's own readers build) are derived data validated against
// the seal digest and are the live run's writes as much as this one's; they
// are the one thing allowed to appear.
func TestShadowRecordsNothingOnEitherOutcome(t *testing.T) {
	s := keygenStore(t)
	dir := writePack(t, testRule)
	s.buildAndSign(t, dir, "vaigil.test", "2026.11.0")
	v, err := s.verify(t, dir, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	spoolAt := t.TempDir()
	sp := seededSpool(t, spoolAt,
		shadowFailures("admin-dana", shadowWindow(), 30, 20*time.Second)...)
	rules := t.TempDir()

	// snapshot is every file under a directory by digest.
	snapshot := func(t *testing.T, root string) map[string]string {
		t.Helper()
		out := map[string]string{}
		err := filepath.WalkDir(root, func(p string, d os.DirEntry,
			err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			body, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			rel, _ := filepath.Rel(root, p)
			out[rel] = sha256Hex(body)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	compare := func(t *testing.T, name, root string, before map[string]string) {
		t.Helper()
		after := snapshot(t, root)
		for path, sum := range before {
			if after[path] != sum {
				t.Fatalf("%s: %s changed under the replay (%s → %s); the "+
					"gate that has not decided yet has no business leaving "+
					"marks", name, path, sum, after[path])
			}
		}
		for path := range after {
			if _, had := before[path]; !had && !strings.HasSuffix(path, ".idx") {
				t.Fatalf("%s: the replay left %s behind", name, path)
			}
		}
	}

	beforeSpool := snapshot(t, spoolAt)
	beforeRules := snapshot(t, rules)
	res, err := Shadow(v, sp, ShadowOptions{Now: time.Now().UTC(),
		RulesDir: rules})
	if err != nil {
		t.Fatal(err)
	}
	if res.Held() {
		t.Fatal("the flood was held; this test needs the refusing outcome")
	}
	compare(t, "refused", spoolAt, beforeSpool)
	compare(t, "refused", rules, beforeRules)

	// The passing outcome: the same replay under an operator's cap.
	res, err = Shadow(v, sp, ShadowOptions{Now: time.Now().UTC(),
		RulesDir: rules, MaxPerRule: 40})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Held() {
		t.Fatalf("the override did not hold: %v", res.Refused)
	}
	compare(t, "held", spoolAt, beforeSpool)
	compare(t, "held", rules, beforeRules)
}

// TestShadowRefusesAnInstallThatWouldBreakTheRun: a pack file landing on a
// path that held a different rule removes that rule, and an installed
// correlation naming it would refuse to start on the next `detect run`. The
// gate holds the run's own load-time check against the state the install
// would leave — by file, not by id, which is the one way this breaks.
func TestShadowRefusesAnInstallThatWouldBreakTheRun(t *testing.T) {
	s := keygenStore(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, TypeDetection), 0o700); err != nil {
		t.Fatal(err)
	}
	// The pack's x.json replaces the installed rule of the same file name
	// with one of a different id.
	if err := os.WriteFile(filepath.Join(dir, TypeDetection, "x.json"),
		[]byte(strings.Replace(testRule, "vaigil.test-privileged-failed",
			"vaigil.replacement", -1)), 0o600); err != nil {
		t.Fatal(err)
	}
	s.buildAndSign(t, dir, "vaigil.test", "2026.11.0")
	v, err := s.verify(t, dir, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	rules := t.TempDir()
	if err := os.WriteFile(filepath.Join(rules, "x.json"),
		[]byte(strings.Replace(testRule, "vaigil.test-privileged-failed",
			"vaigil.installed-rule", -1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rules, "keep.yml"),
		[]byte(strings.Replace(testCorrelation, "vaigil.test-privileged-failed",
			"vaigil.installed-rule", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	sp := seededSpool(t, t.TempDir(),
		shadowFailure("admin-dana", shadowWindow()))

	_, err = Shadow(v, sp, ShadowOptions{Now: time.Now().UTC(),
		RulesDir: rules})
	if err == nil {
		t.Fatal("a pack whose install strands an installed correlation was " +
			"replayed without a word")
	}
	for _, want := range []string{"vaigil.installed-rule", "survives this " +
		"install", "refuse to start"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must mention %q, and said: %v", want, err)
		}
	}
}

// TestInstallCarriesTheShadowRecord: the gate's verdict travels on the
// installed record — the window, the counts, and which of the three words
// it was — because "what did this estate's own week say before this
// content went live" is a question asked months later.
func TestInstallCarriesTheShadowRecord(t *testing.T) {
	s := keygenStore(t)
	dir := writePack(t, testRule)
	s.buildAndSign(t, dir, "vaigil.test", "2026.11.0")
	v, err := s.verify(t, dir, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	rules := t.TempDir()
	rec := &ShadowRecord{Days: 7, Events: 30, Fired: 31, Baseline: 0,
		Outcome: ShadowOverridden, Override: "--max-fires-per-rule 40"}
	if _, err := Install(v, s.root, rules, rec, OverridesRefuse); err != nil {
		t.Fatal(err)
	}
	st, err := LoadInstalled(s.root)
	if err != nil {
		t.Fatal(err)
	}
	got := st.Packs["vaigil.test"].Shadow
	if got == nil {
		t.Fatal("the installed record carries no shadow verdict; the gate " +
			"ran for nothing")
	}
	if *got != *rec {
		t.Fatalf("the record is %+v, want %+v", *got, *rec)
	}
	// A nil record (a caller that ran no gate, the tests' direct use)
	// leaves the field absent, not half-written.
	dir2 := writePack(t, testRuleTuned)
	s.buildAndSign(t, dir2, "vaigil.test", "2026.11.1")
	v2, err := s.verify(t, dir2, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Install(v2, s.root, rules, nil, OverridesRefuse); err != nil {
		t.Fatal(err)
	}
	st, err = LoadInstalled(s.root)
	if err != nil {
		t.Fatal(err)
	}
	if st.Packs["vaigil.test"].Shadow != nil {
		t.Fatalf("a nil record left %+v behind", st.Packs["vaigil.test"].Shadow)
	}
}

// testRuleLockedOut is the second half of an ordered sequence: the account
// the failures belonged to was locked out after them.
const testRuleLockedOut = `{
  "id": "vaigil.test-locked-out",
  "title": "A privileged account was locked out",
  "why": "the identity provider gave up on this account",
  "sources": ["okta/system"],
  "severity": 3,
  "quiet": true,
  "when": {"all": [
    {"match": {"field": "class", "op": "equals", "values": ["3002"]}},
    {"match": {"field": "disposition", "op": "equals", "values": ["blocked"]}}
  ]},
  "fixtures": [
    {"name": "locked out", "match": true, "event": {
      "source": "okta/system", "time": "2026-09-01T00:00:00Z",
      "received": "2026-09-01T00:00:01Z", "class": 3002, "disposition": 2,
      "actor": {"issuer": "okta", "value": "admin-dana"}}},
    {"name": "signed in", "match": false, "event": {
      "source": "okta/system", "time": "2026-09-01T00:00:00Z",
      "received": "2026-09-01T00:00:01Z", "class": 3002, "disposition": 1,
      "actor": {"issuer": "okta", "value": "admin-dana"}}}
  ]
}`

// testSequence is a correlation over two rules in order — the shape a
// single event cannot answer.
const testSequence = `title: Failures then lockout for one account
id: corr.test-sequence
correlation:
    type: temporal_ordered
    rules:
        - vaigil.test-privileged-failed
        - vaigil.test-locked-out
    group-by:
        - actor.value
    timespan: 15m
level: high
`

// TestShadowCountsAnOrderedSequence: the briefest correlation there is —
// two quiet rules, two events in order, one hit. The correlation engine
// runs in the replay exactly as it would live: both rules' matches fed to
// it, the window closed on the watermark, the sequence counted once, and
// nothing else counting at all.
func TestShadowCountsAnOrderedSequence(t *testing.T) {
	s := keygenStore(t)
	dir := t.TempDir()
	for sub, body := range map[string]string{
		TypeDetection + "/vaigil.test-privileged-failed.json": strings.Replace(testRule,
			`"sources": ["okta/system"],`, `"sources": ["okta/system"], "quiet": true,`, 1),
		TypeDetection + "/vaigil.test-locked-out.json": testRuleLockedOut,
		TypeCorrelation + "/seq.yml":                   testSequence,
	} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(sub)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, sub), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s.buildAndSign(t, dir, "vaigil.test", "2026.11.0")
	v, err := s.verify(t, dir, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	// Two events, in order, five minutes apart, in a window the watermark
	// has long passed: the failure and the lockout of the same account.
	w0 := shadowWindow()
	fail := shadowFailure("admin-dana", w0.Add(time.Minute))
	lockout := shadowFailure("admin-dana", w0.Add(6*time.Minute))
	lockout.Disposition = telemetry.DispositionBlocked
	sp := seededSpool(t, t.TempDir(), fail, lockout)

	res, err := Shadow(v, sp, ShadowOptions{Now: time.Now().UTC(),
		RulesDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	corr := shadowRow(t, res, "corr.test-sequence")
	if corr.Fired != 1 {
		t.Fatalf("the sequence would fire %d time(s), want the one the two "+
			"events make", corr.Fired)
	}
	for _, id := range []string{"vaigil.test-privileged-failed",
		"vaigil.test-locked-out"} {
		if row := shadowRow(t, res, id); row.Fired != 0 {
			t.Fatalf("the quiet %s would raise %d finding(s) of its own", id,
				row.Fired)
		}
	}
	if res.Total.Fired != 1 {
		t.Fatalf("the queue would see %d finding(s), want the sequence's one",
			res.Total.Fired)
	}
}

// TestRootRotationEndToEnd: the whole ceremony, from both sides of it. The
// producing store rotates — the old key signs the new root once, for
// continuity; the new key signs it as itself, the handover — a pack signed
// under the rotated chain verifies against the rotated anchor AND against
// the old anchor through the rotation, an installer one root behind
// follows with the apply, and the rotation never un-happens: the older
// root is a rollback wherever the newer one is anchored, and the file
// rollback does not touch the anchor at all.
func TestRootRotationEndToEnd(t *testing.T) {
	s := keygenStore(t)

	// A pack under root v1, signed before any rotation exists.
	v1pack := writePack(t, testRule)
	s.buildAndSign(t, v1pack, "vaigil.test", "2026.11.0")
	v1anchor, err := LoadAnchor(s.root)
	if err != nil {
		t.Fatal(err)
	}
	if v1anchor.Signed.Version != 1 {
		t.Fatalf("a fresh anchor is version %d, not 1", v1anchor.Signed.Version)
	}
	if _, err := s.verify(t, v1pack, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	// The ceremony: the offline key comes back for one act.
	nextKey := filepath.Join(t.TempDir(), "next-root.key")
	res, err := RotateStoreRoot(s.root, s.offline, nextKey, time.Now().UTC())
	if err != nil {
		t.Fatalf("the ceremony refused: %v", err)
	}
	if res.FromVersion != 1 || res.ToVersion != 2 {
		t.Fatalf("the rotation went %d to %d; a ceremony that could jump "+
			"versions would be a ceremony that could skip the chain's "+
			"continuity", res.FromVersion, res.ToVersion)
	}
	if fi, serr := os.Stat(nextKey); serr != nil ||
		fi.Mode().Perm() != 0o600 {
		t.Fatalf("the incoming root key is %v: a signing oracle left open",
			fi.Mode().Perm())
	}
	anchor, err := LoadAnchor(s.root)
	if err != nil {
		t.Fatal(err)
	}
	if anchor.Signed.Version != 2 || anchor.Previous == nil {
		t.Fatalf("the anchor did not move to a doubly-signed root: "+
			"version %d, previous %v", anchor.Signed.Version,
			anchor.Previous != nil)
	}

	// Packs signed by the new release chain verify after the rotation:
	// the store's own anchor is the rotated one, and the packs it signs
	// carry it.
	v2pack := writePack(t, testRuleTuned)
	s.buildAndSign(t, v2pack, "vaigil.test", "2026.11.1")
	carried, err := LoadRoot(v2pack)
	if err != nil || carried.Signed.Version != 2 {
		t.Fatalf("the pack does not carry the rotated root: %v", err)
	}
	v, err := s.verify(t, v2pack, time.Now().UTC())
	if err != nil {
		t.Fatalf("a pack signed under the rotated chain must verify: %v", err)
	}
	everyCheckPassed(t, v)

	// The OLD anchor verifies the rotated root too — this is the client
	// that missed the transition, walking continuity and handover both.
	walked, err := Verify(v2pack, VerifyOptions{Anchor: v1anchor,
		Installed: map[string]int{}, Now: time.Now().UTC(),
		BinaryVersion: "0.9.0"})
	if err != nil {
		t.Fatalf("the old anchor must walk the rotation on both "+
			"signatures: %v", err)
	}
	everyCheckPassed(t, walked)

	// An installer one root behind follows the rotation with the apply:
	// the anchor moves with the content, and the old key's continuity
	// power ends there.
	installer := t.TempDir()
	if err := os.MkdirAll(ContentDir(installer), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteRoot(TrustedRootPath(installer), v1anchor); err != nil {
		t.Fatal(err)
	}
	rules := t.TempDir()
	ires, err := Install(walked, installer, rules, nil, OverridesRefuse)
	if err != nil {
		t.Fatal(err)
	}
	if ires.RootFrom != 1 || ires.RootTo != 2 {
		t.Fatalf("the install did not follow the rotation: %+v", ires)
	}
	followed, err := LoadAnchor(installer)
	if err != nil || followed.Signed.Version != 2 {
		t.Fatalf("the installer's anchor did not follow the apply: %v", err)
	}

	// The rotation never un-happens. The v1-rooted pack refuses as a
	// rollback wherever version 2 is anchored...
	_, err = Verify(v1pack, VerifyOptions{Anchor: followed,
		Installed: map[string]int{}, Now: time.Now().UTC(),
		BinaryVersion: "0.9.0"})
	if err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("an older root must refuse as a rollback, and said: %v", err)
	}
	// ...and the file rollback restores content without touching the
	// anchor — root versions never move down, not by any door.
	if _, err := Rollback(installer, rules); err != nil {
		t.Fatal(err)
	}
	if after, aerr := LoadAnchor(installer); aerr != nil ||
		after.Signed.Version != 2 {
		t.Fatalf("the file rollback moved the root version: %v", aerr)
	}
}

// TestRotationRefusals: the ways a rotation-shaped thing is not a
// rotation. A new root that drops the old key's signature mid-chain
// refuses on continuity; a root that skips a version refuses because the
// chain walks one step at a time; and the ceremony itself refuses a key
// that is not the anchor's and an incoming-key path that already exists.
func TestRotationRefusals(t *testing.T) {
	s := keygenStore(t)
	v1pack := writePack(t, testRule)
	s.buildAndSign(t, v1pack, "vaigil.test", "2026.11.0")
	v1anchor, err := LoadAnchor(s.root)
	if err != nil {
		t.Fatal(err)
	}

	nextKey := filepath.Join(t.TempDir(), "next-root.key")
	if _, err := RotateStoreRoot(s.root, s.offline, nextKey,
		time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	v2pack := writePack(t, testRuleTuned)
	s.buildAndSign(t, v2pack, "vaigil.test", "2026.11.1")

	opts := VerifyOptions{Anchor: v1anchor, Installed: map[string]int{},
		Now: time.Now().UTC(), BinaryVersion: "0.9.0"}

	// A new root that drops the old signature mid-chain: strip Previous
	// from the pack's root.json. The root stays intact and self-signed;
	// continuity is the only thing missing, and it is the thing refused.
	rootAt := filepath.Join(v2pack, RootName)
	rotated, err := LoadRoot(v2pack)
	if err != nil {
		t.Fatal(err)
	}
	var sr SignedRoot
	body, err := os.ReadFile(rootAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &sr); err != nil {
		t.Fatal(err)
	}
	sr.Previous = nil
	stripped, err := json.Marshal(sr)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootAt, stripped, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Verify(v2pack, opts)
	if err == nil || !strings.Contains(err.Error(), "continuity") {
		t.Fatalf("a root that dropped the old key's signature must refuse "+
			"naming continuity, and said: %v", err)
	}
	if err := WriteRoot(rootAt, rotated); err != nil {
		t.Fatal(err)
	}

	// A root that skips a version: rotate again under the incoming key,
	// sign, and hand the v3 pack to a store still anchored at v1.
	thirdKey := filepath.Join(t.TempDir(), "third-root.key")
	if _, err := RotateStoreRoot(s.root, nextKey, thirdKey,
		time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	v3pack := writePack(t, testRule)
	s.buildAndSign(t, v3pack, "vaigil.test", "2026.11.2")
	_, err = Verify(v3pack, opts)
	if err == nil || !strings.Contains(err.Error(), "one version at a time") {
		t.Fatalf("a skipped root version must refuse, and said: %v", err)
	}
	// And it verifies against the store that walked every step — which is
	// the point of walking one at a time.
	if _, err := s.verify(t, v3pack, time.Now().UTC()); err != nil {
		t.Fatalf("the store that followed the chain must accept v3: %v", err)
	}

	// The ceremony with a key that is not the anchor's root key: a
	// "rotation" no client's anchor can walk.
	foreign, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	foreignAt := filepath.Join(t.TempDir(), "foreign.key")
	if err := SaveKey(foreignAt, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = RotateStoreRoot(s.root, foreignAt,
		filepath.Join(t.TempDir(), "out.key"), time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "anchor names") {
		t.Fatalf("a rotation signed by a key the anchor does not name must "+
			"refuse, and said: %v", err)
	}

	// The incoming key path is written once, like keygen's outputs.
	_, err = RotateStoreRoot(s.root, thirdKey, foreignAt, time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("a rotation over an existing key file must refuse, and "+
			"said: %v", err)
	}
}

// The local-override gate: user edits win, recorded, shown. The three
// answers an install can give about a locally-edited pack file — refuse,
// keep, adopt — and the one thing that is not an override at all.

// overrideSite is a store with v1 of the pack installed and the rule file
// edited by hand afterwards: the situation every override test starts in.
// It returns the rules directory, the edited rule's path and body, and a
// maker for v2 directories whose correlation is tuned too, so "the pack's
// other files landed" is a claim about bytes rather than file counts.
func overrideSite(t *testing.T) (s *signedStore, rules, ruleAt,
	editedBody string, v2 func() string) {

	t.Helper()
	s = keygenStore(t)
	rules = t.TempDir()
	d1 := writePack(t, testRule)
	s.buildAndSign(t, d1, "vaigil.test", "2026.11.0")
	v1, err := s.verify(t, d1, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Install(v1, s.root, rules, nil, OverridesRefuse); err != nil {
		t.Fatal(err)
	}
	ruleAt = filepath.Join(rules, "vaigil.test-privileged-failed.json")
	editedBody = strings.Replace(testRule, "admin-dana", "admin-reshma", -1)
	if err := os.WriteFile(ruleAt, []byte(editedBody), 0o600); err != nil {
		t.Fatal(err)
	}
	tunedCorr := strings.Replace(testCorrelation, "gte: 5", "gte: 8", 1)
	v2 = func() string {
		d := writePack(t, testRuleTuned)
		if err := os.WriteFile(filepath.Join(d, TypeCorrelation, "test.yml"),
			[]byte(tunedCorr), 0o600); err != nil {
			t.Fatal(err)
		}
		return d
	}
	return s, rules, ruleAt, editedBody, v2
}

// overrideRel is the pack path of the rule file every override test edits.
const overrideRel = "detections/vaigil.test-privileged-failed.json"

// TestInstallRefusesALocallyEditedFile: the default answer to a local
// edit — stop, name the file, name the flags — with nothing moved.
func TestInstallRefusesALocallyEditedFile(t *testing.T) {
	s, rules, ruleAt, edited, v2 := overrideSite(t)

	d2 := v2()
	s.buildAndSign(t, d2, "vaigil.test", "2026.11.1")
	ver, err := s.verify(t, d2, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, err = Install(ver, s.root, rules, nil, OverridesRefuse)
	if !errors.Is(err, ErrLocalEdits) {
		t.Fatalf("an install over a local edit must refuse as the override "+
			"gate, and said: %v", err)
	}
	for _, want := range []string{overrideRel, "--keep-overrides",
		"--adopt-overrides"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name %q, and said:\n%v", want, err)
		}
	}
	// Refused before anything moved: the edit intact, the pack's v2 not
	// placed, the record still at v1.
	got, rerr := os.ReadFile(ruleAt)
	if rerr != nil || string(got) != edited {
		t.Fatal("a refused install touched the edit")
	}
	if strings.Contains(string(got), "narrowed to two failures") {
		t.Fatal("a refused install placed the pack's version")
	}
	st, lerr := LoadInstalled(s.root)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if st.Packs["vaigil.test"].Version != "2026.11.0" {
		t.Fatalf("a refused install moved the record: %+v",
			st.Packs["vaigil.test"])
	}
}

// TestKeepOverridesInstallsAroundTheEdit: --keep-overrides places the
// pack's other files, leaves the edit standing, records the divergence on
// the installed record with the baseline it will be compared against next
// time — the pack's last placed bytes, not the edit — and a rollback
// restores the previous set without touching the kept edit.
func TestKeepOverridesInstallsAroundTheEdit(t *testing.T) {
	s, rules, ruleAt, edited, v2 := overrideSite(t)

	d2 := v2()
	s.buildAndSign(t, d2, "vaigil.test", "2026.11.1")
	ver, err := s.verify(t, d2, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	res, err := Install(ver, s.root, rules, nil, OverridesKeep)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Kept) != 1 || res.Kept[0] != overrideRel ||
		res.Written != len(ver.Manifest.Files)-1 {
		t.Fatalf("the install did not keep exactly the edit: %+v", res)
	}
	// The edit stands; the pack's other file landed around it.
	got, rerr := os.ReadFile(ruleAt)
	if rerr != nil || string(got) != edited {
		t.Fatal("the kept override was replaced")
	}
	if got, rerr = os.ReadFile(filepath.Join(rules, "test.yml")); rerr != nil ||
		!strings.Contains(string(got), "gte: 8") {
		t.Fatal("the pack's other files did not land around the edit")
	}
	// The record shows the kept override, and the baseline for the kept
	// path is still what the pack LAST placed — the edit must not quietly
	// become the version of record.
	st, lerr := LoadInstalled(s.root)
	if lerr != nil {
		t.Fatal(lerr)
	}
	rec := st.Packs["vaigil.test"]
	if len(rec.Overrides) != 1 || rec.Overrides[0] != overrideRel {
		t.Fatalf("the record does not show the kept override: %+v", rec)
	}
	if rec.Placed[overrideRel] != sha256Hex([]byte(testRule)) {
		t.Fatalf("the baseline for the kept path is %s, want the digest of "+
			"what the pack last placed there", rec.Placed[overrideRel])
	}
	if rec.Placed["correlations/test.yml"] != sha256Hex(got) {
		t.Fatal("the baseline for the placed path is not the pack's bytes")
	}

	// Rollback restores the previous set without touching the kept edit:
	// the correlation goes back to v1, the rule stays the organisation's,
	// and the record goes back to v1's — whose baseline still says the
	// edit is a divergence.
	if _, err := Rollback(s.root, rules); err != nil {
		t.Fatal(err)
	}
	if got, rerr = os.ReadFile(filepath.Join(rules, "test.yml")); rerr != nil ||
		!strings.Contains(string(got), "gte: 5") {
		t.Fatal("rollback did not restore the pack's previous correlation")
	}
	if got, rerr = os.ReadFile(ruleAt); rerr != nil || string(got) != edited {
		t.Fatal("rollback clobbered the override the install kept")
	}
	st, lerr = LoadInstalled(s.root)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if back := st.Packs["vaigil.test"]; back.Version != "2026.11.0" ||
		len(back.Overrides) != 0 {
		t.Fatalf("the record did not move back to v1's: %+v", back)
	}

	// Which means the edit is still the person's decision: the next
	// install asks again.
	d3 := v2()
	s.buildAndSign(t, d3, "vaigil.test", "2026.11.2")
	ver3, err := s.verify(t, d3, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Install(ver3, s.root, rules, nil, OverridesRefuse); !errors.Is(err, ErrLocalEdits) {
		t.Fatalf("a kept override must still be a decision the next "+
			"install asks for, and said: %v", err)
	}
}

// TestAdoptOverridesTakesThePacksVersion: --adopt-overrides places the
// pack's file over the edit, the divergence ends — no override on the
// record, the baseline moved to the pack's bytes — and the next install
// of the same content asks nothing.
func TestAdoptOverridesTakesThePacksVersion(t *testing.T) {
	s, rules, ruleAt, _, v2 := overrideSite(t)

	d2 := v2()
	s.buildAndSign(t, d2, "vaigil.test", "2026.11.1")
	ver, err := s.verify(t, d2, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	res, err := Install(ver, s.root, rules, nil, OverridesAdopt)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Adopted) != 1 || res.Adopted[0] != overrideRel ||
		res.Written != len(ver.Manifest.Files) {
		t.Fatalf("the adoption did not name the edit it replaced: %+v", res)
	}
	if got, rerr := os.ReadFile(ruleAt); rerr != nil ||
		string(got) != testRuleTuned {
		t.Fatal("the pack's version did not replace the edit")
	}
	st, lerr := LoadInstalled(s.root)
	if lerr != nil {
		t.Fatal(lerr)
	}
	rec := st.Packs["vaigil.test"]
	if len(rec.Overrides) != 0 {
		t.Fatalf("an adopted override lingers on the record: %+v", rec)
	}
	if rec.Placed[overrideRel] != sha256Hex([]byte(testRuleTuned)) {
		t.Fatal("the baseline is not the adopted bytes; the next install " +
			"would ask about a divergence that is resolved")
	}

	// Resolved is resolved: the same content installs again without a
	// flag and without a word.
	d3 := v2()
	s.buildAndSign(t, d3, "vaigil.test", "2026.11.2")
	ver3, err := s.verify(t, d3, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	res3, err := Install(ver3, s.root, rules, nil, OverridesRefuse)
	if err != nil {
		t.Fatalf("a resolved divergence must not ask again: %v", err)
	}
	if len(res3.Kept) != 0 || len(res3.Adopted) != 0 {
		t.Fatalf("the install treated a resolved file as an override: %+v", res3)
	}
}

// TestAFreshFileIsNotAnOverride: the gate compares against the pack's own
// baseline and nothing else. A file the pack adds over empty space is no
// override question, and a file sitting where this pack never placed one
// is placed over as phase one placed it — an override is a divergence from
// the pack's own last word or it is nothing.
func TestAFreshFileIsNotAnOverride(t *testing.T) {
	s := keygenStore(t)
	rules := t.TempDir()

	d1 := writePack(t, testRule)
	s.buildAndSign(t, d1, "vaigil.test", "2026.11.0")
	v1, err := s.verify(t, d1, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Install(v1, s.root, rules, nil, OverridesRefuse); err != nil {
		t.Fatal(err)
	}

	// v2 carries a second rule — the locked-out rule, un-quieted — and
	// before it lands, a hand-written file already sits at the path it
	// will claim. Neither that path nor the empty one beside it has a
	// baseline: v1 never placed either.
	second := strings.Replace(testRuleLockedOut, `"quiet": true,`, "", 1)
	d2 := writePack(t, testRuleTuned)
	if err := os.WriteFile(filepath.Join(d2, TypeDetection,
		"vaigil.test-locked-out.json"), []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}
	s.buildAndSign(t, d2, "vaigil.test", "2026.11.1")
	ver, err := s.verify(t, d2, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	squatter := strings.Replace(second, "admin-dana", "admin-hippolyta", -1)
	if err := os.WriteFile(filepath.Join(rules, "vaigil.test-locked-out.json"),
		[]byte(squatter), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Install(ver, s.root, rules, nil, OverridesRefuse)
	if err != nil {
		t.Fatalf("a pack adding a file is not an override question, and "+
			"said: %v", err)
	}
	if len(res.Kept) != 0 || len(res.Adopted) != 0 {
		t.Fatalf("a fresh file was treated as an override: %+v", res)
	}
	// Both of v2's rules landed, and the hand-written squatter was
	// replaced by the pack's version — the phase-one rule, unchanged, for
	// a file the pack never placed.
	for _, name := range []string{"vaigil.test-privileged-failed.json",
		"vaigil.test-locked-out.json"} {
		if got, rerr := os.ReadFile(filepath.Join(rules, name)); rerr != nil ||
			strings.Contains(string(got), "hippolyta") {
			t.Fatalf("%s did not land as the pack's bytes", name)
		}
	}
}
