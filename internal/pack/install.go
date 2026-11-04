// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aeroprove/aeroprove/internal/atomicfile"
)

// Install, rollback and the state both read.
//
// Layout under the store (root/content/):
//
//	release.key    the online release key, seeds, 0600
//	root.json      the trusted anchor: this store's root of trust, at the
//	               highest root version this store has verified or rotated to
//	installed.json what is installed, per pack id, at which metadata version
//	               — carrying, per file, the baseline of what the pack last
//	               placed (the override comparison) and the overrides the
//	               install kept standing
//	produced.json  the producer's counter, per pack id — the signer's
//	               monotonic memory, kept beside the release key because
//	               they are only ever used together
//	prev/          the previous bytes of every path the last install touched
//	prev.json      what prev/ holds: those paths, and the installed record
//	               to restore to
//
// Content itself is not kept in a parallel tree: it is placed where the
// engines already read (the rules directory `aeroprove detect run` loads), as
// plain files, because the whole argument of the content plane is that it
// ships around files that already exist. A pack's files are the
// organisation's the moment they land, exactly like the starter pack's —
// which is why a file the organisation then edits is theirs to keep: the
// install compares every path it owns against the baseline of what it last
// placed, and an edited file stops the install until a person says which
// copy wins (user edits win, recorded, shown — the Sentinel Content Hub
// overwrite problem answered by construction).
//
// Installs are atomic per file (atomicfile: write-beside, fsync, rename)
// and pointer-last: the installed-state record moves only after every file
// is in place, so a crash mid-install leaves the previous set running and
// the store recording the previous version — stale-but-working, the
// internal/feed argument, and the reason nothing here holds a lock across
// the whole apply.

// Store layout.

// ContentDir is where a store keeps the content plane's own state.
func ContentDir(root string) string { return filepath.Join(root, "content") }

// ReleaseKeyPath is the online release key, 0600.
func ReleaseKeyPath(root string) string {
	return filepath.Join(ContentDir(root), "release.key")
}

// TrustedRootPath is the anchor. Public: nothing in it is secret.
func TrustedRootPath(root string) string {
	return filepath.Join(ContentDir(root), RootName)
}

// InstalledPath records what is installed.
func InstalledPath(root string) string {
	return filepath.Join(ContentDir(root), "installed.json")
}

// ProducedPath is the producer's per-pack counter.
func ProducedPath(root string) string {
	return filepath.Join(ContentDir(root), "produced.json")
}

// PrevDir holds the previous bytes of the paths the last install touched.
func PrevDir(root string) string { return filepath.Join(ContentDir(root), "prev") }

// PrevInfoPath records what prev/ holds.
func PrevInfoPath(root string) string {
	return filepath.Join(ContentDir(root), "prev.json")
}

// InstalledPack is one pack's installed record.
type InstalledPack struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	MetaVersion int    `json:"meta_version"`
	Channel     string `json:"channel"`
	Files       int    `json:"files"`
	InstalledAt string `json:"installed_at"`
	// Expires is the targets metadata's expiry date, kept so `content
	// installed` can report staleness — expiry refuses updates and never
	// disables content, and the one thing that must not happen is for the
	// expiry to pass silently.
	Expires string `json:"expires"`
	// Shadow is what the shadow gate measured when this version was let
	// in: the window, the counts, and whether the budget held, was
	// overridden by an operator, or never ran (--no-shadow). Kept on the
	// record because "what did the estate's own week say about this
	// content before it went live" is a question asked months later, by
	// somebody deciding whether to trust the next version.
	Shadow *ShadowRecord `json:"shadow,omitempty"`
	// Placed is the baseline: per pack path, the digest of what this pack
	// last placed there. The next install compares the rules directory
	// against it, and a file that differs has been edited locally — that
	// comparison, not the manifest's digest, is what the override decision
	// turns on. A path the install kept as an override keeps its OLD
	// baseline, so the edit is still an override next time rather than
	// quietly becoming the new normal.
	Placed map[string]string `json:"placed,omitempty"`
	// Overrides lists the paths this install kept as locally-edited: the
	// user's bytes are standing, the pack's version of them is not
	// installed, and the divergence stays on the record until a person
	// adopts the pack's version or the edit is reverted to it.
	Overrides []string `json:"overrides,omitempty"`
}

// The three words a ShadowRecord's Outcome may carry, named so no caller
// invents a fourth.
const (
	// ShadowHeld: the budget held on its computed defaults.
	ShadowHeld = "held"
	// ShadowOverridden: an operator-named budget let in content the
	// defaults would have refused.
	ShadowOverridden = "overridden"
	// ShadowSkipped: --no-shadow; the gate never ran.
	ShadowSkipped = "skipped"
)

// ShadowRecord is the gate's verdict, carried on the installed record.
type ShadowRecord struct {
	// Days is the window, Events how many the window held — the gate's
	// exercise, said plainly so a record from a two-event rehearsal is
	// never mistaken for one from a busy estate.
	Days   int `json:"days"`
	Events int `json:"events"`
	// Fired is what the pack would have fired over the window; Baseline
	// what the set it replaced would have fired.
	Fired    int `json:"fired"`
	Baseline int `json:"baseline"`
	// Outcome is "held" (the budget held), "overridden" (an operator
	// named a bigger budget) or "skipped" (--no-shadow; the flag's risk
	// is the flag's to own, on the record).
	Outcome string `json:"outcome"`
	// Override names the flag and number the operator used, when one was
	// used: the difference between a budget that held and one that was
	// argued with.
	Override string `json:"override,omitempty"`
}

// InstalledState is installed.json.
type InstalledState struct {
	Packs map[string]InstalledPack `json:"packs"`
}

// LoadInstalled reads the store's installed state. Absent is empty, not an
// error: a store that has never installed a pack is the starting condition.
func LoadInstalled(root string) (*InstalledState, error) {
	st := &InstalledState{Packs: map[string]InstalledPack{}}
	body, err := os.ReadFile(InstalledPath(root))
	if os.IsNotExist(err) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, st); err != nil {
		return nil, fmt.Errorf("%s is not readable: %w", InstalledPath(root), err)
	}
	if st.Packs == nil {
		st.Packs = map[string]InstalledPack{}
	}
	return st, nil
}

// saveInstalled writes the state back, atomically.
func saveInstalled(root string, st *InstalledState) error {
	body, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(InstalledPath(root), append(body, '\n'), 0o600)
}

// VersionMap is the installed metadata versions by pack id, for Verify's
// rollback check. The counters live here, in this store, not in anything a
// pack carries — which is the whole rollback defence: an old pack served
// again compares against this and refuses.
func (st *InstalledState) VersionMap() map[string]int {
	out := map[string]int{}
	for id, p := range st.Packs {
		out[id] = p.MetaVersion
	}
	return out
}

// StaleSince reports the installed targets expiry, for the staleness note.
// The boolean is whether it has passed. An expiry that cannot be parsed
// counts as stale: a date that cannot be read cannot be relied on.
func (p InstalledPack) StaleSince(now time.Time) (string, bool) {
	t, err := time.Parse(time.RFC3339, p.Expires)
	if err != nil {
		return p.Expires, true
	}
	return t.UTC().Format("2 Jan 2006"), !now.Before(t)
}

// ProducedState is produced.json: the last metadata version emitted per
// pack id. The signer's monotonic memory — re-signing at or below the last
// emitted version is refused, because monotonicity is a property of what
// was signed, not of what any installer happens to hold.
type ProducedState struct {
	Last map[string]int `json:"last"`
}

// LoadProduced reads the producer's counter.
func LoadProduced(root string) (*ProducedState, error) {
	ps := &ProducedState{Last: map[string]int{}}
	body, err := os.ReadFile(ProducedPath(root))
	if os.IsNotExist(err) {
		return ps, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, ps); err != nil {
		return nil, fmt.Errorf("%s is not readable: %w", ProducedPath(root), err)
	}
	if ps.Last == nil {
		ps.Last = map[string]int{}
	}
	return ps, nil
}

// NextVersion is the next metadata version for a pack id.
func (ps *ProducedState) NextVersion(id string) int { return ps.Last[id] + 1 }

// RecordEmitted notes a version as emitted and persists the counter.
func (ps *ProducedState) RecordEmitted(root, id string, version int) error {
	ps.Last[id] = version
	body, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(ProducedPath(root), append(body, '\n'), 0o600)
}

// prevFile is one path the previous set held.
type prevFile struct {
	SHA256 string `json:"sha256"`
}

// rulePath is where a pack file lands in the rules directory: its base
// name, flat. The pack's internal layout (detections/, correlations/)
// names what each file IS; the rules directory the engines already read
// holds the same flat shape the starter pack installs — rules beside
// correlations.yml — and both loaders walk it, so that is the shape this
// writes. Pack paths are type/basename by construction (the manifest
// enforces it), so the mapping is one-to-one.
func rulePath(packPath string) string { return filepath.Base(packPath) }

// prevInfo is prev.json. It records, for the paths the LAST install owned:
// what was there before (Files, with digests — possibly nothing for some
// paths, which is how an addition is told from a replacement), and the
// installed record to restore to (Prior, nil when the pack was not
// installed before — the first install, whose rollback uninstalls).
type prevInfo struct {
	Pack  string              `json:"pack"`
	Owned []string            `json:"owned"`
	Prior *InstalledPack      `json:"prior,omitempty"`
	Files map[string]prevFile `json:"files"`
}

// sorted copies of v's file paths.
func (v *Verified) ownedPaths() []string {
	out := make([]string, 0, len(v.Manifest.Files))
	for _, f := range v.Manifest.Files {
		out = append(out, f.Path)
	}
	sort.Strings(out)
	return out
}

// OverridesPolicy says what an install does when a file it would place
// over has been edited locally since the pack last placed it.
type OverridesPolicy int

const (
	// OverridesRefuse is the default: the install stops, naming the file
	// and the flags that proceed. An update must never clobber a customer
	// modification, and it must never silently leave one behind either —
	// stopping is the only answer that is neither.
	OverridesRefuse OverridesPolicy = iota
	// OverridesKeep installs around the edit: the pack's other files
	// land, the edited file stays as this organisation left it, and the
	// divergence is recorded on the installed record.
	OverridesKeep
	// OverridesAdopt takes the pack's version, replacing the edit — on
	// the record, because discarding somebody's edit silently is the
	// Sentinel failure with the serial numbers filed off.
	OverridesAdopt
)

// ErrLocalEdits is the refusal an install makes when the pack would
// overwrite files edited locally since the pack last placed them. A
// sentinel so the command surface can answer it as a gate's decision
// rather than a breakage, the way the shadow gate's refusals are answered.
var ErrLocalEdits = errors.New("the pack would overwrite locally-edited " +
	"files")

// InstallResult is what an install did, for the record and the audit entry.
type InstallResult struct {
	// Written is files placed into the rules directory.
	Written int
	// Replaced is files that were already there and are now in prev/.
	Replaced int
	// Kept is the locally-edited files the install left standing
	// (--keep-overrides): this organisation's bytes, not the pack's, and
	// the divergence is on the installed record.
	Kept []string
	// Adopted is the locally-edited files whose pack version replaced the
	// edit (--adopt-overrides): a decision to throw an edit away, which
	// is exactly the decision nobody should be able to make silently.
	Adopted []string
	// RootFrom and RootTo say when the pack carried a root rotation this
	// store followed: the anchor's version before and after, zero when it
	// did not. Root versions never move down — not here, not anywhere.
	RootFrom, RootTo int
	// Pack and Version echo the pack, for convenience.
	Pack    string
	Version string
}

// locallyEdited names the pack-owned paths that are on disk and differ
// from what the pack last placed there — the Placed baseline the previous
// install of this pack recorded. A path with no baseline is never an
// override: the pack has never placed a version of it, so whatever sits
// there was put by something else (the starter set, a person, another
// pack), and the phase-one rule this keeps applies — the pack owns its
// namespace and places its files. A baseline path that is GONE is not an
// override either: a deletion has no bytes to keep, and the pack placing
// its file again is the loudest way one can be answered.
func locallyEdited(rulesDir string, owned []string,
	baseline map[string]string) []string {

	if len(baseline) == 0 {
		return nil
	}
	var edited []string
	for _, rel := range owned {
		want, recorded := baseline[rel]
		if !recorded {
			continue
		}
		body, err := os.ReadFile(filepath.Join(rulesDir, rulePath(rel)))
		if err != nil {
			continue
		}
		if sha256Hex(body) != want {
			edited = append(edited, rel)
		}
	}
	return edited
}

// Install places a verified pack's content files into rulesDir, keeping the
// previous set under prev/ for rollback. Call it only with a pack Verify
// accepted — this function does not re-verify, because the gate's
// trustworthiness rests on running once, in order, before anything is
// written.
//
// shadow is the gate's verdict to carry on the installed record: held,
// overridden or skipped, with the numbers. Nil leaves no shadow record —
// for callers that have run no gate, which is the tests' direct use; the
// command surface never installs without recording one of the three words.
//
// overrides says what to do about a locally-edited pack file (see
// OverridesPolicy). The comparison happens before anything is written, so
// a refusal leaves the rules directory, the rollback point and the record
// exactly as they were.
//
// Files the pack does not own are never touched: anything else in the rules
// directory (the starter pack's rules, an organisation's own) is left
// alone — an update cannot clobber what it does not own, and with the
// override gate it cannot clobber what it does own and this organisation
// has edited either.
func Install(v *Verified, root, rulesDir string, shadow *ShadowRecord,
	overrides OverridesPolicy) (*InstallResult, error) {

	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		return nil, err
	}
	st, err := LoadInstalled(root)
	if err != nil {
		return nil, err
	}
	prior, had := st.Packs[v.Manifest.ID]
	owned := v.ownedPaths()

	// The override gate, before anything is written: every path the pack
	// owns that is on disk and differs from what the pack last placed has
	// been edited here, and what happens to an edit is a person's
	// decision to make.
	edited := locallyEdited(rulesDir, owned, prior.Placed)
	var kept map[string]bool
	var adopted []string
	switch {
	case len(edited) == 0:
	case overrides == OverridesKeep:
		kept = make(map[string]bool, len(edited))
		for _, rel := range edited {
			kept[rel] = true
		}
	case overrides == OverridesAdopt:
		adopted = edited
	default:
		return nil, fmt.Errorf("%w:\n  - %s\nThese file(s) differ from what "+
			"%s last placed here, so they have been edited locally. User "+
			"edits win by default: --keep-overrides installs around the "+
			"edit(s) — yours stand, the pack's other files land — and "+
			"--adopt-overrides takes the pack's version(s) instead, on the "+
			"audit record",
			ErrLocalEdits, strings.Join(edited, "\n  - "), v.Manifest.ID)
	}

	// The rollback point: for every path this pack owns, the bytes that
	// are there now, if any; plus the record to restore to. prev/ always
	// describes the state immediately before the LAST install, so
	// rollback is one step however many installs have happened. A kept
	// override's bytes are what is there, so they are what rollback
	// restores — undoing an install that kept an edit cannot clobber the
	// edit either.
	prev := prevInfo{Pack: v.Manifest.ID, Owned: owned,
		Files: map[string]prevFile{}}
	if had {
		prev.Prior = &prior
	}
	if err := os.RemoveAll(PrevDir(root)); err != nil {
		return nil, fmt.Errorf("clearing the rollback point: %w", err)
	}
	var replaced int
	for _, rel := range owned {
		body, rerr := os.ReadFile(filepath.Join(rulesDir, rulePath(rel)))
		if os.IsNotExist(rerr) {
			continue
		}
		if rerr != nil {
			return nil, rerr
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(PrevDir(root),
			filepath.FromSlash(rel))), 0o700); err != nil {
			return nil, err
		}
		if werr := atomicfile.Write(filepath.Join(PrevDir(root),
			filepath.FromSlash(rel)), body, 0o600); werr != nil {
			return nil, fmt.Errorf("keeping the rollback point: %w", werr)
		}
		prev.Files[rel] = prevFile{SHA256: sha256Hex(body)}
		replaced++
	}
	// prev.json, then the files, then the pointer: the order is the crash
	// story. A crash after prev.json but before the files leaves the old
	// set running with a rollback point that restores it — correct. A
	// crash after the files but before installed.json leaves the new
	// files running with the old state record, which the next install of
	// the same version refuses as a rollback — also correct, and loud.
	pbody, err := json.MarshalIndent(prev, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := atomicfile.Write(PrevInfoPath(root), append(pbody, '\n'), 0o600); err != nil {
		return nil, err
	}

	// Placement, and the new baseline with it: Placed records what THIS
	// install put on disk, except at a kept override, where the pack put
	// nothing and the baseline stays what the pack last placed — so the
	// edit remains a divergence at the next install instead of quietly
	// becoming the version of record.
	placed := map[string]string{}
	var written int
	for _, rel := range owned {
		body, rerr := os.ReadFile(filepath.Join(v.Dir, filepath.FromSlash(rel)))
		if rerr != nil {
			return nil, fmt.Errorf("reading %s back from the verified pack: %w",
				rel, rerr)
		}
		if !kept[rel] {
			if werr := atomicfile.Write(filepath.Join(rulesDir, rulePath(rel)),
				body, 0o600); werr != nil {
				return nil, fmt.Errorf("placing %s: %w", rel, werr)
			}
			placed[rel] = sha256Hex(body)
			written++
			continue
		}
		if old, was := prior.Placed[rel]; was {
			placed[rel] = old
		}
	}

	// A pack whose root is one version ahead of the anchor carries a
	// rotation Verify already walked (continuity and handover both
	// checked to get this far). The store follows it with the apply: the
	// anchor moves to the pack's root, the old root key's continuity
	// power ends here, and the root version never moves down. Trust that
	// follows content is the TUF client step; trust without content is
	// the producing store's own ceremony (RotateStoreRoot).
	rootFrom, rootTo := 0, 0
	if anchor, aerr := LoadAnchor(root); aerr != nil {
		return nil, fmt.Errorf("reading the anchor to follow a rotation: %w", aerr)
	} else if v.Root.Signed.Version > anchor.Signed.Version {
		if werr := WriteRoot(TrustedRootPath(root), &v.Root); werr != nil {
			return nil, fmt.Errorf("following the pack's root rotation: %w", werr)
		}
		rootFrom, rootTo = anchor.Signed.Version, v.Root.Signed.Version
	}

	var keptList []string
	if len(kept) > 0 {
		keptList = edited
	}
	now := time.Now().UTC().Format(time.RFC3339)
	st.Packs[v.Manifest.ID] = InstalledPack{
		ID: v.Manifest.ID, Version: v.Manifest.Version,
		MetaVersion: v.Targets.Signed.Version,
		Channel:     string(v.Manifest.Channel), Files: written,
		InstalledAt: now, Expires: v.Targets.Signed.Expires,
		Shadow: shadow, Placed: placed, Overrides: keptList,
	}
	if err := saveInstalled(root, st); err != nil {
		return nil, err
	}
	return &InstallResult{Written: written, Replaced: replaced,
		Kept: keptList, Adopted: adopted,
		RootFrom: rootFrom, RootTo: rootTo,
		Pack: v.Manifest.ID, Version: v.Manifest.Version}, nil
}

// RollbackResult is what a rollback did.
type RollbackResult struct {
	// Restored is files written back from prev/.
	Restored int
	// Removed is files the last install added that the previous set
	// never had.
	Removed int
	// Pack names the pack the last install belonged to; Prior says what
	// was restored to, and is nil when a first install was undone.
	Pack  string
	Prior *InstalledPack
}

// Rollback restores the previous set: the paths prev/ holds go back to
// their recorded bytes, paths the last install added that the previous set
// never had are removed, and the installed state moves back to the record
// prev.json names. Nothing outside the paths the last install owned is
// touched — the starter pack's rules and the organisation's own files are
// not this plane's to snapshot or to restore.
//
// The set being left is itself copied into prev/, so a rollback is itself
// reversible: instant, one pointer move, and it never needs the network or
// the pack directory, because the previous bytes were kept.
func Rollback(root, rulesDir string) (*RollbackResult, error) {
	ibody, err := os.ReadFile(PrevInfoPath(root))
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("there is no rollback point in this store; " +
			"nothing has been installed over anything")
	}
	if err != nil {
		return nil, err
	}
	var prev prevInfo
	if err := json.Unmarshal(ibody, &prev); err != nil {
		return nil, fmt.Errorf("%s is not readable: %w", PrevInfoPath(root), err)
	}

	st, err := LoadInstalled(root)
	if err != nil {
		return nil, err
	}
	cur, installed := st.Packs[prev.Pack]

	// Read before writing anything: the bytes being left (which become the
	// new rollback point) and the bytes being restored are both under
	// prev/ or rulesDir, and rewriting prev/ before the old copy is read
	// would destroy the very thing being restored.
	// leaving is what the rules directory holds now, for the owned paths.
	leaving := map[string][]byte{}
	if installed {
		for _, rel := range prev.Owned {
			body, rerr := os.ReadFile(filepath.Join(rulesDir, rulePath(rel)))
			if os.IsNotExist(rerr) {
				continue
			}
			if rerr != nil {
				return nil, rerr
			}
			leaving[rel] = body
		}
	}
	// restoring is what prev/ holds, digest-checked on the way in — a
	// rollback point that has been tampered with is refused rather than
	// restored, because "restore" is exactly the verb an attacker wants.
	restoring := map[string][]byte{}
	for rel, before := range prev.Files {
		body, rerr := os.ReadFile(filepath.Join(PrevDir(root), filepath.FromSlash(rel)))
		if rerr != nil {
			return nil, fmt.Errorf("the rollback point is missing %s: %w", rel, rerr)
		}
		if sha256Hex(body) != before.SHA256 {
			return nil, fmt.Errorf("the rollback point's copy of %s does not "+
				"match its recorded digest; restoring a tampered rollback "+
				"is worse than not restoring", rel)
		}
		restoring[rel] = body
	}

	// The reversibility snapshot: the bytes being left become the new
	// rollback point, so undoing the undo is one command too.
	if installed {
		if err := os.RemoveAll(PrevDir(root)); err != nil {
			return nil, err
		}
		newPrev := prevInfo{Pack: prev.Pack, Owned: prev.Owned,
			Prior: &cur, Files: map[string]prevFile{}}
		for rel, body := range leaving {
			if err := os.MkdirAll(filepath.Dir(filepath.Join(PrevDir(root),
				filepath.FromSlash(rel))), 0o700); err != nil {
				return nil, err
			}
			if werr := atomicfile.Write(filepath.Join(PrevDir(root),
				filepath.FromSlash(rel)), body, 0o600); werr != nil {
				return nil, werr
			}
			newPrev.Files[rel] = prevFile{SHA256: sha256Hex(body)}
		}
		nb, merr := json.MarshalIndent(newPrev, "", "  ")
		if merr != nil {
			return nil, merr
		}
		if werr := atomicfile.Write(PrevInfoPath(root), append(nb, '\n'), 0o600); werr != nil {
			return nil, werr
		}
	}

	// Restore: the recorded bytes back, additions removed.
	var restored, removed int
	for _, rel := range prev.Owned {
		dest := filepath.Join(rulesDir, rulePath(rel))
		body, had := restoring[rel]
		if !had {
			// The previous set never had this path: it is an addition of
			// the install being undone, so it goes.
			if rerr := os.Remove(dest); rerr != nil && !os.IsNotExist(rerr) {
				return nil, rerr
			}
			removed++
			continue
		}
		if werr := atomicfile.Write(dest, body, 0o600); werr != nil {
			return nil, fmt.Errorf("restoring %s: %w", rel, werr)
		}
		restored++
	}

	// The state pointer, last — the same pointer-last rule as install.
	if prev.Prior != nil {
		restored := *prev.Prior
		restored.InstalledAt = time.Now().UTC().Format(time.RFC3339)
		st.Packs[prev.Pack] = restored
	} else {
		delete(st.Packs, prev.Pack)
	}
	if err := saveInstalled(root, st); err != nil {
		return nil, err
	}
	return &RollbackResult{Restored: restored, Removed: removed,
		Pack: prev.Pack, Prior: prev.Prior}, nil
}
