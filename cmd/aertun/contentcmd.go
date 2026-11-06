// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/out"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/spool"
)

// The signed content plane: detections delivered as data, on their own
// cadence, without a binary release.
//
// Everything here is file-to-file. A pack arrives as a directory — copied,
// mailed, carried on a stick — and nothing is trusted because of how it
// arrived: trust is in two signatures (Ed25519 and ML-DSA-65, both
// required, per internal/audit/sign.go's discipline) over a small TUF-shaped
// chain of metadata that pins the pack's exact bytes. Verification is the
// first gate: `content install` runs every check first and refuses with the
// failed check named. The second gate is the customer's own, and no producer
// can run it for them: the shadow replay, which asks the pack's rules and
// correlations over the last week of this estate's stored telemetry what
// they would have raised, and refuses a pack the false-positive budget says
// would flood the queue. Only after both does anything land where `aertun
// detect run` already reads it. There is no network anywhere, because the
// transport was never the trust.
//
// Trust itself can be renewed without a binary release: `rotate-root` is
// the TUF rotation ceremony, a new root signed by both the outgoing and the
// incoming offline keys. And what lands is the organisation's the moment it
// lands: an install that would overwrite a locally-edited pack file stops
// and asks, because user edits win — recorded, shown, never clobbered and
// never silently left behind.
//
// What this deliberately does not have yet, with the reasons, is written in
// internal/pack's package comment: the trial-ring bake after an apply and
// the automatic rollback on a budget breach measured on live traffic (the
// replay before an apply and its budget are here; so is manual rollback),
// channels beyond the pinned field, the marketplace, and binary
// self-update.

func contentUsage() error {
	return fmt.Errorf("usage: aertun content keygen [--out FILE] | " +
		"rotate-root --old-root-key FILE --new-root-key FILE | " +
		"sign DIR --id ID --version V | verify DIR | install DIR " +
		"[--rules DIR] [--days N] [--max-fires-per-rule N] " +
		"[--max-total-fires N] [--no-shadow] " +
		"[--keep-overrides|--adopt-overrides] | list [DIR] | installed | " +
		"rollback")
}

// cmdContent is the content plane's command surface.
func cmdContent(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"installed"}
	}
	switch args[0] {
	case "keygen":
		return contentKeygen(root, args[1:])
	case "rotate-root":
		return contentRotateRoot(root, args[1:])
	case "sign":
		return contentSign(root, args[1:])
	case "verify":
		return contentVerify(root, args[1:])
	case "install":
		return contentInstall(root, args[1:])
	case "list":
		return contentList(root, args[1:])
	case "installed":
		return contentInstalled(root, args[1:])
	case "rollback":
		return contentRollback(root, args[1:])
	}
	return contentUsage()
}

// contentKeygen makes the two halves of the trust split: an offline root
// key written where the operator said (and must move away), and the online
// release key the store keeps, 0600. The root key signs exactly one thing
// per store — root.json, the anchor — and the release key signs every pack.
func contentKeygen(root string, args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "aertun-content-root.key",
		"where to write the offline root key (move it away afterwards)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	// Key material: the same weight as issuing tokens. Whoever could re-run
	// keygen could re-anchor trust for every pack this store verifies.
	if err := authorise(root, caller, auth.ActToken, "/"); err != nil {
		return err
	}
	res, err := pack.Keygen(root, *out, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := recordE(root, caller.auditRecord("content.keygen", "/content",
		audit.Success, map[string]string{
			// Fingerprints, not keys: the guard on detail keys refuses a
			// name that sounds like it carries a secret, and rightly —
			// these are the public halves' ids, named for what they are.
			"root_fingerprint":    res.RootKeyID,
			"release_fingerprint": res.ReleaseKeyID,
		})); err != nil {
		return err
	}
	if w.JSON(map[string]any{
		"root_key_path": res.RootKeyPath, "root_key_id": res.RootKeyID,
		"release_key_id": res.ReleaseKeyID, "anchor": res.AnchorPath,
	}) {
		return nil
	}
	w.Human("%stwo keys made%s\n", bold, reset)
	w.Human("  offline root key %s%s%s  written to %s\n",
		bold, res.RootKeyID, reset, res.RootKeyPath)
	w.Human("  online release key %s%s%s  in the store, 0600\n",
		bold, res.ReleaseKeyID, reset)
	w.Human("\n  %smove %s away now%s — off this machine, backed up where\n"+
		"  the root key's seeds can be written down. It signs root.json and\n"+
		"  nothing else, and losing it makes the next key rotation a new\n"+
		"  trust anchor instead of a routine act\n", yellow, res.RootKeyPath, reset)
	w.Human("  %sthe fingerprints above are what an installer checks before\n"+
		"  trusting a pack from this store%s\n", dim, reset)
	return nil
}

// contentRotateRoot is the rotation ceremony: the operator brings the
// offline root key back for one act, a fresh root key is made where they
// say, and the store's anchor moves to version N+1 signed by both keys —
// the outgoing one for continuity, the incoming one for the handover. The
// same weight as keygen: token authority, on the whole store, because this
// is the other command that decides what this store will trust.
func contentRotateRoot(root string, args []string) error {
	var oldAt, newAt string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--old-root-key", "--new-root-key":
			if i+1 >= len(args) {
				return fmt.Errorf("%s needs a value", args[i])
			}
			if args[i] == "--old-root-key" {
				oldAt = args[i+1]
			} else {
				newAt = args[i+1]
			}
			i++
		default:
			return fmt.Errorf("%q is not an option here", args[i])
		}
	}
	if oldAt == "" || newAt == "" {
		return contentUsage()
	}
	caller := resolveCaller(root, flagToken)
	// Key material: re-anchoring trust is the same weight as issuing
	// tokens, exactly as keygen.
	if err := authorise(root, caller, auth.ActToken, "/"); err != nil {
		return err
	}
	res, err := pack.RotateStoreRoot(root, oldAt, newAt, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := recordE(root, caller.auditRecord("content.root-rotated",
		"/content", audit.Success, map[string]string{
			"from_version":     strconv.Itoa(res.FromVersion),
			"to_version":       strconv.Itoa(res.ToVersion),
			"from_fingerprint": res.FromKeyID,
			"to_fingerprint":   res.ToKeyID,
		})); err != nil {
		return err
	}
	if w.JSON(map[string]any{
		"from_version": res.FromVersion, "to_version": res.ToVersion,
		"from_fingerprint": res.FromKeyID, "to_fingerprint": res.ToKeyID,
		"new_key_path": res.NewKeyPath, "anchor": res.AnchorPath,
	}) {
		return nil
	}
	w.Human("%sroot rotated%s  version %d to %d\n", bold, reset,
		res.FromVersion, res.ToVersion)
	w.Human("  %soutgoing root %s%s  signed the new root once, for "+
		"continuity, and retires here\n", dim, res.FromKeyID, reset)
	w.Human("  %sincoming root %s%s  wrote to %s\n",
		dim, res.ToKeyID, reset, res.NewKeyPath)
	w.Human("  %sthe anchor at %s now trusts version %d, and every pack "+
		"signed from this store carries it. An installer one version "+
		"behind walks the rotation on the old key's signature%s\n",
		dim, res.AnchorPath, res.ToVersion, reset)
	w.Human("\n  %smove %s away now%s — off this machine, backed up where\n"+
		"  the seeds can be written down, like the keygen key before it.\n"+
		"  It signs root.json and nothing else, and the next rotation "+
		"needs it\n", yellow, res.NewKeyPath, reset)
	w.Human("  %sdestroy the OLD root's seeds (%s) only after every "+
		"installer you serve has seen version %d; until then the old key "+
		"is still the continuity a store behind the rotation walks%s\n",
		yellow, oldAt, res.ToVersion, reset)
	return nil
}

// contentSign builds a pack's manifest from the content files in a
// directory and signs the metadata with the store's release key.
//
// The options are read by hand rather than through a flag set, because the
// natural order — `sign DIR --id ID --version V` — puts the directory
// first, and a flag set stops parsing at the first word that is not a
// flag, so every option after the directory would be taken for another
// positional and the command would demand usage. The same hand-reading
// inboundcmd.go does, for the same reason.
func contentSign(root string, args []string) error {
	var dir, id, version, channel, about, minBinary string
	channel = string(pack.Stable)
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--id", "--version", "--channel", "--about", "--min-binary":
			if i+1 >= len(args) {
				return fmt.Errorf("%s needs a value", args[i])
			}
			switch args[i] {
			case "--id":
				id = args[i+1]
			case "--version":
				version = args[i+1]
			case "--channel":
				channel = args[i+1]
			case "--about":
				about = args[i+1]
			case "--min-binary":
				minBinary = args[i+1]
			}
			i++
		default:
			if dir == "" && !strings.HasPrefix(args[i], "-") {
				dir = args[i]
				continue
			}
			return fmt.Errorf("%q is not an option here", args[i])
		}
	}
	if dir == "" || id == "" || version == "" {
		return contentUsage()
	}
	caller := resolveCaller(root, flagToken)
	// Producing content is the tune permission: the same authority as
	// editing a rule by hand, which is what this is a batch of.
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	release, err := pack.LoadReleaseKey(root)
	if err != nil {
		return fmt.Errorf("the store has no release key: %w\n"+
			"  aertun content keygen makes one, with the offline root beside it", err)
	}
	anchor, err := pack.LoadAnchor(root)
	if err != nil {
		return fmt.Errorf("the store has no trusted root: %w", err)
	}
	p, err := pack.Build(dir, pack.BuildOptions{
		ID: id, Version: version, Channel: pack.Channel(channel),
		About: about, MinBinary: minBinary,
	})
	if err != nil {
		return err
	}
	produced, err := pack.LoadProduced(root)
	if err != nil {
		return err
	}
	meta := produced.NextVersion(id)
	now := time.Now().UTC()
	if err := pack.SignPack(dir, p, release, anchor, meta, now); err != nil {
		return err
	}
	if err := produced.RecordEmitted(root, id, meta); err != nil {
		return err
	}
	if err := recordE(root, caller.auditRecord("content.signed", "/content",
		audit.Success, map[string]string{
			"pack": id, "version": version,
			"meta_version": strconv.Itoa(meta),
			"files":        strconv.Itoa(len(p.Manifest.Files)),
		})); err != nil {
		return err
	}
	rules, corrs := p.Counts()
	if w.JSON(map[string]any{
		"pack": id, "version": version, "meta_version": meta,
		"detections": rules, "correlation_files": corrs, "dir": dir,
	}) {
		return nil
	}
	w.Human("%s%s %s signed%s  metadata version %d\n",
		bold, id, version, reset, meta)
	w.Human("  %s%d rule(s) and %d correlation file(s), each digest pinned "+
		"in the manifest, the manifest pinned in targets.json, and the whole "+
		"chain double-signed%s\n", dim, rules, corrs, reset)
	w.Human("  %sinstall it elsewhere with the directory: aertun content "+
		"install %s%s\n", dim, dir, reset)
	return nil
}

// contentVerify runs every check, prints each, and names the first that
// fails. It installs nothing — the same walk install gates on, offered on
// its own because a pack someone handed you deserves an answer before any
// question of installing it.
func contentVerify(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: aertun content verify DIR")
	}
	v, err := verifyPack(root, args[0])
	if v != nil {
		printChecks(v.Checks)
	}
	if err != nil {
		// A gate refusing, not a command breaking.
		return errBlocked{err}
	}
	if w.JSON(map[string]any{
		"pack": v.Manifest.ID, "version": v.Manifest.Version,
		"meta_version": v.Targets.Signed.Version, "checks": v.Checks,
	}) {
		return nil
	}
	w.Human("%s%s %s verifies%s  every check, in order\n",
		green, v.Manifest.ID, v.Manifest.Version, reset)
	return nil
}

// printChecks shows the walk the way the audit log's verifier shows its
// chain: each check named, passed or not, with what it found. JSON callers
// get the same list as a field instead.
func printChecks(checks []pack.Check) {
	if w.Mode == out.JSON || len(checks) == 0 {
		return
	}
	for _, c := range checks {
		mark, colour := green+"ok  "+reset, green
		if !c.OK {
			mark, colour = red+"FAIL"+reset, red
		}
		w.Human("  %s %s%s%s  %s\n", mark, colour, c.Name, reset, c.Note)
	}
}

// verifyPack is the shared gate: the full chain walk against this store's
// anchor and installed versions, with the binary's own version for the
// floor check.
func verifyPack(root, dir string) (*pack.Verified, error) {
	anchor, err := pack.LoadAnchor(root)
	if err != nil {
		return nil, fmt.Errorf("this store has no trusted root under %s: %w\n"+
			"  aertun content keygen makes one, or copy the producer's "+
			"root.json there deliberately", pack.TrustedRootPath(root), err)
	}
	installed, err := pack.LoadInstalled(root)
	if err != nil {
		return nil, err
	}
	return pack.Verify(dir, pack.VerifyOptions{
		Anchor: anchor, Installed: installed.VersionMap(),
		BinaryVersion: version,
	})
}

// contentRulesDir is where install places content and rollback restores
// it: a directory given with --rules, else the store's own detections
// directory, created. The run prefers exactly that directory once it
// exists, and a cwd-relative default for a store command is a directory
// the server never finds — the argument detectPack's install makes for
// the same path.
func contentRulesDir(root, given string) string {
	if given != "" {
		return given
	}
	return filepath.Join(root, "detections")
}

// shadowFlags is what the operator said about the gate on the command line.
type shadowFlags struct {
	days, perRule, total int
	skip                 bool
}

// contentCount reads the one shape --days and the budget flags share: a
// positive whole number, refused once here rather than parsed four ways.
func contentCount(flag, text string) (int, error) {
	n, err := strconv.Atoi(text)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s wants a positive whole number, not %q",
			flag, text)
	}
	return n, nil
}

// contentInstall verifies, replays, then places the content where the
// detection run reads it. Verify-first is not a formality the install skips
// when confident: it is the gate, run whole, in order. Between verification
// and placement stands the second gate, the shadow replay over this
// estate's own telemetry — required, because the producer's corpus is not
// this estate's week and only one of them answers for the noise — unless
// --no-shadow skips it and says its risk out loud. At placement stands the
// third: a pack file edited locally since the pack last placed it stops
// the install until --keep-overrides (the edit stands) or --adopt-overrides
// (the pack's version wins, on the record) says which copy is real.
// Options read by hand, as in contentSign.
func contentInstall(root string, args []string) error {
	var dir, rulesAt string
	fl := shadowFlags{}
	var keepEdits, adoptEdits bool
	// needsValue checks a flag's argument is there before anything indexes
	// past the end of the command line.
	needsValue := func(i int) error {
		if i+1 >= len(args) {
			return fmt.Errorf("%s needs a value", args[i])
		}
		return nil
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--rules":
			if err := needsValue(i); err != nil {
				return err
			}
			rulesAt = args[i+1]
			i++
		case "--days", "--max-fires-per-rule", "--max-total-fires":
			if err := needsValue(i); err != nil {
				return err
			}
			n, err := contentCount(args[i], args[i+1])
			if err != nil {
				return err
			}
			switch args[i] {
			case "--days":
				fl.days = n
			case "--max-fires-per-rule":
				fl.perRule = n
			default:
				fl.total = n
			}
			i++
		case "--no-shadow":
			fl.skip = true
		case "--keep-overrides":
			keepEdits = true
		case "--adopt-overrides":
			adoptEdits = true
		default:
			if dir == "" && !strings.HasPrefix(args[i], "-") {
				dir = args[i]
				continue
			}
			return fmt.Errorf("%q is not an option here", args[i])
		}
	}
	if dir == "" {
		return contentUsage()
	}
	if keepEdits && adoptEdits {
		return fmt.Errorf("--keep-overrides and --adopt-overrides say " +
			"opposite things about a locally-edited file: one keeps the " +
			"edit, the other takes the pack's version. Name one")
	}
	policy := pack.OverridesRefuse
	switch {
	case keepEdits:
		policy = pack.OverridesKeep
	case adoptEdits:
		policy = pack.OverridesAdopt
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	v, err := verifyPack(root, dir)
	if v != nil {
		printChecks(v.Checks)
	}
	if err != nil {
		return errBlocked{err}
	}
	// The same directory `aertun detect run --rules` reads, resolved the
	// same way, so what is installed is what runs — and what the replay
	// measures the pack against.
	target := contentRulesDir(root, rulesAt)
	rec, err := shadowGate(root, v, target, fl)
	if err != nil {
		return errBlocked{err}
	}
	res, err := pack.Install(v, root, target, rec, policy)
	if err != nil {
		// An override refusal is a gate's decision — a person's question,
		// phrased by the gate — not a breakage.
		if errors.Is(err, pack.ErrLocalEdits) {
			return errBlocked{err}
		}
		return err
	}
	detail := map[string]string{
		"pack": res.Pack, "version": res.Version,
		"meta_version": strconv.Itoa(v.Targets.Signed.Version),
		"files":        strconv.Itoa(res.Written),
		"replaced":     strconv.Itoa(res.Replaced),
		"dir":          target,
	}
	// The gate's verdict travels with the apply: what the estate's own week
	// said about this content, on the record, where the person deciding
	// whether to trust the next version will look for it.
	if rec != nil {
		detail["shadow"] = rec.Outcome
		detail["shadow_days"] = strconv.Itoa(rec.Days)
		detail["shadow_events"] = strconv.Itoa(rec.Events)
		detail["shadow_fired"] = strconv.Itoa(rec.Fired)
		detail["shadow_baseline"] = strconv.Itoa(rec.Baseline)
		if rec.Override != "" {
			detail["shadow_override"] = rec.Override
		}
	}
	if res.RootTo > res.RootFrom {
		detail["root_from"] = strconv.Itoa(res.RootFrom)
		detail["root_to"] = strconv.Itoa(res.RootTo)
	}
	if err := recordE(root, caller.auditRecord("content.installed", "/detections",
		audit.Success, detail)); err != nil {
		return err
	}
	// Either override decision is itself an act with a name: keeping an
	// edit and discarding one are the two things a person must never be
	// able to do unrecorded.
	for _, d := range []struct {
		action string
		files  []string
	}{
		{"content.override-kept", res.Kept},
		{"content.override-adopted", res.Adopted},
	} {
		if len(d.files) == 0 {
			continue
		}
		if err := recordE(root, caller.auditRecord(d.action, "/detections",
			audit.Success, map[string]string{
				"pack": res.Pack, "version": res.Version,
				"files": strings.Join(d.files, ", "),
			})); err != nil {
			return err
		}
	}
	if w.JSON(map[string]any{
		"pack": res.Pack, "version": res.Version,
		"meta_version": v.Targets.Signed.Version,
		"files":        res.Written, "replaced": res.Replaced, "dir": target,
		"shadow": rec, "kept_overrides": res.Kept,
		"adopted_overrides": res.Adopted,
		"root_from":         res.RootFrom, "root_to": res.RootTo,
	}) {
		return nil
	}
	w.Human("%s%s %s installed%s  %d file(s) into %s\n",
		bold, res.Pack, res.Version, reset, res.Written, target)
	if rec != nil {
		printShadowVerdict(rec)
	}
	if len(res.Kept) > 0 {
		w.Human("  %s%d local edit(s) kept — yours stand, the pack's "+
			"versions were not placed: %s%s\n", yellow, len(res.Kept),
			strings.Join(res.Kept, ", "), reset)
	}
	if len(res.Adopted) > 0 {
		w.Human("  %s%d local edit(s) adopted over — the pack's versions "+
			"replaced: %s%s\n", yellow, len(res.Adopted),
			strings.Join(res.Adopted, ", "), reset)
	}
	if res.RootTo > res.RootFrom {
		w.Human("  %sthe pack carried root version %d; this store's anchor "+
			"followed it, %d to %d. Root versions never move down%s\n",
			dim, res.RootTo, res.RootFrom, res.RootTo, reset)
	}
	if res.Replaced > 0 {
		w.Human("  %s%d file(s) replaced, the previous set kept under %s "+
			"for aertun content rollback%s\n", dim, res.Replaced,
			pack.PrevDir(root), reset)
	} else {
		w.Human("  %snothing was overwritten; the previous set (nothing of "+
			"this pack's) is the rollback point%s\n", dim, reset)
	}
	w.Human("  %sthey run on the next aertun detect run. Files this pack "+
		"does not own were left alone%s\n", dim, reset)
	return nil
}

// shadowGate runs the install's empirical gate and returns the record to
// carry, or the refusal. The gate is the customer's own: replay the pack's
// content, and the installed content it would replace, over the stored
// telemetry of the last N days, and let the false-positive budget decide —
// trial-ring semantics, so nothing the replay touches is recorded, queued
// or moved on either outcome (internal/pack/shadow.go holds the whole
// argument). An empty store cannot run the gate, and that refusal names the
// one flag that skips it, because a gate that "passed" without asking the
// estate anything is a decoration.
func shadowGate(root string, v *pack.Verified, target string,
	fl shadowFlags) (*pack.ShadowRecord, error) {

	if fl.skip {
		w.Human("  %sskipping the shadow replay (--no-shadow): this "+
			"estate's own week was never asked about this content, so what "+
			"it would have raised stays unmeasured until the first detect "+
			"run. The flag is for a first install or an air-gapped store, "+
			"and the installed record will say it was used%s\n", yellow, reset)
		return &pack.ShadowRecord{Outcome: pack.ShadowSkipped}, nil
	}
	if !dirExists(spoolDir(root)) {
		return nil, fmt.Errorf("%w: this store holds no events at all, so "+
			"the pack's rules have nothing to be asked about. Collect "+
			"telemetry first, or — deliberately, for an air-gapped first "+
			"install or an empty store — install without the gate: "+
			"--no-shadow", pack.ErrNoTelemetry)
	}
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		return nil, err
	}
	defer sp.Close()
	res, err := pack.Shadow(v, sp, pack.ShadowOptions{
		Now: time.Now().UTC(), Days: fl.days, RulesDir: target,
		MaxPerRule: fl.perRule, MaxTotal: fl.total,
	})
	if err != nil {
		return nil, err
	}
	printShadowSummary(res)
	if !res.Held() {
		return nil, fmt.Errorf("the shadow replay refused this pack — it "+
			"would flood the queue on this estate's own week:\n  - %s",
			strings.Join(res.Refused, "\n  - "))
	}
	rec := &pack.ShadowRecord{Days: res.Days, Events: res.Events,
		Fired: res.Total.Fired, Baseline: res.Total.Installed,
		Outcome: pack.ShadowHeld}
	// Held under an operator-named cap that the defaults would have refused
	// is a different fact from held outright, and the record must be able
	// to say which — a budget argued with is a decision, and decisions
	// belong to whoever made them.
	if res.OverDefaultBudget() {
		rec.Outcome = pack.ShadowOverridden
		rec.Override = overrideWords(fl)
	}
	return rec, nil
}

// overrideWords names the flag(s) and number(s) that let the pack in, in
// the words the operator could type again.
func overrideWords(fl shadowFlags) string {
	var parts []string
	if fl.perRule > 0 {
		parts = append(parts, fmt.Sprintf("--max-fires-per-rule %d", fl.perRule))
	}
	if fl.total > 0 {
		parts = append(parts, fmt.Sprintf("--max-total-fires %d", fl.total))
	}
	return strings.Join(parts, " ")
}

// printShadowSummary says what the replay measured: the window, every id
// that would have raised anything against its budget and its installed
// equivalent, and the rules this estate's week never exercised. Printed on a
// pass and on a refusal alike — numbers shown only when a gate refuses
// teach people that its refusals are the only thing worth reading.
func printShadowSummary(res *pack.ShadowResult) {
	w.Human("  %sshadow replay%s  %d event(s) over the last %d day(s)\n",
		bold, reset, res.Events, res.Days)
	for _, rows := range [][]pack.ShadowCount{res.Rules, res.Correlations} {
		for _, c := range rows {
			if c.Fired == 0 && c.Installed == 0 {
				continue
			}
			mark := dim
			if c.Over {
				mark = yellow
			}
			w.Human("  %s%s would fire %d time(s); the installed equivalent "+
				"%d, the budget %d%s\n", mark, c.ID, c.Fired, c.Installed,
				c.Cap, reset)
		}
	}
	if res.Total.Fired > 0 || res.Total.Installed > 0 {
		w.Human("  %sthe pack as a whole would fire %d against %d from the "+
			"set it replaces; the budget %d%s\n", dim, res.Total.Fired,
			res.Total.Installed, res.Total.Cap, reset)
	}
	if res.Unexercised > 0 {
		w.Human("  %s%d rule(s) raised nothing over the window — "+
			"unexercised by this estate's week, which is silence, not "+
			"safety, and what the trial ring answers after the install%s\n",
			dim, res.Unexercised, reset)
	}
}

// printShadowVerdict is the one-line form for an installed record, on
// install and on `content installed`: the outcome, the numbers, and — when
// a flag was the difference — the flag.
func printShadowVerdict(rec *pack.ShadowRecord) {
	switch rec.Outcome {
	case pack.ShadowSkipped:
		w.Human("  %sshadow replay skipped (--no-shadow): this estate's own "+
			"week was never asked about this content%s\n", yellow, reset)
	case pack.ShadowOverridden:
		w.Human("  %sshadow replay held after an override (%s): would have "+
			"fired %d against a baseline of %d, over %d day(s) of %d "+
			"event(s)%s\n", yellow, rec.Override, rec.Fired, rec.Baseline,
			rec.Days, rec.Events, reset)
	default:
		w.Human("  %sshadow replay held: would have fired %d against a "+
			"baseline of %d, over %d day(s) of %d event(s)%s\n", dim,
			rec.Fired, rec.Baseline, rec.Days, rec.Events, reset)
	}
}

// contentList shows what a pack directory holds, from its manifest, without
// verifying — the listing is for a directory somebody is deciding about,
// and the answer to "is it any good" is `verify`, said here rather than
// implied.
func contentList(root string, args []string) error {
	dir := "."
	if len(args) == 1 {
		dir = args[0]
	} else if len(args) > 1 {
		return contentUsage()
	}
	if _, err := os.Stat(filepath.Join(dir, pack.ManifestName)); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s has no %s. aertun content sign %s --id ID "+
				"--version V builds and signs one from the content files",
				dir, pack.ManifestName, dir)
		}
		return err
	}
	p, err := pack.Read(dir)
	if err != nil {
		return err
	}
	rules, corrs := p.Counts()
	signed := "unsigned"
	if _, serr := pack.LoadRoot(dir); serr == nil {
		if _, terr := pack.LoadTargets(dir); terr == nil {
			if _, tserr := pack.LoadTimestamp(dir); tserr == nil {
				signed = "signed"
			}
		}
	}
	if w.JSON(map[string]any{
		"pack": p.Manifest.ID, "version": p.Manifest.Version,
		"channel": p.Manifest.Channel, "about": p.Manifest.About,
		"detections": rules, "correlation_files": corrs,
		"metadata": signed, "dir": dir,
	}) {
		return nil
	}
	w.Human("%s%s %s%s  %s  [%s]\n", bold, p.Manifest.ID, p.Manifest.Version,
		reset, p.Manifest.Channel, signed)
	if p.Manifest.About != "" {
		w.Human("  %s%s%s\n", dim, p.Manifest.About, reset)
	}
	w.Human("  %s%d rule(s), %d correlation file(s)%s\n", dim, rules, corrs, reset)
	if signed == "unsigned" {
		w.Human("  %sunverified: the metadata side is missing, so aertun "+
			"content install will refuse it%s\n", yellow, reset)
	} else {
		w.Human("  %s%s says what it holds; aertun content verify %s says "+
			"whether it checks out%s\n", dim, pack.ManifestName, dir, reset)
	}
	return nil
}

// contentInstalled lists what this store has installed, with versions. An
// expired pack is listed like any other — expiry refuses updates and never
// disables content — with the staleness said out loud beside it, because a
// silence where "content froze three weeks ago" should have been is the
// failure the staleness note exists to prevent.
func contentInstalled(root string, args []string) error {
	if len(args) > 0 {
		return contentUsage()
	}
	st, err := pack.LoadInstalled(root)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	var ids []string
	for id := range st.Packs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if w.JSON(map[string]any{"packs": st.Packs}) {
		return nil
	}
	if len(ids) == 0 {
		w.Human("  no packs installed; aertun content install DIR places " +
			"one\n")
		return nil
	}
	for _, id := range ids {
		p := st.Packs[id]
		w.Human("%s%s %s%s  metadata v%d  %d file(s)  [%s]\n",
			bold, id, p.Version, reset, p.MetaVersion, p.Files, p.Channel)
		when, _ := time.Parse(time.RFC3339, p.InstalledAt)
		w.Human("  %sinstalled %s%s\n", dim,
			when.UTC().Format("2 Jan 2006"), reset)
		if p.Shadow != nil {
			printShadowVerdict(p.Shadow)
		}
		if len(p.Overrides) > 0 {
			w.Human("  %s%d local override(s) kept: %s — the pack's "+
				"version was not placed over the edit%s\n", yellow,
				len(p.Overrides), strings.Join(p.Overrides, ", "), reset)
		}
		if since, stale := p.StaleSince(now); stale {
			w.Human("  %scontent frozen: this pack's metadata expired %s. "+
				"Updates are refused; what is installed keeps running. "+
				"Ask the producer for a fresh pack%s\n", yellow, since, reset)
		} else if since != "" {
			w.Human("  %supdates accepted until %s%s\n", dim, since, reset)
		}
	}
	return nil
}

// contentRollback restores the previous set: one command, no pack
// directory needed, audited. The automatic rollback (on a false-positive
// budget breach during a bake window) is deferred with the rest of the
// replay pipeline; this is the manual one, and it is instant because the
// previous bytes were kept.
func contentRollback(root string, args []string) error {
	if len(args) > 0 {
		return contentUsage()
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActTune, auth.AreaSecurity); err != nil {
		return err
	}
	target := contentRulesDir(root, "")
	res, err := pack.Rollback(root, target)
	if err != nil {
		return err
	}
	detail := map[string]string{
		"pack": res.Pack, "restored": strconv.Itoa(res.Restored),
		"removed": strconv.Itoa(res.Removed), "dir": target,
	}
	if res.Prior != nil {
		detail["to_version"] = res.Prior.Version
	}
	if err := recordE(root, caller.auditRecord("content.rolled-back",
		"/detections", audit.Success, detail)); err != nil {
		return err
	}
	if w.JSON(map[string]any{
		"pack": res.Pack, "restored": res.Restored, "removed": res.Removed,
		"to": res.Prior,
	}) {
		return nil
	}
	w.Human("%srolled back%s  %d file(s) restored, %d added file(s) removed\n",
		bold, reset, res.Restored, res.Removed)
	if res.Prior != nil {
		w.Human("  %s%s is back at %s (metadata v%d)%s\n", dim, res.Pack,
			res.Prior.Version, res.Prior.MetaVersion, reset)
	} else {
		w.Human("  %s%s had nothing installed before it; its files are gone "+
			"from %s%s\n", dim, res.Pack, target, reset)
	}
	w.Human("  %sthe set just left is itself kept, so this undoes cleanly%s\n",
		dim, reset)
	return nil
}
