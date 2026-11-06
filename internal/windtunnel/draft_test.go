// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// The purple loop's acceptance bar, in the honesty-test tradition: the
// refuses refuse with their sentences, the one separable miss drafts and
// survives the engine's own bar, the closed loop closes through the
// promotion a human would make, and nothing outside the proposals directory
// is ever written.

// doctorWithoutTrifecta is the reference pack with corr.lethal-trifecta
// removed — the doctored instrument the existing honesty test introduced,
// here raised to a whole run: every scenario still loads (the loose corpus
// path is exactly for an instrument that lacks an expectation), the trifecta
// is a content miss, and the loop has a miss worth drafting.
func doctorWithoutTrifecta(t *testing.T) *Reference {
	t.Helper()
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	out := &Reference{Name: ref.Name, Rules: ref.Rules, Corrs: nil,
		Digest:    ref.Digest,
		ruleQuiet: map[string]bool{}, corrIDs: map[string]bool{}}
	for k, v := range ref.ruleQuiet {
		out.ruleQuiet[k] = v
	}
	for _, c := range ref.Corrs {
		if strings.EqualFold(c.ID, "corr.lethal-trifecta") {
			continue
		}
		out.Corrs = append(out.Corrs, c)
		out.corrIDs[strings.ToLower(c.ID)] = true
	}
	return out
}

// dirDigests is a directory's whole content as one map, for asserting that
// nothing outside the proposals directory moved.
func dirDigests(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		out[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The two scenarios whose blinds declare the pack has no rule for them are
// the loop's honest refusals: their events and their twins' are identical on
// every closed field, and no rule this telemetry can carry would separate
// them. The refusal is the exact sentence, a record is written, and no draft
// exists.
func TestDraftRefusesWhatTheTelemetryCannotDistinguish(t *testing.T) {
	root := t.TempDir()
	card, err := Run(RunOptions{Into: filepath.Join(root, "scratch"), Seed: 7,
		Now: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	drafts := filepath.Join(root, "drafts")
	recs, err := Draft(card, ref, DraftOptions{Dir: drafts})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("%d record(s); the shipped pack misses nothing it carries a "+
			"rule for, and the two telemetry-only sessions are the loop's "+
			"whole ledger here", len(recs))
	}
	seen := map[string]DraftRecord{}
	for _, r := range recs {
		if r.Outcome != DraftOutcomeRefused {
			t.Errorf("%s was %s; over the shipped pack the only draftable "+
				"misses are the two no rule can honestly carry", r.Scenario,
				r.Outcome)
		}
		if !strings.Contains(r.Reason,
			"a miss the telemetry cannot distinguish is a gap to declare, "+
				"not a rule to force") {
			t.Errorf("%s's refusal (%s) does not carry the sentence the "+
				"discipline is named by", r.Scenario, r.Reason)
		}
		seen[r.Scenario] = r
	}
	for _, id := range []string{"agent.slopsquat-install",
		"agent.recorder-blind-window"} {
		if _, ok := seen[id]; !ok {
			t.Errorf("%s was not refused; its blind says no rule exists for "+
				"it and the loop must say the same in its own words", id)
		}
		if seen[id].Separable != 0 || seen[id].Indistinguishable == 0 {
			t.Errorf("%s: separable %d, indistinguishable %d; every event "+
				"its session emits is the twin's shape", id,
				seen[id].Separable, seen[id].Indistinguishable)
		}
	}
	entries, err := os.ReadDir(drafts)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("%d file(s) in the drafts directory; two refusals, no "+
			"proposals", len(entries))
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".refused.json") {
			t.Errorf("%s is not a refusal record; nothing over the shipped "+
				"pack should have drafted", e.Name())
		}
	}
}

// The closed loop, end to end: the doctored pack misses the trifecta, the
// loop drafts the one leg the twin does not share, the engine's own bar
// passes, the replay validates, the proposal lands as a file plus its audit
// record — and promoting it, the way a person would (copying the file into
// the pack) turns the miss into a caught-alert under the engine's own tier
// arithmetic. Along the way the pack directory is proven untouched: the
// loop proposes, it never writes the pack.
func TestDraftSeparatesTheTrifectaLegsAndClosesTheLoop(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	doctored := doctorWithoutTrifecta(t)

	// The pack directory as a person holds it: the shipped files, written
	// once, digested before anything the loop does.
	packDir := filepath.Join(root, "pack")
	if err := os.MkdirAll(packDir, 0o700); err != nil {
		t.Fatal(err)
	}
	files, err := detect.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(packDir, f.Name), f.Body,
			0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := dirDigests(t, packDir)

	scratch := filepath.Join(root, "scratch")
	card, err := Run(RunOptions{Reference: doctored, Into: scratch, Seed: 7,
		Now: now})
	if err != nil {
		t.Fatalf("the run over the doctored pack refused: %v", err)
	}
	var row *Row
	for i := range card.Rows {
		if card.Rows[i].Scenario == "agent.trifecta-mailroom-exfil" {
			row = &card.Rows[i]
		}
	}
	if row == nil || row.Outcome != OutcomeMissed ||
		row.MissKind() != MissContent {
		t.Fatalf("the trifecta row is %v; removing corr.lethal-trifecta "+
			"must be a content miss the scorecard reports", row)
	}

	drafts := filepath.Join(root, "drafts")
	recs, err := Draft(card, doctored, DraftOptions{Dir: drafts})
	if err != nil {
		t.Fatal(err)
	}
	// The loop never wrote the pack: identical bytes, before and after.
	if after := dirDigests(t, packDir); !reflect.DeepEqual(before, after) {
		t.Fatal("the pack directory changed while the loop drafted; the " +
			"loop proposes and never writes the pack, because a detector " +
			"that edits its own controls is the thing the ring prevents")
	}

	byScenario := map[string]DraftRecord{}
	refusals := 0
	for _, r := range recs {
		if r.Outcome == DraftOutcomeDrafted {
			byScenario[r.Scenario] = r
			continue
		}
		refusals++
	}
	// Two scenarios expect corr.lethal-trifecta must-alert — the trifecta
	// and the injection hijack, which arrives at the same ordered shape from
	// the injection side — so removing the correlation is two misses, and
	// the loop answers both. The recorder-blind session refuses. The
	// slopsquat row is not here at all: its trifecta expectation was
	// stays-quiet, the absent correlation makes it unmet (deleting a
	// detection must not improve a scorecard), the row is wrongly-quiet — a
	// precision finding, not a detection gap, and not the loop's to draft.
	if len(byScenario) != 2 || refusals != 1 {
		t.Fatalf("%d draft(s), %d refusal(s); the doctored pack misses the "+
			"two scenarios that expect the trifecta correlation, one "+
			"session refuses as indistinguishable, and the wrongly-quiet "+
			"row is nobody's draft", len(byScenario), refusals)
	}
	drafted := byScenario["agent.trifecta-mailroom-exfil"]
	if drafted.RuleID == "" {
		t.Fatal("the trifecta did not draft; its egress leg is the separable " +
			"miss this run carries")
	}
	if drafted.RuleID != "draft.trifecta-mailroom-exfil" {
		t.Fatalf("the draft is %s; the id is the scenario's own, "+
			"deterministically", drafted.RuleID)
	}
	if drafted.MatchFixtures != 1 || drafted.RefuseFixtures != 3 {
		t.Fatalf("fixtures %d matched, %d refused; the egress leg is the "+
			"must-match and the twin's three steps are the must-not",
			drafted.MatchFixtures, drafted.RefuseFixtures)
	}
	if drafted.Separable != 1 || drafted.Indistinguishable != 2 {
		t.Fatalf("separable %d, indistinguishable %d; the mail and query "+
			"legs are the twin's own shape and only egress separates",
			drafted.Separable, drafted.Indistinguishable)
	}
	if drafted.AmbientFires != 0 || drafted.CaughtFires != 1 {
		t.Fatalf("ambient %d, caught %d; the draft must be quiet on the "+
			"estate and catch the session it answers", drafted.AmbientFires,
			drafted.CaughtFires)
	}
	// The injection's draft, and its honest ambient rate: the estate's
	// reporter posts webhooks all morning, the session's own egress leg is
	// that shape, and the record says so rather than hiding it.
	injection := byScenario["agent.injection-hijack-via-issue"]
	if injection.RuleID != "draft.injection-hijack-via-issue" {
		t.Fatalf("the injection draft is %q; both trifecta-expecting "+
			"scenarios must draft", injection.RuleID)
	}
	if injection.MatchFixtures != 2 || injection.CaughtFires != 2 {
		t.Fatalf("the injection draft matched %d fixture(s) and caught %d "+
			"fire(s); its secret read and its webhook push are the two "+
			"legs the twin does not share", injection.MatchFixtures,
			injection.CaughtFires)
	}
	if injection.AmbientFires != 3 {
		t.Fatalf("the injection draft's ambient rate is %d; the estate's "+
			"three honest webhook posts are exactly what the ambient count "+
			"exists to report", injection.AmbientFires)
	}

	// The proposal file: the pack's own format, loadable by the pack's own
	// loader's standards, its fixtures proven, its tree closed-vocabulary
	// narrow — it reads no field the boundary does not declare.
	proposal := filepath.Join(drafts, drafted.RuleID+".json")
	body, err := os.ReadFile(proposal)
	if err != nil {
		t.Fatal(err)
	}
	var rule detect.Rule
	if err := json.Unmarshal(body, &rule); err != nil {
		t.Fatalf("the proposal is not a rule: %v", err)
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("the proposal fails the engine's own bar: %v", err)
	}
	for _, res := range rule.Test() {
		if !res.OK() {
			t.Fatalf("a fixture refuses the draft: %s", res.Why())
		}
	}
	closed := map[string]bool{}
	for _, f := range draftFieldNames() {
		closed[f] = true
	}
	for _, f := range rule.Fields() {
		if !closed[f] {
			t.Errorf("the draft reads %s, outside the closed vocabulary; a "+
				"rule quoting anything the boundary does not declare is a "+
				"rule about one attacker's spelling", f)
		}
	}
	// Narrowness, beyond the fixtures: the session's own egress shape fires,
	// and the estate's honest reporter — the same label on a different tool —
	// does not.
	shaped := telemetry.Event{Source: "otel/genai",
		Class:       telemetry.ClassAPIActivity,
		Disposition: telemetry.DispositionAllowed,
		Actor:       telemetry.ID{Issuer: "otel", Value: "wt-whoever"},
		Message:     "execute_tool",
		Raw: map[string]string{"operation": "execute_tool",
			"tool": "http_post", "status": "ok", "labels": "egress"}}
	if !rule.Matches(shaped) {
		t.Error("the draft does not match the session's egress shape")
	}
	honest := shaped
	honest.Raw = map[string]string{"operation": "execute_tool",
		"tool": "post_webhook", "status": "ok", "labels": "egress"}
	if rule.Matches(honest) {
		t.Error("the draft matches the estate's own webhook tool; the tree " +
			"must quote the tools this session used, not the label alone")
	}
	unlabelled := shaped
	unlabelled.Raw = map[string]string{"operation": "execute_tool",
		"tool": "http_post", "status": "ok"}
	if rule.Matches(unlabelled) {
		t.Error("the draft matches an unlabelled call; the label is the " +
			"boundary's declaration and the tree must demand it")
	}

	// The audit record: the closed details, pinned to the proposal's bytes.
	auditBody, err := os.ReadFile(filepath.Join(drafts,
		drafted.RuleID+".audit.json"))
	if err != nil {
		t.Fatal(err)
	}
	var audit DraftRecord
	if err := json.Unmarshal(auditBody, &audit); err != nil {
		t.Fatalf("the audit record does not decode: %v", err)
	}
	sum := sha256.Sum256(body)
	if audit.RuleDigest != hex.EncodeToString(sum[:]) {
		t.Error("the audit record's rule digest is not the proposal's " +
			"bytes; the record must pin what a person is asked to promote")
	}
	if audit.Miss == "" || audit.PackDigest != card.PackDigest ||
		audit.ScorecardDigest != card.SHA256 {
		t.Errorf("the audit record is not pinned to the miss it answers: "+
			"miss %q, pack %s, scorecard %s", audit.Miss, audit.PackDigest,
			audit.ScorecardDigest)
	}

	// The promotion, in the engine's own terms: the doctored pack plus the
	// draft, replayed over the same session the run spliced, scored by the
	// same id join the scorecard uses — the miss is now a catch at alert
	// tier, and the twin stays quiet under the promoted instrument.
	promoted := doctorWithoutTrifecta(t)
	promoted.Rules = append(promoted.Rules, rule)
	promoted.ruleQuiet[strings.ToLower(rule.ID)] = false
	sc := copyScenario(t, "agent.trifecta-mailroom-exfil")
	base := DefaultBase()
	anchor, _ := DefaultAnchor(base)
	placed, err := Place(sc, sc.Steps, base, 7, anchor)
	if err != nil {
		t.Fatal(err)
	}
	ambient, err := ambientPass(t, promoted, base)
	if err != nil {
		t.Fatal(err)
	}
	attack, _, err := replayPlaced(t, promoted, base, placed)
	if err != nil {
		t.Fatal(err)
	}
	r := scoreExpect(sc, Expect{Kind: ExpectRule, ID: rule.ID,
		Verdict: VerdictMustAlert}, promoted, attack, ambient, placed)
	if !r.Met || r.Fires != 1 {
		t.Fatalf("the promoted draft fired %d time(s) above ambient on the "+
			"session it was drafted from; the loop did not close", r.Fires)
	}
	if got := outcomeOf([]ExpectRow{*r}); got != OutcomeCaughtAlert {
		t.Fatalf("the session's tier under the promoted pack is %q; the "+
			"miss the draft answered is a caught-alert or the loop closed "+
			"nothing", got)
	}
	twinPlaced, err := Place(sc, sc.Twin.Steps, base, 7, anchor)
	if err != nil {
		t.Fatal(err)
	}
	twinPass, _, err := replayPlaced(t, promoted, base, twinPlaced)
	if err != nil {
		t.Fatal(err)
	}
	for id, fires := range twinPass.loud {
		if fires > ambient.loud[id] {
			t.Fatalf("the promoted draft fired %d time(s) above ambient on "+
				"the twin %s; the catch is noise until the twin is quiet",
				fires-ambient.loud[id], id)
		}
	}

	// And the promotion the way a person makes it: the proposal file copied
	// into the pack, byte for byte, the directory loaded as an instrument,
	// the whole corpus rerun — nothing regresses, no twin wakes, and the
	// scorecard's own baseline outcomes hold with the draft living in the
	// pack beside them.
	if err := os.WriteFile(filepath.Join(packDir, drafted.RuleID+".json"),
		body, 0o600); err != nil {
		t.Fatal(err)
	}
	dirRef, err := LoadReferenceDir(packDir)
	if err != nil {
		t.Fatalf("the pack holding the promoted proposal did not load: %v",
			err)
	}
	baseline, err := Run(RunOptions{Into: filepath.Join(root, "base-scratch"),
		Seed: 7, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	rerun, err := Run(RunOptions{Reference: dirRef,
		Into: filepath.Join(root, "rerun-scratch"), Seed: 7, Now: now})
	if err != nil {
		t.Fatalf("the rerun over the promoted pack refused: %v", err)
	}
	if len(rerun.Rows) != len(baseline.Rows) {
		t.Fatalf("%d rows against the baseline's %d", len(rerun.Rows),
			len(baseline.Rows))
	}
	for i := range rerun.Rows {
		if rerun.Rows[i].Outcome != baseline.Rows[i].Outcome {
			t.Errorf("%s is %s with the draft promoted, %s without; a "+
				"promoted draft must add a catch without moving any other "+
				"row's tier", rerun.Rows[i].Scenario, rerun.Rows[i].Outcome,
				baseline.Rows[i].Outcome)
		}
		if rerun.Rows[i].Twin.Outcome != TwinQuiet {
			t.Errorf("%s's twin %sd under the promoted pack; the draft "+
				"living beside the pack must wake nothing", rerun.Rows[i].Scenario,
				rerun.Rows[i].Twin.Outcome)
		}
	}
	if rerun.Aggregate.TwinFires != 0 {
		t.Fatalf("%d twin false fires under the promoted pack",
			rerun.Aggregate.TwinFires)
	}
}

// replayPlaced splices a placed session into the base stream and replays the
// given instrument over it — the run's own three steps, for a test that asks
// a question of the passes themselves.
func replayPlaced(t *testing.T, ref *Reference, base []telemetry.Event,
	placed *Placed) (*passResult, *spool.Spool, error) {
	t.Helper()
	stream := Interleave(base, placed.Events)
	sp, err := WriteScratch(t.TempDir(), stream)
	if err != nil {
		return nil, nil, err
	}
	res, err := runPass(sp, ref, latenessHistogram(stream).quantile(0.99))
	if err != nil {
		sp.Close()
		return nil, nil, err
	}
	return res, sp, nil
}

// A draft that fires on the estate's own traffic is refused with its count:
// six honest http_post calls already living in the base stream make the
// egress draft a rule about the estate, and the count — six — is the
// refusal, not a footnote on a promotion.
func TestDraftRefusesARuleThatFiresOnTheEstate(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

	// The estate: the quiet morning, plus a reporter integration that posts
	// to its own webhook through http_post six times — honest work, on the
	// exact closed-field shape the trifecta's egress leg carries.
	base := DefaultBase()
	for j := 0; j < MaxDraftAmbient+1; j++ {
		base = append(base, genai("reporter", "execute_tool", at(45+j, 0), j,
			map[string]string{"operation": "execute_tool",
				"tool": "http_post", "status": "ok",
				"trace_id": fmt.Sprintf("7c22e0ab41f94d77b0a1e5d3f6c8023%02x", j),
				"labels":   "egress",
				"dest":     "https://hooks.example.internal/ticketing"}))
	}
	var lines []string
	for _, e := range base {
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(b))
	}
	basePath := filepath.Join(root, "estate.jsonl")
	if err := writeLines(basePath, lines...); err != nil {
		t.Fatal(err)
	}

	doctored := doctorWithoutTrifecta(t)
	card, err := Run(RunOptions{Reference: doctored, Base: basePath,
		Into: filepath.Join(root, "scratch"), Seed: 7, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	drafts := filepath.Join(root, "drafts")
	recs, err := Draft(card, doctored, DraftOptions{Dir: drafts})
	if err != nil {
		t.Fatal(err)
	}
	var trifecta *DraftRecord
	for i := range recs {
		if recs[i].Scenario == "agent.trifecta-mailroom-exfil" {
			trifecta = &recs[i]
		}
	}
	if trifecta == nil {
		t.Fatal("the trifecta's miss produced no record at all")
	}
	if trifecta.Outcome != DraftOutcomeRefused {
		t.Fatalf("the trifecta was %s over an estate whose own traffic "+
			"carries the draft's shape; a rule that fires on the estate it "+
			"watches is noise wearing a detection's name", trifecta.Outcome)
	}
	if !strings.Contains(trifecta.Reason, "6 time(s) on the base stream") {
		t.Fatalf("the refusal (%s) does not name the count; the number is "+
			"the refusal and the reader deserves it", trifecta.Reason)
	}
	if trifecta.AmbientFires != MaxDraftAmbient+1 {
		t.Fatalf("ambient %d; the six honest posts are the count the record "+
			"must carry", trifecta.AmbientFires)
	}
	if _, err := os.Stat(filepath.Join(drafts,
		"draft.trifecta-mailroom-exfil.json")); err == nil {
		t.Fatal("a proposal was written for a refused draft; the gap stays " +
			"declared, and a file is a promotion waiting to happen")
	}
	if _, err := os.Stat(filepath.Join(drafts,
		"agent.trifecta-mailroom-exfil.refused.json")); err != nil {
		t.Fatalf("no refusal record for the trifecta: %v", err)
	}
}

// A lateness miss is refused as the watermark finding it is: drafting a rule
// over it would paper over a lateness budget with a detection, and the loop
// says so in words rather than reaching for the tree.
func TestDraftRefusesALatenessMissByName(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	card, err := Run(RunOptions{Into: filepath.Join(root, "scratch"), Seed: 7,
		Now: now})
	if err != nil {
		t.Fatal(err)
	}
	// The row the run would have written had the egress leg arrived after
	// its window closed: the same document discipline (sealed, so it
	// verifies) over a lateness miss, which is what the existing two-clock
	// test proves the engine reports.
	for i := range card.Rows {
		if card.Rows[i].Scenario != "agent.trifecta-mailroom-exfil" {
			continue
		}
		card.Rows[i].Outcome = OutcomeMissed
		for j := range card.Rows[i].Expects {
			x := &card.Rows[i].Expects[j]
			if x.Kind == ExpectCorrelation && x.ID == "corr.lethal-trifecta" {
				x.Met = false
				x.MissKind = MissLateness
			}
		}
	}
	if err := card.seal(); err != nil {
		t.Fatal(err)
	}
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	recs, err := Draft(card, ref, DraftOptions{Dir: filepath.Join(root,
		"drafts")})
	if err != nil {
		t.Fatal(err)
	}
	var trifecta *DraftRecord
	for i := range recs {
		if recs[i].Scenario == "agent.trifecta-mailroom-exfil" {
			trifecta = &recs[i]
		}
	}
	if trifecta == nil {
		t.Fatal("the lateness miss produced no record")
	}
	if trifecta.Outcome != DraftOutcomeRefused ||
		!strings.Contains(trifecta.Reason, "the miss was lateness") {
		t.Fatalf("the lateness miss was %s (%s); it is a finding about the "+
			"watermark budget and must be refused as one", trifecta.Outcome,
			trifecta.Reason)
	}
	if trifecta.Separable != 0 {
		t.Errorf("a lateness refusal derived a tree anyway (%d separable); "+
			"the derivation is for content misses", trifecta.Separable)
	}
}

// Same inputs, byte-identical drafts: the proposal, the audit record and the
// refusal ledger are functions of the run's evidence and nothing else. The
// scorecard's own digest differs between the two runs (it names its scratch
// directory), so that one field is set aside — the same allowance the
// scorecard's own determinism test makes.
func TestDraftIsDeterministic(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	doctored := doctorWithoutTrifecta(t)

	write := func(root string) map[string][]byte {
		card, err := Run(RunOptions{Reference: doctored,
			Into: filepath.Join(root, "scratch"), Seed: 7, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(root, "drafts")
		if _, err := Draft(card, doctored, DraftOptions{Dir: dir}); err != nil {
			t.Fatal(err)
		}
		out := map[string][]byte{}
		err = filepath.Walk(dir, func(path string, fi os.FileInfo,
			err error) error {
			if err != nil || fi.IsDir() {
				return err
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			out[rel] = body
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	a := write(t.TempDir())
	b := write(t.TempDir())
	if len(a) != len(b) {
		t.Fatalf("%d file(s) against %d; two runs of the same evidence "+
			"produce the same ledger", len(a), len(b))
	}
	for name, bodyA := range a {
		bodyB, ok := b[name]
		if !ok {
			t.Fatalf("%s was written by one run and not the other", name)
		}
		// Every record names its scorecard's digest, and the two scorecards
		// differ only in the scratch path they name; that one field is set
		// aside, the same allowance the scorecard's own determinism test
		// makes for itself. A proposal rule is compared as the bytes a
		// person would promote.
		if strings.HasSuffix(name, ".audit.json") ||
			strings.HasSuffix(name, ".refused.json") {
			var ra, rb DraftRecord
			if err := json.Unmarshal(bodyA, &ra); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(bodyB, &rb); err != nil {
				t.Fatal(err)
			}
			ra.ScorecardDigest, rb.ScorecardDigest = "", ""
			if !reflect.DeepEqual(ra, rb) {
				t.Fatalf("%s differs between two runs of the same evidence"+
					": %+v against %+v", name, ra, rb)
			}
			continue
		}
		if string(bodyA) != string(bodyB) {
			t.Fatalf("%s is not byte-identical between two runs of the "+
				"same evidence; a draft is a commitment, and a diff nobody "+
				"acted on is a question nobody can answer", name)
		}
	}
}
