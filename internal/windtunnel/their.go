// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aertun/aertun/internal/sigma"
)

// their-Sigma mode: the organisation's own Sigma rules, imported through the
// existing importer and replayed under this engine, joined to the corpus at
// technique level (decision 6's second mode, arrived).
//
// # What reuses what
//
// The importer is internal/sigma's, whole and untouched: the same refusals
// (aggregations, bare keywords, the modifiers that lie), the same report
// shape, the same never-half-compile discipline. Nothing here re-parses a
// Sigma file; a construct this implementation refuses is refused in this
// mode too, counted on the scorecard, and excluded from the denominator —
// a rule that cannot compile cannot catch anything, and pretending
// otherwise would be the half-run this package refuses everywhere else.
//
// The replay is runPass's, over the same scratch spools, with the same
// ambient calibration: their rules run once over the base stream alone and
// every count the join credits is the count above that.
//
// # The join, and its honest limit
//
// Reference mode joins by id — the highest fidelity there is, because the
// scenario and the pack share the vocabulary. Their rules share no
// vocabulary with the corpus, so the join is at technique level: the
// scenario stages technique ids, the rule carries them in its Sigma tags
// (tags.attack.*, harvested by the importer as ATT&CK ids), and a
// technique-tagged rule firing above ambient within the run is a catch.
// The limit, stated on every document this mode seals: technique-intersect
// is not rule-id. A rule can tag a technique the scenario stages and still
// not fire on its events — wrong source, wrong field, too narrow a value —
// and those are misses this mode reports in its per-rule rows, never hides
// behind the aggregate. Generosity runs one way only: any intersecting
// rule firing catches the scenario, with every quiet intersecting rule
// still on the record beside it.

// sigmaJoinBlind is the fidelity limit, stated on every their-Sigma
// document in the blind tradition: the reader of a number needs to know
// which join produced it.
const sigmaJoinBlind = "their-Sigma scoring joins at technique level, not " +
	"rule id: a rule can tag a technique this scenario stages and still not " +
	"fire on its events — wrong source, wrong field, too narrow a value — " +
	"and those misses are reported in the per-rule rows, never hidden behind " +
	"the aggregate. A catch is a technique-tagged rule firing above ambient; " +
	"rules that fired while tagging none of the scenario's techniques are " +
	"recorded, not credited; rules the importer refused are counted and can " +
	"catch nothing. And this measures their rules under this engine's " +
	"semantics — never their pipeline's own, which is what the their-alerts " +
	"mode exists to measure."

// SigmaRefusal is one rule the importer refused, carried on the scorecard
// with the construct named — the house import report, promoted from a
// console message to a sealed field.
type SigmaRefusal struct {
	// Rule is the rule's title, or its file when the file would not read.
	Rule string `json:"rule"`
	// What is the construct that was refused.
	What string `json:"what"`
	// Why is the importer's sentence for it.
	Why string `json:"why"`
	// Ours says the gap is in this program's Sigma support rather than in
	// the rule: two lists for two different people, the importer's own
	// distinction.
	Ours bool `json:"ours"`
}

// SigmaReport is what happened to their library at import: names what ran
// before how it went, the same discipline as the pack digest. Read is the
// denominator the honesty of the whole mode rests on — refused rules are
// in it, counted, never silently dropped.
type SigmaReport struct {
	Dir      string         `json:"dir"`
	Digest   string         `json:"digest"`
	Read     int            `json:"read"`
	Imported int            `json:"imported"`
	Refused  []SigmaRefusal `json:"refused,omitempty"`
	// Gaps is the importer's own list of the constructs this program does
	// not implement, most common first — carried rather than re-derived,
	// because the importer's report IS the report.
	Gaps []string `json:"gaps,omitempty"`
	// Loud names rules that claim high or critical severity while saying
	// their false positives are unknown — the importer's finding, carried
	// because a library scored here deserves the same sentence an import
	// prints.
	Loud []string `json:"loud,omitempty"`
}

// theirSigma is their library as a runnable instrument plus the report of
// what importing it did.
type theirSigma struct {
	ref    *Reference
	report *SigmaReport
}

// loadTheirSigma reads a directory of Sigma rules through the existing
// importer and hands back the instrument they compile to.
//
// The refusals are the honest ones about the library it was handed: an
// empty directory is not an instrument that caught nothing, it is nothing
// to score with, and scoring it anyway would print an empty 100% — the
// naked percentage this package exists to refuse. A library none of whose
// rules import is the same refusal with the constructs named.
func loadTheirSigma(dir string) (*theirSigma, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading their Sigma rules: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") &&
			!strings.HasSuffix(name, ".yaml") {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("their-Sigma scoring needs a directory of "+
			"Sigma rules (.yml, .yaml) and %s holds none. An empty library "+
			"is not an instrument that caught nothing — it is nothing to "+
			"score with, and a miss rate over it would be the empty 100%% "+
			"this package refuses to print. Reference mode — the default — "+
			"remains the calibrated instrument that does ship", dir)
	}
	sort.Strings(names)
	files := make(map[string][]byte, len(names))
	h := sha256.New()
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		files[name] = body
		// The digest recipe is loadReference's: every file's name and
		// bytes, in name order, so a scorecard's their-rules digest means
		// the same bytes wherever the library lived.
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(body)
		h.Write([]byte{0})
	}

	// The one importer, called once. Its skips are its own type with the
	// construct named; they are carried to the scorecard verbatim rather
	// than re-derived, because the importer's report IS the report.
	rep := sigma.Import(files, sigma.Pipeline{})
	report := &SigmaReport{Dir: dir, Digest: hex.EncodeToString(h.Sum(nil)),
		Read: rep.Read, Imported: len(rep.Rules), Loud: rep.Loud,
		Gaps: rep.Gaps()}
	for _, s := range rep.Skipped {
		report.Refused = append(report.Refused, SigmaRefusal{
			Rule: s.Title, What: s.What, Why: s.Why, Ours: s.Ours})
	}
	if len(rep.Rules) == 0 {
		return nil, fmt.Errorf("none of the %d Sigma rule(s) in %s imported "+
			"(%s), so their controls would be scored by an instrument with "+
			"no rules and every scenario would read as a miss nothing could "+
			"have caught. The refusal is the report; fix or drop the "+
			"constructs and run again", rep.Read, dir,
			strings.Join(report.Gaps, "; "))
	}

	// Two rules sharing an id would merge their fire counts silently — the
	// quiet half-drop this package refuses everywhere — so the collision is
	// refused with both names.
	seen := map[string]string{}
	for _, r := range rep.Rules {
		id := strings.ToLower(r.ID)
		if prev, ok := seen[id]; ok {
			return nil, fmt.Errorf("two rules in %s share the id %s (%s, "+
				"%s); under one id their fires would count as one rule's, "+
				"and a join that cannot tell two rules apart cannot report "+
				"which one caught", dir, r.ID, prev, r.Title)
		}
		seen[id] = r.Title
	}

	// Their rules run as the reference does: compiled by runPass, asked of
	// every event, counted above ambient. All loud — Sigma has no quiet
	// tier, and inventing one here would be scoring a library this mode
	// never read. The digest is the library's own bytes, the same recipe
	// as the pack's, so the scorecard names their exact rules the way it
	// names the reference pack's.
	ref := &Reference{Name: ModeTheirSigma + ":" + filepath.Base(dir),
		Rules: rep.Rules, Digest: report.Digest,
		ruleQuiet: map[string]bool{}, corrIDs: map[string]bool{}}
	for _, r := range rep.Rules {
		ref.ruleQuiet[strings.ToLower(r.ID)] = false
	}
	return &theirSigma{ref: ref, report: report}, nil
}

// techniquesIntersect reports whether a scenario and one of their rules
// share a technique id. Case-folded, because the vocabulary's ids and the
// importer's harvest of tags.attack.* are the same ids in different cases.
func techniquesIntersect(scenario []string, rule []string) bool {
	for _, a := range scenario {
		for _, b := range rule {
			if strings.EqualFold(a, b) {
				return true
			}
		}
	}
	return false
}

// joinByTechnique builds the scenario's expectation rows for their mode:
// one must-alert per rule of theirs that tags a technique the scenario
// stages, met when that rule fired above ambient. Sorted by rule id, so
// two runs of the same library produce the same table.
func joinByTechnique(sc *Scenario, ref *Reference, attack,
	ambient *passResult) []ExpectRow {

	var out []ExpectRow
	for i := range ref.Rules {
		r := &ref.Rules[i]
		if !techniquesIntersect(sc.Technique, r.Technique) {
			continue
		}
		fires := attack.loud[r.ID] - ambient.loud[r.ID]
		out = append(out, ExpectRow{Kind: ExpectRule, ID: r.ID,
			Verdict: VerdictMustAlert, Met: fires > 0, Fires: fires})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// uncreditedFires names their rules that fired on the session above
// ambient while tagging none of its techniques. Recorded, not credited:
// the join is at technique level, and a catch by a rule that claims no
// technique this scenario stages is a fact the reader sees rather than a
// number the aggregate borrows.
func uncreditedFires(sc *Scenario, ref *Reference, attack,
	ambient *passResult) []string {

	var ids []string
	for i := range ref.Rules {
		r := &ref.Rules[i]
		if attack.loud[r.ID]-ambient.loud[r.ID] <= 0 {
			continue
		}
		if techniquesIntersect(sc.Technique, r.Technique) {
			continue
		}
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	return ids
}

// theirOutcome folds their per-rule rows into the scenario's tier:
// caught-at-their-rule when any intersecting rule fired — generosity
// toward the estate, with every quiet intersecting rule still on the
// record — and missed otherwise. An empty join (no rule of theirs tags
// anything the scenario stages) is the plain miss it is: nothing fired,
// and the row's note says the library never even claimed the coverage.
func theirOutcome(expects []ExpectRow) string {
	for _, x := range expects {
		if x.Met {
			return OutcomeCaughtAlert
		}
	}
	return OutcomeMissed
}

// theirRowNote is the sentence a their-mode row carries when the join had
// nothing to join or fired what it could not credit.
func theirRowNote(sc *Scenario, ref *Reference, attack,
	ambient *passResult, joined []ExpectRow) string {

	if len(joined) == 0 {
		return fmt.Sprintf("no rule in their library tags any technique "+
			"this scenario stages (%s): the library does not claim this "+
			"coverage, nothing fired, and the honest tier is the miss — "+
			"reported, not hidden", strings.Join(sc.Technique, ", "))
	}
	ids := uncreditedFires(sc, ref, attack, ambient)
	if len(ids) == 0 {
		return ""
	}
	return fmt.Sprintf("%d fire(s) above ambient from rules tagging none "+
		"of this scenario's techniques (%s) — recorded, not credited: the "+
		"join is at technique level", len(ids), strings.Join(ids, ", "))
}

// refusalWhy is the importer's sentence for a refusal with its own
// preamble trimmed — the sentence already named the rule and the
// construct on the line above it, and printing them twice is the kind of
// noise a reader skips, which is where refusals go to die.
func refusalWhy(s SigmaRefusal) string {
	lead := s.Rule + ": " + s.What + " is not implemented here — "
	if strings.HasPrefix(s.Why, lead) {
		return strings.TrimPrefix(s.Why, lead)
	}
	return s.Why
}
