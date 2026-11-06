// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fixture library a run is scored against: one rule that intersects
// the trifecta's techniques and fires on its events (caught at their
// rule), one that intersects and would not fire in a month of Mondays
// (the honest miss the mode reports rather than hides), and one
// aggregation the importer refuses (counted, never dropped).
const theirFixtures = "testdata/their-sigma"

// theirRun is a their-Sigma run of the named scenarios over the default
// base stream, at a fixed moment, so every assertion is over the same
// numbers a document would seal.
func theirRun(t *testing.T, dir string, ids ...string) *Scorecard {
	t.Helper()
	card, err := Run(RunOptions{ScoreMode: ModeTheirSigma + ":" + dir,
		Scenarios: ids, Seed: 7,
		Now: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("their-Sigma run over %s refused: %v", dir, err)
	}
	return card
}

// The join, scored honestly: the rule that fires catches the scenario
// with the quiet intersecting rule still on the record beside it; the
// aggregation is counted as import-refused with its construct named; the
// document names their library's digest and states the join's fidelity
// limit as a blind; the twin, under their rules, stays quiet.
func TestTheirSigmaScoresTheJoinHonestly(t *testing.T) {
	card := theirRun(t, theirFixtures, "agent.trifecta-mailroom-exfil")

	// The mode on the document carries the directory it scored, so the
	// reader of a number can name the library behind it.
	if !strings.HasPrefix(card.ScoreMode, ModeTheirSigma+":") {
		t.Fatalf("the document says scoring %q", card.ScoreMode)
	}
	ts := card.TheirSigma
	if ts == nil {
		t.Fatal("a their-Sigma document carries no import report; the " +
			"refusals would have nowhere to live but a footnote")
	}
	if ts.Read != 3 || ts.Imported != 2 || len(ts.Refused) != 1 {
		t.Fatalf("read %d, imported %d, refused %d; the fixture library is "+
			"3 rules of which 2 compile and 1 aggregates", ts.Read,
			ts.Imported, len(ts.Refused))
	}
	refused := ts.Refused[0]
	if !strings.Contains(refused.What, "aggregation") ||
		!strings.Contains(refused.Why, "threshold") {
		t.Errorf("the refusal (%+v) does not name the aggregation and why "+
			"the importer refuses it", refused)
	}
	if ts.Digest == "" || ts.Digest != card.PackDigest {
		t.Errorf("their digest %q is not the instrument digest the card "+
			"names (%q); names what ran, before how it went", ts.Digest,
			card.PackDigest)
	}
	if card.ModeBlind == "" || !strings.Contains(card.ModeBlind,
		"technique level, not rule id") ||
		!strings.Contains(card.ModeBlind, "still not fire") {
		t.Errorf("the mode blind (%q) does not state the join's limit: a "+
			"rule can intersect and still not fire, and the document owes "+
			"the reader that sentence", card.ModeBlind)
	}

	if len(card.Rows) != 1 {
		t.Fatalf("%d rows; one scenario was named", len(card.Rows))
	}
	row := card.Rows[0]
	if row.Outcome != OutcomeCaughtAlert {
		t.Fatalf("%s is %s under their rules; the egress rule tags T1041 "+
			"and fires on the session's egress leg", row.Scenario,
			row.Outcome)
	}
	byID := map[string]ExpectRow{}
	for _, x := range row.Expects {
		byID[x.ID] = x
	}
	if len(row.Expects) != 2 {
		t.Fatalf("%d expectation row(s); two of their rules intersect the "+
			"trifecta's techniques and both belong on the record", len(row.Expects))
	}
	caught := byID["their.egress-fresh-destination"]
	if !caught.Met || caught.Fires != 1 {
		t.Errorf("the egress rule: met %t, %d fire(s) above ambient; it "+
			"matches the session's http_post and nothing in the base "+
			"stream does", caught.Met, caught.Fires)
	}
	// The honest miss, kept beside the catch: a rule can tag the
	// technique and still not fire, and the row says so rather than
	// folding it away.
	missed := byID["their.egress-dns-tunnel"]
	if missed.Met || missed.Fires != 0 {
		t.Errorf("the dns-tunnel rule: met %t, %d fire(s); it tags T1041 "+
			"and matches nothing — the intersect-without-firing case the "+
			"blind promises to report, not hide", missed.Met, missed.Fires)
	}
	if row.Twin.Outcome != TwinQuiet {
		t.Errorf("the twin %sd under their rules; neither imported rule "+
			"reads anything the twin does", row.Twin.Outcome)
	}
	if card.Aggregate.MustAlert != 1 || card.Aggregate.Missed != 0 ||
		card.Aggregate.Caught != 1 {
		t.Errorf("aggregate %+v; one scenario, caught at their rule",
			card.Aggregate)
	}
	if card.AmbientFires != 0 {
		t.Errorf("%d ambient fire(s); neither imported rule matches the "+
			"base stream alone", card.AmbientFires)
	}
	if err := card.Verify(); err != nil {
		t.Fatalf("the document does not verify: %v", err)
	}
}

// A scenario none of their rules tags — the cost bomb stages ASI08 and
// LLM10, and Sigma's tag namespace is ATT&CK-shaped — is the plain miss
// it is: nothing fired, the library never claimed the coverage, and the
// row's note says both rather than filing the scenario under telemetry.
func TestTheirSigmaReportsAScenarioNothingOfTheirsTags(t *testing.T) {
	card := theirRun(t, theirFixtures, "agent.cost-bomb-loop")
	row := card.Rows[0]
	if row.Outcome != OutcomeMissed {
		t.Fatalf("%s is %s; no rule of theirs tags ASI08 or LLM10, nothing "+
			"fired, and the honest tier is the miss", row.Scenario,
			row.Outcome)
	}
	if !strings.Contains(row.Note, "no rule in their library tags") ||
		!strings.Contains(row.Note, "ASI08") {
		t.Errorf("the note (%q) does not say the library never claimed "+
			"this coverage", row.Note)
	}
	if len(row.Expects) != 0 {
		t.Errorf("%d expectation row(s) joined; the join found nothing",
			len(row.Expects))
	}
	if card.Aggregate.MustAlert != 1 || card.Aggregate.Missed != 1 {
		t.Errorf("aggregate %+v; an unclaimed scenario is in the miss "+
			"denominator, not excused from it", card.Aggregate)
	}
}

// Fires above ambient that the join cannot credit: a rule that tags none
// of the scenario's techniques but fires on the session anyway is
// recorded in the note, not borrowed by the aggregate — and the ambient
// count it had to beat is on the document, sealed.
func TestTheirSigmaRecordsWhatItCannotCreditAndSealsTheAmbientCount(t *testing.T) {
	card := theirRun(t, "testdata/their-sigma-quiet",
		"agent.trifecta-mailroom-exfil")
	row := card.Rows[0]
	// The mail reader tags T1567, which the trifecta does not stage, and
	// fires once above the three fetches the base stream's own refunder
	// sessions produce.
	if !strings.Contains(row.Note, "recorded, not credited") ||
		!strings.Contains(row.Note, "their.untrusted-mail-read") {
		t.Errorf("the note (%q) does not name the uncredited fire", row.Note)
	}
	if card.AmbientFires != 3 {
		t.Errorf("%d ambient fire(s) sealed on the document; the base "+
			"stream's three refunder fetches are what the join subtracts",
			card.AmbientFires)
	}
	for _, x := range row.Expects {
		if x.ID == "their.untrusted-mail-read" {
			t.Errorf("the uncredited rule was credited as an expectation " +
				"row; the join is at technique level and says so")
		}
	}
}

// The refusals about the library itself: a directory whose every rule is
// refused at import is not an instrument, and scoring it would read every
// scenario as a miss nothing could have caught; duplicate rule ids would
// merge two rules' fires into one name.
func TestTheirSigmaRefusesLibrariesItCannotScore(t *testing.T) {
	allRefused := t.TempDir()
	body, err := os.ReadFile(filepath.Join(theirFixtures,
		"refused-aggregation.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(allRefused, "only.yml"), body,
		0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Run(RunOptions{ScoreMode: ModeTheirSigma + ":" + allRefused,
		Scenarios: []string{"agent.trifecta-mailroom-exfil"}})
	if err == nil || !strings.Contains(err.Error(), "none of the 1") ||
		!strings.Contains(err.Error(), "aggregation") {
		t.Fatalf("a library of one aggregation gave %v; the refusal is the "+
			"report, with the construct named", err)
	}

	dup := t.TempDir()
	caught, err := os.ReadFile(filepath.Join(theirFixtures,
		"caught-egress.yml"))
	if err != nil {
		t.Fatal(err)
	}
	two := strings.Replace(string(caught), "their.egress-fresh-destination",
		"their.same-id", -1)
	for _, name := range []string{"one.yml", "two.yml"} {
		if err := os.WriteFile(filepath.Join(dup, name), []byte(two),
			0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, err = Run(RunOptions{ScoreMode: ModeTheirSigma + ":" + dup,
		Scenarios: []string{"agent.trifecta-mailroom-exfil"}})
	if err == nil || !strings.Contains(err.Error(), "share the id") {
		t.Fatalf("two rules under one id gave %v; their fires would count "+
			"as one rule's and the join could not say which caught", err)
	}

	// And one run cannot score two instruments at once.
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	_, err = Run(RunOptions{ScoreMode: ModeTheirSigma + ":" + theirFixtures,
		Reference: ref, Scenarios: []string{"agent.trifecta-mailroom-exfil"}})
	if err == nil || !strings.Contains(err.Error(), "two instruments") {
		t.Fatalf("a run handed both instruments gave %v", err)
	}
}

// Two their-Sigma runs over the same library, base and seed produce the
// same document — their rules are data with a digest, so the determinism
// a CI gate needs holds in this mode exactly as it holds in reference
// mode.
func TestTheirSigmaRunIsDeterministic(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	a, err := Run(RunOptions{ScoreMode: ModeTheirSigma + ":" + theirFixtures,
		Scenarios: []string{"agent.trifecta-mailroom-exfil"}, Seed: 7, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Run(RunOptions{ScoreMode: ModeTheirSigma + ":" + theirFixtures,
		Scenarios: []string{"agent.trifecta-mailroom-exfil"}, Seed: 7, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Scorecard{a, b} {
		c.Scratch = ""
		c.SHA256 = ""
		c.Signature = nil
		if err := c.seal(); err != nil {
			t.Fatal(err)
		}
	}
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	if string(ab) != string(bb) {
		t.Fatal("two their-Sigma runs of the same library produced " +
			"different documents; their rules have a digest and the " +
			"document is only worth sealing if it is the same bytes")
	}
}

// The summary carries the import accounting where a reader sees it: read,
// imported, refused with the construct named, and the mode blind under
// the scenario blinds.
func TestTheirSigmaSummarizeCarriesTheAccounting(t *testing.T) {
	card := theirRun(t, theirFixtures, "agent.trifecta-mailroom-exfil")
	s := card.Summarize()
	for _, want := range []string{
		"scoring " + ModeTheirSigma,
		"their Sigma rules " + theirFixtures,
		"3 read, 2 imported, 1 refused at import",
		"refused constructs are counted, never dropped",
		"scoring blind:",
		"technique level, not rule id",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the summary never says %q: %s", want, s)
		}
	}
	flat := strings.Join(strings.Fields(s), " ")
	if !strings.Contains(flat, "an aggregation in the condition") {
		t.Errorf("the refused construct is not named on the screen; the " +
			"import report is a first-class result, not a footnote")
	}
}
