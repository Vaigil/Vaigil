// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// The scorecard: the document a run writes, seals, and (when a key was
// supplied) signs; the file a third party verifies offline.
//
// Shaped like aertunbench's Results (internal/bench/run.go): it names what
// ran — corpus, digests, pack, mode, engine — before how it went, because a
// number without those names is a claim rather than a measurement. And it
// carries what the results document honestly says it lacks: dual signatures
// on day one, in this package's own context (decision 7).
const (
	// DocSchema is the document's versioned schema name. A document from
	// another schema is refused rather than best-effort rendered.
	DocSchema = "aertun/windtunnel-scorecard/v1"
	// Engine is the wind tunnel engine's own version: bumped when the
	// splicing or scoring semantics change, because a scorecard's numbers
	// are only comparable against the engine that produced them.
	Engine = "windtunnel-1"
)

// attributionCaveat is stated on every document, in the blind tradition: a
// replay has no detection wall-clock, and the number that stands in for one
// is a property of the rule windows, not of anybody's shifts.
const attributionCaveat = "Attribution times are event-time-to-attribution: " +
	"the gap between the step that completed a pattern and the window that " +
	"attributed it. They are a property of the rule windows, not of a SOC's " +
	"shifts — a replay has no detection wall-clock, and nothing here should " +
	"be read as a response-time promise."

// ExpectRow is one expectation's verdict.
type ExpectRow struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Verdict string `json:"verdict"`
	Met     bool   `json:"met"`
	// Fires is the count above ambient: what this session added.
	Fires int `json:"fires"`
	// MissKind says which kind of miss a missed must-alert was.
	MissKind string `json:"miss_kind,omitempty"`
	// AttributionSecs is the event-time-to-attribution for a met must-alert
	// expectation; zero for a rule, whose match is the event itself.
	AttributionSecs float64 `json:"attribution_secs,omitempty"`
	// Note carries the honest particulars: a lateness miss's count, a
	// deleted rule's absence.
	Note string `json:"note,omitempty"`
}

// TwinOutcome is the benign twin's result: the precision axis.
type TwinOutcome struct {
	ID            string `json:"id"`
	Outcome       string `json:"outcome"`
	SessionEvents int    `json:"session_events"`
}

// Row is one scenario's whole result.
type Row struct {
	Scenario string `json:"scenario"`
	Digest   string `json:"digest"`
	Family   string `json:"family"`
	// Techniques are what this scenario stages, for the coverage grid.
	Techniques []string `json:"technique"`
	Outcome    string   `json:"outcome"`
	// SessionEvents is how many events the spliced session expanded to.
	SessionEvents int         `json:"session_events"`
	Expects       []ExpectRow `json:"expects"`
	Twin          TwinOutcome `json:"twin"`
}

// missKind is the scenario-level miss kind: the lateness kind when any
// missed correlation reported it, else a content miss.
func (r *Row) MissKind() string {
	for _, x := range r.Expects {
		if !x.Met && x.MissKind == MissLateness {
			return MissLateness
		}
	}
	return MissContent
}

// ScenarioDigest names one scenario and the exact bytes it came from.
type ScenarioDigest struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
	Twin   string `json:"twin"`
}

// Blind is one scenario's declared blind spot, restated on the document so
// the reader of a number can read what the number does not cover.
type Blind struct {
	Scenario string `json:"scenario"`
	Blind    string `json:"blind"`
}

// Aggregate is the scorecard's numbers: the primary miss rate with its
// Wilson bounds, and the counts that qualify it.
type Aggregate struct {
	Scenarios int `json:"scenarios"`
	// MustAlert is the denominator: scenarios carrying a must-alert
	// expectation, the only ones a miss rate may be read over.
	MustAlert int `json:"must_alert_scenarios"`
	Missed    int `json:"missed"`
	// MissedLateness splits the misses: windows that closed before the
	// completing event arrived.
	MissedLateness int `json:"missed_lateness"`
	Caught         int `json:"caught_alert"`
	TelemetryOnly  int `json:"caught_telemetry_only"`
	WronglyQuiet   int `json:"wrongly_quiet"`
	TwinFires      int `json:"twin_false_fires"`

	MissRate     float64 `json:"miss_rate"`
	MissRateLow  float64 `json:"miss_rate_wilson_low"`
	MissRateHigh float64 `json:"miss_rate_wilson_high"`
}

// FamilyRow is the family grid: what ran, per family.
type FamilyRow struct {
	Family        string `json:"family"`
	Tested        int    `json:"tested"`
	Caught        int    `json:"caught_alert"`
	Missed        int    `json:"missed"`
	TelemetryOnly int    `json:"telemetry_only"`
	WronglyQuiet  int    `json:"wrongly_quiet"`
	TwinFires     int    `json:"twin_false_fires"`
}

// TechniqueRow is the technique grid. Caught means a scenario that stages
// the technique was caught at alert tier — and per the pack's own rule
// comments, a technique marked covered does not reveal whether detections
// reliably identify all its variations; the grid is navigation, never a
// score.
type TechniqueRow struct {
	Technique string `json:"technique"`
	Tested    int    `json:"tested"`
	Caught    int    `json:"caught"`
}

// Scorecard is the sealed document. Field order is the reading order: what
// ran, then what happened.
type Scorecard struct {
	Schema    string `json:"schema"`
	Mode      string `json:"mode"`
	Engine    string `json:"engine"`
	ScoreMode string `json:"score_mode"`
	Corpus    string `json:"corpus"`
	Seed      int64  `json:"seed"`

	Base       string `json:"base"`
	BaseDigest string `json:"base_digest"`
	BaseEvents int    `json:"base_events"`
	Pack       string `json:"pack"`
	PackDigest string `json:"pack_digest"`

	Scenarios []ScenarioDigest `json:"scenarios"`

	Rows       []Row          `json:"rows"`
	Aggregate  *Aggregate     `json:"aggregate"`
	Families   []FamilyRow    `json:"families"`
	Techniques []TechniqueRow `json:"techniques"`
	Blinds     []Blind        `json:"blinds"`
	Caveat     string         `json:"caveat"`

	// Scratch names where the scratch spools were written, so an operator
	// can inspect the exact streams that were scored.
	Scratch     string    `json:"scratch"`
	GeneratedAt time.Time `json:"generated_at"`

	// SHA256 is the document's own digest, over the canonical form with the
	// digest empty and the signature absent: a check against sloppiness, so
	// a rendered number can be traced to the file it came from and an edited
	// file refuses to render. The signature is the check against forgery.
	SHA256 string `json:"sha256"`
	// Signature is both algorithms over that digest, in this package's own
	// context. Nil on an unsigned document, which says so when rendered.
	Signature *ScorecardSignature `json:"signature,omitempty"`
}

// digestBytes is the canonical form a digest is taken over and a signature
// covers: the whole document, digest empty and signature absent, compact
// JSON — deterministic by Go's encoder: fields in declaration order, no
// insignificant whitespace. The receiver is not mutated, so verifying a
// signed document does not strip its own signature.
func (c *Scorecard) digestBytes() ([]byte, error) {
	body := *c
	body.SHA256 = ""
	body.Signature = nil
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(buf.String(), "\n")), nil
}

// seal fills the document's own digest. Called before any signature is
// made: the signature covers the digest, and the digest covers everything
// else, so an edit anywhere is caught twice.
func (c *Scorecard) seal() error {
	b, err := c.digestBytes()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	c.SHA256 = hex.EncodeToString(sum[:])
	return nil
}

// Verify checks a document against its own digest, and its schema. This is
// the check a rendered number can be traced by; the signature check is
// VerifyScorecard's, and the verify entry point runs both.
func (c *Scorecard) Verify() error {
	if c.Schema != DocSchema {
		return fmt.Errorf("the document's schema is %q; this build reads %q",
			c.Schema, DocSchema)
	}
	b, err := c.digestBytes()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	got := hex.EncodeToString(sum[:])
	if got != c.SHA256 {
		return fmt.Errorf("the document's digest is %s and its contents hash "+
			"to %s: it has been edited since it was written, and nothing "+
			"rendered from it can be cited", c.SHA256, got)
	}
	return nil
}

// Document renders the scorecard as the bytes a run writes: indented, HTML
// unescaped, one field per line — the same conventions as the results
// document, so a scorecard diffs the way the corpus diffs.
func (c *Scorecard) Document() ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// shortDigest is a digest the way a person compares one.
func shortDigest(d string) string {
	if len(d) <= 12 {
		return d
	}
	return d[:12] + "…"
}

// pct is a rate the way a person reads one at a glance.
func pct(v float64) string { return fmt.Sprintf("%.1f%%", v*100) }

// Summarize is the run in words, for a terminal: what ran first, then the
// per-scenario tiers, then the aggregate with its bounds, then the grids,
// the twins, the blinds — one screen a founder can read, one file an
// insurer can verify. Nothing here is a claim the document does not carry.
func (c *Scorecard) Summarize() string {
	var b strings.Builder
	fmt.Fprintf(&b, "wind tunnel, mode %s, scoring %s, engine %s\n", c.Mode,
		c.ScoreMode, c.Engine)
	fmt.Fprintf(&b, "  base stream %s (%d event(s), digest %s)\n", c.Base,
		c.BaseEvents, shortDigest(c.BaseDigest))
	fmt.Fprintf(&b, "  reference pack %s (digest %s), corpus %s, seed %d\n",
		c.Pack, shortDigest(c.PackDigest), c.Corpus, c.Seed)
	for _, s := range c.Scenarios {
		fmt.Fprintf(&b, "      %-40s %s (twin %s)\n", s.ID,
			shortDigest(s.Digest), s.Twin)
	}
	fmt.Fprintf(&b, "  %d scenario(s):\n", len(c.Rows))
	for _, r := range c.Rows {
		note := ""
		switch {
		case r.Outcome == OutcomeMissed && r.MissKind() == MissLateness:
			note = " (lateness: the window closed before the completing " +
				"event arrived)"
		case r.Outcome == OutcomeMissed:
			note = " (content)"
		}
		fmt.Fprintf(&b, "    %-38s %-18s%s\n", r.Scenario, r.Outcome, note)
		for _, x := range r.Expects {
			mark := "met"
			if !x.Met {
				mark = "UNMET"
			}
			fmt.Fprintf(&b, "        %-12s %-28s %-14s %s", x.Kind, x.ID,
				x.Verdict, mark)
			if x.Verdict == VerdictMustAlert && x.Met {
				if x.Kind == ExpectRule {
					fmt.Fprintf(&b, ", matched at the event")
				} else {
					fmt.Fprintf(&b, ", attributed %.0fs after the completing step",
						x.AttributionSecs)
				}
			}
			if x.Note != "" {
				fmt.Fprintf(&b, "\n            %s", x.Note)
			}
			fmt.Fprintf(&b, "\n")
		}
		twin := "quiet"
		if r.Twin.Outcome == TwinFalseFire {
			twin = "FALSE FIRE"
		}
		fmt.Fprintf(&b, "        twin %-38s %s\n", r.Twin.ID, twin)
	}
	a := c.Aggregate
	fmt.Fprintf(&b, "  missed %d of %d must-alert scenario(s) (%s, 95%% "+
		"Wilson %.1f%% to %.1f%%)\n", a.Missed, a.MustAlert,
		pct(a.MissRate), a.MissRateLow*100, a.MissRateHigh*100)
	fmt.Fprintf(&b, "  %d caught at alert, %d telemetry-only, %d "+
		"wrongly-quiet; %d of the misses were lateness\n", a.Caught,
		a.TelemetryOnly, a.WronglyQuiet, a.MissedLateness)
	fmt.Fprintf(&b, "  benign twins: %d false fire(s) of %d\n", a.TwinFires,
		a.Scenarios)
	fmt.Fprintf(&b, "  families: ")
	for i, f := range c.Families {
		if i > 0 {
			fmt.Fprintf(&b, ", ")
		}
		fmt.Fprintf(&b, "%s %d/%d", f.Family, f.Caught, f.Tested)
	}
	fmt.Fprintf(&b, "\n  techniques: ")
	for i, t := range c.Techniques {
		if i > 0 {
			fmt.Fprintf(&b, ", ")
		}
		fmt.Fprintf(&b, "%s %d/%d", t.Technique, t.Caught, t.Tested)
	}
	fmt.Fprintf(&b, "\n")
	if len(c.Blinds) > 0 {
		fmt.Fprintf(&b, "  declared blinds:\n")
		for _, bl := range c.Blinds {
			fmt.Fprintf(&b, "    %s: %s\n", bl.Scenario, wrap(bl.Blind))
		}
	}
	fmt.Fprintf(&b, "  %s\n", wrap(c.Caveat))
	sig := "unsigned: no key was supplied, and this document makes no claim " +
		"a signature would back"
	if c.Signature != nil {
		sig = "dual-signed (Ed25519 and ML-DSA-65) by key " +
			c.Signature.KeyID + ", context " + ScorecardContext
	}
	fmt.Fprintf(&b, "  %s\n  document sha256 %s; generated %s; scratch %s\n",
		sig, shortDigest(c.SHA256),
		c.GeneratedAt.Format(time.RFC3339), c.Scratch)
	return b.String()
}

// wrap breaks a long sentence for the terminal, the way the help wraps.
func wrap(s string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > 72 {
			lines = append(lines, line)
			line = w
			continue
		}
		line += " " + w
	}
	lines = append(lines, line)
	return strings.Join(lines, "\n    ")
}
