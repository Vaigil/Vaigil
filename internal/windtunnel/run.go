// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aeroprove/aeroprove/internal/correlate"
	"github.com/aeroprove/aeroprove/internal/detect"
	"github.com/aeroprove/aeroprove/internal/pack"
	"github.com/aeroprove/aeroprove/internal/spool"
	"github.com/aeroprove/aeroprove/internal/telemetry"
)

// The run: splice, replay, join, score.
//
// The replay is the shadow replay's shape (internal/pack/shadow.go), which is
// the detect run's shape minus everything that writes: the reference pack's
// rules compiled once and asked of every event in arrival order, the
// correlations' engines fed from the matches, and nothing recorded in any
// finding register, no cursor moved, no suppression consulted. The wind
// tunnel has no findings to raise — it is measuring the raising.
//
// # Where this replay is stricter than the shadow
//
// The shadow replays with no watermark on the way in and closes at the end —
// right for asking "what would the last seven days have raised". The wind
// tunnel asks a different question — did the controls catch this session —
// and answers it with the live system's own semantics: each event is observed
// against the watermark its arrivals have earned (newest arrival less the
// observed 99th-percentile delay, the run's own rule), so an event that
// lands after its window closed is dropped and counted late exactly as the
// live engine drops and counts it. Then, the recording being over, the
// windows still open are decided — the live system's later runs would close
// every one of them, and nothing further can arrive in a replay. A miss
// caused by that drop is a lateness miss, and the scorecard says which kind
// of miss it was: a finding about the lateness budget, not about the rules.

// passResult is what one replay of the rules over one stream found.
type passResult struct {
	events int
	// loud counts loud rule fires; quiet counts quiet rule matches, which
	// raise nothing themselves and are the correlations' to count.
	loud  map[string]int
	quiet map[string]int
	// hits is each correlation's met windows; late is how many events the
	// engine dropped because their window had already closed.
	hits map[string][]correlate.Hit
	late map[string]int
	// matched remembers which rules each placed event matched, for the
	// attribution arithmetic. Keyed by the event's arrival instant.
	matched map[time.Time][]string
}

// runPass replays the reference pack over a scratch spool's whole stream.
//
// budget is the arrival delay the watermark waits behind — the 99th
// percentile of the stream's own observed lateness, computed by the caller
// from the same stream.
func runPass(sp *spool.Spool, ref *Reference, budget time.Duration) (*passResult, error) {
	progs := make([]*detect.Program, 0, len(ref.Rules))
	for _, r := range ref.Rules {
		p, err := r.Compile()
		if err != nil {
			return nil, fmt.Errorf("%s cannot be replayed: %w", r.ID, err)
		}
		progs = append(progs, p)
	}
	engines := make([]*correlate.Engine, 0, len(ref.Corrs))
	for _, c := range ref.Corrs {
		e, err := correlate.New(c)
		if err != nil {
			return nil, fmt.Errorf("%s cannot be replayed: %w", c.ID, err)
		}
		engines = append(engines, e)
	}

	res := &passResult{loud: map[string]int{}, quiet: map[string]int{},
		hits: map[string][]correlate.Hit{}, late: map[string]int{},
		matched: map[time.Time][]string{}}
	wm := time.Time{}
	err := sp.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		res.events++
		// The watermark this arrival has earned: everything older than the
		// stream's own 99th-percentile delay has been delivered.
		if w := e.Received.Add(-budget); w.After(wm) {
			wm = w
		}
		f := e.Fields()
		for _, p := range progs {
			if !p.MatchesFields(e.Source, f) {
				continue
			}
			if p.Quiet {
				res.quiet[p.ID]++
			} else {
				res.loud[p.ID]++
			}
			res.matched[e.Received] = append(res.matched[e.Received], p.ID)
			for _, eng := range engines {
				if !eng.Watches(p.ID) {
					continue
				}
				if oerr := eng.Observe(correlate.Seen{Rule: p.ID, Event: e},
					wm); oerr != nil {
					return oerr
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, eng := range engines {
		res.hits[eng.Rule().ID] = eng.Flush()
		res.late[eng.Rule().ID] = eng.Late()
	}
	return res, nil
}

// The outcome tiers, categorical in the MITRE Evaluations tradition:
// recorded, never dressed up as a number (decision 4). Telemetry is never
// counted as caught; a miss says which kind it was; the twin axis is
// reported beside, not folded in.
const (
	// OutcomeCaughtAlert: a named detection alerted within the window.
	OutcomeCaughtAlert = "caught-alert"
	// OutcomeCaughtTelemetry: the events are visible in the stream the stack
	// retains and nothing alerted. Recorded, never counted as caught.
	OutcomeCaughtTelemetry = "caught-telemetry"
	// OutcomeMissed: no detection, and the scorecard says whether the window
	// closed before the completing event arrived.
	OutcomeMissed = "missed"
	// OutcomeWronglyQuiet: a declared-quiet leg fired. A stack that alerts
	// on every untrusted read is drowning its analysts — Axelsson again.
	OutcomeWronglyQuiet = "wrongly-quiet"
)

// The twin's outcome: quiet, or the precision axis failed.
const (
	TwinQuiet     = "quiet"
	TwinFalseFire = "false-fire"
)

// The miss kinds: a lateness miss is a finding about the watermark budget,
// a content miss is a finding about the rules. Conflating them is how a
// replay flatters itself.
const (
	MissLateness = "lateness"
	MissContent  = "content"
)

// The scoring modes (decision 6). Reference mode is the calibrated
// instrument and the only one this build runs; the their-controls modes are
// named here so their refusal is a named refusal, not a missing feature.
const (
	ModeReference  = "reference"
	ModeTheirSigma = "their-sigma"
	ModeTheirAlert = "their-alerts"
)

// RunOptions is what a run needs. Nothing in it opens the live store: the
// base stream is a file or the embedded fixture, the scratch spool is a
// directory the operator named or a fresh temporary one, and the only key
// read is one the operator pointed at.
type RunOptions struct {
	// Scenarios names scenario ids; empty means the whole seed corpus.
	Scenarios []string
	// Base is the recorded base stream: a JSONL file, a directory of spool
	// segments, or empty for the embedded fixture. A live endpoint here is
	// refused by code (decision 8) — replay is the safety story, and phase 1
	// has no live mode to be talked into.
	Base string
	// Into is the scratch root. Empty means a fresh temporary directory.
	Into string
	// Seed moves the clocks — the arrival-delay draws — and nothing else:
	// the session identities come from the scenario files, so a digest names
	// the same session whatever seed it ran under.
	Seed int64
	// ScoreMode is the scoring mode; empty means reference.
	ScoreMode string
	// Now stamps the document.
	Now time.Time
	// Signer, when set, dual-signs the sealed scorecard in the wind tunnel's
	// own context. Nil writes an unsigned document that says so.
	Signer *pack.Key
}

// Run splices, replays, joins and scores, and returns the sealed scorecard.
func Run(opts RunOptions) (*Scorecard, error) {
	// The live-target refusal, in code. A URL where a stream path belongs is
	// somebody asking the wind tunnel to fire at a staging collector, and no
	// scenario this build can load is allowed there: they are all
	// synthetic-only, replay is the whole safety story, and the refusal is
	// here rather than in the CLI so no caller can route around it.
	for _, prefix := range []string{"http://", "https://", "otlp://", "grpc://"} {
		if strings.HasPrefix(strings.ToLower(opts.Base), prefix) {
			return nil, fmt.Errorf("refused: %s names a live endpoint, and "+
				"every scenario this build loads is synthetic-only — replay "+
				"is the safety story, by construction. Live targets arrive "+
				"with phase 3's containment, and nothing in this build can "+
				"be configured into them", opts.Base)
		}
	}
	mode := opts.ScoreMode
	if mode == "" {
		mode = ModeReference
	}
	switch {
	case mode == ModeReference:
	case strings.HasPrefix(mode, ModeTheirSigma+":"):
		return nil, fmt.Errorf("%s scoring arrives in phase 2: it imports the "+
			"organisation's own Sigma rules through the existing importer and "+
			"joins at technique level. Running it now would measure nothing "+
			"while claiming to measure their controls, so it is refused "+
			"rather than half-run. Reference mode — the default — measures "+
			"what this program's own pack caught on the stream, as the "+
			"calibrated instrument", ModeTheirSigma)
	case strings.HasPrefix(mode, ModeTheirAlert+":"):
		return nil, fmt.Errorf("%s scoring arrives in phase 2: it reads the "+
			"organisation's alert output for the replay window in OCSF and "+
			"joins by time and technique. Running it now would measure "+
			"nothing while claiming to measure their pipeline, so it is "+
			"refused rather than half-run. Reference mode — the default — "+
			"measures what this program's own pack caught on the stream, as "+
			"the calibrated instrument", ModeTheirAlert)
	default:
		return nil, fmt.Errorf("%q is not a scoring mode; the closed set is "+
			"%s (this build), %s:DIR and %s:FILE (phase 2)", mode,
			ModeReference, ModeTheirSigma, ModeTheirAlert)
	}

	ref, err := LoadReference()
	if err != nil {
		return nil, err
	}
	corpus, err := Corpus(ref)
	if err != nil {
		return nil, err
	}
	var selected []*Loaded
	if len(opts.Scenarios) == 0 {
		selected = corpus
	} else {
		for _, id := range opts.Scenarios {
			l := ByID(corpus, id)
			if l == nil {
				return nil, fmt.Errorf("there is no scenario called %q in the "+
					"seed corpus; windtunnel list-scenarios names what ships",
					id)
			}
			selected = append(selected, l)
		}
	}

	baseName, base := FixtureName, DefaultBase()
	if opts.Base != "" {
		base, err = ReadBase(opts.Base)
		if err != nil {
			return nil, fmt.Errorf("reading the base stream: %w", err)
		}
		baseName = filepath.Base(opts.Base)
	}
	baseDigest, baseEvents := BaseDigest(base)

	into := opts.Into
	if into == "" {
		into, err = os.MkdirTemp("", "windtunnel-")
		if err != nil {
			return nil, err
		}
	} else if err := os.MkdirAll(into, 0o700); err != nil {
		return nil, err
	}

	// The ambient pass: the same rules over the base stream alone. Any alert
	// it raises is the estate's, not the scenario's, and every join below
	// subtracts it before crediting the scenario with anything — the
	// calibration statement, made arithmetic.
	ambientSp, err := WriteScratch(filepath.Join(into, "ambient"), base)
	if err != nil {
		return nil, err
	}
	ambientBudget := latenessHistogram(base).quantile(0.99)
	ambient, err := runPass(ambientSp, ref, ambientBudget)
	if err != nil {
		return nil, fmt.Errorf("the ambient pass: %w", err)
	}
	ambientSp.Close()

	card := &Scorecard{Schema: DocSchema, Mode: PhaseReplay, Engine: Engine,
		ScoreMode: mode, Base: baseName, BaseDigest: baseDigest,
		BaseEvents: baseEvents, Pack: ref.Name, PackDigest: ref.Digest,
		Corpus: CorpusName, Seed: opts.Seed, Scratch: into,
		GeneratedAt: opts.Now.UTC(),
		Caveat:      attributionCaveat}
	for _, l := range selected {
		row, err := runOne(l, ref, base, into, opts.Seed, ambient)
		if err != nil {
			return nil, err
		}
		card.Rows = append(card.Rows, *row)
		card.Scenarios = append(card.Scenarios, ScenarioDigest{
			ID: l.Scenario.ID, Digest: l.Digest, Twin: l.Scenario.Twin.ID})
		card.Blinds = append(card.Blinds, Blind{Scenario: l.Scenario.ID,
			Blind: l.Scenario.Blind})
	}
	if err := card.aggregate(); err != nil {
		return nil, err
	}
	if err := card.seal(); err != nil {
		return nil, err
	}
	if opts.Signer != nil {
		sig, serr := SignScorecard(card, opts.Signer)
		if serr != nil {
			return nil, serr
		}
		card.Signature = &sig
	}
	return card, nil
}

// runOne runs one scenario and its twin over the base stream and scores
// both by the id join.
func runOne(l *Loaded, ref *Reference, base []telemetry.Event, into string,
	seed int64, ambient *passResult) (*Row, error) {

	sc := l.Scenario
	if err := Preflight(sc, base); err != nil {
		return nil, err
	}
	anchor, err := DefaultAnchor(base)
	if err != nil {
		return nil, err
	}

	pass := func(steps []Step, suffix string) (*passResult, *Placed, error) {
		placed, perr := Place(sc, steps, base, seed, anchor)
		if perr != nil {
			return nil, nil, perr
		}
		stream := Interleave(base, placed.Events)
		dir := filepath.Join(into, sanitize(sc.ID)+suffix)
		sp, werr := WriteScratch(dir, stream)
		if werr != nil {
			return nil, nil, werr
		}
		defer sp.Close()
		budget := latenessHistogram(stream).quantile(0.99)
		res, rerr := runPass(sp, ref, budget)
		if rerr != nil {
			return nil, nil, rerr
		}
		return res, placed, nil
	}

	attack, placed, err := pass(sc.Steps, "")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", sc.ID, err)
	}
	twinPass, twinPlaced, err := pass(sc.Twin.Steps, "--twin")
	if err != nil {
		return nil, fmt.Errorf("%s, its twin: %w", sc.ID, err)
	}

	row := &Row{Scenario: sc.ID, Digest: l.Digest, Family: sc.Family,
		Techniques: sc.Technique, SessionEvents: len(placed.Events),
		Twin: TwinOutcome{ID: sc.Twin.ID, Outcome: TwinQuiet}}
	for _, x := range sc.Expects {
		row.Expects = append(row.Expects, *scoreExpect(sc, x, ref, attack,
			ambient, placed))
	}
	row.Outcome = outcomeOf(row.Expects)

	// The twin: any new alert is a false fire — the precision axis.
	twinFired := false
	for id, n := range twinPass.loud {
		if n > ambient.loud[id] {
			twinFired = true
		}
	}
	for id, hits := range twinPass.hits {
		if len(hits) > len(ambient.hits[id]) {
			twinFired = true
		}
	}
	if twinFired {
		row.Twin.Outcome = TwinFalseFire
	}
	row.Twin.SessionEvents = len(twinPlaced.Events)
	return row, nil
}

// scoreExpect joins one expectation to what the replay found. The join is
// by id — the highest-fidelity join there is, because the scenario and the
// pack share the vocabulary — and every count is the count above ambient.
func scoreExpect(sc *Scenario, x Expect, ref *Reference, attack,
	ambient *passResult, placed *Placed) *ExpectRow {

	r := &ExpectRow{Kind: x.Kind, ID: x.ID, Verdict: x.Verdict}
	newLoud := func(id string) int { return attack.loud[id] - ambient.loud[id] }
	newHits := func(id string) int {
		return len(attack.hits[id]) - len(ambient.hits[id])
	}
	switch x.Kind {
	case ExpectRule:
		if !ref.has(x.Kind, x.ID) {
			// The honesty rule: a rule the pack no longer carries is a miss
			// the scorecard reports, never an error that stops the run. The
			// build-time corpus validation catches the drift for the shipped
			// corpus; a third-party pack scored here gets the truth instead
			// of a refusal. The one verdict this must not satisfy is
			// stays-quiet — a deleted rule cannot fire, and letting its
			// absence count as quiet would mean deleting rules improves a
			// scorecard.
			r.Met = false
			if x.Verdict == VerdictStaysQuiet {
				r.Note = "the rule is not in the reference pack, so nothing " +
					"proves the session stayed quiet — a rule cannot fire " +
					"from outside the pack, and deleting one must not " +
					"improve a scorecard"
			} else {
				r.Note = "the rule is not in the reference pack: deleted or " +
					"renamed since the scenario was written, and nothing it " +
					"could have caught was caught"
			}
			return r
		}
		switch x.Verdict {
		case VerdictMustAlert:
			r.Fires = newLoud(x.ID)
			r.Met = r.Fires > 0
			if r.Met {
				r.AttributionSecs = 0
			}
		case VerdictFiresQuietly:
			r.Fires = attack.quiet[x.ID] - ambient.quiet[x.ID]
			r.Met = r.Fires > 0
		case VerdictStaysQuiet:
			r.Fires = newLoud(x.ID)
			r.Met = r.Fires == 0
		}
	case ExpectCorrelation:
		if !ref.has(x.Kind, x.ID) {
			r.Met = false
			if x.Verdict == VerdictStaysQuiet {
				r.Note = "the correlation is not in the reference pack, so " +
					"nothing proves the session stayed quiet — deleting the " +
					"window must not improve a scorecard"
			} else {
				r.Note = "the correlation is not in the reference pack: " +
					"deleted or renamed since the scenario was written, and " +
					"the window it would have closed never opened"
			}
			return r
		}
		r.Fires = newHits(x.ID)
		switch x.Verdict {
		case VerdictMustAlert:
			r.Met = r.Fires > 0
			if r.Met {
				r.AttributionSecs = attributionSecs(x.ID, ref, attack,
					ambient, placed)
			} else if late := attack.late[x.ID] - ambient.late[x.ID]; late > 0 {
				// The two-clock edge, told apart by name: the window closed
				// before the completing event arrived, which is a finding
				// about the lateness budget, not about the content.
				r.MissKind = MissLateness
				r.Note = fmt.Sprintf("%d event(s) of this session arrived "+
					"after their window had closed under the stream's own "+
					"watermark: a lateness miss, not a content miss", late)
			} else {
				r.MissKind = MissContent
			}
		case VerdictStaysQuiet:
			r.Met = r.Fires == 0
		}
	}
	return r
}

// outcomeOf folds a scenario's expectation rows into its categorical tier.
func outcomeOf(expects []ExpectRow) string {
	var unmetMust, unmetStay bool
	for _, x := range expects {
		if x.Met {
			continue
		}
		switch x.Verdict {
		case VerdictMustAlert:
			unmetMust = true
		case VerdictStaysQuiet:
			unmetStay = true
		}
	}
	switch {
	case unmetMust:
		return OutcomeMissed
	case unmetStay:
		return OutcomeWronglyQuiet
	}
	for _, x := range expects {
		if x.Verdict == VerdictMustAlert && x.Met {
			return OutcomeCaughtAlert
		}
	}
	return OutcomeCaughtTelemetry
}

// attributionSecs is the event-time-to-attribution for a met correlation:
// the gap between the step that completed the pattern and the window that
// attributed it (decision 9). A property of the rule's own windows — never
// of anybody's shifts, and the document says so in its caveat.
func attributionSecs(corrID string, ref *Reference, attack,
	ambient *passResult, placed *Placed) float64 {

	var rule *correlate.Rule
	for i := range ref.Corrs {
		if strings.EqualFold(ref.Corrs[i].ID, corrID) {
			rule = &ref.Corrs[i]
			break
		}
	}
	if rule == nil || len(placed.Events) == 0 {
		return 0
	}
	hits := attack.hits[corrID]
	if len(hits) <= len(ambient.hits[corrID]) {
		return 0
	}
	hit := hits[len(ambient.hits[corrID])]
	// The completing event: the session's last event, inside the hit's
	// window, that matched the correlation's last rule — the one whose
	// arrival the window was waiting on.
	want := rule.Rules[len(rule.Rules)-1]
	var completing *telemetry.Event
	for i := range placed.Events {
		e := placed.Events[i]
		if e.Time.Before(hit.From) || !e.Time.Before(hit.To) {
			continue
		}
		for _, m := range attack.matched[e.Received] {
			if strings.EqualFold(m, want) {
				completing = &placed.Events[i]
			}
		}
	}
	if completing == nil {
		return 0
	}
	d := hit.To.Sub(completing.Time).Seconds()
	if d < 0 {
		d = 0
	}
	return d
}

// sanitize makes a scenario id safe as one path element.
func sanitize(id string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			return r
		}
		return '-'
	}, id)
}

// sortRows orders the scorecard's rows by scenario id, so two documents
// diff as tables rather than as maps.
func sortRows(rows []Row) {
	sort.Slice(rows, func(i, j int) bool { return rows[i].Scenario < rows[j].Scenario })
}
