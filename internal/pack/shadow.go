// SPDX-FileCopyrightText: 2026 Rashik Adhikari
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

	"github.com/aertun/aertun/internal/correlate"
	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// The shadow replay: the customer-side empirical gate, between verification
// and placement.
//
// CrowdStrike's July 2024 content passed a Content Validator that agreed with
// a definition file and disagreed with the runtime, and it passed twelve
// synthetic test cases — and neither of those facts said anything about what
// eight and a half million real machines would do with it. The countermeasure
// is not a better synthetic test. It is that the customer's own installation
// is the last gate, the gate is empirical — replay the candidate content
// against the customer's real stored telemetry — and the failure mode is a
// refusal (here) or a rollback (later), never an outage. Every customer is
// their own canary ring; this is the ring's rehearsal.
//
// # Trial-ring semantics, held to exactly
//
// The replay runs the pack's rules and correlations and the installed
// equivalents over the window and records what they WOULD have done. Nothing
// is recorded in the finding register, nothing is queued, no cursor moves, no
// suppression is consulted or counted against, no ring is read: the same
// posture a trial rule has today (internal/detect/tuning.go), applied to
// content that is not installed yet. The counts are would-have-fired — raw
// matches on both sides of the comparison, so the delta asks one question of
// both: is the pack louder than what it replaces, on this estate's own week?
//
// Suppressions and rings are deliberately NOT applied to either side. They are
// this organisation's verdicts on the content being replaced, and folding
// them into the baseline would make a suppressed (or switched-off) rule look
// like silence and any successor look like an explosion. The gate measures
// the content; the queue's filters stay the organisation's.
//
// # The budget
//
// A pack that would flood the queue refuses, naming the numbers and the
// flags that override them. The defaults are reasoned about in the constants
// below, and the one principle above all of them: a budget that can be
// configured into meaninglessness will be (the AcceptSingle argument), so the
// flags here replace a number with a number an operator typed — they cannot
// remove the check.

const (
	// ShadowDays is the default window: the last seven days of stored
	// telemetry. A week holds the weekly cycle a rule trips over — the
	// Saturday backup that looks like exfiltration, the Monday patch
	// restart, the Friday certificate renewal — which a day never shows
	// and a month dilutes. The design's own default (§5.3).
	ShadowDays = 7
	// PerRuleFloor is the absolute ceiling for one rule (or correlation)
	// with no installed equivalent to compare against. Twenty findings in
	// a week is roughly three a day: by the base-rate argument that opens
	// internal/detect's package comment, a rule raising that much had
	// better be nearly all real, and "is it?" is a verdict the trial ring
	// exists to collect — not one an install gets to presume.
	PerRuleFloor = 20
	// PerRuleMultiple is how much louder than its installed equivalent a
	// rule may get before the update is a different rule wearing the same
	// id. Tuning a rule louder is legitimate and often the point;
	// three times louder is a rewrite, and deserves a human with a flag.
	PerRuleMultiple = 3
	// PackTotalMultiple is the same question for the pack as a whole.
	// A weekly pack legitimately churns several rules at once, so the
	// whole-pack multiple is looser than the per-rule one.
	PackTotalMultiple = 5
	// PackTotalFloor is the whole-pack ceiling when there is no baseline
	// to be a multiple of (nothing installed, or the installed set fired
	// nothing). The ratio has nothing to measure, so the absolute number
	// the design's own §5.4 instincts point at — "more than 50 findings"
	// — rounded up to one a first pack on a real estate can live under.
	PackTotalFloor = 100
)

// ErrNoTelemetry is the honest refusal when the gate has nothing to ask the
// pack about: the window holds no events. An unexercised gate is a decorative
// one, and the codebase's own convention is to say the mistake rather than
// record an empty result (noEventsYet in the detect run), so an empty store
// or an empty window refuses and names the escape rather than "passing".
var ErrNoTelemetry = errors.New("the shadow replay found no events in its " +
	"window")

// ShadowOptions is what the replay needs beyond the verified pack.
type ShadowOptions struct {
	// Now is the clock, a parameter for the same reason Verify's is.
	Now time.Time
	// Days is the window in days. Zero means ShadowDays.
	Days int
	// RulesDir is where the installed rules live — the same directory the
	// install would place into, read without placing anything. The
	// baseline is what is THERE today, not what the pack would leave.
	RulesDir string
	// MaxPerRule, when non-zero, replaces the computed per-rule budget
	// (max(PerRuleFloor, PerRuleMultiple× the installed equivalent)) with
	// an absolute cap the operator named. Absolute, not a floor to raise:
	// the operator who knows better states the number.
	MaxPerRule int
	// MaxTotal, when non-zero, replaces the computed whole-pack budget
	// (max(PackTotalFloor, PackTotalMultiple× the installed total)) the
	// same way.
	MaxTotal int
}

// ShadowCount is one content id's would-have-fired over the window, beside
// what the installed equivalent with the same id would have fired, and the
// budget that was applied to it.
type ShadowCount struct {
	ID string `json:"id"`
	// Fired is what the pack's version would have raised: matches, for a
	// rule that is not quiet; met windows, for a correlation. A quiet
	// rule fires nothing itself — its matches are the correlation's to
	// count — so its Fired is zero and its loudness reaches the budget
	// only through the correlation that counts it.
	Fired int `json:"fired"`
	// Installed is what the equivalent currently in the rules directory
	// would have fired over the same window; zero when the pack's id is
	// new here.
	Installed int `json:"installed"`
	// Cap is the budget that was applied to this id, computed or
	// operator-named, so a refusal can name it and a report can show it.
	Cap int `json:"cap"`
	// Over is whether Fired passed Cap.
	Over bool `json:"over"`
}

// ShadowTotal is the pack-as-a-whole count, against its baseline.
type ShadowTotal struct {
	Fired     int  `json:"fired"`
	Installed int  `json:"installed"`
	Cap       int  `json:"cap"`
	Over      bool `json:"over"`
}

// ShadowResult is the replay's whole answer: the numbers, the budgets, the
// decision, and the refusals in words a person reads.
type ShadowResult struct {
	Pack    string `json:"pack"`
	Version string `json:"version"`
	// Days, From and To describe the window: arrival time, the spool's
	// own clock, which nothing being recorded can move.
	Days int       `json:"days"`
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// Events is how many the window held — the gate's exercise. Zero
	// never reaches here as a pass; Shadow refuses first.
	Events int `json:"events"`
	// Rules and Correlations are per id, sorted, pack-side and baseline
	// side in one row.
	Rules        []ShadowCount `json:"rules"`
	Correlations []ShadowCount `json:"correlations"`
	Total        ShadowTotal   `json:"total"`
	// Unexercised counts the pack's rules that would have raised nothing
	// over the window. Silence is not proof of harm — but it is not proof
	// of anything else either: those rules never met this estate's week,
	// which is exactly what the trial ring is for after the install.
	Unexercised int `json:"unexercised"`
	// Dropped is events the correlation engines could not place in a
	// group (the group cap), reported rather than swallowed because a
	// correlation that stopped tracking groups has lost cover.
	Dropped int `json:"dropped"`
	// Refused is the budget's refusal in words, one entry per breached
	// budget, each naming the counts, the window, the budget and the
	// override flag. Empty means the budget held.
	Refused []string `json:"refused,omitempty"`
}

// Held reports whether the budget held: the install may proceed.
func (r *ShadowResult) Held() bool { return len(r.Refused) == 0 }

// Noisiest names the id with the most would-have-fired, for the one-line
// audit detail and the top of a refusal.
func (r *ShadowResult) Noisiest() string {
	best := ""
	var bestN int
	for _, rows := range [][]ShadowCount{r.Rules, r.Correlations} {
		for _, c := range rows {
			if c.Fired > bestN || (c.Fired == bestN && c.Fired > 0 &&
				c.ID < best) {
				best, bestN = c.ID, c.Fired
			}
		}
	}
	if bestN == 0 {
		return ""
	}
	return fmt.Sprintf("%s=%d", best, bestN)
}

// PerRuleBudget is the computed ceiling for one id against its installed
// equivalent: the floor when there is nothing to compare against, three
// times the equivalent when there is and that is louder.
func PerRuleBudget(installed int) int {
	cap := PerRuleFloor
	if m := PerRuleMultiple * installed; m > cap {
		cap = m
	}
	return cap
}

// PackTotalBudget is the computed ceiling for the pack as a whole, the same
// shape at five times and the looser floor.
func PackTotalBudget(installed int) int {
	cap := PackTotalFloor
	if m := PackTotalMultiple * installed; m > cap {
		cap = m
	}
	return cap
}

// OverDefaultBudget reports whether any count passes the budget the defaults
// would have set — asked of a result computed under operator-named caps, so
// the installed record can say "overridden" only when a flag was the
// difference between refused and installed, and "held" when the budget held
// regardless of it. A cap the operator lowered below the default is not
// honoured here in the other direction either: the record names what let
// content in, never what the defaults alone would have allowed.
func (r *ShadowResult) OverDefaultBudget() bool {
	for _, rows := range [][]ShadowCount{r.Rules, r.Correlations} {
		for _, c := range rows {
			if c.Fired > PerRuleBudget(c.Installed) {
				return true
			}
		}
	}
	return r.Total.Fired > PackTotalBudget(r.Total.Installed)
}

// Shadow replays a verified pack's content, and the installed equivalents
// with the same ids, over the last opts.Days of the store's events, and
// applies the false-positive budget.
//
// Call it only with a pack Verify accepted: the replay re-reads the pack
// through Read, digests and all, so the rules it runs are the bytes the
// signatures cover — but the ordering argument (cheap gates before empirical
// ones) is Verify's, and this function does not repeat it.
//
// It writes nothing. Not the finding register, not the cursors, not the
// suppression counters, not installed.json: the gate that has not decided
// yet has no business leaving marks. The caller records the decision.
func Shadow(v *Verified, sp *spool.Spool, opts ShadowOptions) (*ShadowResult, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	days := opts.Days
	if days <= 0 {
		days = ShadowDays
	}

	// The candidate content, re-read through the digest-checking loader:
	// only the pack's own rules and correlations run, from the pack
	// directory, exactly as they will land.
	p, err := Read(v.Dir)
	if err != nil {
		return nil, err
	}
	packRules, packCorrs, err := packContent(p)
	if err != nil {
		return nil, err
	}
	instRules, instCorrs, err := installedContent(opts.RulesDir)
	if err != nil {
		return nil, err
	}

	// The paths the pack's files land on, by basename (rulePath): an
	// installed rule read from one of them does not survive the install,
	// whatever its id.
	replaced := map[string]bool{}
	for _, f := range p.Manifest.Files {
		replaced[rulePath(f.Path)] = true
	}

	// A pack whose install would break the next run refuses here, not
	// there: an install that leaves `detect run` refusing to start is not
	// a successful install.
	if err := runsAfterInstall(packRules, instRules, packCorrs, instCorrs,
		replaced); err != nil {
		return nil, err
	}

	// Compiled once, asked of every event: the same shape the run uses.
	// The baseline side is restricted to the ids the pack carries — the
	// delta is "the pack vs what it replaces", and rules the pack does
	// not touch are not being replaced. A rule the pack's own file is
	// about to replace still counts: it is what the pack replaces.
	packIDs := map[string]bool{}
	progs := make([]*detect.Program, 0, len(packRules))
	for _, r := range packRules {
		prog, cerr := r.Compile()
		if cerr != nil {
			return nil, fmt.Errorf("%s cannot be replayed: %w", r.ID, cerr)
		}
		progs = append(progs, prog)
		packIDs[r.ID] = true
	}
	var instProgs []*detect.Program
	for _, r := range instRules {
		if !packIDs[r.ID] {
			continue
		}
		if verr := r.Validate(); verr != nil {
			return nil, fmt.Errorf("the installed %s cannot be "+
				"replayed: %w. The rules directory the pack would "+
				"install over holds a rule the run itself would refuse; "+
				"fix or remove it first", r.ID, verr)
		}
		prog, cerr := r.Compile()
		if cerr != nil {
			return nil, fmt.Errorf("the installed %s cannot be replayed: %w",
				r.ID, cerr)
		}
		instProgs = append(instProgs, prog)
	}

	// Correlation engines, both sides: the pack's correlations fed by the
	// pack's rules (the candidate set, as it will run together), and the
	// installed correlations the pack shares an id with, fed by the
	// installed rules (the set as it runs today).
	newEngines, err := enginesFor(packCorrs)
	if err != nil {
		return nil, err
	}
	corrIDs := map[string]bool{}
	for _, c := range packCorrs {
		corrIDs[c.ID] = true
	}
	var oldEngines []*correlate.Engine
	for _, c := range instCorrs {
		if !corrIDs[c.ID] {
			continue
		}
		eng, nerr := correlate.New(c)
		if nerr != nil {
			return nil, fmt.Errorf("the installed %s cannot be replayed: %w",
				c.ID, nerr)
		}
		oldEngines = append(oldEngines, eng)
	}

	// The watermark, decided exactly as the run decides it: the worst
	// lateness this store has ever seen (never less than correlate.Safe),
	// or the spool's own measurement when it is later — so windows close
	// on the same boundary the live correlations close on, and the
	// rehearsal answers for the performance.
	worst := sp.Lateness(1)
	if worst < correlate.Safe {
		worst = correlate.Safe
	}
	watermark := correlate.Watermark(now, worst)
	if w := sp.Watermark(); w.After(watermark) && !w.After(now) {
		watermark = w
	}

	res := &ShadowResult{Pack: v.Manifest.ID, Version: v.Manifest.Version,
		Days: days, From: now.Add(-time.Duration(days) * 24 * time.Hour),
		To: now}
	packFired := map[string]int{}
	instFired := map[string]int{}

	err = sp.Range(res.From, time.Time{}, func(e telemetry.Event) error {
		res.Events++
		f := e.Fields()
		for _, prog := range progs {
			if !prog.MatchesFields(e.Source, f) {
				continue
			}
			if !prog.Quiet {
				packFired[prog.ID]++
			}
			for _, eng := range newEngines {
				if eng.Watches(prog.ID) {
					// No watermark on the way in: everything is read
					// before anything is closed, so nothing is "late"
					// within a replay.
					if oerr := eng.Observe(correlate.Seen{Rule: prog.ID,
						Event: e}, time.Time{}); oerr != nil {
						return oerr
					}
				}
			}
		}
		for _, prog := range instProgs {
			if !prog.MatchesFields(e.Source, f) {
				continue
			}
			if !prog.Quiet {
				instFired[prog.ID]++
			}
			for _, eng := range oldEngines {
				if eng.Watches(prog.ID) {
					if oerr := eng.Observe(correlate.Seen{Rule: prog.ID,
						Event: e}, time.Time{}); oerr != nil {
						return oerr
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if res.Events == 0 {
		return nil, fmt.Errorf("%w: no event has arrived in the last %d "+
			"day(s), so the pack's rules have nothing to be asked about. "+
			"Widen the window with --days N, or — deliberately, for an "+
			"air-gapped first install or an empty store — install without "+
			"the gate: --no-shadow", ErrNoTelemetry, days)
	}

	// The correlations decide now, once every event that could land in a
	// window has been observed. A window that began before the replay
	// read back to is not decided — its early events were never seen, so
	// its count would be short — which is the run's own rule, held to
	// here so the rehearsal does not invent hits the performance would
	// not raise.
	corrFired := map[string]int{}
	for _, eng := range newEngines {
		for _, h := range eng.Close(watermark) {
			if !h.From.Before(res.From) {
				corrFired[eng.Rule().ID]++
			}
		}
		res.Dropped += eng.Dropped()
	}
	oldCorrFired := map[string]int{}
	for _, eng := range oldEngines {
		for _, h := range eng.Close(watermark) {
			if !h.From.Before(res.From) {
				oldCorrFired[eng.Rule().ID]++
			}
		}
	}

	// The per-id budgets. An operator-named cap is absolute, computed or
	// typed: the refusal must be able to name which it was.
	perRuleCap := func(installed int) int {
		if opts.MaxPerRule > 0 {
			return opts.MaxPerRule
		}
		return PerRuleBudget(installed)
	}
	count := func(fired, baseline map[string]int, ids []string) []ShadowCount {
		out := make([]ShadowCount, 0, len(ids))
		for _, id := range ids {
			c := ShadowCount{ID: id, Fired: fired[id],
				Installed: baseline[id], Cap: perRuleCap(baseline[id])}
			c.Over = c.Fired > c.Cap
			out = append(out, c)
		}
		return out
	}
	var ruleIDs, corrIDList []string
	for _, r := range packRules {
		ruleIDs = append(ruleIDs, r.ID)
		if !r.Quiet && packFired[r.ID] == 0 {
			res.Unexercised++
		}
	}
	for _, c := range packCorrs {
		corrIDList = append(corrIDList, c.ID)
	}
	sort.Strings(ruleIDs)
	sort.Strings(corrIDList)
	res.Rules = count(packFired, instFired, ruleIDs)
	res.Correlations = count(corrFired, oldCorrFired, corrIDList)

	// The pack as a whole: every would-be finding the queue would see —
	// loud rules and correlation hits; quiet rules contribute through
	// their correlations, as they do live.
	for _, c := range res.Rules {
		res.Total.Fired += c.Fired
		res.Total.Installed += c.Installed
	}
	for _, c := range res.Correlations {
		res.Total.Fired += c.Fired
		res.Total.Installed += c.Installed
	}
	if opts.MaxTotal > 0 {
		res.Total.Cap = opts.MaxTotal
	} else {
		res.Total.Cap = PackTotalBudget(res.Total.Installed)
	}
	res.Total.Over = res.Total.Fired > res.Total.Cap

	// The refusals, in words, naming everything: the count, the window,
	// the baseline, the budget, and the flag that overrides it — the
	// operator who knows better must be told how to say so.
	window := fmt.Sprintf("over the last %d day(s)", days)
	for _, c := range res.Rules {
		if !c.Over {
			continue
		}
		res.Refused = append(res.Refused, fmt.Sprintf(
			"%s would fire %d time(s) %s (%d event(s) seen); the budget "+
				"for it is %s = %d. The operator who knows better says so "+
				"with --max-fires-per-rule N", c.ID, c.Fired, window,
			res.Events, budgetWords(opts.MaxPerRule, c.Installed), c.Cap))
	}
	for _, c := range res.Correlations {
		if !c.Over {
			continue
		}
		res.Refused = append(res.Refused, fmt.Sprintf(
			"the correlation %s would fire %d time(s) %s (%d event(s) "+
				"seen); the budget for it is %s = %d. The operator who "+
				"knows better says so with --max-fires-per-rule N", c.ID,
			c.Fired, window, res.Events,
			budgetWords(opts.MaxPerRule, c.Installed), c.Cap))
	}
	if res.Total.Over {
		res.Refused = append(res.Refused, fmt.Sprintf(
			"the pack as a whole would fire %d time(s) %s against %d from "+
				"the set it replaces (%d event(s) seen); the budget is %s "+
				"= %d. The operator who knows better says so with "+
				"--max-total-fires N", res.Total.Fired, window,
			res.Total.Installed, res.Events,
			totalWords(opts.MaxTotal, res.Total.Installed), res.Total.Cap))
	}
	return res, nil
}

// budgetWords names a per-id budget the way the refusal should: the
// computation when it was computed, the flag when it was typed.
func budgetWords(override, installed int) string {
	if override > 0 {
		return fmt.Sprintf("--max-fires-per-rule %d", override)
	}
	return fmt.Sprintf("max(%d, %d× the installed %d)", PerRuleFloor,
		PerRuleMultiple, installed)
}

// totalWords is budgetWords for the whole-pack budget.
func totalWords(override, installed int) string {
	if override > 0 {
		return fmt.Sprintf("--max-total-fires %d", override)
	}
	return fmt.Sprintf("max(%d, %d× the installed %d)", PackTotalFloor,
		PackTotalMultiple, installed)
}

// packContent loads a pack's own rules and correlations from the bodies the
// digest-checked Read holds — the candidate content, and only it.
func packContent(p *Pack) ([]detect.Rule, []correlate.Rule, error) {
	var rules []detect.Rule
	var corrs []correlate.Rule
	for _, f := range p.Manifest.Files {
		body := p.Bodies[f.Path]
		switch f.Type {
		case TypeDetection:
			var r detect.Rule
			if err := decodeStrict(body, &r); err != nil {
				return nil, nil, fmt.Errorf("%s is not a rule: %w", f.Path, err)
			}
			if err := r.Validate(); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", f.Path, err)
			}
			rules = append(rules, r)
		case TypeCorrelation:
			parsed, err := correlate.Read(body)
			if err != nil {
				return nil, nil, fmt.Errorf("%s is not a correlation: %w",
					f.Path, err)
			}
			corrs = append(corrs, parsed...)
		}
	}
	return rules, corrs, nil
}

// installedRule is one rule already in the target directory, with the file it
// was read from. The file matters because the install replaces files, not
// rule ids: a pack file landing on a path that held a different rule removes
// that rule, and the state the install would leave is a question about files.
type installedRule struct {
	detect.Rule
	File string
}

// installedContent loads the rules and correlations already in the target
// directory — the same files `aertun detect run` walks, loaded here without
// installing anything, and refused for the same reasons the run refuses them
// (a rule id held by two files, a correlation with no id), because a baseline
// the run itself would not load is a measurement of nothing. A missing
// directory is an empty baseline, not an error: the first pack into a fresh
// store replaces nothing.
func installedContent(dir string) ([]installedRule, []correlate.Rule, error) {
	if !dirExistsUnder(dir) {
		return nil, nil, nil
	}
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".yml") ||
			strings.HasSuffix(path, ".yaml") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	// Sorted, so the load is repeatable and a diff of two replays is a
	// diff of the rules, not of the walk order.
	sort.Strings(files)
	var rules []installedRule
	var corrs []correlate.Rule
	seen := map[string]string{}
	for _, f := range files {
		fi, serr := os.Stat(f)
		if serr != nil {
			return nil, nil, serr
		}
		if fi.Size() > MaxFileBytes {
			return nil, nil, fmt.Errorf("%s is %d bytes; a rule is not that "+
				"big", f, fi.Size())
		}
		body, rerr := os.ReadFile(f)
		if rerr != nil {
			return nil, nil, rerr
		}
		switch {
		case strings.HasSuffix(f, ".json"):
			var r detect.Rule
			// The same decode the run's loader uses: the baseline must
			// be what the run would actually evaluate, not a stricter
			// or looser reading of it.
			if uerr := json.Unmarshal(body, &r); uerr != nil {
				return nil, nil, fmt.Errorf("%s is not a rule: %w", f, uerr)
			}
			if where, dup := seen[r.ID]; dup {
				return nil, nil, fmt.Errorf("%s and %s are both called %q, and "+
					"a finding has to say which rule raised it. The run "+
					"refuses this directory; so does the gate", where, f, r.ID)
			}
			seen[r.ID] = f
			rules = append(rules, installedRule{Rule: r, File: f})
		default:
			parsed, perr := correlate.Read(body)
			if perr != nil {
				return nil, nil, fmt.Errorf("%s: %w", f, perr)
			}
			for _, c := range parsed {
				if strings.TrimSpace(c.ID) == "" {
					return nil, nil, fmt.Errorf("%s: %q has no id, and a "+
						"finding has to say which correlation raised it", f,
						c.Title)
				}
				corrs = append(corrs, c)
			}
		}
	}
	return rules, corrs, nil
}

func dirExistsUnder(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// enginesFor builds a correlation engine per correlation, refusing the first
// that does not build: a correlation the live run could not construct is a
// pack that must not install.
func enginesFor(corrs []correlate.Rule) ([]*correlate.Engine, error) {
	var out []*correlate.Engine
	for _, c := range corrs {
		eng, err := correlate.New(c)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.ID, err)
		}
		out = append(out, eng)
	}
	return out, nil
}

// runsAfterInstall holds the run's own load-time checks against the state
// the install would leave: every correlation that will exist afterwards (the
// pack's, or the directory's — files the pack does not own are left alone)
// must name rules that will exist afterwards, and a quiet pack rule must be
// counted by some correlation that will. "Afterwards" is decided by files,
// not ids: a pack file landing on a path that held a different rule removes
// that rule, so an installed rule read from a path the pack owns is not part
// of the state the install leaves. A pack that passed verification but broke
// the next `detect run` would be an install that shipped an outage.
func runsAfterInstall(packRules []detect.Rule, instRules []installedRule,
	packCorrs, instCorrs []correlate.Rule, replaced map[string]bool) error {

	have := map[string]bool{}
	for _, r := range packRules {
		have[strings.ToLower(r.ID)] = true
	}
	for _, r := range instRules {
		if replaced[filepath.Base(r.File)] {
			continue
		}
		have[strings.ToLower(r.ID)] = true
	}
	all := append(append([]correlate.Rule{}, packCorrs...), instCorrs...)
	for _, c := range all {
		for _, name := range c.Rules {
			if !have[strings.ToLower(name)] {
				return fmt.Errorf("%s correlates %q, and no rule called that "+
					"survives this install; the run after it would refuse "+
					"to start", c.ID, name)
			}
		}
	}
	named := map[string]bool{}
	for _, c := range all {
		for _, name := range c.Rules {
			named[name] = true
		}
	}
	for _, r := range packRules {
		if r.Quiet && !named[r.ID] {
			return fmt.Errorf("%s is quiet and no correlation the install "+
				"would leave counts it, so it would match and tell nobody. "+
				"Remove \"quiet\", or add the correlation it was written for",
				r.ID)
		}
	}
	return nil
}
