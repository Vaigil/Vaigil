// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vaigil/vaigil/internal/correlate"
	"github.com/vaigil/vaigil/internal/detect"
	"github.com/vaigil/vaigil/internal/finding"
	"github.com/vaigil/vaigil/internal/spool"
	"github.com/vaigil/vaigil/internal/telemetry"
)

// Correlations, run over the estate's own events.
//
// internal/correlate was complete — four correlation types, windows closed
// on a watermark rather than a clock, a cap on groups — and the only thing
// that ever fed it was `correlate demo`, with five invented events. A
// correlation file beside the rules was parsed by nothing and raised
// nothing. This is the run.
//
// # Re-read, not remembered
//
// A correlation window outlives a run: five failures in fifteen minutes may
// arrive across three of them. Rather than keep half-open windows on disk
// between runs — state that can be corrupted, and that makes yesterday's
// run unrepeatable — each run re-reads the recent events, evaluates them
// afresh, and closes only the windows the watermark has passed. The same
// events give the same hits every time, which is the property the package
// was built for. What is kept is only which hits have been raised already,
// so a window is a finding once.

// MaxCorrelationFile bounds one file of correlations.
const MaxCorrelationFile = 1 << 20

// correlateCursor is the watermark the last correlation run decided up to.
const correlateCursor = "correlate"

func correlatedPath(root string) string {
	return filepath.Join(detectDir(root), "correlated.json")
}

// correlationsIn reads every correlation in the rules directory: Sigma
// YAML, in .yml or .yaml files.
func correlationsIn(dir string) ([]correlate.Rule, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml") {
			files = append(files, p)
		}
		return nil
	})
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var out []correlate.Rule
	seen := map[string]string{}
	for _, f := range files {
		fi, serr := os.Stat(f)
		if serr != nil {
			return nil, serr
		}
		if fi.Size() > MaxCorrelationFile {
			return nil, fmt.Errorf("%s is %d bytes; a correlation is not "+
				"that big", f, fi.Size())
		}
		b, rerr := os.ReadFile(f)
		if rerr != nil {
			return nil, rerr
		}
		rules, perr := correlate.Read(b)
		if perr != nil {
			return nil, fmt.Errorf("%s: %w", f, perr)
		}
		for _, r := range rules {
			if strings.TrimSpace(r.ID) == "" {
				return nil, fmt.Errorf("%s: %q has no id, and a finding has "+
					"to say which correlation raised it", f, r.Title)
			}
			if where, dup := seen[r.ID]; dup {
				return nil, fmt.Errorf("%s and %s both define %q", where, f,
					r.ID)
			}
			seen[r.ID] = f
			out = append(out, r)
		}
	}
	return out, nil
}

// asRule presents a correlation on the screens and in the statistics that
// list detection rules, so its ring and its verdicts sit beside theirs.
func asRule(c correlate.Rule) detect.Rule {
	return detect.Rule{ID: c.ID, Title: c.Title, Severity: c.Severity,
		Why: fmt.Sprintf("a correlation (%s) over %s within %s", c.Type,
			strings.Join(c.Rules, ", "), plainClockSpan(c.Timespan))}
}

// hitEntity is who or what a hit is about: the actor it was grouped by
// when there is one, and the group itself otherwise.
func hitEntity(h correlate.Hit) telemetry.ID {
	for _, field := range []string{"actor", "target", "device"} {
		if v, ok := h.Group[field]; ok {
			if issuer, value, cut := strings.Cut(v, ":"); cut {
				return telemetry.ID{Issuer: issuer, Value: value}
			}
		}
	}
	// Grouped by the person: the hit is about them, whichever platform's
	// identifier each event carried.
	if v, ok := h.Group["raw.person"]; ok && v != "" {
		return telemetry.ID{Issuer: "person", Value: v}
	}
	if len(h.Group) == 0 {
		return telemetry.ID{Issuer: "estate", Value: "everything"}
	}
	var parts []string
	for k, v := range h.Group {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return telemetry.ID{Issuer: "group", Value: strings.Join(parts, ",")}
}

// correlationRun is what one pass found.
type correlationRun struct {
	Rules, Hits, Opened, Late, Dropped int
}

// correlations is a correlation run between its two halves: the engines
// built, the window and watermark decided, and nothing yet fed into them.
//
// Split in two so that one scan of the store can feed the rules, the
// correlations and the indicators together — detectPass — without changing
// what the correlations see. Their engines are built before anything is
// read, fed the events of their own window in store order, and closed after
// everything has been observed: the same events, in the same order, at the
// same times as when the correlations were a pass of their own, which is
// the order the watermark logic in internal/correlate is built around.
type correlations struct {
	run       correlationRun
	engines   []*correlate.Engine
	span      time.Duration
	watermark time.Time
	from      time.Time
}

// prepareCorrelations loads and validates every correlation, builds an
// engine for each that is not switched off, and decides how far back this
// run reads and to where it will close windows. It reads no events and
// moves no cursor: the feeding is the caller's scan and the deciding is
// finish.
//
// A nil return is not an error: it means there is nothing to correlate this
// run, and every method on a nil *correlations says the same.
func prepareCorrelations(dir string, rules []detect.Rule,
	rings map[string]detect.Placement, sp *spool.Spool,
	cursors map[string]time.Time, now time.Time) (*correlations, error) {

	corrs, err := correlationsIn(dir)
	if err != nil || len(corrs) == 0 {
		return nil, err
	}
	known := map[string]bool{}
	for _, r := range rules {
		known[strings.ToLower(r.ID)] = true
	}
	c := &correlations{}
	for _, corr := range corrs {
		if rings[corr.ID].Ring == detect.Off {
			continue
		}
		for _, name := range corr.Rules {
			if !known[strings.ToLower(name)] {
				// A correlation over a rule that is not there can never
				// fire, and would sit on the screen looking like cover.
				return nil, fmt.Errorf("%s correlates %q, and there is no "+
					"rule called that (or it is switched off)", corr.ID, name)
			}
		}
		e, nerr := correlate.New(corr)
		if nerr != nil {
			return nil, fmt.Errorf("%s: %w", corr.ID, nerr)
		}
		c.engines = append(c.engines, e)
		if corr.Timespan > c.span {
			c.span = corr.Timespan
		}
	}
	if len(c.engines) == 0 {
		return nil, nil
	}
	c.run.Rules = len(c.engines)

	// Complete up to here: everything older has arrived, by the spool's own
	// measurement of how late this estate's events turn up.
	//
	// The spool's watermark is the newest arrival less the observed delay,
	// so it stops moving when a source goes quiet — and a spray followed by
	// silence would sit in a window that never closed. Time passing
	// completes a window as well: once the slowest arrival this store has
	// ever seen would have turned up, it has. Whichever is later. The
	// slowest ever, and not the usual, because closing early loses a
	// detection and closing late only delays one.
	worst := sp.Lateness(1)
	if worst < correlate.Safe {
		worst = correlate.Safe
	}
	c.watermark = correlate.Watermark(now, worst)
	if w := sp.Watermark(); w.After(c.watermark) && !w.After(now) {
		c.watermark = w
	}
	// Back to where the last run had got to, and a little before: every
	// window that run left open is read again whole. Not a fixed distance
	// from now — a store nobody ran this on for six hours would have six
	// hours of windows that were never decided, and nothing would say so.
	// The first run reads everything the store holds.
	if prev := cursors[correlateCursor]; !prev.IsZero() {
		c.from = prev.Add(-2*c.span - time.Hour)
	}
	return c, nil
}

// observe feeds one event to every engine watching a rule it matched.
//
// matched is the rules the event matched, in load order, and the caller
// holds it because the rules pass asked the same question of the same event
// a moment before; matching is the expensive part and it is asked once.
// Suppressed matches do not feed the engines, exactly as when the
// correlations read the store themselves: a suppression is a decision that
// the events it hides are not worth counting, not a decision about who
// counts them.
func (c *correlations) observe(e telemetry.Event, matched []*detect.Program,
	sups []detect.Suppression, now time.Time) error {

	if c == nil {
		return nil
	}
	for _, p := range matched {
		hidden := false
		for _, s := range sups {
			hidden = hidden || s.Hides(p.ID, e, now)
		}
		if hidden {
			continue
		}
		for _, eng := range c.engines {
			if !eng.Watches(p.ID) {
				continue
			}
			// No watermark on the way in: everything is read before
			// anything is closed, so nothing is "late" within a run.
			if oerr := eng.Observe(correlate.Seen{Rule: p.ID, Event: e},
				time.Time{}); oerr != nil {
				return oerr
			}
		}
	}
	return nil
}

// finish decides every window the watermark has passed and folds new hits
// into the register. Called once the scan that fed the engines is done,
// because a window can only be decided once everything that could land in
// it has been observed.
func (c *correlations) finish(root string,
	rings map[string]detect.Placement, reg *finding.Register,
	cursors map[string]time.Time, now time.Time) (correlationRun, error) {

	if c == nil {
		return correlationRun{}, nil
	}
	raised := map[string]time.Time{}
	if err := loadJSONFile(correlatedPath(root), &raised); err != nil {
		return c.run, err
	}
	for _, eng := range c.engines {
		corr := eng.Rule()
		for _, h := range eng.Close(c.watermark) {
			if !c.from.IsZero() && h.From.Before(c.from) {
				// A window that began before this run read back to. Its
				// early events were not read, so its count is short and
				// it is not decided here; the run that saw all of it did.
				continue
			}
			c.run.Hits++
			entity := hitEntity(h)
			key := fmt.Sprintf("%s|%s|%d", corr.ID, entity, h.From.Unix())
			if _, done := raised[key]; done {
				continue
			}
			raised[key] = h.To
			if _, isNew := reg.Record(finding.Finding{
				Kind: finding.FromDetection, Title: corr.Title, Source: corr.ID,
				Entity: entity, Severity: corr.Severity, State: finding.Open,
				Trial: rings[corr.ID].Ring == detect.Trial,
				Evidence: []finding.Evidence{{At: h.To, What: h.Why(),
					Source: "correlation", Tainted: true}},
			}, h.To); isNew {
				c.run.Opened++
			}
		}
		c.run.Late += eng.Late()
		c.run.Dropped += eng.Dropped()
	}
	// Forgotten once no run could raise them again.
	for k, to := range raised {
		if now.Sub(to) > 4*c.span+48*time.Hour {
			delete(raised, k)
		}
	}
	cursors[correlateCursor] = c.watermark
	return c.run, saveJSONFile(correlatedPath(root), raised)
}

// quietRulesAreCounted refuses a quiet rule that no correlation names. It
// would match, raise nothing, and be counted by nobody: a detection that
// looks installed and tells no one.
func quietRulesAreCounted(dir string, rules []detect.Rule) error {
	var quiet []string
	for _, r := range rules {
		if r.Quiet {
			quiet = append(quiet, r.ID)
		}
	}
	if len(quiet) == 0 {
		return nil
	}
	corrs, err := correlationsIn(dir)
	if err != nil {
		return err
	}
	named := map[string]bool{}
	for _, c := range corrs {
		for _, id := range c.Rules {
			named[id] = true
		}
	}
	for _, id := range quiet {
		if !named[id] {
			return fmt.Errorf("%s is quiet and no correlation counts it, so "+
				"it would match and tell nobody. Remove \"quiet\", or add "+
				"the correlation it was written for", id)
		}
	}
	return nil
}
