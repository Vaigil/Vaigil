// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// The splicer: a scenario's events placed on the two clocks and interleaved
// into a base stream by arrival, written to a scratch spool.
//
// # Why arrival synthesis is the critical step
//
// The victim's correlations are windowed on event time and closed by
// watermarks derived from arrival (decision 3). A spliced event with a
// zero-delay arrival is trivially distinguishable from live traffic and
// flatters every windowed correlation in the stack, because it lands before
// any window could have closed. So each scenario event's arrival delay is
// drawn from the base stream's own measured distribution — literally the
// log2 buckets the spool keeps — sampled deterministically from the run seed.
// Never a constant.
//
// # The restated histogram
//
// The bucketing and the quantile walk below are internal/spool's own
// (retention.go: observe/bucket/Lateness), restated here rather than reused
// through the store because the spool owns a live store's histogram and the
// splicer owns a base stream's — the same arithmetic over a different life.
// The spool's reasoning holds word for word: log2 buckets because arrival
// delay spans six orders of magnitude, and the top of the bucket because a
// window sized from this is too wide rather than too narrow, and too wide
// costs compute while too narrow misses attacks.

// histogram is observed arrival delay in log2-seconds buckets.
type histogram map[int]int64

// latenessHistogram builds the base stream's arrival-delay histogram, the
// same bucketing spool.observe keeps for every event that arrives. One
// stated difference: the spool counts a fast source clock in its separate
// Ahead counter and keeps it out of the lateness histogram, while here an
// ahead event floors at bucket zero and stays — a base stream's histogram
// is the distribution new arrivals are drawn from, and an event that
// arrived before it happened is still an event that arrived; dropping it
// would lean every quantile toward the late tail.
func latenessHistogram(base []telemetry.Event) histogram {
	h := histogram{}
	for _, e := range base {
		d := e.Lateness()
		if d < 0 {
			d = 0
		}
		secs := int64(d / time.Second)
		n := 0
		for secs > 0 {
			secs >>= 1
			n++
		}
		h[n]++
	}
	return h
}

// quantile is the observed delay at a quantile, as the top of its bucket —
// spool.Lateness's walk, over the imported histogram.
func (h histogram) quantile(q float64) time.Duration {
	if q <= 0 || q > 1 {
		return 0
	}
	var total int64
	for _, n := range h {
		total += n
	}
	if total == 0 {
		return 0
	}
	want := int64(float64(total) * q)
	var seen int64
	buckets := make([]int, 0, len(h))
	for b := range h {
		buckets = append(buckets, b)
	}
	sort.Ints(buckets)
	for _, b := range buckets {
		seen += h[b]
		if seen >= want {
			return time.Duration(1<<b) * time.Second
		}
	}
	return time.Duration(1<<buckets[len(buckets)-1]) * time.Second
}

// profiles are the declared lateness distributions for base streams that
// carry no arrival history of their own — fixture corpora where every event
// arrived the moment it happened. Cloud-audit batches minutes late; a local
// agent arrives in seconds.
var profiles = map[string]histogram{
	ProfileCloudAudit: {2: 30, 5: 20, 7: 45, 11: 5},
	ProfileLocalAgent: {0: 60, 2: 30, 3: 10},
}

// Preflight runs a scenario's declared checks over the base stream, plus the
// collision checks every scenario pays for whether it declares them or not.
//
// A failed preflight refuses the run rather than splicing events no rule can
// read or joining a session onto somebody else's — the same refusal as a rule
// fixture that names a field nothing emits.
func Preflight(sc *Scenario, base []telemetry.Event) error {
	if len(base) == 0 {
		return fmt.Errorf("the base stream holds no events, so there is " +
			"nothing for a session to hide among and nothing to preflight " +
			"against")
	}
	for _, p := range sc.Preflight {
		switch p.Check {
		case CheckSourceEmits:
			found := false
			for _, e := range base {
				if strings.EqualFold(e.Source, p.Source) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%s: preflight failed — the base stream "+
					"carries no event from %q, so the scenario's events "+
					"would be spliced into a stream that has never emitted "+
					"them and no rule written against that source can be "+
					"asked anything", sc.ID, p.Source)
			}
		case CheckToolLabelled:
			found := false
			for _, e := range base {
				if !strings.EqualFold(e.Source, p.Source) ||
					e.Raw["tool"] != p.Tool {
					continue
				}
				if labelsContain(e.Raw["labels"], p.Label) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("%s: preflight failed — the base stream has "+
					"never carried the tool %q labelled %q. The label is a "+
					"declaration made at the ingest boundary, and splicing "+
					"it into a stream whose boundary never stamped it would "+
					"test a world this stream is not", sc.ID, p.Tool, p.Label)
			}
		}
	}
	// The built-ins: the generated identities must be disjoint from the
	// base stream's, which the seeded ranges make near-certain and the check
	// makes certain.
	values, err := Expand(sc)
	if err != nil {
		return err
	}
	for _, e := range base {
		if t := values["trace"]; t != "" && e.Raw["trace_id"] == t {
			return fmt.Errorf("%s: preflight failed — the generated trace id "+
				"%s is already in the base stream. The generators draw from "+
				"disjoint ranges precisely so a session cannot join a "+
				"recorded one", sc.ID, t)
		}
		if a := values["agent"]; a != "" && e.Actor.Value == a {
			return fmt.Errorf("%s: preflight failed — the generated agent "+
				"name %s is already the base stream's; a windtunnel session "+
				"must be nobody else's", sc.ID, a)
		}
	}
	return nil
}

// labelsContain reads a comma-separated label list the way the ingest
// boundary writes it.
func labelsContain(list, want string) bool {
	for _, l := range strings.Split(list, ",") {
		if strings.TrimSpace(l) == want {
			return true
		}
	}
	return false
}

// Placed is a session after the splicer owned its clocks: every event with
// both times set, in step order, and the delays that were drawn.
type Placed struct {
	Events []telemetry.Event
	Anchor time.Time
	Delays []time.Duration
}

// expandSteps is a session's steps expanded to concrete offsets: a repeated
// step becomes its copies, Every seconds apart.
func expandSteps(steps []Step) []Step {
	var out []Step
	for _, s := range steps {
		if s.Repeat == nil || s.Repeat.Count <= 1 {
			out = append(out, s)
			continue
		}
		for i := 0; i < s.Repeat.Count; i++ {
			c := s
			c.At = s.At + s.Repeat.Every*i
			c.Repeat = nil
			out = append(out, c)
		}
	}
	return out
}

// Place gives a scenario's steps both clocks: event time anchored in the
// base stream, arrival drawn from the base stream's own lateness
// distribution (or the declared profile), deterministically from the seed.
//
// The twin's steps are placed the same way, over the same base and the same
// bindings, so attack and twin differ only in what the session did.
func Place(sc *Scenario, steps []Step, base []telemetry.Event, seed int64,
	anchor time.Time) (*Placed, error) {

	expanded := expandSteps(steps)
	values, err := Expand(sc)
	if err != nil {
		return nil, err
	}

	// The distribution the delays are drawn from. "measured" needs a base
	// stream that actually arrived late at least once; a stream with no
	// observed delay would make every draw zero, which is the constant this
	// whole function exists to refuse.
	src := sc.LatenessSource()
	var hist histogram
	switch src {
	case LatenessMeasured:
		hist = latenessHistogram(base)
	default:
		hist = profiles[src]
		if hist == nil {
			return nil, fmt.Errorf("%s: %q is not a lateness source; the "+
				"closed set is %s", sc.ID, src,
				strings.Join(LatenessSources(), ", "))
		}
	}
	if worst := hist.quantile(1); worst <= time.Second {
		return nil, fmt.Errorf("%s: the base stream's worst observed arrival "+
			"delay is %s, so a measured splice would arrive at the speed "+
			"of a local function call — trivially distinguishable from "+
			"live traffic, and flattering to every windowed correlation in "+
			"the stack. Declare a lateness profile (%s, %s) or use a base "+
			"stream that arrived like traffic does", sc.ID, worst,
			ProfileCloudAudit, ProfileLocalAgent)
	}
	delays, err := synthesiseLateness(sc.ID, src, hist, len(expanded), seed)
	if err != nil {
		return nil, err
	}

	out := &Placed{Anchor: anchor, Delays: delays}
	for i, s := range expanded {
		e := Substitute(s.Emit, values)
		e.Time = anchor.Add(time.Duration(s.At) * time.Second).UTC()
		e.Received = e.Time.Add(delays[i]).UTC()
		out.Events = append(out.Events, e)
	}
	return out, nil
}

// synthesiseLateness draws one arrival delay per event: a quantile from the
// run seed, mapped through the histogram's own buckets, then jittered into
// the top half of the bucket so a concentrated distribution still spreads
// rather than collapsing to one number. The draw is over (L/2, L], never
// zero, never above the worst delay the base stream has shown.
func synthesiseLateness(id, src string, hist histogram, n int,
	seed int64) ([]time.Duration, error) {

	out := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		b := drawBytes("lateness:"+src, seed, i)
		// Ten bits of quantile, in (0, 1]: a thousand draw points, so the
		// tail above the 99th percentile is genuinely reachable — about one
		// draw in a hundred, which is what a 99th-percentile watermark is
		// built to drop.
		q := float64((int(b[0])<<2|int(b[1])>>6)+1) / 1024
		top := hist.quantile(q)
		if top <= 0 {
			return nil, fmt.Errorf("%s: the lateness histogram refused the "+
				"draw at step %d", id, i+1)
		}
		jitter := float64(b[2]) / 255 // (0, 1]
		out[i] = time.Duration(float64(top) * (0.5 + 0.5*jitter))
	}
	return out, nil
}

// Interleave merges the base stream and a placed session by arrival — the
// base's own order preserved, the session's events inserted where their
// synthesised arrivals put them.
//
// Not a tail append. A tail append places every attack event after the last
// watermark, which is the classical replay determinism bug in different
// clothes: it hands the victim a stream whose endings are all in order and
// whose windows therefore close as kindly as possible. Interleaving by the
// synthesised Received is what makes the two-clock semantics real.
func Interleave(base, session []telemetry.Event) []telemetry.Event {
	merged := make([]telemetry.Event, 0, len(base)+len(session))
	merged = append(merged, base...)
	merged = append(merged, session...)
	// Base first in the concatenation, and a stable sort, so equal arrivals
	// keep the base stream ahead and both halves keep their own order.
	sort.SliceStable(merged, func(i, j int) bool {
		return merged[i].Received.Before(merged[j].Received)
	})
	return merged
}

// DefaultAnchor is where a session goes by default: one second after the
// last event time the base stream records. The anchor is event time — where
// the session happened — and the arrivals that follow it are the splicer's
// to synthesise.
func DefaultAnchor(base []telemetry.Event) (time.Time, error) {
	if len(base) == 0 {
		return time.Time{}, fmt.Errorf("the base stream holds no events, so " +
			"there is no end to anchor a session to")
	}
	var last time.Time
	for _, e := range base {
		if e.Time.After(last) {
			last = e.Time
		}
	}
	return last.Add(time.Second).UTC(), nil
}

// WriteScratch writes a whole stream into a fresh scratch spool, through the
// store's own append path so segmentation, sealing and the lateness
// histogram behave exactly as they do live. The production spool is never
// written by anything in this package.
func WriteScratch(dir string, stream []telemetry.Event) (*spool.Spool, error) {
	sp, err := spool.Open(dir, spool.Options{})
	if err != nil {
		return nil, err
	}
	if _, err := sp.AppendBatch(stream); err != nil {
		sp.Close()
		return nil, err
	}
	if err := sp.Close(); err != nil {
		return nil, err
	}
	return spool.Open(dir, spool.Options{})
}

// BaseDigest is the sha256 of a base stream's canonical bytes: one compact
// JSON line per event, in stream order. The digest the scorecard names so a
// number is always about a stream somebody can identify.
func BaseDigest(base []telemetry.Event) (string, int) {
	h := sha256.New()
	for _, e := range base {
		line, err := json.Marshal(e)
		if err != nil {
			// Event.Validate has run by now and these are plain structs; a
			// marshal failure here is not a condition a caller can act on.
			continue
		}
		h.Write(line)
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil)), len(base)
}
