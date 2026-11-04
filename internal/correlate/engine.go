// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package correlate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/telemetry"
)

// Seen is one event that matched one of the correlated rules.
type Seen struct {
	Rule  string
	Event telemetry.Event
}

// Hit is a correlation that fired.
type Hit struct {
	Rule string `json:"rule"`
	// Group is the field values this fired for, in group-by order.
	Group map[string]string `json:"group,omitempty"`
	// Window is the span the events fell in.
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// Count is what satisfied the condition: events, or distinct values.
	Count int `json:"count"`
	// Rules are the distinct detections involved, in the order they fired.
	Rules    []string           `json:"rules,omitempty"`
	Severity telemetry.Severity `json:"severity,omitempty"`
	// Sample is a few of the events, so somebody can see what this is.
	Sample []telemetry.Event `json:"-"`
}

// MaxSample caps what a hit carries back.
const MaxSample = 5

// Why describes a hit for somebody reading an alert.
func (h Hit) Why() string {
	var who string
	if len(h.Group) > 0 {
		var parts []string
		for _, k := range sorted(keys(h.Group)) {
			parts = append(parts, k+"="+h.Group[k])
		}
		who = " for " + strings.Join(parts, ", ")
	}
	return fmt.Sprintf("%s%s: %d within %s, between %s and %s", h.Rule,
		who, h.Count, plainly(h.To.Sub(h.From)),
		h.From.Format(time.RFC3339), h.To.Format(time.RFC3339))
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// MaxGroups caps how many distinct groups one correlation tracks at once.
//
// A correlation grouped by a field an attacker controls — a username in a
// spray, a source port — grows a bucket per value. Unbounded, that is a
// detection rule being used to exhaust the machine running it, so the
// engine refuses to open a new group past this and reports it rather than
// growing quietly. The refusal is the safe failure: a correlation that
// stopped tracking new groups has lost coverage and says so, where one that
// consumed all the memory has lost everything.
const MaxGroups = 100_000

// Engine evaluates one correlation over a stream.
//
// Events go in with their event time. Nothing comes out until the watermark
// passes a window's end, which is what makes the same input produce the
// same output on a replay as it did live.
type Engine struct {
	rule Rule

	// buckets are keyed by group then by window start.
	buckets map[string]*group
	dropped int
	late    int
	groups  int
}

// group is one group-by value's open windows, and the window that closed
// most recently beside them. The retained one exists because a pair inside
// the timespan can sit either side of a window boundary, and neither window
// alone can see it; see window for why the boundaries are fixed.
type group struct {
	windows map[int64]*bucket
	prior   *closed
}

type bucket struct {
	events []Seen
}

// closed is a window that has been evaluated, whose events are kept until
// the window beside them has closed too — and no longer, so the retention
// costs one window per group rather than the group's whole history.
type closed struct {
	start  int64
	events []Seen
}

// New builds an engine for a correlation.
func New(r Rule) (*Engine, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &Engine{rule: r, buckets: map[string]*group{}}, nil
}

// Rule is the correlation this evaluates.
func (e *Engine) Rule() Rule { return e.rule }

// Dropped is how many events were refused because the group cap was
// reached, and Late how many arrived after their window had already closed.
func (e *Engine) Dropped() int { return e.dropped }
func (e *Engine) Late() int    { return e.late }

// Watches reports whether this correlation is over a given rule.
func (e *Engine) Watches(rule string) bool {
	for _, r := range e.rule.Rules {
		if strings.EqualFold(r, rule) {
			return true
		}
	}
	return false
}

// group is the key an event falls under.
func (e *Engine) group(ev telemetry.Event) (string, map[string]string, bool) {
	if len(e.rule.GroupBy) == 0 {
		return "", nil, true
	}
	f := ev.Fields()
	vals := map[string]string{}
	var parts []string
	for _, g := range e.rule.GroupBy {
		v, ok := f[g]
		if !ok || strings.TrimSpace(v) == "" {
			// An event missing a grouping field cannot be placed. Dropped
			// rather than pooled under an empty key, which would make one
			// bucket that every unrelated event falls into.
			return "", nil, false
		}
		vals[g] = v
		parts = append(parts, g+"\x00"+v)
	}
	return strings.Join(parts, "\x01"), vals, true
}

// window is the start of the window an event time falls in.
//
// Fixed windows aligned to the epoch rather than sliding ones. A sliding
// window has to be recomputed on every arrival and cannot be closed by a
// watermark at all, because there is always another window still open. The
// cost is that two events fifteen minutes apart can land in different
// buckets, which is why the temporal types are evaluated over each closing
// window together with the one before it: Close keeps the closed window's
// events beside the next, and decide reports the occurrences that reach
// across the boundary, which no single window could have seen.
func (e *Engine) window(t time.Time) int64 {
	span := int64(e.rule.Timespan)
	return (t.UnixNano() / span) * span
}

// Observe takes one event that matched one of the correlated rules.
func (e *Engine) Observe(s Seen, watermark time.Time) error {
	if !e.Watches(s.Rule) {
		return fmt.Errorf("%q is not one of the rules %q correlates",
			s.Rule, e.rule.Title)
	}
	when := s.Event.Time
	if when.IsZero() {
		when = s.Event.Received
	}
	if when.IsZero() {
		return fmt.Errorf("this event has no time, so no window holds it")
	}
	key, _, ok := e.group(s.Event)
	if !ok {
		e.dropped++
		return nil
	}
	start := e.window(when)
	if !watermark.IsZero() &&
		watermark.UnixNano() >= start+int64(e.rule.Timespan) {
		// Its window has already been closed and reported. Counted rather
		// than silently accepted into a window nobody will look at again:
		// a rising late count is the signal that the watermark is too
		// aggressive for a source.
		e.late++
		return nil
	}

	gb, seen := e.buckets[key]
	if !seen {
		if e.groups >= MaxGroups {
			e.dropped++
			return nil
		}
		gb = &group{windows: map[int64]*bucket{}}
		e.buckets[key] = gb
		e.groups++
	}
	b, ok := gb.windows[start]
	if !ok {
		b = &bucket{}
		gb.windows[start] = b
	}
	b.events = append(b.events, s)
	return nil
}

// Close evaluates and releases every window the watermark has passed.
//
// Everything older than the watermark has been delivered, so a window
// ending before it is complete and can be decided. Anything still open is
// left alone.
func (e *Engine) Close(watermark time.Time) []Hit {
	var out []Hit
	span := int64(e.rule.Timespan)
	for key, gb := range e.buckets {
		starts := make([]int64, 0, len(gb.windows))
		for s := range gb.windows {
			starts = append(starts, s)
		}
		sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })
		for _, start := range starts {
			if watermark.UnixNano() < start+span {
				continue // still open
			}
			b := gb.windows[start]
			if h, ok := e.decide(key, start, b, gb.prior); ok {
				out = append(out, h)
			}
			if e.pairs() {
				// Kept beside the next window, which is the one whose events
				// can still pair with these; the window before it is let go,
				// because a pair reaches no further back than that.
				gb.prior = &closed{start: start, events: b.events}
			}
			delete(gb.windows, start)
		}
		// A group goes once nothing pairs with what closed. The window beside
		// a retained one closes — or is revealed never to have existed — by
		// the time the watermark is two windows past it, and holding it
		// longer would keep a group's memory alive after its events ran out.
		if len(gb.windows) == 0 && (gb.prior == nil ||
			watermark.UnixNano() >= gb.prior.start+2*span) {
			delete(e.buckets, key)
			e.groups--
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].From.Equal(out[j].From) {
			return out[i].From.Before(out[j].From)
		}
		return out[i].Why() < out[j].Why()
	})
	return out
}

// Flush closes every window regardless of the watermark.
//
// For the end of a replay, where there is no more input and leaving the
// last window open would silently lose the tail. Never for a live stream:
// closing a window early is exactly the bug the watermark exists to avoid.
func (e *Engine) Flush() []Hit {
	return e.Close(time.Unix(1<<62/int64(time.Second), 0))
}

// pairs reports whether this type's occurrences can reach across a window
// boundary, and so are evaluated over the pair of adjacent windows rather
// than one window at a time. The counting types are not: a count over two
// windows is a different number rather than the same one seen twice, and
// each window's count is already the whole of what the rule asks.
func (e *Engine) pairs() bool {
	return e.rule.Type == Temporal || e.rule.Type.Ordered()
}

// decide evaluates one closing window, beside the window that closed before
// it when there is one.
func (e *Engine) decide(key string, start int64, b *bucket, prior *closed) (Hit, bool) {
	if !e.pairs() {
		return e.evaluate(key, start, b)
	}
	return e.temporal(key, start, b, prior)
}

// temporal evaluates a closing window for the temporal types, over its own
// events together with the immediately preceding window's.
//
// The events are scanned as spans of the timespan anchored at each event,
// because the two windows together are twice the timespan wide and most of
// what they hold was never close to the rest. A span is reported only when
// it involves an event of the closing window: everything the earlier window
// could satisfy was reported when it closed, and reporting it again from
// beside the next window would fire one occurrence twice. Nothing is lost
// by that — an occurrence involving the closing window was invisible until
// now, and one involving only earlier events is more than the timespan from
// anything still arriving.
func (e *Engine) temporal(key string, start int64, b *bucket, prior *closed) (Hit, bool) {
	span := int64(e.rule.Timespan)
	// Only the window immediately before pairs: anything further back is
	// more than the timespan from everything closing now.
	paired := prior != nil && prior.start == start-span
	var events []Seen
	if paired {
		events = append(events, prior.events...)
	}
	events = append(events, b.events...)
	sort.SliceStable(events, func(i, j int) bool {
		return at(events[i].Event).Before(at(events[j].Event))
	})
	for i := range events {
		t := at(events[i].Event).UnixNano()
		j := i + 1
		for j < len(events) && at(events[j].Event).UnixNano() < t+span {
			j++
		}
		within := events[i:j]
		if paired && !reachesInto(within, start) {
			continue
		}
		if !e.holds(within, start) {
			continue
		}
		from := at(events[i].Event).UTC()
		h := Hit{
			Rule: e.rule.Title, From: from, To: from.Add(e.rule.Timespan),
			Severity: e.rule.Severity, Group: groupOf(key),
			Rules: firedOrder(within),
		}
		for _, s := range within {
			if len(h.Sample) < MaxSample {
				h.Sample = append(h.Sample, s.Event)
			}
		}
		if e.rule.Type.Ordered() {
			h.Count = len(e.rule.Rules)
		} else {
			h.Count = len(h.Rules)
		}
		return h, true
	}
	return Hit{}, false
}

// reachesInto reports whether the span includes an event of the window that
// is closing now rather than only of the one before it.
func reachesInto(within []Seen, boundary int64) bool {
	for _, s := range within {
		if at(s.Event).UnixNano() >= boundary {
			return true
		}
	}
	return false
}

// holds reports whether a span of events satisfies the rule. When it is
// paired with the window before, an ordered match must also be one that
// uses an event of the closing window: the leftmost reading of a span can
// be satisfied entirely by the earlier window's events, which were reported
// when that window closed.
func (e *Engine) holds(within []Seen, boundary int64) bool {
	if e.rule.Type == Temporal {
		want := map[string]bool{}
		for _, r := range e.rule.Rules {
			want[strings.ToLower(r)] = false
		}
		for _, s := range within {
			want[strings.ToLower(s.Rule)] = true
		}
		for _, got := range want {
			if !got {
				return false
			}
		}
		return true
	}
	if !follows(firedOrder(within), e.rule.Rules) {
		return false
	}
	return usesClosing(within, e.rule.Rules, boundary)
}

// usesClosing reports whether some in-order choice of the wanted rules over
// the span includes an event at or after the boundary. The choice that
// follows finds the leftmost one; when that falls entirely in the earlier
// window, each closing-window event takes its turn standing for its rule
// with the rest matched around it.
func usesClosing(within []Seen, want []string, boundary int64) bool {
	for p := range within {
		if at(within[p].Event).UnixNano() < boundary {
			continue
		}
		for j, w := range want {
			if !strings.EqualFold(within[p].Rule, w) {
				continue
			}
			if matches(within[:p], want[:j]) &&
				matches(within[p+1:], want[j+1:]) {
				return true
			}
		}
	}
	return false
}

// matches is follows over events rather than rule names, and without
// collapsing a rule that fired twice: the position a choice assigns each
// wanted rule matters, and a repeated rule is a repeated position.
func matches(in []Seen, want []string) bool {
	i := 0
	for _, s := range in {
		if i < len(want) && strings.EqualFold(s.Rule, want[i]) {
			i++
		}
	}
	return i == len(want)
}

// evaluate decides one window for the counting types, which a single window
// answers in full; the temporal types go through temporal instead.
func (e *Engine) evaluate(key string, start int64, b *bucket) (Hit, bool) {
	if len(b.events) == 0 {
		return Hit{}, false
	}
	from := time.Unix(0, start).UTC()
	h := Hit{
		Rule: e.rule.Title, From: from,
		To:       from.Add(e.rule.Timespan),
		Severity: e.rule.Severity,
		Group:    groupOf(key),
	}
	ordered := append([]Seen(nil), b.events...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return at(ordered[i].Event).Before(at(ordered[j].Event))
	})
	for _, s := range ordered {
		if len(h.Sample) < MaxSample {
			h.Sample = append(h.Sample, s.Event)
		}
	}

	switch e.rule.Type {
	case EventCount:
		h.Count = len(ordered)
		if !e.rule.Test.Holds(h.Count) {
			return Hit{}, false
		}
	case ValueCount:
		seen := map[string]bool{}
		for _, s := range ordered {
			if v, ok := s.Event.Fields()[e.rule.Field]; ok && v != "" {
				seen[v] = true
			}
		}
		h.Count = len(seen)
		if !e.rule.Test.Holds(h.Count) {
			return Hit{}, false
		}
	}
	return h, true
}

// firedOrder is the distinct rules in the order they first fired.
func firedOrder(in []Seen) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		k := strings.ToLower(s.Rule)
		if !seen[k] {
			seen[k] = true
			out = append(out, s.Rule)
		}
	}
	return out
}

// follows reports whether every rule in want appears in order within got.
//
// A subsequence rather than an exact match: other things happening in
// between is normal, and requiring an exact sequence would mean the
// detection stops working the moment anything else on the machine matches
// one of the rules.
func follows(got, want []string) bool {
	i := 0
	for _, g := range got {
		if i < len(want) && strings.EqualFold(g, want[i]) {
			i++
		}
	}
	return i == len(want)
}

func groupOf(key string) map[string]string {
	if key == "" {
		return nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(key, "\x01") {
		k, v, ok := strings.Cut(pair, "\x00")
		if ok {
			out[k] = v
		}
	}
	return out
}

func at(e telemetry.Event) time.Time {
	if !e.Time.IsZero() {
		return e.Time
	}
	return e.Received
}

// Watermark is how far behind now a stream is believed to be complete.
//
// The caller's to supply: internal/spool measures observed lateness per
// source and that is the right input. This exists so a caller with no
// measurement has an explicit, visible default rather than accidentally
// using the clock — which is the bug the package comment is about.
func Watermark(now time.Time, lateness time.Duration) time.Time {
	return now.Add(-lateness)
}

// Safe is a lateness that assumes nothing about the source.
//
// Five minutes, because cloud provider exports commonly batch on that
// interval, so a window closed sooner than this misses whole batches. Too
// long for a fast source and the right sort of wrong: closing late delays a
// detection, closing early loses one.
const Safe = 5 * time.Minute
