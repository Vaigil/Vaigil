// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package spool

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Retention, holds, and the watermark: the three places a store quietly
// stops being able to answer the question it was built for.

// Plan is what retention would do, before it does it.
type Plan struct {
	// Drop is what would be deleted, oldest first.
	Drop []Segment `json:"drop,omitempty"`
	// Held is what age or size said to drop and a hold pinned. Reported
	// rather than silently skipped: a spool over its cap because of a hold
	// nobody remembers is a disk that fills for a reason somebody has to be
	// told about.
	Held []Segment `json:"held,omitempty"`
	// Pinned is what the size limit said to drop and the retention floor
	// refused. A floor that quietly stopped binding whenever the disk got
	// full would be a floor on paper only, so a spool held over its cap by
	// its own floor says so in the plan — the same discipline as Held.
	Pinned []Segment `json:"pinned,omitempty"`
	// Freed is how many bytes dropping would recover.
	Freed int64 `json:"freed"`
	// Over is how far past the cap the spool would still be afterwards.
	// Non-zero means the holds or the floor are the binding constraint, not
	// the policy.
	Over int64 `json:"over,omitempty"`
	// Covers is the earliest arrival the spool would still answer for.
	Covers time.Time `json:"covers"`
	// Made is when the plan was made. Apply refuses a stale one.
	Made time.Time `json:"made"`
	// Segments is how many the spool held when the plan was made, which is
	// what Apply checks against.
	Segments int `json:"segments"`
	// Keep, Cap and Floor are the limits the plan was made under, carried so
	// a plan can be read on its own and Why can say which of them did the
	// work. Keep is the age limit actually applied — the configured one,
	// raised to the floor when the floor was higher.
	Keep  time.Duration `json:"keep"`
	Cap   int64         `json:"cap"`
	Floor time.Duration `json:"floor,omitempty"`
}

// Empty reports whether there is nothing to do.
func (p Plan) Empty() bool { return len(p.Drop) == 0 }

// Why explains a plan in one line.
func (p Plan) Why() string {
	// What could not go and why, for the two reasons an operator can act
	// on: a hold is lifted by whoever placed it, a floor by whoever set the
	// policy.
	blockedBy := ""
	switch {
	case len(p.Held) > 0 && len(p.Pinned) > 0:
		blockedBy = fmt.Sprintf("%d segment(s) are on hold and %d are inside "+
			"the %s retention floor", len(p.Held), len(p.Pinned), inDays(p.Floor))
	case len(p.Held) > 0:
		blockedBy = fmt.Sprintf("%d segment(s) are on hold", len(p.Held))
	case len(p.Pinned) > 0:
		blockedBy = fmt.Sprintf("%d segment(s) are inside the %s retention "+
			"floor", len(p.Pinned), inDays(p.Floor))
	}
	switch {
	case p.Empty() && blockedBy != "":
		return "nothing to drop: " + blockedBy
	case p.Empty():
		return "nothing is older than the age limit and the spool is under cap"
	case p.Over > 0:
		return fmt.Sprintf(
			"dropping %d segment(s) frees %d bytes and leaves the spool %d "+
				"bytes over cap, because %s",
			len(p.Drop), p.Freed, p.Over, blockedBy)
	case p.Covers.IsZero():
		// Everything goes. Printed as a sentence rather than as a zero date,
		// because "answer from 0001-01-01" is the one line in this output
		// somebody would skim past.
		return fmt.Sprintf(
			"dropping %d segment(s) frees %d bytes and leaves the spool "+
				"with nothing: it would answer for no period at all",
			len(p.Drop), p.Freed)
	default:
		return fmt.Sprintf(
			"dropping %d segment(s) frees %d bytes; the spool would then "+
				"answer from %s", len(p.Drop), p.Freed,
			p.Covers.Format(time.RFC3339))
	}
}

// inDays renders a retention duration the way a policy is written: whole
// days. A floor set as thirty days prints as 30d rather than 720h0m0s,
// which is a number a person has to convert back to check against the
// policy that set it.
func inDays(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	}
	return d.String()
}

// Retain plans what to delete. It changes nothing.
//
// Two limits, applied in that order: everything past the age limit goes, and
// then oldest-first until the spool is under the byte cap. The open segment
// is never a candidate — a store that deletes the file it is currently
// writing to is one that loses the events arriving during the delete, which
// is the window somebody is most likely to care about.
//
// The floor bounds both limits (NIST SP 800-53 AU-11 asks for one). It is
// the youngest age at which evidence may be deleted at all: an age limit
// shorter than the floor is raised to it, because a keep that undercuts the
// floor would delete evidence the organisation promised to keep, and the
// byte cap is not allowed to eat young evidence either — a spool that
// deletes this week's segment because March was busy is one that fails its
// retention commitments at exactly the moment somebody needs them. Over cap
// and pinned by the floor, the plan says it is over cap. The disk is then
// the operator's problem, which is the honest direction for the failure to
// land: a full disk is loud, an early delete is silent.
func (s *Spool) Retain() Plan {
	now := s.opt.Now()
	keep := s.opt.Keep
	if s.opt.Floor > keep {
		keep = s.opt.Floor
	}
	p := Plan{Made: now, Segments: len(s.idx.Segments), Keep: keep,
		Cap: s.opt.Cap, Floor: s.opt.Floor}
	segs := s.Segments()

	held := map[string]bool{}
	if s.holding(now) != "" {
		for _, seg := range segs {
			held[seg.Name] = true
		}
	}

	total := s.Bytes()
	// floored is what the floor protects from the size limit. The age limit
	// already respects it — keep was raised above — so this is the only
	// other road to a delete, and the one that would otherwise delete the
	// youngest evidence first.
	floored := func(seg Segment) bool {
		return s.opt.Floor > 0 && now.Sub(seg.Last) <= s.opt.Floor
	}
	candidate := func(seg Segment) bool {
		return seg.Sealed() && !held[seg.Name]
	}

	dropped := map[string]bool{}
	for _, seg := range segs {
		if !candidate(seg) {
			continue
		}
		if now.Sub(seg.Last) > keep {
			p.Drop = append(p.Drop, seg)
			dropped[seg.Name] = true
			p.Freed += seg.Bytes
			total -= seg.Bytes
		}
	}
	for _, seg := range segs {
		if total <= s.opt.Cap {
			break
		}
		if !candidate(seg) || dropped[seg.Name] {
			continue
		}
		if floored(seg) {
			continue
		}
		p.Drop = append(p.Drop, seg)
		dropped[seg.Name] = true
		p.Freed += seg.Bytes
		total -= seg.Bytes
	}
	if total > s.opt.Cap {
		p.Over = total - s.opt.Cap
	}

	for _, seg := range segs {
		if held[seg.Name] &&
			(now.Sub(seg.Last) > keep || p.Over > 0) {
			p.Held = append(p.Held, seg)
		}
		if !held[seg.Name] && !dropped[seg.Name] && p.Over > 0 &&
			candidate(seg) && floored(seg) {
			p.Pinned = append(p.Pinned, seg)
		}
		if !dropped[seg.Name] && (p.Covers.IsZero() ||
			seg.First.Before(p.Covers)) {
			p.Covers = seg.First
		}
	}
	return p
}

// Apply carries out a plan.
//
// Under the writer's lock, like every index change: an Apply that acted on
// the index as this handle last saw it would save that stale copy over the
// one another writer saved in between, and the events of theirs would be on
// disk and missing from the index — a store that answers with fewer events
// than it holds, which reads exactly like a quiet period.
//
// Refuses a plan made against a different shape of spool, checked after the
// rejoin so it is checked against the store as it is now rather than as this
// handle remembers it. The gap between planning and applying is where an
// operator looks at what would go, decides it is fine, and applies it ten
// minutes later — by which time a segment may have sealed, a hold may have
// been placed, and the list they approved is not the list that would run.
// Deleting evidence is not a thing to be approximately right about.
func (s *Spool) Apply(p Plan) (int, error) {
	if p.Made.IsZero() {
		return 0, fmt.Errorf(
			"that plan was never made by Retain, so nobody has seen what it " +
				"would delete")
	}
	unlock, err := s.lock()
	if err != nil {
		return 0, err
	}
	defer unlock()
	if p.Segments != len(s.idx.Segments) {
		return 0, fmt.Errorf(
			"the spool held %d segment(s) when the plan was made and holds "+
				"%d now. Plan again and look at the new list",
			p.Segments, len(s.idx.Segments))
	}
	now := s.opt.Now()
	remaining := s.idx.Segments[:0:0]
	going := map[string]bool{}
	for _, seg := range p.Drop {
		going[seg.Name] = true
	}
	var gone int
	for _, seg := range s.idx.Segments {
		if !going[seg.Name] {
			remaining = append(remaining, seg)
			continue
		}
		// Re-checked at the moment of deletion, not trusted from the plan. A
		// hold placed after the plan was made is a hold placed by somebody
		// who had a reason.
		if why := s.holding(now); why != "" {
			remaining = append(remaining, seg)
			continue
		}
		// The floor is re-checked the same way. A plan made before a floor
		// was declared is not a licence to delete young evidence after it
		// was, and an operator applying an old plan with a new policy in
		// force is the one case where the two disagree.
		if s.opt.Floor > 0 && now.Sub(seg.Last) <= s.opt.Floor {
			remaining = append(remaining, seg)
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, seg.Name)); err != nil &&
			!os.IsNotExist(err) {
			return gone, err
		}
		gone++
	}
	s.idx.Segments = remaining
	if s.cur >= 0 {
		// The open segment moved in the slice. Find it again by name rather
		// than trusting an index across a rewrite.
		s.cur = -1
		for i, seg := range s.idx.Segments {
			if !seg.Sealed() {
				s.cur = i
			}
		}
	}
	return gone, s.save()
}

// holding names an active hold, or empty.
//
// It takes no segment because a hold covers the whole spool; see Hold for
// why a hold scoped to a time range is a hold that is always too narrow.
func (s *Spool) holding(now time.Time) string {
	for _, h := range s.idx.Holds {
		if h.Active(now) {
			return h.Name
		}
	}
	return ""
}

// Hold pins every segment against retention until it is lifted.
//
// Deliberately whole-spool rather than a time range. A hold placed over "the
// week of the incident" is a hold placed before anybody knows when the
// incident started, and the commonest correction in an investigation is that
// it started earlier than anyone thought. Holding everything is cheap for the
// days a hold lasts and is the only version that cannot be too narrow.
func (s *Spool) Hold(h Hold) error {
	if strings.TrimSpace(h.Name) == "" {
		return fmt.Errorf("a hold needs a name, so somebody can lift it")
	}
	if strings.TrimSpace(h.By) == "" {
		return fmt.Errorf("a hold needs whoever placed it on the record")
	}
	if strings.TrimSpace(h.Why) == "" {
		return fmt.Errorf(
			"a hold needs a reason. One nobody can explain is one nobody " +
				"will dare lift, and a spool that can never delete anything " +
				"breaks its retention commitments as surely as one that " +
				"deletes too early")
	}
	if h.At.IsZero() {
		h.At = s.opt.Now()
	}
	// Under the writer's lock, like every index change. A hold is the one
	// write that must not be lost to a racing append: the hold is placed
	// because an investigation started, and the writer it races with is the
	// ingestion that investigation is about to depend on.
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	for _, existing := range s.idx.Holds {
		if existing.Name == h.Name {
			return fmt.Errorf("there is already a hold called %q", h.Name)
		}
	}
	s.idx.Holds = append(s.idx.Holds, h)
	return s.save()
}

// Lift removes a hold by name.
//
// Under the writer's lock for the same reason as Hold: lifting a hold is
// what lets deletion run again, and a lift lost to a racing append is a
// hold nobody can see that retention keeps refusing for.
func (s *Spool) Lift(name string) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	keep := s.idx.Holds[:0:0]
	var found bool
	for _, h := range s.idx.Holds {
		if h.Name == name {
			found = true
			continue
		}
		keep = append(keep, h)
	}
	if !found {
		return fmt.Errorf("there is no hold called %q", name)
	}
	s.idx.Holds = keep
	return s.save()
}

// Holds returns the holds currently in force.
func (s *Spool) Holds() []Hold {
	now := s.opt.Now()
	var out []Hold
	for _, h := range s.idx.Holds {
		if h.Active(now) {
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lateness is the observed arrival delay at a quantile, from the histogram.
//
// Measured, never configured. Every correlation window in every product is
// built on somebody's guess about how late events arrive, and the guess is
// made once, by the person writing the rule, about sources they have not seen
// yet. The spool has watched every event that ever arrived and is the only
// thing in the system that knows.
//
// Returned as the top of the log2 bucket, so it rounds up. A window sized
// from this is too wide rather than too narrow, and too wide costs compute
// while too narrow misses attacks.
//
// The histogram is cumulative over the spool's life and is not trimmed when
// segments are. Lateness(1) is therefore the worst delay ever seen and not
// the worst seen lately: one pathological export in March pins it until the
// spool is rebuilt. That is the right way round for a floor on how long to
// wait, and the wrong number to put on a dashboard as "current".
func (s *Spool) Lateness(q float64) time.Duration {
	if q <= 0 || q > 1 {
		return 0
	}
	var total int64
	for _, n := range s.idx.Late {
		total += n
	}
	if total == 0 {
		return 0
	}
	want := int64(float64(total) * q)
	var seen int64
	buckets := make([]int, 0, len(s.idx.Late))
	for b := range s.idx.Late {
		buckets = append(buckets, b)
	}
	sort.Ints(buckets)
	for _, b := range buckets {
		seen += s.idx.Late[b]
		if seen >= want {
			return time.Duration(1<<b) * time.Second
		}
	}
	return time.Duration(1<<buckets[len(buckets)-1]) * time.Second
}

// Ahead is how many events arrived with a source clock running fast.
//
// Not an error and not folded into Lateness. A fleet minutes ahead is an
// operational fact worth a dashboard line, and averaging it into the arrival
// delay would hide both it and the delay.
func (s *Spool) Ahead() int64 { return s.idx.Ahead }

// Watermark is the arrival time before which the spool believes it is complete.
//
// The newest arrival, less the observed 99th-percentile delay. A correlation
// window ending before this is one that can be closed; one ending after it is
// still waiting for events that have not turned up yet, and closing it early
// is how a multi-stage detection reports the first three steps of an attack
// and not the fourth.
//
// This is a measurement and not a guarantee, and the quantile is where the
// trade lives. At the 99th, one arrival in a hundred is later than the
// watermark by construction; a source that is slow only occasionally does not
// move the number at all, and its rare late event falls outside a window that
// has already closed. It is still in the spool — the watermark excludes
// things from a closed window, never from storage — and a caller who would
// rather wait than miss it asks for a higher quantile, up to 1, which is the
// slowest arrival the spool has ever seen. That pushes the watermark further
// back and closes windows later. This function makes the choice visible
// rather than making it for them.
func (s *Spool) Watermark() time.Time {
	var newest time.Time
	for _, seg := range s.idx.Segments {
		if seg.Last.After(newest) {
			newest = seg.Last
		}
	}
	if newest.IsZero() {
		return time.Time{}
	}
	return newest.Add(-s.Lateness(0.99))
}
