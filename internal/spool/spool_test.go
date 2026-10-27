// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package spool

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vaigil/vaigil/internal/telemetry"
)

var base = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

// clock is a settable now, so a test can age a spool without sleeping.
type clock struct{ at time.Time }

func (c *clock) now() time.Time { return c.at }

func openAt(t testing.TB, c *clock, o Options) (*Spool, string) {
	t.Helper()
	dir := t.TempDir()
	o.Now = c.now
	s, err := Open(dir, o)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return s, dir
}

func event(at, received time.Time, msg string) telemetry.Event {
	return telemetry.Event{
		Time: at, Received: received, Class: telemetry.ClassAuthentication,
		Activity: 1, Severity: telemetry.SeverityInfo,
		Disposition: telemetry.DispositionAllowed,
		Source:      "okta/system", Message: msg,
	}
}

func TestAnEventGoesInTheSegmentForWhenItArrivedNotWhenItClaims(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()

	// A source claiming to be a week in the future, and one claiming to be a
	// week in the past. Both arrive now, and both must land in today's
	// segment — otherwise one lands in a partition already swept and the
	// other in one already dropped, and neither is an error anybody sees.
	for _, claimed := range []time.Time{
		base.Add(7 * 24 * time.Hour), base.Add(-7 * 24 * time.Hour), base,
	} {
		if _, err := s.Append(event(claimed, base, "login")); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	segs := s.Segments()
	if len(segs) != 1 {
		t.Fatalf("a source's clock split the spool into %d segments",
			len(segs))
	}
	if !strings.HasPrefix(segs[0].Name, "20260925") {
		t.Errorf("segment is named %q, not for the day of arrival",
			segs[0].Name)
	}
	if segs[0].Events != 3 {
		t.Errorf("segment holds %d events, want 3", segs[0].Events)
	}
}

func TestArrivalAndEventTimeAreSeparateQueries(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()

	// Happened yesterday, arrived today. A daily export does this every day.
	late := event(base.Add(-20*time.Hour), base, "yesterday's export")
	prompt := event(base, base, "arrived immediately")
	for _, e := range []telemetry.Event{late, prompt} {
		if _, err := s.Append(e); err != nil {
			t.Fatal(err)
		}
	}

	var arrived, happened []string
	if err := s.Range(base.Add(-time.Hour), base.Add(time.Hour),
		func(e telemetry.Event) error {
			arrived = append(arrived, e.Message)
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if len(arrived) != 2 {
		t.Errorf("Range by arrival found %d, want both", len(arrived))
	}
	if err := s.During(base.Add(-time.Hour), base.Add(time.Hour),
		func(e telemetry.Event) error {
			happened = append(happened, e.Message)
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if len(happened) != 1 || happened[0] != "arrived immediately" {
		t.Errorf("During by event time found %v, want only the one that "+
			"happened in the window", happened)
	}
}

func TestAReaderSeesEventsWrittenASecondAgo(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	if _, err := s.Append(event(base, base, "just now")); err != nil {
		t.Fatal(err)
	}
	// No Seal. A reader that only sees sealed segments reports an incident
	// in progress as a quiet period.
	var seen int
	if err := s.Range(time.Time{}, time.Time{},
		func(telemetry.Event) error { seen++; return nil }); err != nil {
		t.Fatal(err)
	}
	if seen != 1 {
		t.Fatalf("an unsealed segment's events are invisible: saw %d", seen)
	}
}

func TestASegmentRollsOnTheDayAndOnSize(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{SegmentBytes: 400})
	defer s.Close()

	for range 10 {
		if _, err := s.Append(event(base, c.at, "a message long enough to "+
			"push the segment over four hundred bytes quickly")); err != nil {
			t.Fatal(err)
		}
	}
	bySize := len(s.Segments())
	if bySize < 2 {
		t.Fatalf("size never rolled the segment: %d segment(s)", bySize)
	}

	c.at = base.Add(24 * time.Hour)
	if _, err := s.Append(event(base, c.at, "next day")); err != nil {
		t.Fatal(err)
	}
	segs := s.Segments()
	if len(segs) != bySize+1 {
		t.Errorf("the day boundary did not roll: %d then %d",
			bySize, len(segs))
	}
	if !strings.HasPrefix(segs[len(segs)-1].Name, "20260926") {
		t.Errorf("the new segment is %q", segs[len(segs)-1].Name)
	}
}

func TestASealedSegmentIsDigestedAndTamperingShows(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{})
	if _, err := s.Append(event(base, base, "login")); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	seg := s.Segments()[0]
	if !seg.Sealed() {
		t.Fatal("a sealed segment has no digest")
	}
	if bad, err := s.Verify(); err != nil || len(bad) != 0 {
		t.Fatalf("a fresh spool does not verify: %v %v", bad, err)
	}
	if len(s.Anchor()) != 1 {
		t.Error("nothing to anchor in the audit log")
	}

	// Rewrite history. One hash per segment is what makes this cheap enough
	// to do unconditionally on volume data.
	path := filepath.Join(dir, seg.Name)
	if err := os.WriteFile(path,
		[]byte(`{"time":"2026-09-25T12:00:00Z","received":"2026-09-25T12:00:00Z","class":3002,"activity":1,"severity":1,"disposition":1,"source":"okta/system","message":"nothing happened"}`+"\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	bad, err := s.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 1 || !strings.Contains(bad[0], seg.Name) {
		t.Fatalf("a rewritten segment verified: %v", bad)
	}
}

func TestAnOpenSegmentIsNotReportedAsUnverified(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	if _, err := s.Append(event(base, base, "login")); err != nil {
		t.Fatal(err)
	}
	bad, err := s.Verify()
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 0 {
		t.Errorf("a segment still being written to was reported: %v", bad)
	}
}

func TestAgeAndSizeAreBothLimits(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{
		SegmentBytes: 200, Keep: 48 * time.Hour, Cap: 1 << 30,
	})
	defer s.Close()

	for day := range 5 {
		c.at = base.Add(time.Duration(day) * 24 * time.Hour)
		if _, err := s.Append(event(c.at, c.at, "day")); err != nil {
			t.Fatal(err)
		}
	}
	c.at = base.Add(5 * 24 * time.Hour)
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}

	p := s.Retain()
	if len(p.Drop) != 3 {
		t.Fatalf("age dropped %d segment(s), want the three over two days: %s",
			len(p.Drop), p.Why())
	}
	if p.Covers.IsZero() || p.Covers.Before(base.Add(72*time.Hour)) {
		t.Errorf("the spool would still claim to cover %s", p.Covers)
	}

	// Now the size limit alone, with nothing old enough to age out.
	c.at = base.Add(5 * 24 * time.Hour)
	s.opt.Keep = 365 * 24 * time.Hour
	s.opt.Cap = 400
	p = s.Retain()
	if p.Empty() {
		t.Fatal("a spool over its byte cap planned to drop nothing")
	}
	if p.Freed == 0 {
		t.Error("the plan frees nothing")
	}
}

func TestPlanningDeletesNothing(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{SegmentBytes: 200, Keep: time.Hour})
	for day := range 3 {
		c.at = base.Add(time.Duration(day) * 24 * time.Hour)
		if _, err := s.Append(event(c.at, c.at, "day")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	before, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))

	p := s.Retain()
	if p.Empty() {
		t.Fatal("nothing planned")
	}
	after, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(after) != len(before) {
		t.Fatalf("planning deleted %d file(s)", len(before)-len(after))
	}

	gone, err := s.Apply(p)
	if err != nil {
		t.Fatal(err)
	}
	if gone != len(p.Drop) {
		t.Errorf("applied deleted %d, planned %d", gone, len(p.Drop))
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(left) != len(before)-gone {
		t.Errorf("%d files left, expected %d", len(left), len(before)-gone)
	}
}

func TestAStalePlanIsRefused(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{SegmentBytes: 200, Keep: time.Hour})
	defer s.Close()
	for day := range 3 {
		c.at = base.Add(time.Duration(day) * 24 * time.Hour)
		if _, err := s.Append(event(c.at, c.at, "day")); err != nil {
			t.Fatal(err)
		}
	}
	p := s.Retain()

	// Ten minutes pass and another segment seals. The list the operator
	// approved is no longer the list that would run.
	c.at = base.Add(4 * 24 * time.Hour)
	if _, err := s.Append(event(c.at, c.at, "later")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(p); err == nil {
		t.Fatal("a plan made against a different spool was applied")
	}
}

func TestAPlanNobodyMadeIsRefused(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	if _, err := s.Apply(Plan{Drop: s.Segments()}); err == nil {
		t.Fatal("a hand-made plan deleted segments nobody had seen listed")
	}
}

func TestAHoldPinsEverythingAndSaysSo(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{SegmentBytes: 200, Keep: time.Hour})
	defer s.Close()
	for day := range 3 {
		c.at = base.Add(time.Duration(day) * 24 * time.Hour)
		if _, err := s.Append(event(c.at, c.at, "day")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}

	if err := s.Hold(Hold{Name: "inc-2026-41", By: "rashik",
		Why: "possible exfiltration under investigation"}); err != nil {
		t.Fatal(err)
	}
	p := s.Retain()
	if !p.Empty() {
		t.Fatalf("retention planned to drop %d segment(s) under a hold",
			len(p.Drop))
	}
	if len(p.Held) == 0 {
		t.Error("the plan does not report that a hold is the reason")
	}
	if !strings.Contains(p.Why(), "hold") {
		t.Errorf("the explanation does not mention the hold: %q", p.Why())
	}

	// And a plan made before the hold does not get to run afterwards.
	if err := s.Lift("inc-2026-41"); err != nil {
		t.Fatal(err)
	}
	fresh := s.Retain()
	if err := s.Hold(Hold{Name: "inc-2026-41", By: "rashik",
		Why: "reopened"}); err != nil {
		t.Fatal(err)
	}
	gone, err := s.Apply(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if gone != 0 {
		t.Fatalf("%d segment(s) deleted under a hold placed after the plan",
			gone)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(left) == 0 {
		t.Fatal("everything was deleted under a hold")
	}
}

func TestAHoldNobodyCanExplainIsRefused(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	for _, h := range []Hold{
		{By: "rashik", Why: "incident"},
		{Name: "x", Why: "incident"},
		{Name: "x", By: "rashik"},
	} {
		if err := s.Hold(h); err == nil {
			t.Errorf("accepted a hold missing something: %+v", h)
		}
	}
}

func TestTheWatermarkIsMeasuredRatherThanConfigured(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()

	// Ninety prompt arrivals and ten that took an hour. Nobody configured an
	// hour anywhere; the spool watched it happen.
	for i := range 90 {
		at := base.Add(time.Duration(i) * time.Second)
		if _, err := s.Append(event(at, at, "prompt")); err != nil {
			t.Fatal(err)
		}
	}
	var newest time.Time
	for i := range 10 {
		newest = base.Add(time.Duration(90+i) * time.Second)
		if _, err := s.Append(event(newest.Add(-time.Hour), newest,
			"an hour late")); err != nil {
			t.Fatal(err)
		}
	}

	if lat := s.Lateness(0.5); lat > time.Minute {
		t.Errorf("the median delay is %s; most events arrived at once", lat)
	}
	if lat := s.Lateness(0.99); lat < time.Hour {
		t.Errorf("the 99th percentile is %s, under the hour a tenth of the "+
			"events actually took", lat)
	}
	wm := s.Watermark()
	if !wm.Before(newest.Add(-time.Hour)) {
		t.Errorf("the watermark %s is not behind the newest arrival by the "+
			"observed tail", wm)
	}
}

// The stated limit, asserted rather than left in a comment: a source that is
// slow once in a while does not move the 99th percentile, so its late event
// falls outside a window that has already closed. That is the trade the
// quantile makes, and a caller who cannot accept it asks for a higher one.
func TestARareLateArrivalDoesNotMoveTheWatermarkAndIsSaidSo(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	for i := range 999 {
		at := base.Add(time.Duration(i) * time.Second)
		if _, err := s.Append(event(at, at, "prompt")); err != nil {
			t.Fatal(err)
		}
	}
	slow := base.Add(1000 * time.Second)
	if _, err := s.Append(event(slow.Add(-6*time.Hour), slow,
		"a daily export")); err != nil {
		t.Fatal(err)
	}
	if lat := s.Lateness(0.99); lat > time.Minute {
		t.Errorf("one arrival in a thousand moved the 99th percentile to %s",
			lat)
	}
	// And it is in the spool regardless. Excluded from a closed window is not
	// the same as dropped.
	var found bool
	if err := s.During(slow.Add(-7*time.Hour), slow,
		func(e telemetry.Event) error {
			if e.Message == "a daily export" {
				found = true
			}
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Error("the late event is not in the store")
	}
	// A tail of one in a thousand is not reached by the 99.9th percentile
	// either — the 999th of a thousand ordered samples is still prompt. Only
	// the whole distribution reaches it, and that is the honest shape of the
	// trade rather than a rounding detail.
	if lat := s.Lateness(1); lat < 6*time.Hour {
		t.Errorf("the whole distribution does not reach the tail: %s", lat)
	}
}

func TestAClockRunningFastIsCountedRatherThanAveragedIn(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	// Happened "later" than it arrived: the source's clock is ahead.
	if _, err := s.Append(event(base.Add(10*time.Minute), base,
		"fast clock")); err != nil {
		t.Fatal(err)
	}
	if s.Ahead() != 1 {
		t.Errorf("a source running fast was not counted: %d", s.Ahead())
	}
	if lat := s.Lateness(0.99); lat != 0 {
		t.Errorf("a negative delay was folded into the arrival delay: %s",
			lat)
	}
}

func TestASpoolReopensWithEverythingItKnew(t *testing.T) {
	c := &clock{at: base}
	dir := t.TempDir()
	s, err := Open(dir, Options{Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if _, aerr := s.Append(event(base, base,
			fmt.Sprintf("event %d", i))); aerr != nil {
			t.Fatal(aerr)
		}
	}
	if err := s.Hold(Hold{Name: "audit", By: "rashik",
		Why: "evidence for the SOC 2 period"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir, Options{Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if again.Events() != 5 {
		t.Errorf("reopened with %d events", again.Events())
	}
	if len(again.Holds()) != 1 {
		t.Error("the hold did not survive a restart, so retention would run")
	}
	if bad, verr := again.Verify(); verr != nil || len(bad) != 0 {
		t.Errorf("reopened spool does not verify: %v %v", bad, verr)
	}
	var seen int
	if err := again.Range(time.Time{}, time.Time{},
		func(telemetry.Event) error { seen++; return nil }); err != nil {
		t.Fatal(err)
	}
	if seen != 5 {
		t.Errorf("read back %d events", seen)
	}
}

func TestAnIndexedSegmentThatIsNotOnDiskIsAnError(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{})
	if _, err := s.Append(event(base, base, "login")); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, s.Segments()[0].Name)); err != nil {
		t.Fatal(err)
	}
	err := s.Range(time.Time{}, time.Time{},
		func(telemetry.Event) error { return nil })
	if err == nil {
		t.Fatal("a query over a spool missing a file reported nothing wrong, " +
			"which reads exactly like a quiet period")
	}
	if !strings.Contains(err.Error(), "coverage it does not have") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}
}

func TestAnUnusableEventIsRefusedAtTheDoor(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	if _, err := s.Append(telemetry.Event{Received: base}); err == nil {
		t.Fatal("an event with no time was stored, and nothing can window it")
	}
	if s.Events() != 0 {
		t.Error("the refused event was counted")
	}
}

func TestReceivedIsStampedWhenTheCallerLeavesItOut(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	e := event(base.Add(-time.Minute), time.Time{}, "no arrival time")
	if _, err := s.Append(e); err != nil {
		t.Fatal(err)
	}
	var got telemetry.Event
	if err := s.Range(time.Time{}, time.Time{},
		func(e telemetry.Event) error { got = e; return nil }); err != nil {
		t.Fatal(err)
	}
	if !got.Received.Equal(base) {
		t.Errorf("arrival stamped as %s, want the spool's clock", got.Received)
	}
}

// Dropping everything is a real plan and a zero date is the one line in the
// output somebody would skim past.
func TestAPlanThatEmptiesTheSpoolSaysSoInWords(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{SegmentBytes: 200, Keep: time.Second})
	defer s.Close()
	if _, err := s.Append(event(base, base, "login")); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	c.at = base.Add(time.Hour)
	p := s.Retain()
	if len(p.Drop) != 1 {
		t.Fatalf("planned to drop %d", len(p.Drop))
	}
	if strings.Contains(p.Why(), "0001") {
		t.Errorf("the plan prints a zero date: %q", p.Why())
	}
	if !strings.Contains(p.Why(), "no period at all") {
		t.Errorf("the plan does not say the spool would be empty: %q",
			p.Why())
	}
}

// TestTwoWritersKeepEveryEvent: serve ingesting while a command writes. The
// segments append, but the index does not — every save writes it whole — so
// without a writer's lock the second save discards the first's counts and
// the store answers with fewer events than it holds.
func TestTwoWritersKeepEveryEvent(t *testing.T) {
	c := &clock{at: base}
	dir := t.TempDir()
	const each = 50

	write := func(name string) func() error {
		return func() error {
			s, err := Open(dir, Options{Now: c.now})
			if err != nil {
				return err
			}
			for i := range each {
				if _, aerr := s.Append(event(base, base,
					fmt.Sprintf("%s %d", name, i))); aerr != nil {
					return aerr
				}
			}
			return s.Close()
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, name := range []string{"serve", "command"} {
		wg.Add(1)
		go func(f func() error) {
			defer wg.Done()
			errs <- f()
		}(write(name))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	// A third, fresh open: what the store says, not what either writer left
	// in its own memory.
	fresh, err := Open(dir, Options{Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if got := fresh.Events(); got != 2*each {
		t.Errorf("the index holds %d events after two writers wrote %d", got,
			2*each)
	}
	var inIndex, onDisk int
	for _, seg := range fresh.Segments() {
		inIndex += seg.Events
	}
	if inIndex != 2*each {
		t.Errorf("the segments' counts sum to %d, want %d", inIndex, 2*each)
	}
	if err := fresh.Range(time.Time{}, time.Time{},
		func(telemetry.Event) error { onDisk++; return nil }); err != nil {
		t.Fatal(err)
	}
	if onDisk != 2*each {
		t.Errorf("%d events on disk, want %d", onDisk, 2*each)
	}
	if bad, err := fresh.Verify(); err != nil || len(bad) != 0 {
		t.Errorf("a spool two writers filled does not verify: %v %v", bad, err)
	}
}

// TestAStaleLockDoesNotBlockForever: a writer that died holding the lock
// must not stop ingestion until somebody notices a file. The lock is aged by
// mtime, because a crashed holder can tell nobody it crashed.
func TestAStaleLockDoesNotBlockForever(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{})
	defer s.Close()
	lock := filepath.Join(dir, "index.json.lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dead := time.Now().Add(-2 * lockStale)
	if err := os.Chtimes(lock, dead, dead); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := s.Append(event(base, base, "after the crash"))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * lockWait):
		t.Fatal("a lock from a dead holder still blocks the writer")
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Errorf("the taken-over lock was left behind")
	}
}

// TestALockAnotherWriterHoldsIsWaitedForNotIgnored: a lock too young to be
// stale belongs to a live writer, and the second must fail rather than
// write beside it.
func TestALockAnotherWriterHoldsIsWaitedForNotIgnored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.json.lock")
	unlock, err := lockFile(path, 50*time.Millisecond, lockStale)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockFile(path, 50*time.Millisecond, lockStale); err == nil {
		t.Fatal("a second writer took a lock the first still holds")
	}
	unlock()
	again, err := lockFile(path, 50*time.Millisecond, lockStale)
	if err != nil {
		t.Fatalf("a released lock was not given up: %v", err)
	}
	again()
}

// TestTheLockIsHeldPerOperationAndReleasedOnClose: readers never wait on a
// writer, which is only possible because the lock lasts exactly as long as
// the operation that changed the store.
func TestTheLockIsHeldPerOperationAndReleasedOnClose(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{})
	lock := filepath.Join(dir, "index.json.lock")
	if _, err := s.Append(event(base, base, "one")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatal("the writer's lock outlived the append")
	}
	// Reading takes nothing, so a reader never waits on a writer.
	if len(s.Segments()) != 1 {
		t.Fatalf("the store holds %d segment(s)", len(s.Segments()))
	}
	if bad, err := s.Verify(); err != nil || len(bad) != 0 {
		t.Fatalf("verify: %v %v", bad, err)
	}
	if err := s.Range(time.Time{}, time.Time{},
		func(telemetry.Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatal("reading the spool took the writer's lock")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatal("Close left the writer's lock behind")
	}

	// And the next writer takes the store straight after.
	next, err := Open(dir, Options{Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if _, err := next.Append(event(base, base, "two")); err != nil {
		t.Fatalf("a released lock still stood in the way: %v", err)
	}
}

// A writer that releases rather than closes leaves one growing segment, not
// a sealed one for every few events; the day still rolls and seals it, and a
// segment whose file is not what the index says is never added to.
func TestAReleasedSegmentIsResumed(t *testing.T) {
	c := &clock{at: base}
	_, dir := openAt(t, c, Options{})
	for i := range 5 {
		s, err := Open(dir, Options{Now: c.now})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Append(event(base, c.at, fmt.Sprint("push ", i))); err != nil {
			t.Fatal(err)
		}
		if err := s.Release(); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := Open(dir, Options{Now: c.now})
	segs := s.Segments()
	if len(segs) != 1 || segs[0].Events != 5 || segs[0].Digest != "" {
		t.Fatalf("five released pushes made %+v", segs)
	}
	var n int
	if err := s.Range(time.Time{}, time.Time{}, func(telemetry.Event) error { n++; return nil }); err != nil || n != 5 {
		t.Errorf("read back %d events, %v", n, err)
	}
	// The next day starts a new segment and seals the old one.
	c.at = base.Add(24 * time.Hour)
	if _, err := s.Append(event(c.at, c.at, "tomorrow")); err != nil {
		t.Fatal(err)
	}
	if segs := s.Segments(); len(segs) != 2 || segs[0].Digest == "" {
		t.Errorf("the day did not roll and seal: %+v", segs)
	}
	_ = s.Release()

	// Somebody appends to the released file behind the index's back.
	f, _ := os.OpenFile(filepath.Join(dir, s.Segments()[1].Name), os.O_WRONLY|os.O_APPEND, 0o600)
	_, _ = f.WriteString("{}\n")
	_ = f.Close()
	again, _ := Open(dir, Options{Now: c.now})
	if _, err := again.Append(event(c.at, c.at, "after")); err != nil {
		t.Fatal(err)
	}
	if segs := again.Segments(); len(segs) != 3 {
		t.Errorf("a segment whose size disagrees with the index was resumed: %d segments", len(segs))
	}
	_ = again.Close()
}

// TestABatchLandsWholeAndCounted: the shape a push source produces —
// hundreds of events handed over together — stored by one call. Everything
// the batch held is on disk in order, the index counts it after a reopen
// rather than only in the writer's memory, and the segment each event landed
// in is said, in order.
func TestABatchLandsWholeAndCounted(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{})
	batch := make([]telemetry.Event, 0, 500)
	for i := range 500 {
		at := base.Add(time.Duration(i) * time.Second)
		batch = append(batch, event(at, at, fmt.Sprintf("push %d", i)))
	}
	into, err := s.AppendBatch(batch)
	if err != nil {
		t.Fatalf("append batch: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	fresh, err := Open(dir, Options{Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if got := fresh.Events(); got != 500 {
		t.Fatalf("the index holds %d events after a reopen, want the 500 in "+
			"the batch — the counts were not saved with them", got)
	}
	if segs := fresh.Segments(); len(segs) != 1 || segs[0].Events != 500 {
		t.Fatalf("the segment says %v", segs)
	}
	var read []string
	if err := fresh.Range(time.Time{}, time.Time{},
		func(e telemetry.Event) error {
			read = append(read, e.Message)
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if len(read) != 500 || read[0] != "push 0" || read[499] != "push 499" {
		t.Fatalf("read back %d events; first %q last %q", len(read),
			read[0], read[len(read)-1])
	}
	for i, name := range into {
		if name != fresh.Segments()[0].Name {
			t.Errorf("event %d was said to land in %q, not %q", i, name,
				fresh.Segments()[0].Name)
		}
	}
}

// TestABatchIsRefusedWhole: an event that cannot be stored refuses the
// batch it is part of, storing none of it. The alternative — storing the
// events before the bad one — is what a loop of single Appends leaves, and a
// caller that retries then stores that half twice.
func TestABatchIsRefusedWhole(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{})
	defer s.Close()
	ok := event(base, base, "fine")
	batch := []telemetry.Event{ok,
		{Received: base, Source: "okta/system"}, // no time: nothing can window it
		ok}
	if _, err := s.AppendBatch(batch); err == nil {
		t.Fatal("a batch holding an event with no time was accepted")
	}
	if s.Events() != 0 {
		t.Errorf("the refused batch left %d event(s) behind", s.Events())
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(files) != 0 {
		t.Errorf("the refused batch left %d segment file(s)", len(files))
	}
}

// TestABatchThatCrossesADayRollsInsideItself: a batch spanning midnight is
// not one segment falsely dated by its first arrival. The day rolls where it
// always does, mid-batch, and both segments are counted and named.
func TestABatchThatCrossesADayRollsInsideItself(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	next := base.Add(24 * time.Hour)
	batch := []telemetry.Event{
		event(base, base, "before midnight"),
		event(next, next, "after midnight"),
		event(next.Add(time.Second), next.Add(time.Second), "still after"),
	}
	into, err := s.AppendBatch(batch)
	if err != nil {
		t.Fatal(err)
	}
	segs := s.Segments()
	if len(segs) != 2 || segs[0].Events != 1 || segs[1].Events != 2 {
		t.Fatalf("a batch over midnight made %v", segs)
	}
	if into[0] != segs[0].Name || into[1] != segs[1].Name ||
		into[2] != segs[1].Name {
		t.Errorf("segments named %v for events landed in %v", into, segs)
	}
	if bad, err := s.Verify(); err != nil || len(bad) != 0 {
		t.Errorf("a spool a rolled batch filled does not verify: %v %v", bad, err)
	}
}

// TestAConcurrentMixOfBatchAndSingleWritesKeepsEveryEvent: a batching
// writer and a one-at-a-time writer at once, under the race detector. The
// batch holds the lock once for all of it, so the two interleave between
// operations and never inside one; what must survive is every event either
// wrote, in a store that still verifies.
func TestAConcurrentMixOfBatchAndSingleWritesKeepsEveryEvent(t *testing.T) {
	c := &clock{at: base}
	dir := t.TempDir()
	const batches, perBatch, alone = 20, 50, 300

	batcher := func() error {
		s, err := Open(dir, Options{Now: c.now})
		if err != nil {
			return err
		}
		for i := range batches {
			batch := make([]telemetry.Event, 0, perBatch)
			for j := range perBatch {
				batch = append(batch, event(base, base,
					fmt.Sprintf("batch %d %d", i, j)))
			}
			if _, err := s.AppendBatch(batch); err != nil {
				return err
			}
		}
		return s.Close()
	}
	oneAtATime := func() error {
		s, err := Open(dir, Options{Now: c.now})
		if err != nil {
			return err
		}
		for i := range alone {
			if _, err := s.Append(event(base, base,
				fmt.Sprintf("single %d", i))); err != nil {
				return err
			}
		}
		return s.Close()
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, f := range []func() error{batcher, oneAtATime} {
		wg.Add(1)
		go func(f func() error) {
			defer wg.Done()
			errs <- f()
		}(f)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	fresh, err := Open(dir, Options{Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	want := batches*perBatch + alone
	if got := fresh.Events(); got != want {
		t.Errorf("the index holds %d events after two writers wrote %d", got,
			want)
	}
	var onDisk int
	if err := fresh.Range(time.Time{}, time.Time{},
		func(telemetry.Event) error { onDisk++; return nil }); err != nil {
		t.Fatal(err)
	}
	if onDisk != want {
		t.Errorf("%d events on disk, want %d", onDisk, want)
	}
	if bad, err := fresh.Verify(); err != nil || len(bad) != 0 {
		t.Errorf("the store two kinds of writer filled does not verify: %v %v",
			bad, err)
	}
}

// TestTheFloorRefusesEvidenceYoungerThanIt: the byte cap is the one limit
// that deletes young evidence, so it is the one the floor has to bind. A
// spool over cap with everything inside the floor plans to drop nothing,
// says it is over cap, and names the segments the floor is holding.
func TestTheFloorRefusesEvidenceYoungerThanIt(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{
		SegmentBytes: 200, Keep: 365 * 24 * time.Hour, Cap: 1 << 30,
	})
	defer s.Close()
	for day := range 3 {
		c.at = base.Add(time.Duration(day) * 24 * time.Hour)
		if _, err := s.Append(event(c.at, c.at, "day")); err != nil {
			t.Fatal(err)
		}
	}
	c.at = base.Add(3 * 24 * time.Hour)
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}

	// Over cap, keep a year: without a floor the cap drops the oldest
	// sealed segment whatever its age. That is the behaviour the floor
	// exists to bound.
	s.opt.Cap = 1
	if p := s.Retain(); p.Empty() {
		t.Fatal("a spool one byte over cap with no floor planned to drop " +
			"nothing, so the test is not exercising the cap")
	}

	s.opt.Floor = 10 * 24 * time.Hour
	p := s.Retain()
	if !p.Empty() {
		t.Fatalf("the cap planned to drop %d segment(s) younger than the "+
			"floor", len(p.Drop))
	}
	if len(p.Pinned) != 3 {
		t.Errorf("the floor pinned %d segment(s), want all 3", len(p.Pinned))
	}
	if p.Over == 0 {
		t.Error("a spool held over cap by its own floor reported being " +
			"under cap, which is the quiet version of the same failure")
	}
	if !strings.Contains(p.Why(), "floor") {
		t.Errorf("the explanation does not name the floor: %q", p.Why())
	}
	// And nothing went anywhere.
	left, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(left) != 3 {
		t.Fatalf("%d segment file(s) left, want 3", len(left))
	}
}

// TestAFloorAboveTheAgeLimitRaisesIt: a keep shorter than the floor would
// delete evidence the organisation promised to keep, so the floor wins and
// the plan carries the raised limit rather than the configured one.
func TestAFloorAboveTheAgeLimitRaisesIt(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{
		SegmentBytes: 200, Keep: time.Hour, Floor: 2 * 24 * time.Hour,
		Cap: 1 << 30,
	})
	defer s.Close()
	for day := range 4 {
		c.at = base.Add(time.Duration(day) * 24 * time.Hour)
		if _, err := s.Append(event(c.at, c.at, "day")); err != nil {
			t.Fatal(err)
		}
	}
	c.at = base.Add(5 * 24 * time.Hour)
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}

	p := s.Retain()
	if p.Keep != 2*24*time.Hour {
		t.Errorf("the plan's age limit is %s, not the 2d floor it should "+
			"have been raised to", p.Keep)
	}
	for _, seg := range p.Drop {
		if c.at.Sub(seg.Last) <= p.Floor {
			t.Errorf("%s is %s old, inside the %s floor, and was planned",
				seg.Name, c.at.Sub(seg.Last), p.Floor)
		}
	}
	// Days 0, 1 and 2 are outside the floor; day 3 is exactly two days old
	// and must stay. One hour of keep without the floor would have taken it.
	if len(p.Drop) != 3 {
		t.Fatalf("the raised limit planned to drop %d segment(s), want the "+
			"3 older than the floor: %s", len(p.Drop), p.Why())
	}
}

// TestApplyRechecksTheFloorAtDeletionTime: a plan made before a floor was
// declared is not a licence to delete young evidence after it was. The same
// re-check the hold gets, for the same reason.
func TestApplyRechecksTheFloorAtDeletionTime(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{SegmentBytes: 200, Keep: time.Hour})
	for day := range 3 {
		c.at = base.Add(time.Duration(day) * 24 * time.Hour)
		if _, err := s.Append(event(c.at, c.at, "day")); err != nil {
			t.Fatal(err)
		}
	}
	c.at = base.Add(3 * 24 * time.Hour)
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	p := s.Retain()
	if p.Empty() {
		t.Fatal("nothing was planned, so the test is not exercising Apply")
	}

	// The floor is declared after the plan was made and approved.
	s.opt.Floor = 30 * 24 * time.Hour
	gone, err := s.Apply(p)
	if err != nil {
		t.Fatal(err)
	}
	if gone != 0 {
		t.Fatalf("%d segment(s) were deleted inside a floor declared after "+
			"the plan", gone)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(left) != 3 {
		t.Fatalf("%d segment file(s) left, want all 3", len(left))
	}
}

// TestRetentionAppliesUnderTheWritersLock: Apply changes the index like
// Append does, and was left outside the writer's lock when the lock landed.
// The failure is quiet and asymmetric: an Apply that acted on the index as
// its own handle last saw it saves that stale copy over the one another
// writer saved in between, and the other writer's events stay on disk while
// vanishing from the index — a store that answers with fewer events than it
// holds, which reads exactly like a quiet period.
func TestRetentionAppliesUnderTheWritersLock(t *testing.T) {
	c := &clock{at: base}
	dir := t.TempDir()
	// SegmentBytes big enough that the other writer's five events all land
	// in the open segment: the count of segments must not move, or the plan
	// is refused for staleness rather than applied against fresh counts.
	planner, err := Open(dir, Options{Now: c.now, SegmentBytes: 4096,
		Keep: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	// Two sealed days and one open segment: the shape a live store has while
	// serve is ingesting into today.
	for day := range 3 {
		c.at = base.Add(time.Duration(day) * 24 * time.Hour)
		if _, aerr := planner.Append(event(c.at, c.at, "day")); aerr != nil {
			t.Fatal(aerr)
		}
	}
	plan := planner.Retain()
	if plan.Empty() {
		t.Fatal("nothing was planned")
	}

	// Another writer stores into the open segment and saves — exactly what
	// ingestion does while a command plans retention. The segment count does
	// not move, so the plan is not stale; only the counts change.
	writer, err := Open(dir, Options{Now: c.now, SegmentBytes: 4096,
		Keep: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if _, aerr := writer.Append(event(c.at, c.at,
			fmt.Sprintf("late %d", i))); aerr != nil {
			t.Fatal(aerr)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := planner.Apply(plan); err != nil {
		t.Fatal(err)
	}
	fresh, err := Open(dir, Options{Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if got := fresh.Events(); got != 6 {
		t.Fatalf("the index holds %d events; one writer stored 1 and the "+
			"other 5, and Apply saved an index that lost the second "+
			"writer's", got)
	}
	var onDisk int
	if err := fresh.Range(time.Time{}, time.Time{},
		func(telemetry.Event) error { onDisk++; return nil }); err != nil {
		t.Fatal(err)
	}
	if onDisk != 6 {
		t.Errorf("%d events on disk, want the 6 the index must account for",
			onDisk)
	}
	if bad, verr := fresh.Verify(); verr != nil || len(bad) != 0 {
		t.Errorf("the spool retention ran beside does not verify: %v %v",
			bad, verr)
	}
}

// TestConcurrentRetentionAndAppendKeepTheIndexWhole: the three index writers
// the lock has to cover at once — ingestion appending, retention applying,
// and a hold going on and coming off — under the race detector. A plan that
// runs against a spool whose segment count moved is refused, which is the
// stale-plan rule doing its job, so the applier replans until the writers
// stop. What must survive is every event anybody wrote, in a store that
// still verifies.
func TestConcurrentRetentionAndAppendKeepTheIndexWhole(t *testing.T) {
	c := &clock{at: base}
	dir := t.TempDir()
	seed, err := Open(dir, Options{Now: c.now, SegmentBytes: 200,
		Keep: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for day := range 3 {
		c.at = base.Add(time.Duration(day) * 24 * time.Hour)
		if _, aerr := seed.Append(event(c.at, c.at, "old day")); aerr != nil {
			t.Fatal(aerr)
		}
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	c.at = base.Add(3 * 24 * time.Hour) // today, from here on

	const appended = 300
	var wg sync.WaitGroup
	errs := make(chan error, 3)

	appender := func() error {
		s, err := Open(dir, Options{Now: c.now, SegmentBytes: 200,
			Keep: time.Hour})
		if err != nil {
			return err
		}
		for i := range appended {
			if _, aerr := s.Append(event(c.at, c.at,
				fmt.Sprintf("today %d", i))); aerr != nil {
				return aerr
			}
		}
		return s.Close()
	}
	retainer := func() error {
		for range 30 {
			s, err := Open(dir, Options{Now: c.now, SegmentBytes: 200,
				Keep: time.Hour})
			if err != nil {
				return err
			}
			p := s.Retain()
			if !p.Empty() {
				// A refusal is the stale-plan rule doing its job — the
				// appender sealed another segment between the plan and the
				// apply — so the applier replans, which is the next turn of
				// this loop. What is under test is that the applies that do
				// run cannot lose the appender's index writes.
				_, _ = s.Apply(p)
			}
			if cerr := s.Close(); cerr != nil {
				return cerr
			}
		}
		return nil
	}
	holder := func() error {
		for i := range 30 {
			s, err := Open(dir, Options{Now: c.now})
			if err != nil {
				return err
			}
			name := fmt.Sprintf("hold-%d", i)
			if herr := s.Hold(Hold{Name: name, By: "rashik",
				Why: "the investigation is still open"}); herr != nil {
				s.Close()
				return herr
			}
			if lerr := s.Lift(name); lerr != nil {
				s.Close()
				return lerr
			}
			if cerr := s.Close(); cerr != nil {
				return cerr
			}
		}
		return nil
	}
	for _, f := range []func() error{appender, retainer, holder} {
		wg.Add(1)
		go func(f func() error) {
			defer wg.Done()
			errs <- f()
		}(f)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	fresh, err := Open(dir, Options{Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	// What must hold is not which segments retention reached — with the
	// appender rolling segments under it, most applies are refused by the
	// stale-plan rule and the old days may or may not have gone. It is that
	// every event anybody wrote is on disk, that the index accounts for
	// every one of them, and that the seals still hold.
	var today, onDisk int
	if err := fresh.Range(time.Time{}, time.Time{},
		func(e telemetry.Event) error {
			onDisk++
			if strings.HasPrefix(e.Message, "today ") {
				today++
			}
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if today != appended {
		t.Errorf("%d of today's %d events survived the run", today, appended)
	}
	if got := fresh.Events(); got != onDisk {
		t.Errorf("the index holds %d events and %d are on disk; an index "+
			"write was lost to a racing retention or hold", got, onDisk)
	}
	if bad, verr := fresh.Verify(); verr != nil || len(bad) != 0 {
		t.Errorf("the store three kinds of writer shared does not verify: "+
			"%v %v", bad, verr)
	}
}
