// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package spool

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/vaigil/vaigil/internal/telemetry"
)

// linearWhere is RangeWhere as it was before the fan-out: every segment the
// window and keep leave, opened and scanned one after another, eachFrom's
// seek included. The oracle the equivalence tests below prove the parallel
// reader against — the same shape as linearRange in index_test.go, kept for
// the reads that carry a keep.
func linearWhere(s *Spool, from, to time.Time, keep func(Segment) bool,
	fn func(telemetry.Event) error) error {

	for _, seg := range s.Segments() {
		if !to.IsZero() && !seg.First.Before(to) {
			continue
		}
		if !from.IsZero() && seg.Last.Before(from) {
			continue
		}
		if keep != nil && !keep(seg) {
			continue
		}
		if err := s.eachFrom(seg, from, func(e telemetry.Event) error {
			if !from.IsZero() && e.Received.Before(from) {
				return nil
			}
			if !to.IsZero() && !e.Received.Before(to) {
				return nil
			}
			return fn(e)
		}); err != nil {
			return err
		}
	}
	return nil
}

// linearDuring is During as it was before the fan-out, the same way.
func linearDuring(s *Spool, from, to time.Time,
	fn func(telemetry.Event) error) error {

	for _, seg := range s.Segments() {
		if !to.IsZero() && !seg.Earliest.IsZero() && !seg.Earliest.Before(to) {
			continue
		}
		if !from.IsZero() && !seg.Latest.IsZero() && seg.Latest.Before(from) {
			continue
		}
		if err := s.each(seg, func(e telemetry.Event) error {
			if !from.IsZero() && e.Time.Before(from) {
				return nil
			}
			if !to.IsZero() && !e.Time.Before(to) {
				return nil
			}
			return fn(e)
		}); err != nil {
			return err
		}
	}
	return nil
}

// syntheticReads is n segment reads that each emit per events naming their
// segment and line, the odd-numbered ones pausing halfway so finishing out
// of order is the common case and any order the gatherer produces is its
// own doing rather than the scheduler's luck. No files, no clock: what can
// be pinned with these is the fan-out's contract alone.
func syntheticReads(n, per int) []func(func(telemetry.Event) error) error {
	reads := make([]func(func(telemetry.Event) error) error, n)
	for i := range reads {
		reads[i] = func(emit func(telemetry.Event) error) error {
			for j := range per {
				if j == per/2 && i%2 == 1 {
					time.Sleep(time.Duration(i) * time.Millisecond)
				}
				e := telemetry.Event{
					Message: fmt.Sprintf("segment %d line %d", i, j)}
				if err := emit(e); err != nil {
					return err
				}
			}
			return nil
		}
	}
	return reads
}

// TestInOrderHandsOverExactlyTheSequenceTheSequentialLoopWould: the fan-out
// itself, pinned without a store in the way. Whatever order the workers
// finish in, the gatherer's handover is the segments in order, the lines in
// order within each, and the same twice.
func TestInOrderHandsOverExactlyTheSequenceTheSequentialLoopWould(t *testing.T) {
	reads := syntheticReads(8, 50)
	collect := func() []string {
		var got []string
		if err := inOrder(reads, func(e telemetry.Event) error {
			got = append(got, e.Message)
			return nil
		}); err != nil {
			t.Fatalf("inOrder: %v", err)
		}
		return got
	}
	var want []string
	for i := range 8 {
		for j := range 50 {
			want = append(want, fmt.Sprintf("segment %d line %d", i, j))
		}
	}
	if got := collect(); !reflect.DeepEqual(got, want) {
		t.Fatalf("the gatherer handed the segments over out of order; they "+
			"disagree first at %q", firstDiff(got, want))
	}
	if again := collect(); !reflect.DeepEqual(again, want) {
		t.Fatal("the same reads, gathered twice, produced two sequences")
	}
}

// TestInOrderReturnsTheFirstErrorInSegmentOrderNotTheFirstToHappen: two
// segments fail, the later one first. A sequential loop would have returned
// the earlier segment's error having never opened the later one, and so
// must the gatherer — the error a parallel read returns may not depend on
// which worker was fastest.
func TestInOrderReturnsTheFirstErrorInSegmentOrderNotTheFirstToHappen(t *testing.T) {
	reads := syntheticReads(8, 50)
	errTwo := errors.New("segment two gave up")
	errFive := errors.New("segment five gave up")
	reads[2] = func(emit func(telemetry.Event) error) error {
		time.Sleep(25 * time.Millisecond)
		return errTwo
	}
	reads[5] = func(emit func(telemetry.Event) error) error {
		return errFive
	}
	var seen []string
	err := inOrder(reads, func(e telemetry.Event) error {
		seen = append(seen, e.Message)
		return nil
	})
	if err != errTwo {
		t.Fatalf("the gatherer returned %v; segment two's error comes first "+
			"in segment order however early segment five fails", err)
	}
	// Segments zero and one whole, and nothing of three onwards — segment
	// three's worker will have finished long before segment two's error
	// lands, and not one of its events may show for it.
	if len(seen) != 100 || seen[0] != "segment 0 line 0" ||
		seen[99] != "segment 1 line 49" {
		t.Fatalf("the caller saw %d events, last %q; a sequential loop "+
			"would have handed over exactly the first two segments",
			len(seen), seen[len(seen)-1])
	}
}

// TestTheCallersStopEndsTheWalkWhereTheSequentialLoopEndedIt: a caller
// erroring from fn is how every reader bounds a walk. The gatherer returns
// that error, calls fn no further, and the stopped workers are gone by the
// time it returns — inOrder never leaks a reader past its caller.
func TestTheCallersStopEndsTheWalkWhereTheSequentialLoopEndedIt(t *testing.T) {
	reads := syntheticReads(8, 50)
	stop := errors.New("enough")
	var seen int
	err := inOrder(reads, func(telemetry.Event) error {
		seen++
		if seen == 60 {
			return stop
		}
		return nil
	})
	if err != stop {
		t.Fatalf("the gatherer returned %v, not the caller's own stop", err)
	}
	if seen != 60 {
		t.Fatalf("fn was called %d times; a sequential loop would have "+
			"stopped at sixty — fifty of segment zero, ten of segment one",
			seen)
	}
}

// randomStore is days of varied events with the counts, sources, actors and
// arrival delays all drawn from one seeded generator, so a failure
// reproduces. The last day's arrivals run backwards a third of the time —
// its sidecar is honestly marked unsorted and its reads take the linear
// path inside eachFrom — and an unsealed tail is left behind, so a fan-out
// over this store mixes sealed seeks, unsorted scans and an active segment.
func randomStore(t *testing.T, rng *rand.Rand, days int) (*Spool, string) {
	t.Helper()
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{})
	srcs := []string{"okta/system", "github/audit", "proxy/egress"}
	n := 0
	for d := range days {
		day := base.Add(time.Duration(d) * 24 * time.Hour)
		c.at = day.Add(time.Hour)
		per := 40 + rng.Intn(200)
		batch := make([]telemetry.Event, 0, per)
		for i := range per {
			at := day.Add(time.Duration(i) * 17 * time.Second)
			delay := time.Duration(rng.Intn(13)) * time.Second
			if d == days-1 && rng.Intn(3) == 0 {
				delay = -time.Duration(rng.Intn(97)) * time.Second
			}
			e := varied(at, at.Add(delay), n)
			e.Source = srcs[rng.Intn(len(srcs))]
			if rng.Intn(5) == 0 {
				e.Actor = telemetry.ID{}
			}
			batch = append(batch, e)
			n++
		}
		if _, err := s.AppendBatch(batch); err != nil {
			t.Fatalf("append: %v", err)
		}
		if err := s.Seal(); err != nil {
			t.Fatalf("seal: %v", err)
		}
	}
	tail := base.Add(time.Duration(days) * 24 * time.Hour)
	c.at = tail
	batch := make([]telemetry.Event, 0, 16)
	for i := range 16 {
		at := tail.Add(time.Duration(i) * time.Second)
		e := varied(at, at, n+i)
		e.Source = srcs[rng.Intn(len(srcs))]
		batch = append(batch, e)
	}
	if _, err := s.AppendBatch(batch); err != nil {
		t.Fatalf("tail: %v", err)
	}
	if err := s.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	return s, dir
}

// TestAParallelReadAnswersExactlyWhatASequentialOneDoes: the guard the
// fan-out stands on. Over a randomized multi-segment store — sealed days, an
// unsorted day, an active tail — every window shape a caller can ask for is
// read three ways: by the parallel reader, by the parallel reader again, and
// by the sequential loop it replaced. All three must agree exactly, and so
// must the keeps — a keep is asked once per candidate segment, in order,
// whichever reader is asking.
func TestAParallelReadAnswersExactlyWhatASequentialOneDoes(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	s, _ := randomStore(t, rng, 5)
	defer func() { _ = s.Close() }()

	// The corpus must exercise every path the fan-out can route around:
	// sealed segments with sorted columns to seek with, at least one
	// honestly unsorted, and an unsealed tail.
	var sealed, sorted, unsorted, open int
	for _, seg := range s.Segments() {
		if !seg.Sealed() {
			open++
			continue
		}
		sealed++
		if sc := s.sidecarOf(seg); sc != nil {
			if sc.sorted {
				sorted++
			} else {
				unsorted++
			}
			sc.close()
		}
	}
	if sealed < 3 || sorted == 0 || unsorted == 0 || open != 1 {
		t.Fatalf("the corpus must exercise every path: %d sealed (%d sorted, "+
			"%d unsorted), %d open", sealed, sorted, unsorted, open)
	}

	key := func(e telemetry.Event) string {
		return fmt.Sprintf("%s|%d", e.Message, e.Received.UnixNano())
	}
	day := 24 * time.Hour
	windows := [][2]time.Time{
		{time.Time{}, time.Time{}},
		{base.Add(2 * day), time.Time{}},
		{base.Add(day + 3*time.Hour), base.Add(3 * day)},
	}
	for range 6 {
		from := base.Add(time.Duration(rng.Intn(5)) * day)
		var to time.Time
		if rng.Intn(2) == 1 {
			to = base.Add(time.Duration(2+rng.Intn(4)) * day)
		}
		windows = append(windows, [2]time.Time{from, to})
	}

	var compared int
	for _, w := range windows {
		parallel := func() []string {
			var out []string
			if err := s.Range(w[0], w[1], func(e telemetry.Event) error {
				out = append(out, key(e))
				return nil
			}); err != nil {
				t.Fatalf("parallel [%s,%s): %v", w[0], w[1], err)
			}
			return out
		}
		got, again := parallel(), parallel()
		var plain, kept []string
		if err := linearRange(s, w[0], w[1], func(e telemetry.Event) error {
			plain = append(plain, key(e))
			return nil
		}); err != nil {
			t.Fatalf("linear [%s,%s): %v", w[0], w[1], err)
		}
		if err := linearWhere(s, w[0], w[1], nil, func(e telemetry.Event) error {
			kept = append(kept, key(e))
			return nil
		}); err != nil {
			t.Fatalf("linearWhere [%s,%s): %v", w[0], w[1], err)
		}
		if !reflect.DeepEqual(got, again) {
			t.Fatalf("window [%s,%s): the same parallel read twice produced "+
				"two sequences, disagreeing first at %s", w[0], w[1],
				firstDiff(got, again))
		}
		if !reflect.DeepEqual(got, plain) || !reflect.DeepEqual(got, kept) {
			t.Fatalf("window [%s,%s): the parallel read returned %d events "+
				"and the sequential one %d; they disagree first at %s",
				w[0], w[1], len(got), len(plain), firstDiff(got, plain))
		}
		compared += len(got)
	}
	if compared == 0 {
		t.Fatal("every window read nothing; the corpus is too thin to prove " +
			"equivalence with")
	}

	// The pruned hunt: a keep the blooms can answer, asked by both readers.
	// The order keep was asked in is part of the answer — a keep that counts
	// pruned events, as the hunt's does, must see the same segments in the
	// same order whichever reader is asking.
	for _, w := range windows[:4] {
		var askedParallel, askedLinear []string
		keepParallel := func(seg Segment) bool {
			askedParallel = append(askedParallel, seg.Name)
			return s.CouldHold(seg, "source", "okta/system")
		}
		keepLinear := func(seg Segment) bool {
			askedLinear = append(askedLinear, seg.Name)
			return s.CouldHold(seg, "source", "okta/system")
		}
		var got, want []string
		if err := s.RangeWhere(w[0], w[1], keepParallel,
			func(e telemetry.Event) error {
				got = append(got, key(e))
				return nil
			}); err != nil {
			t.Fatalf("pruned parallel [%s,%s): %v", w[0], w[1], err)
		}
		if err := linearWhere(s, w[0], w[1], keepLinear,
			func(e telemetry.Event) error {
				want = append(want, key(e))
				return nil
			}); err != nil {
			t.Fatalf("pruned linear [%s,%s): %v", w[0], w[1], err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("pruned window [%s,%s): the reads disagree first at %s",
				w[0], w[1], firstDiff(got, want))
		}
		if !reflect.DeepEqual(askedParallel, askedLinear) {
			t.Fatalf("pruned window [%s,%s): keep was asked about %v by the "+
				"parallel reader and %v by the sequential one", w[0], w[1],
				askedParallel, askedLinear)
		}
	}

	// During, over windows on the event clock rather than the arrival one.
	duringWindows := [][2]time.Time{
		{time.Time{}, time.Time{}},
		{base.Add(36 * time.Hour), base.Add(3 * day)},
		{base.Add(2 * day), time.Time{}},
	}
	for _, w := range duringWindows {
		var got, want []string
		if err := s.During(w[0], w[1], func(e telemetry.Event) error {
			got = append(got, key(e))
			return nil
		}); err != nil {
			t.Fatalf("During [%s,%s): %v", w[0], w[1], err)
		}
		if err := linearDuring(s, w[0], w[1], func(e telemetry.Event) error {
			want = append(want, key(e))
			return nil
		}); err != nil {
			t.Fatalf("linear During [%s,%s): %v", w[0], w[1], err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("During [%s,%s): the reads disagree first at %s", w[0],
				w[1], firstDiff(got, want))
		}
	}
}

// TestAMissingSegmentStopsTheParallelReadWhereItStoppedTheSequentialOne: a
// missing file is the one error a reader must never soften. The parallel
// reader returns the same error, in the same words, having handed over
// exactly the events the sequential reader handed over before it stopped —
// and nothing from any segment after the missing one.
func TestAMissingSegmentStopsTheParallelReadWhereItStoppedTheSequentialOne(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	s, dir := randomStore(t, rng, 4)
	defer func() { _ = s.Close() }()
	segs := s.Segments()
	victim := segs[len(segs)/2]
	if !victim.Sealed() {
		t.Fatal("the corpus left no sealed middle segment to delete")
	}
	if err := os.Remove(filepath.Join(dir, victim.Name)); err != nil {
		t.Fatal(err)
	}

	var gotPrefix, wantPrefix []string
	gotErr := s.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		gotPrefix = append(gotPrefix, e.Message)
		return nil
	})
	wantErr := linearRange(s, time.Time{}, time.Time{},
		func(e telemetry.Event) error {
			wantPrefix = append(wantPrefix, e.Message)
			return nil
		})
	if gotErr == nil || wantErr == nil {
		t.Fatalf("a store missing a segment read cleanly: %v %v", gotErr,
			wantErr)
	}
	if gotErr.Error() != wantErr.Error() {
		t.Fatalf("the parallel reader said %q and the sequential one %q; the "+
			"error may not depend on which worker hit it", gotErr, wantErr)
	}
	if !reflect.DeepEqual(gotPrefix, wantPrefix) {
		t.Fatalf("the readers stopped on different prefixes, disagreeing "+
			"first at %s", firstDiff(gotPrefix, wantPrefix))
	}
	if len(gotPrefix) == 0 {
		t.Fatal("both readers stopped before the first event; the corpus is " +
			"too thin to prove the prefix with")
	}
}

// TestReadsWalkBesideAWriterWithoutWaitingOnIt: the race-detector guard.
// A writer appends batch after batch — through the writer's lock, which a
// reader never takes — while four readers walk the store through the
// fan-out. Nothing may race; every read must still answer; what the sealed
// segments produced never varies between reads; and each reader's own
// successive answers grow only by appension, because the only thing that
// changed between them is events arriving.
func TestReadsWalkBesideAWriterWithoutWaitingOnIt(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{})
	srcs := []string{"okta/system", "github/audit", "proxy/egress"}
	n := 0
	for d := range 3 {
		day := base.Add(time.Duration(d) * 24 * time.Hour)
		c.at = day.Add(time.Hour)
		batch := make([]telemetry.Event, 0, 60)
		for i := range 60 {
			at := day.Add(time.Duration(i) * 17 * time.Second)
			e := varied(at, at, n)
			e.Source = srcs[n%3]
			batch = append(batch, e)
			n++
		}
		if _, err := s.AppendBatch(batch); err != nil {
			t.Fatalf("append: %v", err)
		}
		if err := s.Seal(); err != nil {
			t.Fatalf("seal: %v", err)
		}
	}
	// An active tail, released rather than sealed: the writer below resumes
	// it, so its bytes move while the readers are inside it.
	tail := base.Add(3 * 24 * time.Hour)
	c.at = tail
	tailBatch := make([]telemetry.Event, 0, 20)
	for i := range 20 {
		at := tail.Add(time.Duration(i) * time.Second)
		e := varied(at, at, n+i)
		e.Source = srcs[n%3]
		tailBatch = append(tailBatch, e)
	}
	if _, err := s.AppendBatch(tailBatch); err != nil {
		t.Fatalf("tail: %v", err)
	}
	if err := s.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}

	// What the immutable half of the store answers, pinned before the writer
	// starts: no later read may vary on it.
	var sealedPrefix []string
	if err := s.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		sealedPrefix = append(sealedPrefix, e.Message)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// The writer is its own handle on the same directory, as serve ingesting
	// while a command reads, and its clock stays inside the tail's day so
	// its batches join the segment the readers are walking through.
	start := time.Now()
	writer, err := Open(dir, Options{Now: func() time.Time {
		return tail.Add(time.Since(start))
	}})
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				_ = writer.Close()
				return
			default:
			}
			batch := make([]telemetry.Event, 0, 20)
			for j := range 20 {
				at := tail.Add(time.Since(start))
				e := varied(at, time.Time{}, 10_000+i*20+j)
				e.Source = srcs[(n+i*20+j)%3]
				batch = append(batch, e)
			}
			if _, err := writer.AppendBatch(batch); err != nil {
				t.Errorf("the writer stopped writing: %v", err)
				return
			}
		}
	}()

	var readers sync.WaitGroup
	for r := range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			var last []string
			for range 6 {
				var got []string
				read := func(fn func(telemetry.Event) error) error {
					return s.RangeWhere(time.Time{}, time.Time{},
						func(seg Segment) bool {
							// Some passes with a bloom consulted, as the
							// hunt consults one, beside the appends.
							return s.CouldHold(seg, "source", "okta/system")
						}, fn)
				}
				if r%2 == 0 {
					read = func(fn func(telemetry.Event) error) error {
						return s.Range(time.Time{}, time.Time{}, fn)
					}
				}
				if err := read(func(e telemetry.Event) error {
					got = append(got, e.Message)
					return nil
				}); err != nil {
					t.Errorf("a read beside a writer failed: %v", err)
					return
				}
				if len(got) < len(sealedPrefix) ||
					!reflect.DeepEqual(got[:len(sealedPrefix)], sealedPrefix) {
					t.Errorf("a read changed its mind about the sealed half " +
						"of the store")
					return
				}
				if last != nil && (len(got) < len(last) ||
					!reflect.DeepEqual(got[:len(last)], last)) {
					t.Errorf("a later answer is not the earlier one with " +
						"arrivals added; the read reordered the store")
					return
				}
				last = got
			}
		}()
	}
	readers.Wait()
	close(stop)
	writers.Wait()

	// The readers walked beside a live writer: the final answer must hold
	// more than the store did before one of them started.
	var final []string
	if err := s.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		final = append(final, e.Message)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(final) <= len(sealedPrefix) {
		t.Fatalf("the writer's events never became readable: %d then %d",
			len(sealedPrefix), len(final))
	}
}

// benchFanStore is eight sealed segments of a hundred thousand events each —
// a week and a bit of a busy estate — with a window starting two days in, so
// the read is six segments of work and two that pruning skips: the shape an
// eight-day store gives a hunt over "the last six days", where segment-level
// pruning cannot help because every remaining segment straddles the window.
func benchFanStore(b *testing.B) (*Spool, time.Time) {
	b.Helper()
	c := &clock{at: base}
	s, _ := openAt(b, c, Options{})
	n := 0
	for d := range 8 {
		day := base.Add(time.Duration(d) * 24 * time.Hour)
		c.at = day.Add(time.Hour)
		batch := make([]telemetry.Event, 0, 100_000)
		for i := range 100_000 {
			at := day.Add(time.Hour + time.Duration(i)*400*time.Millisecond)
			batch = append(batch, varied(at,
				at.Add(time.Duration(i%13)*time.Millisecond), n))
			n++
		}
		if _, err := s.AppendBatch(batch); err != nil {
			b.Fatal(err)
		}
		if err := s.Seal(); err != nil {
			b.Fatal(err)
		}
	}
	return s, base.Add(2 * 24 * time.Hour)
}

// BenchmarkFanoutRangeLinear is the multi-segment window as the sequential
// loop read it: one segment after another, each seeked where its sidecar has
// earned it. linearWhere is that reader, kept as the oracle above.
func BenchmarkFanoutRangeLinear(b *testing.B) {
	s, from := benchFanStore(b)
	defer func() { _ = s.Close() }()
	var n int
	for b.Loop() {
		n = 0
		if err := linearWhere(s, from, time.Time{}, nil,
			func(telemetry.Event) error { n++; return nil }); err != nil {
			b.Fatal(err)
		}
	}
	// Six whole segments survive the window; the equivalence tests in this
	// file are what say this is the same answer the parallel reader gives.
	if n != 600_000 {
		b.Fatalf("read %d events", n)
	}
}

// BenchmarkFanoutRangeParallel is the same window through the fan-out: the
// six segments read beside each other on the pool, gathered in order.
func BenchmarkFanoutRangeParallel(b *testing.B) {
	s, from := benchFanStore(b)
	defer func() { _ = s.Close() }()
	var n int
	for b.Loop() {
		n = 0
		if err := s.Range(from, time.Time{},
			func(telemetry.Event) error { n++; return nil }); err != nil {
			b.Fatal(err)
		}
	}
	if n != 600_000 {
		b.Fatalf("read %d events", n)
	}
}

// BenchmarkFanoutHuntUnfilteredLinear is the expensive hunt: a condition the
// blooms cannot answer — a contains, a prefix, any field but the three — so
// every segment is opened and every line parsed, one segment at a time.
func BenchmarkFanoutHuntUnfilteredLinear(b *testing.B) {
	s, _ := benchHuntStore(b)
	defer func() { _ = s.Close() }()
	var n int
	for b.Loop() {
		n = 0
		if err := linearWhere(s, time.Time{}, time.Time{},
			func(Segment) bool { return true },
			func(e telemetry.Event) error {
				if e.Source == "okta/system" {
					n++
				}
				return nil
			}); err != nil {
			b.Fatal(err)
		}
	}
	if n != 50_000 {
		b.Fatalf("found %d events", n)
	}
}

// BenchmarkFanoutHuntUnfilteredParallel is the same hunt through the fan-out
// — the case it exists for, where nothing can be pruned and the only speed
// left is reading the segments beside each other.
func BenchmarkFanoutHuntUnfilteredParallel(b *testing.B) {
	s, _ := benchHuntStore(b)
	defer func() { _ = s.Close() }()
	var n int
	for b.Loop() {
		n = 0
		if err := s.RangeWhere(time.Time{}, time.Time{},
			func(Segment) bool { return true },
			func(e telemetry.Event) error {
				if e.Source == "okta/system" {
					n++
				}
				return nil
			}); err != nil {
			b.Fatal(err)
		}
	}
	if n != 50_000 {
		b.Fatalf("found %d events", n)
	}
}

// BenchmarkFanoutHuntPrunedLinear is the hunt the blooms already answer:
// seven of eight segments refused unopened, one read, sequentially.
func BenchmarkFanoutHuntPrunedLinear(b *testing.B) {
	s, want := benchHuntStore(b)
	defer func() { _ = s.Close() }()
	var n int
	for b.Loop() {
		n = 0
		if err := linearWhere(s, time.Time{}, time.Time{},
			func(seg Segment) bool { return s.CouldHold(seg, "source", want) },
			func(e telemetry.Event) error {
				if e.Source == want {
					n++
				}
				return nil
			}); err != nil {
			b.Fatal(err)
		}
	}
	if n != 50_000 {
		b.Fatalf("found %d events", n)
	}
}

// BenchmarkFanoutHuntPrunedParallel is that same pruned hunt through the
// fan-out. One segment survives the blooms, so there is nothing to overlap
// and nothing the pool may add: the pair exists to show the fan-out costs
// the pruned hunt nothing, not to show it speed.
func BenchmarkFanoutHuntPrunedParallel(b *testing.B) {
	s, want := benchHuntStore(b)
	defer func() { _ = s.Close() }()
	var n int
	for b.Loop() {
		n = 0
		if err := s.RangeWhere(time.Time{}, time.Time{},
			func(seg Segment) bool { return s.CouldHold(seg, "source", want) },
			func(e telemetry.Event) error {
				if e.Source == want {
					n++
				}
				return nil
			}); err != nil {
			b.Fatal(err)
		}
	}
	if n != 50_000 {
		b.Fatalf("found %d events", n)
	}
}
