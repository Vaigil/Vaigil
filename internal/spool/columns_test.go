// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package spool

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aeroprove/aeroprove/internal/telemetry"
)

// columnEvent is one event of a corpus drawn for the dictionary columns'
// hard cases: fold twins in source, message and actor — values one equality
// calls equal but a row must still tell apart — an empty message, values
// that appear exactly once in a segment, values repeated across every
// segment, actor-less events, and two classes. i is the event's place in
// its own day, so the once-per-segment cases fire once per segment.
func columnEvent(at, received time.Time, day, i int,
	rng *rand.Rand) telemetry.Event {

	e := event(at, received, "")
	e.Source = []string{"okta/system", "github/audit", "proxy/egress"}[i%3]
	if i%7 == 0 {
		// The fold twin of okta/system, in the same segment as it.
		e.Source = "OKTA/SYSTEM"
	}
	if i%11 == 0 {
		// At most a handful of times per segment and nowhere else.
		e.Source = fmt.Sprintf("one-off/day-%d", day)
	}
	if i == 3 {
		// Exactly once in every segment, spelled identically.
		e.Source = "shared/everywhere"
	}
	if i%2 == 0 {
		e.Class = telemetry.ClassAPIActivity
	}
	if i%5 != 0 {
		e.Actor = telemetry.ID{Issuer: "okta",
			Value: fmt.Sprintf("user-%d", i%23)}
		if i%9 == 0 {
			e.Actor.Value = fmt.Sprintf("USER-%d", i%23)
		}
	}
	e.Message = []string{"sign-in", "PutBucketPolicy", "GetBucketPolicy",
		"list-buckets"}[rng.Intn(4)]
	if i%13 == 0 {
		// The empty string is a value Fields holds; the dictionary must
		// carry it rather than leave a hole.
		e.Message = ""
	}
	if i%17 == 0 {
		// The fold twin of sign-in over a rune whose orbit leaves ASCII.
		e.Message = "ſign-in"
	}
	if i%19 == 0 {
		e.Message = "once-day-" + fmt.Sprint(day)
	}
	if i == 5 {
		// Exactly once in every segment, message edition.
		e.Message = "cross-segment-repeat"
	}
	return e
}

// columnStore is days of sealed segments of that corpus plus an active
// tail, with the last day's arrivals partly running backwards so its
// sidecar is honestly unsorted and its scan cannot seek.
func columnStore(t *testing.T, rng *rand.Rand, days int) (*Spool, string) {
	t.Helper()
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{})
	for d := range days {
		day := base.Add(time.Duration(d) * 24 * time.Hour)
		c.at = day.Add(time.Hour)
		per := 150 + rng.Intn(60)
		batch := make([]telemetry.Event, 0, per)
		for i := range per {
			at := day.Add(time.Duration(i) * 17 * time.Second)
			delay := time.Duration(rng.Intn(13)) * time.Second
			if d == days-1 && rng.Intn(3) == 0 {
				delay = -time.Duration(rng.Intn(97)) * time.Second
			}
			batch = append(batch,
				columnEvent(at, at.Add(delay), d, i, rng))
		}
		if _, err := s.AppendBatch(batch); err != nil {
			t.Fatalf("append: %v", err)
		}
		if err := s.Seal(); err != nil {
			t.Fatalf("seal: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	again, err := Open(dir, Options{Now: c.now})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	tail := base.Add(time.Duration(days) * 24 * time.Hour)
	c.at = tail
	batch := make([]telemetry.Event, 0, 10)
	for i := range 10 {
		at := tail.Add(time.Duration(i) * time.Second)
		batch = append(batch, columnEvent(at, at, days, i, rng))
	}
	if _, err := again.AppendBatch(batch); err != nil {
		t.Fatalf("tail: %v", err)
	}
	if err := again.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	return again, dir
}

// decodedRows is the scan as decoding the line answers it: every segment
// the window keeps, opened and parsed, the same four values taken off each
// event. The oracle the column path is proved against, in the same shape as
// linearRange and linearEqual.
func decodedRows(s *Spool, from, to time.Time) ([]string,
	[]telemetry.Event, error) {

	var keys []string
	var whole []telemetry.Event
	for _, seg := range s.Segments() {
		if !to.IsZero() && !seg.First.Before(to) {
			continue
		}
		if !from.IsZero() && seg.Last.Before(from) {
			continue
		}
		n := 0
		err := s.each(seg, func(e telemetry.Event) error {
			i := n
			n++
			if !withinArrival(e, from, to) {
				return nil
			}
			actor := ""
			if !e.Actor.Zero() {
				actor = e.Actor.Value
			}
			keys = append(keys, fmt.Sprintf("%s|%s|%s|%s|%d|%d", e.Source,
				fmt.Sprint(uint32(e.Class)), actor, e.Message,
				e.Received.UnixNano(), i))
			whole = append(whole, e)
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	return keys, whole, nil
}

// TestAColumnScanAnswersExactlyWhatDecodingDoes: the guard the columns stand
// on. Over a randomized store with sealed days, an unsorted day, fold twins
// in three fields, empty messages, once-per-segment values, cross-segment
// repeats and an unsealed tail, every window shape a caller can ask for is
// scanned twice through the columns and once through the decode of every
// line — and the three must agree exactly, in order, row for row. The rows
// sampled for Event must decode to the very event the oracle decoded, and
// the second Event call must return the first one's answer.
func TestAColumnScanAnswersExactlyWhatDecodingDoes(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	s, _ := columnStore(t, rng, 5)
	defer func() { _ = s.Close() }()

	var sealed, unsorted int
	for _, seg := range s.Segments() {
		if !seg.Sealed() {
			continue
		}
		sealed++
		if sc := s.sidecarOf(seg); sc != nil {
			if !sc.sorted {
				unsorted++
			}
			sc.close()
		}
	}
	if sealed < 4 || unsorted == 0 {
		t.Fatalf("the corpus must exercise every path: %d sealed, %d with "+
			"backwards arrivals", sealed, unsorted)
	}

	day := 24 * time.Hour
	windows := [][2]time.Time{
		{time.Time{}, time.Time{}},
		{base.Add(2 * day), time.Time{}},
		{base.Add(day + 3*time.Hour), base.Add(3 * day)},
		{base.Add(4*day + 20*time.Hour), time.Time{}},
	}
	for range 4 {
		// Only windows that can hold events are drawn: from inside the
		// store's six days, to some days after it, so no degenerate
		// from-past-to window thins the comparison for a reason that has
		// nothing to do with the columns.
		from := base.Add(time.Duration(rng.Intn(5)) * day)
		var to time.Time
		if rng.Intn(2) == 1 {
			to = from.Add(time.Duration(1+rng.Intn(3)) * day)
		}
		windows = append(windows, [2]time.Time{from, to})
	}

	scan := func(w [2]time.Time, sample func(*Row) error) ([]string, error) {
		var out []string
		err := s.Scan(w[0], w[1], func(r *Row) error {
			out = append(out, fmt.Sprintf("%s|%s|%s|%s|%d|%d", r.Source(),
				r.Class(), r.ActorValue(), r.Message(),
				r.Received().UnixNano(), r.Ordinal()))
			if sample != nil {
				if serr := sample(r); serr != nil {
					return serr
				}
			}
			return nil
		})
		return out, err
	}

	someNonEmpty := false
	for _, w := range windows {
		want, whole, err := decodedRows(s, w[0], w[1])
		if err != nil {
			t.Fatalf("decode [%s,%s): %v", w[0], w[1], err)
		}
		if len(want) == 0 {
			t.Fatalf("window [%s,%s) read nothing; the corpus is too thin "+
				"to prove equivalence with", w[0], w[1])
		}
		// The sampled rows' Events are checked against the oracle's decoded
		// events by position, so the row counter has to run outside sample.
		row := 0
		sample := func(r *Row) error {
			i := row
			row++
			if i%7 != 0 && r.Message() != "" && r.HasActor() {
				return nil
			}
			got, gerr := r.Event()
			if gerr != nil {
				return gerr
			}
			again, aerr := r.Event()
			if aerr != nil {
				return aerr
			}
			if !reflect.DeepEqual(got, again) {
				return fmt.Errorf("row %d: Event answered twice differently",
					i)
			}
			if !reflect.DeepEqual(got, whole[i]) {
				return fmt.Errorf("row %d: Event decoded a different event "+
					"than the oracle read from the same line", i)
			}
			return nil
		}
		got, err := scan(w, sample)
		if err != nil {
			t.Fatalf("scan [%s,%s): %v", w[0], w[1], err)
		}
		again, _ := scan(w, nil)
		if !reflect.DeepEqual(got, again) {
			t.Fatalf("window [%s,%s): the same scan twice produced two "+
				"sequences, disagreeing first at %s", w[0], w[1],
				firstDiff(got, again))
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("window [%s,%s): the column scan returned %d rows and "+
				"the decoded one %d; they disagree first at %s", w[0], w[1],
				len(got), len(want), firstDiff(got, want))
		}
		someNonEmpty = true
	}
	if !someNonEmpty {
		t.Fatal("every window read nothing")
	}

	// The fold twins, said outright rather than left to the oracle: the
	// column carries the original spellings, both of them, and an equality
	// over either finds both while the rows still tell them apart.
	twins := 0
	if err := s.Scan(time.Time{}, time.Time{}, func(r *Row) error {
		if strings.EqualFold(r.Source(), "okta/system") &&
			r.Source() != "okta/system" {
			twins++
		}
		if strings.EqualFold(r.Message(), "sign-in") &&
			r.Message() != "sign-in" {
			twins++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if twins == 0 {
		t.Fatal("the corpus held no fold twin; the test proves nothing " +
			"about telling originals apart")
	}
}

// TestTheWideOrdinalColumnAnswersToo: past sixty-five thousand five hundred
// and thirty-five distinct values a dictionary no longer fits its ordinals
// in two bytes, and the section switches to four. A segment over the
// boundary is scanned and checked against the decode, so the wide layout is
// exercised by equivalence and not by inspection.
func TestTheWideOrdinalColumnAnswersToo(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{SegmentBytes: 1 << 30})
	const n = 66_000
	batch := make([]telemetry.Event, 0, n)
	for i := range n {
		at := base.Add(time.Duration(i) * 10 * time.Millisecond)
		e := event(at, at, "")
		e.Message = fmt.Sprintf("message only event %d ever carried", i)
		batch = append(batch, e)
	}
	if _, err := s.AppendBatch(batch); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	seg := s.Segments()[0]
	b, err := os.ReadFile(filepath.Join(s.dir, seg.Name+SidecarExt))
	if err != nil {
		t.Fatal(err)
	}
	sc := parseSidecarHeader(b)
	if sc == nil {
		t.Fatal("the sidecar will not parse")
	}
	if sc.dn[3] <= 1<<16-1 {
		t.Fatalf("the corpus built %d distinct messages, under the width "+
			"boundary; the wide layout was never reached", sc.dn[3])
	}
	if dictWidth(int(sc.dn[3]), dictAbsent(3)) != 4 {
		t.Fatal("the message column did not take the wide layout")
	}

	want, _, derr := decodedRows(s, time.Time{}, time.Time{})
	if derr != nil {
		t.Fatal(derr)
	}
	var got []string
	if serr := s.Scan(time.Time{}, time.Time{}, func(r *Row) error {
		got = append(got, fmt.Sprintf("%s|%s|%s|%s|%d|%d", r.Source(),
			r.Class(), r.ActorValue(), r.Message(), r.Received().UnixNano(),
			r.Ordinal()))
		return nil
	}); serr != nil {
		t.Fatal(serr)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the wide column returned %d rows and the decode %d; they "+
			"disagree first at %s", len(got), len(want), firstDiff(got, want))
	}
}

// TestVspool2SidecarsAreRebuiltAsVspool3: the version bump's whole promise.
// A sidecar this build does not understand — an older magic and the older,
// shorter header it carried — is not an error and not an answer from stale
// bytes; it is a rebuild from the segment on disk, persisted, and every
// reader after it reads the new format.
func TestVspool2SidecarsAreRebuiltAsVspool3(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	s, dir := columnStore(t, rng, 2)
	defer func() { _ = s.Close() }()
	want, _, err := decodedRows(s, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}

	var sidecars []string
	for _, seg := range s.Segments() {
		if seg.Sealed() {
			sidecars = append(sidecars, filepath.Join(dir, seg.Name+SidecarExt))
		}
	}
	if len(sidecars) == 0 {
		t.Fatal("the corpus sealed nothing")
	}
	const vspool2HeaderLen = len("vspool2\n") + 64 + 8 + 8 + 1 + 24 +
		3*8*postFields
	for _, p := range sidecars {
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if string(b[:len(sidecarMagic)]) != sidecarMagic {
			t.Fatalf("%s was not written as %q", p, sidecarMagic)
		}
		// An honest vspool2-shaped file: the old magic, the old header's
		// length, and nothing this build would mistake for its own.
		old := append([]byte("vspool2\n"), make([]byte, vspool2HeaderLen-8)...)
		if werr := os.WriteFile(p, old, 0o600); werr != nil {
			t.Fatal(werr)
		}
	}

	var got []string
	if serr := s.Scan(time.Time{}, time.Time{}, func(r *Row) error {
		got = append(got, fmt.Sprintf("%s|%s|%s|%s|%d|%d", r.Source(),
			r.Class(), r.ActorValue(), r.Message(), r.Received().UnixNano(),
			r.Ordinal()))
		return nil
	}); serr != nil {
		t.Fatal(serr)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the scan over rebuilt sidecars disagreed with the decode "+
			"first at %s", firstDiff(got, want))
	}
	for _, p := range sidecars {
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if string(b[:len(sidecarMagic)]) != sidecarMagic {
			t.Fatalf("%s was not rebuilt as %q", p, sidecarMagic)
		}
		if parseSidecarHeader(b) == nil {
			t.Fatalf("%s was rebuilt into bytes that will not parse", p)
		}
	}
	// And the blooms and postings rebuilt with it, as strong as ever: a
	// refusal and an exact jump both still answer.
	var segs []Segment
	for _, seg := range s.Segments() {
		if seg.Sealed() {
			segs = append(segs, seg)
		}
	}
	if s.CouldHold(segs[0], "source", "nowhere/at/all") {
		t.Error("a rebuilt bloom stopped refusing a value the segment " +
			"never held")
	}
	var jumped int
	if jerr := s.RangeWhereEqual(time.Time{}, time.Time{}, "source",
		"shared/everywhere", nil, func(telemetry.Event) error {
			jumped++
			return nil
		}); jerr != nil {
		t.Fatal(jerr)
	}
	// One per sealed segment and one in the unsealed tail: the corpus
	// places "shared/everywhere" at day-local index 3 of every batch,
	// the tail included, and the jump must find exactly those.
	if jumped != len(segs)+1 {
		t.Fatalf("the rebuilt postings found %d events, want one per sealed "+
			"segment plus the tail's (%d)", jumped, len(segs)+1)
	}
}

// TestBrokenColumnsFallBackToDecodeNeverWrong: the corrupt-section
// discipline for the new sections. Deleted, torn, all-ones, an offset table
// blown past its blob, an ordinal past the dictionary, ordinals zeroed into
// a valid entry, postings indexes zeroed, another segment's sidecar, a file
// grown behind the index's back — every way a column file can stop
// describing its segment, the scan answers what decoding the lines answers,
// because an unusable section is "cannot answer", never an answer.
func TestBrokenColumnsFallBackToDecodeNeverWrong(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	s, dir := columnStore(t, rng, 3)
	defer func() { _ = s.Close() }()

	scan := func() []string {
		var out []string
		if err := s.Scan(time.Time{}, time.Time{}, func(r *Row) error {
			out = append(out, fmt.Sprintf("%s|%s|%s|%s|%d|%d", r.Source(),
				r.Class(), r.ActorValue(), r.Message(),
				r.Received().UnixNano(), r.Ordinal()))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	oracle := func() []string {
		keys, _, err := decodedRows(s, time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		return keys
	}
	var sealed []Segment
	for _, seg := range s.Segments() {
		if seg.Sealed() {
			sealed = append(sealed, seg)
		}
	}
	if len(sealed) < 2 {
		t.Fatal("the corpus sealed too little")
	}
	first := filepath.Join(dir, sealed[0].Name+SidecarExt)
	want := oracle()
	if len(want) == 0 {
		t.Fatal("the corpus holds nothing; the test proves nothing")
	}

	// Deleted: rebuilt for the next reader, same rows.
	idx, err := filepath.Glob(filepath.Join(dir, "*"+SidecarExt))
	if err != nil || len(idx) == 0 {
		t.Fatalf("no sidecars were written at seal time: %v %v", idx, err)
	}
	for _, p := range idx {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	if got := scan(); !reflect.DeepEqual(got, want) {
		t.Fatal("a scan after the sidecars were deleted answered differently")
	}

	// Torn: a truncated file is a torn write and reads as absent.
	b, _ := os.ReadFile(first)
	if werr := os.WriteFile(first, b[:sidecarHeaderLen+16], 0o600); werr != nil {
		t.Fatal(werr)
	}
	if got := scan(); !reflect.DeepEqual(got, want) {
		t.Fatal("a torn sidecar changed the rows")
	}

	// Corrupt with the length preserved — so the header, the digest and the
	// size check all pass and only the sections can notice — in the shapes
	// that keep a section structurally plausible and must still refuse.
	corrupt := func(name string, edit func(b []byte, sc *sidecar) []byte) {
		t.Helper()
		b, rerr := os.ReadFile(first)
		if rerr != nil {
			t.Fatal(rerr)
		}
		sc := parseSidecarHeader(b)
		if sc == nil {
			t.Fatalf("%s: the header will not parse", name)
		}
		if werr := os.WriteFile(first, edit(b, sc), 0o600); werr != nil {
			t.Fatal(werr)
		}
		if got := scan(); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s changed the rows", name)
		}
	}
	dictAt := func(sc *sidecar, i int) int64 {
		return sc.dictBase(i) + 4*int64(sc.dn[i]+1) + int64(sc.dk[i])
	}
	// All ones from the first dictionary section onward: the tables no
	// longer fit their blobs and every load refuses.
	corrupt("a section of all ones", func(b []byte, sc *sidecar) []byte {
		for i := int(sc.dictBase(0)); i < len(b); i++ {
			b[i] = 0xff
		}
		return b
	})
	// An offset table entry past the value blob's length.
	corrupt("an offset past the blob", func(b []byte, sc *sidecar) []byte {
		b[sc.dictBase(0)+2] = 0xff
		b[sc.dictBase(0)+3] = 0x0f
		return b
	})
	// An ordinal past the dictionary: the message column's first event.
	corrupt("an ordinal past the dictionary", func(b []byte, sc *sidecar) []byte {
		at := dictAt(sc, 3) + 4*int64(sc.dn[3])
		b[at], b[at+1] = 0xff, 0xff
		return b
	})
	// Ordinals zeroed into a valid entry — structurally plausible, and the
	// one shape only the counts catch: every event claiming the source
	// dictionary's first value moves a count the postings still hold.
	corrupt("ordinals zeroed", func(b []byte, sc *sidecar) []byte {
		at := dictAt(sc, 0) + 4*int64(sc.dn[0])
		for i := int64(0); i < int64(sc.events)*2; i++ {
			b[at+i] = 0
		}
		return b
	})
	// Postings indexes zeroed — every entry claiming the first key's
	// position, which only the counts can refuse.
	corrupt("postings indexes zeroed", func(b []byte, sc *sidecar) []byte {
		at := dictAt(sc, 0)
		for i := int64(0); i < 4*int64(sc.dn[0]); i++ {
			b[at+i] = 0
		}
		return b
	})

	// Bound to another segment: the digest disagrees, the file is not this
	// segment's index, and both are rebuilt from the bytes that are there.
	other, err := os.ReadFile(filepath.Join(dir, sealed[1].Name+SidecarExt))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first, other, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := scan(); !reflect.DeepEqual(got, want) {
		t.Fatal("another segment's sidecar changed the rows")
	}

	// Grown behind the index's back: the ordinals describe sealed bytes, so
	// they are not trusted; the appended event is answered from what is
	// there, as the decoded reader always answered it.
	segPath := filepath.Join(dir, sealed[len(sealed)-1].Name)
	f, err := os.OpenFile(segPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, werr := f.WriteString(
		`{"time":"2026-09-25T12:00:00Z","received":"2026-10-02T12:00:00Z",` +
			`"class":3002,"activity":1,"severity":1,"disposition":1,` +
			`"source":"okta/system","message":"appended behind the index"}` +
			"\n"); werr != nil {
		t.Fatal(werr)
	}
	f.Close()
	got := scan()
	found := false
	for _, k := range got {
		if strings.Contains(k, "appended behind the index") {
			found = true
		}
	}
	if !found {
		t.Fatal("an event appended after sealing was dropped; the scan must " +
			"answer from the bytes that are there")
	}
	if want := oracle(); !reflect.DeepEqual(got, want) {
		t.Fatalf("after an append behind the index, the scan and the decode "+
			"disagree first at %s", firstDiff(got, want))
	}
}

// TestScansWalkBesideAWriterWithoutWaitingOnIt: the race-detector guard for
// the column path. A writer appends batch after batch while four readers
// scan the store through the columns, some rows lazily decoded; nothing may
// race, and each reader's successive answers grow only by appension.
func TestScansWalkBesideAWriterWithoutWaitingOnIt(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	s, dir := columnStore(t, rng, 3)
	srcs := []string{"okta/system", "github/audit", "proxy/egress"}

	start := time.Now()
	writer, err := Open(dir, Options{Now: func() time.Time {
		return base.Add(4 * 24 * time.Hour).Add(time.Since(start))
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
				at := base.Add(4 * 24 * time.Hour).Add(time.Since(start))
				e := event(at, at, "PutBucketPolicy")
				e.Source = srcs[(i+j)%3]
				batch = append(batch, e)
			}
			if _, aerr := writer.AppendBatch(batch); aerr != nil {
				t.Errorf("the writer stopped writing: %v", aerr)
				return
			}
		}
	}()

	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			var last []string
			for range 6 {
				var got []string
				serr := s.Scan(time.Time{}, time.Time{}, func(row *Row) error {
					got = append(got, row.Source()+"|"+row.Message())
					// Some rows are decoded beside the writer: the lazy
					// read runs under the same discipline as the columns.
					if row.Ordinal()%97 == 0 {
						if _, derr := row.Event(); derr != nil {
							return derr
						}
					}
					return nil
				})
				if serr != nil {
					t.Errorf("a scan beside a writer failed: %v", serr)
					return
				}
				if last != nil && (len(got) < len(last) ||
					!reflect.DeepEqual(got[:len(last)], last)) {
					t.Errorf("a later answer is not the earlier one with " +
						"arrivals added; the scan reordered the store")
					return
				}
				last = got
			}
		}()
	}
	readers.Wait()
	close(stop)
	writers.Wait()
}

// TestTheColumnsSidecarIsCountedAndBounded: the dictionary sections' size,
// said out loud, over a closed vocabulary and over the adversarial corpus
// where every message is distinct — the most a free-text log can hold. The
// sections cannot outgrow the segment that carried their values, Bytes()
// counts none of them, and the store still verifies.
func TestTheColumnsSidecarIsCountedAndBounded(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(t *testing.T) (*Spool, string)
	}{
		{"a closed vocabulary", func(t *testing.T) (*Spool, string) {
			rng := rand.New(rand.NewSource(1))
			return columnStore(t, rng, 2)
		}},
		{"every message distinct", func(t *testing.T) (*Spool, string) {
			c := &clock{at: base}
			s, dir := openAt(t, c, Options{})
			batch := make([]telemetry.Event, 0, 400)
			for i := range 400 {
				at := base.Add(time.Duration(i) * time.Second)
				e := event(at, at, "")
				e.Message = fmt.Sprintf(
					"user-%d signed in from 203.0.113.%d at %d and the "+
						"session lasted %d seconds", i, i%254+1, i, i%997)
				batch = append(batch, e)
			}
			if _, err := s.AppendBatch(batch); err != nil {
				t.Fatal(err)
			}
			if err := s.Seal(); err != nil {
				t.Fatal(err)
			}
			return s, dir
		}},
	} {
		s, dir := tc.build(t)
		var segBytes, sidecarBytes, columnBytes int64
		for _, seg := range s.Segments() {
			segBytes += seg.Bytes
			if !seg.Sealed() {
				continue
			}
			p := filepath.Join(dir, seg.Name+SidecarExt)
			st, err := os.Stat(p)
			if err != nil {
				continue
			}
			sidecarBytes += st.Size()
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				t.Fatal(rerr)
			}
			sc := parseSidecarHeader(b)
			if sc == nil {
				t.Fatalf("%s: %s will not parse", tc.name, p)
			}
			columnBytes += st.Size() - sc.dictBase(0)
		}
		if columnBytes == 0 || segBytes == 0 {
			t.Fatalf("%s: nothing to measure", tc.name)
		}
		t.Logf("%s: %d bytes of segments, %d of sidecar, %d of them the "+
			"dictionary columns (%.1f%% of the segments)", tc.name, segBytes,
			sidecarBytes, columnBytes,
			float64(columnBytes)/float64(segBytes)*100)
		if columnBytes > segBytes {
			t.Errorf("%s: the dictionary columns (%d bytes) outgrew the "+
				"segments they describe (%d bytes)", tc.name, columnBytes,
				segBytes)
		}
		if got := s.Bytes(); got != segBytes {
			t.Errorf("%s: the store counts %d bytes and the segments hold "+
				"%d; a sidecar has leaked into the count", tc.name, got,
				segBytes)
		}
		if bad, verr := s.Verify(); verr != nil || len(bad) != 0 {
			t.Errorf("%s: a store with dictionary columns does not verify: "+
				"%v %v", tc.name, bad, verr)
		}
		_ = s.Close()
	}
}

// BenchmarkScanDecodeToLearnFour is the "before": the full scan a consumer
// runs today to learn what the four hot fields say. Every line of every
// segment is decoded through Range — the parallel read path, so its numbers
// carry whatever the machine's cores give it — and the callback reads the
// four values off the decoded event. Class is read typed, without the
// fmt.Sprint the column's string form costs, which flatters the before.
func BenchmarkScanDecodeToLearnFour(b *testing.B) {
	s, _ := benchHuntStore(b)
	defer func() { _ = s.Close() }()
	b.ReportAllocs()
	var n int
	for b.Loop() {
		n = 0
		if err := s.Range(time.Time{}, time.Time{},
			func(e telemetry.Event) error {
				n += len(e.Source) + len(e.Message) + len(e.Actor.Value) +
					int(uint32(e.Class))
				return nil
			}); err != nil {
			b.Fatal(err)
		}
	}
	if n == 0 {
		b.Fatal("the scan read nothing")
	}
}

// BenchmarkScanColumns is the same question through the dictionary columns:
// eight sealed segments walked ordinal by ordinal, the four values and the
// arrival time answered by index lookups, and no line read at all. Sequential
// where the decode fans out — the comparison keeps each path's own shape.
func BenchmarkScanColumns(b *testing.B) {
	s, _ := benchHuntStore(b)
	defer func() { _ = s.Close() }()
	b.ReportAllocs()
	var n int
	for b.Loop() {
		n = 0
		if err := s.Scan(time.Time{}, time.Time{}, func(r *Row) error {
			n += len(r.Source()) + len(r.Message()) + len(r.ActorValue()) +
				len(r.Class()) + int(r.Received().UnixNano())
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
	if n == 0 {
		b.Fatal("the scan read nothing")
	}
}

// BenchmarkScanLazyDecodeEveryRow is the honest worst case of the new API:
// every row decoded, one capped read plus one unmarshal at a time, with no
// buffered pass over the file. Where this lands against the decoded scan is
// the crossover — the fraction of rows a consumer may decode before Range's
// buffered parallel read is the better tool — and the numbers go in the
// report, not just this label.
func BenchmarkScanLazyDecodeEveryRow(b *testing.B) {
	s, _ := benchHuntStore(b)
	defer func() { _ = s.Close() }()
	b.ReportAllocs()
	var n int
	for b.Loop() {
		n = 0
		if err := s.Scan(time.Time{}, time.Time{}, func(r *Row) error {
			e, err := r.Event()
			if err != nil {
				return err
			}
			n += len(e.Source) + len(e.Message)
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
	if n == 0 {
		b.Fatal("the scan read nothing")
	}
}
