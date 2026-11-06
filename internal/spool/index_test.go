// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package spool

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/telemetry"
)

// linearRange is the read as it was before sidecar indexes: every segment
// the window keeps, opened and scanned from the top. It is kept here as the
// oracle the indexed path is proved against — the same code Range ran, so a
// difference between the two is a difference the index introduced and
// nothing else.
func linearRange(s *Spool, from, to time.Time,
	fn func(telemetry.Event) error) error {

	for _, seg := range s.Segments() {
		if !to.IsZero() && !seg.First.Before(to) {
			continue
		}
		if !from.IsZero() && seg.Last.Before(from) {
			continue
		}
		if err := s.each(seg, func(e telemetry.Event) error {
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

// varied is one event of a corpus chosen to exercise every part of the
// index: sources that differ by case, two classes, actors present in four of
// five events, and arrival delays that vary per event.
func varied(at, received time.Time, i int) telemetry.Event {
	e := event(at, received, fmt.Sprintf("event %d", i))
	e.Source = []string{"okta/system", "github/audit", "proxy/egress"}[i%3]
	if i%7 == 0 {
		e.Source = "Okta/System"
	}
	if i%2 == 0 {
		e.Class = telemetry.ClassAPIActivity
	}
	if i%5 != 0 {
		e.Actor = telemetry.ID{Issuer: "okta",
			Value: fmt.Sprintf("user-%d", i%23)}
	}
	return e
}

// variedStore is several sealed days of varied events plus an active tail.
// The arrival delay is 17s of event spacing plus (i mod 13) seconds, which
// increases down every day's file — except the last day, where a third of
// the arrivals run explicitly backwards, so the store holds at least one
// segment whose times column is honestly marked unsorted and whose reads
// must take the linear path inside eachFrom rather than seek.
func variedStore(t *testing.T, days, perDay int) (*Spool, string, *clock) {
	t.Helper()
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{})
	n := 0
	for d := range days {
		day := base.Add(time.Duration(d) * 24 * time.Hour)
		c.at = day.Add(time.Hour)
		batch := make([]telemetry.Event, 0, perDay)
		for i := range perDay {
			at := day.Add(time.Duration(i) * 17 * time.Second)
			delay := time.Duration(i%13) * time.Second
			if d == days-1 && i%3 == 0 {
				delay = -time.Duration(i%97) * time.Second
			}
			batch = append(batch, varied(at, at.Add(delay), n))
			n++
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
	batch := make([]telemetry.Event, 0, 8)
	for i := range 8 {
		at := tail.Add(time.Duration(i) * time.Second)
		batch = append(batch, varied(at, at, n+i))
	}
	if _, err := again.AppendBatch(batch); err != nil {
		t.Fatalf("tail: %v", err)
	}
	if err := again.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	return again, dir, c
}

// The indexed read answers exactly what the linear one does, in the same
// order, over a corpus with sealed segments, an unsorted day, an active tail
// and arrival jitter — for every window shape a caller can ask for.
func TestAnIndexedReadAnswersExactlyWhatALinearOneDoes(t *testing.T) {
	s, _, c := variedStore(t, 4, 300)
	defer func() { _ = s.Close() }()
	c.at = base.Add(5 * 24 * time.Hour)

	var sealed, sorted, unsorted int
	for _, seg := range s.Segments() {
		if !seg.Sealed() {
			continue
		}
		sealed++
		sc := s.sidecarOf(seg)
		if sc == nil {
			t.Fatalf("%s is sealed and has no usable sidecar", seg.Name)
		}
		if sc.sorted {
			sorted++
		} else {
			unsorted++
		}
		sc.close()
	}
	if sealed < 3 || sorted == 0 || unsorted == 0 {
		t.Fatalf("the corpus must exercise every path: %d sealed, %d sorted, "+
			"%d unsorted — a test that covers one path proves nothing about "+
			"the others", sealed, sorted, unsorted)
	}

	d2 := base.Add(2 * 24 * time.Hour)
	windows := [][2]time.Time{
		{time.Time{}, time.Time{}},
		{base.Add(-time.Hour), time.Time{}},
		{d2, time.Time{}},
		{d2.Add(3 * time.Hour), time.Time{}},
		{base, d2},
		{d2.Add(3 * time.Hour), base.Add(3*24*time.Hour + time.Hour)},
	}
	compared := 0
	for _, w := range windows {
		var indexed, linear []string
		if err := s.Range(w[0], w[1], func(e telemetry.Event) error {
			indexed = append(indexed, fmt.Sprintf("%s|%d", e.Message,
				e.Received.UnixNano()))
			return nil
		}); err != nil {
			t.Fatalf("indexed [%s,%s): %v", w[0], w[1], err)
		}
		if err := linearRange(s, w[0], w[1], func(e telemetry.Event) error {
			linear = append(linear, fmt.Sprintf("%s|%d", e.Message,
				e.Received.UnixNano()))
			return nil
		}); err != nil {
			t.Fatalf("linear [%s,%s): %v", w[0], w[1], err)
		}
		if len(linear) == 0 {
			t.Fatalf("window [%s,%s) read nothing; the corpus is too thin "+
				"to prove equivalence with", w[0], w[1])
		}
		compared++
		if !reflect.DeepEqual(indexed, linear) {
			t.Fatalf("window [%s,%s): the indexed read returned %d events "+
				"and the linear one %d; they disagree first at %s",
				w[0], w[1], len(indexed), len(linear), firstDiff(indexed,
					linear))
		}
	}
	if compared < len(windows) {
		t.Fatalf("only %d of %d windows were compared", compared,
			len(windows))
	}
}

func firstDiff(a, b []string) string {
	for i := range a {
		if i >= len(b) || a[i] != b[i] {
			return a[i]
		}
	}
	if len(b) > len(a) {
		return b[len(a)]
	}
	return ""
}

// The seek itself: for a window starting at an event in the middle of a
// sealed segment, the column lands on exactly that event's line — the one
// the linear scan would have had to walk half the file to reach.
func TestTheSeekLandsOnTheFirstEventInTheWindow(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{SegmentBytes: 1 << 30})
	batch := make([]telemetry.Event, 0, 100)
	for i := range 100 {
		at := base.Add(time.Duration(i) * time.Second)
		batch = append(batch, varied(at, at, i))
	}
	if _, err := s.AppendBatch(batch); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	seg := s.Segments()[0]
	sc := s.sidecarOf(seg)
	if sc == nil || !sc.sorted {
		t.Fatal("no sorted sidecar to seek with")
	}
	defer sc.close()

	mid := base.Add(59 * time.Second) // event 59's arrival
	off, idx, ok := sc.firstAtOrAfter(mid)
	if !ok || idx != 59 {
		t.Fatalf("the column pointed at entry %d (ok %v), want 59", idx, ok)
	}
	b := make([]byte, 512)
	f, err := os.Open(filepath.Join(s.dir, seg.Name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.ReadAt(b, int64(off)); err != nil {
		t.Fatal(err)
	}
	end := 0
	for end < len(b) && b[end] != '\n' {
		end++
	}
	var e telemetry.Event
	if uerr := json.Unmarshal(b[:end], &e); uerr != nil {
		t.Fatalf("the seek landed mid-line: %v", uerr)
	}
	if !e.Received.Equal(mid) {
		t.Fatalf("the seek landed on %s, want %s", e.Received, mid)
	}
}

// The blooms, asked what a hunt asks of them. The refusals are the load
// -bearing half: a value the segment provably never carried — under the
// case-insensitive whole-value equality a detection's equals makes — is
// refused, and everything else is allowed through.
func TestTheBloomsAnswerDefinitelyNotOnlyWhenItIsTrue(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	one := func(src string, class telemetry.Class, actor string, i int) {
		e := varied(base.Add(time.Duration(i)*300*time.Millisecond),
			base.Add(time.Duration(i)*300*time.Millisecond), i)
		e.Source = src
		e.Class = class
		e.Actor = telemetry.ID{}
		if actor != "" {
			e.Actor = telemetry.ID{Issuer: "okta", Value: actor}
		}
		if _, err := s.AppendBatch([]telemetry.Event{e}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 10 {
		one("okta/system", telemetry.ClassAuthentication, "dana", 4*i)
		one("Okta/System", telemetry.ClassAPIActivity, "", 4*i+1)
		one("github/audit", telemetry.ClassAPIActivity, "sam", 4*i+2)
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	seg := s.Segments()[0]

	maybe := map[string][2]string{
		"a source it holds":         {"source", "okta/system"},
		"the same in another case":  {"source", "OKTA/SYSTEM"},
		"the case-folded twin":      {"source", "okta/system"},
		"the other source it holds": {"source", "github/audit"},
		"its class":                 {"class", fmt.Sprint(uint32(telemetry.ClassAuthentication))},
		"the twin's class":          {"class", fmt.Sprint(uint32(telemetry.ClassAPIActivity))},
		"an actor it holds":         {"actor.value", "dana"},
		"the actor in another case": {"actor.value", "DANA"},
		"a field the blooms do not": {"ip", "203.0.113.9"},
	}
	for name, q := range maybe {
		if !s.CouldHold(seg, q[0], q[1]) {
			t.Errorf("%s: the bloom said definitely not to %q on %q, and it "+
				"cannot know that", name, q[1], q[0])
		}
	}
	definitely := map[string][2]string{
		"a source never held":       {"source", "crowdstrike/detections"},
		"a prefix of a held one":    {"source", "okta"},
		"a suffix of a held one":    {"source", "system"},
		"more than a held one":      {"source", "okta/systems"},
		"a class never held":        {"class", "4002"},
		"an actor never present":    {"actor.value", "omar"},
		"part of a held actor":      {"actor.value", "dan"},
		"the issuer, not the value": {"actor.value", "okta"},
	}
	for name, q := range definitely {
		if s.CouldHold(seg, q[0], q[1]) {
			t.Errorf("%s: %q on %q cannot be in the segment — an equals "+
				"over the whole value would not hold for any event in it — "+
				"and the bloom did not say so", name, q[1], q[0])
		}
	}

	// A segment whose events carry no actor at all: an equality on
	// actor.value is refused outright, because Fields holds no actor.value
	// for any of its events either.
	c2 := base.Add(24 * time.Hour)
	c.at = c2
	bare := varied(c2, c2, 0)
	bare.Actor = telemetry.ID{}
	bare.Source = "proxy/egress"
	if _, err := s.AppendBatch([]telemetry.Event{bare}); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	bareSeg := s.Segments()[1]
	if s.CouldHold(bareSeg, "actor.value", "dana") {
		t.Error("a segment whose events carry no actor was not refused on " +
			"actor.value")
	}
	if !s.CouldHold(bareSeg, "source", "proxy/egress") {
		t.Error("a segment was refused for a source it holds")
	}

	// An unsealed segment is never refused: it has no sidecar, and its bytes
	// are still moving.
	c.at = base.Add(48 * time.Hour)
	if _, err := s.AppendBatch([]telemetry.Event{
		varied(c.at, c.at, 99)}); err != nil {
		t.Fatal(err)
	}
	tail := s.Segments()[len(s.Segments())-1]
	if !s.CouldHold(tail, "source", "crowdstrike/detections") {
		t.Error("an unsealed segment was refused by a bloom it cannot have")
	}
}

// bloomKey must fold exactly what detect's equals compares: EqualFold(a, b)
// implies bloomKey(a) == bloomKey(b), and nothing folds together that
// EqualFold keeps apart. A cheaper fold — ToLower — breaks this on "ſ" and
// "s", and a bloom keyed by it would skip a segment holding one when asked
// for the other.
func TestTheBloomFoldMatchesWhatEqualsCompares(t *testing.T) {
	pairs := [][2]string{
		{"okta/system", "OKTA/System"},
		{"ſ", "s"}, {"S", "ſ"}, {"σ", "ς"}, {"ς", "Σ"}, {"İ", "İ"},
		{"Straße", "STRASSE"}, // not EqualFold, and the folds differ too
		{"user-dana", "USER-DANA"},
		{"", ""},
	}
	for _, p := range pairs {
		want := strings.EqualFold(p[0], p[1])
		got := bloomKey(p[0]) == bloomKey(p[1])
		if want != got {
			t.Errorf("bloomKey(%q) == bloomKey(%q) is %v but EqualFold is "+
				"%v. A mismatch where EqualFold is true skips segments; a "+
				"mismatch where it is false is fine in principle but means "+
				"the fold is not the one equals makes", p[0], p[1], got,
				want)
		}
	}
}

// The hunt's read: a bloom that says definitely not lets a segment be
// skipped whole, and the events the hunt sees are exactly the ones the
// linear read would have filtered out of the full store.
func TestABloomSkippedSegmentIsNeverMissed(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	day := func(d int, src, mark string, n int) {
		c.at = base.Add(time.Duration(d) * 24 * time.Hour)
		batch := make([]telemetry.Event, 0, n)
		for i := range n {
			at := c.at.Add(time.Duration(i) * time.Second)
			e := varied(at, at, d*1000+i)
			e.Source = src
			e.Message = fmt.Sprintf("%s %d", mark, i)
			batch = append(batch, e)
		}
		if _, err := s.AppendBatch(batch); err != nil {
			t.Fatal(err)
		}
		if err := s.Seal(); err != nil {
			t.Fatal(err)
		}
	}
	day(0, "github/audit", "github-only", 40)
	day(1, "okta/system", "wanted", 40)
	day(2, "github/audit", "github-only", 40)
	day(3, "proxy/egress", "github-only", 40)
	// An active tail the hunt must not skip: unsealed, so no bloom exists.
	tailAt := base.Add(4 * 24 * time.Hour)
	c.at = tailAt
	e := varied(tailAt, tailAt, 4000)
	e.Source = "okta/system"
	e.Message = "wanted tail"
	if _, err := s.AppendBatch([]telemetry.Event{e}); err != nil {
		t.Fatal(err)
	}

	var allowed, refused int
	keep := func(seg Segment) bool {
		if s.CouldHold(seg, "source", "okta/system") {
			allowed++
			return true
		}
		refused++
		return false
	}
	var got []string
	if err := s.RangeWhere(time.Time{}, time.Time{}, keep,
		func(e telemetry.Event) error {
			if !strings.EqualFold(e.Source, "okta/system") {
				t.Errorf("the pruned read handed over %q from %s",
					e.Message, e.Source)
			}
			got = append(got, e.Message)
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if refused != 3 || allowed != 2 {
		t.Fatalf("the bloom refused %d segment(s) and allowed %d; three "+
			"hold nothing an equality on okta/system keeps, and the wanted "+
			"segment and the unsealed tail are two", refused, allowed)
	}
	if len(got) != 41 || got[0] != "wanted 0" ||
		got[len(got)-1] != "wanted tail" {
		t.Fatalf("the pruned hunt saw %d events, from %q to %q; the wanted "+
			"segment and the tail together are 41", len(got), got[0],
			got[len(got)-1])
	}

	// Against the linear read of the whole store under the same filter.
	var want []string
	if err := s.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		if strings.EqualFold(e.Source, "okta/system") {
			want = append(want, e.Message)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the pruned read and the full one disagree first at %q",
			firstDiff(got, want))
	}
}

// A bloom corrupted to always say yes — every bit set — changes nothing
// about the answer, only how much was read to produce it. That is the whole
// safety argument for the filter, so it is asserted rather than assumed.
func TestABloomCorruptedToAlwaysSayYesChangesNothing(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{})
	batch := make([]telemetry.Event, 0, 60)
	for i := range 60 {
		at := base.Add(time.Duration(i) * time.Second)
		batch = append(batch, varied(at, at, i))
	}
	if _, err := s.AppendBatch(batch); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	seg := s.Segments()[0]

	var before []string
	if err := s.RangeWhere(time.Time{}, time.Time{}, func(g Segment) bool {
		return s.CouldHold(g, "source", "okta/system")
	}, func(e telemetry.Event) error {
		before = append(before, e.Message)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(before) == 0 {
		t.Fatal("the uncorrupted filter found nothing to read")
	}

	b, err := os.ReadFile(filepath.Join(dir, seg.Name+SidecarExt))
	if err != nil {
		t.Fatal(err)
	}
	blooms := sidecarOffsetOf(0) + 16*int64(seg.Events)
	for i := int(blooms); i < len(b); i++ {
		b[i] = 0xff
	}
	if werr := os.WriteFile(filepath.Join(dir, seg.Name+SidecarExt), b,
		0o600); werr != nil {
		t.Fatal(werr)
	}
	if !s.CouldHold(seg, "source", "nothing/anywhere") {
		t.Fatal("a filter of all ones still said definitely not")
	}

	var after []string
	if err := s.RangeWhere(time.Time{}, time.Time{}, func(g Segment) bool {
		return s.CouldHold(g, "source", "okta/system")
	}, func(e telemetry.Event) error {
		after = append(after, e.Message)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("a bloom corrupted to always say yes changed the answer")
	}
}

// Missing, torn and stale sidecars are rebuilt or ignored, and a store that
// cannot be written to still answers. The one thing that must never happen
// is a wrong answer to protect an index.
func TestAMissingOrBrokenSidecarIsRebuiltOrIgnoredNeverWrong(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{SegmentBytes: 4000})
	batch := make([]telemetry.Event, 0, 300)
	for i := range 300 {
		at := base.Add(time.Duration(i) * time.Second)
		batch = append(batch, varied(at, at, i))
	}
	if _, err := s.AppendBatch(batch); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	var segs []string
	for _, seg := range s.Segments() {
		segs = append(segs, seg.Name)
	}
	read := func() []string {
		var out []string
		if err := s.Range(base.Add(time.Minute), time.Time{},
			func(e telemetry.Event) error {
				out = append(out, e.Message)
				return nil
			}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	want := read()

	// Deleted: rebuilt on the next read, and the answer is the same one.
	idx, err := filepath.Glob(filepath.Join(dir, "*"+SidecarExt))
	if err != nil || len(idx) == 0 {
		t.Fatalf("no sidecars were written at seal time: %v %v", idx, err)
	}
	for _, p := range idx {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	if got := read(); !reflect.DeepEqual(got, want) {
		t.Fatal("a read after the sidecars were deleted answered differently")
	}
	if idx, _ = filepath.Glob(filepath.Join(dir, "*"+SidecarExt)); len(idx) == 0 {
		t.Fatal("the sidecars were not rebuilt for the next reader")
	}

	// Torn: a truncated file is a torn write and reads as absent.
	p := filepath.Join(dir, segs[0]+SidecarExt)
	b, _ := os.ReadFile(p)
	if werr := os.WriteFile(p, b[:len(b)/2], 0o600); werr != nil {
		t.Fatal(werr)
	}
	if got := read(); !reflect.DeepEqual(got, want) {
		t.Fatal("a torn sidecar changed the answer")
	}

	// Grown behind the index's back: the offsets describe the sealed bytes,
	// so they are not trusted; the whole file is read, and the event that
	// arrived after sealing is answered from the bytes that are there, as
	// the linear reader always answered it.
	segPath := filepath.Join(dir, segs[len(segs)-1])
	f, err := os.OpenFile(segPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, werr := f.WriteString(
		`{"time":"2026-09-25T12:00:00Z","received":"2026-09-26T12:00:00Z",` +
			`"class":3002,"activity":1,"severity":1,"disposition":1,` +
			`"source":"okta/system","message":"appended behind the index"}` +
			"\n"); werr != nil {
		t.Fatal(werr)
	}
	f.Close()
	found := false
	for _, m := range read() {
		if m == "appended behind the index" {
			found = true
		}
	}
	if !found {
		t.Fatal("an event appended after sealing was dropped; the reader " +
			"must answer from the bytes that are there, as it always did")
	}

	// Unwritable: a store that cannot persist a rebuild still answers. The
	// expected answer is retaken here, with the appended event in it.
	want = read()
	if os.Geteuid() == 0 {
		t.Skip("running as root, permissions would not stop the write")
	}
	idx, _ = filepath.Glob(filepath.Join(dir, "*"+SidecarExt))
	for _, p := range idx {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Skipf("chmod: %v", err)
	}
	defer func() { _ = os.Chmod(dir, 0o755) }()
	if got := read(); !reflect.DeepEqual(got, want) {
		t.Fatal("a read that could not persist its rebuild answered wrong")
	}
	if idx, _ = filepath.Glob(filepath.Join(dir, "*"+SidecarExt)); len(idx) != 0 {
		t.Fatal("a sidecar was written into a directory nobody may write to")
	}
}

// Sidecars are derived data: nothing that counts the store may count them.
func TestSidecarsAreCountedByNothing(t *testing.T) {
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{})
	batch := make([]telemetry.Event, 0, 50)
	for i := range 50 {
		at := base.Add(time.Duration(i) * time.Second)
		batch = append(batch, varied(at, at, i))
	}
	if _, err := s.AppendBatch(batch); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}
	if s.Events() != 50 || s.Bytes() == 0 {
		t.Fatalf("the store counts %d events and %d bytes", s.Events(),
			s.Bytes())
	}
	var onDisk int64
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	for _, p := range files {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		onDisk += st.Size()
	}
	if onDisk != s.Bytes() {
		t.Fatalf("the index counts %d bytes and the segment files hold %d; "+
			"a sidecar has leaked into the count", s.Bytes(), onDisk)
	}
	if bad, err := s.Verify(); err != nil || len(bad) != 0 {
		t.Fatalf("a store with sidecars does not verify: %v %v", bad, err)
	}
	var seen int
	if err := s.Range(time.Time{}, time.Time{}, func(telemetry.Event) error {
		seen++
		return nil
	}); err != nil || seen != 50 {
		t.Fatalf("read %d events (%v), want the 50 that were stored", seen,
			err)
	}
}

// benchRangeStore is two sealed segments of two hundred thousand events
// each — a real 64 MiB segment's worth, spanning most of an arrival day —
// and a window that starts twenty hours into the second one. That is the
// shape every incremental reader produces: a detect run's cursor or a hunt's
// period begins deep inside a segment that segment-level pruning cannot
// skip, because the segment holds events on both sides of it.
func benchRangeStore(b *testing.B) (*Spool, time.Time) {
	b.Helper()
	c := &clock{at: base}
	s, _ := openAt(b, c, Options{})
	n := 0
	for d := range 2 {
		day := base.Add(time.Duration(d) * 24 * time.Hour)
		c.at = day.Add(time.Hour)
		batch := make([]telemetry.Event, 0, 200_000)
		for i := range 200_000 {
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
	return s, base.Add(24*time.Hour + 20*time.Hour)
}

// BenchmarkSpoolRangeLinear is the same query without the index: every
// segment the window touches opened and scanned from the top, the events
// before the window parsed only to be dropped. linearRange is that reader,
// kept in this file for exactly this comparison.
func BenchmarkSpoolRangeLinear(b *testing.B) {
	s, from := benchRangeStore(b)
	defer func() { _ = s.Close() }()
	var n int
	for b.Loop() {
		n = 0
		if err := linearRange(s, from, time.Time{},
			func(telemetry.Event) error { n++; return nil }); err != nil {
			b.Fatal(err)
		}
	}
	// Both readers hand the caller the same 29,000 events — that is the
	// equivalence the tests assert — and differ only in what they parsed to
	// produce them: this one unmarshalled all 200,000 lines of the segment.
	if n != 29_000 {
		b.Fatalf("read %d events", n)
	}
}

// BenchmarkSpoolRangeIndexed is the same window through the sidecar's times
// column: the touched segment binary-searched to the first event that can be
// in the window — twenty hours in — and everything before it left unparsed
// on disk.
func BenchmarkSpoolRangeIndexed(b *testing.B) {
	s, from := benchRangeStore(b)
	defer func() { _ = s.Close() }()
	var n int
	for b.Loop() {
		n = 0
		if err := s.Range(from, time.Time{},
			func(telemetry.Event) error { n++; return nil }); err != nil {
			b.Fatal(err)
		}
	}
	// 200,000 events spanning 22.2 hours of arrivals; a window opening at
	// 20:00 leaves the last 3.2 hours, which at one event per 400ms is
	// 29,000 — the same 29,000 the linear read above walked past to find.
	if n != 29_000 {
		b.Fatalf("read %d events", n)
	}
}

// benchHuntStore is eight sealed segments each holding one source, the shape
// a hunt prunes over: asking for a source that is in one segment of eight
// is the question the source bloom exists to answer.
func benchHuntStore(b *testing.B) (*Spool, string) {
	b.Helper()
	c := &clock{at: base}
	s, _ := openAt(b, c, Options{})
	srcs := []string{"github/audit", "proxy/egress", "aws/cloudtrail",
		"crowdstrike/detections", "m365/audit", "k8s/audit", "okta/system",
		"syslog/linux"}
	for d := range 8 {
		day := base.Add(time.Duration(d) * 24 * time.Hour)
		c.at = day.Add(time.Hour)
		batch := make([]telemetry.Event, 0, 50_000)
		for i := range 50_000 {
			at := day.Add(time.Duration(i) * 17 * time.Millisecond)
			e := varied(at, at.Add(time.Duration(i%13)*time.Millisecond),
				d*50_000+i)
			e.Source = srcs[d]
			batch = append(batch, e)
		}
		if _, err := s.AppendBatch(batch); err != nil {
			b.Fatal(err)
		}
		if err := s.Seal(); err != nil {
			b.Fatal(err)
		}
	}
	return s, "okta/system"
}

// BenchmarkHuntBloomPruned is the hunt's read over the whole store with an
// equality the blooms can answer: seven of eight segments are refused
// without opening them, and the one that may hold the value is read.
func BenchmarkHuntBloomPruned(b *testing.B) {
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
		b.Fatalf("found %d events from the wanted source", n)
	}
}

// BenchmarkHuntUnpruned is the same read with the blooms consulted nowhere —
// the hunt as it was before the sidecar indexes existed — so the two numbers
// are the same question asked with and without the index.
func BenchmarkHuntUnpruned(b *testing.B) {
	s, want := benchHuntStore(b)
	defer func() { _ = s.Close() }()
	var n int
	for b.Loop() {
		n = 0
		if err := s.Range(time.Time{}, time.Time{},
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
		b.Fatalf("found %d events from the wanted source", n)
	}
}
