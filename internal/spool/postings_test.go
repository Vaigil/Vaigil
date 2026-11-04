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

// linearEqual is the equality read as a detection's predicate would do it:
// the plain linear scan of every segment the window keeps, with the same
// comparison Match.eval makes — Fields' value for the field, EqualFold over
// the whole of it. The oracle the indexed path is proved against; the same
// shape as linearRange and linearWhere, kept beside them for exactly this.
func linearEqual(s *Spool, from, to time.Time, field, value string,
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
			got, present := e.Fields()[field]
			if !present || !strings.EqualFold(got, value) {
				return nil
			}
			return fn(e)
		}); err != nil {
			return err
		}
	}
	return nil
}

// actions is a closed vocabulary of the shape a rule's message equality
// matches: whole API action names, near-miss neighbours a prefix or a
// one-byte edit would confuse, and two fold twins.
var actions = []string{
	"PutAccountPublicAccessBlock", "PutAccountPublicAccessBloc",
	"PutAccountPublicAccessBlocks", "PutBucketPolicy", "GetBucketPolicy",
	"CreateBucket", "DeleteBucket", "UpdateAssumeRolePolicy",
	"ſign-in", "sign-in",
}

// actionStore is days of sealed segments drawn from that vocabulary — with
// one value deliberately shared across several segments, case variants of
// another, a third of one day's arrivals running backwards so its sidecar is
// honestly unsorted, and an unsealed tail. The shape the postings exist for:
// rare values in a store of common ones, spread unevenly.
func actionStore(t *testing.T, rng *rand.Rand, days int) (*Spool, string) {
	t.Helper()
	c := &clock{at: base}
	s, dir := openAt(t, c, Options{})
	n := 0
	for d := range days {
		day := base.Add(time.Duration(d) * 24 * time.Hour)
		c.at = day.Add(time.Hour)
		per := 120 + rng.Intn(80)
		batch := make([]telemetry.Event, 0, per)
		for i := range per {
			at := day.Add(time.Duration(i) * 17 * time.Second)
			delay := time.Duration(rng.Intn(13)) * time.Second
			if d == days-1 && rng.Intn(3) == 0 {
				delay = -time.Duration(rng.Intn(97)) * time.Second
			}
			e := varied(at, at.Add(delay), n)
			// The common noise of the day, with the rare action salted in:
			// every day carries some PutBucketPolicy (shared across
			// segments), and only the middle day carries the
			// public-access-block write a rule waits for.
			e.Message = actions[rng.Intn(len(actions))]
			if rng.Intn(40) == 0 {
				e.Message = "PutBucketPolicy"
			}
			if d == days/2 && rng.Intn(30) == 0 {
				e.Message = "PutAccountPublicAccessBlock"
			}
			if rng.Intn(9) == 0 {
				e.Message = strings.ToUpper(e.Message)
			}
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
	batch := make([]telemetry.Event, 0, 12)
	for i := range 12 {
		at := tail.Add(time.Duration(i) * time.Second)
		e := varied(at, at, n+i)
		e.Message = "PutAccountPublicAccessBlock"
		if i%2 == 0 {
			e.Message = "putaccountpublicaccessblock"
		}
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

// equalityKeys is the query list every equivalence comparison draws from:
// values present once, values shared across segments, values absent,
// case twins of each, and the empty string — which Fields holds for a
// message-less event and which an equality must therefore be able to ask
// about honestly.
func equalityKeys() [][2]string {
	return [][2]string{
		{"message", "PutAccountPublicAccessBlock"},
		{"message", "PUTACCOUNTPUBLICACCESSBLOCK"},
		{"message", "PutAccountPublicAccessBloc"},
		{"message", "PutAccountPublicAccessBlocks"},
		{"message", "PutBucketPolicy"},
		{"message", "putbucketpolicy"},
		{"message", "DeleteBucket"},
		{"message", "nothing/ever/happened"},
		{"source", "okta/system"},
		{"source", "OKTA/SYSTEM"},
		{"source", "nowhere/at/all"},
		{"class", fmt.Sprint(uint32(telemetry.ClassAuthentication))},
		{"class", fmt.Sprint(uint32(telemetry.ClassAPIActivity))},
		{"class", "4002"},
		{"actor.value", "user-5"},
		{"actor.value", "USER-5"},
		{"actor.value", "user-99"},
		{"actor.value", ""},
	}
}

// TestAnEqualityReadAnswersExactlyWhatThePredicateWould: the guard the
// postings stand on. Over a randomized store with sealed days, an unsorted
// day, case-variant values, values shared across segments and an unsealed
// tail, every equality-shaped query is read three ways — through the
// postings, through the postings again, and through the linear scan with the
// detection predicate applied — over windows of every shape. All three must
// agree exactly, in order.
func TestAnEqualityReadAnswersExactlyWhatThePredicateWould(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	s, _ := actionStore(t, rng, 5)
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

	key := func(e telemetry.Event) string {
		return fmt.Sprintf("%s|%d", e.Message, e.Received.UnixNano())
	}
	day := 24 * time.Hour
	windows := [][2]time.Time{
		{time.Time{}, time.Time{}},
		{base.Add(2 * day), time.Time{}},
		{base.Add(day + 3*time.Hour), base.Add(3 * day)},
	}
	for range 4 {
		from := base.Add(time.Duration(rng.Intn(5)) * day)
		var to time.Time
		if rng.Intn(2) == 1 {
			to = base.Add(time.Duration(2+rng.Intn(4)) * day)
		}
		windows = append(windows, [2]time.Time{from, to})
	}

	queries := equalityKeys()
	someNonEmpty := false
	for _, w := range windows {
		for _, q := range queries {
			indexed := func() []string {
				var out []string
				if err := s.RangeWhereEqual(w[0], w[1], q[0], q[1], nil,
					func(e telemetry.Event) error {
						out = append(out, key(e))
						return nil
					}); err != nil {
					t.Fatalf("indexed %s=%q [%s,%s): %v", q[0], q[1], w[0],
						w[1], err)
				}
				return out
			}
			got, again := indexed(), indexed()
			var want []string
			if err := linearEqual(s, w[0], w[1], q[0], q[1],
				func(e telemetry.Event) error {
					want = append(want, key(e))
					return nil
				}); err != nil {
				t.Fatalf("linear %s=%q [%s,%s): %v", q[0], q[1], w[0], w[1],
					err)
			}
			if !reflect.DeepEqual(got, again) {
				t.Fatalf("%s=%q [%s,%s): the same indexed read twice "+
					"produced two sequences, disagreeing first at %s", q[0],
					q[1], w[0], w[1], firstDiff(got, again))
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s=%q [%s,%s): the indexed read returned %d "+
					"events and the predicate's linear one %d; they "+
					"disagree first at %s", q[0], q[1], w[0], w[1],
					len(got), len(want), firstDiff(got, want))
			}
			someNonEmpty = someNonEmpty || len(got) > 0
		}
	}
	if !someNonEmpty {
		t.Fatal("every query over every window read nothing; the corpus is " +
			"too thin to prove equivalence with")
	}

	// A keep is still asked before anything else, and refusing everything
	// yields exactly nothing — the postings never route around the caller.
	var asked []string
	var n int
	if err := s.RangeWhereEqual(time.Time{}, time.Time{}, "source",
		"okta/system",
		func(seg Segment) bool {
			asked = append(asked, seg.Name)
			return false
		}, func(telemetry.Event) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	if n != 0 || len(asked) != len(s.Segments()) {
		t.Fatalf("a keep that refused everything was asked about %d of %d "+
			"segments and still yielded %d events", len(asked),
			len(s.Segments()), n)
	}
}

// TestEveryValueTheStoreHoldsIsInTheIndex: postings exactness, asserted
// exhaustively rather than sampled. Every distinct value every sealed
// segment actually holds — enumerated by reading the events — must have a
// run in that segment's dictionary, and every distinct value it does not
// hold must not. A hash-based structure could only promise the first half;
// a sorted dictionary of full keys promises both, and this is the test that
// says so on collision-prone input: prefix neighbours, one-byte edits,
// fold twins, and the empty value.
func TestEveryValueTheStoreHoldsIsInTheIndex(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	s, _ := actionStore(t, rng, 3)
	// An event with no message at all: Fields carries the empty string for
	// it, so the dictionary must carry the empty key, or an equality on the
	// empty value would fall through a hole.
	tail := base.Add(3 * 24 * time.Hour)
	bare := varied(tail, tail, 9_999)
	bare.Message = ""
	if _, err := s.AppendBatch([]telemetry.Event{bare}); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}

	for _, seg := range s.Segments() {
		if !seg.Sealed() {
			continue
		}
		held := map[string]bool{}
		if err := s.each(seg, func(e telemetry.Event) error {
			f := e.Fields()
			for _, field := range postFieldNames[:] {
				if v, present := f[field]; present {
					held[field+"\x00"+bloomKey(v)] = true
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		sc := s.sidecarOf(seg)
		if sc == nil {
			t.Fatalf("%s is sealed and has no sidecar", seg.Name)
		}
		for _, field := range postFieldNames[:] {
			col := sc.postingsOf(field)
			if col == nil {
				t.Fatalf("%s has no postings column for %s", seg.Name, field)
			}
			for _, k := range append(actions, "") {
				want := held[field+"\x00"+bloomKey(k)]
				_, _, got, err := col.run(bloomKey(k))
				if err != nil {
					t.Fatalf("%s %s: the dictionary would not read: %v",
						seg.Name, field, err)
				}
				if got != want {
					t.Fatalf("%s: the dictionary says %q on %s is %v and "+
						"the segment says %v; a value absent from the "+
						"index must be absent from the segment, and a "+
						"value present must be present", seg.Name, k,
						field, got, want)
				}
			}
		}
		sc.close()
	}

	// And the empty message is found by the read, not just by the
	// dictionary: an equality over it yields the one event that carries it.
	var n int
	if err := s.RangeWhereEqual(time.Time{}, time.Time{}, "message", "",
		nil, func(e telemetry.Event) error {
			if e.Message != "" {
				t.Fatalf("the empty-message read yielded %q", e.Message)
			}
			n++
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("the empty message was found %d times, want the one event "+
			"that carries it", n)
	}
}

// TestTheEqualityReadKeepsTheSegmentsOrder: matches scattered through one
// segment and across several are yielded in file order within each segment
// and segment order overall — the sequence the gatherer's consumers stand
// on. The equivalence test above proves it against the oracle for random
// corpora; this one pins the mechanism itself with hand-placed matches.
func TestTheEqualityReadKeepsTheSegmentsOrder(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	mk := func(day, sec int, msg string) telemetry.Event {
		at := base.Add(time.Duration(day)*24*time.Hour +
			time.Duration(sec)*time.Second)
		e := varied(at, at, day*10_000+sec)
		e.Message = msg
		return e
	}
	// Two days of ten events each, all GetBucketPolicy but for day one's
	// seconds 2, 3 and 7 and day two's seconds 3 and 7 — matches with gaps
	// before, between and after them, in both segments.
	var batch []telemetry.Event
	for sec := range 10 {
		batch = append(batch, mk(0, sec, "GetBucketPolicy"))
	}
	for sec := range 10 {
		batch = append(batch, mk(1, sec, "GetBucketPolicy"))
	}
	for _, sec := range []int{2, 3, 7} {
		batch[sec].Message = "PutBucketPolicy"
	}
	for _, sec := range []int{3, 7} {
		batch[10+sec].Message = "PutBucketPolicy"
	}
	if _, err := s.AppendBatch(batch); err != nil {
		t.Fatal(err)
	}
	if err := s.Seal(); err != nil {
		t.Fatal(err)
	}

	key := func(e telemetry.Event) string {
		return fmt.Sprintf("%s|%d", e.Message, e.Received.UnixNano())
	}
	var got []string
	if err := s.RangeWhereEqual(time.Time{}, time.Time{}, "message",
		"PutBucketPolicy", nil, func(e telemetry.Event) error {
			got = append(got, key(e))
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, sec := range []int{2, 3, 7} {
		want = append(want, key(mk(0, sec, "PutBucketPolicy")))
	}
	for _, sec := range []int{3, 7} {
		want = append(want, key(mk(1, sec, "PutBucketPolicy")))
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the jumped read yielded the matches out of file order; "+
			"they disagree first at %s", firstDiff(got, want))
	}
}

// TestABrokenPostingsSectionIsFallbackNotWrongAnswer: the corrupt-index
// discipline, carried to the new section. Deleted, torn, overwritten to
// all-ones, zeroed in its runs, or bound to another segment's digest — every
// which way a postings file can stop describing its segment, the read
// answers what the linear scan answers, because an unusable section is
// "cannot answer", never an answer.
func TestABrokenPostingsSectionIsFallbackNotWrongAnswer(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	s, dir := actionStore(t, rng, 3)
	defer func() { _ = s.Close() }()

	read := func() []string {
		var out []string
		if err := s.RangeWhereEqual(time.Time{}, time.Time{}, "message",
			"PutAccountPublicAccessBlock", nil,
			func(e telemetry.Event) error {
				out = append(out, fmt.Sprintf("%s|%d", e.Message,
					e.Received.UnixNano()))
				return nil
			}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	want := read()
	if len(want) == 0 {
		t.Fatal("the corpus holds no match; the test proves nothing")
	}

	// Deleted: rebuilt for the next reader, same answer.
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

	// Torn: a truncated file is a torn write and reads as absent.
	var segs []string
	for _, seg := range s.Segments() {
		if seg.Sealed() {
			segs = append(segs, seg.Name)
		}
	}
	p := filepath.Join(dir, segs[0]+SidecarExt)
	b, _ := os.ReadFile(p)
	if werr := os.WriteFile(p, b[:len(b)/2], 0o600); werr != nil {
		t.Fatal(werr)
	}
	if got := read(); !reflect.DeepEqual(got, want) {
		t.Fatal("a torn sidecar changed the answer")
	}

	// Overwritten to all ones from the postings onward: the tables no
	// longer fit the blobs, and every lookup fails — each to "cannot
	// answer", so the linear read decides, and the answer does not move.
	if b, err = os.ReadFile(p); err != nil {
		t.Fatal(err)
	}
	sc := parseSidecarHeader(b)
	if sc == nil {
		t.Fatal("the header will not parse")
	}
	for i := int(sidecarPostingsAt(sc.events)); i < len(b); i++ {
		b[i] = 0xff
	}
	if werr := os.WriteFile(p, b, 0o600); werr != nil {
		t.Fatal(werr)
	}
	if got := read(); !reflect.DeepEqual(got, want) {
		t.Fatal("a postings section of all ones changed the answer")
	}

	// Zeroed runs: the deltas decode to repeats, which the run decoder
	// refuses rather than trusts, and the segment falls back whole.
	if b, err = os.ReadFile(p); err != nil {
		t.Fatal(err)
	}
	sc = parseSidecarHeader(b)
	for i := range sc.pn {
		at := sc.postingsBase(i) + 4*int64(sc.pn[i]+1) + 8*int64(sc.pn[i]+1) +
			int64(sc.pk[i])
		for j := at; j < at+int64(sc.pp[i]); j++ {
			b[j] = 0
		}
	}
	if werr := os.WriteFile(p, b, 0o600); werr != nil {
		t.Fatal(werr)
	}
	if got := read(); !reflect.DeepEqual(got, want) {
		t.Fatal("zeroed ordinal runs changed the answer")
	}

	// Bound to another segment: the digest disagrees, the file is not this
	// segment's index, and both are rebuilt from the bytes that are there.
	if len(segs) < 2 {
		t.Fatal("the corpus left no second sealed segment to borrow from")
	}
	other, err := os.ReadFile(filepath.Join(dir, segs[1]+SidecarExt))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, segs[0]+SidecarExt), other,
		0o600); err != nil {
		t.Fatal(err)
	}
	if got := read(); !reflect.DeepEqual(got, want) {
		t.Fatal("another segment's sidecar changed the answer")
	}

	// Grown behind the index's back: the ordinals describe sealed bytes, so
	// they are not trusted; the appended event is answered from what is
	// there, as the linear reader always answered it. The appended line
	// carries the wanted message, so the answer must grow by exactly it.
	segPath := filepath.Join(dir, segs[len(segs)-1])
	f, err := os.OpenFile(segPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, werr := f.WriteString(
		`{"time":"2026-09-25T12:00:00Z","received":"2026-09-29T12:00:00Z",` +
			`"class":3002,"activity":1,"severity":1,"disposition":1,` +
			`"source":"okta/system","message":"PutAccountPublicAccessBlock"}` +
			"\n"); werr != nil {
		t.Fatal(werr)
	}
	f.Close()
	got := read()
	// The appended event arrives after the unsealed tail's day but lives in
	// an earlier segment, so the answer is not want-with-one-more-at-the-
	// end; the linear oracle is the honest comparison, as ever.
	appendedAt := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	var appended bool
	var linear []string
	if err := linearEqual(s, time.Time{}, time.Time{}, "message",
		"PutAccountPublicAccessBlock", func(e telemetry.Event) error {
			linear = append(linear, fmt.Sprintf("%s|%d", e.Message,
				e.Received.UnixNano()))
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	for _, k := range got {
		if strings.HasSuffix(k, fmt.Sprint(appendedAt.UnixNano())) {
			appended = true
		}
	}
	if !appended {
		t.Fatalf("an event appended after sealing was dropped: %d events, "+
			"and the linear scan answers %d", len(got), len(linear))
	}
	if !reflect.DeepEqual(got, linear) {
		t.Fatalf("after an append behind the index, the indexed read and "+
			"the linear one disagree first at %s", firstDiff(got, linear))
	}
}

// TestEqualityReadsWalkBesideAWriterWithoutWaitingOnIt: the race-detector
// guard for the new read path. A writer appends batch after batch while
// four readers walk the store through the postings; nothing may race, the
// immutable half never varies between reads, and each reader's successive
// answers grow only by appension.
func TestEqualityReadsWalkBesideAWriterWithoutWaitingOnIt(t *testing.T) {
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
			e.Message = actions[n%len(actions)]
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
	tail := base.Add(3 * 24 * time.Hour)
	c.at = tail
	tailBatch := make([]telemetry.Event, 0, 20)
	for i := range 20 {
		at := tail.Add(time.Duration(i) * time.Second)
		e := varied(at, at, n+i)
		e.Source = srcs[n%3]
		e.Message = actions[(n+i)%len(actions)]
		tailBatch = append(tailBatch, e)
	}
	if _, err := s.AppendBatch(tailBatch); err != nil {
		t.Fatal(err)
	}
	if err := s.Release(); err != nil {
		t.Fatal(err)
	}

	var sealedPrefix []string
	if err := s.RangeWhereEqual(time.Time{}, time.Time{}, "source",
		"okta/system", nil, func(e telemetry.Event) error {
			sealedPrefix = append(sealedPrefix, e.Message)
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if len(sealedPrefix) == 0 {
		t.Fatal("the corpus holds no okta/system event to walk beside")
	}

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
				e.Message = "PutBucketPolicy"
				batch = append(batch, e)
			}
			if _, err := writer.AppendBatch(batch); err != nil {
				t.Errorf("the writer stopped writing: %v", err)
				return
			}
		}
	}()

	queries := [][2]string{
		{"source", "okta/system"}, {"message", "PutBucketPolicy"},
		{"message", "putaccountpublicaccessblock"},
		{"actor.value", "user-5"},
	}
	var readers sync.WaitGroup
	for r := range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			q := queries[r%len(queries)]
			var last []string
			for range 6 {
				var got []string
				if err := s.RangeWhereEqual(time.Time{}, time.Time{},
					q[0], q[1], nil, func(e telemetry.Event) error {
						got = append(got, e.Message)
						return nil
					}); err != nil {
					t.Errorf("an equality read beside a writer failed: %v",
						err)
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
}

// TestThePostingsSidecarIsCountedAndBounded: the sidecar's size, said out
// loud and split honestly into its parts. The blooms were always a fixed
// 192 KiB per segment whatever the data — that cost predates the postings
// and is not theirs to answer for. The postings sections are what grew, so
// they are what is measured: small over a closed vocabulary, and over the
// adversarial corpus — every message distinct, the worst a free-text log
// can do — bounded by the segment, because a dictionary cannot hold more
// distinct bytes than the file that carried them. And Bytes() counts none
// of it, as ever.
func TestThePostingsSidecarIsCountedAndBounded(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(t *testing.T) (*Spool, string)
	}{
		{"a closed vocabulary", func(t *testing.T) (*Spool, string) {
			rng := rand.New(rand.NewSource(1))
			return actionStore(t, rng, 1)
		}},
		{"every message distinct", func(t *testing.T) (*Spool, string) {
			c := &clock{at: base}
			s, dir := openAt(t, c, Options{})
			batch := make([]telemetry.Event, 0, 400)
			for i := range 400 {
				at := base.Add(time.Duration(i) * time.Second)
				e := varied(at, at, i)
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
		var segBytes, sidecarBytes, postingsBytes int64
		for _, seg := range s.Segments() {
			segBytes += seg.Bytes
			p := filepath.Join(dir, seg.Name+SidecarExt)
			st, err := os.Stat(p)
			if err != nil || !seg.Sealed() {
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
			postingsBytes += st.Size() - sidecarPostingsAt(sc.events)
		}
		if postingsBytes == 0 || segBytes == 0 {
			t.Fatalf("%s: nothing to measure", tc.name)
		}
		t.Logf("%s: %d bytes of segments, %d of sidecar (%d of them the "+
			"fixed blooms and the column, %d the postings, %.1f%% of the "+
			"segments)", tc.name, segBytes, sidecarBytes,
			sidecarBytes-postingsBytes, postingsBytes,
			float64(postingsBytes)/float64(segBytes)*100)
		if postingsBytes > segBytes {
			t.Errorf("%s: the postings sections (%d bytes) outgrew the "+
				"segments they describe (%d bytes)", tc.name, postingsBytes,
				segBytes)
		}
		if got := s.Bytes(); got != segBytes {
			t.Errorf("%s: the store counts %d bytes and the segments hold "+
				"%d; a sidecar has leaked into the count", tc.name, got,
				segBytes)
		}
		_ = s.Close()
	}
}

// benchEqualStore is eight sealed segments of fifty thousand events over a
// closed vocabulary of actions — the shape a hunt scans when it asks where
// one API call happened. The wanted action lives only in the fourth segment,
// two hundred times among fifty thousand, so segment-level pruning and
// in-segment jumping both have work to do.
func benchEqualStore(b *testing.B) (*Spool, string) {
	b.Helper()
	c := &clock{at: base}
	s, _ := openAt(b, c, Options{})
	rng := rand.New(rand.NewSource(9))
	srcs := []string{"github/audit", "proxy/egress", "aws/cloudtrail",
		"crowdstrike/detections", "m365/audit", "k8s/audit", "okta/system",
		"syslog/linux"}
	common := []string{"GetBucketPolicy", "CreateBucket", "DeleteBucket",
		"UpdateAssumeRolePolicy", "ListBuckets", "GetBucketLocation"}
	for d := range 8 {
		day := base.Add(time.Duration(d) * 24 * time.Hour)
		c.at = day.Add(time.Hour)
		batch := make([]telemetry.Event, 0, 50_000)
		for i := range 50_000 {
			at := day.Add(time.Duration(i) * 17 * time.Millisecond)
			e := varied(at, at.Add(time.Duration(i%13)*time.Millisecond),
				d*50_000+i)
			e.Source = srcs[d]
			e.Message = common[rng.Intn(len(common))]
			// Two hundred exactly, every 250th event, so the two
			// benchmarks assert the same count against a number that is
			// placed rather than drawn.
			if d == 3 && i%250 == 0 {
				e.Message = "PutAccountPublicAccessBlock"
			}
			batch = append(batch, e)
		}
		if _, err := s.AppendBatch(batch); err != nil {
			b.Fatal(err)
		}
		if err := s.Seal(); err != nil {
			b.Fatal(err)
		}
	}
	return s, "PutAccountPublicAccessBlock"
}

// BenchmarkEqualityScanFullParallel is the equality scan as it was before
// the postings existed: every segment opened, every line parsed, the
// equality applied per event. Message had no bloom, so there was nothing
// to prune with either — this is the honest "before".
func BenchmarkEqualityScanFullParallel(b *testing.B) {
	s, want := benchEqualStore(b)
	defer func() { _ = s.Close() }()
	var n int
	for b.Loop() {
		n = 0
		if err := s.RangeWhere(time.Time{}, time.Time{},
			func(Segment) bool { return true },
			func(e telemetry.Event) error {
				if strings.EqualFold(e.Message, want) {
					n++
				}
				return nil
			}); err != nil {
			b.Fatal(err)
		}
	}
	if n != 200 {
		b.Fatalf("found %d events, want the 200 salted into the fourth "+
			"segment", n)
	}
}

// BenchmarkEqualityScanPostings is the same scan through the inverted
// index: seven dictionaries refuse the value and their segments are never
// opened, and the eighth is read at two hundred line offsets instead of
// fifty thousand.
func BenchmarkEqualityScanPostings(b *testing.B) {
	s, want := benchEqualStore(b)
	defer func() { _ = s.Close() }()
	var n int
	for b.Loop() {
		n = 0
		if err := s.RangeWhereEqual(time.Time{}, time.Time{}, "message",
			want, nil, func(telemetry.Event) error { n++; return nil }); err != nil {
			b.Fatal(err)
		}
	}
	if n != 200 {
		b.Fatalf("found %d events, want the 200 salted into the fourth "+
			"segment", n)
	}
	// The index's size, said beside its speed: what the postings-bearing
	// sidecars cost against the segments they describe.
	var segBytes, sidecarBytes int64
	for _, seg := range s.Segments() {
		segBytes += seg.Bytes
		if st, err := os.Stat(filepath.Join(s.dir, seg.Name+SidecarExt)); err == nil {
			sidecarBytes += st.Size()
		}
	}
	b.ReportMetric(float64(sidecarBytes)/float64(segBytes), "sidecar/segment")
}
