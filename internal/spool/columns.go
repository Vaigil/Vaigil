// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

// The dictionary columns: a scan that learns the hot fields without decoding
// a line.
//
// The postings answer "which events carry this value". The columns answer the
// question every other consumer of a full scan is actually asking: "what does
// this event's source, class, actor.value or message say". A detect pass
// pre-filtering on source, a hunt with a contains or prefix condition, an
// export of one field — each decodes every line of every segment to read a
// handful of strings that were all knowable at seal time. So the sidecar now
// keeps, per sealed segment and per field, a dictionary of the distinct
// original values plus one ordinal per event, and a scan over the store can
// walk the ordinals and the dictionaries instead of the JSON.
//
// # Layout
//
// One section per field, laid out in the order of postFieldNames after the
// postings sections, addressed by arithmetic from the header:
//
//	offset table   (n+1) × u32   offsets into the value blob, ascending; the
//	                              last entry is the blob's length
//	value blob     the ORIGINAL values, concatenated, sorted by folded key
//	                              with the original value breaking ties
//	postings idx   n × u32       each entry's folded key's position in this
//	                              field's postings key table — ascending,
//	                              because both dictionaries are sorted by the
//	                              same fold
//	ordinal col    events × width   the value's dictionary index per event,
//	                              u16 while the column's top index fits
//	                              sixteen bits, u32 after that
//
// The dictionary holds originals, not folded keys, and that is deliberate: a
// column read must answer exactly what decoding the line answers, and the
// line says "Okta/System" where the fold says "OKTA/SYSTEM". The fold still
// disciplines the section — it is the sort key, so fold twins sit beside each
// other and the ordering is the same one the postings dictionary uses — but
// it never touches the bytes a scan hands over. actor.value is the one field
// not every event carries, and its column says so with an ordinal of n, one
// past the last entry, rather than with a hole a reader could mistake for a
// value.
//
// # What is checked, and what is not
//
// On the way in the whole section is validated: the offset table must ascend
// and end at the blob's length, every ordinal must name an entry the
// dictionary has, every entry must name a postings key that exists — and
// then the section is checked against those postings, an independent count
// of the same values built in the same pass: the events pointing at an entry
// must number exactly what its folded key's postings run holds, for every
// key at once. A corruption that leaves a section structurally plausible —
// ordinals zeroed into a valid entry, a postings index shifted — moves those
// counts, and anything that moves them is "cannot answer" and the scan
// decodes lines. The same discipline the postings follow, carried one step
// further because a column has no per-event answer to re-check: a jumped
// equality re-verifies every event it hands over, and these counts are the
// column's way of re-verifying every value without reading a line.
//
// Two residuals remain, stated rather than hidden, both inherited from the
// format's refusal to checksum itself: an ordinal flipped from one fold twin
// to another leaves every count exactly where it was, and a value-blob byte
// flipped within a rune's case orbit changes the original the rows answer
// without changing anything the postings hold. A flipped postings key byte
// narrows an equality the same way. Staleness is what the digest-and-size
// binding rules out; bit rot is what Verify — which recomputes the segment's
// own digest — is for.
//
// # The scan, and where it honestly wins
//
// Scan hands its caller one Row per event in the order Range produces, with
// the four hot values, the arrival time and the event's ordinal answered
// from the columns; Event decodes the line on first call, at one read plus
// one unmarshal. The scan is sequential where Range fans out over segments,
// because there is nothing left worth overlapping: the columns cost
// nanoseconds per event, and the one slow thing a row can do — decode — is
// the caller's choice, per row, and cannot be gathered in order by a worker
// that has already moved on. A consumer that decodes every row should use
// Range, whose buffered parallel read beats a per-row seek; the crossover is
// measured, not asserted, and the benchmarks beside the tests report it.
package spool

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/aertun/aertun/internal/telemetry"
)

// dictAbsent reports whether field i's column needs a "no value" ordinal.
// Only actor.value: Fields holds it only when an actor exists at all, and a
// column that cannot say "absent" would answer an actor-less event with some
// other event's actor.
func dictAbsent(i int) bool { return postFieldNames[i] == "actor.value" }

// dictWidth is the ordinal column's byte width for a dictionary of entries
// distinct values. Two bytes while the column's top index fits sixteen bits
// — entries-1 for a column every event carries, entries for one whose last
// index is the absent ordinal — and four after that. Derived at both ends
// from the count the header carries, so the writer and the reader can never
// disagree about a section's geometry.
func dictWidth(entries int, absent bool) int {
	top := entries
	if !absent && top > 0 {
		top--
	}
	if top <= 1<<16-1 {
		return 2
	}
	return 4
}

// dictBuild gathers one field's column while a sidecar is built: the
// distinct original values interned as they are met, and each event's place
// among them.
type dictBuild struct {
	intern map[string]int
	vals   []string
	// per holds, per event in file order, the interned value's index, or -1
	// for an event that carried no value at all.
	per []int
}

func newDictBuild() *dictBuild {
	return &dictBuild{intern: map[string]int{}}
}

// add records a value every event carries.
func (b *dictBuild) add(v string) {
	i, ok := b.intern[v]
	if !ok {
		i = len(b.vals)
		b.intern[v] = i
		b.vals = append(b.vals, v)
	}
	b.per = append(b.per, i)
}

// addIf records a value only some events carry; the rest take the absent
// ordinal.
func (b *dictBuild) addIf(present bool, v string) {
	if !present {
		b.per = append(b.per, -1)
		return
	}
	b.add(v)
}

// marshalDict writes one field's dictionary section: the offset table with
// its sentinel, the value blob sorted by (folded key, value), each entry's
// position in the postings key table, and one ordinal per event at the
// width the dictionary's own size decides. keys is the blob's length,
// returned rather than recomputed so the header can never disagree with the
// section it describes.
//
// postKeys is this field's postings dictionary in the order it was written,
// so an entry's postings index is looked up against the very order on disk.
// Every entry's fold must be there — both are built from the same events in
// the same pass — and the one way that can fail is a bug in this build, so
// it refuses the build rather than writing a section that could not be
// true: a reader of a store so sealed falls back to decoding, which is the
// honest answer to a derived structure nobody can vouch for.
//
// The sort is over interned values whose indices are arbitrary — a value
// first met late can sort early — so the ordinals are emitted through a
// rank table rather than in the order they were gathered. The result is
// deterministic over the same bytes whatever the map handed the interner
// first, which is what two racing rebuilders both writing this file rely on.
func marshalDict(b *dictBuild, absent bool,
	postKeys []string) (section []byte, keys int64, err error) {

	n := len(b.vals)
	pos := make(map[string]int, len(postKeys))
	for q, k := range postKeys {
		pos[k] = q
	}
	folds := make([]string, n)
	order := make([]int, n)
	for i, v := range b.vals {
		folds[i] = bloomKey(v)
		order[i] = i
	}
	sort.Slice(order, func(x, y int) bool {
		if folds[order[x]] != folds[order[y]] {
			return folds[order[x]] < folds[order[y]]
		}
		// Fold twins: two originals one equality calls equal. Both stay in
		// the dictionary — a scan answers originals — and the bytewise tie
		// break is what keeps their order fixed.
		return b.vals[order[x]] < b.vals[order[y]]
	})
	rank := make([]int, n)
	for place, interned := range order {
		rank[interned] = place
	}

	width := dictWidth(n, absent)
	keyTable := make([]byte, 4*(n+1))
	postIdx := make([]byte, 4*n)
	var valueBlob []byte
	for place, interned := range order {
		q, ok := pos[folds[interned]]
		if !ok {
			return nil, 0, fmt.Errorf(
				"a value whose fold is not in the postings dictionary; the " +
					"two are built from the same events and cannot disagree")
		}
		binary.LittleEndian.PutUint32(keyTable[4*place:],
			uint32(len(valueBlob)))
		binary.LittleEndian.PutUint32(postIdx[4*place:], uint32(q))
		valueBlob = append(valueBlob, b.vals[interned]...)
	}
	binary.LittleEndian.PutUint32(keyTable[4*n:], uint32(len(valueBlob)))
	ords := make([]byte, width*len(b.per))
	for e, interned := range b.per {
		idx := n // the absent ordinal, one past the last entry
		if interned >= 0 {
			idx = rank[interned]
		}
		if width == 2 {
			binary.LittleEndian.PutUint16(ords[2*e:], uint16(idx))
		} else {
			binary.LittleEndian.PutUint32(ords[4*e:], uint32(idx))
		}
	}

	buf := bytes.NewBuffer(make([]byte, 0,
		4*(n+1)+len(valueBlob)+4*n+len(ords)))
	buf.Write(keyTable)
	buf.Write(valueBlob)
	buf.Write(postIdx)
	buf.Write(ords)
	return buf.Bytes(), int64(len(valueBlob)), nil
}

// dictColumn is one field's dictionary and ordinal column, loaded and
// validated. The values are strings of their own — split from the blob once,
// at load — so a scan's per-event work is an index lookup and nothing
// allocates per row.
type dictColumn struct {
	vals   []string
	post   []uint32 // each entry's folded key's position in the postings
	ords   []uint32
	absent bool
}

// loadDict reads field i's dictionary section out of the sidecar and checks
// all of it: the offset table must ascend within the blob, its last entry
// must be the blob's length, every event's ordinal must name an entry the
// dictionary has — the absent ordinal only where the field has one — every
// entry must name a postings key that exists and the names must ascend, and
// the events per postings key must count out to exactly what the postings
// hold. A section that fails any of this is an error, and the scan's caller
// treats errors here exactly as the postings' callers do: "cannot answer",
// never an answer, and the lines decide.
func (sc *sidecar) loadDict(i int) (*dictColumn, error) {
	n := int(sc.dn[i])
	base := sc.dictBase(i)
	table := make([]byte, 4*(n+1))
	if _, err := sc.r.ReadAt(table, base); err != nil {
		return nil, err
	}
	offs := make([]int, n+1)
	prev := -1
	for j := range offs {
		v := int(binary.LittleEndian.Uint32(table[4*j:]))
		if v < prev || v > int(sc.dk[i]) {
			return nil, fmt.Errorf("a dictionary offset outside its blob")
		}
		offs[j] = v
		prev = v
	}
	if offs[n] != int(sc.dk[i]) {
		return nil, fmt.Errorf("a dictionary whose last offset is not its " +
			"blob's length")
	}
	blob := make([]byte, sc.dk[i])
	if _, err := sc.r.ReadAt(blob, base+4*int64(n+1)); err != nil {
		return nil, err
	}
	col := &dictColumn{vals: make([]string, n), absent: dictAbsent(i)}
	for j := range col.vals {
		col.vals[j] = string(blob[offs[j]:offs[j+1]])
	}

	// The postings indexes: ascending, because the entries are sorted by the
	// same fold the postings keys are, and inside the key table they name.
	rawPost := make([]byte, 4*n)
	if _, err := sc.r.ReadAt(rawPost,
		base+4*int64(n+1)+int64(sc.dk[i])); err != nil {
		return nil, err
	}
	col.post = make([]uint32, n)
	prevPost := -1
	for j := range col.post {
		q := int(binary.LittleEndian.Uint32(rawPost[4*j:]))
		if q < prevPost || q >= int(sc.pn[i]) {
			return nil, fmt.Errorf("a postings position a dictionary entry " +
				"cannot have")
		}
		col.post[j] = uint32(q)
		prevPost = q
	}

	width := dictWidth(n, col.absent)
	raw := make([]byte, width*int(sc.events))
	if _, err := sc.r.ReadAt(raw,
		base+4*int64(n+1)+int64(sc.dk[i])+4*int64(n)); err != nil {
		return nil, err
	}
	col.ords = make([]uint32, sc.events)
	for e := range col.ords {
		idx := int(binary.LittleEndian.Uint16(raw[width*e:]))
		if width == 4 {
			idx = int(binary.LittleEndian.Uint32(raw[width*e:]))
		}
		if idx > n || (!col.absent && idx == n) {
			return nil, fmt.Errorf("an ordinal outside the dictionary")
		}
		col.ords[e] = uint32(idx)
	}
	if err := sc.countsAgree(i, col); err != nil {
		return nil, err
	}
	return col, nil
}

// countsAgree is the cross-check that makes a corrupt-but-plausible column
// "cannot answer" rather than a wrong row: the postings in this same file
// counted, per folded key, exactly the events that carried it, and the
// column counts, per dictionary entry, exactly the events whose ordinals
// name it. Entries sharing a fold — twins — add up to one postings key, so
// the two must agree on every key at once. Anything that edits ordinals or
// postings indexes without keeping every count moves one of these sums, and
// the segment's scan falls back to decoding its lines.
func (sc *sidecar) countsAgree(i int, col *dictColumn) error {
	perEntry := make([]int, len(col.vals)+1)
	for _, ord := range col.ords {
		perEntry[ord]++
	}
	got := make([]int, sc.pn[i])
	for entry, q := range col.post {
		got[q] += perEntry[entry]
	}
	want, err := sc.postingsCounts(i)
	if err != nil {
		return err
	}
	for q := range want {
		if got[q] != want[q] {
			return fmt.Errorf(
				"a dictionary column that disagrees with its own postings")
		}
	}
	return nil
}

// postingsCounts walks field i's postings section whole — one read, then a
// linear pass — and returns the event count per key position. The section's
// own run table is validated on the way: offsets must ascend within the runs
// blob, whose length the last one must be, and every run must decode into
// whole varints. A section that fails is an error, and a cross-check that
// cannot be read is not a cross-check: the column falls back too.
func (sc *sidecar) postingsCounts(i int) ([]int, error) {
	n := int(sc.pn[i])
	if n == 0 {
		return nil, nil
	}
	sec := make([]byte, sc.sectionLen(i))
	if _, err := sc.r.ReadAt(sec, sc.postingsBase(i)); err != nil {
		return nil, err
	}
	tables := 4*int64(n+1) + 8*int64(n+1)
	if int64(len(sec)) < tables+int64(sc.pk[i])+int64(sc.pp[i]) {
		return nil, fmt.Errorf("a postings section shorter than its tables")
	}
	runs := sec[tables+int64(sc.pk[i]):]
	prev := int64(0)
	counts := make([]int, n)
	for j := range counts {
		from := int64(binary.LittleEndian.Uint64(
			sec[4*int64(n+1)+8*int64(j):]))
		to := int64(binary.LittleEndian.Uint64(
			sec[4*int64(n+1)+8*int64(j+1):]))
		if from < prev || to < from || to > int64(sc.pp[i]) {
			return nil, fmt.Errorf("a run offset outside the runs blob")
		}
		prev = to
		c := 0
		buf := runs[from:to]
		for len(buf) > 0 {
			_, m := binary.Uvarint(buf)
			if m <= 0 {
				return nil, fmt.Errorf("a postings run that is not varint")
			}
			buf = buf[m:]
			c++
		}
		counts[j] = c
	}
	if prev != int64(sc.pp[i]) {
		return nil, fmt.Errorf("a postings run table whose last offset is " +
			"not its blob's length")
	}
	return counts, nil
}

// valueAt is event i's original value, or ("", false) when the event carried
// none. The absent case is decided by the column's own sentinel, kept out of
// vals so every index into vals is in range by construction.
func (c *dictColumn) valueAt(i int) (string, bool) {
	idx := int(c.ords[i])
	if c.absent && idx == len(c.vals) {
		return "", false
	}
	return c.vals[idx], true
}

// markStream walks the times column in file order, a fixed buffer at a time,
// so a scan of any segment costs a bounded read window. ReadAt at the end of
// the column returns a short count; only whole marks are kept and the tail
// is re-read when its other half arrives.
type markStream struct {
	sc   *sidecar
	at   int64
	buf  []byte
	end  int
	used int
}

func newMarkStream(sc *sidecar, from int) *markStream {
	return &markStream{
		sc:   sc,
		at:   sidecarOffsetOf(from),
		buf:  make([]byte, 4096*16),
		end:  0,
		used: 0,
	}
}

// next reads the next mark, or an error when the column runs dry before the
// header's event count — a section too short for the file it is part of,
// which is corruption, not an end of data: the header's own length
// arithmetic vouched for these bytes.
func (ms *markStream) next() (mark, error) {
	if ms.used >= ms.end {
		n, err := ms.sc.r.ReadAt(ms.buf, ms.at)
		n -= n % 16
		if n == 0 {
			if err != nil && !errors.Is(err, io.EOF) {
				return mark{}, err
			}
			return mark{}, fmt.Errorf(
				"the times column is shorter than the header claims")
		}
		ms.end, ms.used = n, 0
		ms.at += int64(n)
	}
	m := mark{
		offset: binary.LittleEndian.Uint64(ms.buf[ms.used:]),
		at:     int64(binary.LittleEndian.Uint64(ms.buf[ms.used+8:])),
	}
	ms.used += 16
	return m, nil
}

// Row is one event as a scan sees it: the four hot fields, the arrival time
// and the event's ordinal in its segment, answered from the columns without
// decoding a line — plus the line itself, decoded on demand.
//
// A Row is valid only inside the call it was handed to, and its values are
// the row's own until the next: a consumer that wants to keep one copies
// what it reads or calls Event. What a Row cannot answer without Event is
// everything else the event carries — its own time, activity, severity,
// disposition, the actor's issuer, target, device, observables and raw —
// because the columns hold four fields and no honest API pretends
// otherwise.
type Row struct {
	source   string
	class    string
	actor    string
	hasActor bool
	message  string
	received time.Time
	ordinal  int

	// The lazy decode. event is set once the line has been read — or up
	// front, on the decode path a segment answers with when its columns
	// cannot be consulted; buf, off and name are the line's where until
	// then. off is -1 when event already holds the event.
	buf   *lineBuf
	off   int64
	name  string
	event *telemetry.Event
}

// Source is the event's source, spelled as the line spells it — the original
// value, not the folded key an equality would compare.
func (r *Row) Source() string { return r.source }

// Class is the event's class as its string form, the value a detection's
// Fields map holds for "class" and the one an equality on it compares.
func (r *Row) Class() string { return r.class }

// HasActor reports whether the event carries an actor at all. An actor-less
// event has no actor.value for a predicate to compare, and the column says
// so rather than answering with some other event's value.
func (r *Row) HasActor() bool { return r.hasActor }

// ActorValue is the actor's value, empty when HasActor is false.
func (r *Row) ActorValue() string { return r.actor }

// Message is the event's message, empty when the event carried none.
func (r *Row) Message() string { return r.message }

// Received is when this program took delivery of the event — the clock the
// spool is ordered by and Scan windows on, out of the times column.
func (r *Row) Received() time.Time { return r.received }

// Ordinal is the event's zero-based place among its segment's events, by
// file order — the same ordinal the postings name and the times column
// indexes. It restarts at each segment.
func (r *Row) Ordinal() int { return r.ordinal }

// lineBuf reads one \n-terminated line at a time into a buffer it keeps, so
// a scan whose consumer decodes row after row does not allocate a fresh
// chunk for each one. The buffer is the segment scan's, shared by its rows
// one at a time — which is why a Row is valid only inside its call — and it
// grows only when a line outgrows it, never past the line cap every reader
// of telemetry keeps.
type lineBuf struct {
	f *os.File
	b []byte
}

// line reads the line that starts at off, without its newline, reusing the
// buffer it grew last time.
func (lb *lineBuf) line(off int64) ([]byte, error) {
	lb.b = lb.b[:0]
	for {
		if len(lb.b) == cap(lb.b) {
			if len(lb.b) >= MaxLine {
				return nil, fmt.Errorf("a line over the %d-byte limit", MaxLine)
			}
			next := 2 * cap(lb.b)
			if next < 64<<10 {
				next = 64 << 10
			}
			if next > MaxLine {
				next = MaxLine
			}
			grown := make([]byte, len(lb.b), next)
			copy(grown, lb.b)
			lb.b = grown
		}
		n, err := lb.f.ReadAt(lb.b[len(lb.b):cap(lb.b)], off+int64(len(lb.b)))
		lb.b = lb.b[:len(lb.b)+n]
		if i := bytes.IndexByte(lb.b, '\n'); i >= 0 {
			return lb.b[:i], nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				// EOF without a newline: the last line of a file whose final
				// byte was not \n. The builder consumed the same bytes.
				return lb.b, nil
			}
			return nil, err
		}
	}
}

// Event is the whole event, decoded from its line on first call and kept for
// the Row's remaining life. On a segment the columns could not serve, the
// line was decoded to build the Row and this returns it for free.
//
// The decode is one capped read at the row's offset plus one unmarshal:
// honest for the rows a hot-field consumer occasionally needs more of, and
// the measured reason a consumer that needs every event whole should use
// Range instead, whose buffered parallel read is built for exactly that.
func (r *Row) Event() (telemetry.Event, error) {
	if r.event != nil {
		return *r.event, nil
	}
	if r.buf == nil {
		return telemetry.Event{}, fmt.Errorf(
			"the row has no segment to decode its line from")
	}
	line, err := r.buf.line(r.off)
	if err != nil {
		return telemetry.Event{}, err
	}
	text := bytes.TrimSpace(line)
	if len(text) == 0 {
		return telemetry.Event{}, fmt.Errorf(
			"%s line %d is blank where the index said an event was", r.name,
			r.ordinal+1)
	}
	var e telemetry.Event
	if uerr := json.Unmarshal(text, &e); uerr != nil {
		return telemetry.Event{}, fmt.Errorf("%s line %d: %w", r.name,
			r.ordinal+1, uerr)
	}
	r.event = &e
	return e, nil
}

// Scan calls fn for every event that arrived in [from, to), handing it the
// four hot fields — source, class, actor.value and message — plus the
// arrival time and the event's ordinal, without reading or decoding the
// events' lines: a sealed segment answers from its sidecar's dictionary
// columns, and the line is decoded only when fn asks a Row for its Event.
//
// The rows arrive in exactly the order Range produces events — segment by
// segment in arrival order, file order within each — and the arrival window
// is the same one, applied to the same clock. Anything a segment cannot
// answer from its columns — an unsealed tail, a missing, torn, stale or
// unreadable sidecar, a file whose size has moved behind the index's back, a
// section that will not validate — is answered by decoding its lines, and
// the two paths differ in what they parse to produce a row, never in the
// row. That equivalence is what the tests stand on, against the decode of
// every line as the oracle.
//
// The scan runs segment after segment rather than through the reader pool:
// a column row costs an index lookup, and there is nothing in it worth
// overlapping, while the one expensive thing a row can do — Event — is a
// per-row choice the caller makes and a gatherer cannot make for it. The
// trade is measured in the benchmarks; until the columns' margin over a
// decoded scan is a real number on real data, this comment promises only
// what they show.
func (s *Spool) Scan(from, to time.Time, fn func(*Row) error) error {
	if s.open != nil {
		// Flushed as ever: a scan that missed the events written a second
		// ago is a scan that reports the store quieter than it is.
		if err := s.open.Sync(); err != nil {
			return err
		}
	}
	for _, seg := range s.Segments() {
		if !to.IsZero() && !seg.First.Before(to) {
			continue
		}
		if !from.IsZero() && seg.Last.Before(from) {
			continue
		}
		if err := s.scanSegment(seg, from, to, fn); err != nil {
			return err
		}
	}
	return nil
}

// scanSegment is one segment's contribution to a Scan: the dictionary
// columns where they can be consulted, the decoded read everywhere else.
// Which of the two runs is settled before the first row, so a segment never
// answers half from its columns and half from its lines.
func (s *Spool) scanSegment(seg Segment, from, to time.Time,
	fn func(*Row) error) error {

	f, err := os.Open(filepath.Join(s.dir, seg.Name))
	if os.IsNotExist(err) {
		return missingSegment(seg.Name)
	}
	if err != nil {
		return err
	}
	defer f.Close()

	decode := func() error {
		return scanDecoded(f, seg, from, to, fn)
	}
	// The columns may only be consulted over bytes the seal digested: a
	// file whose size has moved is not the one the ordinals describe, and
	// the decoded read answers from what is there, as ever.
	if !seg.Sealed() {
		return decode()
	}
	if st, serr := f.Stat(); serr != nil || st.Size() != seg.Bytes {
		return decode()
	}
	sc := s.sidecarOf(seg)
	if sc == nil {
		return decode()
	}
	defer sc.close()
	var cols [postFields]*dictColumn
	for i := range cols {
		c, lerr := sc.loadDict(i)
		if lerr != nil {
			return decode()
		}
		cols[i] = c
	}
	return scanColumns(f, sc, &cols, seg, from, to, fn)
}

// scanColumns is a segment's rows out of its dictionary columns: the times
// column streamed a buffer at a time, the four values one index lookup each,
// and the line left on disk unless the consumer asks a row for its Event.
func scanColumns(f *os.File, sc *sidecar, cols *[postFields]*dictColumn,
	seg Segment, from, to time.Time, fn func(*Row) error) error {

	// A sorted times column lets the window's lower bound be seeked, exactly
	// as eachFrom seeks: everything below the first event at or after from
	// is a row the window would have dropped without a second glance. An
	// unsorted column cannot say that, and the per-row check keeps it
	// honest instead.
	start := 0
	if sc.sorted && !from.IsZero() {
		_, idx, ok := sc.firstAtOrAfter(from)
		if !ok {
			// Every arrival in this segment precedes the window; the
			// decoded read would have yielded no row either.
			return nil
		}
		start = idx
	}
	var lo, hi int64
	hasLo, hasHi := !from.IsZero(), !to.IsZero()
	if hasLo {
		lo = from.UnixNano()
	}
	if hasHi {
		hi = to.UnixNano()
	}

	ms := newMarkStream(sc, start)
	var row Row
	row.name = seg.Name
	row.buf = &lineBuf{f: f}
	for i := start; i < int(sc.events); i++ {
		m, err := ms.next()
		if err != nil {
			return err
		}
		if (hasLo && m.at < lo) || (hasHi && m.at >= hi) {
			continue
		}
		row.ordinal = i
		row.received = time.Unix(0, m.at)
		row.off = int64(m.offset)
		row.event = nil
		row.source = cols[0].vals[cols[0].ords[i]]
		row.class = cols[1].vals[cols[1].ords[i]]
		if v, ok := cols[2].valueAt(i); ok {
			row.actor, row.hasActor = v, true
		} else {
			row.actor, row.hasActor = "", false
		}
		row.message = cols[3].vals[cols[3].ords[i]]
		if err := fn(&row); err != nil {
			return err
		}
	}
	return nil
}

// scanDecoded is the scan a segment answers with when its columns cannot be
// consulted: every line parsed, the same four values taken off the decoded
// event, and Event already holding the event. It yields, by construction,
// the same rows the columns do — which is the whole equivalence the tests
// stand on.
func scanDecoded(f *os.File, seg Segment, from, to time.Time,
	fn func(*Row) error) error {

	n := 0
	var row Row
	row.name = seg.Name
	row.buf = &lineBuf{f: f}
	row.off = -1
	return scanEvents(f, seg.Name, 1, func(e telemetry.Event) error {
		i := n
		n++
		if !withinArrival(e, from, to) {
			return nil
		}
		row.source = e.Source
		row.class = fmt.Sprint(uint32(e.Class))
		row.hasActor = !e.Actor.Zero()
		row.actor = e.Actor.Value
		row.message = e.Message
		row.received = e.Received
		row.ordinal = i
		row.event = &e
		return fn(&row)
	})
}
