// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

// Per-segment sidecar indexes: the read accelerator over immutable bytes.
//
// A sealed segment never changes again — that is what sealing means — so
// everything worth knowing about its contents can be computed once, at seal
// time, and kept beside it. Four things are kept:
//
//   - a column of (line offset, arrival time) pairs, one per event, in file
//     order, so a read by arrival can binary-search for the first event in
//     its window and start there instead of parsing every line before it;
//   - a bloom filter over each of three single-valued fields — source, class
//     and actor.value — so a hunt with an equality on one of them can be told
//     "definitely not in this segment" and skip the read entirely;
//   - an inverted index — postings of sorted event ordinals per whole folded
//     value — over those same three fields plus message, so an equality can
//     be answered exactly: a value absent from the dictionary is absent from
//     the segment, and a value present says which events carry it, by
//     ordinal into the times column. See postings.go for that section.
//   - a dictionary column for each of those four fields — the distinct
//     original values, sorted by folded key, plus one dictionary ordinal per
//     event — so a scan that only wants to know what an event's source,
//     class, actor.value or message says can read the ordinals and the
//     dictionaries instead of decoding every line. See columns.go for those
//     sections and the scan they serve.
//
// The index is derived data, never authoritative. It is validated against the
// segment's seal digest on every use, rebuilt when missing or stale, and a
// store whose sidecars are all deleted answers exactly as it did before —
// only slower. That is the property every part of this file is arranged
// around: an index that could change an answer is not an index, it is a
// second copy of the data with its own bugs.
//
// One known wart, left rather than half-fixed: retention deletes segments by
// name and does not know about sidecars, so a dropped segment's index
// outlives it. The orphan is never read (lookups go through the segment
// index) and is overwritten if the day-and-counter name is ever reused,
// because a reused name gets a fresh sidecar at seal time before any reader
// can consult the old one. It is disk litter, not a correctness question;
// reclaiming it belongs to the retention file, where deletion lives.
package spool

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/aeroprove/aeroprove/internal/atomicfile"
	"github.com/aeroprove/aeroprove/internal/telemetry"
)

// sidecarMagic identifies the format. A version bump means "rebuild
// everything", which is exactly what a reader does with bytes it does not
// understand, so one version number is all the format ever carries. vspool2
// added the postings section; vspool3 added the dictionary columns; a file
// of any older magic parses as nothing at all and is rebuilt with both.
const sidecarMagic = "vspool3\n"

// SidecarExt is appended to a segment's name for its index.
const SidecarExt = ".idx"

// The bloom filters. Fixed 64 KiB per field rather than sized to the data:
// a segment is capped by DefaultSegmentBytes, a filter that had to grow with
// its keys would need its own retention, and the fixed size bounds the worst
// case (a filter per field per segment, forever) to something a store can be
// planned around.
//
// False positives, stated rather than waved at: with m bits, n distinct keys
// and k = ln2·m/n hashes, the rate is about 0.6185^(m/n). This filter has
// m = 524,288 bits, so at 32,768 distinct values — two bytes per key, the
// density this is designed around — it is about 0.05%; at 100,000 it is
// about 5%. A false positive costs a read that was not needed. A false
// negative would cost a detection, and cannot happen: everything inserted is
// hashed from the same folded key the probe hashes.
const (
	bloomLen  = 64 << 10
	bloomBits = bloomLen * 8
	// maxBloomHashes caps k for tiny key sets, where the optimum exceeds
	// anything worth computing per probe.
	maxBloomHashes = 30
)

// sidecarFields are the fields the blooms cover, in column order. Exactly the
// ones Fields always holds zero or one of: source, class and actor.value are
// single-valued in every event, so an equality over the whole value is a
// question a bloom over the whole values answers. A field like ip, which
// Fields joins from several observables, is not here, because "equals" over
// a joined value is not a question the parts can answer.
var sidecarFields = [3]string{"source", "class", "actor.value"}

func sidecarColumn(field string) int {
	for i, f := range sidecarFields {
		if f == field {
			return i
		}
	}
	return -1
}

// postFieldNames are the fields the inverted index covers, in section order:
// the three the blooms already answer "definitely not" for, plus message —
// which a bloom was never built over because free text can hold a distinct
// value per event and a fixed-size filter over a near-unique key set answers
// nothing. Postings are the structure that admits message honestly: the
// dictionary grows with the data it describes, and an equality over a whole
// action name — what a rule's "message equals PutAccountPublicAccessBlock"
// asks — is exactly the question whole-value postings answer.
//
// What is deliberately not here: anything under raw.*. The raw map is open
// vocabulary — a source may name a key once and never again — so a postings
// dictionary over its values has no shape anybody can plan a store around,
// and the master report's own caution about unbounded keys applies. An
// equality on raw.* keeps the linear read; when some key proves itself a
// stable closed vocabulary in the field, it can be promoted into this list
// and every sealed segment from then on carries postings for it, because
// old sidecars simply rebuild.
const postFields = 4

var postFieldNames = [postFields]string{
	"source", "class", "actor.value", "message"}

// postColumn is a field's section number, or -1 for a field the inverted
// index does not cover.
func postColumn(field string) int {
	for i, f := range postFieldNames {
		if f == field {
			return i
		}
	}
	return -1
}

// mark is one event's place in the segment: where its line starts, and when
// it arrived. Arrival and not event time, because the column serves Range,
// and Range is the query the store is ordered by — see the package comment
// for why that ordering is the whole design.
type mark struct {
	offset uint64
	at     int64
}

// sidecar is a validated sidecar header over the index's bytes. The times
// column, the blooms and the postings are read through r on demand, so a
// seek never loads a bloom, a bloom probe never loads a column, and neither
// loads a dictionary until an equality asks for one.
type sidecar struct {
	r      io.ReaderAt
	closer io.Closer
	digest string
	events uint64
	// bytes is the segment size the index was built against; a segment that
	// is not this size is not the one this index describes.
	bytes  uint64
	sorted bool
	n      [3]uint64
	// The postings section, per field: the count of distinct folded values,
	// the bytes of the key blob and the bytes of the ordinal runs. The
	// section's own tables are addressed by arithmetic from these.
	pn [postFields]uint64
	pk [postFields]uint64
	pp [postFields]uint64
	// The dictionary columns, per field: the count of distinct original
	// values and the bytes of the value blob. The ordinal column's length
	// needs no descriptor of its own — it is one ordinal per event at a width
	// the count decides.
	dn [postFields]uint64
	dk [postFields]uint64
}

// sidecarHeaderLen is everything before the times column. Fixed, so every
// column and section is addressed by arithmetic instead of by a footer.
const sidecarHeaderLen = len(sidecarMagic) + 64 + 8 + 8 + 1 + 24 +
	3*8*postFields + 2*8*postFields

// sidecarPostingsAt is the file offset the postings sections start at: the
// end of the third bloom.
func sidecarPostingsAt(events uint64) int64 {
	return sidecarOffsetOf(0) + 16*int64(events) + 3*bloomLen
}

// sectionLen is field i's whole postings section: two offset tables with a
// sentinel entry each, the key blob and the runs blob.
func (sc *sidecar) sectionLen(i int) int64 {
	entries := int64(sc.pn[i]) + 1
	return 4*entries + 8*entries + int64(sc.pk[i]) + int64(sc.pp[i])
}

// postingsBase is field i's section start, by summation over the fields
// before it.
func (sc *sidecar) postingsBase(i int) int64 {
	at := sidecarPostingsAt(sc.events)
	for j := 0; j < i; j++ {
		at += sc.sectionLen(j)
	}
	return at
}

// dictLen is field i's whole dictionary section: the offset table with its
// sentinel entry, the value blob, one postings position per entry, and one
// ordinal per event at the width the dictionary's own size decides. See
// columns.go for what the section says and how it is checked on the way in.
func (sc *sidecar) dictLen(i int) int64 {
	return 4*int64(sc.dn[i]+1) + int64(sc.dk[i]) + 4*int64(sc.dn[i]) +
		int64(sc.events)*int64(dictWidth(int(sc.dn[i]), dictAbsent(i)))
}

// dictBase is field i's dictionary section start: the end of the last
// postings section — which postingsBase(postFields) already is — plus every
// dictionary section before i's.
func (sc *sidecar) dictBase(i int) int64 {
	at := sc.postingsBase(postFields)
	for j := 0; j < i; j++ {
		at += sc.dictLen(j)
	}
	return at
}

// fileEnd is the whole file this header describes. A sidecar shorter than
// this is a torn write and reads as absent.
func (sc *sidecar) fileEnd() int64 {
	return sc.dictBase(postFields)
}

// sidecarOffsetOf is the file offset of column entry i.
func sidecarOffsetOf(i int) int64 {
	return int64(sidecarHeaderLen + 16*i)
}

// sidecarPath is where a segment's index lives.
func (s *Spool) sidecarPath(seg Segment) string {
	return filepath.Join(s.dir, seg.Name+SidecarExt)
}

// sidecarOf returns a validated sidecar for a sealed segment, or nil when
// there is none usable — which the callers treat as "read linearly", never as
// an error. A missing, stale, corrupt or unbuildable index costs speed and
// nothing else.
//
// Stale means the header disagrees with the segment index about the
// segment's digest or size, which covers every way a sidecar can stop
// describing its segment: the segment was rewritten, or its name was reused
// after retention dropped the original. When that happens the index is
// rebuilt from the bytes on disk now and the rebuild is persisted beside
// them, best effort — a store mounted read-only gets the in-memory rebuild
// and keeps answering.
func (s *Spool) sidecarOf(seg Segment) *sidecar {
	if !seg.Sealed() {
		return nil
	}
	if sc := openSidecar(s.sidecarPath(seg), seg); sc != nil {
		return sc
	}
	// Rebuild. Deterministic over the same bytes, so two readers racing both
	// write the same file and atomicfile's rename keeps readers whole.
	b, err := buildSidecar(filepath.Join(s.dir, seg.Name), seg)
	if err != nil {
		return nil
	}
	sc := parseSidecarHeader(b)
	if sc == nil {
		return nil
	}
	sc.r = bytes.NewReader(b)
	// A failure to persist is not a failure to use: the index is derived,
	// and the next reader tries the same write.
	_ = atomicfile.Write(s.sidecarPath(seg), b, 0o600)
	return sc
}

// openSidecar opens a persisted index and validates its header against the
// segment it claims to describe. A too-short file is a torn write and reads
// as absent.
func openSidecar(path string, seg Segment) *sidecar {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	hdr := make([]byte, sidecarHeaderLen)
	if _, err := io.ReadFull(f, hdr); err != nil {
		f.Close()
		return nil
	}
	sc := parseSidecarHeader(hdr)
	if sc == nil || sc.digest != seg.Digest || sc.bytes != uint64(seg.Bytes) {
		f.Close()
		return nil
	}
	if st, serr := f.Stat(); serr != nil || st.Size() < sc.fileEnd() {
		f.Close()
		return nil
	}
	sc.r, sc.closer = f, f
	return sc
}

// parseSidecarHeader reads a header, or returns nil for bytes that are not a
// sidecar this build understands.
func parseSidecarHeader(b []byte) *sidecar {
	if len(b) < sidecarHeaderLen ||
		string(b[:len(sidecarMagic)]) != sidecarMagic {
		return nil
	}
	sc := &sidecar{}
	p := len(sidecarMagic)
	sc.digest = string(b[p : p+64])
	p += 64
	sc.events = binary.LittleEndian.Uint64(b[p:])
	p += 8
	sc.bytes = binary.LittleEndian.Uint64(b[p:])
	p += 8
	sc.sorted = b[p] == 1
	p++
	for i := range sc.n {
		sc.n[i] = binary.LittleEndian.Uint64(b[p:])
		p += 8
	}
	for i := range sc.pn {
		sc.pn[i] = binary.LittleEndian.Uint64(b[p:])
		p += 8
	}
	for i := range sc.pk {
		sc.pk[i] = binary.LittleEndian.Uint64(b[p:])
		p += 8
	}
	for i := range sc.pp {
		sc.pp[i] = binary.LittleEndian.Uint64(b[p:])
		p += 8
	}
	for i := range sc.dn {
		sc.dn[i] = binary.LittleEndian.Uint64(b[p:])
		p += 8
	}
	for i := range sc.dk {
		sc.dk[i] = binary.LittleEndian.Uint64(b[p:])
		p += 8
	}
	return sc
}

// firstAtOrAfter binary-searches the times column for the first event that
// arrived at or after t, returning its line offset and its index in the
// column. ok is false when every event in the segment arrived before t, in
// which case there is nothing to read here at all.
//
// Only meaningful when sorted: the column is in file order, and a binary
// search over file order answers "first at or after" only when arrival never
// goes backwards down the file. Sortedness is measured when the index is
// built; a writer that handed the spool out-of-order arrivals gets a column
// marked unsorted and a reader that scans, because a seek that skipped a
// late arrival would be fast and wrong.
func (sc *sidecar) firstAtOrAfter(t time.Time) (offset uint64, index int, ok bool) {
	want := t.UnixNano()
	lo, hi := 0, int(sc.events)
	var buf [16]byte
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if _, err := sc.r.ReadAt(buf[:], sidecarOffsetOf(mid)); err != nil {
			return 0, 0, false
		}
		if int64(binary.LittleEndian.Uint64(buf[8:])) < want {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo >= int(sc.events) {
		return 0, 0, false
	}
	if _, err := sc.r.ReadAt(buf[:], sidecarOffsetOf(lo)); err != nil {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint64(buf[:]), lo, true
}

// mightHold reports whether the segment may hold an event whose field is
// value, as an equality over the whole value. False is definitive; true may
// be a false positive, and costs a read.
func (sc *sidecar) mightHold(field, value string) bool {
	col := sidecarColumn(field)
	if col < 0 {
		return true
	}
	if sc.n[col] == 0 {
		// Nothing in this segment carried the field at all, so no event's
		// equality on it can hold. The one answer an empty filter gives for
		// free, and the reason n is kept per column.
		return false
	}
	buf := make([]byte, bloomLen)
	at := sidecarOffsetOf(0) + 16*int64(sc.events) + int64(col*bloomLen)
	if _, err := sc.r.ReadAt(buf, at); err != nil {
		return true
	}
	return bloomOf(buf, int64(sc.n[col])).might(bloomKey(value))
}

// CouldHold says whether a segment may hold an event whose field equals
// value. False means definitely not, and lets a caller skip reading the
// segment; true means maybe, and the read decides.
//
// Definitive only for a sealed segment, only for source, class and
// actor.value — the single-valued fields the blooms were built over — and
// only under the case-insensitive equality a detection's "equals" makes
// (see bloomKey for how that is kept exact). Anything else, including every
// failure to load or rebuild an index, answers true: a filter that could not
// be read is one that may hold anything.
func (s *Spool) CouldHold(seg Segment, field, value string) bool {
	if sidecarColumn(field) < 0 || !seg.Sealed() {
		return true
	}
	sc := s.sidecarOf(seg)
	if sc == nil {
		return true
	}
	defer sc.close()
	return sc.mightHold(field, value)
}

func (sc *sidecar) close() {
	if sc.closer != nil {
		_ = sc.closer.Close()
	}
}

// buildSidecar derives a segment's index from its bytes and returns the
// marshalled sidecar. The digest in the header is the segment index's, which
// is what makes a stale sidecar detectable later.
//
// One pass, and a bounded one: lines are read with a cap of MaxLine, as
// everywhere else that reads telemetry, so a tampered segment cannot turn an
// index rebuild into an unbounded allocation. A line that will not parse
// refuses the build — the reader falls back to the linear scan, which
// reports the bad line the way it always did.
func buildSidecar(path string, seg Segment) ([]byte, error) {
	if len(seg.Digest) != 64 {
		return nil, fmt.Errorf("%s has no seal digest to bind an index to",
			seg.Name)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64<<10)

	var marks []mark
	var sets [3]map[string]bool
	for i := range sets {
		sets[i] = map[string]bool{}
	}
	// The inverted index: per field, each folded value's event ordinals, in
	// the order the events appear in the file. Built in the same pass and
	// from the same fold as the blooms, so the two never disagree.
	var posts [postFields]map[string][]int
	for i := range posts {
		posts[i] = map[string][]int{}
	}
	// The dictionary columns: per field, the distinct ORIGINAL values the
	// events carry — folded nowhere, because a column's job is to answer
	// what the line answers and the line says "Okta/System", not the folded
	// key an equality would compare. Sorted by folded key when the section
	// is marshalled, so the fold still disciplines the order.
	var dicts [postFields]*dictBuild
	for i := range dicts {
		dicts[i] = newDictBuild()
	}
	sorted := true
	var off uint64
	for {
		line, consumed, rerr := readCappedLine(r)
		if consumed == 0 && rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return nil, rerr
		}
		start := off
		off += uint64(consumed)
		if text := strings.TrimSpace(string(line)); text != "" {
			var e telemetry.Event
			if uerr := json.Unmarshal([]byte(text), &e); uerr != nil {
				return nil, fmt.Errorf("%s: %w", seg.Name, uerr)
			}
			at := e.Received.UnixNano()
			if n := len(marks); n > 0 && marks[n-1].at > at {
				sorted = false
			}
			ord := len(marks)
			marks = append(marks, mark{offset: start, at: at})
			// The same three values Fields holds one of, folded the same
			// way the probe folds. Mirroring Fields is the whole contract:
			// a bloom over values Fields would not produce would answer
			// questions nobody asked.
			sets[0][bloomKey(e.Source)] = true
			sets[1][bloomKey(fmt.Sprint(uint32(e.Class)))] = true
			if !e.Actor.Zero() {
				sets[2][bloomKey(e.Actor.Value)] = true
			}
			// And the same four values the postings answer for, folded the
			// same way. message is always in Fields — an event with no
			// message carries the empty string there — so the empty key is
			// an honest dictionary entry, not a hole a query could fall
			// through. actor.value is only in Fields when an actor is, so
			// its postings skip actor-less events exactly as Match.eval
			// refuses them.
			src := bloomKey(e.Source)
			posts[0][src] = append(posts[0][src], ord)
			cls := bloomKey(fmt.Sprint(uint32(e.Class)))
			posts[1][cls] = append(posts[1][cls], ord)
			if !e.Actor.Zero() {
				k := bloomKey(e.Actor.Value)
				posts[2][k] = append(posts[2][k], ord)
			}
			msg := bloomKey(e.Message)
			posts[3][msg] = append(posts[3][msg], ord)
			// And the same four values the dictionary columns carry, spelled
			// as the line spells them. actor.value's column skips actor-less
			// events exactly as its postings do, with an ordinal of its own
			// that says "no value" rather than a hole a reader could
			// misread.
			dicts[0].add(e.Source)
			dicts[1].add(fmt.Sprint(uint32(e.Class)))
			dicts[2].addIf(!e.Actor.Zero(), e.Actor.Value)
			dicts[3].add(e.Message)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return nil, rerr
		}
	}

	// The postings and dictionary sections are marshalled before the header
	// is written, because the header carries their lengths and a reader
	// addresses everything by arithmetic from them. The dictionary sections
	// are marshalled against the postings' own sorted keys, so an entry's
	// postings position is the position this build wrote, not a number
	// re-derived at read time.
	sections := make([][]byte, postFields)
	sortedKeys := make([][]string, postFields)
	var pk, pp [postFields]int64
	size := sidecarPostingsAt(uint64(len(marks)))
	for i := range posts {
		sections[i], pk[i], pp[i], sortedKeys[i] = marshalPostings(posts[i])
		size += int64(len(sections[i]))
	}
	dsections := make([][]byte, postFields)
	var dkeys [postFields]int64
	for i := range dicts {
		var derr error
		dsections[i], dkeys[i], derr = marshalDict(dicts[i], dictAbsent(i),
			sortedKeys[i])
		if derr != nil {
			return nil, derr
		}
		size += int64(len(dsections[i]))
	}

	buf := bytes.NewBuffer(make([]byte, 0, size))
	buf.WriteString(sidecarMagic)
	buf.WriteString(seg.Digest)
	var tmp [8]byte
	put := func(v uint64) {
		binary.LittleEndian.PutUint64(tmp[:], v)
		buf.Write(tmp[:])
	}
	put(uint64(len(marks)))
	put(uint64(seg.Bytes))
	if sorted {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	for i := range sets {
		put(uint64(len(sets[i])))
	}
	// The postings descriptors, as three contiguous arrays in the order the
	// reader reads them: counts, key-blob lengths, run-blob lengths.
	for i := range sections {
		put(uint64(len(posts[i]))) // distinct folded values
	}
	for i := range sections {
		put(uint64(pk[i])) // key blob bytes
	}
	for i := range sections {
		put(uint64(pp[i])) // ordinal-run bytes
	}
	// The dictionary descriptors the same way: counts, then value-blob
	// lengths.
	for i := range dsections {
		put(uint64(len(dicts[i].vals))) // distinct original values
	}
	for i := range dsections {
		put(uint64(dkeys[i])) // value blob bytes
	}
	for _, m := range marks {
		put(m.offset)
		put(uint64(m.at))
	}
	for i := range sets {
		b := make([]byte, bloomLen)
		bl := bloomOf(b, int64(len(sets[i])))
		for k := range sets[i] {
			bl.add(k)
		}
		buf.Write(b)
	}
	for i := range sections {
		buf.Write(sections[i])
	}
	for i := range dsections {
		buf.Write(dsections[i])
	}
	return buf.Bytes(), nil
}

// readCappedLine reads one \n-terminated line, at most MaxLine bytes of it,
// returning the line without its newline and how many bytes it consumed.
// The byte count is what the offset column is built from, so it counts the
// delimiter and every byte of an over-long line alike: the offsets have to
// describe the file as it is, not as the writer should have left it.
func readCappedLine(r *bufio.Reader) (line []byte, consumed int, err error) {
	var acc []byte
	for {
		chunk, rerr := r.ReadSlice('\n')
		consumed += len(chunk)
		if rerr == bufio.ErrBufferFull {
			acc = append(acc, chunk...)
			if len(acc) > MaxLine {
				return nil, consumed,
					fmt.Errorf("a line over the %d-byte limit", MaxLine)
			}
			continue
		}
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return nil, consumed, rerr
		}
		if len(acc) == 0 {
			return chunk, consumed, rerr
		}
		acc = append(acc, chunk...)
		return acc, consumed, rerr
	}
}

// bloom is a fixed-size filter over folded keys, double-hashed with FNV-1a.
type bloom struct {
	b []byte
	n int64
}

// bloomOf wraps a buffer sized for n keys. The buffer is the caller's
// because building writes into a fresh one and probing reads a loaded one,
// and both want the same three lines without pretending they share state.
func bloomOf(b []byte, n int64) *bloom { return &bloom{b: b, n: n} }

// bloomHashes is k, the hash count, derived from n exactly as it will be at
// probe time (n travels in the header), so build and probe always agree.
func bloomHashes(n int64) int {
	if n <= 0 {
		return 1
	}
	k := int(math.Round(math.Ln2 * float64(bloomBits) / float64(n)))
	if k < 1 {
		k = 1
	}
	if k > maxBloomHashes {
		k = maxBloomHashes
	}
	return k
}

// fnv1a is FNV-1a with a seedable offset basis, so the second hash of the
// double hash is the same function over the same key with a different
// beginning rather than a second algorithm to maintain.
func fnv1a(s string, seed uint64) uint64 {
	h := seed
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

const (
	fnvBasis1 = 14695981039346656037
	fnvBasis2 = 14695981039346656037 ^ 0x9e3779b97f4a7c15
)

func (bl *bloom) add(key string) {
	h1 := fnv1a(key, fnvBasis1)
	// Odd, so the double hash walks the whole filter instead of the coset
	// an even stride would visit.
	h2 := fnv1a(key, fnvBasis2) | 1
	for i := 0; i < bloomHashes(bl.n); i++ {
		p := (h1 + uint64(i)*h2) % bloomBits
		bl.b[p/8] |= 1 << (p % 8)
	}
}

func (bl *bloom) might(key string) bool {
	h1 := fnv1a(key, fnvBasis1)
	h2 := fnv1a(key, fnvBasis2) | 1
	for i := 0; i < bloomHashes(bl.n); i++ {
		p := (h1 + uint64(i)*h2) % bloomBits
		if bl.b[p/8]&(1<<(p%8)) == 0 {
			return false
		}
	}
	return true
}

// bloomKey folds a value the way a detection's "equals" compares it: over
// the whole value, case-insensitively.
//
// The fold maps every rune to the smallest rune in its case-folding orbit.
// strings.ToLower is not that fold and would make this filter wrong rather
// than slow: EqualFold says "ſ" and "s" are equal, their lowercases differ,
// and a bloom keyed by lowercases would say "definitely not" about a segment
// that held the one when asked for the other. Orbit-minimal folding makes
// EqualFold(a, b) imply bloomKey(a) == bloomKey(b), which is the direction a
// "definitely not" has to be true in.
func bloomKey(s string) string {
	// No ASCII shortcut: the orbits of "s" and "k" reach past ASCII ("ſ",
	// the Kelvin sign), so even a pure-ASCII value has to walk its orbits.
	// The walk is a few steps per rune and happens three times per event at
	// build and once per hunt probe, which is not where the time goes.
	out := make([]rune, 0, len(s))
	for _, r := range s {
		low := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < low {
				low = f
			}
		}
		out = append(out, low)
	}
	return string(out)
}

// writeSidecar builds and persists a sealed segment's index. Best effort by
// design: the seal has already happened, the digest is already saved, and a
// store whose index could not be written is one whose next reader rebuilds
// it — not one whose events stop being readable.
func (s *Spool) writeSidecar(seg Segment) {
	b, err := buildSidecar(filepath.Join(s.dir, seg.Name), seg)
	if err != nil {
		return
	}
	_ = atomicfile.Write(s.sidecarPath(seg), b, 0o600)
}
