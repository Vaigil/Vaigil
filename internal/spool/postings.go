// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

// The inverted index: whole-value postings over the fields equality-heavy
// consumers filter on.
//
// A bloom says maybe. That is the right answer for a hunt deciding whether to
// open a segment at all, and it stays what CouldHold gives its callers. But
// the questions that dominate once a segment is open are equalities with a
// known answer: a rule's "message equals PutAccountPublicAccessBlock", a
// hunt narrowed by "actor.value is dana", a scan for one source. For those,
// this file keeps an exact structure per sealed segment: a sorted dictionary
// of folded values, and for each value the sorted ordinals of the events
// that carry it — ordinals being indexes into the times column, so the line
// offset of any posting is one eight-byte read away.
//
// Exactness comes from the fold, not from luck. bloomKey maps every rune to
// the smallest rune in its case-folding orbit, and two strings fold alike
// exactly when a detection's equals calls them equal — EqualFold compares
// runes by orbit membership, orbits are disjoint, so fold equality and
// EqualFold are the same predicate. There is no hashing of keys into buckets
// anywhere in the section: the dictionary holds the folded values
// themselves, compared bytewise, so a value present in the segment is
// present in the dictionary and a value absent is absent. A lookup therefore
// has no false positives to tolerate and no false negatives to fear; the
// only imprecision left is a stale or corrupt file, and the header's
// digest-and-size binding is what rules that out the same way it rules out a
// stale bloom.
//
// # Layout
//
// One section per field, laid out in the order of postFieldNames after the
// blooms, addressed end to end by arithmetic from the header:
//
//	key table    (n+1) × u32   offsets into the key blob, ascending; the
//	                           last entry is the blob's length
//	run table    (n+1) × u64   offsets into the runs blob, one per key in
//	                           dictionary order; the last is the length
//	key blob     the folded values, concatenated, sorted bytewise
//	runs blob    per key, the event ordinals as a first uvarint then
//	                           uvarint deltas — ascending, so each delta is
//	                           at least one and a run of neighbours costs a
//	                           byte a posting
//
// Nothing is loaded until an equality asks: a lookup binary-searches the key
// table through ReadAt — a dozen small reads against the page cache — and a
// seek never touches a dictionary at all.
//
// # Consumers, and the one deliberate non-consumer
//
// RangeWhereEqual is the read path (see spool.go): segments whose dictionary
// refuses the value are skipped whole, and segments it admits are read at
// just their postings' offsets, in file order, so the gatherer's ordering
// guarantee is untouched. Every event the jump produces is re-checked
// against the equality before it is handed over — the index decides what to
// parse, never what the answer is — so a section corrupt into plausible
// offsets can only cost reads, not events, in the inclusion direction.
//
// The detect run is not wired to this index, on purpose. Its fused pass
// walks one arrival window shared by rules, correlations and indicator
// matching; a segment may be skipped only if no consumer could match any
// event in it, and with predicate trees over every field beside contains,
// prefix and regex comparisons, no single equality dominates that union.
// Per-rule jumping inside the pass would mean evaluating rules against a
// scattered subset of each segment — exactly the complication the fused scan
// exists to avoid — so detection keeps the linear pass and the hunts, where
// one equality is the whole question, take the jump.
package spool

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/aertun/aertun/internal/telemetry"
)

// marshalPostings writes one field's section from its value→ordinals map:
// the two offset tables with sentinels, the sorted key blob, the delta-coded
// runs. keys and runs are the blob lengths the header carries, returned
// rather than recomputed so the file can never disagree with itself. sorted
// is the key blob's entries in dictionary order, returned so the dictionary
// columns — whose entries name their postings key's position — can be built
// against the very order this section wrote, without either guessing at the
// other's.
func marshalPostings(values map[string][]int) (section []byte, keys,
	runs int64, sorted []string) {

	sorted = make([]string, 0, len(values))
	for k := range values {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	n := len(sorted)
	keyTable := make([]byte, 4*(n+1))
	runTable := make([]byte, 8*(n+1))
	var keyBlob, runBlob []byte
	for i, k := range sorted {
		binary.LittleEndian.PutUint32(keyTable[4*i:], uint32(len(keyBlob)))
		keyBlob = append(keyBlob, k...)
		binary.LittleEndian.PutUint64(runTable[8*i:], uint64(len(runBlob)))
		prev := -1
		for _, ord := range values[k] {
			if prev < 0 {
				runBlob = binary.AppendUvarint(runBlob, uint64(ord))
			} else {
				// Ordinals arrive in file order, so every delta is at least
				// one and most are one: a value carried by consecutive
				// events costs a byte per posting.
				runBlob = binary.AppendUvarint(runBlob, uint64(ord-prev))
			}
			prev = ord
		}
	}
	binary.LittleEndian.PutUint32(keyTable[4*n:], uint32(len(keyBlob)))
	binary.LittleEndian.PutUint64(runTable[8*n:], uint64(len(runBlob)))

	buf := bytes.NewBuffer(make([]byte, 0,
		4*(n+1)+8*(n+1)+len(keyBlob)+len(runBlob)))
	buf.Write(keyTable)
	buf.Write(runTable)
	buf.Write(keyBlob)
	buf.Write(runBlob)
	return buf.Bytes(), int64(len(keyBlob)), int64(len(runBlob)), sorted
}

// postingsCol addresses one field's postings section inside an open sidecar.
// It holds nothing but geometry; every read goes through the sidecar's
// ReaderAt, so a column costs nothing until it is asked a question.
type postingsCol struct {
	sc   *sidecar
	i    int // the section index, for the header's blob lengths
	n    int
	base int64
}

// postingsOf returns field's column, or nil for a field the inverted index
// does not cover — the caller treats that as "cannot answer", never as
// "definitely not".
func (sc *sidecar) postingsOf(field string) *postingsCol {
	i := postColumn(field)
	if i < 0 {
		return nil
	}
	return &postingsCol{sc: sc, i: i, n: int(sc.pn[i]), base: sc.postingsBase(i)}
}

// keyBlobAt is the file offset of the key blob inside the section.
func (c *postingsCol) keyBlobAt() int64 {
	return c.base + 4*int64(c.n+1) + 8*int64(c.n+1)
}

// runBlobAt is the file offset of the runs blob inside the section.
func (c *postingsCol) runBlobAt() int64 {
	return c.keyBlobAt() + int64(c.sc.pk[c.i])
}

// keyAt reads dictionary entry i's key, via its u32 offsets in the key
// table. Offsets out of the blob are a corrupt section and an error, which
// the callers treat as "cannot answer" — never as an answer.
func (c *postingsCol) keyAt(i int) (string, error) {
	var lo, hi [4]byte
	if _, err := c.sc.r.ReadAt(lo[:], c.base+4*int64(i)); err != nil {
		return "", err
	}
	if _, err := c.sc.r.ReadAt(hi[:], c.base+4*int64(i+1)); err != nil {
		return "", err
	}
	from, to := int64(binary.LittleEndian.Uint32(lo[:])),
		int64(binary.LittleEndian.Uint32(hi[:]))
	if to < from || to > int64(c.sc.pk[c.i]) {
		return "", fmt.Errorf("a key offset outside the key blob")
	}
	if to == from {
		return "", nil
	}
	b := make([]byte, to-from)
	if _, err := c.sc.r.ReadAt(b, c.keyBlobAt()+from); err != nil {
		return "", err
	}
	return string(b), nil
}

// run returns the byte range of key's ordinal run in the runs blob. ok is
// false when the dictionary does not hold the key — the exact, final answer
// that a value absent from the index is absent from the segment. err is
// reserved for a section that cannot be read at all, which is not an answer
// of any kind.
func (c *postingsCol) run(key string) (from, to int64, ok bool, err error) {
	// An empty dictionary is an exact answer too: nothing in the segment
	// carried the field, so no equality on it can hold. The same shortcut
	// the blooms take for free.
	if c.n == 0 {
		return 0, 0, false, nil
	}
	lo, hi := 0, c.n
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		k, kerr := c.keyAt(mid)
		if kerr != nil {
			return 0, 0, false, kerr
		}
		switch bytes.Compare([]byte(k), []byte(key)) {
		case 0:
			var a, b [8]byte
			rt := c.base + 4*int64(c.n+1)
			if _, rerr := c.sc.r.ReadAt(a[:], rt+8*int64(mid)); rerr != nil {
				return 0, 0, false, rerr
			}
			if _, rerr := c.sc.r.ReadAt(b[:], rt+8*int64(mid+1)); rerr != nil {
				return 0, 0, false, rerr
			}
			from, to = int64(binary.LittleEndian.Uint64(a[:])),
				int64(binary.LittleEndian.Uint64(b[:]))
			if from < 0 || to < from || to > int64(c.sc.pp[c.i]) {
				return 0, 0, false,
					fmt.Errorf("a run offset outside the runs blob")
			}
			return from, to, true, nil
		case -1:
			lo = mid + 1
		default:
			hi = mid
		}
	}
	return 0, 0, false, nil
}

// ordinals decodes one delta-coded run into its event ordinals. Anything
// that does not decode into strictly ascending ordinals below the segment's
// event count is a corrupt run and an error: the caller gives up on the
// section and reads the segment linearly rather than trust one posting it
// could not check.
func (c *postingsCol) ordinals(from, to int64) ([]int, error) {
	if to == from {
		return nil, nil
	}
	buf := make([]byte, to-from)
	if _, err := c.sc.r.ReadAt(buf, c.runBlobAt()+from); err != nil {
		return nil, err
	}
	var out []int
	prev := -1
	for len(buf) > 0 {
		v, n := binary.Uvarint(buf)
		if n <= 0 {
			return nil, fmt.Errorf("a postings run that is not varint")
		}
		buf = buf[n:]
		ord := int(v)
		if prev >= 0 {
			// A delta, added to the ordinal before it. Zero deltas and
			// non-positive steps are corrupt, not merely useless: a run
			// describes distinct events in file order.
			if v == 0 {
				return nil, fmt.Errorf("a postings run repeats an event")
			}
			ord = prev + int(v)
		}
		if ord <= prev || ord >= int(c.sc.events) {
			return nil, fmt.Errorf("a postings run leaves the segment")
		}
		out = append(out, ord)
		prev = ord
	}
	return out, nil
}

// equalField is the equality a detection's equals makes of one event,
// answered without building the whole field map for the four fields the
// index covers — the values are the very ones Fields would produce, so the
// jump path and the predicate path cannot disagree. Any other field falls
// back to Fields itself, which is exact for everything and fast for none.
func equalField(e telemetry.Event, field, want string) bool {
	var got string
	switch field {
	case "source":
		got = e.Source
	case "class":
		got = fmt.Sprint(uint32(e.Class))
	case "message":
		got = e.Message
	case "actor.value":
		// Fields holds actor.value only when an actor exists at all; an
		// actor-less event must refuse the equality the same way.
		if e.Actor.Zero() {
			return false
		}
		got = e.Actor.Value
	default:
		v, present := e.Fields()[field]
		if !present {
			return false
		}
		got = v
	}
	return strings.EqualFold(got, want)
}

// lineAt reads the \n-terminated line that starts at off, at most MaxLine
// bytes of it. The offset came from the times column of a sidecar bound to
// this file's digest and size, so it is a line start; the cap is kept anyway
// because every reader of telemetry keeps it, and a tampered segment must
// not turn an indexed read into an unbounded allocation.
func lineAt(f *os.File, off int64) ([]byte, error) {
	var out []byte
	chunk := make([]byte, 64<<10)
	for {
		n, err := f.ReadAt(chunk, off+int64(len(out)))
		if n == 0 {
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			// EOF without a newline: the last line of a file whose final
			// byte was not \n. The builder consumed the same bytes.
			return out, nil
		}
		if i := bytes.IndexByte(chunk[:n], '\n'); i >= 0 {
			return append(out, chunk[:i]...), nil
		}
		out = append(out, chunk[:n]...)
		if len(out) > MaxLine {
			return nil, fmt.Errorf("a line over the %d-byte limit", MaxLine)
		}
	}
}
