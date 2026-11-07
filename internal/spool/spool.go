// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package spool is where events land before anything reasons about them.
//
// Append-only segments, partitioned by arrival, retained by two limits at
// once, and sealed with a digest cheap enough to compute on volume data.
// Nothing here is a database. A spool answers one question — what arrived
// between these two moments — and the design is entirely about the four ways
// that question is usually answered wrongly.
//
// # Partition by arrival, not by the timestamp in the event
//
// Every event carries two clocks: when the source says it happened, and when
// this program took delivery. Almost every store partitions by the first,
// because that is what an analyst asks about, and it is the wrong choice for
// a security store for a reason that has nothing to do with performance.
//
// The first clock belongs to whoever wrote the event. Set it a week forward
// and the record lands in a partition that has already been swept, indexed
// and reported on; set it a week back and it lands in one that retention has
// already dropped, or is about to. Either way the event is in the store and
// out of every window that would have looked at it — and nothing anywhere
// reports an error, because writing into a past partition is exactly what a
// late event legitimately does.
//
// The second clock is ours. It cannot be moved by the thing being recorded.
// So segments are cut on arrival, and the timestamp in the event is an
// ordinary field a query filters on. Both are kept; only one decides where
// the bytes go.
//
// # Two retention limits, because one is a promise you cannot keep
//
// "Ninety days" on its own is a disk that fills up. Volume is not flat — it
// spikes during exactly the incident whose evidence you needed — so an age
// limit alone means the store stops accepting writes at the worst possible
// moment, or silently starts dropping. A byte cap alone means a quiet month
// keeps two years and a noisy week keeps four days, and nobody can say what
// the store will answer for. Both are set, Oldest() says what the store
// currently covers, and that number is the honest answer to "how far back can
// we look", rather than the configured one. Under both sits a floor — a
// youngest age below which nothing is deleted whatever the cap says — so the
// size limit can narrow retention but never gut it.
//
// # Deleting is never a side effect
//
// Retention is two calls. Plan says what would go and what the store would
// then cover; Apply takes a plan and does it. A store that deletes while
// answering a query is one that deleted evidence during an investigation, and
// the investigation is the moment somebody is most likely to run a query and
// least likely to be watching the log. Holds pin segments against any plan,
// which is the same mechanism a legal hold needs and is worth having before
// anybody asks for one.
//
// # Integrity you can afford
//
// The audit log signs every record with Ed25519 and ML-DSA-65, which is right
// for decisions and unaffordable for a million events a day. Here a sealed
// segment gets one SHA-256 over its bytes. That is cheap enough to be
// unconditional, and anchoring those digests in the audit log — which is
// signed — gives the whole spool tamper-evidence at the cost of one hash per
// segment rather than two signatures per event.
package spool

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/telemetry"
)

// Defaults. Every one of them is a number somebody will want to change, and
// every one is stated here rather than discovered by reading behaviour.
const (
	// DefaultSegmentBytes rolls a segment at 64 MiB. Small enough that a
	// retention delete frees a useful amount, large enough that a busy day is
	// tens of files rather than thousands.
	DefaultSegmentBytes = 64 << 20
	// DefaultKeep is ninety days, which is what most frameworks ask for.
	DefaultKeep = 90 * 24 * time.Hour
	// DefaultCap is 16 GiB of events. Paired with DefaultKeep, never alone.
	DefaultCap = 16 << 30
	// MaxLine bounds one event, as everywhere else that reads telemetry.
	MaxLine = 1 << 20
)

// Options configure a spool.
type Options struct {
	// SegmentBytes is when to roll. A segment also rolls when the arrival day
	// changes, so retention can drop whole files on a day boundary.
	SegmentBytes int64
	// Keep is the age limit and Cap the size limit. Both apply.
	Keep time.Duration
	Cap  int64
	// Floor is the youngest age at which evidence may be deleted at all
	// (NIST SP 800-53 AU-11). It raises Keep when Keep is shorter, and it
	// stops the cap from eating young segments: over cap and inside the
	// floor, the spool stays over cap and says so. Zero means no floor —
	// the pre-floor behaviour, and an honest default rather than a policy,
	// because a floor is a promise an organisation makes on purpose.
	Floor time.Duration
	// Now is the clock, injectable so a test can age a store without
	// sleeping. Nil means time.Now.
	Now func() time.Time
}

func (o Options) withDefaults() Options {
	if o.SegmentBytes <= 0 {
		o.SegmentBytes = DefaultSegmentBytes
	}
	if o.Keep <= 0 {
		o.Keep = DefaultKeep
	}
	if o.Cap <= 0 {
		o.Cap = DefaultCap
	}
	if o.Floor < 0 {
		o.Floor = 0
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	return o
}

// Segment is one append-only file of events.
type Segment struct {
	Name string `json:"name"`
	// First and Last are arrival times, not event times. They are what Range
	// skips files on, and the distinction is the package's whole thesis.
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
	// Earliest and Latest are the event times inside, kept so a query for a
	// period can skip a segment whose contents are entirely outside it
	// without reading it. Advisory: a source with a wrong clock widens these
	// and costs a read, which is the right way round.
	Earliest time.Time `json:"earliest"`
	Latest   time.Time `json:"latest"`

	Events int   `json:"events"`
	Bytes  int64 `json:"bytes"`
	// Digest is SHA-256 over the sealed file. Empty while the segment is
	// still open, because a digest of a file still being appended to is a
	// claim that stops being true a millisecond later.
	Digest string `json:"digest,omitempty"`
}

// Sealed reports whether the segment is closed and digested.
func (s Segment) Sealed() bool { return s.Digest != "" }

// Hold pins segments against retention.
type Hold struct {
	Name  string    `json:"name"`
	By    string    `json:"by"`
	At    time.Time `json:"at"`
	Until time.Time `json:"until"`
	// Why the hold exists. Required: a hold nobody can explain is one nobody
	// will ever dare lift, and a store that can never delete anything fails
	// its retention commitments as surely as one that deletes too early.
	Why string `json:"why"`
}

// Active reports whether a hold still applies.
func (h Hold) Active(now time.Time) bool {
	return h.Until.IsZero() || now.Before(h.Until)
}

// index is the spool's metadata, written atomically beside the segments.
type index struct {
	Segments []Segment `json:"segments"`
	Holds    []Hold    `json:"holds,omitempty"`
	// Late is a histogram of observed arrival delay, in log2 seconds. Kept
	// because the watermark has to be measured rather than configured; see
	// Watermark.
	Late map[int]int64 `json:"late,omitempty"`
	// Ahead counts events whose source clock ran ahead of ours. Counted
	// separately rather than folded into Late as a negative, because a fleet
	// running fast is an operational fact and averaging it into the arrival
	// delay hides both.
	Ahead int64 `json:"ahead,omitempty"`
}

// Spool is an open store.
type Spool struct {
	dir  string
	opt  Options
	idx  index
	open *os.File
	cur  int
}

// Open prepares a spool in dir, creating it if absent.
func Open(dir string, o Options) (*Spool, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("a spool needs a directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Spool{dir: dir, opt: o.withDefaults(), cur: -1}
	b, err := os.ReadFile(filepath.Join(dir, "index.json"))
	switch {
	case os.IsNotExist(err):
	case err != nil:
		return nil, err
	default:
		if uerr := json.Unmarshal(b, &s.idx); uerr != nil {
			return nil, fmt.Errorf("%s/index.json is unreadable: %w", dir, uerr)
		}
	}
	if s.idx.Late == nil {
		s.idx.Late = map[int]int64{}
	}
	return s, nil
}

// lock takes the store for one writer and brings this handle back in step
// with what other writers did while it held nothing.
//
// A spool is opened by processes that share no memory — serve ingesting
// while a command writes — and the segments append, but index.json does not:
// every save writes the whole index, so without this the second save
// discards the first's events, its histogram, or a whole segment entry, and
// nothing reports an error. Taken per operation and never held between
// them, so a reader never waits. The lock is the kernel's (atomicfile.Lock):
// a writer that died released it as it died, so there is no lock file to
// age, no takeover, and no moment two writers both hold it; and a writer
// waiting for it is woken when it is free rather than polling for a gap the
// writer before it keeps closing.
//
// The writes are Append, Seal, Release, Close, and the retention operations
// Hold, Lift and Apply in retention.go: every path that mutates the index
// passes through here, so a save can never be built on a copy of the index
// another writer has already replaced.
func (s *Spool) lock() (func(), error) {
	unlock, err := atomicfile.Lock(filepath.Join(s.dir, "index.json.lock"))
	if err != nil {
		return nil, err
	}
	if err := s.rejoin(); err != nil {
		unlock()
		return nil, err
	}
	return unlock, nil
}

// rejoin reloads the index, which is the truth under the lock, and keeps the
// open segment only while it is still the last one, still unsealed and
// still the size the index says. A segment another writer rolled or sealed
// is not one to hold open: it is let go, and ensure re-decides which segment
// an arrival belongs in against the index as it now stands.
func (s *Spool) rejoin() error {
	var held string
	if s.open != nil && s.cur >= 0 && s.cur < len(s.idx.Segments) {
		held = s.idx.Segments[s.cur].Name
	}
	b, err := os.ReadFile(filepath.Join(s.dir, "index.json"))
	switch {
	case os.IsNotExist(err):
		s.idx = index{}
	case err != nil:
		return err
	default:
		var fresh index
		if uerr := json.Unmarshal(b, &fresh); uerr != nil {
			return fmt.Errorf("%s/index.json is unreadable: %w", s.dir, uerr)
		}
		s.idx = fresh
	}
	if s.idx.Late == nil {
		s.idx.Late = map[int]int64{}
	}
	if s.open == nil {
		return nil
	}
	n := len(s.idx.Segments)
	if held != "" && n > 0 && s.idx.Segments[n-1].Name == held &&
		s.idx.Segments[n-1].Digest == "" {
		if st, serr := os.Stat(filepath.Join(s.dir, held)); serr == nil &&
			st.Size() == s.idx.Segments[n-1].Bytes {
			s.cur = n - 1
			return nil
		}
	}
	if err := s.open.Sync(); err != nil {
		return err
	}
	err = s.open.Close()
	s.open, s.cur = nil, -1
	return err
}

// Append writes one event and returns the segment it landed in.
//
// Received is stamped here when the caller left it zero, because the spool is
// the moment of delivery and nothing upstream is better placed to say so.
func (s *Spool) Append(e telemetry.Event) (string, error) {
	segs, err := s.AppendBatch([]telemetry.Event{e})
	if err != nil {
		return "", err
	}
	return segs[0], nil
}

// AppendBatch writes a batch of events under one lock and returns the
// segment each landed in, in order.
//
// Every event pays for the lock, the whole-index rewrite and the fsyncs —
// the segment's, then the index's — once per batch rather than once per
// event: a push source hands over hundreds of
// events together, and a store that fsyncs an index per line caps the estate
// at the speed of the disk's willingness to flush, not the speed events
// arrive. A segment that rolls mid-batch seals — and saves — as rolling
// always does; everything else is one save at the end.
//
// The batch is prepared before the first line is written: an event that
// cannot be validated or marshalled refuses the whole batch rather than
// half-storing it, so a caller that retries retries all of it, where a caller
// retrying a half-failed loop of Appends would store the half that succeeded
// twice. A failure while the lines are being written leaves the same torn
// tail a failed single Append leaves, and is recovered from the same way.
func (s *Spool) AppendBatch(events []telemetry.Event) ([]string, error) {
	if len(events) == 0 {
		return nil, nil
	}
	stamped := make([]telemetry.Event, len(events))
	lines := make([][]byte, len(events))
	for i, e := range events {
		if e.Received.IsZero() {
			e.Received = s.opt.Now()
		}
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("event %d of the batch: %w", i+1, err)
		}
		line, err := json.Marshal(e)
		if err != nil {
			return nil, fmt.Errorf("event %d of the batch: %w", i+1, err)
		}
		if len(line)+1 > MaxLine {
			return nil, fmt.Errorf(
				"event %d of the batch is %d bytes, over the %d-byte line "+
					"limit; a source that can write an unbounded record can "+
					"fill the disk", i+1, len(line), MaxLine)
		}
		stamped[i] = e
		lines[i] = line
	}
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	into := make([]string, len(events))
	for i, e := range stamped {
		if err := s.ensure(e.Received); err != nil {
			return into, err
		}
		if _, err := s.open.Write(append(lines[i], '\n')); err != nil {
			return into, err
		}
		seg := &s.idx.Segments[s.cur]
		seg.Events++
		seg.Bytes += int64(len(lines[i])) + 1
		seg.Last = e.Received
		if seg.Earliest.IsZero() || e.Time.Before(seg.Earliest) {
			seg.Earliest = e.Time
		}
		if e.Time.After(seg.Latest) {
			seg.Latest = e.Time
		}
		s.observe(e.Lateness())
		into[i] = seg.Name
	}
	// The lines reach the disk before the index that counts them does:
	// an index saved first, then a crash, would count events the segment
	// never received.
	if s.open != nil {
		if err := s.open.Sync(); err != nil {
			return into, err
		}
	}
	return into, s.save()
}

// observe records one arrival delay in the histogram.
func (s *Spool) observe(d time.Duration) {
	if d < 0 {
		s.idx.Ahead++
		return
	}
	s.idx.Late[bucket(d)]++
}

// bucket is the log2 of a delay in seconds, floored at zero.
//
// Log-bucketed because the distribution spans six orders of magnitude — a
// local agent arrives in milliseconds, a cloud audit trail in fifteen minutes,
// a daily export in a day — and a linear histogram over that range is either
// useless at the bottom or enormous at the top.
func bucket(d time.Duration) int {
	secs := int64(d / time.Second)
	n := 0
	for secs > 0 {
		secs >>= 1
		n++
	}
	return n
}

// ensure opens or rolls the segment that an arrival at t belongs in.
func (s *Spool) ensure(at time.Time) error {
	if s.open == nil {
		if s.resume(at) {
			return nil
		}
		if err := s.sealReleased(); err != nil {
			return err
		}
	}
	if s.open != nil {
		seg := s.idx.Segments[s.cur]
		sameDay := seg.First.UTC().Format("20060102") ==
			at.UTC().Format("20060102")
		if sameDay && seg.Bytes < s.opt.SegmentBytes {
			return nil
		}
		if err := s.seal(); err != nil {
			return err
		}
	}
	// A name that already exists on disk is not a name to reuse. The count
	// is only a starting point: retention applying a plan shrinks the index,
	// and a writer rolling its next segment against that shrunken index
	// would compute the name of a file still on disk — appending today's
	// events into a sealed segment of the same day, whose digest then
	// matches nothing and whose events are counted twice. Existing files win
	// over the count, always; called under the writer's lock, where the
	// check and the create cannot interleave with another writer's.
	seq := len(s.idx.Segments)
	var name string
	for {
		name = fmt.Sprintf("%s-%04d.jsonl", at.UTC().Format("20060102"), seq)
		if _, serr := os.Stat(filepath.Join(s.dir, name)); os.IsNotExist(serr) {
			break
		}
		seq++
	}
	f, err := os.OpenFile(filepath.Join(s.dir, name),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	s.open = f
	s.idx.Segments = append(s.idx.Segments,
		Segment{Name: name, First: at, Last: at})
	s.cur = len(s.idx.Segments) - 1
	return nil
}

// Seal closes the open segment and digests it.
//
// Under the lock, because a digest is an index change like any other: it is
// saved, and another writer's save would otherwise drop it.
func (s *Spool) Seal() error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return s.seal()
}

// seal is Seal under a lock already held — ensure, rolling a segment in the
// middle of an append, already has it.
func (s *Spool) seal() error {
	if s.open == nil {
		return nil
	}
	if err := s.open.Sync(); err != nil {
		return err
	}
	if err := s.open.Close(); err != nil {
		return err
	}
	s.open = nil
	digest, err := digestOf(filepath.Join(s.dir, s.idx.Segments[s.cur].Name))
	if err != nil {
		return err
	}
	s.idx.Segments[s.cur].Digest = digest
	// Built while the writer's lock is held, so no reader ever meets a
	// sealed segment and starts rebuilding an index another process is
	// writing. The build reads the file the digest above just read; see
	// index.go for why that cost belongs here rather than on the read path.
	s.writeSidecar(s.idx.Segments[s.cur])
	s.cur = -1
	return s.save()
}

// Close seals and releases the spool.
func (s *Spool) Close() error { return s.Seal() }

// Release lets go of the open segment without sealing it, for a writer that
// appends a few events at a time — events pushed by another system as they
// happen — and must not leave a sealed segment behind for every few. The
// next Open appends to the same segment, until the day or the size rolls it
// and it is sealed like any other.
func (s *Spool) Release() error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return s.release()
}

// release is Release under a lock already held.
func (s *Spool) release() error {
	if s.open == nil {
		return nil
	}
	if err := s.open.Sync(); err != nil {
		return err
	}
	err := s.open.Close()
	s.open, s.cur = nil, -1
	if err != nil {
		return err
	}
	return s.save()
}

// sealReleased digests a released segment the next arrival cannot go in, as
// rolling would have. One whose file disagrees with the index is left
// unsealed: sealing it would vouch for bytes nobody here wrote.
func (s *Spool) sealReleased() error {
	n := len(s.idx.Segments)
	if n == 0 || s.idx.Segments[n-1].Digest != "" {
		return nil
	}
	path := filepath.Join(s.dir, s.idx.Segments[n-1].Name)
	st, err := os.Stat(path)
	if err != nil || st.Size() != s.idx.Segments[n-1].Bytes {
		return nil
	}
	digest, err := digestOf(path)
	if err != nil {
		return err
	}
	s.idx.Segments[n-1].Digest = digest
	s.writeSidecar(s.idx.Segments[n-1])
	return nil
}

// resume reopens the last segment when it was released rather than sealed
// and an arrival at t still belongs in it.
func (s *Spool) resume(at time.Time) bool {
	n := len(s.idx.Segments)
	if n == 0 {
		return false
	}
	seg := s.idx.Segments[n-1]
	if seg.Digest != "" || seg.Bytes >= s.opt.SegmentBytes ||
		seg.First.UTC().Format("20060102") != at.UTC().Format("20060102") {
		return false
	}
	path := filepath.Join(s.dir, seg.Name)
	st, err := os.Stat(path)
	// The file must be what the index says it is: a segment somebody
	// truncated or replaced is not one to add to.
	if err != nil || st.Size() != seg.Bytes {
		return false
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return false
	}
	s.open, s.cur = f, n-1
	return true
}

func digestOf(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Spool) save() error {
	b, err := json.MarshalIndent(s.idx, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(s.dir, "index.json"), b, 0o600)
}

// Segments returns what the spool holds, oldest arrival first.
func (s *Spool) Segments() []Segment {
	out := append([]Segment(nil), s.idx.Segments...)
	sort.Slice(out, func(i, j int) bool { return out[i].First.Before(out[j].First) })
	return out
}

// Oldest is the earliest arrival the spool can still answer for.
//
// The honest answer to "how far back can we look", which is not the same as
// the configured retention and is the number to put in a policy document.
func (s *Spool) Oldest() time.Time {
	var out time.Time
	for _, seg := range s.idx.Segments {
		if out.IsZero() || seg.First.Before(out) {
			out = seg.First
		}
	}
	return out
}

// Bytes is how much the spool currently holds.
func (s *Spool) Bytes() int64 {
	var n int64
	for _, seg := range s.idx.Segments {
		n += seg.Bytes
	}
	return n
}

// Events is how many events the spool holds.
func (s *Spool) Events() int {
	var n int
	for _, seg := range s.idx.Segments {
		n += seg.Events
	}
	return n
}

// Range calls fn for every event that arrived in [from, to).
//
// By arrival, because that is what the spool is ordered by and what it can
// answer without reading everything. A caller wanting a period of event time
// filters inside fn; the segment's Earliest and Latest let Range skip files
// that cannot contain anything in the period, which is the only place the
// source's clock is allowed to influence what gets read — and the worst a
// wrong clock can do there is cost a read.
func (s *Spool) Range(from, to time.Time, fn func(telemetry.Event) error) error {
	return s.RangeWhere(from, to, nil, fn)
}

// RangeWhere is Range over the segments keep still allows.
//
// keep is asked once per segment the arrival window has not already pruned,
// and a segment it refuses is not opened at all. It must refuse only
// segments no event of which the caller's own per-event test would have
// kept — the question CouldHold answers for an equality on source, class or
// actor.value. A keep that is wrong in that direction does not slow a read,
// it narrows one: the caller sees fewer events and nothing says so.
//
// The segments that remain are read in parallel — see parallel.go — and
// handed to fn in the order this function has always produced. Which
// segments those are is settled below before any of them is opened, by the
// same three tests that have always settled it, so a hunt's byte budget,
// passed here as a from that excludes the segments it will not pay for,
// prunes exactly what it always pruned.
func (s *Spool) RangeWhere(from, to time.Time, keep func(Segment) bool,
	fn func(telemetry.Event) error) error {

	if s.open != nil {
		// Flushed, not sealed. A reader that missed the events written a
		// second ago is a reader that will report an incident as quiet.
		if err := s.open.Sync(); err != nil {
			return err
		}
	}
	var reads []func(func(telemetry.Event) error) error
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
		reads = append(reads, s.arrivalsIn(seg, from, to))
	}
	return inOrder(reads, fn)
}

// arrivalsIn is one segment's contribution to a Range: eachFrom's seek
// where the sidecar has earned it, then the arrival window applied to every
// line it lands on. Pure in from and to — the same line is kept whichever
// goroutine asks — so it is safe to run beside the other segments' reads,
// and only ever its own, one worker to a segment.
func (s *Spool) arrivalsIn(seg Segment, from, to time.Time) func(func(telemetry.Event) error) error {
	return func(emit func(telemetry.Event) error) error {
		return s.eachFrom(seg, from, func(e telemetry.Event) error {
			if !from.IsZero() && e.Received.Before(from) {
				return nil
			}
			if !to.IsZero() && !e.Received.Before(to) {
				return nil
			}
			return emit(e)
		})
	}
}

// RangeWhereEqual is RangeWhere with an equality inside the read: fn is
// handed exactly the events, of those keep still allows, whose field
// EqualFolds value — the comparison a detection's equals makes — in the same
// order RangeWhere produces, segment by segment and line by line within
// each.
//
// The equality is a hint about where the answer lives, never the answer
// itself. For a sealed segment whose sidecar carries postings for the field
// (source, class, actor.value and message; see postings.go), the segment is
// skipped whole when the dictionary refuses the value — an exact refusal, no
// false negatives — and otherwise read at just the postings' line offsets,
// each event re-checked against the equality before it is handed over. Every
// other case — an unsealed tail, a missing or unreadable index, a field with
// no postings, a file whose size has moved behind the index's back — reads
// the segment linearly with the equality applied per event, which yields
// exactly the same events. The two paths differ in what they parse to
// produce an answer, never in the answer.
//
// keep runs before any of that, exactly as in RangeWhere, and may refuse
// only segments no event of which the equality would have kept. It cannot
// consult the postings itself; CouldHold remains the advisory, fixed-size
// question a keep wants answered.
func (s *Spool) RangeWhereEqual(from, to time.Time, field, value string,
	keep func(Segment) bool, fn func(telemetry.Event) error) error {

	if s.open != nil {
		if err := s.open.Sync(); err != nil {
			return err
		}
	}
	var reads []func(func(telemetry.Event) error) error
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
		reads = append(reads, s.equalsIn(seg, from, to, field, value))
	}
	return inOrder(reads, fn)
}

// equalsIn is arrivalsIn's counterpart for an equality: the segment's
// contribution to a RangeWhereEqual, decided by the postings where they
// apply and by a filtered linear read everywhere else. Pure in its inputs
// like arrivalsIn, for the same reason — one worker to a segment, and the
// same lines kept whichever goroutine asks.
func (s *Spool) equalsIn(seg Segment, from, to time.Time, field,
	value string) func(func(telemetry.Event) error) error {

	return func(emit func(telemetry.Event) error) error {
		f, err := os.Open(filepath.Join(s.dir, seg.Name))
		if os.IsNotExist(err) {
			return missingSegment(seg.Name)
		}
		if err != nil {
			return err
		}
		defer f.Close()

		// The filtered linear read: what the equality falls back to whenever
		// the postings cannot be consulted. It yields, by construction, the
		// same events the jump does — which is the whole equivalence the
		// tests stand on.
		linear := func() error {
			return scanEvents(f, seg.Name, 1, func(e telemetry.Event) error {
				if !withinArrival(e, from, to) {
					return nil
				}
				if !equalField(e, field, value) {
					return nil
				}
				return emit(e)
			})
		}

		// The postings may only be consulted over bytes the seal digested:
		// a file whose size has moved is not the one the ordinals describe,
		// and the linear read answers from what is there, as ever.
		if st, serr := f.Stat(); serr != nil || st.Size() != seg.Bytes {
			return linear()
		}
		ords, sc, decided := s.postingOrdinals(seg, field, value)
		if !decided {
			return linear()
		}
		defer sc.close()

		// A sorted times column lets a lower bound cut the ordinals before
		// a single line is read: everything below the first event at or
		// after from is a line the window would have dropped anyway. An
		// unsorted column cannot say that, and the per-event window check
		// below keeps it honest instead.
		skipBelow := 0
		if sc.sorted && !from.IsZero() {
			_, idx, ok := sc.firstAtOrAfter(from)
			if !ok {
				// Every arrival in the segment precedes the window; the
				// linear read would have emitted nothing either.
				return nil
			}
			skipBelow = idx
		}
		for _, ord := range ords {
			if ord < skipBelow {
				continue
			}
			off, ok := sc.offsetOf(ord)
			if !ok {
				return fmt.Errorf("%s: the times column is shorter than its "+
					"own postings", seg.Name)
			}
			if off > uint64(seg.Bytes) {
				return fmt.Errorf("%s: a posting points past the sealed "+
					"bytes it indexes", seg.Name)
			}
			line, lerr := lineAt(f, int64(off))
			if lerr != nil {
				return lerr
			}
			text := strings.TrimSpace(string(line))
			if text == "" {
				continue
			}
			var e telemetry.Event
			if uerr := json.Unmarshal([]byte(text), &e); uerr != nil {
				return fmt.Errorf("%s line %d: %w", seg.Name, ord+1, uerr)
			}
			if !withinArrival(e, from, to) {
				continue
			}
			// The index chose what to parse; the event itself decides what
			// the answer is. A posting that pointed anywhere but at an
			// event carrying the value is dropped here, so a corrupt
			// section can cost reads in the inclusion direction, never
			// events — and the refusal direction never gets the chance,
			// because an unreadable section never reached this path.
			if !equalField(e, field, value) {
				continue
			}
			if err := emit(e); err != nil {
				return err
			}
		}
		return nil
	}
}

// postingOrdinals asks the segment's postings for the value's event
// ordinals. decided is true when the sidecar answered exactly — including
// the answer "nothing", for ordinals empty — and then sc is the open sidecar
// the caller must close. decided false means no exact answer existed (no
// seal, no sidecar, no postings for the field, a size the index does not
// vouch for, a section that would not read), and the caller falls back to
// the filtered linear read; a sidecar opened on that path is closed here.
func (s *Spool) postingOrdinals(seg Segment, field,
	value string) (ords []int, sc *sidecar, decided bool) {

	if !seg.Sealed() || postColumn(field) < 0 {
		return nil, nil, false
	}
	sc = s.sidecarOf(seg)
	if sc == nil {
		return nil, nil, false
	}
	col := sc.postingsOf(field)
	if col == nil {
		sc.close()
		return nil, nil, false
	}
	from, to, ok, err := col.run(bloomKey(value))
	if err != nil {
		sc.close()
		return nil, nil, false
	}
	if !ok {
		// The dictionary's refusal is exact: no event in this segment
		// carries the value, so the read contributes nothing. The sidecar
		// stays open for the times column in case a window wants it.
		return nil, sc, true
	}
	ords, err = col.ordinals(from, to)
	if err != nil {
		sc.close()
		return nil, nil, false
	}
	return ords, sc, true
}

// offsetOf is event ordinal i's line offset, out of the times column.
func (sc *sidecar) offsetOf(i int) (uint64, bool) {
	if i < 0 || i >= int(sc.events) {
		return 0, false
	}
	var buf [8]byte
	if _, err := sc.r.ReadAt(buf[:], sidecarOffsetOf(i)); err != nil {
		return 0, false
	}
	return binary.LittleEndian.Uint64(buf[:]), true
}

// withinArrival is the arrival window Range and RangeWhere apply to every
// event they hand over, stated once so the equality read applies the same
// one.
func withinArrival(e telemetry.Event, from, to time.Time) bool {
	if !from.IsZero() && e.Received.Before(from) {
		return false
	}
	if !to.IsZero() && !e.Received.Before(to) {
		return false
	}
	return true
}

// During calls fn for every event whose own timestamp is in [from, to).
//
// The query an analyst means. Separate from Range so that the choice between
// the two clocks is made at the call site by somebody who knows which one
// their question is about, rather than by a default nobody remembers.
//
// Fanned out over its segments like RangeWhere, gathered in the same order
// this function has always produced.
func (s *Spool) During(from, to time.Time, fn func(telemetry.Event) error) error {
	var reads []func(func(telemetry.Event) error) error
	for _, seg := range s.Segments() {
		if !to.IsZero() && !seg.Earliest.IsZero() && !seg.Earliest.Before(to) {
			continue
		}
		if !from.IsZero() && !seg.Latest.IsZero() && seg.Latest.Before(from) {
			continue
		}
		reads = append(reads, s.happeningsIn(seg, from, to))
	}
	return inOrder(reads, fn)
}

// happeningsIn is arrivalsIn's counterpart for During: the whole segment
// scanned — there is no arrival order to seek on for a question about event
// time — with the event-time window applied per line. Pure like arrivalsIn,
// for the same reason.
func (s *Spool) happeningsIn(seg Segment, from, to time.Time) func(func(telemetry.Event) error) error {
	return func(emit func(telemetry.Event) error) error {
		return s.each(seg, func(e telemetry.Event) error {
			if !from.IsZero() && e.Time.Before(from) {
				return nil
			}
			if !to.IsZero() && !e.Time.Before(to) {
				return nil
			}
			return emit(e)
		})
	}
}

func (s *Spool) each(seg Segment, fn func(telemetry.Event) error) error {
	f, err := os.Open(filepath.Join(s.dir, seg.Name))
	if os.IsNotExist(err) {
		return missingSegment(seg.Name)
	}
	if err != nil {
		return err
	}
	defer f.Close()
	return scanEvents(f, seg.Name, 1, fn)
}

// eachFrom is each with a head start. When the segment is sealed, the file
// on disk is still the size the index says it is, and its sidecar says
// arrivals never ran backwards down the file, the read starts at the first
// line that can hold an event in [from, …) instead of at the top of the
// file — everything skipped is a line the caller's own window would have
// dropped without a second glance, which is the only property that makes a
// seek like this admissible.
//
// Any doubt — unsealed, absent, stale, unsorted, unreadable, or a file whose
// size has moved since the index described it — reads the whole file as
// before. The active tail stays linear because it is small and because an
// index of a file still being appended to is a claim that stops being true a
// millisecond later.
func (s *Spool) eachFrom(seg Segment, from time.Time,
	fn func(telemetry.Event) error) error {

	f, err := os.Open(filepath.Join(s.dir, seg.Name))
	if os.IsNotExist(err) {
		return missingSegment(seg.Name)
	}
	if err != nil {
		return err
	}
	defer f.Close()
	if from.IsZero() || !seg.Sealed() {
		return scanEvents(f, seg.Name, 1, fn)
	}
	if st, serr := f.Stat(); serr != nil || st.Size() != seg.Bytes {
		// Grew or shrank behind the index's back. The sidecar's offsets
		// describe the file the seal digested, not this one, so they are not
		// trusted; the scan reads what is actually there, as the linear
		// reader always did. What to make of it is Verify's to say.
		return scanEvents(f, seg.Name, 1, fn)
	}
	sc := s.sidecarOf(seg)
	if sc == nil || !sc.sorted {
		if sc != nil {
			sc.close()
		}
		return scanEvents(f, seg.Name, 1, fn)
	}
	defer sc.close()
	off, at, ok := sc.firstAtOrAfter(from)
	if !ok {
		// Every arrival in this segment is before the window: the linear
		// read would have called fn for none of them either.
		return nil
	}
	if _, err := f.Seek(int64(off), io.SeekStart); err != nil {
		return err
	}
	// at is the entry the seek landed on; the lines before it are the ones
	// skipped, so counting from at+1 keeps line numbers in errors the same
	// ones a scan from the top would have printed.
	return scanEvents(f, seg.Name, at+1, fn)
}

// missingSegment is the one error a reader must never soften: a store that
// answers a window with the events of a file it no longer has is reporting
// coverage it does not have.
func missingSegment(name string) error {
	return fmt.Errorf(
		"%s is in the index and not on disk. The spool is reporting "+
			"coverage it does not have", name)
}

// scanEvents reads whole JSONL lines out of an open segment, from wherever
// it is positioned, calling fn for each. line is the number of the line at
// that position, so errors name the same lines a scan from the top would.
func scanEvents(f *os.File, name string, line int,
	fn func(telemetry.Event) error) error {

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLine)
	for ; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" {
			continue
		}
		var e telemetry.Event
		if uerr := json.Unmarshal([]byte(text), &e); uerr != nil {
			return fmt.Errorf("%s line %d: %w", name, line, uerr)
		}
		if ferr := fn(e); ferr != nil {
			return ferr
		}
	}
	return sc.Err()
}

// Verify recomputes every sealed segment's digest and names what changed.
//
// An open segment is skipped rather than reported: it is still being appended
// to and has no digest to check against, which is a fact about when Verify
// ran and not a finding.
func (s *Spool) Verify() ([]string, error) {
	var bad []string
	for _, seg := range s.Segments() {
		if !seg.Sealed() {
			continue
		}
		got, err := digestOf(filepath.Join(s.dir, seg.Name))
		if os.IsNotExist(err) {
			bad = append(bad, seg.Name+" is gone")
			continue
		}
		if err != nil {
			return nil, err
		}
		if got != seg.Digest {
			bad = append(bad, seg.Name+" does not match its digest")
		}
	}
	return bad, nil
}

// Anchor returns the sealed segments' digests, for recording somewhere signed.
//
// The spool does not reach into the audit log itself. Keeping the dependency
// pointing one way means a store that fills up cannot stall the log that
// records who did what, and the caller that wants tamper-evidence over volume
// data writes one audit record per seal.
func (s *Spool) Anchor() map[string]string {
	out := map[string]string{}
	for _, seg := range s.idx.Segments {
		if seg.Sealed() {
			out[seg.Name] = seg.Digest
		}
	}
	return out
}
