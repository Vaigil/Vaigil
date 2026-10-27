// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/vaigil/vaigil/internal/fetch"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vaigil/vaigil/internal/atomicfile"
)

// Shipping: evidence leaves the endpoint in signed batches.
//
// Records are written to a bounded local spool first, then sent — a
// write-ahead rather than a memory queue, so an outage or a restart loses
// nothing that had been noticed. The spool is bounded by batch count with
// drop-oldest: when the bound is hit, the oldest batches go and the drop is
// counted, on the heartbeat, where the server's own missing-heartbeat rules
// and an operator reading the feed can see the recorder was overrunning its
// uplink. Dropping the oldest is the honest direction — the newest evidence
// is what an investigation starts from, and the alternative is dropping the
// new, which is how a recorder goes quiet exactly when things are
// happening.
//
// # The credential, and what the signature adds
//
// A push carries the collector's credential the way the OTLP endpoint's
// does: a bearer token from the server's sealed store, compared there in
// constant time. The body is additionally signed with HMAC-SHA256, keyed
// with that same credential — one provisioned secret per collector, not two
// to rotate out of sync — over the batch id, the timestamp and the body.
// The bearer proves the sender; the signature proves the body is the body
// the sender wrote, which a captured header set or a rewriting middlebox
// cannot forge. The timestamp is checked server-side against a five-minute
// window, so a captured whole request cannot be replayed next week, and the
// batch id is remembered, so the retry that follows a lost answer stores
// nothing twice.

// Record is one observation on its way to the server.
type Record struct {
	Source string         `json:"source"`
	At     time.Time      `json:"at"`
	Data   map[string]any `json:"data"`
}

// Batch is one POST body: who is talking, and what they noticed.
type Batch struct {
	Collector string   `json:"collector"`
	Records   []Record `json:"records"`
}

// The headers both halves of the wire agree on.
const (
	HeaderToken     = "X-Vaigil-Token"     // the credential's name server-side
	HeaderBatch     = "X-Vaigil-Batch"     // the batch id, for dedup
	HeaderTime      = "X-Vaigil-Time"      // unix seconds, for replay refusal
	HeaderSignature = "X-Vaigil-Signature" // hex HMAC-SHA256
	// CollectorPath is the endpoint the batches POST to and the config is
	// fetched from.
	CollectorPath = "/v1/collector"
)

// SignBatch is the batch signature: HMAC-SHA256 over
// "batch-id.timestamp.body", hex-encoded. The timestamp is the send time,
// not the seal time, so a batch that waited out an outage in the spool
// still signs fresh.
func SignBatch(secret, batchID string, at time.Time, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(batchID))
	mac.Write([]byte{'.'})
	mac.Write([]byte(strconv.FormatInt(at.Unix(), 10)))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyBatch checks one. Both the id and the timestamp are signed inputs,
// so neither can be swapped onto a captured signature.
func VerifyBatch(secret, batchID string, at time.Time, body []byte, hexSig string) bool {
	if hexSig == "" || batchID == "" {
		return false
	}
	got, err := hex.DecodeString(hexSig)
	if err != nil {
		return false
	}
	want, _ := hex.DecodeString(SignBatch(secret, batchID, at, body))
	return hmac.Equal(got, want)
}

// Counts is what the heartbeat says the shipper did. Every number is
// monotonic for the life of the process; a reset would be the recorder
// lying about its own past.
type Counts struct {
	// Shipped is records the server took. Dropped is records evicted from
	// the spool by the bound — the number an operator of a starved collector
	// reads first.
	Shipped int64 `json:"shipped"`
	Dropped int64 `json:"dropped"`
	// Batches sealed, and attempts that had to be retried.
	Batches int64 `json:"batches"`
	Retries int64 `json:"retries"`
}

// Shipper batches records, spools them, and sends them.
type Shipper struct {
	// Name is the collector's identity and its credential's name.
	Name string
	// Secret is the credential itself. Held in memory for the process's
	// life, never written anywhere, including the spool: spool files are
	// bodies, and bodies are signed, not sealed.
	Secret string
	// Server is the base URL.
	Server string
	// Dir is the spool directory, inside the state directory.
	Dir string
	// MaxBatches is the spool bound. Default 500.
	MaxBatches int
	// BatchMax is records per sealed batch. Default 200.
	BatchMax int
	// BatchSeconds is how long a partial batch waits before it is sealed
	// anyway. Default 10.
	BatchSeconds int
	// Gzip the bodies.
	Gzip bool

	Client *http.Client
	// Now and Sleep are the clock and the waiter; tests set them.
	Now   func() time.Time
	Sleep func(time.Duration)
	Logf  func(string, ...any)

	mu      sync.Mutex
	pending []Record
	// sealedAt is when the oldest pending record was added, so a batch goes
	// out on age as well as on count.
	sealedAt time.Time
	counts   Counts
	failures int
	seq      uint64
}

func (s *Shipper) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Shipper) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// Add takes a record. When the forming batch is full it is sealed to the
// spool at once, so even a crash between cycles costs at most BatchMax
// records of nothing.
func (s *Shipper) Add(r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) == 0 {
		s.sealedAt = s.now()
	}
	s.pending = append(s.pending, r)
	if len(s.pending) < s.batchMax() {
		return nil
	}
	return s.seal()
}

// Tick seals what is old enough and drains what is spooled.
//
// One pass rather than a goroutine per concern: the cycle owns the rhythm,
// and a shipper whose pieces each had a timer would have two timers to
// disagree about what "10 seconds" means. A batch that could not leave is
// the outage's business, not the cycle's: it was logged, the backoff grew,
// and the next tick tries again.
func (s *Shipper) Tick(ctx context.Context) error {
	s.mu.Lock()
	if len(s.pending) > 0 && s.now().Sub(s.sealedAt) >= s.batchSeconds() {
		if err := s.seal(); err != nil {
			s.mu.Unlock()
			return err
		}
	}
	s.mu.Unlock()
	s.drain(ctx)
	return nil
}

func (s *Shipper) batchMax() int {
	if s.BatchMax > 0 {
		return s.BatchMax
	}
	return 200
}

func (s *Shipper) maxBatches() int {
	if s.MaxBatches > 0 {
		return s.MaxBatches
	}
	return 500
}

func (s *Shipper) batchSeconds() time.Duration {
	if s.BatchSeconds > 0 {
		return time.Duration(s.BatchSeconds) * time.Second
	}
	return 10 * time.Second
}

// newID is a batch id: 16 random bytes, hex. Random rather than sequential
// so an id names a batch without naming the machine's event count, and
// UUID-shaped collisions are not a thing at 128 bits.
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Crypto randomness refusing is not survivable for a program whose
		// whole job is trustworthy evidence ids.
		panic(fmt.Sprintf("the system refused random bytes: %v", err))
	}
	return hex.EncodeToString(b)
}

// seal writes the forming batch to the spool. Called with the lock held.
//
// The file name carries a monotonic sequence so "oldest" is a sort, and the
// batch id so a file and its signature inputs are never far apart. The
// sequence survives restarts by starting past whatever the directory
// already holds.
func (s *Shipper) seal() error {
	if len(s.pending) == 0 {
		return nil
	}
	id := newID()
	b := Batch{Collector: s.Name, Records: s.pending}
	body, err := json.Marshal(b)
	if err != nil {
		return err
	}
	s.seq++
	name := fmt.Sprintf("%016x-%s.json", s.seq, id)
	if err := atomicfile.Write(filepath.Join(s.Dir, name), body, 0o600); err != nil {
		return err
	}
	s.counts.Batches++
	s.pending = nil
	s.trim()
	return nil
}

// trim enforces the spool bound, dropping oldest first and counting what
// went. Called with the lock held, after a seal: the bound is a property of
// the spool, checked whenever the spool grows.
func (s *Shipper) trim() {
	files := s.spoolFiles()
	if len(files) <= s.maxBatches() {
		return
	}
	for _, f := range files[:len(files)-s.maxBatches()] {
		n := s.recordsIn(f)
		if err := os.Remove(filepath.Join(s.Dir, f)); err != nil && !os.IsNotExist(err) {
			s.logf("cannot drop the oldest spool batch %s: %v", f, err)
			continue
		}
		s.counts.Dropped += int64(n)
		s.logf("spool is at its bound of %d batches; dropped the oldest "+
			"batch of %d records", s.maxBatches(), n)
	}
}

// recordsIn says how many records a spool file holds, for the drop
// accounting. A file that cannot be read counts as its own loss and is
// dropped by the caller regardless: an unreadable batch is not made more
// readable by keeping it.
func (s *Shipper) recordsIn(name string) int {
	b, err := os.ReadFile(filepath.Join(s.Dir, name))
	if err != nil {
		return 0
	}
	var batch Batch
	if err := json.Unmarshal(b, &batch); err != nil {
		return 0
	}
	return len(batch.Records)
}

// spoolFiles lists the spool, oldest first.
//
// It does not touch the sequence: reading and writing it from whatever
// goroutine happened to list first is a race, and the sequence is set once,
// in Resume, before anything runs.
func (s *Shipper) spoolFiles() []string {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

// Resume starts the batch sequence past whatever the spool already holds,
// once, before anything is sealed or sent. A restart that reset to zero
// would seal a file named below the ones already waiting, and "oldest
// first" would send the new evidence before the old.
func (s *Shipper) Resume() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq = 0
	for _, name := range s.spoolFiles() {
		if len(name) < 17 {
			continue
		}
		if seq, err := strconv.ParseUint(name[:16], 16, 64); err == nil && seq > s.seq {
			s.seq = seq
		}
	}
}

// Counters is a copy of the counts, for the heartbeat.
func (s *Shipper) Counters() Counts {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts
}

// Pending is how many records are in memory, unsent. A number that stays
// nonzero across heartbeats is a number that names a stuck shipper.
func (s *Shipper) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// drain sends spooled batches oldest first.
//
// A batch that could not leave — network trouble, a 5xx, a 429, or a
// refusal the server will give every time — stops the drain for this tick
// and grows the backoff, and the batch stays first in line: evidence order
// is preserved, and a heartbeat queued behind an unsendable batch is itself
// silent, which the server's missing-heartbeat detection is there to notice.
// A permanent refusal (a 4xx other than 429) is never answered by deleting
// the evidence either: the operator should find the refused batch still
// trying, not a recorder that quietly swallowed the thing the server
// rejected. Eviction by the bound is the only discard, ever.
func (s *Shipper) drain(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		files := s.spoolFiles()
		if len(files) == 0 {
			return
		}
		name := files[0]
		body, err := os.ReadFile(filepath.Join(s.Dir, name))
		if err != nil {
			// Gone — a previous process or an operator. Not ours to send.
			continue
		}
		id := strings.TrimSuffix(name[17:], ".json")
		retry, err := s.send(ctx, id, body)
		if err != nil || retry {
			s.mu.Lock()
			s.counts.Retries++
			s.failures++
			delay := s.backoff()
			s.mu.Unlock()
			s.logf("batch %s did not leave (%v); backing off %s", id, err, delay)
			s.sleep(ctx, delay)
			return
		}
		s.mu.Lock()
		s.failures = 0
		var batch Batch
		_ = json.Unmarshal(body, &batch)
		s.counts.Shipped += int64(len(batch.Records))
		s.mu.Unlock()
		if err := os.Remove(filepath.Join(s.Dir, name)); err != nil && !os.IsNotExist(err) {
			s.logf("cannot remove the sent batch %s: %v", name, err)
			return
		}
	}
}

// backoff is the wait after consecutive failures: one second doubling to a
// minute. Capped, because a collector that backed off without a cap would
// be a collector whose outage outlasted the operator's patience for looking.
func (s *Shipper) backoff() time.Duration {
	d := time.Second
	for i := 1; i < s.failures && d < time.Minute; i++ {
		d *= 2
	}
	if d > time.Minute {
		d = time.Minute
	}
	return d
}

func (s *Shipper) sleep(ctx context.Context, d time.Duration) {
	if s.Sleep != nil {
		s.Sleep(d)
		return
	}
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

// send posts one batch and reports whether it should be retried.
//
// The signature is computed over the uncompressed body and at send time;
// gzip changes the bytes on the wire, not what was said, and a spool that
// waited hours signs the moment it leaves.
func (s *Shipper) send(ctx context.Context, id string, body []byte) (retry bool, err error) {
	at := s.now()
	if s.Client == nil {
		s.Client = fetch.Speaking("collector", fetch.Anywhere, 30*time.Second)
	}
	wire := body
	encoding := ""
	if s.Gzip {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(body); err != nil {
			return true, err
		}
		if err := gz.Close(); err != nil {
			return true, err
		}
		wire, encoding = buf.Bytes(), "gzip"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(s.Server, "/")+CollectorPath, bytes.NewReader(wire))
	if err != nil {
		return true, err
	}
	req.Header.Set("Content-Type", "application/json")
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	req.Header.Set("Authorization", "Bearer "+s.Secret)
	req.Header.Set(HeaderToken, s.Name)
	req.Header.Set(HeaderBatch, id)
	req.Header.Set(HeaderTime, strconv.FormatInt(at.Unix(), 10))
	req.Header.Set(HeaderSignature, SignBatch(s.Secret, id, at, body))
	res, err := s.Client.Do(req)
	if err != nil {
		// The network being down is the ordinary outage: retry.
		return true, err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	switch {
	case res.StatusCode >= 200 && res.StatusCode < 300:
		return false, nil
	case res.StatusCode == http.StatusTooManyRequests,
		res.StatusCode >= 500:
		return true, fmt.Errorf("the server answered %s", res.Status)
	default:
		// A refusal: wrong credential, bad signature, a shape the server
		// will not take. Retrying cannot change the answer, so the batch is
		// neither dropped nor resealed — it waits, first in line, for the
		// operator, and the heartbeat says so by going silent.
		return true, fmt.Errorf("the server refused the batch: %s", res.Status)
	}
}

// Flush seals and tries once to send everything. Shutdown's last act: what
// was noticed deserves one attempt, and the spool keeps whatever could not
// leave.
func (s *Shipper) Flush(ctx context.Context) {
	s.mu.Lock()
	err := s.seal()
	s.mu.Unlock()
	if err != nil {
		s.logf("cannot seal the last batch: %v", err)
	}
	s.drain(ctx)
}
