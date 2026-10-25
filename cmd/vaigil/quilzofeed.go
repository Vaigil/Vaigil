// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vaigil/vaigil/internal/audit"
	"github.com/vaigil/vaigil/internal/auditstream"
	"github.com/vaigil/vaigil/internal/httpsig"
	"github.com/vaigil/vaigil/internal/inbound"
	"github.com/vaigil/vaigil/internal/spool"
	"github.com/vaigil/vaigil/internal/telemetry"
)

// Quilzo's audit log, received.
//
// A feed of kind quilzo is the receiving end of Quilzo's siem.stream.url.
// Quilzo pushes; nothing here reaches into Quilzo. A batch is taken only
// when it is signed by the stream key the feed pinned, follows the last
// record held exactly, and its leaves rebuild a tree head signed by the
// head keys the feed pinned. Then the records go into the event store as
// quilzo/audit, the rules read them at once, and the answer tells Quilzo
// how far it has got: 200 with what is held, or 409 with what is held when
// a batch does not follow, so the sender starts again from there.
//
// The leaves taken are kept beside the feed, one per line, so the chain
// survives a restart: a receiver that forgot them would take a batch that
// skipped records, which is exactly what the stream exists to make
// impossible.

// streamFeedHelp is what `vaigil inbound help` says about this kind.
const streamFeedHelp = `
  Quilzo's audit log, as Quilzo writes it
    quilzo siem stream key --json > quilzo-keys.json        (in Quilzo)
    vaigil inbound add quilzo quilzo --keys quilzo-keys.json
    quilzo config set siem.stream.url https://YOUR-ADMIN/feeds/quilzo
    Each batch is taken only when it is signed by the stream key, follows
    the last record held exactly, and rebuilds the signed tree head. The
    records are stored as quilzo/audit, where the quilzo.* rules read them.
`

// streamFeedLabel is what the Feeds screen calls the kind.
const streamFeedLabel = "Quilzo audit log"

// streamRotateHelp is the answer to rotating one: its keys are Quilzo's.
const streamRotateHelp = "an audit stream's keys are Quilzo's: rotate them there, then " +
	"`vaigil inbound remove NAME` and add the feed again with the new `quilzo siem stream key --json`"

// streamFeedUsage is its line in the usage.
const streamFeedUsage = "add quilzo NAME --keys FILE | "

// streamBodyLimit is the largest batch taken: five hundred records of OCSF
// with their envelope and leaves come to about a megabyte and a half.
const streamBodyLimit = 8 << 20

func streamLeavesPath(root, name string) string {
	return filepath.Join(inboundDir(root), name+".leaves")
}

// heldStream is one feed's receiver, and the lock that keeps its batches in
// order.
type heldStream struct {
	mu   sync.Mutex
	keys string
	rc   *auditstream.Receiver
}

// streamKeysDigest names a set of keys, so a receiver built for old keys is
// not used once the feed has new ones.
func streamKeysDigest(f inbound.Feed) string {
	// The feed's creation too: one removed and added again under its name
	// starts from nothing, and must not inherit the chain held for the old.
	b, _ := json.Marshal(struct {
		K *inbound.StreamKeys
		C string
	}{f.Stream, f.Created.String()})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// stream returns the feed's receiver, building it and restoring the leaves
// already taken when there is none, or when its keys changed.
func (s *inboundServer) stream(f inbound.Feed) (*heldStream, error) {
	if f.Stream == nil {
		return nil, errors.New("the feed holds no stream keys")
	}
	s.mu.Lock()
	if s.streams == nil {
		s.streams = map[string]*heldStream{}
	}
	h := s.streams[f.Name]
	if h == nil {
		h = &heldStream{}
		s.streams[f.Name] = h
	}
	s.mu.Unlock()
	h.mu.Lock()
	defer h.mu.Unlock()
	digest := streamKeysDigest(f)
	if h.rc != nil && h.keys == digest {
		return h, nil
	}
	rc, err := streamReceiver(s.root, f)
	if err != nil {
		return nil, err
	}
	h.rc, h.keys = rc, digest
	return h, nil
}

func streamReceiver(root string, f inbound.Feed) (*auditstream.Receiver, error) {
	pub, headEd, headML, err := f.Stream.Decode()
	if err != nil {
		return nil, err
	}
	heads, err := audit.NewHeadVerifierIn(inbound.StreamHeadContext, headEd, headML)
	if err != nil {
		return nil, err
	}
	rc := &auditstream.Receiver{
		Keys:  []httpsig.PublicKey{{ID: f.Stream.KeyID, Alg: httpsig.Ed25519, Ed: pub}},
		Heads: heads,
		// The address Quilzo was given, which is the one it signs.
		Origin: strings.TrimSuffix(mustConfig(root).Raw("admin.base_url"), "/"),
	}
	leaves, err := readStreamLeaves(streamLeavesPath(root, f.Name))
	if err != nil {
		return nil, err
	}
	if err := rc.Restore(leaves); err != nil {
		return nil, err
	}
	return rc, nil
}

// readStreamLeaves reads the leaves held, one a line.
//
// A last line with no newline is a write that did not finish: the disk
// filled, or the process stopped, part way through a batch. It is cut off,
// in the file as well, rather than read as a leaf. Read, it would fail every
// restore and the feed would refuse everything from then on; left in the
// file, the next batch's first leaf would be appended to it. The leaves
// before it were written whole and are what was held, so the sender, told
// so, sends again from there.
func readStreamLeaves(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if cut := bytes.LastIndexByte(b, '\n') + 1; cut != len(b) {
		if err := os.Truncate(path, int64(cut)); err != nil {
			return nil, err
		}
		b = b[:cut]
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out, nil
}

// appendStreamLeaves keeps what a batch added, synced before the sender is
// told it was taken.
func appendStreamLeaves(path string, leaves []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := fh.WriteString(strings.Join(leaves, "\n") + "\n")
	serr := fh.Sync()
	cerr := fh.Close()
	return errors.Join(werr, serr, cerr)
}

// storeStream writes a batch's events to the store before its sender is told
// they were taken. Other feeds queue what arrives while the store is busy;
// a stream may not, because the leaves kept next say these records are held,
// and a queue lost with the process would make that untrue with nothing to
// show it. A failure part way leaves some stored, and the sender, told
// nothing was taken, sends them again: twice, never not at all.
func (s *inboundServer) storeStream(f inbound.Feed, events []telemetry.Event, at time.Time) error {
	stored := 0
	err := withSpool(s.root, func(sp *spool.Spool) error {
		for _, e := range events {
			if _, err := sp.Append(e); err != nil {
				return err
			}
			stored++
		}
		return nil
	})
	s.mu.Lock()
	st := s.statusOf(f.Name)
	st.Deliveries++
	st.LastAt = at
	st.Records += len(events)
	st.Stored += stored
	if err != nil {
		st.Error = err.Error()
	} else {
		st.Error = ""
	}
	if stored > 0 {
		s.fresh = true
	}
	s.dirty = true
	s.mu.Unlock()
	s.poke()
	return err
}

func streamAnswer(w http.ResponseWriter, status int, v map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// auditStream takes one batch.
func (s *inboundServer) auditStream(w http.ResponseWriter, r *http.Request, f inbound.Feed, body []byte) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	h, err := s.stream(f)
	if err != nil {
		s.refused(f.Name, err.Error())
		streamAnswer(w, http.StatusServiceUnavailable, map[string]any{"error": "this feed cannot check what it is sent"})
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.rc == nil {
		// A batch before this one was taken and then could not be kept, so
		// what is held is what is on disk.
		if h.rc, err = streamReceiver(s.root, f); err != nil {
			s.refused(f.Name, err.Error())
			streamAnswer(w, http.StatusServiceUnavailable, map[string]any{"error": "this feed cannot check what it is sent"})
			return
		}
	}
	now := s.now().UTC()
	b, err := h.rc.Accept(r, body, now)
	var gap *auditstream.ErrGap
	switch {
	case errors.As(err, &gap):
		streamAnswer(w, http.StatusConflict, map[string]any{"holds": gap.Holds, "error": gap.Error()})
		return
	case err != nil:
		s.refused(f.Name, err.Error())
		streamAnswer(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return
	}
	// From here the receiver holds the batch in memory. Anything that stops
	// it being kept drops that, so the next batch is checked against what
	// is on disk and the sender, told nothing was taken, sends it again.
	events, err := inbound.StreamEvents(b.OCSF, now)
	if err != nil {
		h.rc = nil
		s.refused(f.Name, err.Error())
		streamAnswer(w, http.StatusBadRequest, map[string]any{"error": "the records are not readable"})
		return
	}
	if err := s.storeStream(f, events, now); err != nil {
		h.rc = nil
		streamAnswer(w, http.StatusServiceUnavailable, map[string]any{"error": "what was sent could not be stored"})
		return
	}
	if err := appendStreamLeaves(streamLeavesPath(s.root, f.Name), b.Leaves); err != nil {
		h.rc = nil
		streamAnswer(w, http.StatusServiceUnavailable, map[string]any{"error": "what was sent could not be kept"})
		return
	}
	streamAnswer(w, http.StatusOK, map[string]any{"holds": b.To})
}

// streamFeed fills in a new feed of this kind from the keys file.
func streamFeed(root string, f *inbound.Feed, opts map[string]string) ([]string, error) {
	if opts["keys"] == "" {
		return nil, errors.New("this feed checks Quilzo's batches against its published keys: " +
			"--keys FILE, where FILE is what `quilzo siem stream key --json` writes")
	}
	b, err := os.ReadFile(opts["keys"])
	if err != nil {
		return nil, err
	}
	k, err := inbound.ParseStreamKeys(b)
	if err != nil {
		return nil, err
	}
	f.Kind, f.Stream = inbound.AuditStream, k
	return []string{
		"batches are checked against " + k.KeyID + ", tree heads against " + k.HeadKeyID,
		"in Quilzo: quilzo config set siem.stream.url " + feedURL(root, f.Name),
	}, nil
}
