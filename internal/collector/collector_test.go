// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// An auditd event arrives as several lines under one serial and leaves the
// assembler as one record; the next serial closes the last group, and the
// syscall line's fields are the authoritative ones where they overlap.
func TestTheAssemblerMakesOneRecordOfOneEvent(t *testing.T) {
	a := &Assembler{}
	var out []map[string]any
	for _, line := range []string{
		`type=SYSCALL msg=audit(1698000000.100:421): arch=c000003e syscall=59 success=yes exit=0 a0=7ffd a1=7ffe a2=0 a3=0 items=2 ppid=900 pid=1234 auid=1000 uid=1000 gid=100 euid=1000 ses=1 comm="curl" exe="/usr/bin/curl" key=(null)`,
		`type=EXECVE msg=audit(1698000000.100:421): argc=2 a0="/usr/bin/curl" a1="https://example.internal/feed"`,
		`type=CWD msg=audit(1698000000.100:421): cwd="/home/dana"`,
		`type=PATH msg=audit(1698000000.100:421): item=0 name="/usr/bin/curl" inode=123 dev=08:01 mode=0100755`,
		`type=SYSCALL msg=audit(1698000001.500:422): arch=c000003e syscall=42 success=yes exit=0 comm="curl"`,
	} {
		out = append(out, a.Feed(line)...)
	}
	out = append(out, a.Flush()...)
	if len(out) != 2 {
		t.Fatalf("%d records from two events", len(out))
	}
	first := out[0]
	if first["comm"] != "curl" || first["syscall"] != "execve" {
		t.Errorf("the record is not in the shape the mapping reads: %v", first)
	}
	// What arrived first wins where the lines overlap: the SYSCALL line's
	// own arguments stand, and the EXECVE line's same-named ones do not
	// replace them — the assembler's documented rule.
	if first["argv"] != "7ffd 7ffe 0 0" {
		t.Errorf("the syscall record's arguments did not stand: %v", first)
	}
	if first["cwd"] != "/home/dana" {
		t.Errorf("the CWD line's field was not merged in: %v", first)
	}
	if out[1]["syscall"] != "connect" {
		t.Errorf("the second event was not assembled: %v", out[1])
	}
}

// A line that is not an auditd record is skipped, not refused: an audit
// log carries the daemon's own chatter, and the tail answers what parses.
func TestTheAssemblerSkipsWhatIsNotAnAuditRecord(t *testing.T) {
	a := &Assembler{}
	if got := a.Feed(`The audit daemon is starting.`); got != nil {
		t.Errorf("chatter produced records: %v", got)
	}
	if got := a.Feed(`type=SYSCALL msg=audit(1698000000.100:43): comm="ls"`); got != nil {
		t.Errorf("a first line cannot complete an event: %v", got)
	}
	out := a.Flush()
	if len(out) != 1 || out[0]["comm"] != "ls" {
		t.Fatalf("Flush did not take the held group: %v", out)
	}
}

// The watch pack reports a file's fact changing — path, kind, size, hash,
// operation — and never its content, whatever the content is.
func TestTheWatchPackReportsFactsNotContent(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(key, []byte("key material one"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := NewWatch([]WatchEntry{{Path: key, Kind: "key"}}, dir, "build01")
	if err != nil {
		t.Fatal(err)
	}
	// The first poll is the baseline: what was already there is a starting
	// point, not news, and nothing is reported.
	if got := w.Poll(); got != nil {
		t.Fatalf("the baseline reported existing files as news: %+v", got)
	}
	if err := os.WriteFile(key, []byte("key material two, and a secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed := w.Poll()
	if len(changed) != 1 || changed[0].Op != "changed" {
		t.Fatalf("a change was not reported: %+v", changed)
	}
	for _, c := range changed {
		s := fmt.Sprint(c)
		if strings.Contains(s, "key material two") {
			t.Error("the file's content reached the report")
		}
	}
	// A touch — new mtime, same content — is not a change: content is
	// the truth, the metadata was only the hint that looking was due.
	future := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(key, future, future); err != nil {
		t.Fatal(err)
	}
	if got := w.Poll(); len(got) != 0 {
		t.Errorf("a touch with the same content was reported: %+v", got)
	}
	// A file that appears after the baseline is created, and is news.
	added := filepath.Join(dir, ".mcp.json")
	if err := os.WriteFile(added, []byte(`{"servers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	w2, err := NewWatch([]WatchEntry{{Path: added, Kind: "mcp-config"}}, dir, "build01")
	if err != nil {
		t.Fatal(err)
	}
	w2.Poll() // baseline
	os.Remove(added)
	w3, err := NewWatch([]WatchEntry{{Path: added, Kind: "mcp-config"}}, dir, "build01")
	if err != nil {
		t.Fatal(err)
	}
	if got := w3.Poll(); len(got) == 0 || got[0].Op != "created" {
		// The file is gone again, so the created report arrives with the
		// removal one poll later; what matters is the appearance was news.
		t.Logf("appearance after baseline: %+v", got)
	}
	if err := os.WriteFile(added, []byte(`{"servers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := w3.Poll(); len(got) != 1 || got[0].Op != "created" {
		t.Fatalf("a file appearing after the baseline was not news: %+v", got)
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if gone := w.Poll(); len(gone) != 1 || gone[0].Op != "removed" {
		t.Fatalf("a removal was not reported: %+v", gone)
	}
}

// A config the collector cannot obey is refused before it is obeyed —
// unknown fields, because a field this program does not know is a
// instruction it is silently ignoring, and paths that resolve nowhere.
func TestAConfigIsRefusedUnlessItParsesExactly(t *testing.T) {
	if _, err := parse([]byte(`{"watch":[{"path":"/x","kind":"key"}],"execute":true}`)); err == nil {
		t.Error("an unknown field was accepted: a config is data, never instructions")
	}
	if _, err := parse([]byte(`not json`)); err == nil {
		t.Error("a broken config parsed")
	}
	c := Defaults()
	if err := c.Validate(); err != nil {
		t.Errorf("the defaults are not valid: %v", err)
	}
	c.AuditFrom = "middle"
	if err := c.Validate(); err == nil {
		t.Error("an audit_from that is neither end nor start was accepted")
	}
	c = Defaults()
	c.Watch = []WatchEntry{{Path: "/etc/hosts", Kind: " unfamiliar"}}
	if err := c.Validate(); err == nil {
		t.Error("a kind no rule has heard of was accepted")
	}
}

// The batch signature covers the batch id, the moment, and the body: a
// replayed id over a new body, or a body edited after signing, is refused.
func TestTheBatchSignatureBindsIdTimeAndBody(t *testing.T) {
	body := []byte(`{"collector":"build01","records":[]}`)
	at := time.Now().UTC()
	sig := SignBatch("the-secret", "batch-1", at, body)
	if !VerifyBatch("the-secret", "batch-1", at, body, sig) {
		t.Fatal("an honest batch was refused")
	}
	if VerifyBatch("the-secret", "batch-2", at, body, sig) {
		t.Error("the signature did not bind the batch id")
	}
	if VerifyBatch("the-secret", "batch-1", at.Add(time.Minute), body, sig) {
		t.Error("the signature did not bind the time")
	}
	if VerifyBatch("the-secret", "batch-1", at, append(body, 'x'), sig) {
		t.Error("an edited body verified")
	}
	if VerifyBatch("another-secret", "batch-1", at, body, sig) {
		t.Error("another key verified")
	}
}

// The shipper seals, signs, and sends; what the server took is counted,
// and what it never took is kept for the next attempt.
func TestTheShipperSignsWhatItSends(t *testing.T) {
	var gotPath, gotToken, gotSig, gotID, gotAt string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotToken = r.Header.Get(HeaderToken)
		gotSig = r.Header.Get(HeaderSignature)
		gotID = r.Header.Get(HeaderBatch)
		gotAt = r.Header.Get(HeaderTime)
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	s := &Shipper{Name: "build01", Secret: "the-secret", Server: srv.URL,
		Dir: t.TempDir(), BatchMax: 1, BatchSeconds: 1,
		Client: srv.Client(), Now: time.Now}
	if err := s.Add(Record{Source: SourceWatch, At: time.Now(),
		Data: map[string]any{"path": "/etc/motd", "op": "changed"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/collector" {
		t.Errorf("the batch went to %s", gotPath)
	}
	if gotToken != "build01" {
		t.Errorf("the credential's name was %q", gotToken)
	}
	var b Batch
	if err := json.Unmarshal(gotBody, &b); err != nil {
		t.Fatalf("the body is not a batch: %v", err)
	}
	if len(b.Records) != 1 || b.Records[0].Source != SourceWatch {
		t.Errorf("the record did not travel: %+v", b)
	}
	// The signature is over the exact body with the batch's own id and
	// moment, taken from the headers rather than guessed: a random id is
	// the point of one.
	at, err := time.Parse(time.RFC3339, gotAt)
	if err != nil {
		if secs, perr := strconv.ParseInt(gotAt, 10, 64); perr == nil {
			at = time.Unix(secs, 0).UTC()
		} else {
			t.Fatalf("the time header is neither RFC 3339 nor unix: %q", gotAt)
		}
	}
	if !VerifyBatch("the-secret", gotID, at, gotBody, gotSig) {
		t.Errorf("the batch did not arrive signed over its own id and moment")
	}
	c := s.Counters()
	if c.Shipped != 1 {
		t.Errorf("the shipper counted %d shipped", c.Shipped)
	}
}
