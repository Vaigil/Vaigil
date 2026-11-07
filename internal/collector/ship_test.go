// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The drain quarantines a file whose name is too short to carry a batch
// id, instead of slicing into it and panicking.
func TestTheDrainQuarantinesANameTooShortToCarryAnId(t *testing.T) {
	dir := t.TempDir()
	short := filepath.Join(dir, "x.json")
	if err := os.WriteFile(short, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Shipper{Name: "build01", Secret: "s", Server: "http://unused",
		Dir: dir, Client: http.DefaultClient, Now: time.Now,
		Logf: func(string, ...any) {}}
	s.drain(context.Background())
	if _, err := os.Stat(short); !os.IsNotExist(err) {
		t.Error("the short-named file was not quarantined")
	}
	if c := s.Counters(); c.Quarantined != 1 || c.Dropped != 0 {
		t.Errorf("counted %d quarantined and %d dropped, want 1 and 0",
			c.Quarantined, c.Dropped)
	}
}

// Quarantine renames the file aside and counts it; the evidence is never
// deleted, only set aside where nothing lists it.
func TestQuarantineSetsTheFileAsideAndCountsIt(t *testing.T) {
	dir := t.TempDir()
	name := "0000000000000001-abcdef.json"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(`{"records":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Shipper{Name: "build01", Secret: "s", Server: "http://unused",
		Dir: dir, Client: http.DefaultClient, Now: time.Now,
		Logf: func(string, ...any) {}}
	s.quarantine(name, "test reason")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the original name still exists")
	}
	aside := filepath.Join(dir, "."+name+".quarantine")
	body, err := os.ReadFile(aside)
	if err != nil {
		t.Fatalf("the quarantined copy was not kept: %v", err)
	}
	if string(body) != `{"records":[]}` {
		t.Error("the quarantined copy lost its content")
	}
	if c := s.Counters(); c.Quarantined != 1 || c.Dropped != 0 {
		t.Errorf("counted %d quarantined and %d dropped, want 1 and 0",
			c.Quarantined, c.Dropped)
	}
	// The spool no longer lists it.
	if files := s.spoolFiles(); len(files) != 0 {
		t.Errorf("the quarantined file is still listed: %v", files)
	}
}

// A file the drain can neither read nor move aside — a spool directory
// that has gone read-only — is passed over: the batch behind it still
// leaves, the drain returns rather than spinning on it, and it is counted
// and said once however many passes see it.
func TestAFileThatCannotBeSetAsideDoesNotHoldTheBatchesBehindIt(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads and renames regardless of permissions")
	}
	dir := t.TempDir()
	bad := "0000000000000001-" + strings.Repeat("a", 32) + ".json"
	good := "0000000000000002-" + strings.Repeat("b", 32) + ".json"
	if err := os.WriteFile(filepath.Join(dir, bad), []byte(`{"records":[]}`), 0o000); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, good), []byte(`{"records":[{}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var sent atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderBatch) == strings.Repeat("b", 32) {
			sent.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	// Read-only, so the unreadable file cannot be renamed aside; and the
	// sent batch cannot be removed either, which ends the pass.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	var said atomic.Int64
	s := &Shipper{Name: "build01", Secret: "s", Server: srv.URL,
		Dir: dir, Client: srv.Client(), Now: time.Now,
		Logf: func(f string, _ ...any) {
			if strings.HasPrefix(f, "cannot send") {
				said.Add(1)
			}
		}}
	done := make(chan struct{})
	go func() {
		s.drain(context.Background())
		s.drain(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the drain is stuck on a file it cannot set aside")
	}
	if sent.Load() == 0 {
		t.Error("the batch behind the stuck file never left")
	}
	if c := s.Counters(); c.Quarantined != 1 {
		t.Errorf("counted %d quarantined over two passes, want 1", c.Quarantined)
	}
	if said.Load() != 1 {
		t.Errorf("said it %d times, want once", said.Load())
	}
}

// Only what Seal writes is a batch name: a name of the right length that
// is not hex, or that has no dash, is not sliced into an id.
func TestOnlyASealedNameCarriesAnId(t *testing.T) {
	id := strings.Repeat("c", 32)
	if got, ok := batchName("00000000000000ff-" + id + ".json"); !ok || got != id {
		t.Errorf("a sealed name was refused: %q %v", got, ok)
	}
	for _, name := range []string{
		"x.json",
		"00000000000000ff-" + id + ".jsox",
		"00000000000000ff_" + id + ".json",
		"00000000000000fg-" + id + ".json",
		"00000000000000ff-" + strings.Repeat("C", 32) + ".json",
		"00000000000000ff-" + id + "0.json",
	} {
		if _, ok := batchName(name); ok {
			t.Errorf("%q was taken for a batch name", name)
		}
	}
}
