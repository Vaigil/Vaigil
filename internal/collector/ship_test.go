// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
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
	if c := s.Counters(); c.Dropped != 1 {
		t.Errorf("counted %d dropped, want 1", c.Dropped)
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
	if c := s.Counters(); c.Dropped != 1 {
		t.Errorf("counted %d dropped, want 1", c.Dropped)
	}
	// The spool no longer lists it.
	if files := s.spoolFiles(); len(files) != 0 {
		t.Errorf("the quarantined file is still listed: %v", files)
	}
}
