// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package collector

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// pollWithin fails the test rather than hanging it when a poll blocks,
// which is the failure this file exists to catch.
func pollWithin(t *testing.T, w *Watch) []Change {
	t.Helper()
	done := make(chan []Change, 1)
	go func() { done <- w.Poll() }()
	select {
	case c := <-done:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("a poll blocked: something in the watched set stalled the recorder")
		return nil
	}
}

// A watched key replaced by a fifo is reported as what it became, and
// nothing is read from it — opening a fifo for reading blocks until
// somebody writes, and a recorder that blocks has gone quiet.
func TestAWatchedFileReplacedByAFifoIsReportedNotRead(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(key, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := NewWatch([]WatchEntry{{Path: key, Kind: "key"}}, dir, "build01")
	if err != nil {
		t.Fatal(err)
	}
	if c := pollWithin(t, w); c != nil {
		t.Fatalf("the baseline reported: %+v", c)
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(key, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	c := pollWithin(t, w)
	if len(c) != 1 || c[0].Op != OpChanged || c[0].Type != "fifo" || c[0].SHA256 != "" {
		t.Fatalf("after the swap: %+v", c)
	}
	if again := pollWithin(t, w); len(again) != 0 {
		t.Errorf("an unchanged fifo was reported again: %+v", again)
	}
}

// A fifo appearing in a watched directory is reported as one, and does not
// stop the directory's other files being seen.
func TestAFifoInAWatchedDirectoryDoesNotStallTheRest(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWatch([]WatchEntry{{Path: dir, Kind: "key"}}, dir, "build01")
	if err != nil {
		t.Fatal(err)
	}
	pollWithin(t, w) // the baseline
	if err := syscall.Mkfifo(filepath.Join(dir, "trap"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "authorized_keys"), []byte("ssh-ed25519 AAAA"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := map[string]Change{}
	for _, c := range pollWithin(t, w) {
		got[filepath.Base(c.Path)] = c
	}
	if c := got["authorized_keys"]; c.Op != OpCreated || c.SHA256 == "" || c.Type != "" {
		t.Errorf("the regular file: %+v", c)
	}
	if c := got["trap"]; c.Op != OpCreated || c.Type != "fifo" || c.SHA256 != "" {
		t.Errorf("the fifo: %+v", c)
	}
}
