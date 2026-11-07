// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countSyncs replaces the fsync with one that counts, for the length of a
// test, and returns the counter.
func countSyncs(t *testing.T) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	real := syncFile
	syncFile = func(f *os.File) error {
		n.Add(1)
		return real(f)
	}
	t.Cleanup(func() { syncFile = real })
	return &n
}

// One handle shared by many goroutines, as a server holds one log for every
// request it audits: every record lands once, the chain is one chain, each
// caller is handed the entry that was written for it, and the records
// shared fsyncs — fewer fsyncs than records is what proves the commits were
// grouped at all.
func TestConcurrentAppendsShareCommitsAndKeepOneChain(t *testing.T) {
	syncs := countSyncs(t)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(Options{Path: path, Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	const writers, each = 32, 20
	var wg sync.WaitGroup
	got := make(chan *Event, writers*each)
	for g := 0; g < writers; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				e, err := l.Append(rec(g*1000 + i))
				if err != nil {
					t.Error(err)
					return
				}
				got <- e
			}
		}(g)
	}
	wg.Wait()
	close(got)

	events, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != writers*each {
		t.Fatalf("%d entries for %d records", len(events), writers*each)
	}
	if ok, problems := Verify(events); !ok {
		t.Fatalf("the chain is broken: %v", problems)
	}
	bySeq := map[int64]Event{}
	for _, e := range events {
		bySeq[e.Seq] = e
	}
	seen := map[int64]bool{}
	for e := range got {
		if seen[e.Seq] {
			t.Fatalf("two callers were handed entry %d", e.Seq)
		}
		seen[e.Seq] = true
		if w, ok := bySeq[e.Seq]; !ok || w.Hash != e.Hash || w.Principal != e.Principal {
			t.Fatalf("a caller was handed entry %d, which is not what was written", e.Seq)
		}
	}
	if n := syncs.Load(); n >= int64(writers*each) {
		t.Errorf("%d fsyncs for %d records: no commit was shared", n, writers*each)
	}
}

// A failed fsync refuses the records it carried and leaves the chain whole:
// the next commit picks the chain up from what the file actually holds, so
// it follows the refused entry if that reached the file, rather than
// writing a second entry with the same sequence number after it.
func TestAFailedSyncDoesNotForkTheChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(Options{Path: path, Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(rec(1)); err != nil {
		t.Fatal(err)
	}
	real := syncFile
	syncFile = func(*os.File) error { return errors.New("input/output error") }
	_, err = l.Append(rec(2))
	syncFile = real
	if err == nil {
		t.Fatal("a record whose fsync failed was reported as written")
	}
	next, err := l.Append(rec(3))
	if err != nil {
		t.Fatal(err)
	}
	events, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if ok, problems := Verify(events); !ok {
		t.Fatalf("the chain forked after a failed fsync: %v", problems)
	}
	last := events[len(events)-1]
	if last.Seq != next.Seq || last.Hash != next.Hash {
		t.Fatalf("the entry handed back is not the file's last: %+v", next)
	}
	for i, e := range events {
		if e.Seq != int64(i+1) {
			t.Fatalf("entry %d has sequence %d", i+1, e.Seq)
		}
	}
}

// A record that cannot be written at all — the file cannot be opened —
// is refused, and the chain carries on correctly once it can.
func TestAFailedWriteIsRefusedAndTheChainCarriesOn(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a read-only file regardless")
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(Options{Path: path, Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(rec(1)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(rec(2)); err == nil {
		t.Fatal("a record that could not be written was reported as written")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := l.Append(rec(3))
	if err != nil {
		t.Fatal(err)
	}
	if e.Seq != 2 {
		t.Errorf("the refused record took a sequence number: next is %d", e.Seq)
	}
	if _, ok, problems, _ := VerifyFile(path); !ok {
		t.Fatalf("the chain is broken: %v", problems)
	}
}

// crashChild is set in the process TestAKilledWriterLosesNoAcknowledgedRecord
// starts: it appends from many goroutines until it is killed, printing each
// sequence number only after Append has returned it.
const crashChild = "AERTUN_AUDIT_CRASH_CHILD"

// TestAKilledWriterLosesNoAcknowledgedRecord kills a writer mid-flight,
// with commits in progress, and checks that every record it had been told
// was written is in the file and the chain up to it verifies; and that the
// log takes the next record afterwards. A SIGKILL leaves the page cache
// alone, so this proves what a process crash can do, not a power cut: that
// nothing is acknowledged before it is in the file, and that a batch cut
// short leaves a torn line, not a fork.
func TestAKilledWriterLosesNoAcknowledgedRecord(t *testing.T) {
	if path := os.Getenv(crashChild); path != "" {
		crashWriter(path)
		return
	}
	if testing.Short() {
		t.Skip("starts and kills a process")
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	cmd := exec.Command(os.Args[0], "-test.run=^TestAKilledWriterLosesNoAcknowledgedRecord$")
	cmd.Env = append(os.Environ(), crashChild+"="+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	acked := map[int64]bool{}
	sc := bufio.NewScanner(stdout)
	deadline := time.Now().Add(20 * time.Second)
	for sc.Scan() && len(acked) < 300 && time.Now().Before(deadline) {
		if n, err := strconv.ParseInt(strings.TrimPrefix(sc.Text(), "ack "), 10, 64); err == nil {
			acked[n] = true
		}
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if len(acked) == 0 {
		t.Fatal("the writer acknowledged nothing before it was killed")
	}

	events, _ := Read(path) // a torn last line is expected and reported
	if ok, problems := Verify(events); !ok {
		t.Fatalf("the chain up to the crash is broken: %v", problems)
	}
	inFile := map[int64]bool{}
	for _, e := range events {
		inFile[e.Seq] = true
	}
	for n := range acked {
		if !inFile[n] {
			t.Errorf("record %d was acknowledged and is not in the file", n)
		}
	}
	// And the log carries on from the last whole entry.
	l, err := New(Options{Path: path, Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	e, err := l.Append(rec(0))
	if err != nil {
		t.Fatal(err)
	}
	if want := events[len(events)-1].Seq + 1; e.Seq != want {
		t.Errorf("after the crash the next entry is %d, want %d", e.Seq, want)
	}
}

func crashWriter(path string) {
	l, err := New(Options{Path: path, Source: "crash"})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var mu sync.Mutex
	for g := 0; g < 16; g++ {
		go func(g int) {
			for i := 0; ; i++ {
				e, err := l.Append(rec(g*1_000_000 + i))
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(2)
				}
				mu.Lock()
				fmt.Printf("ack %d\n", e.Seq)
				mu.Unlock()
			}
		}(g)
	}
	select {}
}
