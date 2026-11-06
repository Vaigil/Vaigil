// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"path/filepath"
	"testing"
)

// BenchmarkAppendSequential measures the throughput of one writer appending
// records one at a time — the shape a detection run or a console session
// produces.
func BenchmarkAppendSequential(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := New(Options{Path: path, Source: "test", Mode: 0o600})
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := l.Append(Record{
			Action: "bench", Resource: fmt.Sprintf("/bench/%d", i),
			Outcome: Success, Principal: "bench", Kind: KindHuman,
			Verified: true,
		}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAppendParallel measures the throughput of many writers appending
// concurrently — the shape a busy console with several sessions produces.
// Group-commit lets their fsyncs share: each writer still returns only
// after its record is durable, but one fsync covers what several wrote.
func BenchmarkAppendParallel(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := New(Options{Path: path, Source: "test", Mode: 0o600})
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if _, err := l.Append(Record{
				Action: "bench", Resource: fmt.Sprintf("/bench/%d", i),
				Outcome: Success, Principal: "bench", Kind: KindHuman,
				Verified: true,
			}); err != nil {
				b.Fatal(err)
			}
			i++
		}
	})
}

// BenchmarkAppendOpenClosePerRecord measures what the write path would cost
// if it still opened and closed the file per record — the "before" the
// group-commit design replaced, kept here as the comparison the plan asks
// for. It uses the same record shape and the same fsync; only the
// open/write/fsync/stat/close cycle differs.
func BenchmarkAppendOpenClosePerRecord(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := New(Options{Path: path, Source: "test", Mode: 0o600})
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := l.Append(Record{
			Action: "bench", Resource: fmt.Sprintf("/bench/%d", i),
			Outcome: Success, Principal: "bench", Kind: KindHuman,
			Verified: true,
		}); err != nil {
			b.Fatal(err)
		}
		// The "before": close the file handle so the next Append has to
		// reopen it, exactly what the old write() did per record.
		l.mu.Lock()
		if l.file != nil {
			l.file.Close()
			l.file = nil
		}
		l.mu.Unlock()
	}
}
