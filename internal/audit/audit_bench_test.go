// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"
)

// The audit log's write path, measured through the public API only, so the
// same benchmark runs against any version of it. Every record is durable
// when Append returns, so fsync dominates both: one writer pays one fsync
// per record whatever the design, and what concurrent writers in one
// process can share is the fsync.

func BenchmarkAppendSequential(b *testing.B) {
	l, err := New(Options{Path: filepath.Join(b.TempDir(), "audit.jsonl"), Source: "bench"})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := l.Append(rec(i)); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAppendParallel is one handle shared by many goroutines, as a
// server holds one log for every request it audits.
func BenchmarkAppendParallel(b *testing.B) {
	l, err := New(Options{Path: filepath.Join(b.TempDir(), "audit.jsonl"), Source: "bench"})
	if err != nil {
		b.Fatal(err)
	}
	b.SetParallelism(16)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if _, err := l.Append(rec(i)); err != nil {
				b.Error(err)
				return
			}
			i++
		}
	})
}
