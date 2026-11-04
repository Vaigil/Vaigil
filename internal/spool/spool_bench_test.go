// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package spool

import (
	"fmt"
	"testing"
	"time"

	"github.com/aeroprove/aeroprove/internal/telemetry"
)

// ingestBatch is the workload every append benchmark writes: a thousand
// events a push source hands over together, each the size a real sign-in
// record marshals to.
func ingestBatch(n int) []telemetry.Event {
	out := make([]telemetry.Event, 0, n)
	for i := range n {
		at := base.Add(time.Duration(i) * time.Second)
		out = append(out, event(at, at,
			fmt.Sprintf("sign-in %d for user-%d from 203.0.113.%d", i, i%500,
				i%254+1)))
	}
	return out
}

// BenchmarkAppendOneByOne is the ingest path as one event at a time: each
// event pays for its own lock, its own whole-index rewrite and its own
// fsync. The store is fresh per iteration, so what is timed is a thousand
// appends and not a growing index.
func BenchmarkAppendOneByOne(b *testing.B) {
	evs := ingestBatch(1000)
	for b.Loop() {
		s, err := Open(b.TempDir(), Options{})
		if err != nil {
			b.Fatal(err)
		}
		for _, e := range evs {
			if _, aerr := s.Append(e); aerr != nil {
				b.Fatal(aerr)
			}
		}
		if err := s.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAppendBatched is the same thousand events handed over together:
// one lock, one index rewrite, one fsync.
func BenchmarkAppendBatched(b *testing.B) {
	evs := ingestBatch(1000)
	for b.Loop() {
		s, err := Open(b.TempDir(), Options{})
		if err != nil {
			b.Fatal(err)
		}
		if _, err := s.AppendBatch(evs); err != nil {
			b.Fatal(err)
		}
		if err := s.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
