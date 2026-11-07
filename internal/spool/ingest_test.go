// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package spool

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/telemetry"
)

// ingestFile is n events as JSON lines, numbered in their messages, with
// blank lines scattered through it.
func ingestFile(t testing.TB, n int) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	for i := 0; i < n; i++ {
		line, err := json.Marshal(event(base, time.Time{}, fmt.Sprintf("n=%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
		if i%997 == 0 {
			b.WriteString("\n   \n")
		}
	}
	return &b
}

// stored is the spool's messages in the order it holds them.
func stored(t *testing.T, s *Spool) []string {
	t.Helper()
	var out []string
	if err := s.Scan(time.Time{}, time.Time{}, func(r *Row) error {
		out = append(out, r.Message())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// Thousands of events across many chunks, decoded in parallel, are held
// in the order the file had them, every one exactly once.
func TestIngestKeepsTheFilesOrder(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	const n = 5*IngestChunk + 123
	got, err := s.Ingest(context.Background(), ingestFile(t, n), MaxLine, nil)
	if err != nil || got != n {
		t.Fatalf("stored %d of %d: %v", got, n, err)
	}
	msgs := stored(t, s)
	if len(msgs) != n {
		t.Fatalf("the spool holds %d events, want %d", len(msgs), n)
	}
	for i, m := range msgs {
		if m != fmt.Sprintf("n=%d", i) {
			t.Fatalf("event %d is %q: the order was not kept", i, m)
		}
	}
	if s.Events() != n {
		t.Errorf("the index counts %d events, want %d", s.Events(), n)
	}
}

// A line that is not an event, in the middle of a chunk that is not the
// first: everything before it is stored, nothing from it on is, and the
// error names its line — counting the blank lines, as an editor would.
func TestIngestStopsAtTheBadLineAndStoresWhatCameBefore(t *testing.T) {
	for _, tc := range []struct {
		name, bad, want string
	}{
		{"not json", "{not an event", "is not an event"},
		{"not valid", `{"class_uid":1,"message":"no time, no source"}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &clock{at: base}
			s, _ := openAt(t, c, Options{})
			defer s.Close()
			file := ingestFile(t, 2*IngestChunk+500)
			lines := strings.Split(file.String(), "\n")
			// Line 1600 (1-based) in the file as written, blank lines
			// included.
			const at = 1600
			lines[at-1] = tc.bad
			before := 0
			for _, l := range lines[:at-1] {
				if strings.TrimSpace(l) != "" {
					before++
				}
			}
			got, err := s.Ingest(context.Background(),
				strings.NewReader(strings.Join(lines, "\n")), MaxLine, nil)
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("line %d", at)) ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the error does not name line %d: %v", at, err)
			}
			if got != before {
				t.Fatalf("reported %d stored, want the %d before the bad line", got, before)
			}
			if msgs := stored(t, s); len(msgs) != before {
				t.Fatalf("the spool holds %d events, want %d", len(msgs), before)
			}
		})
	}
}

// The command line clears Received, which the spool stamps; prepare runs
// before the event is checked and stored.
func TestIngestAppliesPrepareBeforeStoring(t *testing.T) {
	c := &clock{at: base}
	s, _ := openAt(t, c, Options{})
	defer s.Close()
	claimed := base.Add(-48 * time.Hour)
	line, _ := json.Marshal(event(base, claimed, "replayed"))
	if _, err := s.Ingest(context.Background(), bytes.NewReader(line), MaxLine,
		func(e *telemetry.Event) { e.Received = time.Time{} }); err != nil {
		t.Fatal(err)
	}
	var received time.Time
	_ = s.Scan(time.Time{}, time.Time{}, func(r *Row) error {
		received = r.Received()
		return nil
	})
	if !received.Equal(base) {
		t.Errorf("received %s, want the spool's own clock %s", received, base)
	}
}

// BenchmarkIngest stores events through Ingest; BenchmarkAppendPerLine is
// the loop of Appends it replaced. Both make every event durable.
func BenchmarkIngest(b *testing.B) {
	c := &clock{at: base}
	s, _ := openAt(b, c, Options{})
	defer s.Close()
	file := ingestFile(b, b.N).Bytes()
	b.ResetTimer()
	if _, err := s.Ingest(context.Background(), bytes.NewReader(file), MaxLine, nil); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkAppendPerLine(b *testing.B) {
	c := &clock{at: base}
	s, _ := openAt(b, c, Options{})
	defer s.Close()
	file := ingestFile(b, b.N).Bytes()
	b.ResetTimer()
	for _, line := range bytes.Split(file, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e telemetry.Event
		if err := json.Unmarshal(line, &e); err != nil {
			b.Fatal(err)
		}
		if _, err := s.Append(e); err != nil {
			b.Fatal(err)
		}
	}
}
