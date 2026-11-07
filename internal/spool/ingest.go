// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package spool

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"sync"
	"time"

	"github.com/aertun/aertun/internal/telemetry"
)

// Reading a file of events into the spool, in order, as fast as the disk
// allows rather than as fast as one core decodes JSON.
//
// One line per event, each written by Append, paid the writer's lock, a
// rewrite of the whole index and an fsync per line: a few dozen events a
// second, whatever the machine. Ingest splits the work three ways. One
// goroutine reads lines and cuts them into chunks; a pool decodes and
// checks the chunks in parallel; and the caller's goroutine writes each
// chunk with one AppendBatch, strictly in the order the chunks were read,
// so the spool holds the file's events in the file's order and the lock,
// the index and the fsyncs are paid once per chunk.
//
// The number of chunks in flight is bounded, so a slow chunk holding up
// the ones behind it cannot make the reordering buffer grow without limit:
// the reader waits for a slot before it cuts the next one.
//
// An error keeps the meaning a loop of Appends had: every event before the
// first bad line is stored, the bad line and everything after it is not,
// and the error names the line.

// IngestChunk is how many events one AppendBatch carries.
const IngestChunk = 1024

// ingestWorkers is how many chunks are decoded at once.
func ingestWorkers() int {
	n := runtime.GOMAXPROCS(0)
	if n > 8 {
		n = 8
	}
	if n < 1 {
		n = 1
	}
	return n
}

// chunk is lines cut from the input, with the line number of each.
type chunk struct {
	seq   int
	lines [][]byte
	at    []int
}

// decoded is a chunk turned into events: all of them, or those before the
// first line that failed, with the failure.
type decoded struct {
	seq    int
	events []telemetry.Event
	err    error
}

// Ingest reads JSON-lines events from r and appends them to the spool in
// the order they appear, returning how many were stored. prepare, when not
// nil, is applied to each event after decoding and before it is checked —
// the command line uses it to clear Received, which the spool stamps.
//
// A line longer than maxLine is an error, as is a line that is not an
// event or not a valid one. Blank lines are skipped.
func (s *Spool) Ingest(ctx context.Context, r io.Reader, maxLine int,
	prepare func(*telemetry.Event)) (int, error) {

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	workers := ingestWorkers()
	slots := make(chan struct{}, workers*4)
	jobs := make(chan chunk, workers)
	results := make(chan decoded, workers)
	readErr := make(chan error, 1)

	// The reader. It owns the scanner and closes jobs when the input ends,
	// fails, or the ingest is abandoned.
	go func() {
		defer close(jobs)
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64<<10), maxLine)
		cur := chunk{}
		send := func() bool {
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return false
			}
			select {
			case jobs <- cur:
			case <-ctx.Done():
				return false
			}
			cur = chunk{seq: cur.seq + 1}
			return true
		}
		for line := 1; sc.Scan(); line++ {
			text := bytes.TrimSpace(sc.Bytes())
			if len(text) == 0 {
				continue
			}
			cur.lines = append(cur.lines, append([]byte(nil), text...))
			cur.at = append(cur.at, line)
			if len(cur.lines) == IngestChunk && !send() {
				return
			}
		}
		if err := sc.Err(); err != nil {
			readErr <- fmt.Errorf("reading: %w", err)
		}
		if len(cur.lines) > 0 {
			send()
		}
	}()

	// The decoders.
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				d := decodeChunk(c, prepare, s.opt.Now)
				select {
				case results <- d:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	// The writer: the caller's goroutine, in read order.
	stored, next := 0, 0
	waiting := map[int]decoded{}
	for d := range results {
		waiting[d.seq] = d
		for {
			cur, ok := waiting[next]
			if !ok {
				break
			}
			delete(waiting, next)
			if len(cur.events) > 0 {
				if _, err := s.AppendBatch(cur.events); err != nil {
					return stored, err
				}
				stored += len(cur.events)
			}
			if cur.err != nil {
				return stored, cur.err
			}
			<-slots
			next++
		}
	}
	select {
	case err := <-readErr:
		return stored, err
	default:
	}
	return stored, nil
}

// decodeChunk turns a chunk's lines into events, stopping at the first
// line that is not a valid event. Validity is checked here, with the
// arrival time the spool will stamp standing in for the one it will
// stamp, so the line a problem is on is named exactly, and AppendBatch's
// own check never refuses a batch that holds good events before a bad one.
func decodeChunk(c chunk, prepare func(*telemetry.Event), now func() time.Time) decoded {
	out := decoded{seq: c.seq, events: make([]telemetry.Event, 0, len(c.lines))}
	for i, line := range c.lines {
		var e telemetry.Event
		if err := json.Unmarshal(line, &e); err != nil {
			out.err = fmt.Errorf("line %d is not an event: %w", c.at[i], err)
			return out
		}
		if prepare != nil {
			prepare(&e)
		}
		probe := e
		if probe.Received.IsZero() {
			probe.Received = now()
		}
		if err := probe.Validate(); err != nil {
			out.err = fmt.Errorf("line %d: %w", c.at[i], err)
			return out
		}
		out.events = append(out.events, e)
	}
	return out
}
