// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Scatter-gather over the segments: the read paths' fan-out.
//
// A window that touches many segments reads them one after another, and one
// sealed segment's read — open, seek where the sidecar has earned it, parse
// every line the window keeps — is independent of every other segment's. So
// the reads are scattered across a small pool of workers and gathered in
// segment order: the caller's function sees all of the first segment's
// events, then all of the second's, each segment's lines in file order.
// That is byte for byte the sequence the sequential loop produced, and it is
// not an optimization detail — the correlation watermark, the replay tests
// and every tally that assumes the last event seen is the newest stand on
// it — so the gather, not the scatter, is what this file is arranged around.
//
// The pool reads; it never decides. Which segments are read is settled by
// the caller — RangeWhere's window and keep, During's event-time bounds —
// before the first segment is opened, so a hunt's byte budget, a bloom's
// refusal and a cursor's window pick out exactly the segments they always
// did, and the parallelism moves work beside other work, never an answer.
//
// What a worker may do is bounded: one segment at a time, one 64 KiB read
// buffer, and no more than fanBuffer events held ahead of the gatherer's
// arrival at its segment, so a store of any size costs the pool a fixed
// amount of memory and a slow consumer stops the reads at the file rather
// than letting them run ahead through it.
package spool

import (
	"errors"
	"runtime"
	"sync"

	"github.com/aertun/aertun/internal/telemetry"
)

// fanBuffer is how many events one segment's worker may hold ahead of the
// gatherer's arrival at it. Large enough that the gatherer is never waiting
// on a parse that has already happened, small enough that the pool's whole
// memory is workers-times-this and nothing a segment's size can move.
const fanBuffer = 64

// fanMaxWorkers caps the pool. Sixteen concurrent segment reads saturate
// what the page cache and the disk queue have to give a parse-heavy reader;
// past that a worker only adds an open file and a buffer of events whose
// turn has not come.
const fanMaxWorkers = 16

// fanWorkers is how many segments are read at once: one per GOMAXPROCS,
// which is the cores the process actually has — inside a container, Go has
// tracked the cgroup CPU limit for it since 1.25 — capped at fanMaxWorkers
// and at the number of segments, which is all the work there is.
func fanWorkers(segments int) int {
	n := runtime.GOMAXPROCS(0)
	if n > fanMaxWorkers {
		n = fanMaxWorkers
	}
	if n > segments {
		n = segments
	}
	if n < 1 {
		n = 1
	}
	return n
}

// fanItem is one event on its way to the gatherer, or — as the last item on
// the channel, and only then — the error that ended that segment's read
// early.
type fanItem struct {
	ev  telemetry.Event
	err error
}

// errFanStopped is what a worker's emit returns once the gatherer has given
// up, because the caller's function erred or an earlier segment did, so the
// scan stops at its next line. Swallowed by the worker that receives it
// back: the gatherer that caused it has already decided what to return.
var errFanStopped = errors.New("the read was stopped behind the worker's back")

// inOrder runs one read per segment on a bounded pool of workers and hands
// every event to fn in exactly the order the sequential loop produced:
// reads[0]'s events in file order, then reads[1]'s, and so on.
//
// Errors keep the sequential loop's meaning. The first failing segment in
// order is the error returned — not the first to fail on the clock, which
// is a distinction only a parallel reader has to be careful about — and fn
// is called for no event of any segment after it, exactly as a sequential
// loop would never have opened those segments at all. Their bytes may well
// have been read by a worker that got there first; reading them changed
// nothing, because nothing of them was handed over. An error from fn
// returns that error and stops the walk the same way.
//
// fn is called by one goroutine — this one — always. The workers parse and
// filter; only the gatherer runs caller code, so a caller's closures need
// no synchronisation their sequential self did not have.
func inOrder(reads []func(emit func(telemetry.Event) error) error,
	fn func(telemetry.Event) error) error {

	if len(reads) < 2 {
		// One segment has nothing to overlap, and it is the incremental
		// reader's common case: a cursor or a hunt deep inside one segment.
		// The pool is set up only when there is a second segment to read
		// beside the first.
		for _, read := range reads {
			if err := read(fn); err != nil {
				return err
			}
		}
		return nil
	}

	res := make([]chan fanItem, len(reads))
	for i := range reads {
		res[i] = make(chan fanItem, fanBuffer)
	}
	// Closed the moment the gatherer returns, for whatever reason, so every
	// worker stops at its next line rather than parsing on for a consumer
	// that has gone.
	cancel := make(chan struct{})
	// The whole job list is queued before any read starts, so no worker is
	// ever waiting on a feeder that the gatherer is too busy to be.
	jobs := make(chan int, len(reads))
	for i := range reads {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	for range fanWorkers(len(reads)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				err := reads[i](func(e telemetry.Event) error {
					select {
					case res[i] <- fanItem{ev: e}:
						return nil
					case <-cancel:
						return errFanStopped
					}
				})
				if err == errFanStopped {
					err = nil
				}
				if err != nil {
					select {
					case res[i] <- fanItem{err: err}:
					case <-cancel:
					}
				}
				close(res[i])
			}
		}()
	}
	defer func() {
		close(cancel)
		wg.Wait()
	}()

	// Gather in segment order. Consuming res[0] to its close before res[1]
	// is opened for reading is what makes the sequence deterministic: the
	// same store read twice hands fn the same events in the same order,
	// whatever the workers did in between.
	for _, ch := range res {
		for it := range ch {
			if it.err != nil {
				return it.err
			}
			if err := fn(it.ev); err != nil {
				return err
			}
		}
	}
	return nil
}
