// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aeroprove/aeroprove/internal/audit"
	"github.com/aeroprove/aeroprove/internal/finding"
)

// The live stream: server-sent events over the audit log.
//
// The console's screens are photographs — counted at request time, still until
// the next navigation. For a security console that stillness is a small lie:
// the thing being watched is moving, and the person watching is the one who
// has to notice. One endpoint, GET /live, turns the append-only audit log —
// already the journal of everything this program and its people did — into a
// stream the Today page can follow.
//
// # Why the audit log is the source
//
// Every surface that changes the things Today counts — a decision on a
// finding, a case opened, an automation held for approval, an agent's call
// refused — already writes a record there, hash-chained and sequenced. The
// sequence number is the cursor: it is assigned under the write lock, so it
// is strictly increasing, which makes "everything after N" a replayable
// range. Detecting events twice — once for the log, once for the stream —
// would be two copies of one fact that can disagree, which is the shape this
// codebase refuses everywhere else.
//
// # Why no cursor file
//
// The selfwatch pass (detect's self.json) keeps its place in a file because
// it is one batch process with one position. A live console is neither: each
// browser tab holds its own position, and the admin process is given the log
// as a reader (LoadAudit) and deliberately does not know where the store
// lives — after the separated-writer work it must not write beside it. The
// browser is the persistence: EventSource sends Last-Event-ID on reconnect,
// and the id on every frame is the audit Seq, so a resume is a range read of
// the same chain. A fresh connection starts at the end, which is the honest
// position for a screen that says "live" rather than one that replays a
// day's history uninvited.
//
// # Untrusted text never crosses this boundary
//
// The audit log's Detail fields carry words people and models typed —
// reasons, notes, error prose. The stream is read by script on a page that
// renders whatever arrives, so it gets the same treatment as every other
// untrusted surface here: payloads are ids, kinds, states and counters from
// a closed vocabulary, selected by the mapping below. Anything a person
// typed stays in the log, where it is labelled as what it is.
//
// # The cap
//
// Each stream holds a connection and re-reads the log on a short timer, so
// the number of them is bounded per process. Past the cap the endpoint
// refuses politely (503 with Retry-After): EventSource treats a non-200 as a
// failure and backs off on its own, so the browser is never left spinning,
// and one person opening six tabs cannot make the console its own outage.
// One stream per session is the expected load; the cap is for the case
// nobody planned for.

const (
	// livePoll is how often a stream re-reads the audit log. The log is
	// append-only and read whole, exactly as the selfwatch pass reads it, so
	// "as it happens" means a short timer rather than a filesystem watch —
	// which the standard library does not have, and inotify for one file
	// re-read whole anyway would be complexity buying two seconds.
	livePoll = 2 * time.Second

	// livePing is the keep-alive interval. A comment line costs a client
	// nothing — every EventSource implementation ignores lines that start
	// with a colon — and it is the only thing that keeps intermediaries that
	// idle-close connections (many proxies time out at 60s of silence) from
	// silently dropping a stream that is quiet because the estate is quiet.
	livePing = 15 * time.Second

	// liveLife is the longest a stream is held open. EventSource reconnects
	// by itself when a stream ends, carrying Last-Event-ID, so closing on a
	// schedule is invisible to the person watching: it exists so a
	// long-lived connection cannot outlive a credential change, a throttle
	// decision or a proxy's idea of a maximum request, and so the process
	// recovers slots without waiting for clients to go away.
	liveLife = 10 * time.Minute

	// liveMaxStreams is the per-process cap on concurrent streams, and the
	// number the refusal names. Eight is a console's worth — several people,
	// several tabs — on a deployment whose whole thesis is one small process.
	liveMaxStreams = 8
)

// liveTiming is the clock a stream runs on. The defaults above are the
// production values; a test passes its own so that pings, polls and
// lifetimes are observed in milliseconds rather than slept through.
type liveTiming struct {
	poll, ping, life time.Duration
}

var liveDefaults = liveTiming{poll: livePoll, ping: livePing, life: liveLife}

// liveGate is the stream semaphore, made once per server. A Server built by
// hand (a test, or a future embedding) has no slots until the first stream
// asks, so the cap governs every path rather than only the ones that went
// through New.
func (s *Server) liveGate() chan struct{} {
	s.liveOnce.Do(func() {
		s.liveSlots = make(chan struct{}, liveMaxStreams)
	})
	return s.liveSlots
}

// handleLive is GET /live: a console page resource, not an agent API.
//
// It is authenticated by the same session as the screen beside it — the
// browser sends the console's cookie, the CSP's connect-src 'self' already
// permits the same-origin connection, and nothing about the stream reaches
// further than a page load does. It is refused before anything is said about
// streams to a caller without a session, for the same reason the rest of the
// console refuses: an anonymous answer is an answer.
func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "the live stream is read with GET", http.StatusMethodNotAllowed)
		return
	}
	// The principal is resolved and never used again: opening the stream is
	// the one act, and what it carries is filtered by the same grants as the
	// screens (an event about a screen this person cannot open counts for
	// nothing they can see, and the counters they follow link there). The
	// stream is not a per-person feed; it is the page's.
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	// A build with no audit reader has nothing to stream, and a stream that
	// says "live" while holding silence would be the lie the badge exists to
	// prevent. Refused, so the client falls back to the poll mode below.
	if s.LoadAudit == nil {
		http.Error(w, "this build has no audit log to stream, so the console "+
			"cannot be live. The pages still work; they reload instead",
			http.StatusServiceUnavailable)
		return
	}
	// The cap is checked after authentication: a refusal here names a number
	// to a caller already entitled to hear it, and refusing first would tell
	// an anonymous one that the endpoint exists.
	gate := s.liveGate()
	select {
	case gate <- struct{}{}:
		defer func() { <-gate }()
	default:
		w.Header().Set("Retry-After", "10")
		http.Error(w, fmt.Sprintf("%d live streams are already open; this "+
			"console holds at most %d. The browser retries on its own, or "+
			"close another tab of this console",
			len(gate), liveMaxStreams), http.StatusServiceUnavailable)
		return
	}
	s.streamLive(w, r, liveDefaults)
}

// streamLive writes the event stream until the request ends, the lifetime
// runs out, or a write fails. It runs with the stream slot held.
//
// Flushing goes through an http.ResponseController rather than a Flusher
// type assertion: the flash middleware wraps the ResponseWriter, and a
// wrapper that does not itself implement Flush would quietly un-flush
// every stream behind it. The controller walks the wrappers — Unwrap is
// how — and errors on a writer that cannot flush at all, which ends this
// stream at once rather than buffering it into a poll with extra steps.
func (s *Server) streamLive(w http.ResponseWriter, r *http.Request, t liveTiming) {
	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	// Told to proxies in front (nginx and friends buffer responses by
	// default, which would hold every frame until the buffer filled — a live
	// stream delivered minutes late and then all at once). The middleware's
	// no-store already covers the browser and anything between that listens.
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return // headers first, so the client sees a stream, not a hang
	}

	// Where the stream starts. Last-Event-ID is the browser's own bookmark —
	// its last received Seq — and anything the log holds after it is the gap
	// a reconnect is asking to fill. Without it, the end of the log: live
	// means from now, not a replay nobody asked for.
	events, err := s.LoadAudit()
	if err != nil {
		// Nothing has been promised yet beyond the stream existing. End it
		// with a word for whoever is watching a wire; the client reconnects
		// and the log is usually back.
		fmt.Fprint(w, ": the audit log could not be read; reconnecting\n\n")
		_ = rc.Flush()
		return
	}
	var cursor int64
	for _, e := range events {
		if e.Seq > cursor {
			cursor = e.Seq
		}
	}
	if id := strings.TrimSpace(r.Header.Get("Last-Event-ID")); id != "" {
		// Clamped to the log's end: a bookmark from before the log was
		// rebuilt names a position that no longer exists, and replaying
		// everything would be the same uninvited history as no header.
		if n, perr := strconv.ParseInt(id, 10, 64); perr == nil && n >= 0 && n < cursor {
			cursor = n
		}
	}
	if werr := writeSSE(w, liveFrame{id: cursor, event: "hello",
		data: liveHello{Cursor: cursor}}); werr != nil {
		return
	}
	// The gap a reconnect asked for is sent at once, from the records the
	// hello was computed from, not on the first poll: a browser that lost
	// its stream for ten seconds is owed the ten seconds immediately, and a
	// page that has just reconnected should not flash its old numbers for a
	// poll interval first.
	for _, e := range events {
		if e.Seq <= cursor {
			continue
		}
		cursor = e.Seq
		event, data, ok := liveEvent(e)
		if !ok {
			continue
		}
		if werr := writeSSE(w, liveFrame{id: e.Seq, event: event, data: data}); werr != nil {
			return
		}
	}
	if err := rc.Flush(); err != nil {
		return
	}

	polls := time.NewTicker(t.poll)
	defer polls.Stop()
	// The keep-alive runs on a ticker rather than a timer reset by writes:
	// whether a ping is owed is decided by pingDue against the last thing
	// actually written, so a busy stream writes no comments over its events
	// and a quiet one keeps its proxies awake.
	pings := time.NewTicker(t.ping)
	defer pings.Stop()
	ends := time.NewTimer(t.life)
	defer ends.Stop()
	lastWrite := time.Now()
	for {
		select {
		case <-r.Context().Done():
			// The tab closed, or the client gave up. Nothing is owed.
			return
		case <-ends.C:
			// The polite close: say nothing, end the response. EventSource
			// reconnects at once with Last-Event-ID set to the last Seq it
			// has, and the code above resumes it — a rotation the person
			// watching never sees.
			return
		case <-polls.C:
			events, err := s.LoadAudit()
			if err != nil {
				continue // one unreadable moment is not a dead stream
			}
			for _, e := range events {
				if e.Seq <= cursor {
					continue
				}
				cursor = e.Seq
				event, data, ok := liveEvent(e)
				if !ok {
					continue // most of the log is nobody's live console
				}
				if werr := writeSSE(w, liveFrame{id: e.Seq, event: event, data: data}); werr != nil {
					return
				}
				lastWrite = time.Now()
			}
			if err := rc.Flush(); err != nil {
				return
			}
		case <-pings.C:
			if !pingDue(lastWrite, time.Now(), t.ping) {
				continue
			}
			if _, werr := writePing(w); werr != nil {
				return
			}
			lastWrite = time.Now()
			if err := rc.Flush(); err != nil {
				return
			}
		}
	}
}

// pingDue says whether a keep-alive is owed, given when something was last
// written. A pure function of its clock inputs so the cadence is tested with
// instants rather than sleeps — a timing test that waits real seconds is a
// test that flakes on a loaded machine and then gets deleted.
func pingDue(last, now time.Time, every time.Duration) bool {
	if every <= 0 {
		return false
	}
	return now.Sub(last) >= every
}

// writePing is one keep-alive frame: a comment line, ignored by every
// EventSource implementation, seen by every proxy. The word "ping" is for
// the person reading a wire; the colon is the whole of the mechanism.
func writePing(w io.Writer) (int, error) {
	return fmt.Fprint(w, ": ping\n\n")
}

// liveFrame is one server-sent event. The id is the audit Seq, which is what
// makes a reconnect a resume: the browser stores the last id it saw and
// sends it back as Last-Event-ID.
type liveFrame struct {
	id    int64
	event string
	data  any
}

// writeSSE writes one frame. The data is a closed-vocabulary struct — see
// the payloads below — so what goes on the wire is exactly the fields named,
// marshalled once, with no room for a detail map to leak through.
func writeSSE(w io.Writer, f liveFrame) error {
	data, err := json.Marshal(f.data)
	if err != nil {
		return err
	}
	if f.id > 0 {
		if _, err := fmt.Fprintf(w, "id: %d\n", f.id); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", f.event, data)
	return err
}

// The payloads. Every field is an id, a kind, a state or a counter — words
// from a closed vocabulary, chosen by this mapping, never carried from a
// record's Detail. The client builds its sentences; the stream never hands
// it somebody else's.

// liveHello tells the client where the stream starts from.
type liveHello struct {
	Cursor int64 `json:"cursor"`
}

// liveDecision is a finding's state being moved by a person.
type liveDecision struct {
	Finding string `json:"finding"`
	To      string `json:"to"`
}

// liveProposal is a model's suggestion about a finding. An event, never a
// verdict: the client may say one exists, nothing more.
type liveProposal struct {
	Finding string `json:"finding"`
	To      string `json:"to"`
}

// liveCase is an incident's existence or state.
type liveCase struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// liveWaiting is the waiting-for-you count moving. Delta is +1 or -1; the
// kind is which of the three things that wait it is, because the person
// needs to know which door to walk through, not merely that a number moved.
type liveWaiting struct {
	Kind  string `json:"kind"`
	Delta int    `json:"delta"`
}

// liveAutomation is an automation run reaching a state that is not a person
// waiting (those are liveWaiting): it ran, it watched, it was limited.
type liveAutomation struct {
	State string `json:"state"`
}

// liveDetection is a detection pass over the store finishing.
type liveDetection struct {
	Outcome string `json:"outcome"`
	Opened  int    `json:"opened"`
}

// liveAgent is a model's tool call through the sidecar being refused. Only
// the refusal is streamed — an agent's successful calls are its operator's
// business, and a console that narrated every one would be noise — and the
// tool is an identifier from the MCP catalogue, not text the agent wrote.
type liveAgent struct {
	Tool    string `json:"tool"`
	Refused bool   `json:"refused"`
}

// liveStates is the closed set of finding states, answering once per call.
func liveStates() map[finding.State]bool {
	out := map[finding.State]bool{}
	for _, s := range finding.States() {
		out[s] = true
	}
	return out
}

// liveEvent maps one audit record to one stream event, or to none.
//
// Most records map to none, deliberately: page views, sign-ins, settings —
// the log's diary of a working console is not the console's pulse. What maps
// is what a person watching Today would act on: what they must decide, what
// just opened, what changed underneath them.
//
// Anything that maps reads only the fields named in its payload — an id cut
// from a resource path, a state validated against the vocabulary, a counter
// parsed from a digit string. Detail keys that hold prose (because, why,
// error, text) are not read here at all, so they cannot be sent.
func liveEvent(e audit.Event) (string, any, bool) {
	states := liveStates()
	switch {
	case strings.HasPrefix(e.Action, "finding."):
		// A decision: the action is "finding." plus the state moved to, and
		// only real states count — the same guard finding.FromAudit applies,
		// so nothing else written under this prefix is read as a verdict.
		to, ok := strings.CutPrefix(e.Action, "finding.")
		if !ok || !states[finding.State(to)] {
			return "", nil, false
		}
		id := e.Detail["finding"]
		if id == "" {
			id = strings.TrimPrefix(e.Resource, "/")
		}
		if id == "" {
			return "", nil, false
		}
		return "decision", liveDecision{Finding: id, To: to}, true

	case e.Action == finding.ProposalAction:
		// A model's suggestion, carrying a state it may not even name: the
		// same vocabulary check, so a proposal of nonsense is not a proposal
		// the page repeats.
		to := e.Detail["to"]
		if !states[finding.State(to)] {
			return "", nil, false
		}
		id := e.Detail["finding"]
		if id == "" {
			return "", nil, false
		}
		return "proposal", liveProposal{Finding: id, To: to}, true
	}

	// Cases: the resource is the incident ("/incidents/ID"), and the action
	// is what happened to it. Only the state-changing verbs map; notes and
	// assignments are the record, not the pulse.
	if id, ok := strings.CutPrefix(e.Action, "incident."); ok {
		inc := strings.TrimPrefix(e.Resource, "/incidents/")
		if inc == "" {
			return "", nil, false
		}
		switch id {
		case "declared", "reopen":
			return "case", liveCase{ID: inc, State: "open"}, true
		case "watch":
			return "case", liveCase{ID: inc, State: "watching"}, true
		case "close":
			return "case", liveCase{ID: inc, State: "closed"}, true
		case "act-request":
			return "waiting", liveWaiting{Kind: "act", Delta: 1}, true
		case "act-approve", "act-undo", "act-withdraw":
			return "waiting", liveWaiting{Kind: "act", Delta: -1}, true
		}
		return "", nil, false
	}

	// Automations. A run held for a person moves the waiting count in or
	// out; a run reaching any other state is the automation working, which
	// the Today page counts.
	if state, ok := strings.CutPrefix(e.Action, "automation.run-"); ok {
		switch state {
		case "waiting":
			return "waiting", liveWaiting{Kind: "automation", Delta: 1}, true
		case "approved", "declined":
			return "waiting", liveWaiting{Kind: "automation", Delta: -1}, true
		}
		return "automation", liveAutomation{State: state}, true
	}

	// The two-person rule. A proposed change waits for a second
	// administrator; its decision, decline or withdrawal stops the waiting.
	switch e.Action {
	case "dual.proposed":
		return "waiting", liveWaiting{Kind: "change", Delta: 1}, true
	case "dual.approved", "dual.declined", "dual.withdrawn":
		return "waiting", liveWaiting{Kind: "change", Delta: -1}, true
	case "mcp.call":
		// Refused calls only, and only the tool's name from the catalogue.
		if e.Outcome != audit.Denied {
			return "", nil, false
		}
		return "agent", liveAgent{Tool: e.Detail["tool"], Refused: true}, true
	case "detect.run":
		// The count of findings a pass opened, or none when it failed; the
		// error text is the log's to hold.
		opened, _ := strconv.Atoi(e.Detail["opened"])
		return "detection", liveDetection{Outcome: string(e.Outcome), Opened: opened}, true
	}
	return "", nil, false
}

// livePollCookie is the fallback's marker: set by the page's script after
// the stream has failed to hold three times, read by Today to render the
// page with the Refresh hook (layout.html) instead of the live badge.
//
// The report's design, kept exactly: the console never pretends to be live.
// Poll mode is visible on the screen, it expires on its own (an hour), and
// the moment the stream holds again the script clears it, so a recovered
// stream heals the page on the next load without anybody asking.
const livePollCookie = "aeroprove_poll"

// pollMode says whether this request's page should render in poll fallback,
// and the value Refresh takes when it does: a full reload once a minute,
// which is the honest cadence of a page that has nothing to push.
func pollMode(r *http.Request) (bool, string) {
	if c, err := r.Cookie(livePollCookie); err == nil && c.Value != "" {
		return true, "60"
	}
	return false, ""
}
