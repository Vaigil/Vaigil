// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
)

// The live stream, checked the way it fails.
//
// A stream has more ways to be wrong than a page: it can speak to somebody
// unauthenticated, outlive its welcome, replay what was never asked for,
// go quiet through a proxy, or — worst, because nothing crashes — carry
// words from the audit log's Detail fields onto a page that renders
// whatever arrives. Each of those is a test here, and the free-text one is
// the reason the payloads are structs rather than the records themselves.

// syncRecorder is a ResponseWriter a test can read while the handler is
// still writing. httptest's recorder is a plain buffer, and a test that
// polls it against a streaming handler is a data race the race detector
// finds and the test then gets deleted over.
type syncRecorder struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	hdr  http.Header
	code int
}

func newSyncRecorder() *syncRecorder { return &syncRecorder{hdr: http.Header{}} }

func (s *syncRecorder) Header() http.Header { return s.hdr }

func (s *syncRecorder) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(b)
}

func (s *syncRecorder) WriteHeader(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.code = code
}

func (s *syncRecorder) Flush() {}

func (s *syncRecorder) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// sse is one parsed frame.
type sse struct {
	id, event, data string
}

// parseSSE reads the wire format: blocks separated by blank lines, each
// block's lines named. Comment blocks (the keep-alive) carry no fields and
// parse to nothing, which is exactly how a client treats them.
func parseSSE(body string) []sse {
	var out []sse
	for _, block := range strings.Split(body, "\n\n") {
		var f sse
		saw := false
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, ":") {
				continue
			}
			if v, ok := strings.CutPrefix(line, "id: "); ok {
				f.id, saw = v, true
			}
			if v, ok := strings.CutPrefix(line, "event: "); ok {
				f.event, saw = v, true
			}
			if v, ok := strings.CutPrefix(line, "data: "); ok {
				f.data, saw = v, true
			}
		}
		if saw {
			out = append(out, f)
		}
	}
	return out
}

// waitFor polls until the stream has said what the test is waiting for.
func waitFor(t *testing.T, what string, until func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if until() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("the stream never %s", what)
}

// streamOf runs streamLive until the test cancels, and hands back what was
// written. Directly rather than through the handler because the frame logic
// is what is under test; the gates around it have their own tests below.
// The second value stops the stream and returns the whole body; the first
// reads it while it runs.
func streamOf(t *testing.T, srv *Server, header, value string) (func() string, func() string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/live", nil).WithContext(ctx)
	if header != "" {
		req.Header.Set(header, value)
	}
	rec := newSyncRecorder()
	done := make(chan struct{})
	go func() {
		srv.streamLive(rec, req, liveDefaults)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the stream did not end when the request did")
		}
	})
	return func() string { return rec.String() },
		func() string {
			cancel()
			<-done
			return rec.String()
		}
}

func testEvents() []audit.Event {
	return []audit.Event{
		{Seq: 1, Action: "finding.fixed", Resource: "/f1", Outcome: audit.Success,
			Detail: map[string]string{"finding": "f1", "because": "patched in 1.2.3"}},
		{Seq: 2, Action: "incident.declared", Resource: "/incidents/inc-20260930-0000aa",
			Outcome: audit.Success},
		{Seq: 3, Action: "entity.viewed", Resource: "/entity/agent:x", Outcome: audit.Success},
		{Seq: 4, Action: "dual.proposed", Resource: "/", Outcome: audit.Success},
		{Seq: 5, Action: "detect.run", Resource: "/findings", Outcome: audit.Success,
			Detail: map[string]string{"opened": "3"}},
	}
}

// A fresh connection starts at the end of the log and is told where that
// is. "Live" that began with a replay of history nobody asked for would be
// the same lie as a badge that spins without a stream.
func TestAFreshStreamStartsAtTheEnd(t *testing.T) {
	srv, _ := setup(t)
	srv.LoadAudit = func() ([]audit.Event, error) { return testEvents(), nil }
	_, stop := streamOf(t, srv, "", "")
	got := stop()
	f := parseSSE(got)
	if len(f) != 1 || f[0].event != "hello" {
		t.Fatalf("a fresh stream sent %d frames; it owes exactly one hello "+
			"and nothing from before it opened:\n%s", len(f), got)
	}
	if f[0].id != "5" || f[0].data != `{"cursor":5}` {
		t.Errorf("hello was id %s data %s; the cursor is where the log ends",
			f[0].id, f[0].data)
	}
}

// A reconnect arrives with its bookmark — the last Seq it saw — and is
// given everything after it, in order, each frame carrying its own Seq so
// the next reconnect resumes from a later place. Records that map to no
// event (a page view) are skipped by name, not by counting: their Seqs are
// not frames, and a client must never be told five when it was told four
// happened but one was nobody's console.
func TestAResumeReplaysFromTheBrowserBookmark(t *testing.T) {
	srv, _ := setup(t)
	srv.LoadAudit = func() ([]audit.Event, error) { return testEvents(), nil }
	_, stop := streamOf(t, srv, "Last-Event-ID", "2")
	got := stop()
	frames := parseSSE(got)
	// hello, then 4 (dual.proposed) and 5 (detect.run). Seq 3 is a page
	// view and maps to nothing; seq 1 and 2 are at or before the bookmark.
	var ids, events []string
	for _, f := range frames {
		ids = append(ids, f.id)
		if f.event != "hello" {
			events = append(events, f.event)
		}
	}
	if strings.Join(ids, ",") != "2,4,5" {
		t.Errorf("ids were %v; a resume from 2 replays 4 and 5 and skips "+
			"what maps to nothing", ids)
	}
	if strings.Join(events, ",") != "waiting,detection" {
		t.Errorf("events were %v", events)
	}
	for _, f := range frames {
		if f.event == "waiting" && f.data != `{"kind":"change","delta":1}` {
			t.Errorf("waiting payload was %s", f.data)
		}
		if f.event == "detection" && f.data != `{"outcome":"success","opened":3}` {
			t.Errorf("detection payload was %s", f.data)
		}
	}
}

// The audit actions map to the eight stream events, and nothing else maps
// at all. The table is the contract: an action added to the codebase
// without a row here is an event the console never sees, which this test
// cannot catch — so the rows that exist are held to exact payloads, and a
// mapping that starts handing out raw records fails the closed-vocabulary
// test below.
func TestAuditActionsMapToStreamEvents(t *testing.T) {
	cases := []struct {
		name string
		e    audit.Event
		want string
		got  any
	}{
		{"a decision", audit.Event{Action: "finding.false-positive", Resource: "/f1",
			Detail: map[string]string{"finding": "f1"}}, "decision",
			liveDecision{Finding: "f1", To: "false-positive"}},
		{"a decision by resource when detail is bare", audit.Event{Action: "finding.fixed",
			Resource: "/f2"}, "decision", liveDecision{Finding: "f2", To: "fixed"}},
		{"not a state a finding can be moved to", audit.Event{Action: "finding.noted",
			Resource: "/f1"}, "", nil},
		{"a proposal", audit.Event{Action: "proposal.finding", Resource: "/f1",
			Detail: map[string]string{"finding": "f1", "to": "benign"}}, "proposal",
			liveProposal{Finding: "f1", To: "benign"}},
		{"a proposal of a word that is not a state", audit.Event{Action: "proposal.finding",
			Resource: "/f1", Detail: map[string]string{"finding": "f1", "to": "destroy"}}, "", nil},
		{"a case declared", audit.Event{Action: "incident.declared",
			Resource: "/incidents/inc-1"}, "case", liveCase{ID: "inc-1", State: "open"}},
		{"a case reopened", audit.Event{Action: "incident.reopen",
			Resource: "/incidents/inc-1"}, "case", liveCase{ID: "inc-1", State: "open"}},
		{"a case watched", audit.Event{Action: "incident.watch",
			Resource: "/incidents/inc-1"}, "case", liveCase{ID: "inc-1", State: "watching"}},
		{"a case closed", audit.Event{Action: "incident.close",
			Resource: "/incidents/inc-1"}, "case", liveCase{ID: "inc-1", State: "closed"}},
		{"a case note is the record, not the pulse", audit.Event{Action: "incident.note",
			Resource: "/incidents/inc-1"}, "", nil},
		{"an act asked for", audit.Event{Action: "incident.act-request",
			Resource: "/incidents/inc-1"}, "waiting", liveWaiting{Kind: "act", Delta: 1}},
		{"an act approved", audit.Event{Action: "incident.act-approve",
			Resource: "/incidents/inc-1"}, "waiting", liveWaiting{Kind: "act", Delta: -1}},
		{"an act undone", audit.Event{Action: "incident.act-undo",
			Resource: "/incidents/inc-1"}, "waiting", liveWaiting{Kind: "act", Delta: -1}},
		{"an automation held for a person", audit.Event{Action: "automation.run-waiting"},
			"waiting", liveWaiting{Kind: "automation", Delta: 1}},
		{"an automation approved", audit.Event{Action: "automation.run-approved"},
			"waiting", liveWaiting{Kind: "automation", Delta: -1}},
		{"an automation ran", audit.Event{Action: "automation.run-done"},
			"automation", liveAutomation{State: "done"}},
		{"a change proposed", audit.Event{Action: "dual.proposed"},
			"waiting", liveWaiting{Kind: "change", Delta: 1}},
		{"a change approved", audit.Event{Action: "dual.approved"},
			"waiting", liveWaiting{Kind: "change", Delta: -1}},
		{"a change declined", audit.Event{Action: "dual.declined"},
			"waiting", liveWaiting{Kind: "change", Delta: -1}},
		{"a change withdrawn", audit.Event{Action: "dual.withdrawn"},
			"waiting", liveWaiting{Kind: "change", Delta: -1}},
		{"an agent refused", audit.Event{Action: "mcp.call", Outcome: audit.Denied,
			Detail: map[string]string{"tool": "fs.write"}},
			"agent", liveAgent{Tool: "fs.write", Refused: true}},
		{"an agent allowed is not the console's business", audit.Event{Action: "mcp.call",
			Outcome: audit.Success, Detail: map[string]string{"tool": "fs.read"}}, "", nil},
		{"a detection pass", audit.Event{Action: "detect.run", Outcome: audit.Success,
			Detail: map[string]string{"opened": "7"}},
			"detection", liveDetection{Outcome: "success", Opened: 7}},
		{"a detection pass that failed", audit.Event{Action: "detect.run",
			Outcome: audit.Failure, Detail: map[string]string{"error": "spool: short read"}},
			"detection", liveDetection{Outcome: "failure", Opened: 0}},
		{"a page view", audit.Event{Action: "entity.viewed"}, "", nil},
		{"a sign-in", audit.Event{Action: "session.start"}, "", nil},
		{"an automation saved", audit.Event{Action: "automation.saved"}, "", nil},
	}
	for _, c := range cases {
		event, data, ok := liveEvent(c.e)
		if !ok {
			if c.want != "" {
				t.Errorf("%s: %s mapped to nothing; the console would never "+
					"see it", c.name, c.e.Action)
			}
			continue
		}
		if c.want == "" {
			t.Errorf("%s: %s mapped to %s; the diary of a working console is "+
				"not its pulse", c.name, c.e.Action, event)
			continue
		}
		if event != c.want || !reflect.DeepEqual(data, c.got) {
			t.Errorf("%s: %s mapped to (%s, %v); want (%s, %v)",
				c.name, c.e.Action, event, data, c.want, c.got)
		}
	}
}

// closedKeys is the whole of what any payload may carry. Held as exact key
// sets — not "does not contain prose", which a renamed field would pass —
// because the discipline is that the stream has no way to carry a Detail
// map, not that today's mapping happens not to.
var closedKeys = map[string][]string{
	"hello":      {"cursor"},
	"decision":   {"finding", "to"},
	"proposal":   {"finding", "to"},
	"case":       {"id", "state"},
	"waiting":    {"kind", "delta"},
	"automation": {"state"},
	"detection":  {"outcome", "opened"},
	"agent":      {"tool", "refused"},
}

// No word anybody typed crosses the stream. The audit log's Detail fields
// hold reasons, notes and error prose — some of it written by whoever the
// detection is about — and the payload structs are the boundary. This test
// pushes prose through every mapped action and holds the wire to the
// closed vocabulary above.
func TestTheStreamCarriesNoWordsFromTheLog(t *testing.T) {
	const prose = "WORDS NOBODY TYPED FOR A CONSOLE qzwxecrv"
	srv, _ := setup(t)
	srv.LoadAudit = func() ([]audit.Event, error) {
		return []audit.Event{
			{Seq: 1, Action: "finding.accepted", Resource: "/f1", Outcome: audit.Denied,
				Detail: map[string]string{"finding": "f1", "because": prose}},
			{Seq: 2, Action: "proposal.finding", Resource: "/f1",
				Detail: map[string]string{"finding": "f1", "to": "benign", "because": prose}},
			{Seq: 3, Action: "incident.declared", Resource: "/incidents/inc-1",
				Detail: map[string]string{"regimes": prose}},
			{Seq: 4, Action: "incident.act-request", Resource: "/incidents/inc-1",
				Detail: map[string]string{"action": prose, "subject": prose}},
			{Seq: 5, Action: "automation.run-done",
				Detail: map[string]string{"summary": prose}},
			{Seq: 6, Action: "dual.proposed", Detail: map[string]string{"why": prose}},
			{Seq: 7, Action: "mcp.call", Outcome: audit.Denied,
				Detail: map[string]string{"tool": "fs.write", "operation": prose}},
			{Seq: 8, Action: "detect.run", Outcome: audit.Failure,
				Detail: map[string]string{"opened": "0", "error": prose}},
		}, nil
	}
	_, stop := streamOf(t, srv, "Last-Event-ID", "0")
	got := stop()
	if strings.Contains(got, prose) {
		t.Fatalf("the stream carried words from an audit detail. The stream " +
			"is read by a page that renders what arrives; the log's prose " +
			"stays in the log")
	}
	frames := parseSSE(got)
	if len(frames) != 9 { // hello, then one per record
		t.Fatalf("%d frames; want 9 (a hello and every mapped record):\n%s",
			len(frames), got)
	}
	for _, f := range frames {
		want, ok := closedKeys[f.event]
		if !ok {
			t.Errorf("event %q is not in the closed set; a new event type "+
				"needs its payload named in closedKeys", f.event)
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(f.data), &payload); err != nil {
			t.Errorf("%s: payload %q is not JSON: %v", f.event, f.data, err)
			continue
		}
		var keys []string
		for k := range payload {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sort.Strings(want)
		if !reflect.DeepEqual(keys, want) {
			t.Errorf("%s carried keys %v; the closed set is %v. A payload "+
				"that grows a field is how prose returns", f.event, keys, want)
		}
	}
}

// A session that holds the console holds the stream: the same door, the
// same answer. An unauthenticated request is refused with the sign-in
// page, never a stream — an open stream is an open feed of the estate's
// pulse.
func TestTheStreamNeedsASession(t *testing.T) {
	srv, _ := setup(t)
	srv.LoadAudit = func() ([]audit.Event, error) { return nil, nil }
	w := get(t, srv, "/live", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated /live answered %d; want 401", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); strings.Contains(ct, "text/event-stream") {
		t.Errorf("an unauthenticated /live began a stream (%s)", ct)
	}
}

// The stream is end to end: the browser's cookie jar is not involved in
// the test's Bearer header, but everything else a real connection does —
// the middleware, the auth, the headers, the tail — is. Records appended
// after the stream opened arrive as frames, which is the whole difference
// between a live console and a page that was refreshed once.
func TestAnAuthenticatedSessionReceivesNewRecords(t *testing.T) {
	srv, token := setup(t)
	var mu sync.Mutex
	events := []audit.Event{{Seq: 1, Action: "incident.declared",
		Resource: "/incidents/inc-20260930-0000aa", Outcome: audit.Success}}
	srv.LoadAudit = func() ([]audit.Event, error) {
		mu.Lock()
		defer mu.Unlock()
		return append([]audit.Event(nil), events...), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/live", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := newSyncRecorder()
	done := make(chan struct{})
	go func() {
		srv.Handler().ServeHTTP(rec, req)
		close(done)
	}()
	// The hello arrives at once; the record lands once the stream's poll of
	// the log sees it.
	waitFor(t, "said hello", func() bool {
		return strings.Contains(rec.String(), "event: hello")
	})
	mu.Lock()
	events = append(events, audit.Event{Seq: 2, Action: "dual.proposed",
		Resource: "/", Outcome: audit.Success})
	mu.Unlock()
	waitFor(t, "carried the record that arrived after it opened", func() bool {
		return strings.Contains(rec.String(), "event: waiting")
	})
	cancel()
	<-done
	if ct := rec.hdr.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("the stream answered as %s", ct)
	}
	var waiting *sse
	for _, f := range parseSSE(rec.String()) {
		if f.event == "waiting" {
			waiting = &f
		}
	}
	if waiting == nil {
		t.Fatal("no waiting frame")
	}
	if waiting.id != "2" {
		t.Errorf("the frame's id was %s; the id is the audit Seq, which is "+
			"what a reconnect resumes from", waiting.id)
	}
	if waiting.data != `{"kind":"change","delta":1}` {
		t.Errorf("payload was %s", waiting.data)
	}
}

// The keep-alive is owed by the clock, not by the wall. Tested with
// instants, because a timing test that sleeps is a timing test that flakes
// on a loaded machine and then gets deleted — and the ping interval is the
// one number in the stream that exists purely for infrastructure nobody
// can see from a test.
func TestTheKeepAliveIsOwedByTheClock(t *testing.T) {
	var buf bytes.Buffer
	if _, err := writePing(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.String() != ": ping\n\n" {
		t.Errorf("writePing wrote %q; a comment frame is a colon line and a "+
			"blank line, and the format is load-bearing", buf.String())
	}
	t0 := time.Unix(1790000000, 0)
	if !pingDue(t0, t0.Add(livePing), livePing) {
		t.Error("a ping is owed at the interval")
	}
	if pingDue(t0, t0.Add(livePing-1), livePing) {
		t.Error("a ping is not owed before the interval")
	}
	if pingDue(t0, t0.Add(livePing), 0) {
		t.Error("a zero interval owes nothing, or a misconfiguration spams " +
			"the wire")
	}
	// Events reset the clock: a stream that just spoke is not quiet, and
	// pinging over its own frames is noise an idle proxy does not need.
	if pingDue(t0.Add(livePing), t0.Add(livePing+livePing/2), livePing) {
		t.Error("a ping is not owed while the stream is speaking")
	}
}

// A quiet stream keeps itself alive and ends on time. The lifetime is the
// only guarantee the process has that a slot comes back without waiting
// for a client that may never go away.
func TestAQuietStreamKeepsAliveAndEndsOnTime(t *testing.T) {
	srv, _ := setup(t)
	srv.LoadAudit = func() ([]audit.Event, error) { return nil, nil }
	req := httptest.NewRequest(http.MethodGet, "/live", nil)
	w := httptest.NewRecorder()
	start := time.Now()
	// Tiny timings, the same code path as the defaults: a busy machine
	// delays ticks but cannot skip the boundary this asserts.
	srv.streamLive(w, req, liveTiming{
		poll: 5 * time.Millisecond, ping: 10 * time.Millisecond, life: 120 * time.Millisecond,
	})
	took := time.Since(start)
	body := w.Body.String()
	if n := strings.Count(body, ": ping"); n < 2 {
		t.Errorf("%d keep-alives in a quiet stream; a proxy that idle-closes "+
			"would have dropped it:\n%s", n, body)
	}
	if took > 2*time.Second {
		t.Errorf("the stream ran %s past a 120ms lifetime; a stream that "+
			"outlives its clock never gives its slot back", took)
	}
}

// Past the cap the stream refuses politely: a number, a Retry-After, and
// an answer EventSource understands as "try later" rather than a
// connection that hangs half-open.
func TestTheCapRefusesPolitely(t *testing.T) {
	srv, token := setup(t)
	srv.LoadAudit = func() ([]audit.Event, error) { return nil, nil }
	gate := srv.liveGate()
	for i := 0; i < liveMaxStreams; i++ {
		gate <- struct{}{}
	}
	t.Cleanup(func() {
		for {
			select {
			case <-gate:
			default:
				return
			}
		}
	})
	w := get(t, srv, "/live", token)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("the %dth stream answered %d; want 503", liveMaxStreams+1, w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("the refusal set no Retry-After; a client that cannot be " +
			"told when to come back hammers instead")
	}
	if !strings.Contains(w.Body.String(), strconv.Itoa(liveMaxStreams)) {
		t.Errorf("the refusal did not name the cap; it said: %s", w.Body.String())
	}
	// One slot back, and the next stream is let in — and gives it back
	// when its request ends, or the cap only ever tightens.
	<-gate
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/live", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := newSyncRecorder()
	done := make(chan struct{})
	go func() {
		srv.Handler().ServeHTTP(rec, req)
		close(done)
	}()
	waitFor(t, "said hello", func() bool {
		return strings.Contains(rec.String(), "event: hello")
	})
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream did not end with its request; the slot is leaked")
	}
	// The handler gave its slot back: this test still holds the other
	// seven, so what should be available is exactly the one the finished
	// stream released — taken here without blocking, because a slot that
	// only comes back eventually is a slot the cap counts twice.
	select {
	case <-gate:
	default:
		t.Error("the finished stream's slot was not released; a cap that " +
			"never gives back is an outage scheduled in advance")
	}
}

// A build with no audit reader has nothing to stream and says so, rather
// than holding a connection open and calling it live.
func TestABuildWithoutTheLogRefusesTheStream(t *testing.T) {
	srv, token := setup(t) // no LoadAudit wired
	w := get(t, srv, "/live", token)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("a build with no audit log answered %d; want 503", w.Code)
	}
}

// Today carries the live region, and it is silent until something true can
// be said. A status region that announces nothing is the honest no-script
// state; the Refresh form beside it is the whole mechanism without script.
func TestTodayCarriesASilentLiveRegion(t *testing.T) {
	srv, token := fullyWired(t)
	page := getPage(t, srv, "/today", token)
	badge := regexp.MustCompile(
		`<span class="hint" data-live-badge role="status" aria-live="polite"></span>`)
	if !badge.MatchString(page) {
		t.Error("the live badge is missing or is not empty; a live region " +
			"that says something it is not doing is worse than none")
	}
	if !strings.Contains(page, `action="/today"`) {
		t.Error("the Refresh form is missing; without it, no script means no " +
			"way to ask for a fresh page")
	}
	for _, hook := range []string{
		`data-live="waiting"`,
		`data-live="waiting-empty"`,
		`data-live-count="/findings"`,
	} {
		if !strings.Contains(page, hook) {
			t.Errorf("Today does not carry %s; the stream has nowhere to put "+
				"what it knows", hook)
		}
	}
}

// Poll mode is visible, which is the point of it: after the stream has
// failed to hold, the page says it is reloading once a minute — through
// the layout's Refresh hook, which this is the one user of — and the badge
// states the mode rather than implying liveness.
func TestTodaySaysWhenItIsPolling(t *testing.T) {
	srv, token := setup(t)
	req := httptest.NewRequest(http.MethodGet, "/today", nil)
	req.AddCookie(&http.Cookie{Name: livePollCookie, Value: "1"})
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	body := w.Body.String()
	if !strings.Contains(body, `<meta http-equiv="refresh" content="60">`) {
		t.Error("poll mode did not render the Refresh hook; the page cannot " +
			"reload itself")
	}
	if !strings.Contains(body, "○ every 60s") {
		t.Error("poll mode did not say so in the badge; a console that polls " +
			"while looking live is lying")
	}

	// Without the cookie, none of it: a page that reloaded every minute
	// while its stream was working would be a stream wasted.
	plain := getPage(t, srv, "/today", token)
	if strings.Contains(plain, `http-equiv="refresh"`) {
		t.Error("the page reloads itself without poll mode being asked for")
	}
	if strings.Contains(plain, "every 60s") {
		t.Error("the badge claims a mode the page is not in")
	}
}
