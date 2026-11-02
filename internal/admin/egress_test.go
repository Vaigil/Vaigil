// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vaigil/vaigil/internal/auth"
	"github.com/vaigil/vaigil/internal/collector"
	"github.com/vaigil/vaigil/internal/spool"
	"github.com/vaigil/vaigil/internal/telemetry"
)

// The egress board's scan: where the machines that run agents talked to,
// joined to the agents the operator declared on them, with every gap the
// records leave said as a count rather than filled with a guess.

// connectOn is one auditd connect record as the mapping stores it: the
// host as the device, the decoded address and port in raw, and a failed
// disposition where the syscall never completed. An empty port is the
// SOCKADDR decoder's AF_UNIX path; an empty address is a connect whose
// destination never arrived.
func connectOn(host, addr, port string, failed bool, recv time.Time) telemetry.Event {
	d := telemetry.DispositionAllowed
	if failed {
		d = telemetry.DispositionFailed
	}
	e := telemetry.Event{Source: "auditd/events",
		Class: telemetry.ClassProcessActivity, Disposition: d,
		Raw:  map[string]string{"syscall": "connect", "addr": addr, "port": port},
		Time: recv, Received: recv}
	// An empty host is the connect no device named — the event a store that
	// predates the host rule holds — and a device with no value at all
	// rather than one that names an issuer and nobody.
	if host != "" {
		e.Device = telemetry.ID{Issuer: "auditd", Value: host}
	}
	return e
}

// beatOn is one recorder heartbeat as the collector endpoint stores it:
// alive on a host, the recorder's enrolment name as the device, and the
// agent names the declaration stamped there — the single join name only
// when the host was declared to run exactly one agent.
func beatOn(recorder, host, agents string, recv time.Time) telemetry.Event {
	raw := map[string]string{"host": host}
	if agents != "" {
		raw["agents"] = agents
		if !strings.Contains(agents, ",") {
			raw["agent"] = agents
		}
	}
	return telemetry.Event{Source: collector.SourceHeartbeat,
		Class:  telemetry.ClassProcessActivity,
		Device: telemetry.ID{Issuer: "collector", Value: recorder},
		Raw:    raw, Time: recv, Received: recv}
}

// watchOn is one watched-file fact, which claims its host for the board
// the way a heartbeat does: a recorder shipping evidence from a machine is
// a recorder speaking for that machine.
func watchOn(host, agents string, recv time.Time) telemetry.Event {
	raw := map[string]string{"host": host, "path": "/home/dana/.mcp.json"}
	if agents != "" {
		raw["agents"] = agents
		if !strings.Contains(agents, ",") {
			raw["agent"] = agents
		}
	}
	return telemetry.Event{Source: collector.SourceWatch,
		Class:  telemetry.ClassFileActivity,
		Device: telemetry.ID{Issuer: "collector", Value: host},
		Raw:    raw, Time: recv, Received: recv}
}

// egressOver scans a fresh store holding these events, on a clock the test
// holds, and reports the store's own event count beside the board.
func egressOver(t *testing.T, in ...telemetry.Event) (EgressReport, time.Time) {
	t.Helper()
	dir := t.TempDir()
	sp, err := spool.Open(dir, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range in {
		if _, err := sp.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	sp, err = spool.Open(dir, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	now := time.Now().UTC()
	rep, err := EgressScan(sp, now)
	if err != nil {
		t.Fatal(err)
	}
	return rep, now
}

// hostOf is the one row for a host, refusing loudly when the board holds
// no such row or more than one.
func hostOf(t *testing.T, rep EgressReport, host string) EgressHost {
	t.Helper()
	var found []EgressHost
	for _, h := range rep.Hosts {
		if strings.EqualFold(h.Host, host) {
			found = append(found, h)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d rows for %s, want exactly one: %+v", len(found), host,
			rep.Hosts)
	}
	return found[0]
}

// TestEgressCountsEachDestinationWithItsFirstAndLastSeen.
//
// A destination is an address and a port the record itself named, counted
// over the window with the share that never completed; the row's own
// counts carry the busiest destinations first, and an address travels
// verbatim — nothing resolves it, because nothing in the record says what
// a resolver would claim to know.
func TestEgressCountsEachDestinationWithItsFirstAndLastSeen(t *testing.T) {
	now := time.Now().UTC()
	rep, _ := egressOver(t,
		beatOn("inbound-build01", "build01", "watcher", now.Add(-70*time.Minute)),
		connectOn("build01", "203.0.113.9", "443", false, now.Add(-60*time.Minute)),
		connectOn("build01", "203.0.113.9", "443", false, now.Add(-50*time.Minute)),
		connectOn("build01", "198.51.100.7", "8080", false, now.Add(-40*time.Minute)),
		// A connect that reached nothing, minutes ago.
		connectOn("build01", "203.0.113.9", "443", true, now.Add(-10*time.Minute)),
	)
	h := hostOf(t, rep, "build01")
	if h.Connects != 4 || h.Failed != 1 {
		t.Errorf("connects %d, failed %d; want 4 and 1", h.Connects, h.Failed)
	}
	if h.NonWeb != 1 {
		t.Errorf("non-web connects %d; want the one to :8080, and only that",
			h.NonWeb)
	}
	if len(h.Dest) != 2 {
		t.Fatalf("%d destinations, want the two addresses", len(h.Dest))
	}
	busy := h.Dest[0]
	if busy.Addr != "203.0.113.9" || busy.Port != "443" || busy.N != 3 ||
		busy.Failed != 1 {
		t.Errorf("the busiest destination is %+v, want three connects to "+
			"203.0.113.9:443, one of them failed", busy)
	}
	if !busy.First.Equal(now.Add(-60*time.Minute)) ||
		!busy.Last.Equal(now.Add(-10*time.Minute)) {
		t.Errorf("the destination's span runs %s to %s; first and last "+
			"seen are arrivals, oldest to newest", busy.First, busy.Last)
	}
	if h.Dest[1].Addr != "198.51.100.7" || h.Dest[1].N != 1 {
		t.Errorf("the quieter address is %+v, not the single connect it was",
			h.Dest[1])
	}
	if !h.First.Equal(now.Add(-60*time.Minute)) ||
		!h.Last.Equal(now.Add(-10*time.Minute)) {
		t.Errorf("the host's span runs %s to %s", h.First, h.Last)
	}
	// The denominators: every connect counted once, one heartbeat read,
	// and the store's own event count beside them.
	if rep.Connects != 4 || rep.Beats != 1 || rep.Stored != 5 {
		t.Errorf("header counts %d connects, %d beats, %d stored; want 4, 1, 5",
			rep.Connects, rep.Beats, rep.Stored)
	}
	if rep.Away != 0 || rep.AwayHost != 0 || rep.Unix != 0 || rep.NoDest != 0 {
		t.Errorf("gaps were counted where the corpus holds none: %+v", rep)
	}
}

// TestEgressJoinsTheDeclaredAgentsWithoutChoosing.
//
// The declaration is a list: a host declared to run one agent shows that
// agent, a host declared to run two shows both and attributes its
// connects to neither, and a host nobody declared shows under the
// recorder's own hostname with the mapping's silence — never as a host
// running none.
func TestEgressJoinsTheDeclaredAgentsWithoutChoosing(t *testing.T) {
	now := time.Now().UTC()
	rep, _ := egressOver(t,
		beatOn("inbound-build01", "build01", "watcher", now.Add(-30*time.Minute)),
		beatOn("inbound-dev02", "dev02", "docs-bot,watcher", now.Add(-25*time.Minute)),
		beatOn("inbound-ci03", "ci03", "", now.Add(-20*time.Minute)),
		// A host only a watch event spoke for, declared through that
		// stream: shipping evidence from a machine claims it.
		watchOn("vm04", "builder", now.Add(-15*time.Minute)),
		connectOn("build01", "203.0.113.9", "443", false, now.Add(-10*time.Minute)),
		connectOn("dev02", "203.0.113.9", "443", false, now.Add(-9*time.Minute)),
		connectOn("ci03", "203.0.113.9", "443", false, now.Add(-8*time.Minute)),
	)
	one := hostOf(t, rep, "build01")
	if len(one.Agents) != 1 || one.Agents[0] != "watcher" ||
		one.AgentList != "watcher" {
		t.Errorf("a one-agent host shows %v (%q)", one.Agents, one.AgentList)
	}
	if one.Recorder != "inbound-build01" || one.LastBeat.IsZero() {
		t.Errorf("the liveness fact is %s at %s; the declaration belongs "+
			"beside the recorder that explained it", one.Recorder, one.LastBeat)
	}
	two := hostOf(t, rep, "dev02")
	if len(two.Agents) != 2 || two.Agents[0] != "docs-bot" ||
		two.Agents[1] != "watcher" {
		t.Errorf("a two-agent host shows %v; both names, or the connects "+
			"were attributed to a program's choice", two.Agents)
	}
	if two.AgentList != "docs-bot, watcher" {
		t.Errorf("the readable list is %q", two.AgentList)
	}
	none := hostOf(t, rep, "ci03")
	if len(none.Agents) != 0 {
		t.Errorf("an undeclared host shows %v; the mapping said nothing", none.Agents)
	}
	if none.Recorder == "" {
		t.Error("an undeclared host lost its recorder's own name")
	}
	claimed := hostOf(t, rep, "vm04")
	if len(claimed.Agents) != 1 || claimed.Agents[0] != "builder" {
		t.Errorf("a host claimed by a watch event shows %v", claimed.Agents)
	}
}

// TestEgressFoldsAHostsTwoSpellingsIntoOneRow.
//
// The join folds case, because a recorder that says BUILD01 and a
// heartbeat that says build01 are one machine and treating them as two is
// a silent miss: half the connects on a row nobody reads.
func TestEgressFoldsAHostsTwoSpellingsIntoOneRow(t *testing.T) {
	// The auditd spelling first, the heartbeat's second.
	now := time.Now().UTC()
	rep, _ := egressOver(t,
		connectOn("BUILD01", "203.0.113.9", "443", false, now.Add(-40*time.Minute)),
		beatOn("inbound-build01", "build01", "watcher", now.Add(-30*time.Minute)),
	)
	if len(rep.Hosts) != 1 {
		t.Fatalf("%d rows for one machine spelled two ways: %+v",
			len(rep.Hosts), rep.Hosts)
	}
	h := rep.Hosts[0]
	if h.Connects != 1 || h.Recorder != "inbound-build01" {
		t.Errorf("the folded row holds %+v; the connects and the liveness "+
			"did not meet", h)
	}
	// And the other order: the heartbeat first, the auditd spelling second.
	now = time.Now().UTC()
	rep, _ = egressOver(t,
		beatOn("inbound-build01", "build01", "watcher", now.Add(-30*time.Minute)),
		connectOn("BUILD01", "203.0.113.9", "443", false, now.Add(-20*time.Minute)),
	)
	if len(rep.Hosts) != 1 || rep.Hosts[0].Connects != 1 {
		t.Errorf("%d rows the other order round: %+v", len(rep.Hosts), rep.Hosts)
	}
}

// TestEgressCountsItsHonestGapsRatherThanInventingRows.
//
// What the board cannot say, it counts. Connects from a host no recorder
// named in the window belong to no row, because nothing can say a recorder
// ever spoke for that machine; a socket path and a missing destination are
// not egress; a heartbeat that named no host cannot be joined to anything;
// and a connect nobody's device named is counted away with the rest.
func TestEgressCountsItsHonestGapsRatherThanInventingRows(t *testing.T) {
	now := time.Now().UTC()
	rep, _ := egressOver(t,
		beatOn("inbound-build01", "build01", "", now.Add(-60*time.Minute)),
		// AF_UNIX: a path on the host, not a destination.
		connectOn("build01", "/var/run/docker.sock", "", false, now.Add(-50*time.Minute)),
		// A connect whose address never arrived.
		connectOn("build01", "", "", false, now.Add(-40*time.Minute)),
		// The web ports, which are the row's to show.
		connectOn("build01", "203.0.113.9", "443", false, now.Add(-30*time.Minute)),
		connectOn("build01", "198.51.100.7", "80", false, now.Add(-20*time.Minute)),
		// A host only the auditd stream named: counted away, no row.
		connectOn("ghost01", "203.0.113.99", "443", false, now.Add(-25*time.Minute)),
		connectOn("ghost01", "203.0.113.99", "8443", false, now.Add(-24*time.Minute)),
		// A heartbeat that named no host at all.
		beatOn("inbound-lost", "", "", now.Add(-15*time.Minute)),
		// A connect no device named: the store that predates the host rule.
		connectOn("", "203.0.113.9", "443", false, now.Add(-10*time.Minute)),
	)
	if len(rep.Hosts) != 1 {
		t.Fatalf("%d rows, want only the host a recorder spoke for: %+v",
			len(rep.Hosts), rep.Hosts)
	}
	h := rep.Hosts[0]
	if h.Unix != 1 || h.Undecoded != 1 {
		t.Errorf("unix %d, undecoded %d; the socket path and the missing "+
			"address are gaps to count, not destinations to show", h.Unix,
			h.Undecoded)
	}
	if h.Connects != 2 || h.NonWeb != 0 || len(h.Dest) != 2 {
		t.Errorf("the row shows %d connects (%d non-web) over %d "+
			"destinations; only the web ports left the host", h.Connects,
			h.NonWeb, len(h.Dest))
	}
	// The denominators say what the row left out.
	if rep.Connects != 7 {
		t.Errorf("%d connect events counted, want all seven", rep.Connects)
	}
	if rep.Away != 3 || rep.AwayHost != 1 {
		t.Errorf("%d away connects over %d hosts, want ghost01's two and "+
			"the device-less one", rep.Away, rep.AwayHost)
	}
	if rep.Unix != 1 || rep.NoDest != 1 {
		t.Errorf("unix %d, no-destination %d across the window", rep.Unix,
			rep.NoDest)
	}
	if rep.Beats != 2 || rep.BeatsNoHost != 1 {
		t.Errorf("%d heartbeats, %d without a host", rep.Beats, rep.BeatsNoHost)
	}
}

// TestEgressShowsTheBusiestSliceAndNamesTheRest.
//
// A busy build host reaches hundreds of addresses in a week; the report
// keeps every one and the row offers the busiest twenty plus the count of
// what is cut, so a reader knows the table is a slice and not the estate.
func TestEgressShowsTheBusiestSliceAndNamesTheRest(t *testing.T) {
	var in []telemetry.Event
	now := time.Now().UTC()
	in = append(in, beatOn("inbound-build01", "build01", "watcher",
		now.Add(-90*time.Minute)))
	for i := 1; i <= 22; i++ {
		addr := "10.0.0." + strconv.Itoa(i)
		n := 1
		if addr == "10.0.0.7" {
			n = 3 // the busiest address on the host
		}
		for c := 0; c < n; c++ {
			in = append(in, connectOn("build01", addr, "443", false,
				now.Add(-time.Duration(80-i-c)*time.Minute)))
		}
	}
	rep, _ := egressOver(t, in...)
	h := hostOf(t, rep, "build01")
	if len(h.Dest) != 22 {
		t.Fatalf("%d destinations kept, want every one of the 22", len(h.Dest))
	}
	if len(h.DestShown) != egressDestShown {
		t.Fatalf("%d destinations shown, want the busiest %d", len(h.DestShown),
			egressDestShown)
	}
	if h.DestMore != 2 {
		t.Errorf("%d destinations cut without being counted", h.DestMore)
	}
	if h.DestShown[0].Addr != "10.0.0.7" || h.DestShown[0].N != 3 {
		t.Errorf("the busiest slice opens with %+v", h.DestShown[0])
	}
}

// TestTheEgressBoardRefusesThoseWhoCannotTriage.
//
// The board is a security screen: it answers a triage-holding credential
// and refuses everybody else at the door, before a single byte of the
// store is read.
func TestTheEgressBoardRefusesThoseWhoCannotTriage(t *testing.T) {
	srv, _ := setup(t)
	req := httptest.NewRequest(http.MethodGet, "/security/agents/egress", nil)
	w := httptest.NewRecorder()
	srv.handleEgress(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("a request with no credential got %d, want the door",
			w.Code)
	}
	// A signed-in viewer: on the console, but not in security triage.
	srv, token := asRole(t, auth.RoleViewer)
	req = httptest.NewRequest(http.MethodGet, "/security/agents/egress", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	srv.handleEgress(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a viewer got %d, want the refusal", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "Not permitted") ||
		strings.Contains(body, "render error") {
		t.Errorf("the refusal does not say what was refused:\n%s",
			firstLines(body, 8))
	}
}

// TestTheEgressBoardAnswersAnAllowedReader.
//
// What the gate admits, the handler reads for: an administrator with a
// store behind the board is answered, not refused. The page's own markup
// lives with the template it renders; this holds the gate, which is the
// part a screen cannot be trusted to re-check.
func TestTheEgressBoardAnswersAnAllowedReader(t *testing.T) {
	srv, token := setup(t)
	now := time.Now().UTC()
	srv.Events, _ = spoolWith(t, spool.Options{},
		beatOn("inbound-build01", "build01", "watcher", now.Add(-30*time.Minute)),
		connectOn("build01", "203.0.113.9", "443", false, now.Add(-20*time.Minute)))
	req := httptest.NewRequest(http.MethodGet, "/security/agents/egress", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.handleEgress(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("an administrator got %d:\n%s", w.Code,
			firstLines(w.Body.String(), 8))
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("the board answered as %s", ct)
	}
	if body := w.Body.String(); strings.Contains(body, "Not permitted") {
		t.Error("an allowed reader was told they are not permitted")
	}
}
