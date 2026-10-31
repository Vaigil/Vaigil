// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/vaigil/vaigil/internal/auth"
	"github.com/vaigil/vaigil/internal/collector"
	"github.com/vaigil/vaigil/internal/spool"
	"github.com/vaigil/vaigil/internal/telemetry"
)

// Where the machines that run agents talk to, from what the recorder already
// ships — the flow-log NDR of docs/research/12-xdr-ndr-tip-iam.md §3.2 at
// startup scale, built on the connect half of the auditd tail rather than on
// a sensor.
//
// # What this reads, and nothing else

// Three streams. The auditd tail's connect records (auditd/events, whose
// mapping keeps the decoded syscall, addr and port) say a host opened a
// socket to an address. The collector's own records (collector/heartbeat and
// collector/watch) say a recorder is alive on a host and — where the operator
// declared one — which agents run there, in raw.agents (the whole list) and
// raw.agent (the single name a one-agent host carries; internal/agentreg is
// the declaration, inboundserve's declaredAgents is the stamp). The join is
// host to host, case folded the way agentreg.AgentsFor folds it, because a
// recorder that says BUILD01 and a heartbeat that says build01 are one
// machine and treating them as two is a silent miss.
//
// # The three honesty rules the join is held to
//
// A host's connects are the host's. Where more than one agent is declared on
// a host, every declared name is shown and the connects are attributed
// between none of them: the declaration says who runs there, no event says
// who held the socket, and choosing would be the false precision the
// recorder-host mapping exists to refuse.
//
// A host nobody mapped shows under the recorder's own hostname with no agents
// named — the mapping's silence, said as that and never as the host running
// none.
//
// Nothing is named that the records do not carry. No packet capture exists
// and none is being built: a connect record holds an address and a port and
// never a hostname, so no destination on this board is resolved to a domain,
// no reverse DNS is attempted (a PTR answer would be somebody else's claim
// about the address, not evidence about the connection), and no address is
// enriched with ASN or country. An address is an address.
//
// # What is counted rather than shown

// Connect events from hosts no recorder named in the window — an auditd
// stream that arrived some other way — are counted in the header and given no
// row: this board is the recorder estate's egress, and a row standing on a
// host the collector never spoke for would claim a liveness it cannot check.
// Connects to AF_UNIX sockets carry a path and no port; they do not leave the
// host and are not egress, so they are counted and excluded. Connects whose
// address field never arrived are counted too — a record that names no
// destination is evidence of a connect, not evidence of where.

// egressLookback is how far back the board counts. Seven days, the same
// window the Agents board beside it holds, so the two screens answer for the
// same period without either saying so in its own words.
const egressLookback = 7 * 24 * time.Hour

// egressDestShown is how many destinations one host's row offers before
// naming the count behind it. A busy build host connects to hundreds of
// addresses in a week; a table that printed them all is a page nobody
// scrolls, and the honest form is the busiest slice plus the number of what
// is cut — the JSON behind the CLI keeps every one.
const egressDestShown = 20

// EgressDest is one destination one host connected to, counted over the
// window. Addr and Port are the record's own fields, verbatim.
type EgressDest struct {
	Addr string `json:"addr"`
	Port string `json:"port"`
	// N is every connect event to this address and port. Failed is the share
	// whose record said it did not complete — an unroutable or refused
	// connect reached nothing, and a count that silently mixed the two would
	// overstate what was actually sent.
	N      int `json:"n"`
	Failed int `json:"failed"`
	// First and Last are arrivals, on this program's clock, for the same
	// reason the Agents board uses arrivals: a recorder whose clock runs
	// ahead must not become the most recent thing on the board.
	First, Last time.Time
}

// EgressHost is one recorder host: everything the window's events said about
// where that machine connected and who is declared to run on it.
type EgressHost struct {
	// Host is the recorder's own hostname, the auditd record's spelling.
	Host string `json:"host"`
	// Recorder is the collector's enrolment name from its heartbeat, and
	// LastBeat when it last said it was alive — the liveness fact beside the
	// egress, because a host whose recorder went quiet is a host whose
	// connects stopped being recorded, and a row that read as "stopped
	// connecting" would claim the wrong thing.
	Recorder string    `json:"recorder,omitempty"`
	LastBeat time.Time `json:"last_heartbeat"`

	// Agents is every agent the window's collector events declared on this
	// host, most of the union a mid-window declaration change leaves behind.
	// Empty means no declaration arrived — said on the page as the mapping's
	// silence, never as the host running none.
	Agents []string `json:"agents,omitempty"`
	// AgentList is the declaration as one readable string, for the row.
	AgentList string `json:"-"`

	Connects, Failed int
	// NonWeb is connects to ports other than 80 and 443. A count, carried
	// because the pack's egress rule asks exactly this question of exactly
	// this join; this board reports it and decides nothing with it.
	NonWeb int `json:"non_web_ports"`
	// Unix is connects to AF_UNIX sockets on this host: paths, not
	// destinations, counted so the row's totals can be reconciled against
	// what the table shows.
	Unix int `json:"unix_sockets"`
	// Undecoded is connects whose record named no address.
	Undecoded int `json:"no_destination"`

	Dest      []EgressDest `json:"destinations"`
	DestShown []EgressDest `json:"-"`
	DestMore  int          `json:"-"`

	// First and Last are the host's first and last connect arrivals in the
	// window; zero times mean the recorder is alive and no connect arrived.
	First, Last time.Time
	LastAgo     string `json:"-"`
}

// EgressReport is the whole board: every recorder host the window holds, and
// the counts that keep the board honest about what it left out.
type EgressReport struct {
	Hosts []EgressHost `json:"hosts"`
	// From is where the window actually began — the lookback, or the byte
	// budget's cut — and Short whether the budget cut in. Said, because a
	// board that quietly counted less than its stated window reports a host
	// as quiet that was connecting before the cut.
	From  time.Time `json:"from"`
	Short bool      `json:"window_short"`

	// Connects is every auditd connect event the window held, including the
	// ones below that belong to no recorder host.
	Connects int `json:"connects"`
	// Away is the share of those from hosts no recorder named in the window,
	// and AwayHost how many such hosts: an auditd stream that arrived another
	// way, which is not this board's estate and not nothing either.
	Away     int `json:"connects_from_unrecorded_hosts"`
	AwayHost int `json:"unrecorded_hosts"`
	// Unix and NoDest are the window's socket-path and undecoded connects
	// across every host, the denominators the rows' own counts sit inside.
	Unix   int `json:"unix_sockets"`
	NoDest int `json:"no_destination"`

	// Beats is heartbeat events read, and BeatsNoHost the ones that named no
	// host — a recorder alive on a machine it never named is a recorder whose
	// egress cannot be joined to anything.
	Beats       int `json:"heartbeats"`
	BeatsNoHost int `json:"heartbeats_without_host"`

	// Stored is the whole store's event count, for the difference between
	// "no connects observed" and "nothing collected".
	Stored int `json:"stored"`
}

// egressSources are the streams the scan reads. The two collector ones are
// named through the collector package's own constants, because a source
// string spelled differently on the two sides of the wire is a stream that
// stores nothing and errors nowhere.
var egressSources = []string{"auditd/events",
	collector.SourceHeartbeat, collector.SourceWatch}

// egressTally is one host being built during the walk.
type egressTally struct {
	h EgressHost
	// dest is the host's destinations by address:port.
	dest map[string]*EgressDest
	// agents is the declared-names union.
	agents map[string]bool
	// claimed is whether a heartbeat or watch event named this host. Until
	// one does, the tally only holds connect counts that may yet have to be
	// counted away instead of shown.
	claimed bool
}

// egressKey folds a host name the way the join folds it: lowercase, so a
// recorder that says BUILD01 and a heartbeat that says build01 are one row.
func egressKey(host string) string { return strings.ToLower(host) }

// EgressScan is one walk of the store: every recorder host's destinations and
// declared agents over the window. The console page and the estate command
// both come here, so the two surfaces cannot disagree about the join.
//
// now is the clock the window is measured against; sp is an open store.
func EgressScan(sp *spool.Spool, now time.Time) (EgressReport, error) {
	out := EgressReport{From: now.Add(-egressLookback), Stored: sp.Events()}
	if wfrom, skipped := window(sp.Segments(), DefaultBudget); skipped > 0 &&
		wfrom.After(out.From) {
		out.From = wfrom
		out.Short = true
	}

	// One of the three sources in a segment is enough to open it: the
	// equality a bloom filter answers before the segment is read, so the
	// walk opens no segment that can hold none of this board's events.
	keep := func(seg spool.Segment) bool {
		for _, s := range egressSources {
			if sp.CouldHold(seg, "source", s) {
				return true
			}
		}
		return false
	}

	by := map[string]*egressTally{}
	tally := func(host string) *egressTally {
		key := egressKey(host)
		t := by[key]
		if t == nil {
			t = &egressTally{dest: map[string]*EgressDest{},
				agents: map[string]bool{}}
			by[key] = t
		}
		if t.h.Host == "" {
			t.h.Host = host
		}
		return t
	}

	err := sp.RangeWhere(out.From, time.Time{}, keep, func(e telemetry.Event) error {
		switch e.Source {
		case "auditd/events":
			if e.Raw["syscall"] != "connect" {
				return nil
			}
			out.Connects++
			if e.Device.Value == "" {
				// The auditd mapping requires a host, so this is a store
				// that predates it or an event built by hand; counted as
				// away rather than shown as a host nobody named.
				out.Away++
				return nil
			}
			t := tally(e.Device.Value)
			egressConnect(t, e)
			return nil
		case collector.SourceHeartbeat:
			out.Beats++
			host := e.Raw["host"]
			if host == "" {
				out.BeatsNoHost++
				return nil
			}
			t := tally(host)
			t.claimed = true
			if e.Received.After(t.h.LastBeat) {
				t.h.LastBeat = e.Received
				if e.Device.Value != "" {
					t.h.Recorder = e.Device.Value
				}
			}
			egressDeclare(t, e)
			return nil
		case collector.SourceWatch:
			// A watch event claims its host the way a heartbeat does: a
			// recorder shipping file evidence from a machine is a recorder
			// speaking for that machine.
			if e.Raw["host"] == "" {
				return nil
			}
			t := tally(e.Raw["host"])
			t.claimed = true
			egressDeclare(t, e)
			return nil
		}
		return nil
	})
	if err != nil {
		return EgressReport{}, err
	}

	for key, t := range by {
		if !t.claimed {
			// A host only connect events named: counted in the header, no
			// row, because nothing here can say a recorder ever spoke for it.
			out.AwayHost++
			out.Away += t.h.Connects + t.h.Unix + t.h.Undecoded
			delete(by, key)
			continue
		}
		h := t.h
		for _, d := range t.dest {
			h.Dest = append(h.Dest, *d)
		}
		sort.Slice(h.Dest, func(i, j int) bool {
			if h.Dest[i].N != h.Dest[j].N {
				return h.Dest[i].N > h.Dest[j].N
			}
			if h.Dest[i].Addr != h.Dest[j].Addr {
				return h.Dest[i].Addr < h.Dest[j].Addr
			}
			return h.Dest[i].Port < h.Dest[j].Port
		})
		h.DestShown = h.Dest
		if len(h.Dest) > egressDestShown {
			h.DestShown = h.Dest[:egressDestShown]
			h.DestMore = len(h.Dest) - egressDestShown
		}
		h.Agents = setList(t.agents)
		h.AgentList = strings.Join(h.Agents, ", ")
		h.LastAgo = agoAt(h.Last.Unix(), now)
		out.Hosts = append(out.Hosts, h)
	}
	// The most recently connecting host first — the machine somebody should
	// read about next — with the host name breaking ties so two loads of the
	// same page read the same.
	sort.Slice(out.Hosts, func(i, j int) bool {
		if !out.Hosts[i].Last.Equal(out.Hosts[j].Last) {
			return out.Hosts[i].Last.After(out.Hosts[j].Last)
		}
		return out.Hosts[i].Host < out.Hosts[j].Host
	})
	return out, nil
}

// egressConnect folds one auditd connect event into its host's tally.
//
// A record with an address and a port is a destination; with an address and
// no port it is an AF_UNIX path (the SOCKADDR decoder returns the path and an
// empty port), which never leaves the host and is not egress; with neither it
// is a connect whose destination never arrived — counted, because the connect
// happened, and shown as a gap rather than dropped.
func egressConnect(t *egressTally, e telemetry.Event) {
	addr, port := e.Raw["addr"], e.Raw["port"]
	h := &t.h
	switch {
	case addr == "":
		h.Undecoded++
	case port == "":
		h.Unix++
	default:
		h.Connects++
		if port != "80" && port != "443" {
			h.NonWeb++
		}
		if e.Disposition == telemetry.DispositionFailed {
			h.Failed++
		}
		key := addr + ":" + port
		d := t.dest[key]
		if d == nil {
			d = &EgressDest{Addr: addr, Port: port,
				First: e.Received, Last: e.Received}
			t.dest[key] = d
		}
		d.N++
		if e.Disposition == telemetry.DispositionFailed {
			d.Failed++
		}
		if e.Received.Before(d.First) {
			d.First = e.Received
		}
		if e.Received.After(d.Last) {
			d.Last = e.Received
		}
	}
	if h.First.IsZero() || e.Received.Before(h.First) {
		h.First = e.Received
	}
	if e.Received.After(h.Last) {
		h.Last = e.Received
	}
}

// egressDeclare reads the declared-mapping fields one collector event carried
// — the whole list in raw.agents, and the single name in raw.agent when the
// list had exactly one — into the host's union. The union over the window is
// the honest join: a declaration changed mid-window shows both names, and the
// page says "declared in this window" rather than "declared".
func egressDeclare(t *egressTally, e telemetry.Event) {
	for _, f := range []string{e.Raw["agents"], e.Raw["agent"]} {
		for _, n := range strings.Split(f, ",") {
			if n = strings.TrimSpace(n); n != "" {
				t.agents[n] = true
			}
		}
	}
}

// handleEgress is the board: every recorder host, where it connected, and
// who is declared to run on it, over the same seven days the Agents board
// beside it counts.
func (s *Server) handleEgress(w http.ResponseWriter, r *http.Request) {
	p, ok := s.securityCan(w, r, auth.ActTriage)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	data := map[string]any{"Nav": "agents", "Title": "Agent egress",
		"Principal": p}
	if s.Events == nil || s.Events.Open == nil {
		data["Unavailable"] = "This build was started without a telemetry " +
			"store. That is not the same as a fleet of quiet recorders: a " +
			"board showing none would say they connect nowhere, and this " +
			"build cannot see whether they do."
		s.render(w, r, "egress.html", data)
		return
	}
	sp, closer, err := s.Events.Open()
	if err != nil {
		if errors.Is(err, ErrNeverCollected) {
			data["Unavailable"] = "Nothing has ever been collected here, so " +
				"no recorder's connects have been observed. That is not an " +
				"estate of machines that connect nowhere — it is one nothing " +
				"is watching. Connect events arrive with the vaigil-collector's " +
				"auditd tail."
			s.render(w, r, "egress.html", data)
			return
		}
		data["Unavailable"] = "The telemetry store could not be opened: " +
			err.Error() + ". A store that cannot be read is not a store " +
			"with no egress in it."
		s.render(w, r, "egress.html", data)
		return
	}
	defer func() { _ = closer() }()

	report, err := EgressScan(sp, time.Now().UTC())
	if err != nil {
		data["Unavailable"] = "The telemetry store could not be read " +
			"through: " + err.Error()
		s.render(w, r, "egress.html", data)
		return
	}
	data["Report"] = report
	s.render(w, r, "egress.html", data)
}
