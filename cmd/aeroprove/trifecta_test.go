// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/aeroprove/aeroprove/internal/telemetry"
)

// The lethal trifecta, rehearsed end to end: the three labelled legs the
// quiet rules count, and the one-hour ordered window over one trace that
// turns them into a finding. Every rehearsal puts the labels on the events
// exactly as the ingest boundary stamps them, because the sequence is only
// as honest as the declaration it stands on.

// trifectaAt is an hour boundary well before now, so the one-hour window
// each leg falls in has closed behind the watermark whatever quarter-hour
// the test runs in.
func trifectaAt() time.Time {
	return closedWindow().Truncate(time.Hour)
}

// leg is one labelled tool call as the ingest boundary stores it: the
// operation in the message, the trace the span itself carried, and the
// labels the tool-label table declared for the tool. An empty labels is
// the unlabelled tool — the table that has not caught up, or never named
// the tool at all.
func leg(agent, trace, tool, labels string, at time.Time) labelled {
	raw := map[string]string{"operation": "execute_tool", "tool": tool,
		"status": "ok", "trace_id": trace}
	if labels != "" {
		raw["labels"] = labels
	}
	return labelled{trace + " " + tool, true, telemetry.Event{
		Source: "otel/genai", Class: telemetry.ClassAPIActivity,
		Disposition: telemetry.DispositionAllowed,
		Actor:       telemetry.ID{Issuer: "otel", Value: agent},
		Message:     "execute_tool", Time: at, Received: at.Add(time.Second),
		Raw: raw}}
}

// The table's own tools, one per leg: the fetcher that reads the open web,
// the query that reads private data, the POST that sends data out.
func untrustedLeg(agent, trace string, at time.Time) labelled {
	return leg(agent, trace, "fetch", "untrusted-content", at)
}

func sensitiveLeg(agent, trace string, at time.Time) labelled {
	return leg(agent, trace, "sql_query", "sensitive-data", at)
}

func egressLeg(agent, trace string, at time.Time) labelled {
	return leg(agent, trace, "http_post", "egress", at)
}

// TestTrifectaFiresOnceOnTheWholeChainInOneTrace.
//
// Untrusted, then sensitive, then egress, in that order, inside the hour,
// on the one trace the spans themselves carried: one finding, about that
// trace, high because the sequence is the pattern and not proof of
// exfiltration. The three legs raise nothing of their own — they are
// counted, not shown — and a second run over the same window does not
// raise the chain twice.
func TestTrifectaFiresOnceOnTheWholeChainInOneTrace(t *testing.T) {
	root, rules := packSite(t)
	w0 := trifectaAt()
	agent := "refunder"
	appendEvents(t, root, []labelled{
		untrustedLeg(agent, "trace-fire", w0.Add(5*time.Minute)),
		sensitiveLeg(agent, "trace-fire", w0.Add(20*time.Minute)),
		egressLeg(agent, "trace-fire", w0.Add(40*time.Minute)),
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	tri := got["corr.lethal-trifecta"]
	if len(tri) != 1 {
		t.Fatalf("the whole chain raised %d finding(s), want the one: %+v",
			len(tri), tri)
	}
	if !strings.Contains(tri[0].Entity.String(), "trace-fire") {
		t.Errorf("the finding is about %s, not the trace the spans carried",
			tri[0].Entity)
	}
	if tri[0].Severity != telemetry.SeverityHigh {
		t.Errorf("the chain is severity %d; the sequence earns high and "+
			"not critical, because triage reads the session", tri[0].Severity)
	}
	if !strings.Contains(tri[0].Evidence[0].What, "3 within") {
		t.Errorf("the evidence does not say what was counted: %s",
			tri[0].Evidence[0].What)
	}
	for _, quiet := range []string{"otel.untrusted-read",
		"otel.sensitive-read", "otel.egress-call"} {
		if len(got[quiet]) != 0 {
			t.Errorf("%s raised %d finding(s) of its own", quiet, len(got[quiet]))
		}
	}
	// The same window read again is the same one finding, not two.
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	if tri = bySource(queue(t, root))["corr.lethal-trifecta"]; len(tri) != 1 ||
		tri[0].Seen != 1 {
		t.Errorf("a second run raised the chain again: %+v", tri)
	}
}

// TestTrifectaDoesNotFireOnTwoLegsOrTheWrongOrder.
//
// Each pair of legs in order is half a chain, the full chain backwards is
// a different shape of work, and none of them is the hijack in order —
// which is the precision the ordering buys and the reason the rule is
// three legs rather than three findings.
func TestTrifectaDoesNotFireOnTwoLegsOrTheWrongOrder(t *testing.T) {
	root, rules := packSite(t)
	w0 := trifectaAt()
	agent := "refunder"
	at := func(m int) time.Time { return w0.Add(time.Duration(m) * time.Minute) }
	appendEvents(t, root, []labelled{
		// The prefix: untrusted then sensitive, no egress.
		untrustedLeg(agent, "trace-prefix", at(5)),
		sensitiveLeg(agent, "trace-prefix", at(20)),
		// The back pair: sensitive then egress, no untrusted leg before them.
		sensitiveLeg(agent, "trace-backpair", at(5)),
		egressLeg(agent, "trace-backpair", at(20)),
		// A skip: untrusted straight to egress.
		untrustedLeg(agent, "trace-skip", at(5)),
		egressLeg(agent, "trace-skip", at(20)),
		// The whole chain, backwards.
		egressLeg(agent, "trace-reverse", at(5)),
		sensitiveLeg(agent, "trace-reverse", at(20)),
		untrustedLeg(agent, "trace-reverse", at(40)),
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	if tri := bySource(queue(t, root))["corr.lethal-trifecta"]; len(tri) != 0 {
		t.Errorf("half chains and a reversed chain raised %d finding(s): %+v",
			len(tri), tri)
	}
}

// TestTrifectaJoinsOnlyInsideTheTraceTheSpansCarried.
//
// The join is the trace the events themselves name, not the agent and not
// the hour: the same three legs one trace apart are three sessions doing
// one thing each, and joining them across traces would be the false
// precision the group-by exists to refuse.
func TestTrifectaJoinsOnlyInsideTheTraceTheSpansCarried(t *testing.T) {
	root, rules := packSite(t)
	w0 := trifectaAt()
	agent := "refunder"
	appendEvents(t, root, []labelled{
		untrustedLeg(agent, "trace-one", w0.Add(5*time.Minute)),
		sensitiveLeg(agent, "trace-two", w0.Add(20*time.Minute)),
		egressLeg(agent, "trace-three", w0.Add(40*time.Minute)),
		// A different agent's complete chain, to prove the finding that
		// does fire is the trace's and not the hour's.
		untrustedLeg("runner-b", "trace-whole", w0.Add(6*time.Minute)),
		sensitiveLeg("runner-b", "trace-whole", w0.Add(21*time.Minute)),
		egressLeg("runner-b", "trace-whole", w0.Add(41*time.Minute)),
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	tri := bySource(queue(t, root))["corr.lethal-trifecta"]
	if len(tri) != 1 || !strings.Contains(tri[0].Entity.String(), "trace-whole") {
		t.Fatalf("the split traces joined: %+v", tri)
	}
}

// TestTrifectaStaysQuietWhenTheTableNamedNothing.
//
// The legs are declarations, not inferences: a chain whose tools the table
// never named joins nothing, and so does a chain that lost one leg to a
// rename the table has not caught up with — the honest miss, recoverable
// in triage, where a label guessed from a tool's name would not be.
func TestTrifectaStaysQuietWhenTheTableNamedNothing(t *testing.T) {
	root, rules := packSite(t)
	w0 := trifectaAt()
	agent := "refunder"
	at := func(m int) time.Time { return w0.Add(time.Duration(m) * time.Minute) }
	appendEvents(t, root, []labelled{
		// Tools that read and send by other names, none of them declared.
		leg(agent, "trace-unlabelled", "fs_read", "", at(5)),
		leg(agent, "trace-unlabelled", "db_query", "", at(20)),
		leg(agent, "trace-unlabelled", "post_update", "", at(40)),
		// The real tools, one leg renamed past the table.
		untrustedLeg(agent, "trace-lagging", at(5)),
		leg(agent, "trace-lagging", "sql_query_v2", "", at(20)),
		egressLeg(agent, "trace-lagging", at(40)),
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	if tri := got["corr.lethal-trifecta"]; len(tri) != 0 {
		t.Errorf("chains the table never declared raised %d finding(s): %+v",
			len(tri), tri)
	}
	for _, quiet := range []string{"otel.untrusted-read",
		"otel.sensitive-read", "otel.egress-call"} {
		if len(got[quiet]) != 0 {
			t.Errorf("%s raised %d finding(s) from tools it was never told about",
				quiet, len(got[quiet]))
		}
	}
}

// TestTrifectaDoesNotReachAcrossItsWindow.
//
// An hour is the window because an agent picks up its work on the run; the
// untrusted read two hours before the egress is a different session doing
// different work, and a window longer than that would join chains that had
// nothing to do with each other.
func TestTrifectaDoesNotReachAcrossItsWindow(t *testing.T) {
	root, rules := packSite(t)
	w0 := trifectaAt()
	agent := "refunder"
	appendEvents(t, root, []labelled{
		untrustedLeg(agent, "trace-slow", w0.Add(5*time.Minute)),
		sensitiveLeg(agent, "trace-slow", w0.Add(20*time.Minute)),
		// Two hours and a bit later: past the window, still well before now.
		egressLeg(agent, "trace-slow", w0.Add(125*time.Minute)),
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	if tri := bySource(queue(t, root))["corr.lethal-trifecta"]; len(tri) != 0 {
		t.Errorf("legs two hours apart raised %d finding(s): %+v", len(tri), tri)
	}
}
