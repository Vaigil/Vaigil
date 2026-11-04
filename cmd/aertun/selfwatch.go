// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// aertun watching itself.
//
// Every security-relevant thing this program does is already in its audit
// log: failed sign-ins past the threshold, tokens issued, access granted,
// settings weakened, the log itself moved, an extension refused. Until now
// that log answered questions somebody thought to ask. It now goes into the
// event store under its own source, so the detection rules — the same
// engine, the same queue, the same incidents as every other platform's
// logs — read it continuously, and a rule pack ships for it (aertun.*).
//
// This is the application-layer intrusion detection OWASP's AppSensor
// describes: detection points inside the application, where the context
// is, rather than a network sensor guessing from outside.
//
// What is copied is what the audit log holds and nothing more: the action,
// its outcome and resource, the kind of actor, and the few details a rule
// needs. The principal is the pseudonym the log already stores.

// SelfSource is the source aertun's own audit records are stored under.
const SelfSource = "aertun/audit"

// AgentSource is the source records of what a model did are stored under:
// the analyst's proposals and the tool calls agents made through MCP. A
// model is watched like any other principal — what it proposed, how often,
// and what it was refused — by the same rules that read every other
// platform's events.
const AgentSource = "aertun/agent"

// selfDetail are the audit details a rule about aertun may read. Others are
// left out: they are either free text somebody typed, or not needed.
var selfDetail = []string{"role", "surface", "failures", "setting", "to",
	"autonomy", "agent", "reason", "conversation"}

// agentDetail are the audit details a rule about a model may read: what it
// proposed and where, which tool it called, and the closed words. The
// reason a model gave is not among them — that is the model's own text
// about attacker-controlled evidence, and it stays in the audit log, where
// it is already marked as what it is. Neither is the person an agent acted
// for: their name is personal data, and the event store is read wider than
// the log. The agent itself is the actor, under the log's pseudonym.
//
// The exchange's words are here because they are closed ones: the scope a
// consent carried, the depth of the chain, the tools the intersection left
// — facts a rule can match, not prose a model wrote.
var agentDetail = []string{"finding", "agent", "client", "to", "why",
	"confidence", "tool", "operation", "used_in", "used_out",
	"scope", "depth", "tools"}

type selfCursor struct {
	Seq int64 `json:"seq"`
}

func selfCursorPath(root string) string {
	return filepath.Join(root, "detect", "self.json")
}

// storeSelfEvents copies the audit records written since the last call into
// the event store, and returns them for the rules to read at once. Records
// of what a model did are left to storeAgentEvents, which stores them under their own
// source with the agent as the actor.
func storeSelfEvents(root string, sp *spool.Spool, now time.Time) ([]telemetry.Event, error) {
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return nil, err
	}
	var cur selfCursor
	if b, rerr := os.ReadFile(selfCursorPath(root)); rerr == nil {
		if jerr := json.Unmarshal(b, &cur); jerr != nil {
			return nil, fmt.Errorf("self.json: %w", jerr)
		}
	}
	var stored []telemetry.Event
	last := cur.Seq
	// Collected and stored as one batch: the audit log is read whole, and a
	// run that locked and fsynced the index per record pays the disk for
	// every line of its own bookkeeping.
	for _, e := range events {
		if e.Seq <= cur.Seq {
			continue
		}
		last = e.Seq
		if e.Kind == audit.KindAI {
			continue
		}
		at, perr := time.Parse(time.RFC3339Nano, e.At)
		if perr != nil {
			at = now
		}
		disposition := telemetry.DispositionAllowed
		switch e.Outcome {
		case audit.Denied:
			disposition = telemetry.DispositionBlocked
		case audit.Failure:
			disposition = telemetry.DispositionFailed
		}
		raw := map[string]string{"action": e.Action, "outcome": string(e.Outcome),
			"resource": e.Resource, "kind": string(e.Kind)}
		for _, k := range selfDetail {
			if v, ok := e.Detail[k]; ok {
				raw[k] = v
			}
		}
		if _, ok := e.Detail["accepted_risk"]; ok {
			// Whether a risk was accepted, not the reason somebody typed.
			raw["accepted_risk"] = "yes"
		}
		stored = append(stored, telemetry.Event{Time: at, Received: now,
			Class: telemetry.ClassAPIActivity, Disposition: disposition,
			Source: SelfSource, Message: e.Action,
			Actor: telemetry.ID{Issuer: "aertun", Value: e.Principal},
			Raw:   raw})
	}
	if last == cur.Seq {
		return stored, nil
	}
	if len(stored) > 0 {
		if _, aerr := sp.AppendBatch(stored); aerr != nil {
			return nil, aerr
		}
	}
	b, _ := json.Marshal(selfCursor{Seq: last})
	if err := os.MkdirAll(filepath.Dir(selfCursorPath(root)), 0o700); err != nil {
		return stored, err
	}
	return stored, atomicfile.Write(selfCursorPath(root), b, 0o600)
}

func agentCursorPath(root string) string {
	return filepath.Join(root, "detect", "agent.json")
}

// storeAgentEvents copies the audit records written by models since the
// last call into the event store under AgentSource, with the agent as the
// actor and the model that acted in the details. Its cursor is its own, so
// it advances over the same log storeSelfEvents reads without either
// depending on the other.
func storeAgentEvents(root string, sp *spool.Spool, now time.Time) ([]telemetry.Event, error) {
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return nil, err
	}
	var cur selfCursor
	if b, rerr := os.ReadFile(agentCursorPath(root)); rerr == nil {
		if jerr := json.Unmarshal(b, &cur); jerr != nil {
			return nil, fmt.Errorf("agent.json: %w", jerr)
		}
	}
	var stored []telemetry.Event
	last := cur.Seq
	// One batch, for the same reason as storeSelfEvents: these records
	// arrive together and are stored together.
	for _, e := range events {
		if e.Seq <= cur.Seq {
			continue
		}
		last = e.Seq
		if e.Kind != audit.KindAI {
			continue
		}
		at, perr := time.Parse(time.RFC3339Nano, e.At)
		if perr != nil {
			at = now
		}
		disposition := telemetry.DispositionAllowed
		switch e.Outcome {
		case audit.Denied:
			disposition = telemetry.DispositionBlocked
		case audit.Failure:
			disposition = telemetry.DispositionFailed
		}
		raw := map[string]string{"action": e.Action, "outcome": string(e.Outcome),
			"resource": e.Resource, "model": e.Model}
		for _, k := range agentDetail {
			if v, ok := e.Detail[k]; ok {
				raw[k] = v
			}
		}
		stored = append(stored, telemetry.Event{Time: at, Received: now,
			Class: telemetry.ClassAPIActivity, Disposition: disposition,
			Source: AgentSource, Message: e.Action,
			Actor: telemetry.ID{Issuer: "aertun", Value: e.Principal},
			Raw:   raw})
	}
	if last == cur.Seq {
		return stored, nil
	}
	if len(stored) > 0 {
		if _, aerr := sp.AppendBatch(stored); aerr != nil {
			return nil, aerr
		}
	}
	b, _ := json.Marshal(selfCursor{Seq: last})
	if err := os.MkdirAll(filepath.Dir(agentCursorPath(root)), 0o700); err != nil {
		return stored, err
	}
	return stored, atomicfile.Write(agentCursorPath(root), b, 0o600)
}

// selfLogGrew reports whether the audit log holds anything the rules have
// not read, other than the records of their own runs, which would
// otherwise make every pass the reason for the next.
func selfLogGrew(root string) (bool, error) {
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return false, err
	}
	var cur selfCursor
	if b, rerr := os.ReadFile(selfCursorPath(root)); rerr == nil {
		if jerr := json.Unmarshal(b, &cur); jerr != nil {
			return false, fmt.Errorf("self.json: %w", jerr)
		}
	}
	for i := len(events) - 1; i >= 0 && events[i].Seq > cur.Seq; i-- {
		if events[i].Action != "detect.run" {
			return true, nil
		}
	}
	return false, nil
}
