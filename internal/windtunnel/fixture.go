// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"time"

	"github.com/aertun/aertun/internal/telemetry"
)

// The default base stream: a synthetic support-desk morning, shaped like the
// OTLP boundary's output — the honest default when no recorded stream is
// named.
//
// Generated, not hand-typed, in the internal/bench/generate.go pattern: each
// session is a line of Go a reviewer reads with its intent beside it, and
// the whole corpus is a function of nothing — no clock, no environment, no
// network — so two runs produce byte-identical base streams and a scorecard
// digest is worth the bytes it names.
//
// # The honest shape, held to
//
// A base stream must be quiet in exactly the ways a normal day is quiet: no
// trace carries untrusted-then-sensitive-then-egress in order, no agent
// approaches the burst rate, no host carries a mapped config change. It must
// also arrive like traffic: seconds late for the spans, and one late batch
// from the cloud audit export — the two events in thirty-eight-minutes-late
// territory that keep the lateness histogram honest and the watermark
// conservative, exactly as the spool's own commentary describes a small
// deployment behaving.

// FixtureName is the default base stream's name, stamped into the scorecard.
const FixtureName = "wt-baseline-v1"

// fixtureDay is the morning the corpus records: a fixed date, because a
// base stream with a moving clock is a different stream every run.
var fixtureDay = time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)

// at is minutes into the recorded morning.
func at(min, sec int) time.Time {
	return fixtureDay.Add(time.Duration(min)*time.Minute +
		time.Duration(sec)*time.Second)
}

// delays cycles the arrival delay of on-time traffic: two to eight seconds,
// the buckets a live agent and a nearby collector actually land in.
var delays = []time.Duration{2 * time.Second, 3 * time.Second,
	4 * time.Second, 5 * time.Second, 6 * time.Second, 8 * time.Second}

// genai is one otel/genai span as the boundary stores it.
func genai(agent, message string, at time.Time, delay int,
	raw map[string]string) telemetry.Event {
	return telemetry.Event{
		Source: "otel/genai", Class: telemetry.ClassAPIActivity,
		Disposition: telemetry.DispositionAllowed,
		Actor:       telemetry.ID{Issuer: "otel", Value: agent},
		Message:     message, Time: at, Received: at.Add(delays[delay%len(delays)]),
		Raw: raw,
	}
}

// watch is one collector/watch file event as the recorder stores it. Hosts
// here are deliberately unmapped: no operator has declared any agent to run
// on them, so no watch event in the base stream can join a tool call.
func watch(host, path, kind, op, sha string, at time.Time,
	delay time.Duration) telemetry.Event {
	return telemetry.Event{
		Source: "collector/watch", Class: telemetry.ClassFileActivity,
		Disposition: telemetry.DispositionAllowed,
		Device:      telemetry.ID{Issuer: "collector", Value: host},
		Message:     path + " " + op + " (" + kind + ")",
		Time:        at, Received: at.Add(delay),
		Raw: map[string]string{"path": path, "kind": kind, "op": op,
			"sha256": sha, "size": "512", "host": host},
	}
}

// DefaultBase generates the default base stream: a support-desk morning,
// machine-paced and boring on purpose.
func DefaultBase() []telemetry.Event {
	var out []telemetry.Event
	i := 0
	next := func() int { i++; return i }

	// The refunder's morning: three ordinary sessions, each reading inbound
	// mail and querying the customer table. Two legs, never three — the
	// mail carries both labels because mail is both things at once, and no
	// session sends anything anywhere. A slice, because the corpus is a
	// function of nothing and a map's iteration order is not nothing.
	refunderTraces := []string{
		"4a01c2dd9e6b4c01a77f5c2d3b8e9012",
		"4a01c2dd9e6b4c01a77f5c2d3b8e9013",
		"4a01c2dd9e6b4c01a77f5c2d3b8e9014",
	}
	for s, trace := range refunderTraces {
		out = append(out,
			genai("refunder", "execute_tool", at(2+s*15, 0), next(),
				map[string]string{"operation": "execute_tool", "tool": "fetch",
					"status": "ok", "trace_id": trace,
					"labels": "untrusted-content"}),
			genai("refunder", "execute_tool", at(5+s*15, 30), next(),
				map[string]string{"operation": "execute_tool",
					"tool": "sql_query", "status": "ok", "trace_id": trace,
					"labels": "sensitive-data", "rows": "3"}))
	}

	// The refunder also works tickets: one issue read from the public
	// tracker, answered from the runbook. Reading an issue is ordinary
	// support work — the label says who could have written it, not that
	// anything was wrong — and the session's only other act is a write, so
	// the ordered chain cannot complete on it. This is also the honest
	// precondition for the injection scenario: a stream whose ingest
	// boundary has stamped read_issue untrusted has declared the tool, and
	// one that never did cannot host a session that reads one.
	out = append(out,
		genai("refunder", "execute_tool", at(9, 0), next(),
			map[string]string{"operation": "execute_tool", "tool": "read_issue",
				"status": "ok", "trace_id": "5e77b3aa1c2d4f09b7e6a8c5d3f20117",
				"labels": "untrusted-content", "issue": "repo-help#391"}),
		genai("refunder", "execute_tool", at(9, 40), next(),
			map[string]string{"operation": "execute_tool",
				"tool": "filesystem.write", "status": "ok",
				"trace_id": "5e77b3aa1c2d4f09b7e6a8c5d3f20117",
				"path":     "replies/391.md"}))

	// The reporter's runs: webhooks and posts to the destinations the
	// integration owns. Egress alone in its traces — the reporting agent
	// never reads untrusted content first, so the ordered chain cannot
	// complete on anything it does.
	for j, trace := range []string{
		"7c22e0ab41f94d77b0a1e5d3f6c80221",
		"7c22e0ab41f94d77b0a1e5d3f6c80222",
		"7c22e0ab41f94d77b0a1e5d3f6c80223",
	} {
		out = append(out, genai("reporter", "execute_tool", at(10+j*4, 0),
			next(), map[string]string{"operation": "execute_tool",
				"tool": "post_webhook", "status": "ok", "trace_id": trace,
				"labels": "egress", "dest": "https://hooks.example.internal/ticketing"}))
	}

	// The docs agent: internal search and a write, at reading pace.
	out = append(out,
		genai("docs-bot", "execute_tool", at(22, 0), next(),
			map[string]string{"operation": "execute_tool", "tool": "search_docs",
				"status": "ok", "trace_id": "9d44f1cc02ab4e88c5f7a1b2d3e40556",
				"labels": "sensitive-data", "query": "refund SLA"}),
		genai("docs-bot", "execute_tool", at(24, 0), next(),
			map[string]string{"operation": "execute_tool",
				"tool": "filesystem.write", "status": "ok",
				"trace_id": "9d44f1cc02ab4e88c5f7a1b2d3e40556"}),
		genai("docs-bot", "execute_tool", at(26, 0), next(),
			map[string]string{"operation": "execute_tool",
				"tool": "filesystem.write", "status": "ok",
				"trace_id": "9d44f1cc02ab4e88c5f7a1b2d3e40557"}))

	// Model calls: the ordinary friction of the model plane. Not tool calls,
	// so nothing counts them.
	for j := 0; j < 4; j++ {
		out = append(out, genai("refunder", "invoke_chat_model", at(31+j, 0),
			next(), map[string]string{"operation": "invoke_chat_model",
				"model": "claude-sonnet-4-5", "status": "ok",
				"tokens_in": "812", "tokens_out": "96"}))
	}

	// The recorder watched two files change on hosts nobody mapped: ordinary
	// configuration noise that joins nothing.
	out = append(out,
		watch("ci02", "/etc/app.conf", "other", "changed", "e6d0b442",
			at(15, 0), 3*time.Second),
		watch("desk03", "/home/mira/.vimrc", "other", "changed", "31aa09e7",
			at(41, 0), 5*time.Second))

	// The cloud audit export: two events that happened at 09:20 and arrived
	// thirty-eight minutes later. The late batch is the base stream's own
	// honest tail — the thing a watermark exists to wait for — and it is the
	// last arrival in the stream.
	out = append(out,
		watch("ci02", "/var/log/audit/audit.log", "other", "changed",
			"9f2c71d0", at(20, 0), 38*time.Minute),
		watch("ci02", "/var/log/audit/audit.log.1", "other", "changed",
			"0d3e88f2", at(20, 30), 38*time.Minute+2*time.Second))

	return out
}
