// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/aeroprove/aeroprove/internal/telemetry"
)

// The agent-telemetry rules, replayed: the collector's watch facts, the
// GenAI spans the OTLP endpoint stores, and the two model platforms' audit
// logs, each fired on a corpus shaped like the events its source really
// keeps — the mapped field names, the leaf names internal/source keeps —
// and on the look-alikes beside them. The watch stream is the interesting
// one: its events carry no actor at all, so what a watch rule says about
// attribution it says honestly, and the findings fold per rule the way an
// actorless stream must.

// watchOn is one watched-path fact as the collector endpoint stores it: the
// path, kind, op, hash and size in raw, the recorder as the device, and no
// actor — the recorder watches files, not processes, and does not pretend
// otherwise.
func watchOn(recorder, path, kind, op string, at time.Time) labelled {
	raw := map[string]string{"path": path, "kind": kind, "op": op,
		"host": recorder}
	if op != "removed" {
		raw["sha256"], raw["size"] = "b42d4f9e", "612"
	}
	return labelled{"watch " + path + " " + op, true, telemetry.Event{
		Source: "collector/watch", Class: telemetry.ClassFileActivity,
		Device:  telemetry.ID{Issuer: "collector", Value: recorder},
		Message: path + " " + op + " (" + kind + ")",
		Time:    at, Received: at.Add(time.Second),
		Raw: raw}}
}

// genaiOn is one GenAI span as the otel/genai mapping stores it: the
// operation in the message, the agent as the actor, the span's status as
// the disposition, and the closed field set — never a prompt or a
// completion, whose lengths are all that crossed the boundary.
func genaiOn(agent, operation, tool, model string, failed bool,
	at time.Time) labelled {
	d, status := telemetry.DispositionAllowed, "ok"
	if failed {
		d, status = telemetry.DispositionFailed, "error"
	}
	raw := map[string]string{"operation": operation, "status": status,
		"trace_id":     "5b8efff798038103d269b633813fc60c",
		"conversation": "conv-0192", "tokens_in": "1520",
		"tokens_out": "344"}
	if tool != "" {
		raw["tool"] = tool
	}
	if model != "" {
		raw["model"] = model
	}
	e := telemetry.Event{Source: "otel/genai",
		Class: telemetry.ClassAPIActivity, Disposition: d,
		Actor:   telemetry.ID{Issuer: "otel", Value: agent},
		Message: operation, Time: at, Received: at.Add(time.Second),
		Raw: raw}
	if model != "" {
		e.Target = telemetry.ID{Issuer: "otel", Value: model}
	}
	return labelled{"genai " + agent + " " + operation, true, e}
}

// openaiOn is one OpenAI audit record as the connector flattens it: the
// event type in the message, the session's user as the actor where the
// record has one, and the type-specific payload under its own name.
func openaiOn(actor, typ string, extra map[string]string,
	at time.Time) labelled {
	d := telemetry.DispositionAllowed
	if strings.HasSuffix(typ, ".failed") {
		d = telemetry.DispositionFailed
	}
	raw := map[string]string{"id": "audit_log-1", "type": typ}
	for k, v := range extra {
		raw[k] = v
	}
	e := telemetry.Event{Source: "openai/audit",
		Class: telemetry.ClassAPIActivity, Disposition: d,
		Message: typ, Time: at, Received: at.Add(time.Second), Raw: raw}
	if actor != "" {
		e.Actor = telemetry.ID{Issuer: "openai", Value: actor}
		e.Raw["email"] = "ada@acme.test"
	}
	if p, ok := extra["project"]; ok {
		e.Target = telemetry.ID{Issuer: "openai", Value: p}
	}
	return labelled{"openai " + typ, true, e}
}

// anthropicOn is one Compliance API activity as the connector flattens it.
// An empty actor is the machine case — an admin key or a service account
// did it — which the feed carries under its own names and no person at
// all.
func anthropicOn(actor, typ string, extra map[string]string,
	at time.Time) labelled {
	d := telemetry.DispositionAllowed
	if strings.Contains(typ, "login_failed") {
		d = telemetry.DispositionFailed
	}
	raw := map[string]string{"id": "activity_01", "type": typ,
		"organization_id": "org_01Wv"}
	for k, v := range extra {
		raw[k] = v
	}
	e := telemetry.Event{Source: "anthropic/audit",
		Class: telemetry.ClassAPIActivity, Disposition: d,
		Message: typ, Time: at, Received: at.Add(time.Second), Raw: raw}
	if actor != "" {
		e.Actor = telemetry.ID{Issuer: "anthropic", Value: actor}
		e.Raw["person"] = "ada@acme.test"
	}
	return labelled{"anthropic " + typ, true, e}
}

// A config edited or appearing is severity 3; the same config vanishing is
// the louder, separate rule. The watch stream carries no actor, so the
// findings fold per rule and the count says how many — which is the honest
// attribution a file watcher can make.
func TestAgentConfigFilesChangedAndRemovedAreSeparateFindings(t *testing.T) {
	root, rules := packSite(t)
	w0 := closedWindow()
	at := func(m int) time.Time { return w0.Add(time.Duration(m) * time.Minute) }
	appendEvents(t, root, []labelled{
		watchOn("build01", "/home/dana/.mcp.json", "mcp-config", "changed", at(1)),
		watchOn("build01", "/home/dana/CLAUDE.md", "agent-config", "created", at(2)),
		watchOn("build01", "/home/dana/.cursorrules", "agent-config", "removed", at(3)),
		watchOn("build01", "/home/dana/.mcp.json", "mcp-config", "removed", at(4)),
		// The look-alikes: rotation cleanup and a file watched without a
		// kind that means anything.
		{"key removed", false,
			watchOn("build01", "/home/dana/.ssh/id_old", "key", "removed", at(5)).event},
		{"other changed", false,
			watchOn("build01", "/etc/app.conf", "other", "changed", at(6)).event},
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	changed := got["collector.agent-config-changed"]
	if len(changed) != 1 || changed[0].Seen != 2 {
		t.Fatalf("config changes: %+v", changed)
	}
	removed := got["collector.agent-config-removed"]
	if len(removed) != 1 || removed[0].Seen != 2 {
		t.Fatalf("config removals: %+v", removed)
	}
	if len(removed) == 1 && removed[0].Severity != telemetry.SeverityHigh {
		t.Errorf("a deleted config is the louder event: severity %d",
			removed[0].Severity)
	}
	if len(got["collector.key-material-changed"]) != 0 {
		t.Errorf("key material counted as a config change: %+v",
			got["collector.key-material-changed"])
	}
}

// Key and environment changes are placed for triage at low severity rather
// than silenced: rotation and .env edits are daily work, and the hash in
// the finding is what triage compares. Removals are the benign half of
// rotation and count for nothing.
func TestAgentKeyMaterialChangesArePlacedForTriageNotSilence(t *testing.T) {
	root, rules := packSite(t)
	w0 := closedWindow()
	at := func(m int) time.Time { return w0.Add(time.Duration(m) * time.Minute) }
	appendEvents(t, root, []labelled{
		watchOn("build01", "/home/dana/.ssh/authorized_keys", "key", "changed", at(1)),
		watchOn("build01", "/home/dana/.env", "env", "created", at(2)),
		watchOn("dev02", "/home/sam/.ssh/id_ed25519", "key", "changed", at(3)),
		{"an old key removed", false,
			watchOn("build01", "/home/dana/.ssh/id_old", "key", "removed", at(4)).event},
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	material := got["collector.key-material-changed"]
	if len(material) != 1 || material[0].Seen != 3 {
		t.Fatalf("key material: %+v", material)
	}
	if len(material) == 1 && material[0].Severity != telemetry.SeverityLow {
		t.Errorf("placed for triage, not silenced: %+v", material[0])
	}
	for _, quiet := range []string{"collector.agent-config-changed",
		"collector.agent-config-removed"} {
		if len(got[quiet]) != 0 {
			t.Errorf("%s raised %d finding(s) of its own", quiet, len(got[quiet]))
		}
	}
}

// The model planes' administration: a key made, a key gone, a role or a
// member changed — each fires on its own action, and the neighbour actions
// (a key renamed, a failed sign-in) do not. Machine actors have no person,
// and their findings stand without one.
func TestAgentModelPlaneAdministrationFiresOnItsActions(t *testing.T) {
	root, rules := packSite(t)
	w0 := closedWindow()
	at := func(m int) time.Time { return w0.Add(time.Duration(m) * time.Minute) }
	appendEvents(t, root, []labelled{
		openaiOn("user-77", "api_key.created",
			map[string]string{"project": "proj_1", "created_key": "key-A1"}, at(1)),
		// Deleted by a key rather than a session: no actor, still a finding.
		openaiOn("", "api_key.deleted",
			map[string]string{"acting_key": "key-A1", "deleted_key": "key-A1"}, at(2)),
		openaiOn("user-77", "role.assignment.created",
			map[string]string{"role_principal": "user-99",
				"role_resource": "proj_1"}, at(3)),
		openaiOn("user-99", "user.added",
			map[string]string{"added_user": "user-99", "added_role": "owner"}, at(4)),
		openaiOn("user-77", "invite.sent",
			map[string]string{"invite_email": "sam@acme.test",
				"invite_role": "member"}, at(5)),
		// The look-alikes: a rename and a failed sign-in.
		{"a key renamed", false, openaiOn("user-77", "api_key.updated",
			map[string]string{"updated_key": "key-A1"}, at(6)).event},
		{"a failed sign-in", false, openaiOn("user-99", "login.failed",
			map[string]string{"login_error": "invalid_credentials"}, at(7)).event},

		anthropicOn("user_01A", "api_key_created",
			map[string]string{"api_key_id": "key-B2"}, at(8)),
		anthropicOn("user_01A", "scoped_api_key_deleted",
			map[string]string{"api_key_id": "key-B2"}, at(9)),
		// An admin key did all of this: no person, and the findings stand.
		anthropicOn("", "admin_api_key_deleted",
			map[string]string{"actor_kind": "admin_api_key_actor",
				"acting_admin_key": "adminkey-1"}, at(10)),
		anthropicOn("", "claude_user_role_updated",
			map[string]string{"actor_kind": "admin_api_key_actor",
				"target_user": "user_01C", "role_now": "admin",
				"role_was": "member"}, at(11)),
		anthropicOn("user_01A", "primary_owner_transferred",
			map[string]string{"target_user": "user_01C"}, at(12)),
		// The look-alike: a failed SSO sign-in.
		{"a failed SSO sign-in", false, anthropicOn("user_01A",
			"sso_login_failed", map[string]string{"auth_method": "sso"}, at(13)).event},
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	for _, id := range []string{"openai.api-key-created",
		"openai.api-key-deleted", "anthropic.api-key-created"} {
		if len(got[id]) != 1 {
			t.Errorf("%s: %d finding(s), want the one action", id, len(got[id]))
		}
	}
	// A key deleted by its owner and an admin key deleted by nobody's
	// hand: two findings, one of them with no person to name.
	if revoked := got["anthropic.api-key-revoked"]; len(revoked) != 2 {
		t.Errorf("anthropic.api-key-revoked: %d finding(s), want the person's "+
			"and the machine's", len(revoked))
	}
	// Two hands on the OpenAI side: Ada's assignment and invite fold, Sam's
	// addition stands alone. Two on the Anthropic side: the owner's, and
	// the admin key's with no person at all.
	if roles := got["openai.role-or-member-changed"]; len(roles) != 2 {
		t.Errorf("openai roles: %d findings, want one per hand", len(roles))
	}
	if roles := got["anthropic.role-or-member-changed"]; len(roles) != 2 {
		t.Errorf("anthropic roles: %d findings, want the owner's and the machine's",
			len(roles))
	}
}

// One hundred and twenty tool calls in fifteen minutes is a call every
// seven and a half seconds without pause; a hundred and nineteen is below
// the line, and agent invocations and model calls are not tool calls at
// all. The base rule itself raises nothing.
func TestAgentToolCallsAreARateNotACall(t *testing.T) {
	root, rules := packSite(t)
	w0 := closedWindow()
	var corpus []labelled
	for i := 0; i < 120; i++ {
		corpus = append(corpus, genaiOn("agent-7", "execute_tool",
			"filesystem.write", "claude-sonnet-4-5", i%13 == 0,
			w0.Add(time.Duration(i+1)*5*time.Second)))
	}
	// One short, by another agent.
	for i := 0; i < 119; i++ {
		corpus = append(corpus, genaiOn("runner-b", "execute_tool",
			"gh.pr", "gpt-5.2-codex", false,
			w0.Add(time.Duration(i+1)*5*time.Second)))
	}
	// Not tool calls at all, however many.
	for i := 0; i < 5; i++ {
		corpus = append(corpus, genaiOn("agent-7", "invoke_agent", "",
			"claude-sonnet-4-5", false, w0.Add(time.Duration(i+1)*time.Minute)))
		corpus = append(corpus, genaiOn("runner-c", "invoke_chat_model", "",
			"claude-haiku-4-5", false, w0.Add(time.Duration(i+1)*time.Minute)))
	}
	appendEvents(t, root, corpus)
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	burst := got["corr.agent-tool-burst"]
	if len(burst) != 1 || !strings.Contains(burst[0].Entity.String(), "agent-7") {
		t.Fatalf("the burst: %+v", burst)
	}
	if !strings.Contains(burst[0].Evidence[0].What, "120 within") {
		t.Errorf("the evidence does not say what was counted: %s",
			burst[0].Evidence[0].What)
	}
	if len(got["otel.tool-call"]) != 0 {
		t.Errorf("the base rule raised %d finding(s) of its own",
			len(got["otel.tool-call"]))
	}
}

// Ten failed model calls in ten minutes from one agent is a streak; nine
// is friction, and failures from a tool call or a working model call do
// not enter the count at all.
func TestAgentFailedModelCallsAreAStreak(t *testing.T) {
	root, rules := packSite(t)
	// A ten-minute window the watermark has passed: the streak rule's own
	// timespan, aligned the way the engine's fixed windows are.
	w := time.Now().UTC().Add(-3 * time.Hour).Truncate(10 * time.Minute)
	var corpus []labelled
	for i := 0; i < 10; i++ {
		corpus = append(corpus, genaiOn("agent-7", "invoke_model", "",
			"claude-sonnet-4-5", true,
			w.Add(time.Duration(i+1)*45*time.Second)))
	}
	// Nine, by another agent: below the streak.
	for i := 0; i < 9; i++ {
		corpus = append(corpus, genaiOn("agent-9", "invoke_chat_model", "",
			"gpt-5.2-codex", true,
			w.Add(time.Duration(i+1)*45*time.Second)))
	}
	// Working model calls, and a failing tool call: none of these count.
	for i := 0; i < 10; i++ {
		corpus = append(corpus, genaiOn("agent-7", "invoke_model", "",
			"claude-sonnet-4-5", false,
			w.Add(time.Duration(i+1)*45*time.Second)))
	}
	corpus = append(corpus, genaiOn("agent-8", "execute_tool", "web.fetch",
		"claude-sonnet-4-5", true, w.Add(30*time.Second)))
	appendEvents(t, root, corpus)
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	streak := got["corr.agent-model-failure-streak"]
	if len(streak) != 1 || !strings.Contains(streak[0].Entity.String(), "agent-7") {
		t.Fatalf("the streak: %+v", streak)
	}
	for _, quiet := range []string{"otel.model-call-failed", "otel.tool-call"} {
		if len(got[quiet]) != 0 {
			t.Errorf("%s raised %d finding(s) of its own", quiet, len(got[quiet]))
		}
	}
}
