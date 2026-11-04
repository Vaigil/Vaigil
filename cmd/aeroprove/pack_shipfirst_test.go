// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aeroprove/aeroprove/internal/telemetry"
)

// The ship-first rules, replayed: each new detection in the pack is fired
// on a hand-built corpus shaped like the events its source really stores —
// the mapped field names, the leaf names internal/source keeps — and on
// the look-alikes that are how each rule goes wrong in production. A rule
// whose fixture passes but whose event shape is wrong is a rule that runs
// nightly and matches nothing, which is the failure the fixtures exist to
// prevent and the replay exists to catch.

// cloudTrailOn is one CloudTrail management event as the connector stores
// it: the operation in the message, its own name and service kept in raw,
// and the caller's user agent as the observable it is carried as.
func cloudTrailOn(actor, event, service, ua string, at time.Time) labelled {
	e := telemetry.Event{Source: "aws/cloudtrail",
		Class:       telemetry.ClassAPIActivity,
		Disposition: telemetry.DispositionAllowed,
		Actor:       telemetry.ID{Issuer: "aws", Value: actor},
		Message:     event, Time: at, Received: at.Add(time.Second),
		Raw: map[string]string{"eventName": event, "eventSource": service,
			"awsRegion": "us-east-1", "readOnly": "false"}}
	if ua != "" {
		e.Observables = []telemetry.Observable{{
			Kind: telemetry.ObservableUserAgent, Value: ua}}
	}
	return labelled{"aws " + event, true, e}
}

// githubOn is one audit-log action as the connector stores it.
func githubOn(actor, action, repo, person string, at time.Time) labelled {
	return labelled{"github " + action, true, telemetry.Event{
		Source: "github/audit", Class: telemetry.ClassAPIActivity,
		Disposition: telemetry.DispositionAllowed,
		Actor:       telemetry.ID{Issuer: "github", Value: actor},
		Message:     action, Time: at, Received: at.Add(time.Second),
		Raw: map[string]string{"action": action, "repo": repo,
			"org": "acme", "person": person}}}
}

// k8sOn is one API-server request as the connector stores it: the verb in
// the message, the object and the response code kept in raw, and the
// disposition the code decided.
func k8sOn(user, verb, resource, code string,
	failed bool, at time.Time) labelled {
	d := telemetry.DispositionAllowed
	if failed {
		d = telemetry.DispositionFailed
	}
	return labelled{"k8s " + verb + " " + resource, true, telemetry.Event{
		Source: "kubernetes/audit", Class: telemetry.ClassAPIActivity,
		Disposition: d,
		Actor:       telemetry.ID{Issuer: "kubernetes", Value: user},
		Message:     verb, Time: at, Received: at.Add(time.Second),
		Raw: map[string]string{"verb": verb, "resource": resource,
			"namespace": "default", "code": code}}}
}

// snowflakeOn is one login-history row as the connector stores it, with
// the two factor fields it keeps and nothing carried for a factor the
// record did not name.
func snowflakeOn(user, first, second string, success bool,
	at time.Time) labelled {
	d := telemetry.DispositionAllowed
	result := "YES"
	if !success {
		d, result = telemetry.DispositionFailed, "NO"
	}
	raw := map[string]string{"IS_SUCCESS": result,
		"FIRST_AUTHENTICATION_FACTOR": first,
		"REPORTED_CLIENT_TYPE":        "JDBC"}
	if second != "" {
		raw["SECOND_AUTHENTICATION_FACTOR"] = second
	}
	return labelled{"snowflake " + user, true, telemetry.Event{
		Source: "snowflake/logins", Class: telemetry.ClassAuthentication,
		Disposition: d,
		Actor:       telemetry.ID{Issuer: "snowflake", Value: user},
		Message:     "LOGIN", Time: at, Received: at.Add(time.Second),
		Raw: raw}}
}

// duoOn is one authentication attempt as the connector stores it.
func duoOn(user, result string, at time.Time) labelled {
	d := telemetry.DispositionFailed
	if result == "success" {
		d = telemetry.DispositionAllowed
	}
	reason := "user rejected the request"
	if result == "success" {
		reason = "user approved"
	}
	return labelled{"duo " + user + " " + result, true, telemetry.Event{
		Source: "duo/auth", Class: telemetry.ClassAuthentication,
		Disposition: d,
		Actor:       telemetry.ID{Issuer: "duo", Value: user},
		Message:     reason, Time: at, Received: at.Add(time.Second),
		Raw: map[string]string{"result": result, "reason": reason,
			"factor": "Duo Push", "name": "Acme SSO", "country": "US"}}}
}

// oktaOn is one system-log record as the connector stores it.
func oktaOn(who, person, eventType string, failed bool,
	at time.Time) labelled {
	d := telemetry.DispositionAllowed
	if failed {
		d = telemetry.DispositionFailed
	}
	return labelled{"okta " + eventType, true, telemetry.Event{
		Source: "okta/system", Class: telemetry.ClassAuthentication,
		Disposition: d,
		Actor:       telemetry.ID{Issuer: "okta", Value: who},
		Message:     eventType, Time: at, Received: at.Add(time.Second),
		Raw: map[string]string{"eventType": eventType, "person": person,
			"country": "US"}}}
}

// agentOn is one of AeroProve's own records of what a model did, as
// storeAgentEvents stores it: the action in the message and in raw, the
// outcome as the disposition, the agent as the actor.
func agentOn(principal, action string, d telemetry.Disposition,
	at time.Time) labelled {
	outcome := "success"
	switch d {
	case telemetry.DispositionBlocked:
		outcome = "denied"
	case telemetry.DispositionFailed:
		outcome = "failure"
	}
	raw := map[string]string{"action": action, "outcome": outcome,
		"resource": "/mcp", "model": principal}
	if action == "mcp.call" {
		raw["tool"], raw["client"] = "write_file", "claude-code"
	} else {
		raw["finding"], raw["agent"], raw["to"] = "f_104", "triage", "benign"
	}
	return labelled{"agent " + action, true, telemetry.Event{
		Source: AgentSource, Class: telemetry.ClassAPIActivity,
		Disposition: d,
		Actor:       telemetry.ID{Issuer: "aeroprove", Value: principal},
		Message:     action, Time: at, Received: at.Add(time.Second),
		Raw: raw}}
}

// The cloud control-plane rules fire on the operations themselves: a
// backup deleted, a key's deletion scheduled, the public-access block
// written — and not on the reads and creations beside them.
func TestTheShipFirstCloudRulesFireOnTheirOperations(t *testing.T) {
	root, rules := packSite(t)
	w0 := closedWindow()
	at := func(m int) time.Time { return w0.Add(time.Duration(m) * time.Minute) }
	person := "arn:aws:iam::1:user/deploy"
	appendEvents(t, root, []labelled{
		cloudTrailOn(person, "DeleteRecoveryPoint", "backup.amazonaws.com",
			"signin.amazonaws.com/console", at(1)),
		cloudTrailOn(person, "ScheduleKeyDeletion", "kms.amazonaws.com",
			"signin.amazonaws.com/console", at(2)),
		cloudTrailOn(person, "PutAccountPublicAccessBlock", "s3.amazonaws.com",
			"signin.amazonaws.com/console", at(3)),
		cloudTrailOn(person, "PutBucketPolicy", "s3.amazonaws.com",
			"signin.amazonaws.com/console", at(4)),
		// The look-alikes: a read, a creation, a softer key action.
		cloudTrailOn(person, "DescribeSnapshots", "ec2.amazonaws.com",
			"signin.amazonaws.com/console", at(5)),
		cloudTrailOn(person, "CreateBackupPlan", "backup.amazonaws.com",
			"signin.amazonaws.com/console", at(6)),
		cloudTrailOn(person, "DisableKey", "kms.amazonaws.com",
			"signin.amazonaws.com/console", at(7)),
		cloudTrailOn(person, "GetBucketPolicy", "s3.amazonaws.com",
			"signin.amazonaws.com/console", at(8)),
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	for _, id := range []string{"aws.backup-deleted",
		"aws.key-deletion-scheduled", "aws.public-access-lowered"} {
		if len(got[id]) != 1 {
			t.Errorf("%s: %d findings, want exactly one operation", id,
				len(got[id]))
		}
	}
	// The public-access rule saw two operations and one actor: one finding,
	// seen twice.
	if len(got["aws.public-access-lowered"]) == 1 &&
		got["aws.public-access-lowered"][0].Seen != 2 {
		t.Errorf("the public-access finding was seen %d times, want 2",
			got["aws.public-access-lowered"][0].Seen)
	}
}

// A user created and keyed by one hand inside fifteen minutes is the
// persistence hand-off; the same pair by the infrastructure pipeline is
// Tuesday, and a key alone is a rotation.
func TestAnIAMUserAndItsKeyWithinMinutesIsOneHandOff(t *testing.T) {
	root, rules := packSite(t)
	w0 := closedWindow()
	at := func(m int) time.Time { return w0.Add(time.Duration(m) * time.Minute) }
	hand := "arn:aws:iam::1:user/deploy"
	pipeline := "arn:aws:sts::1:assumed-role/deploy/terraform"
	appendEvents(t, root, []labelled{
		cloudTrailOn(hand, "CreateUser", "iam.amazonaws.com",
			"signin.amazonaws.com/console", at(1)),
		cloudTrailOn(hand, "CreateAccessKey", "iam.amazonaws.com",
			"signin.amazonaws.com/console", at(4)),
		// The pipeline's own pair, which must stay quiet.
		cloudTrailOn(pipeline, "CreateUser", "iam.amazonaws.com",
			"Terraform/1.9.5", at(2)),
		cloudTrailOn(pipeline, "CreateAccessKey", "iam.amazonaws.com",
			"Terraform/1.9.5", at(3)),
		// A key for a user nobody had just made.
		cloudTrailOn("arn:aws:iam::1:user/sam", "CreateAccessKey",
			"iam.amazonaws.com", "signin.amazonaws.com/console", at(5)),
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	joined := got["corr.iam-user-then-key"]
	if len(joined) != 1 || !strings.Contains(joined[0].Entity.String(), "deploy") {
		t.Fatalf("the hand-off: %+v", joined)
	}
	// A key alone did not make a second finding.
	if len(joined) != 1 || strings.Contains(joined[0].Entity.String(), "sam") {
		t.Errorf("a key alone raised the correlation: %+v", joined)
	}
	for _, quiet := range []string{"aws.iam-user-created",
		"aws.access-key-created"} {
		if len(got[quiet]) != 0 {
			t.Errorf("%s raised %d findings of its own", quiet, len(got[quiet]))
		}
	}
}

// The GitHub rules: a push-protection bypass, a runner joining the fleet
// and a repository's visibility changed each fire once, and the actions
// beside them do not.
func TestTheShipFirstGitHubRulesFireOnTheirActions(t *testing.T) {
	root, rules := packSite(t)
	w0 := closedWindow()
	at := func(m int) time.Time { return w0.Add(time.Duration(m) * time.Minute) }
	person := "dana@acme.com"
	appendEvents(t, root, []labelled{
		githubOn("dana-gh", "secret_scanning_push_protection_bypassed",
			"acme/shop", person, at(1)),
		githubOn("dana-gh", "repo.visibility_change", "acme/shop", person, at(2)),
		githubOn("dana-gh", "self_hosted_runner_group_runner_registered",
			"acme/shop", person, at(3)),
		// The look-alikes: an alert resolved, a push, a runner removed.
		githubOn("dana-gh", "secret_scanning_alert.resolve", "acme/shop",
			person, at(4)),
		githubOn("dana-gh", "git.push", "acme/shop", person, at(5)),
		githubOn("dana-gh", "self_hosted_runner_group_runner_deleted",
			"acme/shop", person, at(6)),
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	for _, id := range []string{"github.push-protection-bypassed",
		"github.repo-visibility-changed", "github.runner-registered"} {
		if len(got[id]) != 1 {
			t.Errorf("%s: %d findings, want the one action", id, len(got[id]))
		}
	}
}

// An anonymous request the API server answered is a finding; the same
// request refused is the internet knocking, and an authenticated write is
// a deploy.
func TestAnAnonymousRequestThatSucceededIsAFinding(t *testing.T) {
	root, rules := packSite(t)
	w0 := closedWindow()
	at := func(m int) time.Time { return w0.Add(time.Duration(m) * time.Minute) }
	appendEvents(t, root, []labelled{
		k8sOn("system:anonymous", "create", "pods", "201", false, at(1)),
		k8sOn("system:anonymous", "list", "secrets", "403", true, at(2)),
		k8sOn("dana@acme.com", "create", "pods", "201", false, at(3)),
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))["k8s.anonymous-succeeded"]
	if len(got) != 1 || got[0].Entity.Value != "system:anonymous" {
		t.Fatalf("anonymous success: %+v", got)
	}
	if len(got) == 1 && got[0].Seen != 1 {
		t.Errorf("seen %d times; the refused probe must not count", got[0].Seen)
	}
}

// The Snowflake rule wants the one-factor success only: a second factor or
// a failure beside it stays quiet.
func TestAPasswordOnlySnowflakeLoginIsAFindingAndItsNeighboursAreNot(t *testing.T) {
	root, rules := packSite(t)
	w0 := closedWindow()
	at := func(m int) time.Time { return w0.Add(time.Duration(m) * time.Minute) }
	appendEvents(t, root, []labelled{
		snowflakeOn("DANA", "PASSWORD", "", true, at(1)),
		snowflakeOn("DANA", "PASSWORD", "OKTA", true, at(2)),
		snowflakeOn("DANA", "PASSWORD", "", false, at(3)),
		snowflakeOn("SVC_ETL", "OKTA", "NONE", true, at(4)),
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))["snowflake.password-only-login"]
	if len(got) != 1 || got[0].Entity.Value != "DANA" {
		t.Fatalf("password-only: %+v", got)
	}
	if len(got) == 1 && got[0].Seen != 1 {
		t.Errorf("seen %d times; only the one-factor success counts", got[0].Seen)
	}
}

// Denials then an approval is fatigue; an approval then denials is a
// person closing a leftover prompt, and denials alone are a boundary
// working.
func TestDenyThenAllowIsFatigueAndTheReverseIsNot(t *testing.T) {
	root, rules := packSite(t)
	w0 := closedWindow()
	at := func(m int) time.Time { return w0.Add(time.Duration(m) * time.Minute) }
	var corpus []labelled
	for i := 0; i < 4; i++ {
		corpus = append(corpus, duoOn("DU1", "failure", at(i+1)))
	}
	corpus = append(corpus, duoOn("DU1", "success", at(5)))
	// The reverse order, same length, for Sam.
	corpus = append(corpus, duoOn("DU2", "success", at(1)))
	for i := 0; i < 4; i++ {
		corpus = append(corpus, duoOn("DU2", "failure", at(i+2)))
	}
	// Denials only, for Li.
	for i := 0; i < 5; i++ {
		corpus = append(corpus, duoOn("DU3", "failure", at(i+1)))
	}
	appendEvents(t, root, corpus)
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	fatigue := got["corr.mfa-fatigue"]
	if len(fatigue) != 1 || !strings.Contains(fatigue[0].Entity.String(), "DU1") {
		t.Fatalf("fatigue: %+v", fatigue)
	}
	for _, quiet := range []string{"duo.push-denied", "duo.push-allowed"} {
		if len(got[quiet]) != 0 {
			t.Errorf("%s raised %d findings of its own", quiet, len(got[quiet]))
		}
	}
}

// A factor reset and then the sign-in, for one person, within the day; the
// order is the detection, and two different people are not a chain.
func TestAFactorResetThenASignInIsTheChain(t *testing.T) {
	root, rules := packSite(t)
	w0 := closedWindow().Add(-30 * time.Hour).Truncate(24 * time.Hour)
	at := func(h int) time.Time { return w0.Add(time.Duration(h) * time.Hour) }
	appendEvents(t, root, []labelled{
		oktaOn("00u1", "dana@acme.com", "user.mfa.factor.reset_all", false, at(1)),
		oktaOn("00u1", "dana@acme.com", "user.session.start", false, at(3)),
		// Sam's factor is reset; Li signs in. Two people, not a chain.
		oktaOn("00u2", "sam@acme.com", "user.mfa.factor.reset_all", false, at(1)),
		oktaOn("00u3", "li@acme.com", "user.session.start", false, at(2)),
		// Omar signs in first and is reset afterwards: the reverse order.
		oktaOn("00u4", "omar@acme.com", "user.session.start", false, at(1)),
		oktaOn("00u4", "omar@acme.com", "user.mfa.factor.reset_all", false, at(2)),
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	chain := got["corr.reset-then-signin"]
	if len(chain) != 1 || chain[0].Entity.String() != "person:dana@acme.com" {
		t.Fatalf("reset then sign-in: %+v", chain)
	}
	for _, quiet := range []string{"okta.signin-succeeded"} {
		if len(got[quiet]) != 0 {
			t.Errorf("%s raised %d findings of its own", quiet, len(got[quiet]))
		}
	}
}

// The agent rules are rates over quiet bases: ten refusals in fifteen
// minutes from one actor, thirty proposals in an hour — and the actors
// below the thresholds, and the calls that went through, count for
// nothing.
func TestAgentRefusalsAndProposalsAreRatesNotEvents(t *testing.T) {
	root, rules := packSite(t)
	w0 := closedWindow()
	at := func(m int) time.Time { return w0.Add(time.Duration(m) * time.Minute) }
	var corpus []labelled
	for i := 0; i < 10; i++ {
		corpus = append(corpus, agentOn("mcp-client", "mcp.call",
			telemetry.DispositionBlocked, at(i+1)))
	}
	// Nine refusals by another actor: below the count.
	for i := 0; i < 9; i++ {
		corpus = append(corpus, agentOn("runner-agent", "mcp.call",
			telemetry.DispositionBlocked, at(i+1)))
	}
	// Calls that worked are not refusals.
	for i := 0; i < 3; i++ {
		corpus = append(corpus, agentOn("mcp-client", "mcp.call",
			telemetry.DispositionAllowed, at(i+6)))
	}
	hour := closedWindow().Truncate(time.Hour)
	for i := 0; i < 30; i++ {
		corpus = append(corpus, agentOn("analyst:triage", "proposal.finding",
			telemetry.DispositionAllowed,
			hour.Add(time.Duration(i+1)*time.Minute)))
	}
	// Ten by another analyst: below the rate.
	for i := 0; i < 10; i++ {
		corpus = append(corpus, agentOn("analyst:night", "proposal.finding",
			telemetry.DispositionAllowed,
			hour.Add(time.Duration(i+1)*time.Minute)))
	}
	appendEvents(t, root, corpus)
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	refusals := got["corr.agent-refusal-burst"]
	if len(refusals) != 1 || !strings.Contains(refusals[0].Entity.String(),
		"mcp-client") {
		t.Fatalf("refusal burst: %+v", refusals)
	}
	proposals := got["corr.agent-proposal-burst"]
	if len(proposals) != 1 || !strings.Contains(proposals[0].Entity.String(),
		"analyst:triage") {
		t.Fatalf("proposal burst: %+v", proposals)
	}
	for _, quiet := range []string{"aeroprove.agent-call-denied",
		"aeroprove.agent-proposed"} {
		if len(got[quiet]) != 0 {
			t.Errorf("%s raised %d findings of its own", quiet, len(got[quiet]))
		}
	}
}

// auditctl on a host is the audit daemon's control tool being run; the
// logrotate and journalctl events a host produces all day are not.
func TestAuditctlRunIsAFindingAndLogRotationIsNot(t *testing.T) {
	root, rules := packSite(t)
	w0 := closedWindow()
	at := func(m int) time.Time { return w0.Add(time.Duration(m) * time.Minute) }
	host := func(exe, comm string, at time.Time) labelled {
		return labelled{"auditd " + comm, true, telemetry.Event{
			Source: "auditd/events", Class: telemetry.ClassProcessActivity,
			Disposition: telemetry.DispositionAllowed,
			Actor:       telemetry.ID{Issuer: "auditd", Value: "1001"},
			Device:      telemetry.ID{Issuer: "auditd", Value: "web-1"},
			Message:     "SYSCALL", Time: at, Received: at.Add(time.Second),
			Raw: map[string]string{"type": "SYSCALL", "exe": exe,
				"comm": comm, "auid": "1001", "uid": "0",
				"res": "success"}}}
	}
	appendEvents(t, root, []labelled{
		host("/usr/sbin/auditctl", "auditctl", at(1)),
		host("/usr/sbin/logrotate", "logrotate", at(2)),
		host("/usr/bin/journalctl", "journalctl", at(3)),
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))["auditd.auditctl-run"]
	if len(got) != 1 {
		t.Fatalf("auditctl: %+v", got)
	}
	if len(got) == 1 && got[0].Seen != 1 {
		t.Errorf("seen %d times; logrotate and journalctl must not count",
			got[0].Seen)
	}
}

// watchChangeOn is one watched-file change as the collector's ingest
// stores it on a host an operator has mapped: the declared closed list in
// raw.agents, and — only when the host maps to exactly one agent — the
// join name in raw.agent (cmd/aeroprove's ingest path, declaredAgents). An
// unmapped host is declared=nil and carries neither.
func watchChangeOn(host, kind, op string, declared []string,
	at time.Time) labelled {
	raw := map[string]string{"path": "/home/dana/.mcp.json", "kind": kind,
		"op": op, "sha256": "b42d4f9e", "size": "612", "host": host}
	if len(declared) > 0 {
		raw["agents"] = strings.Join(declared, ",")
		if len(declared) == 1 {
			raw["agent"] = declared[0]
		}
	}
	return labelled{"watch " + host, true, telemetry.Event{
		Source: "collector/watch", Class: telemetry.ClassFileActivity,
		Time: at, Received: at.Add(time.Second),
		Device:  telemetry.ID{Issuer: "collector", Value: host},
		Message: fmt.Sprintf("/home/dana/.mcp.json %s (%s)", op, kind),
		Raw:     raw}}
}

// genaiToolCall is one tool-call span as the OTLP boundary stores it: the
// span's own actor claim, carried into the join field the declaration
// writes (otelCarriesTheJoinName). The actor is the SDK's string, whatever
// it is — the point of the corridor is that nothing reconciles it with the
// registry by force.
func genaiToolCall(agent string, at time.Time) labelled {
	return labelled{"genai " + agent, true, telemetry.Event{
		Source: "otel/genai", Class: telemetry.ClassAPIActivity,
		Disposition: telemetry.DispositionAllowed,
		Actor:       telemetry.ID{Issuer: "otel", Value: agent},
		Message:     "execute_tool", Time: at, Received: at.Add(time.Second),
		Raw: map[string]string{"operation": "execute_tool",
			"tool": "filesystem.write", "status": "ok", "agent": agent}}}
}

// TestAConfigChangeThenItsAgentsCallsIsTheChain: the corridor the pack's
// own end-comment refused until the join became a declaration — a config
// change on a host mapped to one agent, then that agent's tool calls. The
// whole firing matrix in one corpus: the join that fires, and every
// honest non-join beside it — the unmapped host, the shared box, another
// agent's calls, the reverse order, and the SDK that names its agent
// differently from the registry.
func TestAConfigChangeThenItsAgentsCallsIsTheChain(t *testing.T) {
	root, rules := packSite(t)
	w0 := closedWindow()
	at := func(m int) time.Time { return w0.Add(time.Duration(m) * time.Minute) }
	appendEvents(t, root, []labelled{
		// The chain: build01 is mapped to watcher alone; its config
		// changed, and watcher called tools afterwards.
		watchChangeOn("build01", "mcp-config", "changed", []string{"watcher"}, at(10)),
		genaiToolCall("watcher", at(20)),
		// An unmapped host: the same change carries no declaration and
		// joins nothing, however nearby its calls are.
		watchChangeOn("ci02", "mcp-config", "changed", nil, at(11)),
		genaiToolCall("runner-2", at(21)),
		// A shared box: two agents declared, no single name, and the
		// change is not attributed between them — the join refuses to
		// choose, so neither agent's calls chain onto it.
		watchChangeOn("shared07", "mcp-config", "changed",
			[]string{"docs-bot", "watcher"}, at(12)),
		genaiToolCall("docs-bot", at(22)),
		// The reverse order: triage called tools and its config was
		// changed afterwards, which is an agent being reconfigured, not
		// the chain.
		genaiToolCall("triage", at(25)),
		watchChangeOn("desk09", "agent-config", "created", []string{"triage"}, at(30)),
		// An SDK that names its agent differently from the registry:
		// agent-7 is not the declared name, and nothing is forced to match.
		watchChangeOn("desk10", "mcp-config", "changed", []string{"watcher"}, at(13)),
		genaiToolCall("agent-7", at(23)),
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	got := bySource(queue(t, root))
	chain := got["corr.watch-then-call"]
	if len(chain) != 1 || !strings.Contains(chain[0].Entity.String(), "watcher") {
		t.Fatalf("the chain: %+v — want exactly watcher's, and only it", chain)
	}
	if len(chain) == 1 && !strings.Contains(chain[0].Entity.String(), "raw.agent") {
		t.Errorf("the finding is about %+v; the join field should say whose "+
			"chain it is", chain[0].Entity)
	}
	// The severity-3 rule still raises the changes themselves — the watch
	// stream carries no actor, so it is one finding seen once per change —
	// and the corridor adds the chain without swallowing the finding it
	// joins on.
	changes := got["collector.agent-config-changed"]
	if len(changes) != 1 || changes[0].Seen != 5 {
		seen := 0
		if len(changes) == 1 {
			seen = changes[0].Seen
		}
		t.Errorf("the config changes raised %d finding(s) seen %d time(s); "+
			"want the one actor-less finding, still there beside the chain "+
			"and seen for each of the five changes", len(changes), seen)
	}
	for _, quiet := range []string{"collector.agent-config-changed-mapped",
		"otel.tool-call"} {
		if len(got[quiet]) != 0 {
			t.Errorf("%s raised %d findings of its own", quiet, len(got[quiet]))
		}
	}
}
