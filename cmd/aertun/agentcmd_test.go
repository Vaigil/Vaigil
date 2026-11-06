// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/agentreg"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/mcp"
	"github.com/aertun/aertun/internal/out"
)

// The agent registry, end to end: a token becomes an agent, the registry
// decides whether that agent is anybody, and the kill switch reaches the
// credential and not just the register.
//
// The matrix the design asks to hold (docs/research/02-access-control.md
// §8.1, §8.3, §8.5), each row through the real operation path — buildMCP's
// hook and the handlers, the same lines a stdio or HTTP caller reaches:
//
//	allowed + allowlisted                 succeeds
//	allowlisted but disabled              refused, naming the disable
//	active but not allowlisted the tool   refused, naming the tool
//	agent:-prefixed, no registry row      refused: an unregistered agent is nobody
//	a plain human token                   exactly as before any of this existed

// agentSite is an initialised store with the policy granting a principal
// the rung an operation needs, so the rows below vary the registry and only
// the registry.
func registrySite(t *testing.T, principal string, role auth.Role) string {
	t.Helper()
	if w == nil {
		w = out.New(false)
	}
	root, _ := siemSite(t, nil)
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		return p.Grant(auth.Binding{Principal: principal, Role: role,
			Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	return root
}

// agentToken issues a token bound to an agent by the naming convention and
// resolves it the way every surface resolves a presented token, so what is
// under test is the whole binding: the name, the carry, the caller.
func agentToken(t *testing.T, root, agent, principal string, role auth.Role) (*Caller, string) {
	t.Helper()
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := ts.IssueScoped(agentreg.TokenPrefix+agent, principal,
		role, "/", 24*time.Hour, auth.RoleAdmin, auth.Scope{})
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	c := resolveCaller(root, secret)
	if !c.Verified {
		t.Fatalf("the agent's token did not resolve: %s", c.Why)
	}
	return c, secret
}

// register adds an agent through the command, so the register, the audit
// record and the gate all see the same entry.
func register(t *testing.T, root, name string, tools ...string) {
	t.Helper()
	if err := cmdAgent(root, []string{"add", name, "--owner", "dana@acme.example",
		"--allow", strings.Join(tools, ",")}); err != nil {
		t.Fatal(err)
	}
}

// registerAgent is a full agent — entry, credential, caller — for the
// matrix rows that then vary one thing about it.
func registerAgent(t *testing.T, root, name string, role auth.Role, tools ...string) (*Caller, string) {
	t.Helper()
	register(t, root, name, tools...)
	return agentToken(t, root, name, name, role)
}

func refused(t *testing.T, srv *mcp.Server, tool, op string, args map[string]any) string {
	t.Helper()
	_, err := callTool(t, srv, tool, op, args)
	if err == nil {
		t.Fatalf("%s was served; the row expected a refusal", op)
	}
	if err.Code != mcp.CodeRefused {
		t.Fatalf("%s failed (%d) rather than being refused, so an agent "+
			"would retry it: %s", op, err.Code, err.Message)
	}
	return err.Message
}

// TestAgentRegistryBindsATokenToAnAgent.
//
// The binding is the token's own name, and what it changes is the caller's
// kind: an agent's acts are recorded as an AI principal's, under the
// agent's own name, while a person's token and a plain service token are
// exactly what they were.
func TestAgentRegistryBindsATokenToAnAgent(t *testing.T) {
	root := registrySite(t, "watcher", auth.RoleViewer)
	c, _ := registerAgent(t, root, "watcher", auth.RoleViewer, "aertun_read")
	if c.Agent != "watcher" {
		t.Fatalf("the caller does not carry the agent: %+v", c)
	}
	if c.Kind != audit.KindAI || c.Model != "watcher" {
		t.Errorf("an agent is recorded as %s/%s, not an AI under its own name",
			c.Kind, c.Model)
	}
	// A person's token, in the same store, is untouched by the convention.
	ts, _ := loadTokens(root)
	secret, _, err := ts.IssueScoped("cli", "dana@acme.example", auth.RoleViewer,
		"/", time.Hour, auth.RoleAdmin, auth.Scope{})
	if err != nil {
		t.Fatal(err)
	}
	human := resolveCaller(root, secret)
	if human.Agent != "" || human.Kind != audit.KindHuman || human.Model != "" {
		t.Errorf("a person's token became %+v", human)
	}
}

// TestAgentAllowedAndAllowlistedReadsTheQueue: the row that must succeed,
// through the hook and the handler both, with the registry present and the
// tool allowed.
func TestAgentAllowedAndAllowlistedReadsTheQueue(t *testing.T) {
	root := registrySite(t, "watcher", auth.RoleViewer)
	c, _ := registerAgent(t, root, "watcher", auth.RoleViewer, "aertun_read")
	srv := buildMCP(root, c)
	text, err := callTool(t, srv, "aertun_read", "list_findings", nil)
	if err != nil {
		t.Fatalf("an allowed agent was refused: %s", err.Message)
	}
	if !strings.Contains(text, "total") {
		t.Fatalf("the queue did not answer: %s", text)
	}
}

// TestAgentUnregisteredIsNobody: a token with the agent: prefix and no
// registry row behind it. Fail closed — the refusal names the registry, and
// a person's token in the same store keeps working, so the gate is the
// agent's and not the store's.
func TestAgentUnregisteredIsNobody(t *testing.T) {
	root := registrySite(t, "watcher", auth.RoleViewer)
	c, _ := agentToken(t, root, "ghost", "watcher", auth.RoleViewer)
	srv := buildMCP(root, c)
	msg := refused(t, srv, "aertun_read", "list_findings", nil)
	for _, want := range []string{"no agent", `"ghost"`, "registered"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say the registry refused it (%q missing): %s",
				want, msg)
		}
	}
	// The same store, a person's token: today's behaviour, unchanged.
	ts, _ := loadTokens(root)
	secret, _, err := ts.IssueScoped("cli", "watcher", auth.RoleViewer, "/",
		time.Hour, auth.RoleAdmin, auth.Scope{})
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	human := resolveCaller(root, secret)
	if _, err := callTool(t, buildMCP(root, human), "aertun_read",
		"list_findings", nil); err != nil {
		t.Errorf("a person was refused by the agent's gate: %s", err.Message)
	}
}

// TestAgentDisabledIsRefusedNamingTheDisable.
//
// The kill switch's registry half: a fresh token minted while the entry is
// disabled authenticates as a token — auth is not what is broken — and is
// then refused by the gate that names the disable and the reason recorded
// with it.
func TestAgentDisabledIsRefusedNamingTheDisable(t *testing.T) {
	root := registrySite(t, "watcher", auth.RoleViewer)
	register(t, root, "watcher", "aertun_read")
	if err := cmdAgent(root, []string{"disable", "watcher", "--why",
		"proposing nonsense on closed findings"}); err != nil {
		t.Fatal(err)
	}
	// A person's token still works: the register names an agent, not a store.
	ts, _ := loadTokens(root)
	secret, _, err := ts.IssueScoped("cli", "watcher", auth.RoleViewer, "/",
		time.Hour, auth.RoleAdmin, auth.Scope{})
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	if _, err := callTool(t, buildMCP(root, resolveCaller(root, secret)),
		"aertun_read", "list_findings", nil); err != nil {
		t.Errorf("a person was caught by an agent's disable: %s", err.Message)
	}
	c, _ := agentToken(t, root, "watcher", "watcher", auth.RoleViewer)
	msg := refused(t, buildMCP(root, c), "aertun_read", "list_findings", nil)
	for _, want := range []string{"disabled", "proposing nonsense on closed findings"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not name the disable (%q missing): %s", want, msg)
		}
	}
}

// TestAgentDisableRevokesItsTokensAtTheNextRequest.
//
// The kill switch's other half, and the reason it is one act: the bearer of
// the agent's token is refused by the token store itself — auth, not the
// registry — so a credential that outlived its agent's disablement never
// reaches a gate to be refused by.
func TestAgentDisableRevokesItsTokensAtTheNextRequest(t *testing.T) {
	root := registrySite(t, "watcher", auth.RoleViewer)
	_, secret := registerAgent(t, root, "watcher", auth.RoleViewer, "aertun_read")
	if err := cmdAgent(root, []string{"disable", "watcher", "--why", "gone quiet"}); err != nil {
		t.Fatal(err)
	}
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.Authenticate(secret, time.Now()); err == nil {
		t.Fatal("the disabled agent's token still authenticates; the kill " +
			"switch stopped at the register")
	}
	if c := resolveCaller(root, secret); c.Verified {
		t.Fatalf("the bearer resolved as %+v; it should be told the token is dead", c)
	}
	// The audit record says both halves happened.
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "agent.disable" && e.Detail["agent"] == "watcher" &&
			e.Detail["revoked"] == "1" && e.Detail["why"] == "gone quiet" {
			found = true
		}
	}
	if !found {
		t.Error("the disable was not recorded with the tokens it revoked and the reason")
	}
}

// TestAgentEnableRestoresAccessForAFreshToken.
//
// Enable restores the registry row and nothing else: the revoked token
// stays dead — which is the point of revoking it — and a fresh one works,
// which is the owner's separate act and the one line of recovery.
func TestAgentEnableRestoresAccessForAFreshToken(t *testing.T) {
	root := registrySite(t, "watcher", auth.RoleViewer)
	_, secret := registerAgent(t, root, "watcher", auth.RoleViewer, "aertun_read")
	if err := cmdAgent(root, []string{"disable", "watcher", "--why", "x"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAgent(root, []string{"enable", "watcher", "--why",
		"the vendor fixed the loop"}); err != nil {
		t.Fatal(err)
	}
	ts, _ := loadTokens(root)
	if _, err := ts.Authenticate(secret, time.Now()); err == nil {
		t.Error("enabling the entry resurrected a revoked token; a credential " +
			"that outlived its disablement is one nobody had to think about")
	}
	c, _ := agentToken(t, root, "watcher", "watcher", auth.RoleViewer)
	if _, err := callTool(t, buildMCP(root, c), "aertun_read", "list_findings",
		nil); err != nil {
		t.Fatalf("a fresh token for a re-enabled agent was refused: %s", err.Message)
	}
}

// TestAgentRefusedTheToolsItIsNotAllowed.
//
// The allowlist, both directions, each refusal naming the tool rather than
// a shrug. The agents hold the role their refused tool's operation needs,
// so it is the allowlist that says no and not the ladder — which is the
// whole point: the allowlist is the agent's own ceiling beneath the policy.
func TestAgentRefusedTheToolsItIsNotAllowed(t *testing.T) {
	// An analyst-grade agent allowed only the write tool: it may propose,
	// and it may not read.
	root := registrySite(t, "proposer", auth.RoleAnalyst)
	writer, _ := registerAgent(t, root, "proposer", auth.RoleAnalyst, "aertun_write")
	srv := buildMCP(root, writer)
	m := refused(t, srv, "aertun_read", "list_findings", nil)
	if !strings.Contains(m, "aertun_read") || !strings.Contains(m, "not allowed") {
		t.Errorf("the read refusal does not name the gate and the tool: %s", m)
	}
	// The allowed direction answers (the handler's own refusal for a
	// finding that does not exist, which is not the allowlist's business).
	if _, err := callTool(t, srv, "aertun_write", "propose_finding_decision",
		map[string]any{"id": "no-such", "to": "fixed", "because": "x"}); err == nil ||
		!strings.Contains(err.Message, "no finding has that id") {
		t.Fatalf("the write tool was refused for the agent: %v", err)
	}

	// An analyst-grade agent allowed only the read tool: the ladder says
	// proposing is within an analyst's reach and the allowlist says no.
	root2 := registrySite(t, "reader", auth.RoleAnalyst)
	reader, _ := registerAgent(t, root2, "reader", auth.RoleAnalyst, "aertun_read")
	m2 := refused(t, buildMCP(root2, reader), "aertun_write",
		"propose_finding_decision", map[string]any{"id": "x", "to": "fixed",
			"because": "y"})
	if !strings.Contains(m2, "aertun_write") || !strings.Contains(m2, "not allowed") {
		t.Errorf("the write refusal does not name the gate and the tool: %s", m2)
	}
}

// TestAgentGatesLeaveAPersonUnchanged: the belt-and-braces row. With a
// registry present, agents registered and disabled, a human caller through
// the same buildMCP sees exactly the behaviour the surface had before any
// agent was a principal.
func TestAgentGatesLeaveAPersonUnchanged(t *testing.T) {
	root := registrySite(t, "watcher", auth.RoleViewer)
	register(t, root, "watcher", "aertun_read")
	if err := cmdAgent(root, []string{"disable", "watcher", "--why", "x"}); err != nil {
		t.Fatal(err)
	}
	human := &Caller{Name: "watcher", Kind: audit.KindHuman, Verified: true,
		Role: auth.RoleViewer}
	srv := buildMCP(root, human)
	text, err := callTool(t, srv, "aertun_read", "list_findings", nil)
	if err != nil {
		t.Fatalf("a person was refused beside a disabled agent: %s", err.Message)
	}
	if !strings.Contains(text, "total") {
		t.Fatalf("the queue answer changed shape: %s", text)
	}
}

// -- the command surface -------------------------------------------------

// TestAgentCommandRegistersRefusesAndRecords.
//
// The register is the review object, so what it refuses and what it records
// are the behaviours that matter: bad names and unknown tools never land,
// every mutation is in the audit log under the caller's name, and a
// disable without a reason is not a disable.
func TestAgentCommandRegistersRefusesAndRecords(t *testing.T) {
	root := registrySite(t, "dana@acme.example", auth.RoleAdmin)
	if err := cmdAgent(root, []string{"add", "Watcher", "--owner",
		"dana@acme.example", "--allow", "aertun_read"}); err == nil {
		t.Error("a name that could not be a key was accepted")
	}
	if err := cmdAgent(root, []string{"add", "watcher", "--owner",
		"dana@acme.example", "--allow", "aertun_read,aertun_decide"}); err == nil {
		t.Error("a tool the interface does not serve was allowed at add time")
	}
	if err := cmdAgent(root, []string{"add", "watcher", "--owner", "  ",
		"--allow", "aertun_read"}); err == nil {
		t.Error("an agent with no owner was accepted")
	}
	if err := cmdAgent(root, []string{"add", "watcher", "--allow", "aertun_read"}); err == nil {
		t.Error("a missing --owner was accepted")
	}
	if err := cmdAgent(root, []string{"disable", "watcher", "--why", "x"}); err == nil {
		t.Error("an agent that was never added was disabled")
	}

	register(t, root, "watcher", "aertun_read")
	if err := cmdAgent(root, []string{"add", "watcher", "--owner",
		"dana@acme.example", "--allow", "aertun_read"}); err == nil {
		t.Error("a duplicate registration was accepted")
	}
	if err := cmdAgent(root, []string{"disable", "watcher"}); err == nil {
		t.Error("a disable without --why was accepted")
	}
	if err := cmdAgent(root, []string{"enable", "watcher"}); err == nil {
		t.Error("an enable of an active agent was accepted; nothing was said about why")
	}

	// Allow, both ways, refusing tools that do not exist.
	if err := cmdAgent(root, []string{"allow", "watcher", "--add", "aertun_exec"}); err == nil {
		t.Error("an unknown tool was allowed")
	}
	if err := cmdAgent(root, []string{"allow", "watcher", "--add", "aertun_write"}); err != nil {
		t.Fatal(err)
	}
	if a, _, err := agentStore(root).Get("watcher"); err != nil ||
		!a.MayUse("aertun_write") || !a.MayUse("aertun_read") {
		t.Fatalf("the allowlist after allow --add: %+v (%v)", a, err)
	}
	if err := cmdAgent(root, []string{"allow", "watcher", "--remove",
		"aertun_read,aertun_write"}); err != nil {
		t.Fatal(err)
	}
	if a, _, _ := agentStore(root).Get("watcher"); len(a.Allow) != 0 {
		t.Fatalf("the allowlist after removals: %v", a.Allow)
	}

	// Everything that changed is on the record, with the agent's name.
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"agent.add": false, "agent.allow": false, "agent.disallow": false,
	}
	for _, e := range events {
		if !strings.HasPrefix(e.Action, "agent.") {
			continue
		}
		if e.Detail["agent"] != "watcher" {
			t.Errorf("%s recorded the wrong agent: %v", e.Action, e.Detail)
		}
		if _, ok := want[e.Action]; ok {
			want[e.Action] = true
		}
	}
	for action, seen := range want {
		if !seen {
			t.Errorf("%s was never written to the audit log", action)
		}
	}
}

// TestAgentCommandHelpNamesTheDeliberateOmission: the house style is
// that a bare command teaches, and the one sentence this help must carry is
// the one that refuses the global kill switch — it is the availability
// weapon the design holds behind dual control (§8.5), and a rewrite that
// quietly offered `disable all` would undo that decision in prose.
func TestAgentCommandHelpNamesTheDeliberateOmission(t *testing.T) {
	if w == nil {
		w = out.New(false)
	}
	if err := cmdAgent(t.TempDir(), nil); err != nil {
		t.Fatal(err)
	}
	src := readFile(t, "agentcmd.go")
	for _, want := range []string{
		"no \"disable all agents\"",
		"availability weapon",
		"dual control",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("the help prose no longer says %q — the decision it "+
				"records has been dropped rather than changed", want)
		}
	}
}

// -- the host mapping -----------------------------------------------------

// mapHost declares through the command, so the mapping file, the audit
// record and the listing all see the same declaration.
func mapHost(t *testing.T, root, agent, host string) {
	t.Helper()
	if err := cmdAgent(root, []string{"maps", agent, "--host", host}); err != nil {
		t.Fatal(err)
	}
}

// TestAgentCommandMapsHostsRefusesAndRecords: the mapping is the
// watch-then-call chain's onboarding act, and what it refuses is the
// honest half — names the registry does not hold, a host no recorder could
// report, a fifth agent on one machine, and a declaration made twice —
// each refused in words, and every change on the record under the
// agent's name with the host beside it.
func TestAgentCommandMapsHostsRefusesAndRecords(t *testing.T) {
	root := registrySite(t, "dana@acme.example", auth.RoleAdmin)
	register(t, root, "watcher", "aertun_read")
	register(t, root, "triage", "aertun_read")
	register(t, root, "docs-bot", "aertun_read")
	register(t, root, "loader", "aertun_read")
	register(t, root, "fifth", "aertun_read")

	if err := cmdAgent(root, []string{"maps", "ghost", "--host", "build01"}); err == nil {
		t.Error("an agent the registry does not hold was mapped")
	}
	if err := cmdAgent(root, []string{"maps", "watcher", "--host",
		"build 01"}); err == nil {
		t.Error("a host with a space in it was mapped")
	}
	if err := cmdAgent(root, []string{"maps", "watcher"}); err == nil {
		t.Error("a mapping with no host was accepted")
	}

	mapHost(t, root, "watcher", "build01")
	if err := cmdAgent(root, []string{"maps", "watcher", "--host",
		"build01"}); err == nil {
		t.Error("the same declaration was accepted twice")
	}
	// A shared box, up to the cap: three more agents on build01.
	for _, agent := range []string{"triage", "docs-bot", "loader"} {
		mapHost(t, root, agent, "build01")
	}
	err := cmdAgent(root, []string{"maps", "fifth", "--host", "build01"})
	if err == nil {
		t.Fatal("a fifth agent was mapped onto one host")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Errorf("the cap refusal does not say it is one: %s", err)
	}
	// The cap is per host, and the mapping is agent-first: the same agent
	// may run elsewhere.
	mapHost(t, root, "fifth", "ci02")
	mapHost(t, root, "watcher", "ci02")

	maps, merr := agentMapStore(root).Load()
	if merr != nil {
		t.Fatal(merr)
	}
	if got := agentreg.AgentsFor(maps, "build01"); len(got) != 4 {
		t.Errorf("build01 declares %v, want the four below the cap", got)
	}
	if hosts := agentreg.Hosts(maps, "watcher"); strings.Join(hosts, ",") !=
		"build01,ci02" {
		t.Errorf("watcher's hosts: %v", hosts)
	}

	// Taking one back, then one that was never there.
	if err := cmdAgent(root, []string{"maps", "triage", "--host",
		"build01", "--remove"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAgent(root, []string{"maps", "triage", "--host",
		"build01", "--remove"}); err == nil {
		t.Error("an unmap of nothing was answered as done")
	}

	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	// Both directions on the record, each naming the agent and the host:
	// watcher declared on build01, triage taken back off it.
	want := map[string]bool{
		"agent.mapped watcher build01":  false,
		"agent.unmapped triage build01": false,
	}
	for _, e := range events {
		switch {
		case e.Action == "agent.mapped" && e.Detail["agent"] == "watcher" &&
			e.Detail["host"] == "build01":
			want["agent.mapped watcher build01"] = true
		case e.Action == "agent.unmapped" && e.Detail["agent"] == "triage" &&
			e.Detail["host"] == "build01":
			want["agent.unmapped triage build01"] = true
		}
	}
	for record, seen := range want {
		if !seen {
			t.Errorf("%s was never written to the audit log", record)
		}
	}
}
