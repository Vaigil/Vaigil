// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/vaigil/vaigil/internal/agentreg"
	"github.com/vaigil/vaigil/internal/audit"
	"github.com/vaigil/vaigil/internal/auth"
	"github.com/vaigil/vaigil/internal/macaroon"
	"github.com/vaigil/vaigil/internal/out"
)

// The run token, end to end (docs/research/02-access-control.md §8.4): a
// caveat-bound credential minted for one run of a registered agent,
// verified as a credential everywhere and as a chain of caveats at the one
// gate that authorises tool calls.
//
// The matrix this file holds, every row through the real operation path —
// buildMCP's hook and the handlers, the same lines a stdio caller reaches:
//
//	minted and carried                 reads, as its caveats permit
//	a tool outside the run's set       refused, naming the tool caveat
//	the deadline passed                refused, naming the exp caveat
//	the call budget spent              refused, naming the calls caveat
//	the purpose narrower than the tool refused, naming the purpose caveat
//	the autonomy bound below the tool  refused, naming the level caveat
//	the bearer half presented bare     refused: the caveats are the credential
//	the payload changed by one byte    refused by the chain
//	the agent disabled                 refused by the token store, not the gate
//	minted wider than the register     refused at the mint, not at the gate

// caveatSite is a store where the agent holds analyst (so both the read
// and the write tools are within its ladder) and dana holds admin (so the
// mint's issuer cap passes). The agent is registered for both tools.
func caveatSite(t *testing.T) string {
	t.Helper()
	if w == nil {
		w = out.New(false)
	}
	root, _ := siemSite(t, nil)
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		if err := p.Grant(auth.Binding{Principal: "watcher",
			Role: auth.RoleAnalyst, Resource: "/"}); err != nil {
			return err
		}
		return p.Grant(auth.Binding{Principal: "dana@acme.example",
			Role: auth.RoleAdmin, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	register(t, root, "watcher", "vaigil_read", "vaigil_write")
	return root
}

// caveatAdmin is a verified administrator, because the mint carries its
// issuer's authority and refuses to run without one.
func caveatAdmin(t *testing.T, root string) *Caller {
	t.Helper()
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := ts.IssueScoped("cli", "dana@acme.example",
		auth.RoleAdmin, "/", 24*time.Hour, auth.RoleAdmin, auth.Scope{})
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	c := resolveCaller(root, secret)
	if !c.Verified {
		t.Fatalf("the administrator did not resolve: %s", c.Why)
	}
	return c
}

// mintRun mints through the same core the command calls, and returns the
// token itself — the one string, which the command prints once and the
// tests need whole.
func mintRun(t *testing.T, root, run string, tools []string, purpose string,
	calls, level int) string {
	t.Helper()
	tok, err := issueRunToken(root, caveatAdmin(t, root), "watcher", run,
		tools, 8, purpose, calls, level)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// runCaller resolves a run token the way every surface resolves a
// presented credential, so what is under test is the whole carry.
func runCaller(t *testing.T, root, token string) *Caller {
	t.Helper()
	c := resolveCaller(root, token)
	if !c.Verified {
		t.Fatalf("the run token did not resolve: %s", c.Why)
	}
	if c.Agent != "watcher" {
		t.Fatalf("the run token resolved as %+v", c)
	}
	return c
}

// TestCaveatRunTokenCarriesAndReads: the row that must succeed. The token
// resolves to the agent with its run carried, the store holds it under the
// run's name with the coarse bounds matching the fine ones, and the read
// the caveats permit is served.
func TestCaveatRunTokenCarriesAndReads(t *testing.T) {
	root := caveatSite(t)
	tok := mintRun(t, root, "r1", []string{"vaigil_read"}, "", 0, -1)
	c := runCaller(t, root, tok)
	if c.Run != "r1" || c.RunToken != tok {
		t.Fatalf("the carry is run %q with token %v", c.Run, c.RunToken != tok)
	}
	// The store's half: a real entry, named for the run, viewer-grade and
	// read-only because the caveats name no write tool. The coarse bounds
	// are what holds on surfaces that never read the caveats, so they are
	// asserted here, where they are minted.
	ts, _ := loadTokens(root)
	found := false
	for _, tk := range ts.Tokens {
		if tk.Name == agentreg.TokenPrefix+"watcher/r1" {
			found = true
			if tk.Role != auth.RoleViewer || !tk.Scope.ReadOnly {
				t.Fatalf("the run entry is %s/%s; a read run is minted "+
					"viewer and read-only", tk.Role, tk.Scope)
			}
		}
	}
	if !found {
		t.Fatal("the run token has no entry in the store it was minted into")
	}
	text, err := callTool(t, buildMCP(root, c), "vaigil_read",
		"list_findings", nil)
	if err != nil {
		t.Fatalf("a run minted to read was refused: %s", err.Message)
	}
	if !strings.Contains(text, "total") {
		t.Fatalf("the queue did not answer: %s", text)
	}
}

// TestCaveatToolSetRefusesWhatItOmits: the run was minted with both tools
// and then attenuated to read only, so the credential can write, the
// register allows the write and the ladder permits it — and the call is
// refused by the tool caveat alone, naming it, and recorded in the audit
// log with the caveat that refused it.
func TestCaveatToolSetRefusesWhatItOmits(t *testing.T) {
	root := caveatSite(t)
	parent := mintRun(t, root, "r2", []string{"vaigil_read", "vaigil_write"},
		macaroon.PurposeTriage, 0, -1)
	narrower, err := macaroon.Attenuate(parent, macaroon.Caveat{
		Kind: macaroon.KindTool, Value: "vaigil_read"})
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, runCaller(t, root, narrower))
	msg := refused(t, srv, "vaigil_write", "propose_finding_decision",
		map[string]any{"id": "x", "to": "fixed", "because": "y"})
	for _, want := range []string{"caveat tool", "vaigil_write",
		"not in this run's tool set"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q: %s", want, msg)
		}
	}
	// The audit record names the caveat — the log has to answer "which
	// bound refused which run", not merely "an agent was told no".
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action != "agent.caveat" {
			continue
		}
		if e.Detail["agent"] == "watcher" && e.Detail["run"] == "r2" &&
			e.Detail["caveat"] == "tool" && e.Detail["tool"] == "vaigil_write" {
			found = true
		}
	}
	if !found {
		t.Error("no audit record names the caveat that refused the call")
	}
	// A run minted without the write tool is narrower still, and its write
	// is refused by the credential's own coarse bounds — viewer-grade,
	// read-only — before any caveat is read. Both refusals are correct;
	// which one speaks is decided by how narrow the mint was, and saying
	// so here is the honesty this row owes.
	coarse := mintRun(t, root, "r2b", []string{"vaigil_read"}, "", 0, -1)
	coarseMsg := refused(t, buildMCP(root, runCaller(t, root, coarse)),
		"vaigil_write", "propose_finding_decision",
		map[string]any{"id": "x", "to": "fixed", "because": "y"})
	if !strings.Contains(coarseMsg, "credential carries viewer") {
		t.Errorf("the coarse refusal does not name the credential's own "+
			"bound: %s", coarseMsg)
	}
}

// TestCaveatExpiryIsHonouredThroughTheOperationPath: the parent run works
// beside a child attenuated past its own deadline, and the child's next
// call is refused by the clock the caveat carries — not by the store,
// whose credential is still live.
func TestCaveatExpiryIsHonouredThroughTheOperationPath(t *testing.T) {
	root := caveatSite(t)
	parent := mintRun(t, root, "r3", []string{"vaigil_read"}, "", 0, -1)
	dead, err := macaroon.Attenuate(parent,
		macaroon.ExpCaveat(time.Now().UTC().Add(-time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	msg := refused(t, buildMCP(root, runCaller(t, root, dead)), "vaigil_read",
		"list_findings", nil)
	for _, want := range []string{"caveat exp", "this run ended at"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q: %s", want, msg)
		}
	}
	if _, err := callTool(t, buildMCP(root, runCaller(t, root, parent)),
		"vaigil_read", "list_findings", nil); err != nil {
		t.Errorf("attenuating a token ended the parent: %s", err.Message)
	}
}

// TestCaveatCallsBudgetIsCountedAndRunsAreIndependent: a budget of two is
// two calls and then a refusal that names the budget, and a second run's
// token is not spent by the first — each grant counts its own calls.
func TestCaveatCallsBudgetIsCountedAndRunsAreIndependent(t *testing.T) {
	root := caveatSite(t)
	srv := buildMCP(root, runCaller(t, root,
		mintRun(t, root, "r4", []string{"vaigil_read"}, "", 2, -1)))
	for i := 1; i <= 2; i++ {
		if _, err := callTool(t, srv, "vaigil_read", "list_findings", nil); err != nil {
			t.Fatalf("call %d of 2 was refused: %s", i, err.Message)
		}
	}
	msg := refused(t, srv, "vaigil_read", "list_findings", nil)
	for _, want := range []string{"caveat calls", "budget"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q: %s", want, msg)
		}
	}
	// The independent run, minted beside the spent one.
	if _, err := callTool(t, buildMCP(root, runCaller(t, root,
		mintRun(t, root, "r5", []string{"vaigil_read"}, "", 2, -1))),
		"vaigil_read", "list_findings", nil); err != nil {
		t.Errorf("a fresh run's budget was spent by another run's calls: %s",
			err.Message)
	}
}

// TestCaveatPurposeMismatchRefused: a triage run proposes (the handler's
// own refusal for a finding that does not exist is what a gate-passing
// write looks like), and the same token attenuated to observe is refused
// at the write — by the purpose, before the operation is ever reached.
func TestCaveatPurposeMismatchRefused(t *testing.T) {
	root := caveatSite(t)
	triage := mintRun(t, root, "r6", []string{"vaigil_read", "vaigil_write"},
		macaroon.PurposeTriage, 0, -1)
	_, err := callTool(t, buildMCP(root, runCaller(t, root, triage)),
		"vaigil_write", "propose_finding_decision",
		map[string]any{"id": "no-such", "to": "fixed", "because": "x"})
	if err == nil || !strings.Contains(err.Message, "no finding has that id") {
		t.Fatalf("a triage run's proposal did not reach the handler: %v", err)
	}
	quieter, aerr := macaroon.Attenuate(triage,
		macaroon.Caveat{Kind: macaroon.KindPurpose, Value: macaroon.PurposeObserve})
	if aerr != nil {
		t.Fatal(aerr)
	}
	srv := buildMCP(root, runCaller(t, root, quieter))
	msg := refused(t, srv, "vaigil_write", "propose_finding_decision",
		map[string]any{"id": "x", "to": "fixed", "because": "y"})
	for _, want := range []string{"caveat purpose", macaroon.PurposeObserve,
		"does not propose"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q: %s", want, msg)
		}
	}
	// The read the narrower purpose permits is still served.
	if _, err := callTool(t, srv, "vaigil_read", "list_findings", nil); err != nil {
		t.Errorf("an observe run was refused its reads: %s", err.Message)
	}
}

// TestCaveatLevelBoundsTheWriteTool: autonomy L1 is proposing and L0 is
// reading (research §6.9 mapped onto this surface), so a run bounded at 0
// reads and is refused the write by its level — with the tools and the
// role both permitting, so it is the level that says no.
func TestCaveatLevelBoundsTheWriteTool(t *testing.T) {
	root := caveatSite(t)
	tok := mintRun(t, root, "r7", []string{"vaigil_read", "vaigil_write"},
		macaroon.PurposeTriage, 0, 0)
	srv := buildMCP(root, runCaller(t, root, tok))
	if _, err := callTool(t, srv, "vaigil_read", "list_findings", nil); err != nil {
		t.Fatalf("an L0 run was refused its reads: %s", err.Message)
	}
	msg := refused(t, srv, "vaigil_write", "propose_finding_decision",
		map[string]any{"id": "x", "to": "fixed", "because": "y"})
	for _, want := range []string{"caveat level", "autonomy level 1",
		"bounded at 0"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q: %s", want, msg)
		}
	}
}

// TestCaveatBearerHalfIsRefusedAlone: the strip. The credential half
// authenticates on its own — it is a real token, and the store says so —
// and the gate refuses it anyway, because a run-bound credential arrives
// whole or not at all. The caveats are the credential.
func TestCaveatBearerHalfIsRefusedAlone(t *testing.T) {
	root := caveatSite(t)
	tok := mintRun(t, root, "r8", []string{"vaigil_read"}, "", 0, -1)
	secret, ok := macaroon.Split(tok)
	if !ok {
		t.Fatal("the minted token has no halves")
	}
	c := resolveCaller(root, secret)
	if !c.Verified {
		t.Fatalf("the bare half did not authenticate: %s", c.Why)
	}
	msg := refused(t, buildMCP(root, c), "vaigil_read", "list_findings", nil)
	for _, want := range []string{"bound to run r8", "refused without the " +
		"caveats"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q: %s", want, msg)
		}
	}
}

// TestCaveatTamperedPayloadIsRefusedByTheChain: one changed character in
// the payload half. The credential half still authenticates — the store
// never sees the payload — and the chain refuses what the minter did not
// sign.
func TestCaveatTamperedPayloadIsRefusedByTheChain(t *testing.T) {
	root := caveatSite(t)
	tok := mintRun(t, root, "r9", []string{"vaigil_read"}, "", 0, -1)
	i := strings.Index(tok, ".vgt1.")
	if i < 0 {
		t.Fatal("the minted token carries no payload")
	}
	// A character mid-payload, changed within the base64url alphabet so
	// the string stays the shape of a token: it decodes to different
	// bytes, which is the tamper the chain has to catch.
	j := i + len(".vgt1.") + 5
	if j >= len(tok) {
		t.Fatal("the payload is too short to tamper")
	}
	forged := tok[:j] + "Q" + tok[j+1:]
	if forged == tok {
		t.Fatal("the tamper changed nothing")
	}
	c := resolveCaller(root, forged)
	if !c.Verified {
		t.Fatalf("the tampered token failed as a credential, not as a " +
			"chain: the credential half was never touched")
	}
	msg := refused(t, buildMCP(root, c), "vaigil_read", "list_findings", nil)
	if !strings.Contains(msg, "agent") || !strings.Contains(msg, "run r9") {
		t.Errorf("the refusal does not name the run it refused: %s", msg)
	}
	// A truncated tail is not even the shape of a token, and never
	// authenticates as anything.
	if c := resolveCaller(root, tok[:len(tok)-1]); c.Verified {
		t.Error("a token with its tail cut off authenticated as a credential")
	}
}

// TestCaveatChainNamesItsOwnRun: a chain minted for another run and hung
// on this credential's secret half — which the store is happy to
// authenticate — is refused because the chain does not name the run it was
// presented under. A grant is id and caveats together, not caveats alone.
func TestCaveatChainNamesItsOwnRun(t *testing.T) {
	root := caveatSite(t)
	tok := mintRun(t, root, "r10", []string{"vaigil_read"}, "", 0, -1)
	secret, _ := macaroon.Split(tok)
	key, err := ensureRunKey(root)
	if err != nil {
		t.Fatal(err)
	}
	exp := macaroon.ExpCaveat(time.Now().UTC().Add(time.Hour))
	tools, err := macaroon.ToolCaveat("vaigil_read")
	if err != nil {
		t.Fatal(err)
	}
	forged, err := macaroon.Mint(secret, key, agentreg.TokenPrefix+
		"watcher/other-run", tools, exp)
	if err != nil {
		t.Fatal(err)
	}
	msg := refused(t, buildMCP(root, runCaller(t, root, forged)),
		"vaigil_read", "list_findings", nil)
	for _, want := range []string{"names run", "other-run", "run r10"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q: %s", want, msg)
		}
	}
}

// TestCaveatCoarseBoundsCatchWhatAForgedChainSheds: the honest limit, as a
// row. The run key is the store account's secret material; a reader of it
// plus a run token can re-mint the token's caveats wider — not its
// credential, which the store holds the hash of. What catches that is the
// coarse bounds the mint sets to match the caveats: this run was minted
// viewer-grade and read-only, so a forged write tool is refused by the
// credential itself, on any surface, chain or no chain.
func TestCaveatCoarseBoundsCatchWhatAForgedChainSheds(t *testing.T) {
	root := caveatSite(t)
	tok := mintRun(t, root, "r11", []string{"vaigil_read"}, "", 0, -1)
	secret, _ := macaroon.Split(tok)
	key, err := ensureRunKey(root)
	if err != nil {
		t.Fatal(err)
	}
	wider, err := macaroon.ToolCaveat("vaigil_read", "vaigil_write")
	if err != nil {
		t.Fatal(err)
	}
	exp := macaroon.ExpCaveat(time.Now().UTC().Add(time.Hour))
	purpose, err := macaroon.PurposeCaveat(macaroon.PurposeTriage)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := macaroon.Mint(secret, key, agentreg.TokenPrefix+
		"watcher/r11", wider, purpose, exp)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, runCaller(t, root, forged))
	if _, err := callTool(t, srv, "vaigil_read", "list_findings", nil); err != nil {
		t.Fatalf("the forged token was refused its own reads: %s", err.Message)
	}
	msg := refused(t, srv, "vaigil_write", "propose_finding_decision",
		map[string]any{"id": "x", "to": "fixed", "because": "y"})
	if !strings.Contains(msg, "credential carries viewer") &&
		!strings.Contains(msg, "read-only") {
		t.Errorf("the forged write was refused, but not by the coarse "+
			"bounds the mint set: %s", msg)
	}
}

// TestCaveatKillSwitchReachesRunTokens: the disable revokes the run's
// credential in the same act as everything else bound to the agent, so the
// bearer is told its token is dead before any gate is reached — the sweep
// matches the run after the slash in the name.
func TestCaveatKillSwitchReachesRunTokens(t *testing.T) {
	root := caveatSite(t)
	tok := mintRun(t, root, "r12", []string{"vaigil_read"}, "", 0, -1)
	if err := cmdAgent(root, []string{"disable", "watcher", "--why",
		"proposing outside its run"}); err != nil {
		t.Fatal(err)
	}
	if c := resolveCaller(root, tok); c.Verified {
		t.Fatal("the disabled agent's run token still authenticates")
	}
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	revoked := false
	for _, tk := range ts.Tokens {
		if tk.Name == agentreg.TokenPrefix+"watcher/r12" {
			revoked = tk.Revoked
		}
	}
	if !revoked {
		t.Error("the kill switch left the run credential live")
	}
}

// TestCaveatMintRefusesWhatItCannotMint: the mint's own matrix — an
// unregistered agent, a disabled one, a tool the interface does not serve,
// a tool the register does not allow, a run id that could not be a name,
// hours outside a run's life, a word that is not a purpose, a purpose at
// odds with the tools, a level above what the surface reaches — each
// refused, and each said plainly enough to be fixed at a terminal.
func TestCaveatMintRefusesWhatItCannotMint(t *testing.T) {
	root := caveatSite(t)
	admin := caveatAdmin(t, root)
	badRun := func(run string, tools string, want string) {
		t.Helper()
		if _, err := issueRunToken(root, admin, "watcher", run,
			splitList(tools), 8, "", 0, -1); err == nil ||
			!strings.Contains(err.Error(), want) {
			t.Fatalf("minting run %q tools %s was refused with %v, not %q",
				run, tools, err, want)
		}
	}
	badRun("r13", "", "names the tools")
	badRun("r13", "vaigil_exec", "agent interface serves")
	badRun("r13", "vaigil_read,vaigil_decide", "agent interface serves")
	badRun("R13", "vaigil_read", "not a run id")
	badRun("r", "vaigil_read", "not a run id")
	if _, err := issueRunToken(root, admin, "ghost", "r13",
		[]string{"vaigil_read"}, 8, "", 0, -1); err == nil ||
		!strings.Contains(err.Error(), "no agent") {
		t.Fatalf("minting for an unregistered agent: %v", err)
	}
	if err := cmdAgent(root, []string{"disable", "watcher", "--why", "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := issueRunToken(root, admin, "watcher", "r13",
		[]string{"vaigil_read"}, 8, "", 0, -1); err == nil ||
		!strings.Contains(err.Error(), "disabled") {
		t.Fatalf("minting for a disabled agent: %v", err)
	}
	if err := cmdAgent(root, []string{"enable", "watcher", "--why", "back"}); err != nil {
		t.Fatal(err)
	}
	// A narrower register: an agent allowed to read only cannot pass the
	// write tool on to a run.
	root2 := caveatSite(t)
	if err := cmdAgent(root2, []string{"allow", "watcher", "--remove",
		"vaigil_write"}); err != nil {
		t.Fatal(err)
	}
	if _, err := issueRunToken(root2, caveatAdmin(t, root2), "watcher", "r13",
		[]string{"vaigil_read", "vaigil_write"}, 8, "", 0, -1); err == nil ||
		!strings.Contains(err.Error(), "cannot start wider") {
		t.Fatalf("a run minted wider than its agent: %v", err)
	}
	if _, err := issueRunToken(root, admin, "watcher", "r13",
		[]string{"vaigil_read", "vaigil_write"}, 8, macaroon.PurposeObserve,
		0, -1); err == nil || !strings.Contains(err.Error(),
		"purpose and the tools would disagree") {
		t.Fatalf("a purpose at odds with the tools was minted: %v", err)
	}
	if _, err := issueRunToken(root, admin, "watcher", "r13",
		[]string{"vaigil_read"}, 8, "vibing", 0, -1); err == nil ||
		!strings.Contains(err.Error(), "not a purpose") {
		t.Fatalf("a word outside the vocabulary was minted: %v", err)
	}
	if _, err := issueRunToken(root, admin, "watcher", "r13",
		[]string{"vaigil_read", "vaigil_write"}, 8, macaroon.PurposeTriage,
		0, 2); err == nil || !strings.Contains(err.Error(), "nothing here") {
		t.Fatalf("a level above the surface was minted: %v", err)
	}
	if _, err := issueRunToken(root, admin, "watcher", "r13",
		[]string{"vaigil_read"}, 8, "", 0, 1); err == nil ||
		!strings.Contains(err.Error(), "bound on nothing") {
		t.Fatalf("a read-only run was minted with autonomy above 0: %v", err)
	}
	for _, h := range []int{0, 25} {
		if _, err := issueRunToken(root, admin, "watcher", "r13",
			[]string{"vaigil_read"}, h, "", 0, -1); err == nil ||
			!strings.Contains(err.Error(), "1 to 24") {
			t.Fatalf("hours %d was minted: %v", h, err)
		}
	}
	// And nobody unverified mints anything.
	if _, err := issueRunToken(root, &Caller{Name: "someone"}, "watcher",
		"r13", []string{"vaigil_read"}, 8, "", 0, -1); err == nil ||
		!strings.Contains(err.Error(), "verified") {
		t.Fatalf("an unverified caller minted a run token: %v", err)
	}
}

// TestCaveatMintCommandRunsAndRecords: the command surface — the same core
// the rows above used, reached through the subcommand's grammar, with the
// mint on the record under the minter's own name.
func TestCaveatMintCommandRunsAndRecords(t *testing.T) {
	root := caveatSite(t)
	// The command resolves its own caller, so the administrator's token is
	// where findToken looks: a home with no token file in it, then the
	// environment — in that order of deliberateness (caller.go).
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := ts.IssueScoped("cli", "dana@acme.example",
		auth.RoleAdmin, "/", 24*time.Hour, auth.RoleAdmin, auth.Scope{})
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("VAIGIL_TOKEN", secret)
	if err := cmdAgent(root, []string{"token", "watcher", "--tools",
		"vaigil_read", "--for-run", "r14", "--hours", "4"}); err != nil {
		t.Fatal(err)
	}
	found := false
	ts2, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, tk := range ts2.Tokens {
		if tk.Name == agentreg.TokenPrefix+"watcher/r14" {
			found = true
		}
	}
	if !found {
		t.Error("the command minted no credential in the store")
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	recorded := false
	for _, e := range events {
		if e.Action == "agent.token" && e.Detail["agent"] == "watcher" &&
			e.Detail["run"] == "r14" && e.Detail["tools"] == "vaigil_read" {
			recorded = true
		}
	}
	if !recorded {
		t.Error("the mint was not recorded with its run and its tools")
	}
	// The grammar refuses to guess: no run, no tools.
	if err := cmdAgent(root, []string{"token", "watcher", "--tools",
		"vaigil_read"}); err == nil {
		t.Error("a mint without --for-run was accepted")
	}
	if err := cmdAgent(root, []string{"token", "watcher", "--for-run",
		"r15"}); err == nil {
		t.Error("a mint without --tools was accepted")
	}
}
