// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aeroprove/aeroprove/internal/audit"
	"github.com/aeroprove/aeroprove/internal/auth"
	"github.com/aeroprove/aeroprove/internal/dpop"
	"github.com/aeroprove/aeroprove/internal/finding"
	"github.com/aeroprove/aeroprove/internal/mcp"
	"github.com/aeroprove/aeroprove/internal/telemetry"
)

// TestStdioToolCallsAreAudited.
//
// The HTTP transport records every tools/call; without the same on stdio, the
// transport a caller happened to choose would decide whether anything could
// tell it had been there. An agent scraping the findings queue over a pipe
// leaves the same record as one scraping it over HTTP, so the rules that read
// these records as events watch both.
func TestStdioToolCallsAreAudited(t *testing.T) {
	srv, root, _ := securityMCP(t)
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"aeroprove_read","arguments":{"operation":"list_findings"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"aeroprove_write","arguments":{"operation":"propose_finding_decision","arguments":{"id":"no-such","to":"fixed","because":"x"}}}}`,
		// Not a call: listing tools writes nothing, as on HTTP.
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := serveStdio(root, srv, &Caller{Name: "dana", Kind: audit.KindHuman,
		Verified: true}, strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	// Three requests, three replies: the pipe answered each.
	if n := bytes.Count(out.Bytes(), []byte(`"jsonrpc":"2.0"`)); n != 3 {
		t.Fatalf("%d replies for 3 requests", n)
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var calls []audit.Event
	for _, e := range events {
		if e.Action == "mcp.call" {
			calls = append(calls, e)
		}
	}
	if len(calls) != 2 {
		t.Fatalf("%d mcp.call records for 2 calls; tools/list is not one", len(calls))
	}
	first, second := calls[0], calls[1]
	if first.Outcome != audit.Success ||
		first.Detail["tool"] != "aeroprove_read" ||
		first.Detail["operation"] != "list_findings" {
		t.Errorf("the read was recorded as %s %v", first.Outcome, first.Detail)
	}
	if second.Outcome != audit.Denied ||
		second.Detail["tool"] != "aeroprove_write" ||
		second.Detail["operation"] != "propose_finding_decision" {
		t.Errorf("the refusal was recorded as %s %v", second.Outcome, second.Detail)
	}
	// The same shape the HTTP transport writes: an AI actor under the log's
	// pseudonym for it, with which client made the call.
	l, err := openAudit(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range calls {
		if e.Kind != audit.KindAI || !l.Matches(e.Principal, "mcp-client") {
			t.Errorf("a call by an agent is recorded as %s/%s", e.Principal, e.Kind)
		}
		if e.Detail["client"] != "dana" {
			t.Errorf("which client made the call is lost: %v", e.Detail)
		}
	}
}

// reOffered is one line of aeroprove_find's menu: the tool an operation is
// reached through, and the operation's name.
var reOffered = regexp.MustCompile(`call: (aeroprove_[a-z]+)\{operation:"([a-z_]+)"`)

// TestEveryToolLeadsToAtLeastOneOperation.
//
// aeroprove_check was a tool with no operation behind it: a definition every
// session paid for and no call could use, describing checks this program
// does not run. Each tool must lead somewhere, except aeroprove_find, which is
// excused because it is the search over the operations rather than one of
// them.
func TestEveryToolLeadsToAtLeastOneOperation(t *testing.T) {
	srv := buildMCP(t.TempDir(), &Caller{Name: "tester", Kind: audit.KindHuman})
	resp := srv.Handle(mcp.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`),
		Method: "tools/list"})
	tools := resp.Result.(map[string]any)["tools"].([]mcp.Tool)
	if len(tools) == 0 {
		t.Fatal("no tools are offered")
	}

	// A query nothing matches returns the whole menu, each operation with
	// the tool it goes through.
	params, _ := json.Marshal(map[string]any{"name": "aeroprove_find",
		"arguments": map[string]any{"query": "zzz-nothing-matches-this"}})
	resp = srv.Handle(mcp.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`),
		Method: "tools/call", Params: params})
	if resp.Error != nil {
		t.Fatal(resp.Error.Message)
	}
	var r struct {
		Content []struct{ Text string } `json:"content"`
	}
	b, _ := json.Marshal(resp.Result)
	if jerr := json.Unmarshal(b, &r); jerr != nil || len(r.Content) == 0 {
		t.Fatalf("no menu: %s (%v)", b, jerr)
	}

	byTool := map[string][]string{}
	for _, m := range reOffered.FindAllStringSubmatch(r.Content[0].Text, -1) {
		byTool[m[1]] = append(byTool[m[1]], m[2])
	}
	for _, tool := range tools {
		switch tool.Name {
		case "aeroprove_find":
			// Excused: it is how the rest are found, and it offers itself.
			continue
		case "aeroprove_read", "aeroprove_write":
		default:
			t.Errorf("%q is offered and nobody decided it should be; "+
				"aeroprove_check is the tool this replaces", tool.Name)
		}
		if len(byTool[tool.Name]) == 0 {
			t.Errorf("%s leads to no operation: a dead tool again", tool.Name)
		}
	}
	// And every registered operation is reached through the tool its Writes
	// says it goes through, or it is registered behind the agent's back.
	if len(byTool["aeroprove_check"]) > 0 {
		t.Error("an operation is offered through the removed tool")
	}
	for _, op := range srv.Operations() {
		want := "aeroprove_read"
		if op.Writes {
			want = "aeroprove_write"
		}
		found := false
		for _, name := range byTool[want] {
			if name == op.Name {
				found = true
			}
		}
		if !found {
			t.Errorf("%q is registered and no %s call reaches it", op.Name, want)
		}
	}
}

// agentSite is the console's own arrangement with the agent interface
// mounted on it, over a real socket: a finding to read and propose on, a
// principal who may triage it, and two tokens for her — one that may
// propose and one that may only read.
func agentSite(t *testing.T) (base, root, id, analyst, viewer string) {
	t.Helper()
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	root, rules := siemSite(t, []labelled{{"spray", true,
		signIn("okta/system", "admin-dana", telemetry.DispositionFailed,
			"a password spray", t0)}})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	id = queue(t, root)[0].ID

	// Enforcement on, dana an analyst: what a token holds, not what dana
	// holds, is what the viewer token's refusal has to come from.
	pol, err := loadPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := pol.Grant(auth.Binding{Principal: "dana",
		Role: auth.RoleAnalyst, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}

	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	analyst, _, err = ts.Issue("agent", "dana", auth.RoleAnalyst, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	viewer, _, err = ts.Issue("agent-readonly", "dana", auth.RoleViewer, "/",
		time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}

	// A real socket, and the address known before the handlers are built —
	// the order serve builds in, because the resource names itself by the
	// address it was given.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	mux := http.NewServeMux()
	mountMCP(mux, root, mustConfig(root), addr)
	// The console's own handler is not what these tests are about; a 404 in
	// its place is what proves the agent interface was mounted beside it
	// rather than somewhere inside it.
	mux.Handle("/", http.NotFoundHandler())
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + addr, root, id, analyst, viewer
}

// agentCall is one POST to the agent interface, framed as a 2025-06-18
// client sends it: a body, a bearer token, and optionally a page origin or
// a cookie, which the endpoint is not supposed to so much as look at.
type agentCall struct {
	token  string
	origin string
	cookie string
	body   string
}

func (c agentCall) do(t *testing.T, base string) (int, http.Header, mcp.Response) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/mcp",
		strings.NewReader(c.body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.origin != "" {
		req.Header.Set("Origin", c.origin)
	}
	if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	var resp mcp.Response
	_ = json.Unmarshal(b, &resp)
	return res.StatusCode, res.Header, resp
}

// The text of a successful tool result, for a caller that wants the answer
// and not the envelope.
func contentText(t *testing.T, resp mcp.Response) string {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error.Message)
	}
	b, _ := json.Marshal(resp.Result)
	var r struct {
		Content []struct{ Text string } `json:"content"`
	}
	_ = json.Unmarshal(b, &r)
	if len(r.Content) == 0 {
		t.Fatalf("no content: %s", b)
	}
	return r.Content[0].Text
}

// TestMCPOverHTTP.
//
// The transport was finished and mounted nowhere: a remote agent could not
// reach the store at all, only a local token file and stdio. This drives
// the mounted endpoint the way an agent does — handshake, menu, a read, a
// refusal, a proposal — over a socket, through the same gates stdio
// applies, and checks that the audit log recorded the journey.
func TestMCPOverHTTP(t *testing.T) {
	base, root, id, analyst, viewer := agentSite(t)

	// The handshake: the version answered is the version asked for.
	_, _, resp := agentCall{token: analyst, body: `{"jsonrpc":"2.0","id":1,` +
		`"method":"initialize","params":{"protocolVersion":"2025-06-18",` +
		`"capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`}.do(t, base)
	if got := resp.Result.(map[string]any)["protocolVersion"]; got != "2025-06-18" {
		t.Fatalf("initialize answered %v", got)
	}

	// The menu: three tools and no more, whatever is registered behind them.
	code, _, resp := agentCall{token: analyst,
		body: `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`}.do(t, base)
	if code != 200 {
		t.Fatalf("tools/list: %d", code)
	}
	tools := resp.Result.(map[string]any)["tools"].([]any)
	if len(tools) != 3 {
		t.Fatalf("%d tools over HTTP; the three-tool property is the whole design", len(tools))
	}

	// A read, over the wire, gated by the caller the token resolved to.
	code, _, resp = agentCall{token: analyst, body: `{"jsonrpc":"2.0","id":3,` +
		`"method":"tools/call","params":{"name":"aeroprove_read","arguments":` +
		`{"operation":"list_findings"}}}`}.do(t, base)
	if code != 200 {
		t.Fatalf("read: %d", code)
	}
	if text := contentText(t, resp); !strings.Contains(text, id) {
		t.Fatalf("the finding queue the agent read does not hold the finding: %s", text)
	}

	// The one write, by a token whose role does not reach it: an answer with
	// the refusal code, not an HTTP error and not a retryable one. This is
	// the token's own cap doing the refusing — dana may triage; this token
	// of hers may not — which is what makes a narrow agent token narrow.
	code, _, resp = agentCall{token: viewer, body: fmt.Sprintf(
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":`+
			`{"name":"aeroprove_write","arguments":{"operation":`+
			`"propose_finding_decision","arguments":{"id":%q,"to":"triaged",`+
			`"because":"the spray failed on the second factor"}}}}`, id)}.do(t, base)
	if code != 200 || resp.Error == nil || resp.Error.Code != mcp.CodeRefused {
		t.Fatalf("a viewer's proposal: %d %+v", code, resp.Error)
	}
	data, _ := resp.Error.Data.(map[string]any)
	if data["retryable"] != false {
		t.Errorf("a refusal over HTTP must say not to retry it: %v", data)
	}

	// The same proposal by the analyst's token: served, recorded as the
	// agent's, and changing nothing.
	code, _, resp = agentCall{token: analyst, body: fmt.Sprintf(
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":`+
			`{"name":"aeroprove_write","arguments":{"operation":`+
			`"propose_finding_decision","arguments":{"id":%q,"to":"triaged",`+
			`"because":"the spray failed on the second factor"}}}}`, id)}.do(t, base)
	if code != 200 {
		t.Fatalf("an analyst's proposal: %d", code)
	}
	if text := contentText(t, resp); !strings.Contains(text, "proposed") {
		t.Fatalf("the proposal was not recorded as one: %s", text)
	}

	// Every step of it is in the log: each call by whom and with what
	// outcome, and the proposal under its own action, attributed to the
	// agent and naming the client — which is what a person reading the
	// finding's page decides against.
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var calls []audit.Event
	var proposals []audit.Event
	for _, e := range events {
		switch e.Action {
		case "mcp.call":
			calls = append(calls, e)
		case finding.ProposalAction:
			proposals = append(proposals, e)
		}
	}
	if len(calls) != 3 { // the read, the refused proposal, the recorded one
		t.Fatalf("%d mcp.call records for 3 calls; listing tools and the "+
			"handshake are not calls", len(calls))
	}
	want := []struct {
		tool string
		out  audit.Outcome
	}{{"aeroprove_read", audit.Success}, {"aeroprove_write", audit.Denied},
		{"aeroprove_write", audit.Success}}
	for i, w := range want {
		if calls[i].Detail["tool"] != w.tool || calls[i].Outcome != w.out {
			t.Errorf("call %d recorded as %s %v", i, calls[i].Outcome, calls[i].Detail)
		}
		if calls[i].Kind != audit.KindAI || calls[i].Detail["client"] != "dana" {
			t.Errorf("call %d lost who made it: %s %v", i, calls[i].Kind, calls[i].Detail)
		}
	}
	if len(proposals) != 1 || proposals[0].Kind != audit.KindAI ||
		proposals[0].Detail["client"] != "dana" {
		t.Fatalf("the proposal is recorded as %+v", proposals)
	}
	// The person the agent acted for is the log's pseudonym, not their name:
	// the log pseudonymises who a record is about, while the client — a
	// token's own name, not a person's — stays clear so a proposal can be
	// labelled with who made it.
	if ob := proposals[0].Detail["on_behalf_of"]; ob == "" || ob == "dana" {
		t.Errorf("on_behalf_of is %q, not the log's pseudonym", ob)
	}
	// The refusal was a refusal in the log too, so a rule reading these
	// events tells an agent that was told no from one that broke.
	if calls[1].Outcome != audit.Denied {
		t.Errorf("the refused proposal was recorded as %s", calls[1].Outcome)
	}
}

// TestMCPOverHTTPChallengesAndRefuses.
//
// What an agent without a credential, a page from another site, or a
// console session cookie gets: a 401 that says where the rules are
// (RFC 9728), or a 403 — and never the console's own sign-in round.
func TestMCPOverHTTPChallengesAndRefuses(t *testing.T) {
	base, _, _, _, analyst := agentSite(t)
	list := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

	// No credential: the 401 names the resource's metadata, so a client
	// that knows OAuth finds out what it is holding and what it needs.
	code, h, _ := agentCall{body: list}.do(t, base)
	want := fmt.Sprintf(`Bearer resource_metadata="http://%s%s"`,
		strings.TrimPrefix(base, "http://"), wellKnownMCP)
	if code != http.StatusUnauthorized || h.Get("WWW-Authenticate") != want {
		t.Fatalf("%d %q, want the RFC 9728 challenge %q", code,
			h.Get("WWW-Authenticate"), want)
	}

	// The document the 401 names is served, and says what the resource is.
	res, err := http.Get(base + wellKnownMCP)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc["resource"] != base+"/mcp" {
		t.Fatalf("the metadata names %v", doc["resource"])
	}

	// A bad token says so, in the challenge.
	code, h, _ = agentCall{token: "a-token-nobody-issued", body: list}.do(t, base)
	if code != http.StatusUnauthorized ||
		!strings.Contains(h.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("%d %q", code, h.Get("WWW-Authenticate"))
	}

	// A console session cookie is not a bearer token. The endpoint
	// authenticates by the Authorization header only, so a signed-in
	// person's browser being driven at /mcp by a page has nothing to send.
	code, _, _ = agentCall{cookie: "aeroprove-session=stolen-or-real",
		body: list}.do(t, base)
	if code != http.StatusUnauthorized {
		t.Fatalf("a cookie opened the agent interface: %d", code)
	}

	// And a page from anywhere else is refused before any of the above is
	// even asked, however good the token.
	code, _, _ = agentCall{token: analyst, origin: "https://elsewhere.example",
		body: list}.do(t, base)
	if code != http.StatusForbidden {
		t.Fatalf("another site's page reached the endpoint: %d", code)
	}
	// The console's own origin is the one page origin that may call it.
	code, _, _ = agentCall{token: analyst, origin: base, body: list}.do(t, base)
	if code != http.StatusOK {
		t.Fatalf("the console's own pages were refused: %d", code)
	}
}

// TestMCPOverHTTPAcceptsAKeyBoundTokenWithItsProof.
//
// A token bound to a key is worthless copied on its own — the property
// DPoP exists for. The endpoint accepts it with the proof its key made for
// that one request, and refuses it without, which is what separates this
// surface from everywhere else a key-bound token is a bearer.
func TestMCPOverHTTPAcceptsAKeyBoundTokenWithItsProof(t *testing.T) {
	base, root, _, _, analyst := agentSite(t)
	list := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := dpop.PublicJWK(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	thumb, err := dpop.Thumbprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := loadTokens(root)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := ts.Authenticate(analyst, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := ts.BindKey(tok.ID, thumb); err != nil {
		t.Fatal(err)
	}
	if err := saveTokens(root, ts); err != nil {
		t.Fatal(err)
	}

	// The token alone is now a bearer nobody accepts.
	code, h, _ := agentCall{token: analyst, body: list}.do(t, base)
	if code != http.StatusUnauthorized ||
		!strings.Contains(h.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("a key-bound token was accepted as a bearer: %d", code)
	}

	// With the proof made for this request's method and address, the same
	// agent is in.
	proof, err := dpop.Prove(key, http.MethodPost, base+"/mcp", analyst,
		time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, base+"/mcp",
		strings.NewReader(list))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	req.Header.Set("Authorization", "DPoP "+analyst)
	req.Header.Set("DPoP", proof)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("the proved token was refused: %d %s", res.StatusCode, b)
	}
}
