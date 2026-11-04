// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func testServer() *Server {
	s := NewServer("aertun", "test")
	s.Authorise = allowAll
	s.Register(Operation{
		Name: "list_findings", Summary: "the security finding queue, most urgent first",
		Keywords: []string{"findings", "alerts", "queue", "triage"},
	}, func(a map[string]any) (any, error) { return "F-1, F-2", nil })

	s.Register(Operation{
		Name: "read_finding", Summary: "one finding: why it ranks, its evidence",
		Args:     map[string]string{"id": "the finding id from list_findings"},
		Keywords: []string{"finding", "evidence", "investigate"},
	}, func(a map[string]any) (any, error) { return "evidence, fenced", nil })

	s.Register(Operation{
		Name:    "propose_finding_decision",
		Summary: "suggest a decision on a finding for a person to make",
		Writes:  true, NeedsRole: "analyst",
		Args: map[string]string{"id": "the finding id",
			"to": "a state", "because": "the reasoning"},
		Keywords: []string{"triage", "verdict", "propose", "decision"},
	}, func(a map[string]any) (any, error) {
		return nil, &Refusal{Reason: "no finding has that id"}
	})
	return s
}

func call(t *testing.T, s *Server, method string, params any) *Response {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	return s.Handle(Request{JSONRPC: "2.0", ID: json.RawMessage(`1`),
		Method: method, Params: raw})
}

func text(t *testing.T, r *Response) string {
	t.Helper()
	if r.Error != nil {
		t.Fatalf("unexpected error: %v", r.Error.Message)
	}
	m, ok := r.Result.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result shape: %#v", r.Result)
	}
	content, _ := m["content"].([]map[string]any)
	if len(content) == 0 {
		t.Fatal("no content")
	}
	return content[0]["text"].(string)
}

// The whole point of the design: what an agent pays for unasked is three short
// definitions, not one per command. A server that grew a tool per operation
// would be the thing the measurements condemned.
func TestOnlyThreeToolsAreEverPreloaded(t *testing.T) {
	s := testServer()
	r := s.Handle(Request{JSONRPC: "2.0", Method: "tools/list"})
	m := r.Result.(map[string]any)
	tools := m["tools"].([]Tool)

	if len(tools) != 3 {
		t.Fatalf("expected 3 tools regardless of operation count, got %d", len(tools))
	}
	for _, tool := range tools {
		if tool.Name == "aertun_check" {
			t.Error("aertun_check is offered and no operation answers to it: " +
				"a dead tool is a definition an agent pays for on every " +
				"session and plans around for nothing")
		}
	}
	// Adding operations must not add tools, or the property is accidental.
	s.Register(Operation{Name: "extra", Summary: "another one"},
		func(map[string]any) (any, error) { return "", nil })
	r = s.Handle(Request{JSONRPC: "2.0", Method: "tools/list"})
	if got := len(r.Result.(map[string]any)["tools"].([]Tool)); got != 3 {
		t.Errorf("registering an operation added a tool: %d", got)
	}
}

func TestFindDescribesOnlyWhatWasAskedFor(t *testing.T) {
	s := testServer()
	out := text(t, call(t, s, "tools/call", callParams{
		Name: "aertun_find", Arguments: map[string]any{"query": "propose a decision on a finding"}}))

	if !strings.Contains(out, "propose_finding_decision") {
		t.Errorf("the matching operation is missing: %q", out)
	}
	if !strings.Contains(out, "needs role: analyst") {
		t.Error("the role requirement should be stated, so an agent can tell " +
			"a permission problem from a broken call")
	}
}

func TestFindWithNoMatchReturnsTheMenu(t *testing.T) {
	s := testServer()
	out := text(t, call(t, s, "tools/call", callParams{
		Name: "aertun_find", Arguments: map[string]any{"query": "xyzzy"}}))

	// An agent that searched badly should see what exists rather than a dead
	// end it will guess around.
	for _, want := range []string{"list_findings", "read_finding", "propose_finding_decision"} {
		if !strings.Contains(out, want) {
			t.Errorf("a failed search should list everything; %s missing", want)
		}
	}
}

// Without this the three-tool split would be a labelling convention, and a
// client permitted only to read could write by naming the operation.
func TestAReadToolCannotReachAWriteOperation(t *testing.T) {
	s := testServer()
	r := call(t, s, "tools/call", callParams{
		Name:      "aertun_read",
		Arguments: map[string]any{"operation": "propose_finding_decision"}})

	if r.Error == nil {
		t.Fatal("a write operation was reachable through the read tool")
	}
	if !strings.Contains(r.Error.Message, "aertun_write") {
		t.Errorf("the error should name the right tool, got %q", r.Error.Message)
	}
}

func TestAWriteToolCannotBeUsedForAReadOperation(t *testing.T) {
	s := testServer()
	r := call(t, s, "tools/call", callParams{
		Name:      "aertun_write",
		Arguments: map[string]any{"operation": "list_findings"}})
	if r.Error == nil {
		t.Error("a read operation should not be invoked through the write tool")
	}
}

// A refusal is a decision. An agent that reads "denied by policy" as "the server
// broke" will retry, and retrying a refusal turns one blocked action into many.
func TestARefusalIsDistinguishableFromAFailure(t *testing.T) {
	s := testServer()
	r := call(t, s, "tools/call", callParams{
		Name:      "aertun_write",
		Arguments: map[string]any{"operation": "propose_finding_decision"}})

	if r.Error == nil {
		t.Fatal("the gate should have refused")
	}
	if r.Error.Code != CodeRefused {
		t.Errorf("a refusal should not use the internal-error code, got %d", r.Error.Code)
	}
	if r.Error.Code == CodeInternal {
		t.Error("refusal and malfunction must not share a code")
	}
	data, _ := r.Error.Data.(map[string]any)
	if data["retryable"] != false {
		t.Error("a refusal should say it is not worth retrying")
	}
	if !strings.Contains(r.Error.Message, "no finding has that id") {
		t.Errorf("the refusal should say what blocked it: %q", r.Error.Message)
	}
}

func TestAnInternalFailureIsNotDressedAsARefusal(t *testing.T) {
	s := NewServer("t", "1")
	s.Authorise = allowAll
	s.Register(Operation{Name: "broken", Summary: "fails", Writes: true},
		func(map[string]any) (any, error) { return nil, fmt.Errorf("disk on fire") })

	r := call(t, s, "tools/call", callParams{
		Name: "aertun_write", Arguments: map[string]any{"operation": "broken"}})
	if r.Error.Code != CodeInternal {
		t.Errorf("a genuine failure should be an internal error, got %d", r.Error.Code)
	}
}

func TestUnknownOperationsAndToolsAreRefusedClearly(t *testing.T) {
	s := testServer()

	r := call(t, s, "tools/call", callParams{
		Name: "aertun_read", Arguments: map[string]any{"operation": "nonsense"}})
	if r.Error == nil || !strings.Contains(r.Error.Message, "aertun_find") {
		t.Error("an unknown operation should point at how to discover the real ones")
	}

	r = call(t, s, "tools/call", callParams{Name: "aertun_delete_everything"})
	if r.Error == nil || r.Error.Code != CodeMethodNotFound {
		t.Error("an unknown tool should be a method-not-found")
	}
}

func TestInitializeAnnouncesTheConstraints(t *testing.T) {
	s := testServer()
	r := s.Handle(Request{JSONRPC: "2.0", Method: "initialize"})
	m := r.Result.(map[string]any)

	instructions, _ := m["instructions"].(string)
	// The two things an agent must know before it calls anything.
	if !strings.Contains(instructions, "aertun_find") {
		t.Error("initialize should tell the agent to search first")
	}
	if !strings.Contains(instructions, "a person decides") {
		t.Error("initialize should say the one write proposes and a person " +
			"decides, since an agent that thinks it decided is the thing " +
			"this server exists to prevent")
	}
}

// The version answered is the one the session will actually be served in: the
// client's own when this server speaks it, and the newest it does when not —
// never a fixed date that may be neither. Answering a version the rest of the
// session does not honour is lying to a client at the one moment it asks.
func TestInitializeNegotiatesTheVersionItCanHonour(t *testing.T) {
	s := testServer()

	// The client's own, for every revision this server speaks.
	for _, v := range Supported() {
		if v == Modern {
			// 2026-07-28 has no initialize; a stateless client does not ask.
			continue
		}
		params, _ := json.Marshal(map[string]string{"protocolVersion": v})
		r := s.Handle(Request{JSONRPC: "2.0", Params: params, Method: "initialize"})
		if got := r.Result.(map[string]any)["protocolVersion"]; got != v {
			t.Errorf("asked for %s and answered %v", v, got)
		}
	}
	// No version offered, and one this server does not speak: the newest it
	// does — the same answer the HTTP transport gives, so the two transports
	// cannot disagree about who a client is talking to.
	for _, body := range []string{
		`{}`, `{"protocolVersion":"2024-11-05"}`, `{"protocolVersion":"2099-01-01"}`,
	} {
		r := s.Handle(Request{JSONRPC: "2.0",
			Params: json.RawMessage(body), Method: "initialize"})
		if got := r.Result.(map[string]any)["protocolVersion"]; got != Legacy[0] {
			t.Errorf("params %s were answered with %v, want %s", body, got, Legacy[0])
		}
	}
}

// A tool description is the only thing an agent is told about a tool before it
// calls it, so a description of something this server does not do — drafts,
// publishing, markings from another product — is an agent planning around a
// promise nobody kept. The dead tool is caught by its own test above.
func TestToolDescriptionsPromiseOnlyWhatTheOperationsDo(t *testing.T) {
	s := testServer()
	r := s.Handle(Request{JSONRPC: "2.0", Method: "tools/list"})
	tools := r.Result.(map[string]any)["tools"].([]Tool)
	instructions := s.Handle(Request{JSONRPC: "2.0", Method: "initialize"}).
		Result.(map[string]any)["instructions"].(string)

	// Claims left over from what this server used to be.
	for _, text := range append([]string{instructions},
		func() []string {
			out := make([]string, len(tools))
			for i, tool := range tools {
				out[i] = tool.Description
			}
			return out
		}()...) {
		lower := strings.ToLower(text)
		for _, gone := range []string{"draft", "publish", "ai-generated",
			"eu ai act", "accessibility", "provenance"} {
			if strings.Contains(lower, gone) {
				t.Errorf("a tool description still claims %q: %q", gone, text)
			}
		}
	}
	// And the write tool says what the write is: a proposal, never a decision.
	for _, tool := range tools {
		if tool.Name == "aertun_write" &&
			!strings.Contains(strings.ToLower(tool.Description), "propose") {
			t.Errorf("the write tool does not say it proposes: %q", tool.Description)
		}
	}
}

func TestUnknownMethodIsNotFound(t *testing.T) {
	s := testServer()
	r := s.Handle(Request{JSONRPC: "2.0", Method: "resources/list"})
	if r.Error == nil || r.Error.Code != CodeMethodNotFound {
		t.Error("an unimplemented method should say so rather than fail oddly")
	}
}

// allowAll is the hook for tests about something other than authority.
//
// It has to be written out rather than left nil, because a nil hook refuses
// every operation — which is the point of it, and which is how the suite
// found out: the refusal-semantics test above started failing the moment the
// gate went in, reporting a refusal it had not asked for.
func allowAll(Operation) error { return nil }
