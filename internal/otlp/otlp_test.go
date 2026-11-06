// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/source"
	"github.com/aertun/aertun/internal/telemetry"
)

// A push, in the shape the OTLP/HTTP JSON mapping specifies and the
// collectors send: resourceSpans, attributes as key-plus-typed-value
// objects, integers as strings, nanoseconds since the epoch.
const agentPush = `{
  "resourceSpans": [
    {
      "resource": {
        "attributes": [
          {"key": "service.name", "value": {"stringValue": "billing-agent"}},
          {"key": "telemetry.sdk.name", "value": {"stringValue": "opentelemetry"}}
        ]
      },
      "scopeSpans": [
        {
          "scope": {"name": "opentelemetry.genai", "version": "1.9.0"},
          "spans": [
            {
              "traceId": "5b8efff798038103d269b633813fc60c",
              "spanId": "eee19b7ec3c1b174",
              "parentSpanId": "eee19b7ec3c1b173",
              "name": "invoke_agent",
              "kind": 1,
              "startTimeUnixNano": "1761180000000000000",
              "endTimeUnixNano": "1761180002123000000",
              "attributes": [
                {"key": "gen_ai.operation.name", "value": {"stringValue": "invoke_agent"}},
                {"key": "gen_ai.agent.id", "value": {"stringValue": "agent-7"}},
                {"key": "gen_ai.agent.name", "value": {"stringValue": "refunder"}},
                {"key": "gen_ai.request.model", "value": {"stringValue": "claude-sonnet-4-5"}},
                {"key": "gen_ai.usage.input_tokens", "value": {"intValue": "1520"}},
                {"key": "gen_ai.usage.output_tokens", "value": {"intValue": "344"}},
                {"key": "gen_ai.conversation.id", "value": {"stringValue": "conv-0192"}},
                {"key": "gen_ai.system", "value": {"stringValue": "anthropic"}}
              ],
              "status": {}
            },
            {
              "traceId": "5b8efff798038103d269b633813fc60c",
              "spanId": "eee19b7ec3c1b175",
              "parentSpanId": "eee19b7ec3c1b174",
              "name": "execute_tool",
              "kind": 1,
              "startTimeUnixNano": "1761180000100000000",
              "endTimeUnixNano": "1761180000150000000",
              "attributes": [
                {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}},
                {"key": "gen_ai.agent.id", "value": {"stringValue": "agent-7"}},
                {"key": "gen_ai.tool.name", "value": {"stringValue": "filesystem.write"}},
                {"key": "gen_ai.conversation.id", "value": {"stringValue": "conv-0192"}}
              ],
              "status": {"code": 2, "message": "EACCES: permission denied"}
            },
            {
              "traceId": "5b8efff798038103d269b633813fc60c",
              "spanId": "eee19b7ec3c1b176",
              "name": "invoke_chat_model",
              "kind": 1,
              "startTimeUnixNano": "1761180000200000000",
              "endTimeUnixNano": "1761180000800000000",
              "attributes": [
                {"key": "gen_ai.operation.name", "value": {"stringValue": "invoke_chat_model"}},
                {"key": "gen_ai.request.model", "value": {"stringValue": "claude-sonnet-4-5"}},
                {"key": "gen_ai.usage.input_tokens", "value": {"intValue": 98}},
                {"key": "gen_ai.usage.output_tokens", "value": {"intValue": 1011}}
              ],
              "status": {"code": "STATUS_CODE_OK"}
            },
            {
              "traceId": "5b8efff798038103d269b633813fc60c",
              "spanId": "eee19b7ec3c1b177",
              "name": "GET",
              "kind": 2,
              "startTimeUnixNano": "1761180000900000000",
              "attributes": [
                {"key": "http.request.method", "value": {"stringValue": "GET"}},
                {"key": "url.full", "value": {"stringValue": "https://api.example.test/v1"}}
              ],
              "status": {}
            }
          ]
        }
      ]
    }
  ]
}`

// bench is a handler with everything wired: the built-in mapping, a token,
// and a store that keeps what it was given.
func bench(t *testing.T) (*Handler, *[]telemetry.Event) {
	t.Helper()
	s, ok := source.Find("otel", "genai")
	if !ok {
		t.Fatal("no otel/genai source")
	}
	var stored []telemetry.Event
	h := &Handler{
		Token:   func() (string, error) { return "s3cret-push-token", nil },
		Mapping: func() (source.Source, error) { return s, nil },
		Store: func(events []telemetry.Event) error {
			stored = append(stored, events...)
			return nil
		},
		Now: func() time.Time {
			return time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
		},
	}
	return h, &stored
}

func push(h http.Handler, body string) *httptest.ResponseRecorder {
	return pushFull(h, body, "application/json", "s3cret-push-token", "")
}

func pushFull(h http.Handler, body, contentType, token,
	encoding string) *httptest.ResponseRecorder {

	req := httptest.NewRequest(http.MethodPost, "/v1/traces",
		strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	return res
}

func TestASpecShapedPushBecomesEventsWithTheRightFields(t *testing.T) {
	h, stored := bench(t)
	res := push(h, agentPush)
	if res.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", res.Code, res.Body.String())
	}
	var answer exportResponse
	if err := json.Unmarshal(res.Body.Bytes(), &answer); err != nil {
		t.Fatalf("the answer is not an OTLP response: %v", err)
	}
	if answer.PartialSuccess.RejectedSpans != 0 ||
		answer.PartialSuccess.ErrorMessage != "" {
		t.Fatalf("a full success was not answered as one: %+v", answer)
	}
	if len(*stored) != 3 {
		t.Fatalf("%d event(s) stored, want the three GenAI spans", len(*stored))
	}
	agent, tool, model := (*stored)[0], (*stored)[1], (*stored)[2]

	if agent.Source != "otel/genai" {
		t.Errorf("source = %q", agent.Source)
	}
	if agent.Class != telemetry.ClassAPIActivity {
		t.Errorf("class = %v", agent.Class)
	}
	if agent.Actor.Issuer != "otel" || agent.Actor.Value != "agent-7" {
		t.Errorf("actor = %+v", agent.Actor)
	}
	if !agent.Time.Equal(time.Unix(0, 1761180000000000000)) {
		t.Errorf("time = %s", agent.Time)
	}
	if !agent.Received.Equal(time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("received = %s", agent.Received)
	}
	if agent.Disposition != telemetry.DispositionAllowed {
		t.Errorf("disposition = %v", agent.Disposition)
	}
	for field, want := range map[string]string{
		"operation": "invoke_agent", "model": "claude-sonnet-4-5",
		"tokens_in": "1520", "tokens_out": "344",
		"conversation": "conv-0192", "trace_id": "5b8efff798038103d269b633813fc60c",
		"span_id": "eee19b7ec3c1b174", "span_name": "invoke_agent",
		"agent_name": "refunder", "system": "anthropic",
		"service": "billing-agent", "duration_ms": "2123",
		"status": "ok",
	} {
		if agent.Raw[field] != want {
			t.Errorf("agent raw %s = %q, want %q", field, agent.Raw[field], want)
		}
	}

	// The failed tool call: the span's error status is the event's failure,
	// and it is worth more attention than a completed one by default.
	if tool.Raw["tool"] != "filesystem.write" {
		t.Errorf("tool = %q", tool.Raw["tool"])
	}
	if tool.Disposition != telemetry.DispositionFailed {
		t.Errorf("an errored span read as %v", tool.Disposition)
	}
	if tool.Severity != telemetry.SeverityMedium {
		t.Errorf("a failed tool call's severity = %v", tool.Severity)
	}

	// The model span carries no agent id of its own: the emitting service is
	// the identity, which is a process rather than nobody. Its tokens also
	// arrive as plain JSON numbers, and stay exact integers.
	if model.Actor.Value != "billing-agent" {
		t.Errorf("actor = %+v, want the service that emitted the span",
			model.Actor)
	}
	if model.Raw["tokens_out"] != "1011" {
		t.Errorf("tokens_out = %q", model.Raw["tokens_out"])
	}
	if model.Target.Value != "claude-sonnet-4-5" {
		t.Errorf("target = %+v", model.Target)
	}

	if st := h.Status(); st.Spans != 4 || st.GenAI != 3 || st.Ignored != 1 ||
		st.Stored != 3 {
		t.Errorf("status = %+v", st)
	}
}

// TestPromptContentIsNeverStored is the rule this endpoint exists under.
func TestPromptContentIsNeverStored(t *testing.T) {
	h, stored := bench(t)
	body := `{
      "resourceSpans": [{
        "resource": {"attributes": [
          {"key": "service.name", "value": {"stringValue": "billing-agent"}}]},
        "scopeSpans": [{"spans": [{
          "traceId": "c1", "spanId": "s1", "name": "invoke_chat_model",
          "startTimeUnixNano": "1761180000000000000",
          "endTimeUnixNano": "1761180001000000000",
          "attributes": [
            {"key": "gen_ai.operation.name", "value": {"stringValue": "invoke_chat_model"}},
            {"key": "gen_ai.prompt", "value": {"stringValue": "IGNORE-ME: the api key is hunter2 and the plan is to exfiltrate"}},
            {"key": "gen_ai.completion", "value": {"stringValue": "IGNORE-ME TOO: here is the customer list"}}
          ],
          "events": [
            {"name": "gen_ai.content.prompt", "timeUnixNano": "1761180000000000000",
             "attributes": [{"key": "gen_ai.prompt", "value": {"stringValue": "IGNORE-ME-EVENT"}}]},
            {"name": "gen_ai.user.message", "timeUnixNano": "1761180000000000000",
             "attributes": [{"key": "gen_ai.message", "value": {"stringValue": "IGNORE-ME-MESSAGE"}}]}
          ],
          "status": {}
        }]}]
      }]}`
	res := push(h, body)
	if res.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", res.Code, res.Body.String())
	}
	if len(*stored) != 1 {
		t.Fatalf("%d event(s)", len(*stored))
	}
	e := (*stored)[0]
	// What survives where the content was: presence and length, nothing
	// else. The lengths are of the two span attributes and the two events'
	// attribute values, counted as read.
	if e.Raw["prompt_bytes"] != fmt.Sprint(len(
		"IGNORE-ME: the api key is hunter2 and the plan is to exfiltrate")) {
		t.Errorf("prompt_bytes = %q", e.Raw["prompt_bytes"])
	}
	if e.Raw["completion_bytes"] != fmt.Sprint(len("IGNORE-ME TOO: here is the customer list")) {
		t.Errorf("completion_bytes = %q", e.Raw["completion_bytes"])
	}
	if e.Raw["content_events"] != "2" {
		t.Errorf("content_events = %q", e.Raw["content_events"])
	}
	if e.Raw["content_bytes"] != fmt.Sprint(len("IGNORE-ME-EVENT")+len("IGNORE-ME-MESSAGE")) {
		t.Errorf("content_bytes = %q", e.Raw["content_bytes"])
	}
	// And the content itself, nowhere: not in Raw, not in the message, not
	// anywhere in the stored event as written.
	all, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"IGNORE-ME", "hunter2", "customer list"} {
		if strings.Contains(string(all), forbidden) {
			t.Errorf("the stored event carries %q: %s", forbidden, all)
		}
	}
}

func TestAnUnauthenticatedPushIsRefused(t *testing.T) {
	h, stored := bench(t)
	for name, req := range map[string]func() *httptest.ResponseRecorder{
		"no header": func() *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodPost, "/v1/traces",
				strings.NewReader(agentPush))
			r.Header.Set("Content-Type", "application/json")
			res := httptest.NewRecorder()
			h.ServeHTTP(res, r)
			return res
		},
		"the wrong token": func() *httptest.ResponseRecorder {
			return pushFull(h, agentPush, "application/json", "wrong", "")
		},
		"a token with padding": func() *httptest.ResponseRecorder {
			return pushFull(h, agentPush, "application/json",
				"s3cret-push-token extra", "")
		},
	} {
		res := req()
		if res.Code != http.StatusUnauthorized {
			t.Errorf("%s: answered %d", name, res.Code)
		}
		var answer rpcStatus
		if err := json.Unmarshal(res.Body.Bytes(), &answer); err != nil ||
			answer.Code != codeUnauthenticated {
			t.Errorf("%s: the body is not an UNAUTHENTICATED rpc status: %s",
				name, res.Body.String())
		}
	}
	if len(*stored) != 0 {
		t.Fatalf("%d event(s) stored for pushes that did not prove themselves",
			len(*stored))
	}
	if st := h.Status(); st.Refused != 3 {
		t.Errorf("refused = %d", st.Refused)
	}

	// An endpoint with no credential made refuses everything rather than
	// accepting everything: an open telemetry endpoint is a write primitive
	// for the event store.
	h.Token = func() (string, error) { return "", nil }
	if res := push(h, agentPush); res.Code != http.StatusServiceUnavailable {
		t.Errorf("an endpoint with no credential answered %d", res.Code)
	}
	if len(*stored) != 0 {
		t.Errorf("%d event(s) stored with nobody having made a credential",
			len(*stored))
	}
}

func TestAMalformedBodyIsRefusedAndNothingIsStored(t *testing.T) {
	h, stored := bench(t)
	for name, body := range map[string]string{
		"not JSON":        `{"resourceSpans": `,
		"an array":        `[1, 2, 3]`,
		"the wrong shape": `{"resourceLogs": []}`,
	} {
		res := push(h, body)
		if res.Code != http.StatusBadRequest {
			t.Errorf("%s: answered %d", name, res.Code)
		}
		var answer rpcStatus
		if err := json.Unmarshal(res.Body.Bytes(), &answer); err != nil ||
			answer.Code != codeInvalid {
			t.Errorf("%s: the body is not an INVALID_ARGUMENT rpc status: %s",
				name, res.Body.String())
		}
	}
	if len(*stored) != 0 {
		t.Fatalf("%d event(s) stored from bodies that did not parse",
			len(*stored))
	}
}

// TestADuplicateSpanIsTakenOnce is the idempotency choice, stated as a
// behaviour: the span id is the unit. The exporter's retry and a collector's
// duplicate both land as one event, and the answer is a full success — the
// exporter did its job — with the duplicate counted where a person can see
// it.
func TestADuplicateSpanIsTakenOnce(t *testing.T) {
	h, stored := bench(t)
	one := `{"resourceSpans": [{"resource": {"attributes": [
		{"key": "service.name", "value": {"stringValue": "billing-agent"}}]},
		"scopeSpans": [{"spans": [{
			"traceId": "t1", "spanId": "sp1", "name": "invoke_agent",
			"startTimeUnixNano": "1761180000000000000",
			"attributes": [
				{"key": "gen_ai.operation.name", "value": {"stringValue": "invoke_agent"}}],
			"status": {}}]}]}]}`
	for range 2 {
		if res := push(h, one); res.Code != http.StatusOK {
			t.Fatalf("answered %d: %s", res.Code, res.Body.String())
		}
	}
	if len(*stored) != 1 {
		t.Fatalf("%d event(s) for one span sent twice", len(*stored))
	}
	if st := h.Status(); st.Duplicates != 1 || st.Stored != 1 {
		t.Errorf("status = %+v", st)
	}

	// And twice in one request, which is the same thing nearer together.
	h2, stored2 := bench(t)
	twice := strings.Replace(one, `"scopeSpans": [{"spans": [{`,
		`"scopeSpans": [{"spans": [{`, 1)
	twice = strings.Replace(twice, `"status": {}}]}]}]}`,
		`"status": {}}, {"traceId": "t1", "spanId": "sp1", "name": "invoke_agent",
		  "startTimeUnixNano": "1761180000000000000",
		  "attributes": [{"key": "gen_ai.operation.name", "value": {"stringValue": "invoke_agent"}}],
		  "status": {}}]}]}]}`, 1)
	if err := json.Unmarshal([]byte(twice), &exportRequest{}); err != nil {
		t.Fatalf("the fixture is not JSON: %v", err)
	}
	if res := push(h2, twice); res.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", res.Code, res.Body.String())
	}
	if len(*stored2) != 1 {
		t.Fatalf("%d event(s) for one span sent twice in one request",
			len(*stored2))
	}
	if st := h2.Status(); st.Duplicates != 1 {
		t.Errorf("status = %+v", st)
	}
}

// TestAStoreFailureDoesNotSwallowTheRetry.
//
// The ids are remembered only once the store has taken the batch, so the
// exporter told to send it again is not answered with "duplicate" for spans
// that were never stored.
func TestAStoreFailureDoesNotSwallowTheRetry(t *testing.T) {
	h, stored := bench(t)
	failing := true
	h.Store = func(events []telemetry.Event) error {
		if failing {
			return fmt.Errorf("the disk is on fire")
		}
		*stored = append(*stored, events...)
		return nil
	}
	if res := push(h, agentPush); res.Code != http.StatusServiceUnavailable {
		t.Fatalf("a failed store answered %d", res.Code)
	}
	if len(*stored) != 0 {
		t.Fatalf("%d event(s) stored anyway", len(*stored))
	}
	failing = false
	if res := push(h, agentPush); res.Code != http.StatusOK {
		t.Fatalf("the retry answered %d: %s", res.Code, res.Body.String())
	}
	if len(*stored) != 3 {
		t.Fatalf("%d event(s) on the retry; the failed attempt's spans were "+
			"remembered as stored", len(*stored))
	}
}

func TestNonGenAISpansAreIgnoredNotRejected(t *testing.T) {
	h, stored := bench(t)
	body := `{"resourceSpans": [{"resource": {"attributes": [
		{"key": "service.name", "value": {"stringValue": "web"}}]},
		"scopeSpans": [{"spans": [{
			"traceId": "t2", "spanId": "s2", "name": "GET /health",
			"startTimeUnixNano": "1761180000000000000",
			"attributes": [{"key": "http.request.method", "value": {"stringValue": "GET"}}],
			"status": {}}]}]}]}`
	res := push(h, body)
	if res.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", res.Code, res.Body.String())
	}
	// The exporter did its job; the span is not this platform's business,
	// and the protocol is not told it was rejected.
	if res.Body.String() != "{\"partialSuccess\":{}}\n" {
		t.Errorf("the answer was not a full success: %q", res.Body.String())
	}
	if len(*stored) != 0 {
		t.Errorf("%d event(s) stored from a span with no GenAI attributes",
			len(*stored))
	}
	if st := h.Status(); st.Ignored != 1 || st.Rejected != 0 {
		t.Errorf("status = %+v", st)
	}
}

func TestAGenAISpanThatCannotMapIsAPartialSuccess(t *testing.T) {
	h, stored := bench(t)
	// No agent id, no agent name, no service.name: nothing to attribute the
	// actions to, which is the one field no detection can work around.
	body := `{"resourceSpans": [{"scopeSpans": [{"spans": [{
		"traceId": "t3", "spanId": "s3", "name": "execute_tool",
		"startTimeUnixNano": "1761180000000000000",
		"attributes": [
			{"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}},
			{"key": "gen_ai.tool.name", "value": {"stringValue": "shell"}}],
		"status": {}}]}]}]}`
	res := push(h, body)
	if res.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", res.Code, res.Body.String())
	}
	var answer exportResponse
	if err := json.Unmarshal(res.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	if answer.PartialSuccess.RejectedSpans != 1 {
		t.Fatalf("rejectedSpans = %d", answer.PartialSuccess.RejectedSpans)
	}
	if !strings.Contains(answer.PartialSuccess.ErrorMessage, "agent") {
		t.Errorf("the error does not name the field: %q",
			answer.PartialSuccess.ErrorMessage)
	}
	if len(*stored) != 0 {
		t.Errorf("%d event(s) stored from a span that did not map", len(*stored))
	}

	// A span with no start time is the same refusal: an event with no time
	// cannot be windowed, and guessing one moves every event.
	h2, stored2 := bench(t)
	notime := strings.Replace(body, `"startTimeUnixNano": "1761180000000000000",`, "", 1)
	res = push(h2, notime)
	if res.Code != http.StatusOK {
		t.Fatalf("answered %d", res.Code)
	}
	if err := json.Unmarshal(res.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	if answer.PartialSuccess.RejectedSpans != 1 ||
		!strings.Contains(answer.PartialSuccess.ErrorMessage, "time") {
		t.Errorf("a span with no time: %+v", answer.PartialSuccess)
	}
	if len(*stored2) != 0 {
		t.Errorf("%d event(s) stored without a time", len(*stored2))
	}
}

func TestProtobufAndOtherEncodingsAreRefusedByName(t *testing.T) {
	h, _ := bench(t)
	res := pushFull(h, agentPush, "application/x-protobuf", "s3cret-push-token", "")
	if res.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("a protobuf body answered %d", res.Code)
	}
	if !strings.Contains(res.Body.String(), "protobuf") {
		t.Errorf("the refusal does not say why: %s", res.Body.String())
	}

	res = pushFull(h, agentPush, "application/json", "s3cret-push-token", "zstd")
	if res.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("a zstd body answered %d", res.Code)
	}

	// A content type with a charset parameter is still application/json.
	res = pushFull(h, agentPush, "application/json; charset=utf-8",
		"s3cret-push-token", "")
	if res.Code != http.StatusOK {
		t.Errorf("a charset parameter was refused: %d", res.Code)
	}
}

// TestGzipBodiesAreRead: the specification says receivers support gzip, and
// collectors send it by default.
func TestGzipBodiesAreRead(t *testing.T) {
	h, stored := bench(t)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(agentPush)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/traces", &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer s3cret-push-token")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", res.Code, res.Body.String())
	}
	if len(*stored) != 3 {
		t.Fatalf("%d event(s) from a gzip body", len(*stored))
	}
}

func TestTheEndpointAnswersInTheProtocolShapes(t *testing.T) {
	h, _ := bench(t)
	// A GET is not an export and is told so in the protocol's own failure
	// shape rather than a bare page.
	req := httptest.NewRequest(http.MethodGet, "/v1/traces", nil)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("a GET answered %d", res.Code)
	}
	var answer rpcStatus
	if err := json.Unmarshal(res.Body.Bytes(), &answer); err != nil ||
		answer.Code != codeUnimplemented {
		t.Errorf("the body is not an rpc status: %s", res.Body.String())
	}

	// The rate limit protects the endpoint the way it protects a feed.
	h.Limit = 1
	if res := push(h, agentPush); res.Code != http.StatusOK {
		t.Fatalf("the first push answered %d", res.Code)
	}
	res = push(h, agentPush)
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("the second push in a minute answered %d", res.Code)
	}
	if res.Header().Get("Retry-After") == "" {
		t.Error("a 429 with no Retry-After")
	}
}

// TestAStoredSpanIsRememberedForADay: the horizon, so the map is bounded by
// a day of spans rather than by the process's life.
func TestAStoredSpanIsRememberedForADay(t *testing.T) {
	h, stored := bench(t)
	clock := time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	h.Now = func() time.Time { return clock }
	one := `{"resourceSpans": [{"resource": {"attributes": [
		{"key": "service.name", "value": {"stringValue": "billing-agent"}}]},
		"scopeSpans": [{"spans": [{
			"traceId": "t9", "spanId": "s9", "name": "invoke_agent",
			"startTimeUnixNano": "1761180000000000000",
			"attributes": [{"key": "gen_ai.operation.name", "value": {"stringValue": "invoke_agent"}}],
			"status": {}}]}]}]}`
	if res := push(h, one); res.Code != http.StatusOK {
		t.Fatalf("answered %d", res.Code)
	}
	if res := push(h, one); res.Code != http.StatusOK || h.Status().Duplicates != 1 {
		t.Fatal("a span id inside the window was taken twice")
	}
	clock = clock.Add(keepWindow + time.Minute)
	if res := push(h, one); res.Code != http.StatusOK {
		t.Fatalf("answered %d", res.Code)
	}
	if len(*stored) != 2 {
		t.Fatalf("%d event(s): a span id past the horizon was still "+
			"remembered, so the map is bounded by nothing", len(*stored))
	}
}

// Pushes that fail to authenticate are not charged to the shared window:
// otherwise anybody who can reach the endpoint fills it and the exporters
// it exists for are answered 429.
func TestAnUnauthenticatedFloodDoesNotLockOutTheExporter(t *testing.T) {
	h, _ := bench(t)
	h.Limit = 2
	for i := 0; i < 50; i++ {
		res := pushFull(h, agentPush, "application/json", "not-the-token", "")
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("a push with the wrong token answered %d", res.Code)
		}
	}
	if res := push(h, agentPush); res.Code != http.StatusOK {
		t.Fatalf("after an unauthenticated flood the exporter was answered %d", res.Code)
	}
}

// The de-duplication map has a ceiling as well as a horizon.
func TestTheSeenMapIsBounded(t *testing.T) {
	h, _ := bench(t)
	at := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	ids := make([]string, 0, 4096)
	for i := 0; i < maxSeen/4096+2; i++ {
		ids = ids[:0]
		for j := 0; j < 4096; j++ {
			ids = append(ids, fmt.Sprintf("%d-%d", i, j))
		}
		h.remember(ids, at)
		if len(h.seen) > maxSeen {
			t.Fatalf("the map holds %d ids, past its ceiling of %d", len(h.seen), maxSeen)
		}
	}
}
