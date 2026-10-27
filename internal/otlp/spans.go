// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The OTLP/HTTP JSON mapping of ExportTraceServiceRequest: resourceSpans,
// each holding one resource's attributes and the spans of its scopes. Field
// names are the protocol's own camelCase; every count is a 64-bit integer
// carried as a JSON string, which json.Number keeps exactly rather than
// rounding through a float the way a plain number would be.
type exportRequest struct {
	ResourceSpans []resourceSpans `json:"resourceSpans"`
}

type resourceSpans struct {
	Resource *resource `json:"resource"`
	// ScopeSpans is the current name. LegacySpans catches the
	// instrumentationLibrarySpans spelling SDKs before 1.x wrote, so a
	// deployment with an older pipeline is read rather than mystifyingly
	// empty.
	ScopeSpans  []scopeSpans `json:"scopeSpans"`
	LegacySpans []scopeSpans `json:"instrumentationLibrarySpans"`
}

type resource struct {
	Attributes []attribute `json:"attributes"`
}

type scopeSpans struct {
	Spans []span `json:"spans"`
}

type span struct {
	TraceID           string      `json:"traceId"`
	SpanID            string      `json:"spanId"`
	Name              string      `json:"name"`
	StartTimeUnixNano json.Number `json:"startTimeUnixNano"`
	EndTimeUnixNano   json.Number `json:"endTimeUnixNano"`
	Status            *spanStatus `json:"status"`
	Attributes        []attribute `json:"attributes"`
	Events            []spanEvent `json:"events"`
}

// spanStatus carries a code the protocol renders either as its number or as
// its enum name, so both are taken.
type spanStatus struct {
	Code    json.RawMessage `json:"code"`
	Message string          `json:"message"`
}

type spanEvent struct {
	Name       string      `json:"name"`
	Attributes []attribute `json:"attributes"`
}

type attribute struct {
	Key   string     `json:"key"`
	Value *attrValue `json:"value"`
}

// attrValue is one of the protocol's typed values. Bytes, arrays and
// maps are not modelled because nothing here has a reason to read them:
// the only array-valued GenAI attribute a span carries is message content,
// and that is counted, never read.
type attrValue struct {
	StringValue *string     `json:"stringValue"`
	BoolValue   *bool       `json:"boolValue"`
	IntValue    json.Number `json:"intValue"`
	DoubleValue json.Number `json:"doubleValue"`
}

// text renders an attribute the way a mapping compares it: a number in its
// shortest exact form, so 128 tokens is "128" and not "1.28e+02".
func (v *attrValue) text() string {
	if v == nil {
		return ""
	}
	switch {
	case v.StringValue != nil:
		return *v.StringValue
	case v.IntValue != "":
		return v.IntValue.String()
	case v.DoubleValue != "":
		return v.DoubleValue.String()
	case v.BoolValue != nil:
		return strconv.FormatBool(*v.BoolValue)
	}
	return ""
}

// status reads a span's outcome. Unset (0) and Ok (1) are the ordinary
// paths; Error (2) is a call that did not complete. A span with no status
// at all is unset, which is the protocol's default and not a hole.
func (s *span) status() string {
	if s.Status == nil || len(s.Status.Code) == 0 {
		return "ok"
	}
	raw := strings.Trim(string(s.Status.Code), `"`)
	if n, err := strconv.Atoi(raw); err == nil {
		if n == 2 {
			return "error"
		}
		return "ok"
	}
	if strings.Contains(strings.ToUpper(raw), "ERROR") {
		return "error"
	}
	return "ok"
}

// genaiPrefix marks the semantic conventions this endpoint exists to read.
const genaiPrefix = "gen_ai."

// The closed fields a detection needs, lifted out of the attribute soup.
// Anything not named here is dropped with the rest of the span; anything
// that is content is dropped harder — measured, not kept (see the package
// comment).
const (
	attrOperation    = "gen_ai.operation.name"
	attrAgentID      = "gen_ai.agent.id"
	attrAgentName    = "gen_ai.agent.name"
	attrRequestModel = "gen_ai.request.model"
	attrRespModel    = "gen_ai.response.model"
	attrInputTokens  = "gen_ai.usage.input_tokens"
	attrOutputTokens = "gen_ai.usage.output_tokens"
	attrConversation = "gen_ai.conversation.id"
	attrToolName     = "gen_ai.tool.name"
	attrSystem       = "gen_ai.system"
	attrPrompt       = "gen_ai.prompt"
	attrCompletion   = "gen_ai.completion"
	attrServiceName  = "service.name"
)

// record flattens one span into the fields the otel/genai mapping reads,
// and reports whether the span is this endpoint's business at all.
//
// The second return is false for a span with no GenAI attribute: not an
// error and not a rejection — the exporter delivered what it measured and
// none of it names an agent, a model or a tool.
func record(rs *resourceSpans, sp *span) (map[string]any, bool) {
	attrs := map[string]string{}
	for _, a := range sp.Attributes {
		attrs[a.Key] = a.Value.text()
	}
	genai := false
	for k := range attrs {
		if strings.HasPrefix(k, genaiPrefix) {
			genai = true
			break
		}
	}
	// Content lengths, taken before anything else so the values themselves
	// are never copied into the record. Measured in bytes as read; a prompt
	// that never crossed this boundary has no length to report.
	promptBytes, completionBytes := 0, 0
	if v, ok := attrs[attrPrompt]; ok {
		promptBytes = len(v)
		delete(attrs, attrPrompt)
	}
	if v, ok := attrs[attrCompletion]; ok {
		completionBytes = len(v)
		delete(attrs, attrCompletion)
	}
	// Span events named for GenAI content (gen_ai.content.prompt,
	// gen_ai.user.message, gen_ai.assistant.message, …) are counted and
	// measured, never read: their attributes are message bodies and roles.
	contentEvents, contentBytes := 0, 0
	for _, ev := range sp.Events {
		if !strings.HasPrefix(ev.Name, genaiPrefix) {
			continue
		}
		contentEvents++
		for _, a := range ev.Attributes {
			contentBytes += len(a.Value.text())
		}
	}
	var service string
	if rs.Resource != nil {
		for _, a := range rs.Resource.Attributes {
			if a.Key == attrServiceName {
				service = a.Value.text()
			}
		}
	}
	if !genai {
		return nil, false
	}

	// The agent identity, in order of what it is worth: the id the
	// platform gave the agent, its name, and failing both the service that
	// emitted the span — which is a process rather than an agent, and
	// better than attributing the actions to nobody.
	agent := attrs[attrAgentID]
	if agent == "" {
		agent = attrs[attrAgentName]
	}
	if agent == "" {
		agent = service
	}
	operation := attrs[attrOperation]
	if operation == "" {
		// The span's own name is the operation the conventions put there:
		// invoke_agent, execute_tool, invoke_chat_model.
		operation = sp.Name
	}
	model := attrs[attrRequestModel]
	if model == "" {
		model = attrs[attrRespModel]
	}

	// Every value is a string, because the mapping's paths read through a
	// comparer that renders an int as nothing — a count that arrives as a
	// number would vanish the same way.
	out := map[string]any{
		"operation":        operation,
		"trace_id":         sp.TraceID,
		"span_id":          sp.SpanID,
		"span_name":        sp.Name,
		"status":           sp.status(),
		"prompt_bytes":     strconv.Itoa(promptBytes),
		"completion_bytes": strconv.Itoa(completionBytes),
		"content_events":   strconv.Itoa(contentEvents),
		"content_bytes":    strconv.Itoa(contentBytes),
	}
	// nanos parses the protocol's string-of-digits (or, from a lax sender,
	// number) into the time the span started, which is the event's time:
	// not arrival, and not now.
	if n, err := sp.StartTimeUnixNano.Int64(); err == nil && n > 0 {
		out["time"] = time.Unix(0, n).UTC().Format(time.RFC3339Nano)
	}
	if agent != "" {
		out["agent"] = agent
	}
	if attrs[attrAgentName] != "" {
		out["agent_name"] = attrs[attrAgentName]
	}
	if model != "" {
		out["model"] = model
	}
	if attrs[attrToolName] != "" {
		out["tool"] = attrs[attrToolName]
	}
	if attrs[attrInputTokens] != "" {
		out["tokens_in"] = attrs[attrInputTokens]
	}
	if attrs[attrOutputTokens] != "" {
		out["tokens_out"] = attrs[attrOutputTokens]
	}
	if attrs[attrConversation] != "" {
		out["conversation"] = attrs[attrConversation]
	}
	if attrs[attrSystem] != "" {
		out["system"] = attrs[attrSystem]
	}
	if service != "" {
		out["service"] = service
	}
	if start, err := sp.StartTimeUnixNano.Int64(); err == nil && start > 0 {
		if end, err := sp.EndTimeUnixNano.Int64(); err == nil && end >= start {
			out["duration_ms"] = strconv.FormatInt((end-start)/1_000_000, 10)
		}
	}
	return out, true
}

// walks every span in a request with the resource it belongs to.
func (r exportRequest) each(fn func(rs *resourceSpans, sp *span)) {
	for _, rs := range r.ResourceSpans {
		rs := rs
		for _, group := range [][]scopeSpans{rs.ScopeSpans, rs.LegacySpans} {
			for i := range group {
				for j := range group[i].Spans {
					fn(&rs, &group[i].Spans[j])
				}
			}
		}
	}
}

// parse decodes one request body.
//
// A body carrying none of the traces request's own keys is refused rather
// than read as an empty export: a deployment that points its logs or
// metrics exporter at /v1/traces would otherwise succeed quietly forever,
// which is the empty-estate failure this codebase treats as the worst
// outcome a reader can produce. A body with nothing in it at all ({}) is
// accepted — collectors send empty batches to keep a connection warm.
func parse(body []byte) (exportRequest, error) {
	var req exportRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return req, fmt.Errorf("the body is not OTLP/JSON: %w", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return req, fmt.Errorf("the body is not OTLP/JSON: %w", err)
	}
	_, spans := top["resourceSpans"]
	known := len(top) == 0 || spans
	if !known {
		return req, fmt.Errorf(
			"the body names none of a traces export's own fields. This " +
				"endpoint reads resourceSpans; an exporter pointed here " +
				"with another signal's body would succeed quietly and " +
				"nothing would arrive")
	}
	return req, nil
}
