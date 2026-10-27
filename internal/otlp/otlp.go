// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

// Package otlp reads the traces an AI agent's telemetry pipeline pushes, in
// OpenTelemetry's HTTP/JSON protocol, and keeps from them exactly what a
// security platform has any business keeping.
//
// # Why OTLP, and why only its JSON mapping
//
// The agents this platform is built to watch already speak OpenTelemetry:
// every harness and gateway either exports OTLP natively or stands in front
// of something that does, and the GenAI semantic conventions
// (gen_ai.operation.name, gen_ai.agent.id, gen_ai.usage.*) name the fields
// the whole industry converged on. Accepting the protocol at /v1/traces
// means a deployment points its collector at this program and is done — no
// agent-side code, which matters because the one thing an agent must not be
// trusted to report is its own behaviour.
//
// The OTLP protocol defines a protobuf mapping and a JSON mapping of the
// same messages; this program carries no dependencies and no protobuf
// runtime, so it implements the JSON one — the mapping the specification
// says receivers SHOULD support, and what every collector sends when
// configured with application/json. A protobuf body is refused with 415 and
// a sentence saying why, rather than half-parsed.
//
// # The rule that shapes everything here
//
// A GenAI span can carry the content of the prompts and completions it
// measured — gen_ai.prompt, gen_ai.completion, and the gen_ai.content.*
// span events. That is attacker-influenced text (a prompt is written by
// whoever talks to the agent, which includes whoever is attacking it), and
// the event model already treats message text as hostile. So content never
// crosses this boundary: it is dropped as the body is parsed, and only two
// things survive where it was — whether it was present, and how many bytes
// it was. A detection can ask "did this session's prompts suddenly grow ten
// times", which is the security question; it cannot ask for the prompt,
// which is somebody's data.
//
// # What answers look like
//
// OTLP senders understand exactly two success shapes: a full success, and a
// partial success naming how many spans were rejected and why. This
// endpoint answers in those shapes only — a span that carried no GenAI
// attributes is not a rejection (the exporter did its job; the span is
// simply not this platform's business) and is counted internally rather
// than invented into the response, while a GenAI span that could not be
// mapped is a rejection with the field that failed named in the error
// message. Failures answer with the google.rpc.Status JSON shape the
// protocol's HTTP specification uses, and nothing is stored for a request
// that did not parse.
package otlp

import (
	"time"
)

// SecretName is the credential a push must carry, in the store's sealed
// credentials.
//
// "inbound-" because that is the family this endpoint belongs to (a feed's
// secret is inbound-NAME), and "otlp" rather than "otlp-traces" because
// there is one credential for the one protocol surface, not one per signal.
// An operator makes it with:
//
//	VAIGIL_CONNECT_SECRET=… vaigil connect secret inbound-otlp
//
// and it is checked the way every push credential here is: a static token
// in the Authorization header, compared through a digest in constant time,
// never stored in the clear.
const SecretName = "inbound-otlp"

// Status is what the endpoint has done. Process-local, deliberately: the
// feeds keep their counters in the store because a person reads them from a
// screen, and this surface has no screen yet; a number that exists only to
// be tested is still worth having, and worth saying where it lives.
type Status struct {
	Deliveries int `json:"deliveries"`
	Spans      int `json:"spans"`
	GenAI      int `json:"genai"`
	// Ignored counts spans with no GenAI attributes: accepted, counted,
	// nothing kept. Not a rejection — the exporter did its job — and not
	// silently zero either, because a collector that never sends a GenAI
	// span is a deployment worth noticing.
	Ignored int `json:"ignored"`
	Stored  int `json:"stored"`
	// Duplicates counts span ids a repeat delivery carried. The exporter's
	// own retry semantics make these ordinary, not hostile.
	Duplicates int       `json:"duplicates"`
	Rejected   int       `json:"rejected"`
	Refused    int       `json:"refused"`
	LastRefuse time.Time `json:"last_refuse,omitempty"`
	Why        string    `json:"why,omitempty"`
	LastAt     time.Time `json:"last_at,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// keepWindow is how long a span id is remembered. A day, the same horizon
// the feeds keep delivery ids for.
const keepWindow = 24 * time.Hour
