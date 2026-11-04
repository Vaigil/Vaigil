// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The two AI-stack audit connectors, read against the responses their
// vendors document. The shapes are hand-composed from the documented field
// lists: OpenAI's from the openai-python admin types generated from its
// OpenAPI spec (src/openai/types/admin/organization/audit_log_list_response.py,
// where a type-specific payload sits under a key that is the event type
// itself, dots included), Anthropic's from its Compliance API reference
// (platform.claude.com/docs/en/api/compliance/activities/list).

// TestOpenAIAgainstItsDocumentedResponses.
func TestOpenAIAgainstItsDocumentedResponses(t *testing.T) {
	m, err := entry(t, "openai").For("openai")
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	var auth string
	page1 := `{
 "object": "list",
 "data": [
  {
   "id": "audit_log-1",
   "type": "login.succeeded",
   "effective_at": 1711040400,
   "actor": {
    "type": "session",
    "session": {
     "user": {
      "id": "user-77",
      "email": "ada@acme.test"
     },
     "ip_address": "203.0.113.9"
    }
   }
  },
  {
   "id": "audit_log-2",
   "type": "api_key.created",
   "effective_at": 1711040500,
   "actor": {
    "type": "session",
    "session": {
     "user": {
      "id": "user-77",
      "email": "ada@acme.test"
     },
     "ip_address": "203.0.113.9"
    }
   },
   "project": {
    "id": "proj_1",
    "name": "Refunds"
   },
   "api_key.created": {
    "id": "key-A1",
    "data": {
     "scopes": [
      "api.model.request"
     ]
    }
   }
  },
  {
   "id": "audit_log-3",
   "type": "invite.sent",
   "effective_at": 1711040600,
   "actor": {
    "type": "api_key",
    "api_key": {
     "id": "key-A1",
     "type": "user",
     "user": {
      "id": "user-78",
      "email": "bo@acme.test"
     }
    }
   },
   "invite.sent": {
    "id": "inv-9",
    "data": {
     "email": "eve@example.test",
     "role": "member"
    }
   }
  },
  {
   "id": "audit_log-4",
   "type": "login.failed",
   "effective_at": 1711040700,
   "actor": {
    "type": "session",
    "session": {
     "user": {
      "id": "user-99",
      "email": "mallory@acme.test"
     },
     "ip_address": "198.51.100.7"
    }
   },
   "login.failed": {
    "error_code": "invalid_credentials",
    "error_message": "Invalid username or password"
   }
  }
 ],
 "first_id": "audit_log-1",
 "last_id": "audit_log-4",
 "has_more": true
}`
	page2 := `{
 "object": "list",
 "data": [
  {
   "id": "audit_log-5",
   "type": "role.assignment.created",
   "effective_at": 1711040800,
   "actor": {
    "type": "session",
    "session": {
     "user": {
      "id": "user-77",
      "email": "ada@acme.test"
     },
     "ip_address": "203.0.113.9"
    }
   },
   "role.assignment.created": {
    "id": "ra-1",
    "principal_id": "user-78",
    "principal_type": "user",
    "resource_id": "proj_1",
    "resource_type": "project"
   }
  }
 ],
 "first_id": "audit_log-5",
 "last_id": "audit_log-5",
 "has_more": false
}`
	var calls int
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		seen = append(seen, r.URL.Path+"?"+r.URL.RawQuery)
		if calls == 0 {
			calls++
			w.Write([]byte(page1))
			return
		}
		w.Write([]byte(page2))
	})
	c := route(t, map[string]*httptest.Server{"api.openai.com": srv})
	out, err := Run(context.Background(), m, "audit", c,
		MapFunc{"openai-audit-token": "sk-admin-1"}, State{}, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Records) != 5 {
		t.Fatalf("%d records over two pages", len(out.Records))
	}
	want(t, out.Records[0], map[string]string{
		"id": "audit_log-1", "type": "login.succeeded",
		"effective_at":             "1711040400",
		"actor.session.user.id":    "user-77",
		"actor.session.user.email": "ada@acme.test",
		"actor.session.ip_address": "203.0.113.9"})
	// The type-specific payload under a key with dots in it, reached through
	// the escaped path and nothing else.
	want(t, out.Records[1], map[string]string{"created_key": "key-A1",
		"project": "proj_1", "project_name": "Refunds"})
	want(t, out.Records[2], map[string]string{"invite_email": "eve@example.test",
		"invite_role": "member", "acting_key": "key-A1",
		"key_owner": "user-78", "key_owner_email": "bo@acme.test"})
	want(t, out.Records[3], map[string]string{"login_error": "invalid_credentials"})
	want(t, out.Records[4], map[string]string{"role_principal": "user-78",
		"role_resource": "proj_1"})
	for k, v := range out.Records[1] {
		if strings.Contains(v, "scopes") || strings.Contains(v, "api.model.request") {
			t.Errorf("%s holds a field the connector never declared: %q", k, v)
		}
	}
	// The bearer credential, and the cursor OpenAI documents: the page's
	// last_id back as after.
	if auth != "Bearer sk-admin-1" {
		t.Errorf("Authorization was %q", auth)
	}
	if len(seen) != 2 || !strings.Contains(seen[1], "after=audit_log-4") {
		t.Errorf("the pages asked for were %v", seen)
	}
	if !strings.Contains(seen[0], "limit=100") {
		t.Errorf("the page size was not asked for: %s", seen[0])
	}
	// The watermark is the highest effective_at of the run, in the seconds
	// OpenAI wrote them.
	if out.Watermark != "1711040800" {
		t.Errorf("watermark = %q", out.Watermark)
	}
}

// TestAnthropicAgainstItsDocumentedResponses.
func TestAnthropicAgainstItsDocumentedResponses(t *testing.T) {
	m, err := entry(t, "anthropic").For("anthropic")
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	var key, version string
	body := `{"data":[
		{"id":"activity_01A","created_at":"2026-04-10T08:09:10.123456Z",
		 "organization_id":null,"organization_uuid":null,
		 "actor":{"type":"unauthenticated_user_actor",
		 "unauthenticated_email_address":"mallory@acme.test",
		 "ip_address":"198.51.100.7","user_agent":"Mozilla/5.0"},
		 "type":"sso_login_failed","auth_method":"sso","mfa_method":"not_used"},
		{"id":"activity_01B","created_at":"2026-04-10T08:10:00Z",
		 "organization_id":"org_01Wv","organization_uuid":"abcdef01-2345-6789-abcd-ef0123456789",
		 "actor":{"type":"admin_api_key_actor","admin_api_key_id":"adminkey-1",
		 "ip_address":"192.0.2.35","user_agent":"aeroprove-connector/1"},
		 "type":"claude_user_role_updated","user_id":"user_01C",
		 "user_email":"bo@acme.test","current_role":"admin","previous_role":"member"},
		{"id":"activity_01C","created_at":"2026-04-10T08:11:00Z",
		 "organization_id":"org_01Wv",
		 "actor":{"type":"user_actor","email_address":"ada@acme.test",
		 "user_id":"user_01A","ip_address":"192.0.2.34","user_agent":"Mozilla/5.0"},
		 "type":"api_key_created","api_key_id":"key-B2"}
		],"has_more":false,"first_id":"activity_01A","last_id":"activity_01C"}`
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		key, version = r.Header.Get("x-api-key"),
			r.Header.Get("anthropic-version")
		seen = append(seen, r.URL.Path+"?"+r.URL.RawQuery)
		w.Write([]byte(body))
	})
	c := route(t, map[string]*httptest.Server{"api.anthropic.com": srv})
	out, err := Run(context.Background(), m, "audit", c,
		MapFunc{"anthropic-compliance-key": "sk-ant-api01-x"}, State{}, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Records) != 3 {
		t.Fatalf("%d records", len(out.Records))
	}
	want(t, out.Records[0], map[string]string{
		"id": "activity_01A", "type": "sso_login_failed",
		"created_at":            "2026-04-10T08:09:10.123456Z",
		"unauthenticated_email": "mallory@acme.test",
		"actor.ip_address":      "198.51.100.7", "auth_method": "sso"})
	want(t, out.Records[1], map[string]string{
		"actor_kind": "admin_api_key_actor", "acting_admin_key": "adminkey-1",
		"target_user": "user_01C", "target_user_email": "bo@acme.test",
		"role_now": "admin", "role_was": "member",
		"organization_id": "org_01Wv"})
	want(t, out.Records[2], map[string]string{"api_key_id": "key-B2",
		"actor.user_id": "user_01A", "actor.email_address": "ada@acme.test"})
	if key != "sk-ant-api01-x" {
		t.Errorf("x-api-key was %q", key)
	}
	// The one constant header the API demands of every call, declared in
	// the manifest and carried on every request.
	if version != "2023-06-01" {
		t.Errorf("anthropic-version was %q", version)
	}
	if len(seen) != 1 || !strings.Contains(seen[0], "limit=100") {
		t.Errorf("asked for %v", seen)
	}
	// The newest record's created_at is the checkpoint, and it goes back in
	// the filter the API documents — not as a cursor.
	if out.Watermark != "2026-04-10T08:11:00Z" {
		t.Errorf("watermark = %q", out.Watermark)
	}
	q := m.first(m.Endpoints[0], State{Watermark: out.Watermark}).Query()
	if q.Get("created_at.gte") != "2026-04-10T08:11:00Z" {
		t.Errorf("created_at.gte = %q", q.Get("created_at.gte"))
	}
}

// TestOpenAITakesItsCheckpointBackInSeconds: effective_at is written as
// seconds and taken back as seconds, so a stored checkpoint is echoed and
// the first checkpoint a collector writes — a clock time — is converted,
// never sent as a date to a filter that takes a number.
func TestOpenAITakesItsCheckpointBackInSeconds(t *testing.T) {
	m, _ := entry(t, "openai").For("openai")
	e, _ := m.Endpoint("audit")
	at := func(mark string) url.Values {
		return m.first(e, State{Watermark: mark}).Query()
	}
	if got := at("1761180000").Get("effective_at[gte]"); got != "1761180000" {
		t.Errorf("a seconds checkpoint was sent as %q", got)
	}
	if got := at("2026-10-23T03:20:00Z").Get("effective_at[gte]"); got != "1792725600" {
		t.Errorf("a clock-time checkpoint was sent as %q, want its Unix "+
			"seconds", got)
	}
	// Anthropic's filter takes a time and gets one, unchanged.
	an, _ := entry(t, "anthropic").For("anthropic")
	ae, _ := an.Endpoint("audit")
	if got := an.first(ae, State{Watermark: "2026-04-10T08:11:00Z"}).
		Query().Get("created_at.gte"); got != "2026-04-10T08:11:00Z" {
		t.Errorf("created_at.gte = %q", got)
	}
}

// TestAConstantHeaderIsDeclaredNotSmuggled: the one way a manifest may send
// an extra header is a constant, named in the reviewable place — not a
// credential, not a second header in one value, not the two headers that
// have fields of their own.
func TestAConstantHeaderIsDeclaredNotSmuggled(t *testing.T) {
	for name, edit := range map[string]func(*Endpoint){
		"a credential": func(e *Endpoint) {
			e.Headers = map[string]string{"anthropic-version": "sk-ant-api01-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
		},
		"two in one":       func(e *Endpoint) { e.Headers = map[string]string{"anthropic-version": "2023-06-01\r\nX-Evil: 1"} },
		"an authorization": func(e *Endpoint) { e.Headers = map[string]string{"Authorization": "Bearer x"} },
		"an accept":        func(e *Endpoint) { e.Headers = map[string]string{"Accept": "text/html"} },
		"a broken name":    func(e *Endpoint) { e.Headers = map[string]string{"bad name": "1"} },
		"empty":            func(e *Endpoint) { e.Headers = map[string]string{"anthropic-version": " "} },
	} {
		m := people()
		edit(&m.Endpoints[0])
		if err := m.Validate(); err == nil {
			t.Errorf("%s was accepted as a constant header", name)
		}
	}
	m := people()
	m.Endpoints[0].Headers = map[string]string{"anthropic-version": "2023-06-01"}
	if err := m.Validate(); err != nil {
		t.Errorf("an honest constant header was refused: %v", err)
	}
	// And a watermark layout nobody knows is still refused, while the two
	// that exist are not.
	m2 := people()
	m2.Endpoints[0].WatermarkLayout = "roman"
	if m2.Validate() == nil {
		t.Error("a layout of \"roman\" was accepted")
	}
	m3 := people()
	m3.Endpoints[0].WatermarkLayout = "epoch-s"
	if err := m3.Validate(); err != nil {
		t.Errorf("epoch-s was refused: %v", err)
	}
}

// TestTheEpochSecondsWatermarkKeepsItsConversion: the seconds form of the
// milliseconds conversion GitHub already had, proved against a real page so
// the filter and the records agree on units.
func TestTheEpochSecondsWatermarkKeepsItsConversion(t *testing.T) {
	var asked []string
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Query().Get("effective_at[gte]"))
		w.Write([]byte(`{"data":[{"id":"a1","type":"login.succeeded",
			"effective_at":1761180000,"actor":{"type":"session",
			"session":{"user":{"id":"u1"}}}}],"has_more":false}`))
	})
	m, _ := entry(t, "openai").For("openai")
	out, err := Run(context.Background(), m, "audit", dialTo(t, s),
		MapFunc{"openai-audit-token": "t"}, State{}, noSleep)
	if err != nil {
		t.Fatal(err)
	}
	// The first run had no checkpoint and asked for nothing.
	if asked[0] != "" {
		t.Errorf("the first run asked for %q", asked[0])
	}
	if out.Watermark != "1761180000" {
		t.Fatalf("watermark = %q", out.Watermark)
	}
	if _, err := Run(context.Background(), m, "audit", dialTo(t, s),
		MapFunc{"openai-audit-token": "t"}, State{Watermark: out.Watermark},
		noSleep); err != nil {
		t.Fatal(err)
	}
	if asked[1] != "1761180000" {
		t.Errorf("the second run asked for %q in a filter that takes "+
			"seconds", asked[1])
	}
}
