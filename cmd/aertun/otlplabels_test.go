// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/otlp"
	"github.com/aertun/aertun/internal/out"
	"github.com/aertun/aertun/internal/telemetry"
)

// The ingest boundary's tool-label stamp, pushed the way an exporter pushes
// it: the table the pack installs, the refusal a broken table earns, and
// the freshness that lets an edit reach the next push.

// otlpSite is a store with the pack installed, its tool-label table beside
// the rules, and the OTLP endpoint answering the push credential.
func otlpSite(t *testing.T) (root string, srv *httptest.Server) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if w == nil {
		w = out.New(false)
	}
	root = t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := cmdDetect(root, []string{"pack", "install"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AERTUN_CONNECT_SECRET", "00otlpPushSecret0123456789abcd")
	if err := cmdConnect(root, []string{"secret", otlp.SecretName}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mountOTLP(mux, root)
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return root, srv
}

// oneSpan is one GenAI tool span in a push: the trace it belongs to, its
// own span id, and the tool it names.
type oneSpan struct {
	trace, span, tool string
}

// pushSpans sends one OTLP/JSON batch of tool spans, the shape an SDK's
// exporter sends, each a second apart so no two carry one span id.
func pushSpans(t *testing.T, srv *httptest.Server, at time.Time,
	spans ...oneSpan) *http.Response {
	t.Helper()
	var b strings.Builder
	b.WriteString(`{"resourceSpans":[{"resource":{"attributes":[` +
		`{"key":"service.name","value":{"stringValue":"refunder"}}]},` +
		`"scopeSpans":[{"spans":[`)
	for i, s := range spans {
		if i > 0 {
			b.WriteString(",")
		}
		start := at.Add(time.Duration(i) * time.Second).UnixNano()
		fmt.Fprintf(&b, `{"traceId":%q,"spanId":%q,"name":"execute_tool",`+
			`"startTimeUnixNano":%q,"endTimeUnixNano":%q,`+
			`"attributes":[`+
			`{"key":"gen_ai.operation.name","value":{"stringValue":"execute_tool"}},`+
			`{"key":"gen_ai.agent.id","value":{"stringValue":"refunder"}},`+
			`{"key":"gen_ai.tool.name","value":{"stringValue":%q}}],`+
			`"status":{}}`,
			s.trace, s.span, fmt.Sprint(start), fmt.Sprint(start+1_000_000),
			s.tool)
	}
	b.WriteString(`]}]}]}`)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/traces",
		strings.NewReader(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer 00otlpPushSecret0123456789abcd")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// storedSpans is the GenAI spans the store holds, by span id — the one
// identity a push controls — so a span the batch named but the store never
// took is a missing key rather than a quieter absence.
func storedSpans(t *testing.T, root string) map[string]telemetry.Event {
	t.Helper()
	out := map[string]telemetry.Event{}
	for _, e := range storedEvents(t, root) {
		if e.Source == "otel/genai" {
			out[e.Raw["span_id"]] = e
		}
	}
	return out
}

// TestOTLPIngestStampsOnlyWhatTheTableDeclares.
//
// The three honesty rules of the stamp, on one push: a tool the table names
// carries its labels, the same tool spelled in different casing carries the
// same labels (one tool, not two), and a tool nothing names carries nothing
// at all — no empty list, no guess from the name, no leg the chain can
// stand on that nobody declared.
func TestOTLPIngestStampsOnlyWhatTheTableDeclares(t *testing.T) {
	root, srv := otlpSite(t)
	resp := pushSpans(t, srv, time.Now().UTC().Add(-time.Minute),
		oneSpan{"5b8efff798038103d269b633813fc60c", "a000000000000001", "fetch"},
		oneSpan{"5b8efff798038103d269b633813fc60c", "a000000000000002", "FETCH"},
		oneSpan{"5b8efff798038103d269b633813fc60c", "a000000000000003", "filesystem.write"},
		oneSpan{"5b8efff798038103d269b633813fc60c", "a000000000000004", "read_mail"},
	)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("the push got %d: %s", resp.StatusCode, body)
	}
	spans := storedSpans(t, root)
	for _, id := range []string{"a000000000000001", "a000000000000002",
		"a000000000000003", "a000000000000004"} {
		if _, ok := spans[id]; !ok {
			t.Fatalf("no stored span %s; the matrix is not set up", id)
		}
	}
	if got := spans["a000000000000001"].Raw["labels"]; got != "untrusted-content" {
		t.Errorf("the table's fetch carries %q, want its declared label", got)
	}
	if got := spans["a000000000000002"].Raw["labels"]; got != "untrusted-content" {
		t.Errorf("the same tool spelled FETCH carries %q; the stamp folds "+
			"case or it silently misses", got)
	}
	if got := spans["a000000000000004"].Raw["labels"]; got != "sensitive-data,untrusted-content" {
		t.Errorf("the mailbox carries %q, want both its labels", got)
	}
	if _, said := spans["a000000000000003"].Raw["labels"]; said {
		t.Errorf("a tool the table does not name carries %q; nothing "+
			"declared means nothing stamped",
			spans["a000000000000003"].Raw["labels"])
	}
}

// TestOTLPIngestRefusesTheBatchAgainstABrokenTable.
//
// A table that is there and cannot be read is not an empty one: storing
// the spans as though nobody had declared anything would silently undo
// every declaration on the file, and a chain that quietly lost its legs is
// recoverable in triage while a table nobody was told was broken is not.
// So the batch goes back to the exporter unstored — the same line the
// recorder-host mapping draws — and what repairs the file reaches the very
// next push, because the table is read per delivery and never cached.
func TestOTLPIngestRefusesTheBatchAgainstABrokenTable(t *testing.T) {
	root, srv := otlpSite(t)
	at := time.Now().UTC().Add(-time.Minute)
	// The healthy baseline: one span stored.
	if resp := pushSpans(t, srv, at,
		oneSpan{"5b8efff798038103d269b633813fc60c", "b000000000000001", "fetch"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("the healthy push got %d", resp.StatusCode)
	}
	if n := len(storedSpans(t, root)); n != 1 {
		t.Fatalf("%d span(s) stored after the healthy push, want 1", n)
	}

	// Broken: the batch is refused whole, and nothing of it is stored.
	table := filepath.Join(root, "detections", detect.ToolLabelsFile)
	if err := os.WriteFile(table, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp := pushSpans(t, srv, at,
		oneSpan{"5b8efff798038103d269b633813fc60c", "b000000000000002", "fetch"})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a push against a broken table got %d, want the refusal",
			resp.StatusCode)
	}
	if n := len(storedSpans(t, root)); n != 1 {
		t.Errorf("%d span(s) stored beside a table that cannot be read, "+
			"want only the baseline", n)
	}
	if _, stored := storedSpans(t, root)["b000000000000002"]; stored {
		t.Error("the refused batch's span reached the store anyway")
	}

	// Repaired, and different: the tool was renamed and the table caught
	// up. The next push stamps against what the file says now.
	renamed := `{"tools":[{"tool":"renamed_fetch","labels":["untrusted-content"],` +
		`"why":"the fetcher after the rename"}]}`
	if err := os.WriteFile(table, []byte(renamed), 0o600); err != nil {
		t.Fatal(err)
	}
	if resp := pushSpans(t, srv, at,
		oneSpan{"5b8efff798038103d269b633813fc60c", "b000000000000003", "renamed_fetch"},
		oneSpan{"5b8efff798038103d269b633813fc60c", "b000000000000004", "fetch"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("the push after the repair got %d", resp.StatusCode)
	}
	spans := storedSpans(t, root)
	if got := spans["b000000000000003"].Raw["labels"]; got != "untrusted-content" {
		t.Errorf("the renamed tool carries %q; a repaired table reaches "+
			"the next push or it reaches nothing", got)
	}
	if _, said := spans["b000000000000004"].Raw["labels"]; said {
		t.Errorf("the old name still carries %q; the table's word is per "+
			"push, and this push's table no longer declares it",
			spans["b000000000000004"].Raw["labels"])
	}

	// Absent: the fail-closed answer is silence, not a refusal and never a
	// fabricated label.
	if err := os.Remove(table); err != nil {
		t.Fatal(err)
	}
	if resp := pushSpans(t, srv, at,
		oneSpan{"5b8efff798038103d269b633813fc60c", "b000000000000005", "renamed_fetch"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("a push with no table at all got %d, want it taken", resp.StatusCode)
	}
	spans = storedSpans(t, root)
	if _, said := spans["b000000000000005"].Raw["labels"]; said {
		t.Errorf("an absent table stamped %q", spans["b000000000000005"].Raw["labels"])
	}
}

// TestOTLPLabelsNeverOverwriteWhatTheSpanAlreadySaid.
//
// The event's own word wins: a raw.labels the deployment's mapping already
// wrote is the deployment's declaration, and this boundary renames what was
// declared elsewhere rather than overwriting it — the same line the join
// name draws above it.
func TestOTLPLabelsNeverOverwriteWhatTheSpanAlreadySaid(t *testing.T) {
	labels, err := detect.ParseToolLabels([]byte(
		`{"tools":[{"tool":"fetch","labels":["untrusted-content"],` +
			`"why":"a URL fetcher"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	genai := func(tool string, raw map[string]string) telemetry.Event {
		return telemetry.Event{Source: "otel/genai",
			Actor: telemetry.ID{Issuer: "otel", Value: "refunder"},
			Raw:   raw}
	}
	events := []telemetry.Event{
		genai("fetch", map[string]string{"tool": "fetch"}),
		genai("fetch", map[string]string{"tool": "fetch",
			"labels": "site-declared"}),
		genai("filesystem.write", map[string]string{"tool": "filesystem.write"}),
		{Source: "okta/system", Raw: map[string]string{"tool": "fetch"}},
		genai("", map[string]string{"operation": "invoke_chat_model"}),
	}
	otelCarriesTheToolLabels(events, labels)
	if got := events[0].Raw["labels"]; got != "untrusted-content" {
		t.Errorf("the declared tool carries %q, want the table's label", got)
	}
	if got := events[1].Raw["labels"]; got != "site-declared" {
		t.Errorf("the span's own word was overwritten with %q", got)
	}
	if _, said := events[2].Raw["labels"]; said {
		t.Errorf("an undeclared tool carries %q", events[2].Raw["labels"])
	}
	if _, said := events[3].Raw["labels"]; said {
		t.Error("another source's event was stamped")
	}
	if _, said := events[4].Raw["labels"]; said {
		t.Error("a span naming no tool was stamped")
	}
	// The absent-table answer, on spans nothing has stamped yet: the zero
	// table stamps nothing anywhere, which is the fail-closed silence of a
	// table nobody wrote.
	fresh := []telemetry.Event{
		genai("fetch", map[string]string{"tool": "fetch"}),
		genai("filesystem.write", map[string]string{"tool": "filesystem.write"}),
	}
	otelCarriesTheToolLabels(fresh, detect.ToolLabels{})
	for i, e := range fresh {
		if _, said := e.Raw["labels"]; said {
			t.Errorf("span %d carries %q from a table nobody wrote", i,
				e.Raw["labels"])
		}
	}
}
