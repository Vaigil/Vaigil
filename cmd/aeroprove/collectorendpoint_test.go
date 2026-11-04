// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aeroprove/aeroprove/internal/collector"
	"github.com/aeroprove/aeroprove/internal/spool"
	"github.com/aeroprove/aeroprove/internal/telemetry"
)

// collectorSite is a store with one collector credential, and the endpoint
// answering it.
func collectorSite(t *testing.T) (root string, srv *httptest.Server) {
	t.Helper()
	root = t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AEROPROVE_CONNECT_SECRET", "00collectorSecret0123456789abcdef")
	if err := cmdConnect(root, []string{"secret", "inbound-build01"}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mountCollector(mux, root)
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return root, srv
}

// postBatch sends one signed batch, the way the collector does.
func postBatch(t *testing.T, srv *httptest.Server, id string, at time.Time,
	records []collector.Record, secret, auth string) *http.Response {
	t.Helper()
	body, err := json.Marshal(collector.Batch{Collector: "build01", Records: records})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/collector",
		bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(collector.HeaderToken, "inbound-build01")
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	req.Header.Set(collector.HeaderBatch, id)
	req.Header.Set(collector.HeaderTime, fmt.Sprint(at.Unix()))
	req.Header.Set(collector.HeaderSignature,
		collector.SignBatch(secret, id, at, body))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// watchRecord is one watched-file fact, the shape the collector ships.
func watchRecord(at time.Time) collector.Record {
	return collector.Record{Source: collector.SourceWatch, At: at,
		Data: map[string]any{"path": "/home/dana/.ssh/id_ed25519",
			"kind": "key", "op": "changed", "sha256": "b42d", "size": 419}}
}

// The collector's door answers its own credential, refuses every other
// one, stores what is signed, and answers a retry with the truth: taken
// already, stored once.
func TestTheCollectorEndpointAnswersItsCredential(t *testing.T) {
	root, srv := collectorSite(t)
	now := time.Now().UTC()

	// No credential at all.
	resp := postBatch(t, srv, "b1", now, []collector.Record{watchRecord(now)},
		"00collectorSecret0123456789abcdef", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no credential got %d", resp.StatusCode)
	}
	// A credential that is not this one's.
	resp = postBatch(t, srv, "b2", now, []collector.Record{watchRecord(now)},
		"00collectorSecret0123456789abcdef", "the-wrong-secret")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a wrong credential got %d", resp.StatusCode)
	}
	// A body the signature did not cover.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/collector",
		strings.NewReader(`{"collector":"build01","records":[{"source":"collector/watch"}]}`))
	req.Header.Set(collector.HeaderToken, "inbound-build01")
	req.Header.Set("Authorization", "Bearer 00collectorSecret0123456789abcdef")
	req.Header.Set(collector.HeaderBatch, "b3")
	req.Header.Set(collector.HeaderTime, fmt.Sprint(now.Unix()))
	req.Header.Set(collector.HeaderSignature, "00")
	if resp, err := srv.Client().Do(req); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("an unsigned body was taken (%v, %d)", err, resp.StatusCode)
	}
	// A timestamp from before the tolerance.
	old := now.Add(-2 * time.Hour)
	if resp := postBatch(t, srv, "b4", old, []collector.Record{watchRecord(old)},
		"00collectorSecret0123456789abcdef", "00collectorSecret0123456789abcdef"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a stale batch got %d", resp.StatusCode)
	}

	// The honest delivery: taken, stored, and visible in the store.
	if resp := postBatch(t, srv, "b5", now, []collector.Record{watchRecord(now)},
		"00collectorSecret0123456789abcdef", "00collectorSecret0123456789abcdef"); resp.StatusCode != http.StatusOK {
		t.Fatalf("an honest batch got %d", resp.StatusCode)
	}
	// Its retry: answered as taken, stored nothing twice.
	resp2 := postBatch(t, srv, "b5", now, []collector.Record{watchRecord(now)},
		"00collectorSecret0123456789abcdef", "00collectorSecret0123456789abcdef")
	if resp2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("a retry got %d: %s", resp2.StatusCode, b)
	}
	var ans struct {
		Stored    int  `json:"stored"`
		Duplicate bool `json:"duplicate"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&ans); err != nil {
		t.Fatal(err)
	}
	if !ans.Duplicate {
		t.Error("a retried batch was not answered as the duplicate it is")
	}

	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	var watched int
	if err := sp.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		if e.Source == collector.SourceWatch {
			watched++
			if e.Raw["path"] == "" || e.Raw["sha256"] == "" {
				t.Errorf("a watch fact lost its fields: %v", e.Raw)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if watched != 1 {
		t.Errorf("%d watch events stored, want the one the retry carried", watched)
	}
}

// hostRecord is one watch or heartbeat record from a host that says its
// name, the way every record the collector ships does.
func hostRecord(source, host string, at time.Time) collector.Record {
	data := map[string]any{"host": host}
	if source == collector.SourceWatch {
		data["path"], data["kind"], data["op"] =
			"/home/dana/.mcp.json", "mcp-config", "changed"
		data["sha256"], data["size"] = "b42d", 419
	}
	return collector.Record{Source: source, At: at, Data: data}
}

// TestAMappedHostsEvidenceCarriesTheDeclaredNames: the whole enrichment
// contract on one host. A host mapped to one agent carries the closed list
// and the single join name; an unmapped host carries nothing at all — not
// an empty list, and never an invented actor — and the heartbeat carries
// the declaration beside the liveness it belongs to.
func TestAMappedHostsEvidenceCarriesTheDeclaredNames(t *testing.T) {
	root, srv := collectorSite(t)
	register(t, root, "watcher", "aeroprove_read")
	register(t, root, "docs-bot", "aeroprove_read")
	mapHost(t, root, "watcher", "build01")

	now := time.Now().UTC()
	secret := "00collectorSecret0123456789abcdef"
	for i, rec := range []collector.Record{
		hostRecord(collector.SourceWatch, "build01", now),
		hostRecord(collector.SourceHeartbeat, "build01", now),
		// A host nobody mapped, in the same batch.
		hostRecord(collector.SourceWatch, "ci02", now),
	} {
		if resp := postBatch(t, srv, fmt.Sprintf("m%d", i), now,
			[]collector.Record{rec}, secret, secret); resp.StatusCode != http.StatusOK {
			t.Fatalf("record %d got %d", i, resp.StatusCode)
		}
	}
	var watch, beat, unmapped *telemetry.Event
	for _, e := range storedEvents(t, root) {
		ev := e
		switch {
		case e.Source == collector.SourceWatch && e.Raw["host"] == "build01":
			watch = &ev
		case e.Source == collector.SourceHeartbeat:
			beat = &ev
		case e.Source == collector.SourceWatch && e.Raw["host"] == "ci02":
			unmapped = &ev
		}
	}
	if watch == nil || beat == nil || unmapped == nil {
		t.Fatalf("the batch stored %d event(s); a leg of the matrix is missing",
			len(storedEvents(t, root)))
	}
	if watch.Raw["agents"] != "watcher" || watch.Raw["agent"] != "watcher" {
		t.Errorf("the mapped host's watch event carries %q/%q, want the "+
			"declared list and the join name",
			watch.Raw["agents"], watch.Raw["agent"])
	}
	if !watch.Actor.Zero() {
		t.Errorf("an actor was invented for a file change: %+v — the "+
			"declaration names who runs there, not who changed it", watch.Actor)
	}
	if beat.Raw["agents"] != "watcher" {
		t.Errorf("the heartbeat carries %q; the declaration belongs beside "+
			"the liveness it explains", beat.Raw["agents"])
	}
	if _, has := unmapped.Raw["agents"]; has {
		t.Errorf("an unmapped host carried %q; nothing declared means "+
			"nothing carried", unmapped.Raw["agents"])
	}
	if _, has := unmapped.Raw["agent"]; has {
		t.Errorf("an unmapped host carried the join name %q",
			unmapped.Raw["agent"])
	}
}

// TestAMappingChangeShowsOnTheNextPush: the declaration is read per
// delivery, never cached, so adding a second agent closes the single name
// (a shared box is not attributed between its agents) and unmap takes even
// the list away — each on the push after the change, and never in the
// events already stored.
func TestAMappingChangeShowsOnTheNextPush(t *testing.T) {
	root, srv := collectorSite(t)
	register(t, root, "watcher", "aeroprove_read")
	register(t, root, "docs-bot", "aeroprove_read")
	mapHost(t, root, "watcher", "build01")

	now := time.Now().UTC()
	secret := "00collectorSecret0123456789abcdef"
	push := func(id string) telemetry.Event {
		t.Helper()
		if resp := postBatch(t, srv, id, now,
			[]collector.Record{hostRecord(collector.SourceWatch, "build01", now)},
			secret, secret); resp.StatusCode != http.StatusOK {
			t.Fatalf("%s got %d", id, resp.StatusCode)
		}
		events := storedEvents(t, root)
		return events[len(events)-1]
	}
	first := push("p1")
	if first.Raw["agent"] != "watcher" {
		t.Fatalf("the first push carried %q; the matrix is not set up",
			first.Raw["agent"])
	}
	// A second agent on the same host: the list carries both, the join
	// name carries neither — the program refuses to choose between
	// co-declared agents.
	mapHost(t, root, "docs-bot", "build01")
	shared := push("p2")
	if shared.Raw["agents"] != "docs-bot,watcher" {
		t.Errorf("after the second mapping the push carries %q, want the "+
			"whole closed list", shared.Raw["agents"])
	}
	if _, has := shared.Raw["agent"]; has {
		t.Errorf("a host declared to run two agents carried the single name "+
			"%q; that is a choice the program must not make",
			shared.Raw["agent"])
	}
	// Both taken back: nothing carried, on the push after each.
	if err := cmdAgent(root, []string{"maps", "docs-bot", "--host",
		"build01", "--remove"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdAgent(root, []string{"maps", "watcher", "--host",
		"build01", "--remove"}); err != nil {
		t.Fatal(err)
	}
	after := push("p3")
	if _, has := after.Raw["agents"]; has {
		t.Errorf("an unmapped host still carried %q", after.Raw["agents"])
	}
	// What was stored before the change still says what was declared then:
	// the mapping reaches forward, never backward.
	if first.Raw["agent"] != "watcher" || shared.Raw["agents"] == "" {
		t.Error("a mapping change rewrote events already stored; it must " +
			"reach forward to the next push only")
	}
}

// TestABrokenMappingRefusesTheBatch: a mapping file that cannot be read is
// not an empty one. Storing evidence as though nobody had declared
// anything would silently undo every declaration on the file, so the batch
// is refused with the reason, and nothing is stored.
func TestABrokenMappingRefusesTheBatch(t *testing.T) {
	root, srv := collectorSite(t)
	if err := os.WriteFile(agentMapsPath(root), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	resp := postBatch(t, srv, "broken", now,
		[]collector.Record{hostRecord(collector.SourceWatch, "build01", now)},
		"00collectorSecret0123456789abcdef", "00collectorSecret0123456789abcdef")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a batch against an unreadable mapping got %d, want the "+
			"refusal", resp.StatusCode)
	}
	if events := storedEvents(t, root); len(events) != 0 {
		t.Errorf("%d event(s) stored beside a mapping that cannot be read",
			len(events))
	}
}

// TestTheOTLPBoundaryCarriesTheJoinName: the span's own actor claim,
// renamed into the field the recorder-side declaration writes — and never
// overwritten when the span carried its own word about its agent.
func TestTheOTLPBoundaryCarriesTheJoinName(t *testing.T) {
	span := telemetry.Event{Source: "otel/genai",
		Actor: telemetry.ID{Issuer: "otel", Value: "agent-7"},
		Raw:   map[string]string{"operation": "execute_tool"}}
	events := []telemetry.Event{span,
		{Source: "okta/system", Actor: telemetry.ID{Issuer: "okta", Value: "dana"}},
		{Source: "otel/genai", Actor: telemetry.ID{Issuer: "otel", Value: "said-so"},
			Raw: map[string]string{"agent": "the-name-the-sdk-set"}},
		{Source: "otel/genai"}}
	otelCarriesTheJoinName(events)
	if events[0].Raw["agent"] != "agent-7" {
		t.Errorf("the span's actor did not reach the join field: %v",
			events[0].Raw)
	}
	if events[1].Raw != nil {
		t.Errorf("another source's event was written: %v", events[1].Raw)
	}
	if events[2].Raw["agent"] != "the-name-the-sdk-set" {
		t.Errorf("the span's own word was overwritten: %v", events[2].Raw)
	}
	if events[3].Raw != nil {
		t.Errorf("a span attributing its actions to nobody gained a name: %v",
			events[3].Raw)
	}
}
