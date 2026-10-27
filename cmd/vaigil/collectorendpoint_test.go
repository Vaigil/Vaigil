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
	"strings"
	"testing"
	"time"

	"github.com/vaigil/vaigil/internal/collector"
	"github.com/vaigil/vaigil/internal/spool"
	"github.com/vaigil/vaigil/internal/telemetry"
)

// collectorSite is a store with one collector credential, and the endpoint
// answering it.
func collectorSite(t *testing.T) (root string, srv *httptest.Server) {
	t.Helper()
	root = t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAIGIL_CONNECT_SECRET", "00collectorSecret0123456789abcdef")
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
