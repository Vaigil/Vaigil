// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A model on this machine needs no key; a hosted one does.
//
// Requiring a key refused the arrangement that costs nothing: Ollama,
// llama.cpp, LM Studio and vLLM all serve this protocol and none of them wants
// one. Keyless against a public endpoint stays refused, because that is not a
// cheaper deployment — it is an operator who believes they are authenticated
// and is not.
func TestALocalModelNeedsNoKey(t *testing.T) {
	for _, tc := range []struct {
		url   string
		local bool
	}{
		{"http://127.0.0.1:11434/v1", true},   // Ollama's default
		{"http://localhost:8080/v1", true},    // llama.cpp
		{"http://[::1]:1234/v1", true},        // LM Studio over v6
		{"http://192.168.1.50:8000/v1", true}, // a box on the LAN
		{"https://api.openai.com/v1", false},
		{"https://ollama.com/v1", false},
		{"not a url", false},
		{"", false},
	} {
		got, why := isLocalEndpoint(tc.url)
		if got != tc.local {
			t.Errorf("%q: local=%v want %v (%s)", tc.url, got, tc.local, why)
		}
		if !got && why == "" {
			t.Errorf("%q was refused without saying why", tc.url)
		}
	}
}

// An unresolvable host is not local.
//
// An endpoint nobody can reach is a misconfiguration either way, and guessing
// permissively would let a typo become a keyless call to whatever the name
// eventually resolves to.
func TestAnUnresolvableEndpointIsNotLocal(t *testing.T) {
	got, why := isLocalEndpoint("http://this-host-does-not-exist.invalid/v1")
	if got {
		t.Error("an unresolvable host was treated as local")
	}
	if why == "" {
		t.Error("the refusal says nothing")
	}
}

// The end-to-end decision: a keyless local endpoint builds, a keyless public
// one does not.
func TestKeylessConfigurationIsAcceptedOnlyForALocalModel(t *testing.T) {
	t.Setenv("VAIGIL_MODEL_KEY", "")
	t.Setenv("OLLAMA_API_KEY", "")

	t.Setenv("VAIGIL_MODEL_URL", "http://127.0.0.1:11434/v1")
	if _, err := NewHTTPModel(); err != nil {
		t.Errorf("a keyless local model was refused: %v", err)
	}

	t.Setenv("VAIGIL_MODEL_URL", "https://api.openai.com/v1")
	err := NewHTTPModel2Err()
	if err == nil {
		t.Fatal("a keyless public endpoint was accepted; the operator would " +
			"believe they were authenticated and would not be")
	}
	if !strings.Contains(err.Error(), "local") {
		t.Errorf("the refusal does not point at the local option: %v", err)
	}
}

// NewHTTPModel2Err is NewHTTPModel's error, named so the test above reads as
// one assertion per line.
func NewHTTPModel2Err() error { _, err := NewHTTPModel(); return err }

// A model's key is not sent where anybody on the path can read it.
func TestAModelsKeyTravelsOnlyOverHTTPS(t *testing.T) {
	if _, err := NewHTTPModelAt("http://models.example.com/v1", "sk-1", "m"); err == nil {
		t.Fatal("a key over plain http to another host was accepted")
	}
	for _, ok := range []string{"https://models.example.com/v1", "http://127.0.0.1:11434/v1", "http://localhost:8080/v1"} {
		if _, err := NewHTTPModelAt(ok, "sk-1", "m"); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
}

// sent is a provider that keeps the last request it was sent and answers
// with status, or 200.
func sent(t *testing.T, status int) (*HTTPModel, *map[string]any) {
	t.Helper()
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = nil
		_ = json.Unmarshal(b, &got)
		w.Header().Set("Content-Type", "application/json")
		if status != 0 {
			w.WriteHeader(status)
			io.WriteString(w, `{"error":{"message":"temperature is not supported by this model"}}`)
			return
		}
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}]}`)
	}))
	t.Cleanup(srv.Close)
	return &HTTPModel{BaseURL: srv.URL, Model: "m", Client: srv.Client()}, &got
}

// A provider's refusal keeps its status, so a caller can tell an endpoint
// that is unavailable from a request every endpoint would refuse.
func TestARefusalKeepsItsStatus(t *testing.T) {
	h, _ := sent(t, http.StatusBadRequest)
	_, err := h.Complete(context.Background(), "s", "u")
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusBadRequest {
		t.Fatalf("err = %v", err)
	}
}

// What the provider reports it used is kept; without a report, an estimate.
func TestUsageIsWhatTheProviderReported(t *testing.T) {
	h, _ := sent(t, 0)
	_, u, err := h.CompleteMetered(context.Background(), "s", "u")
	if err != nil || u.Reported || u.In == 0 {
		t.Fatalf("usage %+v, %v", u, err)
	}
}
