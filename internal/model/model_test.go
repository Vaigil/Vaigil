// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	t.Setenv("AERTUN_MODEL_KEY", "")
	t.Setenv("OLLAMA_API_KEY", "")

	t.Setenv("AERTUN_MODEL_URL", "http://127.0.0.1:11434/v1")
	if _, err := NewHTTPModel(); err != nil {
		t.Errorf("a keyless local model was refused: %v", err)
	}

	t.Setenv("AERTUN_MODEL_URL", "https://api.openai.com/v1")
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

// Params are a caller's opinions about the draw, and a caller with no
// opinion must not be given one: a request that sets nothing is the
// request this always built, because "unset" and "temperature 0" are
// different requests — the second is a promise of determinism, and one a
// sampling caller would send by accident reads three identical replies as
// agreement nobody measured.
func TestParamsAreSentOnlyWhenSet(t *testing.T) {
	h, got := sent(t, 0)
	if _, err := h.Complete(context.Background(), "s", "u"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"temperature", "seed", "max_tokens"} {
		if _, ok := (*got)[key]; ok {
			t.Errorf("%s was sent by a caller that set nothing", key)
		}
	}
	temp, seed, tokens := 0.7, int64(12), 512
	if _, err := h.CompleteTuned(context.Background(), "s", "u", Params{
		Temperature: &temp, Seed: &seed, MaxTokens: &tokens}); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]any{
		"temperature": temp, "seed": seed, "max_tokens": tokens} {
		// The body is read back as JSON, where every number is a float64;
		// compared as written rather than as typed.
		if fmt.Sprint((*got)[key]) != fmt.Sprint(want) {
			t.Errorf("%s was sent as %v, want %v", key, (*got)[key], want)
		}
	}
	// An explicit zero temperature is an opinion, and is sent as one.
	zero := 0.0
	if _, err := h.CompleteTuned(context.Background(), "s", "u",
		Params{Temperature: &zero}); err != nil {
		t.Fatal(err)
	}
	if _, ok := (*got)["temperature"]; !ok {
		t.Error("an explicitly set temperature 0 was not sent")
	}
}

// A reply is bounded. The endpoint may be broken or hostile, and one that
// answers with more than any completion could be is cut off at the bound
// rather than read to its end; a large reply that fits is still read.
func TestAReplyIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// The JSON only begins past the bound.
		_, _ = w.Write(bytes.Repeat([]byte(" "), 256<<10+2048))
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	t.Cleanup(srv.Close)
	h := &HTTPModel{BaseURL: srv.URL, Model: "m", Client: srv.Client()}
	if _, err := h.Complete(context.Background(), "s", "u"); err == nil {
		t.Fatal("a reply that only began past the bound was read to the end")
	}

	big := strings.Repeat("a", 64<<10)
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"`+big+`"}}]}`)
	}))
	t.Cleanup(srv2.Close)
	h2 := &HTTPModel{BaseURL: srv2.URL, Model: "m", Client: srv2.Client()}
	got, err := h2.Complete(context.Background(), "s", "u")
	if err != nil || got != big {
		t.Fatalf("a large reply within the bound: %d bytes, %v", len(got), err)
	}
}

// OnUsage is told what each completion used: the provider's own accounting
// when it gives one, and an estimate labelled as an estimate when it does
// not — never a guess dressed as a measurement.
func TestOnUsageIsToldWhatEachCompletionUsed(t *testing.T) {
	var got []Usage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}],`+
			`"usage":{"prompt_tokens":120,"completion_tokens":8}}`)
	}))
	t.Cleanup(srv.Close)
	quietSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	t.Cleanup(quietSrv.Close)

	reported := &HTTPModel{BaseURL: srv.URL, Model: "m",
		Client: srv.Client(), OnUsage: func(u Usage) { got = append(got, u) }}
	if _, err := reported.Complete(context.Background(), "s", "u"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].In != 120 || got[0].Out != 8 || !got[0].Reported {
		t.Fatalf("the provider's accounting was not passed on: %+v", got)
	}

	got = nil
	quiet := &HTTPModel{BaseURL: quietSrv.URL, Model: "m",
		Client: quietSrv.Client(), OnUsage: func(u Usage) { got = append(got, u) }}
	if _, err := quiet.Complete(context.Background(), "s", "u"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Reported {
		t.Fatalf("a quiet provider was reported as a measurement: %+v", got)
	}
	if got[0].In == 0 {
		t.Errorf("the estimate was not even attempted: %+v", got[0])
	}
}
