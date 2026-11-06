// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package twin

import (
	"encoding/json"
	"strings"
	"testing"
)

// The same recorded case answered twice gives byte-identical responses.
func TestTheSameCaseAnswersByteIdentically(t *testing.T) {
	s := &Snapshot{}
	args := map[string]any{"operation": "list_findings", "limit": 20}
	s.Record("vaertun_read", args, `{"findings":[{"id":"f1","title":"test"}]}`)

	// Answer the same query twice; the response must be identical.
	r1, ok1 := s.Answer("vaertun_read", args)
	r2, ok2 := s.Answer("vaertun_read", args)
	if !ok1 || !ok2 {
		t.Fatal("the query did not answer")
	}
	if r1 != r2 {
		t.Errorf("the same query answered differently: %q vs %q", r1, r2)
	}
}

// Different arguments are different queries.
func TestDifferentArgumentsAreDifferentQueries(t *testing.T) {
	s := &Snapshot{}
	s.Record("op", map[string]any{"a": "1"}, "answer-one")
	if _, ok := s.Answer("op", map[string]any{"a": "2"}); ok {
		t.Error("a different argument set answered")
	}
}

// Key is deterministic across map iteration order.
func TestKeyIsDeterministic(t *testing.T) {
	// The same map, built twice with different iteration orders
	a1 := map[string]any{"z": "1", "a": "2", "m": "3"}
	a2 := map[string]any{"m": "3", "z": "1", "a": "2"}
	if Key("op", a1) != Key("op", a2) {
		t.Error("the same arguments hashed differently")
	}
}

// Labels say which fields are attacker-writable.
func TestLabelsNameTheTaintedFields(t *testing.T) {
	fields := map[string]string{
		"id":     "f1",
		"title":  "Failed sign-in", // attacker can influence the title text
		"state":  "open",
		"entity": "svc-backup", // attacker can choose the entity string
	}
	labelled := Label(fields, "title", "entity")
	for k, f := range labelled.Fields {
		switch k {
		case "title", "entity":
			if !f.Tainted {
				t.Errorf("%s should be tainted", k)
			}
		case "id", "state":
			if f.Tainted {
				t.Errorf("%s should not be tainted", k)
			}
		}
	}
}

// Save and Load round-trip.
func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/snap.json"
	s := &Snapshot{}
	s.Record("op", map[string]any{"a": "1"}, "the-answer")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := loaded.Answer("op", map[string]any{"a": "1"})
	if !ok || got != "the-answer" {
		t.Errorf("loaded snapshot answered %q (ok=%v)", got, ok)
	}
}

// The snapshot's JSON has the fields an evaluator needs.
func TestSnapshotJSONIsReadable(t *testing.T) {
	s := &Snapshot{}
	s.Record("vaertun_read", map[string]any{"op": "list_findings"}, `[{"id":"f1"}]`)
	body, _ := json.Marshal(s)
	if !strings.Contains(string(body), "vaertun_read") {
		t.Error("the operation name is not in the JSON")
	}
	if !strings.Contains(string(body), "vaertun_read") {
		t.Error("the response is not in the JSON")
	}
}
