// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package twin is the context twin: an MCP server mode that answers an
// agent's investigation queries from a recorded snapshot instead of the
// live store, so agentic investigations can be replayed deterministically
// for evaluation.
//
// Every field it returns carries whether an attacker could have written
// it. The existing read operations already know: evidence text, entity
// names, finding titles are attacker-writable; sequence numbers, verdicts,
// audit entries are the program's own. The twin labels them in every
// response, so an agent (or an evaluator measuring an agent) can see what
// was data and what was trusted.
//
// The same recorded case answered twice gives byte-identical responses,
// because the twin serves from the snapshot, not from the store.
package twin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Snapshot is the recorded set of query-and-answer pairs.
type Snapshot struct {
	Entries map[string]Entry `json:"entries"`
}

// Entry is one recorded answer, keyed by the query it answers.
type Entry struct {
	Operation string `json:"operation"`
	Arguments string `json:"arguments"` // canonical JSON of the args
	Response  string `json:"response"`  // the answer, as the MCP returned it
}

// Key is the deterministic key for a query: operation and canonical args.
func Key(operation string, args map[string]any) string {
	// Sort the keys so the same arguments always hash the same.
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "%s|", operation)
	for _, k := range keys {
		v, _ := json.Marshal(args[k])
		fmt.Fprintf(&b, "%s=%s;", k, v)
	}
	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:16])
}

// Record adds a query-and-answer pair to the snapshot.
func (s *Snapshot) Record(operation string, args map[string]any, response string) {
	if s.Entries == nil {
		s.Entries = map[string]Entry{}
	}
	s.Entries[Key(operation, args)] = Entry{
		Operation: operation,
		Arguments: mustJSON(args),
		Response:  response,
	}
}

// Answer returns the recorded answer for a query, or says there is none.
func (s *Snapshot) Answer(operation string, args map[string]any) (string, bool) {
	if s.Entries == nil {
		return "", false
	}
	e, ok := s.Entries[Key(operation, args)]
	if !ok {
		return "", false
	}
	return e.Response, true
}

// Save writes the snapshot atomically.
func (s *Snapshot) Save(path string) error {
	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o600)
}

// Load reads a snapshot from a file.
func Load(path string) (*Snapshot, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the snapshot: %w", err)
	}
	var s Snapshot
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, fmt.Errorf("the snapshot does not parse: %w", err)
	}
	return &s, nil
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// LabelledField is one field in a labelled response: the value and
// whether an attacker could have written it.
type LabelledField struct {
	Value   string `json:"value"`
	Tainted bool   `json:"tainted"`
}

// Labelled wraps a plain response value with per-field taint labels,
// so an agent (or the evaluation measuring one) can see which fields
// came from attacker-writable text.
type Labelled struct {
	Fields map[string]LabelledField `json:"fields"`
}

// Label marks which fields of a flat map are attacker-writable. The
// taintedKeys list names the keys whose values an attacker could have
// written; everything else is the program's own computation.
func Label(fields map[string]string, taintedKeys ...string) Labelled {
	tainted := map[string]bool{}
	for _, k := range taintedKeys {
		tainted[k] = true
	}
	out := Labelled{Fields: make(map[string]LabelledField, len(fields))}
	for k, v := range fields {
		out.Fields[k] = LabelledField{Value: v, Tainted: tainted[k]}
	}
	return out
}
