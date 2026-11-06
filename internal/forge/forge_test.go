// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package forge

import (
	"strings"
	"testing"
	"time"
)

// No attacker-writable field from the input ever appears in an exported
// episode: seed every untrusted-adjacent field with a marker, export,
// and assert the marker is absent.
func TestNoAttackerTextReachesAnEpisode(t *testing.T) {
	const marker = "ATTACKER_MARKER_do_not_export"
	facts := map[string]any{
		"kind":             "detection",  // closed set: kept
		"severity":         "high",       // closed set: kept
		"times_seen":       float64(500), // number: kept
		"entity_something": marker,       // attacker text: replaced
		"title_text":       marker,       // attacker text: replaced
	}
	sanitized := SanitizeFacts(facts)
	for k, v := range sanitized {
		if s, ok := v.(string); ok && strings.Contains(s, marker) {
			t.Errorf("field %q carries the attacker's text: %q", k, s)
		}
	}
	// The closed-set words survived
	if sanitized["kind"] != "detection" {
		t.Errorf("kind was sanitized: %v", sanitized["kind"])
	}
	if sanitized["severity"] != "high" {
		t.Errorf("severity was sanitized: %v", sanitized["severity"])
	}
	// The attacker text was replaced by its length
	if !strings.Contains(sanitized["entity_something"].(string), "bytes") {
		t.Errorf("entity text was not replaced: %v", sanitized["entity_something"])
	}
}

// The Merkle root is deterministic: the same episodes always produce the
// same root, and a single changed byte changes the root.
func TestTheMerkleRootIsDeterministicAndSensitive(t *testing.T) {
	mk := func() Set {
		return Set{Episodes: []Episode{
			{FindingID: "f1", ModelVerdict: "real", HumanVerdict: "real",
				HumanDecisionAt: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC),
				ExportedAt:      time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)},
			{FindingID: "f2", ModelVerdict: "benign", HumanVerdict: "false-positive",
				HumanDecisionAt: time.Date(2026, 11, 6, 13, 0, 0, 0, time.UTC),
				ExportedAt:      time.Date(2026, 11, 6, 13, 0, 0, 0, time.UTC)},
		}}
	}
	r1 := mk().Root()
	r2 := mk().Root()
	if r1 != r2 {
		t.Errorf("the same episodes produced different roots: %s vs %s", r1, r2)
	}
	// Change one byte
	changed := mk()
	changed.Episodes[0].ModelVerdict = "false-positive"
	if changed.Root() == r1 {
		t.Error("a changed episode produced the same root")
	}
}

// The JSON-lines output is parseable per-line and matches the set.
func TestMarshalWritesJSONLines(t *testing.T) {
	s := Set{Episodes: []Episode{
		{FindingID: "f1", ModelVerdict: "real", HumanVerdict: "real",
			Facts: map[string]any{"kind": "detection"}},
		{FindingID: "f2", ModelVerdict: "benign", HumanVerdict: "benign"},
	}}
	body, root, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if root == "" || root == strings.Repeat("0", 64) {
		t.Errorf("the root is empty or all-zero: %s", root)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lines, want 2", len(lines))
	}
	if !strings.Contains(lines[0], `"f1"`) {
		t.Errorf("line 0 does not carry f1: %s", lines[0])
	}
}

// An empty set has a defined root.
func TestEmptySetHasARoot(t *testing.T) {
	s := Set{}
	if s.Root() == "" {
		t.Error("an empty set has no root")
	}
}
