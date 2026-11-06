// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package forge exports verified outcomes as signed training episodes.
//
// An episode is what a model saw, what it produced, and what the verifier
// said about it — the exact facts and closed-set words from the analyst's
// state, never the attacker-writable text, because training on an
// attacker's words is training the attacker chose. The episodes are JSON
// lines, one per verdict, with the Merkle root of the whole set recorded
// in the audit log so nobody can quietly add, remove or edit one.
//
// No training code lives here. The forge exports; the trainer (a separate
// sidecar the operator runs) consumes. What the forge guarantees is that
// every episode is derived from a signed human decision and carries no
// attacker-writable bytes — the two properties a training set must have
// to be a reward signal rather than a poisoning vector.
package forge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Episode is one training example: the computed facts the model was shown
// (counts and closed-set words only), what it answered, the calibrated
// confidence, the counterfactual check, and the person's signed decision.
//
// Every string here is either a number rendered as a string, a word from
// a closed set, or a label the program itself assigned. No field carries
// text an attacker could have written — that is the forge's contract, and
// the test proves it by seeding every untrusted field with a marker and
// asserting the marker never appears.
type Episode struct {
	// FindingID identifies the case, for traceability to the audit log.
	FindingID string `json:"finding_id"`
	// Facts are the counted facts the model was shown, from
	// analyst.State.Facts: numbers and closed-set words only.
	Facts map[string]any `json:"facts"`
	// ModelVerdict is the model's closed-set answer.
	ModelVerdict string `json:"model_verdict"`
	// ModelConfidence is the model's calibrated confidence.
	ModelConfidence float64 `json:"model_confidence"`
	// CounterfactualChanged says the verdict flipped without the
	// attacker's words — an injection signal the trainer must know.
	CounterfactualChanged bool `json:"counterfactual_changed,omitempty"`
	// HumanVerdict is the person's signed decision (the ground truth).
	HumanVerdict string `json:"human_verdict"`
	// HumanDecisionAt is when the person decided.
	HumanDecisionAt time.Time `json:"human_decision_at"`
	// ExportedAt is when this episode was written.
	ExportedAt time.Time `json:"exported_at"`
}

// Digest is the episode's canonical sha256.
func (e Episode) Digest() string {
	b, _ := json.Marshal(e)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Set is a collection of episodes, written as JSON lines, with the
// Merkle root of all episode digests recorded in the audit log.
type Set struct {
	Episodes []Episode `json:"episodes"`
}

// Root is the Merkle root of all episode digests: the leaves are each
// episode's sha256, paired bottom-up, with the lone-leaf case promoted
// (not duplicated) so a single-episode set is honest about being one.
func (s Set) Root() string {
	var leaves [][]byte
	for _, e := range s.Episodes {
		h, _ := hex.DecodeString(e.Digest())
		leaves = append(leaves, h)
	}
	if len(leaves) == 0 {
		return hex.EncodeToString(make([]byte, 32))
	}
	for len(leaves) > 1 {
		var next [][]byte
		for i := 0; i < len(leaves); i += 2 {
			if i+1 < len(leaves) {
				h := sha256.Sum256(append(append([]byte{}, leaves[i]...), leaves[i+1]...))
				next = append(next, h[:])
			} else {
				next = append(next, leaves[i])
			}
		}
		leaves = next
	}
	return hex.EncodeToString(leaves[0])
}

// Marshal writes the set as JSON lines (one episode per line), the format
// trainers consume. The Merkle root is NOT in the file (it is recorded in
// the audit log); a trainer verifies the root by recomputing it from the
// lines it read.
func (s Set) Marshal() ([]byte, string, error) {
	var b strings.Builder
	for _, e := range s.Episodes {
		line, err := json.Marshal(e)
		if err != nil {
			return nil, "", fmt.Errorf("episode %s: %w", e.FindingID, err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return []byte(b.String()), s.Root(), nil
}

// SanitizeFacts strips any string that could carry attacker-writable
// text, keeping only numbers, booleans, and strings from a closed set.
// This is the forge's gate: even if a future Facts field carries free
// text by mistake, the forge refuses to export it.
func SanitizeFacts(facts map[string]any) map[string]any {
	out := make(map[string]any, len(facts))
	for k, v := range facts {
		switch vv := v.(type) {
		case float64, int, int64, bool:
			out[k] = vv
		case string:
			// A string is kept only if it is a word from a known closed
			// set: a severity, a kind, a verdict. Anything else could
			// carry attacker text and is replaced by its length.
			if isClosedSetWord(vv) {
				out[k] = vv
			} else {
				out[k] = fmt.Sprintf("[text, %d bytes]", len(vv))
			}
		default:
			out[k] = fmt.Sprintf("[type %T, redacted]", v)
		}
	}
	return out
}

// closedSetWords are the strings the analyst's facts carry that are
// words from a closed set the program assigned, never text an attacker
// could influence.
var closedSetWords = map[string]bool{
	// Severities
	"critical": true, "high": true, "medium": true, "low": true,
	// Kinds
	"detection": true, "indicator": true, "appsec": true, "vendor": true,
	// Verdicts
	"real": true, "false-positive": true, "benign": true,
	// Model verdicts
	"triaged": true, "fixed": true, "accepted": true, "open": true,
	// Purposes
	"observe": true, "triage": true,
}

func isClosedSetWord(s string) bool {
	return closedSetWords[strings.ToLower(s)]
}
