// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/windtunnel"
)

// The committed scorecard seed verifies against the committed public key,
// offline, forever.
//
// # Why the artifacts are committed to main's tree, not read from the
// # scorecards branch
//
// The publication history lives on the `scorecards` branch, where the
// weekly workflow appends one datestamped card per run. A test that read
// the branch would need somebody to have checked it out first: on a laptop
// running the plain suite the branch is not there, the test would have to
// skip, and a seed that skips wherever the artifacts are missing is no
// seed — it stays green on machines that never once looked at the branch.
// A workflow-step assertion instead of a test would run weekly rather
// than on every suite, and would guard neither an edit to the committed
// key nor a regression in the verify path between runs.
//
// So main carries the seed pair under scorecards/: the public half of the
// dedicated CI signing key, and the genesis card it signed, as a frozen
// historical artifact — the same bytes the branch published on the first
// run. Every `go test ./...`, in CI and on any laptop, verifies that pair
// with no workflow coupling, the same way the other root-level tests
// assert on the tree they sit in. The pair is pinned as a pair: when the
// signing key rotates, the committed public key and the seed card are
// replaced together in one deliberate commit, and the old key's cards
// keep verifying against the history that carries them.
//
// The test deliberately does NOT compare the seed card against the live
// corpus. The corpus grows; the genesis card is a record of what ran on
// the day it ran, sealed by its own digest — comparing it to today's
// corpus would break the seed on every growth, which is exactly what a
// genesis pin must not do. The rolling check that each new card covers
// the whole shipped corpus belongs to the publishing workflow, which sees
// the corpus of its own day.
//
// The decode mirrors the CLI's verify discipline field for field: unknown
// fields refused, the self-digest checked before any signature, an
// unsigned document named as such, and both signatures required in the
// wind tunnel's own context — so this test can never pass by being more
// trusting than the command a stranger runs.
func TestTheCommittedScorecardSeedVerifies(t *testing.T) {
	pub, err := windtunnel.LoadPublicKey(filepath.Join("scorecards",
		"public-key.json"))
	if err != nil {
		t.Fatalf("the committed public key does not parse: %v", err)
	}
	cards, err := filepath.Glob(filepath.Join("scorecards",
		"scorecard-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) == 0 {
		t.Fatal("no committed scorecard under scorecards/; the seed pair is " +
			"gone and a test that inspects nothing passes")
	}
	for _, path := range cards {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var card windtunnel.Scorecard
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&card); err != nil {
			t.Errorf("%s is not a scorecard this build reads: %v", path, err)
			continue
		}
		if err := card.Verify(); err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if card.Signature == nil {
			t.Errorf("%s carries no signature: an unsigned document makes no "+
				"claim a signature would back, and a seed of it seeds nothing",
				path)
			continue
		}
		if err := windtunnel.VerifyScorecard(&card, *card.Signature, pub); err != nil {
			t.Errorf("%s does not verify against the committed public key: %v",
				path, err)
			continue
		}
	}
}
