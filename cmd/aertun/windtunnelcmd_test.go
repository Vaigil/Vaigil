// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/out"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/windtunnel"
)

// windtunnelOutput points the program's writer at a buffer, so a test can
// read what a command actually rendered. Restored on cleanup, because w is
// the one writer every command shares.
func windtunnelOutput(t *testing.T) *strings.Builder {
	t.Helper()
	buf := &strings.Builder{}
	old := w
	w = &out.Writer{Out: buf}
	t.Cleanup(func() { w = old })
	return buf
}

// No bare word starts anything: the one subcommand that writes a scratch
// spool and a signed document never starts because a word was typed, and an
// unknown word is told the five that exist.
func TestWindtunnelBareWordAndUnknownSubcommandRefuse(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	err := cmdWindtunnel(root, nil)
	if err == nil || !strings.Contains(err.Error(), "needs list-scenarios") {
		t.Fatalf("a bare windtunnel gave %v; the bare word must name what it "+
			"wants", err)
	}
	err = cmdWindtunnel(root, []string{"detonate"})
	if err == nil || !strings.Contains(err.Error(), "unknown windtunnel command") {
		t.Fatalf("an unknown subcommand gave %v", err)
	}
}

// list-scenarios names the corpus: ids, families, safety classes and the
// twin every scenario ships — the screen an operator reads before choosing
// what to run.
func TestWindtunnelListScenariosNamesTheCorpus(t *testing.T) {
	buf := windtunnelOutput(t)
	if err := cmdWindtunnel(t.TempDir(), []string{"list-scenarios"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"agent.trifecta-mailroom-exfil",
		"agent.mcp-rug-pull",
		"agent.injection-hijack-via-issue",
		"agent.slopsquat-install",
		"agent.recorder-blind-window",
		"agent.cost-bomb-loop",
		"agent.refund-flow-normal", // a twin, named as one
		"synthetic-only",           // the safety class, stated
		windtunnel.CorpusName,
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("list-scenarios never says %q; choosing what to run "+
				"needs the names", want)
		}
	}
}

// preflight checks without splicing: it holds over the default stream for a
// scenario that belongs there, demands the --scenario it is meaningless
// without, and refuses an id nothing carries.
func TestWindtunnelPreflightHoldsAndRefusesByName(t *testing.T) {
	buf := windtunnelOutput(t)
	root := t.TempDir()
	if err := cmdWindtunnel(root, []string{"preflight", "--scenario",
		"agent.trifecta-mailroom-exfil"}); err != nil {
		t.Fatalf("the trifecta's preflight over the default stream failed: %v",
			err)
	}
	if !strings.Contains(buf.String(), "every check held") {
		t.Errorf("a held preflight does not say so: %q", buf.String())
	}

	err := cmdWindtunnel(root, []string{"preflight"})
	if err == nil || !strings.Contains(err.Error(), "needs --scenario") {
		t.Fatalf("a preflight with no scenario gave %v", err)
	}
	err = cmdWindtunnel(root, []string{"preflight", "--scenario", "x"})
	if err == nil || !strings.Contains(err.Error(), "no scenario called") {
		t.Fatalf("an unknown scenario id gave %v", err)
	}
}

// A run writes a document that verifies, names what ran, and says it is
// unsigned when no key was supplied — the honest default, because an
// unsigned document makes no claim a signature would back.
func TestWindtunnelRunWritesASealedScorecard(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	doc := filepath.Join(root, "scorecard.json")
	if err := cmdWindtunnel(root, []string{"run", "--out", doc}); err != nil {
		t.Fatalf("a corpus run over the default stream failed: %v", err)
	}
	b, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	var card windtunnel.Scorecard
	if err := json.Unmarshal(b, &card); err != nil {
		t.Fatal(err)
	}
	if err := card.Verify(); err != nil {
		t.Fatalf("the document a run wrote does not verify: %v", err)
	}
	if card.Signature != nil {
		t.Error("a run without --key wrote a signature; the document must " +
			"say unsigned, not dress an unsigned run up")
	}
	if card.Schema != windtunnel.DocSchema || card.Mode != "replay" ||
		card.ScoreMode != "reference" {
		t.Errorf("schema %q mode %q scoring %q; the document names what ran "+
			"before how it went", card.Schema, card.Mode, card.ScoreMode)
	}
	if len(card.Rows) != 6 || card.Aggregate.TwinFires != 0 {
		t.Errorf("%d rows, %d twin fires; the whole corpus ran", len(card.Rows),
			card.Aggregate.TwinFires)
	}
}

// scorecard renders a document a run wrote and refuses one that was edited
// after the fact — the digest is the only thing standing between a rendered
// number and a number somebody typed in.
func TestWindtunnelScorecardRendersAndRefusesAnEdit(t *testing.T) {
	buf := windtunnelOutput(t)
	root := t.TempDir()
	doc := filepath.Join(root, "scorecard.json")
	if err := cmdWindtunnel(root, []string{"run", "--scenario",
		"agent.cost-bomb-loop", "--out", doc}); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := cmdWindtunnel(root, []string{"scorecard", doc}); err != nil {
		t.Fatalf("rendering the document a run wrote failed: %v", err)
	}
	if !strings.Contains(buf.String(), "missed 0 of 1 must-alert") {
		t.Errorf("the render does not state the aggregate: %q", buf.String())
	}

	b, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(b), `"missed": 0`, `"missed": 1`, 1)
	if edited == string(b) {
		t.Fatal("the edit found nothing to change; the test must be written " +
			"against the document as written")
	}
	if err := os.WriteFile(doc, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	err = cmdWindtunnel(root, []string{"scorecard", doc})
	if err == nil || !strings.Contains(err.Error(), "edited since it was written") {
		t.Fatalf("an edited scorecard rendered (%v); every figure quoted from "+
			"a document must be pinned to the file it came from", err)
	}
}

// The signing and verifying path, end to end through the command, offline
// and store-free: a run signs with a key the operator named, publishes the
// public half beside the document, and a verifier holding those two files
// and nothing else — no store, no deployment — verifies both signatures.
// And the forgeries refuse: an unsigned document, an edited one, a foreign
// key, and a verify asked to trust the document's own say-so.
func TestWindtunnelVerifyIsOfflineStoreFreeAndRefusesForgeries(t *testing.T) {
	buf := windtunnelOutput(t)
	// The store root is an empty directory the whole way through, and the
	// test finishes by proving nothing was written into it.
	root := t.TempDir()
	work := t.TempDir()
	keyPath := filepath.Join(work, "scorecard-key.json")
	k, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := pack.SaveKey(keyPath, k, 0o600); err != nil {
		t.Fatal(err)
	}

	card := filepath.Join(work, "scorecard.json")
	pub := filepath.Join(work, "scorecard-pub.json")
	if err := cmdWindtunnel(root, []string{"run",
		"--scenario", "agent.trifecta-mailroom-exfil",
		"--key", keyPath, "--out", card, "--public-key", pub}); err != nil {
		t.Fatalf("a signed run failed: %v", err)
	}
	if _, err := os.Stat(pub); err != nil {
		t.Fatalf("the public half was not published: %v", err)
	}

	buf.Reset()
	// Flags before the file, the way every flag-then-argument command here
	// reads its command line.
	if err := cmdWindtunnel(root, []string{"verify", "--key", pub, card}); err != nil {
		t.Fatalf("offline verify failed: %v", err)
	}
	if !strings.Contains(buf.String(), "both signatures hold") {
		t.Errorf("verify does not say what it checked: %q", buf.String())
	}

	// No key named: the verifier is told what verification needs.
	err = cmdWindtunnel(root, []string{"verify", card})
	if err == nil || !strings.Contains(err.Error(), "verify needs --key") {
		t.Fatalf("verify without a key gave %v", err)
	}

	// A foreign key refuses: the signature names the key that made it.
	foreign, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	foreignPub := filepath.Join(work, "foreign-pub.json")
	if err := windtunnel.WritePublicKey(foreignPub, foreign.PublicKey()); err != nil {
		t.Fatal(err)
	}
	err = cmdWindtunnel(root, []string{"verify", "--key", foreignPub, card})
	if err == nil || !strings.Contains(err.Error(), "signed by key") {
		t.Fatalf("a foreign public key verified the document (%v)", err)
	}

	// An edited document refuses, digest before signature.
	b, err := os.ReadFile(card)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(b), `"caught-alert"`,
		`"caught-telemetry"`, 1)
	if tampered == string(b) {
		t.Fatal("the edit found nothing to change; the test must be written " +
			"against the document as written")
	}
	tamperedPath := filepath.Join(work, "tampered.json")
	if err := os.WriteFile(tamperedPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	err = cmdWindtunnel(root, []string{"verify", "--key", pub, tamperedPath})
	if err == nil || !strings.Contains(err.Error(), "edited since it was written") {
		t.Fatalf("an edited, signed scorecard verified (%v)", err)
	}

	// An unsigned document refuses with its reason.
	unsigned := filepath.Join(work, "unsigned.json")
	if err := cmdWindtunnel(root, []string{"run", "--scenario",
		"agent.cost-bomb-loop", "--out", unsigned}); err != nil {
		t.Fatal(err)
	}
	err = cmdWindtunnel(root, []string{"verify", "--key", pub, unsigned})
	if err == nil || !strings.Contains(err.Error(), "carries no signature") {
		t.Fatalf("an unsigned document verified (%v)", err)
	}

	// And the store root stayed empty: no subcommand opened a store, which
	// is what makes the whole command CI-runnable.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the wind tunnel wrote %d entr(y/ies) into the store root; "+
			"replay needs no store and must not leave marks in one", len(entries))
	}
}

// The refusals the library makes are the refusals the command surfaces: a
// live endpoint where a stream path belongs, and the phase-2 scoring modes
// named as phase 2 rather than half-run.
func TestWindtunnelRunRefusesLiveTargetsAndPhaseTwoScoring(t *testing.T) {
	windtunnelOutput(t)
	root := t.TempDir()
	err := cmdWindtunnel(root, []string{"run", "--over",
		"https://staging.example.internal:4318"})
	if err == nil || !strings.Contains(err.Error(), "live endpoint") {
		t.Fatalf("a URL as --over gave %v; replay is the safety story, and "+
			"the refusal is in code", err)
	}
	err = cmdWindtunnel(root, []string{"run", "--score", "their-sigma:./rules"})
	if err == nil || !strings.Contains(err.Error(), "phase 2") {
		t.Fatalf("a phase-2 scoring mode gave %v; it must be refused with its "+
			"phase rather than half-run", err)
	}
	// And --public-key without --key is a contradiction, not a courtesy.
	err = cmdWindtunnel(root, []string{"run", "--public-key", "x.json"})
	if err == nil || !strings.Contains(err.Error(), "needs --key") {
		t.Fatalf("publishing the public half of nothing gave %v", err)
	}
}
