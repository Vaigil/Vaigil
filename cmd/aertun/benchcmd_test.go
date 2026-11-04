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

	"github.com/aertun/aertun/internal/bench"
	"github.com/aertun/aertun/internal/decide"
	"github.com/aertun/aertun/internal/out"
)

// benchOutput points the program's writer at a buffer, so a test can read
// what a command actually rendered. Restored on cleanup, because w is the
// one writer every command shares.
func benchOutput(t *testing.T) *strings.Builder {
	t.Helper()
	buf := &strings.Builder{}
	old := w
	w = &out.Writer{Out: buf}
	t.Cleanup(func() { w = old })
	return buf
}

// A stub run, end to end through the command: it writes a document that
// verifies, names the corpus it ran and the stub that ran it, and carries
// the digest of the corpus the program actually shipped — the three names a
// number needs beside it before it can be compared to anything.
func TestBenchStubRunWritesAVerifiedDocument(t *testing.T) {
	benchOutput(t)
	root := t.TempDir()
	doc := filepath.Join(root, "results.json")
	if err := cmdBench(root, []string{"run", "--stub", "--out", doc}); err != nil {
		t.Fatalf("a stub run failed: %v", err)
	}
	b, err := os.ReadFile(doc)
	if err != nil {
		t.Fatalf("no document was written: %v", err)
	}
	var res bench.Results
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatalf("the document does not parse: %v", err)
	}
	if err := res.Verify(); err != nil {
		t.Errorf("the document does not verify: %v", err)
	}
	if res.Mode != bench.ModeStub {
		t.Errorf("mode is %q, not stub: a document must not dress a stub "+
			"run up as a measurement", res.Mode)
	}
	if res.Model != "bench-stub" {
		t.Errorf("model is %q", res.Model)
	}
	if res.CorpusDigest != bench.CorpusDigest() {
		t.Errorf("the document cites corpus %s and the program carries %s",
			res.CorpusDigest, bench.CorpusDigest())
	}
	if res.Counts.Cases != 48 {
		t.Errorf("%d cases ran", res.Counts.Cases)
	}
}

// Model mode goes through the same seam the analyst does — and refuses with
// the analyst's own message when nothing is configured, rather than a new
// one written here that would drift from it.
func TestBenchModelModeUsesTheAnalystSeamAndRefusesWithoutAModel(t *testing.T) {
	benchOutput(t)
	old := analystSeam
	analystSeam = func(string) (decide.Model, string) {
		return nil, "no model is configured: set AERTUN_MODEL"
	}
	t.Cleanup(func() { analystSeam = old })
	root := t.TempDir()
	err := cmdBench(root, []string{"run"})
	if err == nil || !strings.Contains(err.Error(), "no model is configured") {
		t.Fatalf("model mode with no model gave %v, and the honest "+
			"refusal is the analyst's own message", err)
	}

	// The seam returning a model is the configured-model path: the
	// document's mode says model, and the model named is the seam's.
	analystSeam = func(string) (decide.Model, string) {
		return &bench.Stub{}, ""
	}
	doc := filepath.Join(root, "m.json")
	if err := cmdBench(root, []string{"run", "--k", "1", "--out", doc}); err != nil {
		t.Fatalf("the seam's model did not run: %v", err)
	}
	b, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	var res bench.Results
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	if res.Mode != bench.ModeModel {
		t.Errorf("mode is %q, not model", res.Mode)
	}
	if res.Model != "bench-stub" {
		t.Errorf("the document names %q rather than the seam's model",
			res.Model)
	}
	if res.K != 1 {
		t.Errorf("k is %d, not the 1 asked for", res.K)
	}
}

// report renders a document a run wrote, and refuses one that was edited
// after the fact: the digest is the only thing standing between a rendered
// number and a number somebody typed in.
func TestBenchReportRendersAndRefusesEditedDocuments(t *testing.T) {
	buf := benchOutput(t)
	root := t.TempDir()
	doc := filepath.Join(root, "results.json")
	if err := cmdBench(root, []string{"run", "--stub", "--k", "1",
		"--out", doc}); err != nil {
		t.Fatal(err)
	}
	if err := cmdBench(root, []string{"report", doc}); err != nil {
		t.Fatalf("a document a run wrote does not render: %v", err)
	}
	rendered := buf.String()
	for _, want := range []string{"aertunbench-v0", "Wilson", "hijacked"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the report does not show %q:\n%s", want, rendered)
		}
	}

	// The same bytes with one number typed in must be refused, and the
	// refusal must say the document was edited rather than blaming the
	// file's shape.
	var res bench.Results
	b, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatal(err)
	}
	res.Reliable++
	spoiled := filepath.Join(root, "spoiled.json")
	sb, err := res.Document()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spoiled, sb, 0o600); err != nil {
		t.Fatal(err)
	}
	err = cmdBench(root, []string{"report", spoiled})
	if err == nil || !strings.Contains(err.Error(), "edited") {
		t.Errorf("an edited document rendered (%v); the digest is meant to "+
			"be the thing that stops exactly this", err)
	}

	if err := cmdBench(root, []string{"report"}); err == nil {
		t.Errorf("report without a file did something")
	}
	if err := cmdBench(root, []string{"run", "--k", "0"}); err == nil {
		t.Errorf("k=0 was accepted")
	}
	if err := cmdBench(root, nil); err == nil {
		t.Errorf("a bare bench did something rather than naming its " +
			"subcommands")
	}
}
