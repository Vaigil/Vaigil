// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/out"
)

// The command surface over the compliance package: the map, the pack, and
// the offline check, exercised against a real store directory the way an
// operator would drive them.

// seedComplianceStore builds a store whose audit log holds AC-5 records and
// an unrelated token issue, with the pseudonymisation key in the place this
// program's own writer looks for it.
func seedComplianceStore(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	key := bytes.Repeat([]byte{1}, 32)
	if err := os.WriteFile(filepath.Join(root, "audit.key"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := audit.New(audit.Options{
		Path:   filepath.Join(root, "audit.jsonl"),
		Key:    key,
		Source: "aertun-test@host",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []audit.Record{
		{Action: "token.issue", Resource: "/", Outcome: audit.Success,
			Principal: "ada", Kind: audit.KindHuman, Verified: true},
		{Action: "dual.proposed", Resource: "/pending/1", Outcome: audit.Success,
			Principal: "ada", Kind: audit.KindHuman, Verified: true},
		{Action: "dual.approved", Resource: "/pending/1", Outcome: audit.Success,
			Principal: "ben", Kind: audit.KindHuman, Verified: true},
	} {
		if _, err := l.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// captureOutput points the process writer at a buffer and returns it, so a
// test can read what a command printed without inheriting whatever mode the
// test before it left. (contentcmd_test.go's capture runs a function; this
// one hands the buffer back, which is the shape these tests need.)
func captureOutput(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	w = out.New(false)
	w.Out = buf
	return buf
}

func TestComplianceControlsListsTheMap(t *testing.T) {
	buf := captureOutput(t)
	if err := cmdCompliance("", []string{"controls"}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	// A control the mapping covers, and an entry under it — the two things
	// somebody reading this list is looking for.
	if !strings.Contains(got, "AC-5") || !strings.Contains(got, "dual.control") {
		t.Errorf("the controls listing does not show AC-5 and its entries:\n%s", got)
	}
	// Sorted, so two versions of the mapping diff cleanly.
	if strings.Index(got, "AC-2") > strings.Index(got, "AC-5") {
		t.Errorf("the controls are not in order:\n%s", got)
	}
}

func TestComplianceControlsIsInTheUsableShape(t *testing.T) {
	buf := captureOutput(t)
	if err := cmdCompliance("", []string{"controls"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "aertun compliance evidence AC-2") {
		t.Errorf("the listing does not say how to get evidence for a "+
			"control:\n%s", buf.String())
	}
}

func TestComplianceEvidenceWritesAPackThatVerifies(t *testing.T) {
	root := seedComplianceStore(t)
	captureOutput(t)
	packPath := filepath.Join(root, "ac5.json")
	if err := cmdCompliance(root, []string{"evidence", "AC-5",
		"--out", packPath}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"control": "AC-5"`) {
		t.Errorf("the pack on disk is not about AC-5:\n%s", body)
	}

	// The offline check, first with the store's published keys and then
	// with them named, which is the auditor's spelling.
	buf := captureOutput(t)
	if err := cmdCompliance(root, []string{"verify", packPath}); err != nil {
		t.Fatalf("the pack this command wrote does not verify: %v", err)
	}
	if !strings.Contains(buf.String(), "verified") {
		t.Errorf("the verification output does not say so:\n%s", buf.String())
	}
	if err := cmdCompliance(root, []string{"verify", packPath,
		"--keys", headKeysPath(root)}); err != nil {
		t.Fatalf("verification with --keys failed: %v", err)
	}
}

func TestComplianceEvidencePrintsThePackWithoutOut(t *testing.T) {
	root := seedComplianceStore(t)
	buf := captureOutput(t)
	if err := cmdCompliance(root, []string{"evidence", "AC-5"}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, `"schema": "aertun/evidence/v1"`) ||
		!strings.Contains(got, `"dual.proposed"`) {
		t.Errorf("stdout did not carry the document:\n%s", got)
	}
}

func TestComplianceEvidenceRefusesAnUnmappedControl(t *testing.T) {
	root := seedComplianceStore(t)
	captureOutput(t)
	err := cmdCompliance(root, []string{"evidence", "IR-8"})
	if err == nil {
		t.Fatal("a pack was generated for a control the mapping does not cover")
	}
	msg := err.Error()
	if !strings.Contains(msg, "IR-8") {
		t.Errorf("the refusal does not name the control: %s", msg)
	}
	if !strings.Contains(msg, "aertun compliance controls") {
		t.Errorf("the refusal does not say where the covered controls are: %s", msg)
	}
}

func TestComplianceVerifyRefusesATamperedPack(t *testing.T) {
	root := seedComplianceStore(t)
	captureOutput(t)
	packPath := filepath.Join(root, "ac5.json")
	if err := cmdCompliance(root, []string{"evidence", "AC-5",
		"--out", packPath}); err != nil {
		t.Fatal(err)
	}
	// Same length, clean splice: the record's action is changed and its
	// hash stays, which is what a doctored export looks like.
	body, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	doctored := bytes.ReplaceAll(body,
		[]byte("dual.proposed"), []byte("dual.approved"))
	if bytes.Equal(doctored, body) {
		t.Fatal("the splice matched nothing, so this test checked nothing")
	}
	if err := os.WriteFile(packPath, doctored, 0o600); err != nil {
		t.Fatal(err)
	}
	captureOutput(t)
	err = cmdCompliance(root, []string{"verify", packPath})
	if err == nil {
		t.Fatal("a tampered pack was accepted")
	}
	if !strings.Contains(err.Error(), "record") {
		t.Errorf("the refusal does not point at the record: %s", err.Error())
	}
}

// An empty control is a written pack that verifies, not a refusal and not a
// blank page: the operator hands over the document that says what would have
// been there.
func TestComplianceEvidenceForAControlWithNoRecords(t *testing.T) {
	root := seedComplianceStore(t)
	captureOutput(t)
	packPath := filepath.Join(root, "ia2.json")
	if err := cmdCompliance(root, []string{"evidence", "IA-2",
		"--out", packPath}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(packPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"satisfies"`)) {
		t.Errorf("the empty pack does not say what would satisfy the "+
			"control:\n%s", body)
	}
	captureOutput(t)
	if err := cmdCompliance(root, []string{"verify", packPath}); err != nil {
		t.Fatalf("an honest empty pack does not verify: %v", err)
	}
}

func TestComplianceUsageIsRefusedRatherThanGuessed(t *testing.T) {
	captureOutput(t)
	for _, args := range [][]string{
		{"evidence"},
		{"evidence", "--out", "/tmp/x"},
		{"verify"},
		{"nonsense"},
		{},
	} {
		if err := cmdCompliance("", args); err == nil {
			t.Errorf("%v was accepted with nothing to do", args)
		}
	}
}
