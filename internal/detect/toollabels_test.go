// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"strings"
	"testing"
)

// The tool-label table: a declaration somebody reviews, refused when it
// cannot be reviewed, and matched the way the ingest boundary stamps it —
// case folded, sorted, joined, or nothing at all.

// table is a one-entry table with the parts a test wants to vary, so each
// refusal below reads as the mistake it is rather than as JSON ceremony.
func table(tool string, labels []string, why string) []byte {
	quoted := make([]string, len(labels))
	for i, l := range labels {
		quoted[i] = `"` + l + `"`
	}
	return []byte(`{"tools":[{"tool":"` + tool + `","labels":[` +
		strings.Join(quoted, ",") + `],"why":"` + why + `"}]}`)
}

// TestTheShippedTableParsesAndDeclaresItsTools.
//
// The table the pack ships is the declaration the trifecta's three legs
// stand on: it has to parse, every label it carries has to be one of the
// closed set, and the tools its rules' fixtures name have to be declared —
// a table that silently stopped declaring fetch would take the first leg
// out of every chain without anything refusing.
func TestTheShippedTableParsesAndDeclaresItsTools(t *testing.T) {
	files, err := Pack()
	if err != nil {
		t.Fatal(err)
	}
	var body []byte
	for _, f := range files {
		if f.Name == ToolLabelsFile {
			body = f.Body
		}
	}
	if body == nil {
		t.Fatalf("the pack ships no %s", ToolLabelsFile)
	}
	labels, err := ParseToolLabels(body)
	if err != nil {
		t.Fatalf("the shipped table was refused: %v", err)
	}
	closed := map[string]bool{}
	for _, l := range ToolLabelsSet() {
		closed[l] = true
	}
	for _, tool := range labels.Tools() {
		for _, l := range strings.Split(labels.DeclaredFor(tool), ",") {
			if !closed[l] {
				t.Errorf("%s carries %q, which the closed set does not hold",
					tool, l)
			}
		}
	}
	// The legs the pack's own fixtures name: the fetcher, the mailbox that
	// carries two labels at once, and the query against private data.
	for tool, want := range map[string]string{
		"fetch":     "untrusted-content",
		"read_mail": "sensitive-data,untrusted-content",
		"sql_query": "sensitive-data",
		"http_post": "egress",
	} {
		if got := labels.DeclaredFor(tool); got != want {
			t.Errorf("%s carries %q, want %q", tool, got, want)
		}
	}
	// A tool nobody declared is nothing, not an error and not an empty
	// declaration — the honest miss the boundary stamps as silence.
	if got := labels.DeclaredFor("filesystem.write"); got != "" {
		t.Errorf("an undeclared tool carries %q", got)
	}
}

// TestAToolLabelsTableIsRefusedWhenItCannotBeReviewed.
//
// Every refusal is a way a table would silently declare less than it says:
// a label nobody defined, a tool the boundary could never match, a decision
// with no reason, an entry that disagrees with itself. The refusal has to
// say which, because the person it stops is editing a file by hand.
func TestAToolLabelsTableIsRefusedWhenItCannotBeReviewed(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		why  string
	}{
		{"a label outside the closed set",
			table("fetch", []string{"untrusted-content", "reads-the-web"},
				"why not"), `"reads-the-web"`},
		{"an entry naming no tool",
			table("", []string{"untrusted-content"}, "why not"), "names no tool"},
		{"a tool with padding around it",
			table(" fetch", []string{"untrusted-content"}, "why not"),
			"one token"},
		{"a tool with a space inside it",
			table("web fetch", []string{"untrusted-content"}, "why not"),
			"one token"},
		{"a decision with no why",
			table("fetch", []string{"untrusted-content"}, ""), "no why"},
		{"an entry that labels nothing",
			table("fetch", nil, "why not"), "declares no labels"},
		{"the same label twice",
			table("fetch", []string{"egress", "egress"}, "why not"), "twice"},
		{"a hand-edited field name nobody defined",
			[]byte(`{"tools":[{"tool":"fetch","lables":["egress"],"why":"x"}]}`),
			"not readable"},
		{"a file that is not JSON at all",
			[]byte("{"), "not readable"},
		{"a table declaring the same tool twice",
			[]byte(`{"tools":[` +
				`{"tool":"fetch","labels":["untrusted-content"],"why":"a"},` +
				`{"tool":"fetch","labels":["egress"],"why":"b"}]}`),
			"declared twice"},
		{"a table declaring a tool twice across case",
			[]byte(`{"tools":[` +
				`{"tool":"fetch","labels":["untrusted-content"],"why":"a"},` +
				`{"tool":"FETCH","labels":["egress"],"why":"b"}]}`),
			"declared twice"},
	}
	for _, c := range cases {
		_, err := ParseToolLabels(c.body)
		if err == nil {
			t.Errorf("%s: the table was accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: the refusal says %q, not %q", c.name, err, c.why)
		}
	}
}

// TestALabelIsStampedCaseFoldedSortedAndJoined.
//
// The same SDK spells the same tool's name with different casing across
// runs, so the lookup folds case — treating FETCH and fetch as two tools is
// a silent miss, not precision. What is stamped is the sorted, comma-joined
// form every event of that tool then carries identically.
func TestALabelIsStampedCaseFoldedSortedAndJoined(t *testing.T) {
	labels, err := ParseToolLabels(table("read_mail",
		[]string{"untrusted-content", "sensitive-data"}, "a mailbox"))
	if err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{"read_mail", "READ_MAIL", "Read_Mail"} {
		if got := labels.DeclaredFor(spelling); got != "sensitive-data,untrusted-content" {
			t.Errorf("%s carries %q, want both labels sorted and joined",
				spelling, got)
		}
	}
	if got := labels.DeclaredFor("send_mail"); got != "" {
		t.Errorf("a tool the table does not name carries %q", got)
	}
}

// TestAnAbsentTableDeclaresNothing.
//
// The absent-file answer is the zero table: nothing stamped, nothing
// joined, no leg fabricated. An empty file is the same declaration as no
// file, and the difference between the two is not one this boundary gets
// to act on.
func TestAnAbsentTableDeclaresNothing(t *testing.T) {
	labels, err := ParseToolLabels([]byte(`{}`))
	if err != nil {
		t.Fatalf("an empty table was refused: %v", err)
	}
	if got := labels.DeclaredFor("fetch"); got != "" {
		t.Errorf("an empty table stamped %q", got)
	}
	if tools := labels.Tools(); len(tools) != 0 {
		t.Errorf("an empty table declares %v", tools)
	}
	// The zero value, which is what a missing file parses to.
	if got := (ToolLabels{}).DeclaredFor("fetch"); got != "" {
		t.Errorf("a table never read stamped %q", got)
	}
}

// TestTheClosedSetIsTheChainInOrder.
//
// Three labels, one per leg of the chain, in the order the chain reads
// them. A fourth label is a vocabulary nobody can triage, and a set that
// quietly grew one is a rule waiting to be written against a word nobody
// defined.
func TestTheClosedSetIsTheChainInOrder(t *testing.T) {
	want := []string{"untrusted-content", "sensitive-data", "egress"}
	got := ToolLabelsSet()
	if len(got) != len(want) {
		t.Fatalf("the closed set holds %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("the closed set holds %v, want %v", got, want)
			break
		}
	}
	// The list is a copy: a caller editing it cannot bend the answer the
	// next caller gets.
	got[0] = "reads-the-web"
	for _, l := range ToolLabelsSet() {
		if l == "reads-the-web" {
			t.Error("the closed set was handed out by reference")
		}
	}
}
