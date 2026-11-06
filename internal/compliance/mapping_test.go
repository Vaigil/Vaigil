// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/detect"
)

// The shipped mapping is the document an assessor is handed, and the document
// this program reasons from. These tests are the join that keeps it true:
// every detection names a rule that ships with its ATT&CK ids intact, every
// action pattern is a string the program actually writes, and the ids match
// the shapes their catalogues use. A mapping that failed here would still
// parse; it would just be a spreadsheet.

// TestTheShippedMappingIsValid is the floor: the file in the binary parses.
//
// Parse enforces the schema, the closed vocabularies, the no-duplicate rule
// and "empty is legal, absent is not" — the negative tests at the bottom of
// this file prove each of those refusals fires rather than trusting the
// implementation to keep doing it.
func TestTheShippedMappingIsValid(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatalf("the mapping shipped in the binary does not parse: %v", err)
	}
	if len(m.Entries) == 0 {
		t.Fatal("the mapping has no entries")
	}
	seen := map[string]bool{}
	for _, e := range m.Entries {
		if seen[e.ID] {
			t.Errorf("entry %s appears twice", e.ID)
		}
		seen[e.ID] = true
		for _, c := range e.NIST.Controls {
			if !controlRe.MatchString(c) {
				t.Errorf("entry %s names control %s, which is not an SP "+
					"800-53 id of the form XX-N or XX-N(M)", e.ID, c)
			}
		}
	}
	if len(m.Controls()) < 20 {
		t.Fatalf("only %d controls are named; the mapping was probably read "+
			"wrong and a test reading nothing passes", len(m.Controls()))
	}
}

// TestEveryDetectionNamesARuleThatShips is the join on detection ids.
//
// The mapping's detection entries carry the rule's id and its ATT&CK ids. If
// those were typed by hand they would drift — a rule renamed, a technique
// retired — and the mapping would describe detections that do not exist. So
// the ids are read out of the pack the rules ship in and compared for
// equality, in both directions: a mapping entry with no rule is a claim about
// code that is not there, and its ATT&CK column must be the rule's own rather
// than an improvement on it.
func TestEveryDetectionNamesARuleThatShips(t *testing.T) {
	packDir := filepath.Join("..", "..", "internal", "detect", "pack")
	files, err := filepath.Glob(filepath.Join(packDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no pack rules found in %s: %v", packDir, err)
	}
	type rule struct {
		techniques []string
	}
	rules := map[string]rule{}
	for _, f := range files {
		if filepath.Base(f) == detect.ToolLabelsFile {
			// The sensitivity table ships beside the rules and is not one.
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var r struct {
			ID        string   `json:"id"`
			Technique []string `json:"technique"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			t.Fatalf("%s is not a readable rule: %v", f, err)
		}
		if r.ID == "" {
			t.Fatalf("%s carries no id", f)
		}
		rules[r.ID] = rule{techniques: r.Technique}
	}

	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	detections := 0
	for _, e := range m.Entries {
		if e.Kind != "detection" {
			continue
		}
		detections++
		r, ok := rules[e.ID]
		if !ok {
			t.Errorf("mapping entry %s is a detection that ships in no pack. "+
				"A mapping entry about a rule that does not exist is a claim "+
				"nobody can check", e.ID)
			continue
		}
		got := append([]string(nil), e.Attack...)
		want := append([]string(nil), r.techniques...)
		sort.Strings(got)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("mapping entry %s says ATT&CK %v and the rule says %v. "+
				"The mapping joins the rule; retyping the column is how it "+
				"drifts into an improvement on the rule",
				e.ID, e.Attack, r.techniques)
		}
	}
	if detections < 10 {
		t.Fatalf("only %d detection entries; the walk is wrong and a test "+
			"that reads nothing passes", detections)
	}
}

// TestEveryActionIsOneTheProgramWrites is the join on action patterns.
//
// An entry's evidence actions are a query over the audit chain. A pattern no
// writer produces is a query about an empty set wearing the clothes of a
// query about the estate — the pack would build, verify, and prove nothing.
// So every pattern must be traceable to the source.
//
// Most actions are literals at a record call. Some are composed — the log
// writes "auth."+verb from a closed set, and "incident."+a.Do where a.Do is
// one of a switch's cases — so a pattern also passes when its dot-prefix and
// its remainder are each literals, which is exactly the shape a composition
// site leaves behind. Anything looser (substring, any prefix) would let a
// pattern stand for records it has no business gathering.
func TestEveryActionIsOneTheProgramWrites(t *testing.T) {
	literals := map[string]bool{}
	found := 0
	for _, root := range []string{
		filepath.Join("..", "..", "cmd"),
		filepath.Join("..", "..", "internal"),
	} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") ||
				strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if len(lit.Value) >= 2 {
					literals[strings.Trim(lit.Value, `"`)] = true
					found++
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if found < 1000 {
		t.Fatalf("only %d literals were read; the walk is wrong and a test "+
			"that reads nothing passes", found)
	}

	produced := func(action string) bool {
		if literals[action] {
			return true
		}
		if i := strings.LastIndex(action, "."); i > 0 && i < len(action)-1 {
			return literals[action[:i+1]] && literals[action[i+1:]]
		}
		return false
	}

	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	patterns := 0
	for _, e := range m.Entries {
		for _, a := range e.Evidence.Actions {
			patterns++
			pattern := strings.TrimSuffix(a, "*")
			if !produced(pattern) {
				t.Errorf("entry %s queries action %q, and nothing in the "+
					"program writes it. An evidence query that cannot match "+
					"a record is a claim about an empty set wearing the "+
					"clothes of a claim about the estate", e.ID, a)
			}
		}
	}
	if patterns < 30 {
		t.Fatalf("only %d action patterns were checked; the mapping was "+
			"probably read wrong", patterns)
	}
}

// The refusals below are the fail-without-fix half of Parse: each feeds it a
// mapping broken in exactly one way and requires the refusal that way earns.
// They exist because a validator nobody exercises is a validator that stops
// validating the day somebody edits it.

func parseOr(t *testing.T, mutate func(m map[string]any)) error {
	t.Helper()
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	body, _ := json.Marshal(m)
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	mutate(doc)
	body, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(body)
	return err
}

// entry returns a mutable copy of one entry of the raw document.
func entry(t *testing.T, doc map[string]any, id string) map[string]any {
	t.Helper()
	entries, _ := doc["entries"].([]any)
	for _, e := range entries {
		if m, ok := e.(map[string]any); ok && m["id"] == id {
			return m
		}
	}
	t.Fatalf("no entry %s", id)
	return nil
}

func TestParseRefusesADuplicateId(t *testing.T) {
	err := parseOr(t, func(doc map[string]any) {
		// A second entry with the same id and the same tags as the first,
		// so the only thing wrong with the document is the repetition.
		entries, _ := doc["entries"].([]any)
		first, _ := entries[0].(map[string]any)
		cp := map[string]any{}
		for k, v := range first {
			cp[k] = v
		}
		doc["entries"] = append(entries, cp)
	})
	if err == nil || !strings.Contains(err.Error(), "appears twice") {
		t.Errorf("a duplicate id was accepted: %v", err)
	}
}

func TestParseRefusesAControlOutsideTheCatalog(t *testing.T) {
	err := parseOr(t, func(doc map[string]any) {
		e := entry(t, doc, "aertun.signin-failures")
		nist, _ := e["nist"].(map[string]any)
		nist["controls"] = []any{"AC-99"}
	})
	if err == nil || !strings.Contains(err.Error(), "not in the catalog") {
		t.Errorf("an invented control was accepted: %v", err)
	}
}

func TestParseRefusesAnAbsentArray(t *testing.T) {
	err := parseOr(t, func(doc map[string]any) {
		e := entry(t, doc, "aertun.signin-failures")
		delete(e, "attack")
	})
	if err == nil || !strings.Contains(err.Error(), `no "attack" key`) {
		t.Errorf("a missing key was accepted, and empty-only-legal became "+
			"absent-also-legal: %v", err)
	}
}

func TestParseRefusesAnActionPatternThatIsNotOne(t *testing.T) {
	err := parseOr(t, func(doc map[string]any) {
		e := entry(t, doc, "aertun.signin-failures")
		ev, _ := e["evidence"].(map[string]any)
		ev["actions"] = []any{"auth.*.failures"}
	})
	if err == nil || !strings.Contains(err.Error(), "not an action pattern") {
		t.Errorf("a wilder pattern than a trailing * was accepted: %v", err)
	}
}

func TestParseRefusesAnEntryThatProvesNothing(t *testing.T) {
	err := parseOr(t, func(doc map[string]any) {
		e := entry(t, doc, "aertun.signin-failures")
		ev, _ := e["evidence"].(map[string]any)
		ev["proves"] = ""
	})
	if err == nil || !strings.Contains(err.Error(), "nothing about what its evidence proves") {
		t.Errorf("an entry with no proves line was accepted: %v", err)
	}
}

func TestMatchActionCoversExactAndFamily(t *testing.T) {
	if !MatchAction("finding.*", "finding.accepted") {
		t.Error("finding.* must cover the states the writer composes")
	}
	if MatchAction("finding.*", "finding") {
		t.Error("a family pattern is a prefix of composed actions, not a " +
			"match for the bare word")
	}
	if MatchAction("finding.*", "findingx.accepted") {
		t.Error("the * stops at the dot the writer composes after")
	}
	if !MatchAction("dual.approved", "dual.approved") {
		t.Error("an exact pattern matches itself")
	}
	if MatchAction("dual.approved", "dual.approve") {
		t.Error("an exact pattern is not a prefix")
	}
}
