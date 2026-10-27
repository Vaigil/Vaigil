// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

// Package compliance holds the mapping between what this program is and does
// and the control catalogues an assessor reads: SP 800-53 Rev 5 controls, CSF
// 2.0 categories, the AI RMF functions, and — where they genuinely apply —
// OWASP's agentic-application ids and ATT&CK.
//
// # A map, not decoration
//
// A mapping file in a security product is usually a claim nobody can check:
// a spreadsheet of control ids next to feature names, maintained by hand,
// drifting from the product with every release. The two properties that make
// this one different are structural:
//
//   - Every detection entry names a rule that actually ships, and its ATT&CK
//     ids must equal the rule file's own — a join, so the mapping cannot
//     drift from the thing it describes. The test that enforces it lives in
//     this package.
//   - Every entry declares which audit actions evidence it, and those must be
//     strings the program writes: the same test walks the source and fails on
//     an action nobody produces. An evidence query that cannot match a record
//     is a claim about an empty set wearing the clothes of a claim about the
//     estate.
//
// # Empty is legal, absent is not
//
// A tag array may be empty — "considered, none apply" is an answer. It may not
// be missing, because a missing key is a question nobody asked, and the
// difference between the two is the difference between a map and decoration.
// The same rule holds for the actions that evidence an entry: platform
// detections watch events that live in the detection store rather than the
// audit chain, and those entries say so in prose and carry an empty action
// list rather than a query that pretends.
//
// # The vocabularies are closed
//
// Control ids, CSF categories, AI RMF categories, OWASP and ATLAS ids are
// checked against fixed lists, so a typo cannot introduce a control that does
// not exist — the same philosophy as the fixture-refusal in the detection
// engine. The lists carry only ids this project has verified against the
// catalogues (SP 800-53 Rev 5.2.0, CSF 2.0, AI RMF 1.0, the OWASP Agentic Top
// 10 for 2026); the ATLAS column is a closed set of one and is deliberately
// unused, because no detection here observes adversarial ML as such, and an
// unused column is more honest than a decorated one.
package compliance

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The mapping ships in the binary, like the connector catalogue: a file an
// assessor can be handed, and the same bytes the program reasons from, with
// no second copy to drift.
//
//go:embed mapping.json
var mappingJSON []byte

// Schema is the version this package reads and writes.
const Schema = "vaigil/mapping/v1"

// NIST is the catalogues half of an entry's tags.
type NIST struct {
	// Controls are SP 800-53 Rev 5 ids in the catalog's own form, AC-2(3).
	Controls []string `json:"controls"`
	// CSF are CSF 2.0 FUNCTION.CATEGORY codes, PR.AA.
	CSF []string `json:"csf"`
	// AIRMF are AI RMF 1.0 category codes, GV-4.
	AIRMF []string `json:"ai_rmf"`
}

// Evidence says what would demonstrate the entry operating.
type Evidence struct {
	// Actions are audit action patterns whose signed records are the
	// evidence: an exact action, or a trailing * for a family the writer
	// composes (finding.*). Empty means the evidence is not records in the
	// chain, and Proves says what it is instead.
	Actions []string `json:"actions"`
	// Proves is the one-line statement of what a matched record establishes.
	Proves string `json:"proves"`
}

// Entry is one thing this program is or does, tagged.
type Entry struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Title    string   `json:"title"`
	NIST     NIST     `json:"nist"`
	OWASP    []string `json:"owasp_agentic"`
	ATLAS    []string `json:"atlas"`
	Attack   []string `json:"attack"`
	Evidence Evidence `json:"evidence"`
}

// Mapping is the whole document.
type Mapping struct {
	Schema    string            `json:"schema"`
	Generated string            `json:"generated"`
	Catalogs  map[string]string `json:"catalogs"`
	Entries   []Entry           `json:"entries"`
}

// controlsCatalog is the closed list of SP 800-53 Rev 5 ids entries may name.
// Every member is a control this program's design cites; adding one is a
// decision with a control text behind it, not a spelling.
var controlsCatalog = map[string]bool{
	"AC-2": true, "AC-2(3)": true, "AC-2(5)": true, "AC-3": true,
	"AC-4": true, "AC-5": true, "AC-6": true, "AC-6(9)": true,
	"AC-7": true, "AC-12": true,
	"AU-2": true, "AU-3": true, "AU-9": true, "AU-9(5)": true,
	"AU-10": true, "AU-11": true, "AU-12": true,
	"IA-2": true, "IA-2(1)": true, "IA-2(2)": true, "IA-5": true,
	"IA-9": true,
	"IR-4": true, "IR-6": true,
	"RA-5": true, "RA-7": true,
	"SA-15": true, "SA-15(13)": true,
	"SI-2": true, "SI-4": true, "SI-7": true, "SI-19": true,
	"CA-2": true, "CA-7": true,
}

// csfCatalog is the closed list of CSF 2.0 categories.
var csfCatalog = map[string]bool{
	"GV.SC": true, "GV.RR": true, "ID.RA": true, "PR.AA": true,
	"PR.PS": true, "PR.DS": true, "DE.AE": true, "DE.CM": true,
	"RS.AN": true, "RS.CO": true, "RS.MI": true,
}

// aiRMFCatalog is the closed list of AI RMF 1.0 categories. Only the
// categories the design document verified are listed; a longer list would be
// ids copied from memory, which is how the wrong numbering gets in.
var aiRMFCatalog = map[string]bool{
	"GV-4": true, "ME-3": true, "MG-3": true,
}

// owaspCatalog is the closed list of OWASP Agentic Top 10 (2026) ids.
var owaspCatalog = map[string]bool{
	"ASI01": true, "ASI02": true, "ASI03": true,
}

// atlasCatalog is the closed list of MITRE ATLAS technique ids.
var atlasCatalog = map[string]bool{
	"AML.T0051": true,
}

var (
	kindRe    = regexp.MustCompile(`^(detection|feature|soar-action)$`)
	attackRe  = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	actionRe  = regexp.MustCompile(`^[a-z][a-z0-9.-]*\*?$`)
	controlRe = regexp.MustCompile(`^[A-Z]{2}-\d+(\(\d+\))?$`)
)

// Load reads the mapping that ships in the binary.
func Load() (*Mapping, error) {
	return Parse(mappingJSON)
}

// Parse decodes and validates a mapping document.
//
// Validation is the point of the package: an id the catalog does not contain,
// a missing tag array, or an action pattern nobody can match is refused here
// rather than shipped quietly. Errors name the entry, because "invalid
// mapping" sends somebody to read the schema while "entry agents.calls names
// no control the catalog has" sends them to the line.
func Parse(body []byte) (*Mapping, error) {
	var m Mapping
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("the mapping is not readable: %w", err)
	}
	if m.Schema != Schema {
		return nil, fmt.Errorf("the mapping declares schema %q; this reads %q",
			m.Schema, Schema)
	}
	if len(m.Entries) == 0 {
		return nil, fmt.Errorf("the mapping has no entries")
	}
	seen := map[string]bool{}
	for _, e := range m.Entries {
		if strings.TrimSpace(e.ID) == "" {
			return nil, fmt.Errorf("an entry has no id")
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("entry %s appears twice", e.ID)
		}
		seen[e.ID] = true
		if err := validateEntry(e); err != nil {
			return nil, err
		}
	}
	// The tag arrays must be present as well as well-formed, which the typed
	// decode cannot tell: an absent array and an empty one are both nil here.
	// Reading the raw document back for exactly this is cheaper than the
	// alternative of pointer fields on Entry, and it keeps the exported type
	// honest for callers building packs.
	if err := requireKeys(body); err != nil {
		return nil, err
	}
	return &m, nil
}

// validateEntry refuses one entry that cannot be relied on.
func validateEntry(e Entry) error {
	if !kindRe.MatchString(e.Kind) {
		return fmt.Errorf("entry %s has kind %q; detection, feature and "+
			"soar-action are the kinds there are", e.ID, e.Kind)
	}
	if strings.TrimSpace(e.Title) == "" {
		return fmt.Errorf("entry %s has no title", e.ID)
	}
	if len(e.NIST.Controls) == 0 {
		return fmt.Errorf("entry %s names no control. An entry that maps to "+
			"nothing is not an entry", e.ID)
	}
	for _, c := range e.NIST.Controls {
		if !controlRe.MatchString(c) || !controlsCatalog[c] {
			return fmt.Errorf("entry %s names control %s, which is not in "+
				"the catalog this mapping is checked against", e.ID, c)
		}
	}
	for _, c := range e.NIST.CSF {
		if !csfCatalog[c] {
			return fmt.Errorf("entry %s names CSF category %s, which is not "+
				"a CSF 2.0 category this mapping is checked against", e.ID, c)
		}
	}
	for _, c := range e.NIST.AIRMF {
		if !aiRMFCatalog[c] {
			return fmt.Errorf("entry %s names AI RMF category %s, which is "+
				"not an AI RMF 1.0 category this mapping is checked against",
				e.ID, c)
		}
	}
	for _, c := range e.OWASP {
		if !owaspCatalog[c] {
			return fmt.Errorf("entry %s names OWASP id %s, which is not in "+
				"the Agentic Top 10 this mapping is checked against", e.ID, c)
		}
	}
	for _, c := range e.ATLAS {
		if !atlasCatalog[c] {
			return fmt.Errorf("entry %s names ATLAS technique %s, which is "+
				"not in the ATLAS set this mapping is checked against", e.ID, c)
		}
	}
	for _, c := range e.Attack {
		if !attackRe.MatchString(c) {
			return fmt.Errorf("entry %s names ATT&CK id %s, which is not an "+
				"ATT&CK id", e.ID, c)
		}
	}
	if strings.TrimSpace(e.Evidence.Proves) == "" {
		return fmt.Errorf("entry %s says nothing about what its evidence "+
			"proves; an entry without that is a label", e.ID)
	}
	dup := map[string]bool{}
	for _, a := range e.Evidence.Actions {
		if !actionRe.MatchString(a) {
			return fmt.Errorf("entry %s queries action %q, which is not an "+
				"action pattern (lowercase words and dots, an optional "+
				"trailing * for a family)", e.ID, a)
		}
		if dup[a] {
			return fmt.Errorf("entry %s queries action %q twice", e.ID, a)
		}
		dup[a] = true
	}
	return nil
}

// requireKeys fails when a tag array or the evidence object is missing
// outright, which "empty is legal, absent is not" turns on.
func requireKeys(body []byte) error {
	var raw struct {
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return err
	}
	for i, e := range raw.Entries {
		id, _ := e["id"].(string)
		if id == "" {
			id = fmt.Sprintf("entry %d", i+1)
		}
		for _, key := range []string{"id", "kind", "title", "nist",
			"owasp_agentic", "atlas", "attack", "evidence"} {
			if _, ok := e[key]; !ok {
				return fmt.Errorf("%s has no %q key. An absent key is a "+
					"question nobody asked; write an empty array if the "+
					"answer is none", id, key)
			}
		}
		nist, _ := e["nist"].(map[string]any)
		for _, key := range []string{"controls", "csf", "ai_rmf"} {
			if _, ok := nist[key]; !ok {
				return fmt.Errorf("%s has no nist.%q key", id, key)
			}
		}
		ev, _ := e["evidence"].(map[string]any)
		for _, key := range []string{"actions", "proves"} {
			if _, ok := ev[key]; !ok {
				return fmt.Errorf("%s has no evidence.%q key", id, key)
			}
		}
	}
	return nil
}

// Controls lists every control id the mapping names, sorted.
func (m *Mapping) Controls() []string {
	set := map[string]bool{}
	for _, e := range m.Entries {
		for _, c := range e.NIST.Controls {
			set[c] = true
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// EntriesFor returns the entries mapped to one control.
func (m *Mapping) EntriesFor(control string) []Entry {
	var out []Entry
	for _, e := range m.Entries {
		for _, c := range e.NIST.Controls {
			if c == control {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// ActionsFor returns the action patterns that evidence one control: the
// union across its entries, de-duplicated, in the order they were declared.
func (m *Mapping) ActionsFor(control string) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range m.EntriesFor(control) {
		for _, a := range e.Evidence.Actions {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

// MatchAction reports whether an audit action satisfies a pattern.
//
// Exact, or a trailing * for a family the writer composes — finding.* covers
// every state a decision can move a finding to, because the writer builds the
// action from the state and the closed set of states lives in another
// package. Anything looser than a trailing * would let a pattern stand for
// records it has no business gathering.
func MatchAction(pattern, action string) bool {
	if rest, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(action, rest)
	}
	return pattern == action
}
