// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// The sensitivity labels a tool may carry, and the table that declares them.
//
// The lethal trifecta (catalogue B2: untrusted read → sensitive read →
// egress, one session) is a chain over what a tool *is*, not what one call's
// arguments happened to say — a fetch of a public issue and a fetch of a
// private repo are the same operation on different arguments, and arguments
// are attacker-influenced text this event model refuses to read. The honest
// unit is the tool: whoever runs the agent knows whether its fetch tool
// reads the open web and whether its mail tool reads a private mailbox, and
// that knowledge is a declaration, the same one the AI-BOM and the agent
// registry already ask for. So the labels are data: a table shipped with the
// pack, installed as files beside the rules, tuned by the organisation, and
// stamped onto events at the ingest boundary (cmd/aeroprove's OTLP path) so a
// rule can ask about them without any rule having to infer anything.
//
// The set is closed because a label nobody defined is a label nobody can
// triage: "what did this tool do" has to have a finite vocabulary or the
// answer is prose. Three labels, one per leg of the chain:
const (
	// LabelUntrustedContent is a tool whose returned text the organisation
	// did not write: web pages, search results, issue bodies, inbound mail.
	// The injection vector of the whole chain — instructions ride in as
	// content.
	LabelUntrustedContent = "untrusted-content"
	// LabelSensitiveData is a tool that reads private data: repositories,
	// documents, the warehouse, mail others sent, secret stores.
	LabelSensitiveData = "sensitive-data"
	// LabelEgress is a tool that sends data outward: an HTTP POST, a mail
	// send, a webhook.
	LabelEgress = "egress"
)

// toolLabelSet is the closed set, in the order the chain reads them.
var toolLabelSet = []string{LabelUntrustedContent, LabelSensitiveData, LabelEgress}

// ToolLabelsSet lists every label a table may declare.
func ToolLabelsSet() []string {
	return append([]string(nil), toolLabelSet...)
}

// knownToolLabel says whether s is one of the closed set.
func knownToolLabel(s string) bool {
	for _, l := range toolLabelSet {
		if s == l {
			return true
		}
	}
	return false
}

// ToolLabelsFile is the table's file name, in the pack and then in the rules
// directory it is installed into. Named here because two readers have to
// agree on it: the ingest boundary that loads it, and the loaders that walk
// the same directory for rules and must step over it.
const ToolLabelsFile = "tool-labels.json"

// ToolLabel is one entry: a tool, the labels it carries, and why.
type ToolLabel struct {
	// Tool is the OTel GenAI tool name — the exact value an SDK writes to
	// gen_ai.tool.name and this event model keeps as raw.tool. Exact,
	// because a pattern would be an inference wearing a declaration's
	// clothes; compared case-folded, because the same SDK spells the same
	// tool's name with different casing across runs and treating them as
	// two tools is a silent miss, not precision.
	Tool string `json:"tool"`
	// Labels from the closed set. A tool may carry several: a mailbox read
	// is untrusted (anybody can send to it) and sensitive (it holds private
	// correspondence) at once.
	Labels []string `json:"labels"`
	// Why says what the tool is, so a reviewer of the table can disagree
	// with the declaration rather than discover it from a finding.
	Why string `json:"why"`
}

// toolLabelsFile is the stored document: a list, sorted by tool, so the file
// reads like the tool inventory it describes and diffs like a declaration
// rather than a cache.
type toolLabelsFile struct {
	Tools []ToolLabel `json:"tools"`
}

// ToolLabels is a parsed table. The zero value declares nothing, which is
// the absent-file answer: nothing stamped, nothing joined, and the chain
// that needed a label quietly cannot fire — honest, because the alternative
// is a program guessing at tools it was never told about.
type ToolLabels struct {
	// declared maps each lower-cased tool name to its labels, joined with
	// commas in sorted order — the exact string the boundary stamps into
	// raw.labels, prepared once here so every event stamps the same tool
	// the same way.
	declared map[string]string
}

// ParseToolLabels reads and refuses a tool-label table.
//
// Every refusal is a way a table would silently declare nothing: a tool name
// the boundary could never match, a label from outside the closed set, the
// same tool declared twice, an entry that labels nothing, a decision with no
// why. A table that cannot be reviewed cannot be trusted, and the honest
// time to say so is when it is read — the same line the recorder-host
// mapping draws.
func ParseToolLabels(body []byte) (ToolLabels, error) {
	var f toolLabelsFile
	dec := json.NewDecoder(bytes.NewReader(body))
	// Unknown fields refused: a hand-edited "lables" would otherwise be
	// skipped quietly and the entry would declare less than it says.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return ToolLabels{}, fmt.Errorf("the tool-label table is not "+
			"readable: %w", err)
	}
	t := ToolLabels{declared: map[string]string{}}
	for i, e := range f.Tools {
		name := strings.TrimSpace(e.Tool)
		if name == "" {
			return ToolLabels{}, fmt.Errorf("tool entry %d names no tool. "+
				"An entry is the OTel gen_ai.tool.name value, spelled the "+
				"way the SDK writes it", i+1)
		}
		if name != e.Tool || strings.ContainsAny(e.Tool, " \t") {
			return ToolLabels{}, fmt.Errorf("%q is not a tool name the "+
				"boundary could match: gen_ai.tool.name is one token with "+
				"nothing around it", e.Tool)
		}
		if strings.TrimSpace(e.Why) == "" {
			return ToolLabels{}, fmt.Errorf("%s carries no why. A label "+
				"with no reason is a decision nobody can review, and the "+
				"reviewer it belongs to is whoever reads the finding it "+
				"feeds", name)
		}
		if len(e.Labels) == 0 {
			return ToolLabels{}, fmt.Errorf("%s declares no labels, which "+
				"declares nothing. Remove the entry, or give it one of %s",
				name, strings.Join(ToolLabelsSet(), ", "))
		}
		seen := map[string]bool{}
		for _, l := range e.Labels {
			l = strings.TrimSpace(l)
			if !knownToolLabel(l) {
				return ToolLabels{}, fmt.Errorf(
					"%s carries the label %q, which is not one of the "+
						"closed set %s. A label nobody defined is a label "+
						"nobody can triage", name, l,
					strings.Join(ToolLabelsSet(), ", "))
			}
			if seen[l] {
				return ToolLabels{}, fmt.Errorf("%s carries %s twice; the "+
					"second one declares nothing the first did not", name, l)
			}
			seen[l] = true
		}
		key := strings.ToLower(name)
		if _, dup := t.declared[key]; dup {
			return ToolLabels{}, fmt.Errorf("%s is declared twice. The "+
				"table is a declaration, and a declaration that disagrees "+
				"with itself cannot be diffed, reviewed or trusted", name)
		}
		labels := append([]string(nil), e.Labels...)
		sort.Strings(labels)
		t.declared[key] = strings.Join(labels, ",")
	}
	return t, nil
}

// DeclaredFor is the labels a tool carries, joined with commas, or "" when
// the table says nothing about it. An unknown tool is not an error and not
// an empty declaration — it is nothing: the event stores exactly as it
// arrived and joins no chain, which is the fail-closed answer to a table
// that has not caught up with the estate.
func (t ToolLabels) DeclaredFor(tool string) string {
	if t.declared == nil {
		return ""
	}
	return t.declared[strings.ToLower(strings.TrimSpace(tool))]
}

// Tools lists the declared tool names, sorted, for the screens and the
// tests that count the table.
func (t ToolLabels) Tools() []string {
	out := make([]string, 0, len(t.declared))
	for k := range t.declared {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
