// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aertun/aertun/internal/correlate"
	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/telemetry"
)

// The seed corpus: six scenarios and their twins, embedded as data files the
// way the starter pack's rules are (internal/detect/pack), loaded through
// the same validate-refuse discipline everything here is.
//
// The corpus and the pack are each other's fixtures. A pack change that
// makes the reference stack miss a scenario breaks the build here, and a
// scenario change that wakes a twin breaks it too — which is exactly what
// aertunbench does for the analyst, done to the detections.

//go:embed scenarios/*.json
var scenarioFS embed.FS

// CorpusName is the seed corpus's name, stamped into every scorecard.
const CorpusName = "windtunnel-seed-v1"

// Loaded is one scenario with the digest of the exact bytes it came from.
type Loaded struct {
	Scenario *Scenario
	Digest   string
}

// Corpus loads every embedded scenario, validated against the reference
// pack. A scenario that fails validation refuses the load: a corpus that
// half-loads would run the scenarios it liked and say nothing about the
// rest, which is the silent-dropping failure every loader here refuses.
//
// This is the strict reading, and it is the shipped pack's own: the corpus
// and the pack are each other's fixtures, so a scenario naming a detection
// the pack lacks is a build broken loudly. A different instrument — the
// doctored reference a test scores, a third-party pack — meets the loose
// reading instead (loadCorpus with strict false): the shape checks only,
// and every expectation the instrument lacks is scored as the miss it is,
// by the honesty rules the scorer already carries.
func Corpus(ref *Reference) ([]*Loaded, error) {
	return loadCorpus(ref, true)
}

// loadCorpus is Corpus with the strictness named. Strict checks each
// scenario's expectations against the reference's ids; loose passes nil ids,
// which is Scenario.Validate's own way of saying "check everything that does
// not need the pack".
func loadCorpus(ref *Reference, strict bool) ([]*Loaded, error) {
	entries, err := scenarioFS.ReadDir("scenarios")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var out []*Loaded
	for _, name := range names {
		body, err := scenarioFS.ReadFile("scenarios/" + name)
		if err != nil {
			return nil, err
		}
		var sc Scenario
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&sc); err != nil {
			return nil, fmt.Errorf("scenarios/%s is not a scenario: %w", name,
				err)
		}
		ids := ref.ids()
		if !strict {
			ids = nil
		}
		if err := sc.Validate(ids); err != nil {
			return nil, fmt.Errorf("scenarios/%s: %w", name, err)
		}
		sum := sha256.Sum256(body)
		out = append(out, &Loaded{Scenario: &sc,
			Digest: hex.EncodeToString(sum[:])})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the seed corpus is empty; it ships six " +
			"scenarios and something has gone wrong with the embed")
	}
	return out, nil
}

// ByID finds a loaded scenario by id.
func ByID(corpus []*Loaded, id string) *Loaded {
	for _, l := range corpus {
		if l.Scenario.ID == id {
			return l
		}
	}
	return nil
}

// ReadBase loads a base stream: a JSONL file of events, or a directory of
// them (a spool's segments, in name order). The events are validated on the
// way in exactly as the spool validates them, because the scratch store will
// refuse them otherwise and a half-written stream is worse than a refusal.
func ReadBase(path string) ([]telemetry.Event, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var files []string
	if fi.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
				files = append(files, filepath.Join(path, e.Name()))
			}
		}
		sort.Strings(files)
	} else {
		files = []string{path}
	}
	var out []telemetry.Event
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for n, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var e telemetry.Event
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				return nil, fmt.Errorf("%s line %d is not an event: %w", f,
					n+1, err)
			}
			if err := e.Validate(); err != nil {
				return nil, fmt.Errorf("%s line %d: %w", f, n+1, err)
			}
			out = append(out, e)
		}
	}
	return out, nil
}

// Reference is the calibrated instrument: the detection pack that ships with
// the program, loaded the way `detect run` loads it and replayed the way the
// shadow replay replays it. Reference mode measures what aertun's own
// detections caught on the stream, and the scorecard says so in as many
// words — it is the instrument, not the organisation's controls.
type Reference struct {
	// Name is what the scorecard calls the pack.
	Name  string
	Rules []detect.Rule
	Corrs []correlate.Rule
	// Digest pins the pack's exact bytes: every file, hashed in name order.
	Digest string

	ruleQuiet map[string]bool
	corrIDs   map[string]bool
}

// LoadReference loads the shipped pack. The tool-label table ships with it
// but is data the ingest boundary reads, not a rule, and is skipped the way
// `detect pack` skips it.
func LoadReference() (*Reference, error) {
	files, err := detect.Pack()
	if err != nil {
		return nil, err
	}
	return loadReference("shipped", files)
}

// LoadReferenceDir loads a pack from a directory: the installed rules a
// promotion lands beside, or a third-party pack asked the same questions.
// The same walker loads both it and the shipped pack, so a directory of
// rules meets the refusals the shipped pack meets — every rule validated,
// every correlation parsed, nothing silently dropped.
func LoadReferenceDir(dir string) (*Reference, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []detect.PackFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".yml") &&
			!strings.HasSuffix(name, ".yaml") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		files = append(files, detect.PackFile{Name: name, Body: body})
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s holds no .json rules and no .yml "+
			"correlations; a pack directory is files in the shipped pack's "+
			"own format", dir)
	}
	return loadReference(filepath.Base(dir), files)
}

// loadReference is the one walker behind the shipped pack and a directory
// of it. The digest covers every file it was handed, in name order, so a
// scorecard's pack digest means the same bytes wherever the pack lived.
func loadReference(name string, files []detect.PackFile) (*Reference, error) {
	ref := &Reference{Name: name,
		ruleQuiet: map[string]bool{}, corrIDs: map[string]bool{}}
	h := sha256.New()
	for _, f := range files {
		h.Write([]byte(f.Name))
		h.Write([]byte{0})
		h.Write(f.Body)
		h.Write([]byte{0})
		switch {
		case f.Name == detect.ToolLabelsFile:
			continue
		case strings.HasSuffix(f.Name, ".json"):
			var r detect.Rule
			if err := json.Unmarshal(f.Body, &r); err != nil {
				return nil, fmt.Errorf("%s is not a rule: %w", f.Name, err)
			}
			if err := r.Validate(); err != nil {
				return nil, fmt.Errorf("%s: %w", f.Name, err)
			}
			ref.Rules = append(ref.Rules, r)
			ref.ruleQuiet[strings.ToLower(r.ID)] = r.Quiet
		case strings.HasSuffix(f.Name, ".yml") || strings.HasSuffix(f.Name, ".yaml"):
			parsed, err := correlate.Read(f.Body)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f.Name, err)
			}
			ref.Corrs = append(ref.Corrs, parsed...)
			for _, c := range parsed {
				ref.corrIDs[strings.ToLower(c.ID)] = true
			}
		}
	}
	if len(ref.Rules) == 0 || len(ref.Corrs) == 0 {
		return nil, fmt.Errorf("the pack at %s loaded %d rule(s) and %d "+
			"correlation(s); the wind tunnel has no instrument to replay",
			name, len(ref.Rules), len(ref.Corrs))
	}
	ref.Digest = hex.EncodeToString(h.Sum(nil))
	return ref, nil
}

// ids is the pack's ids, for scenario validation.
func (r *Reference) ids() *IDs {
	return &IDs{Rules: r.ruleQuiet, Correlations: r.corrIDs}
}

// Expects reports whether the reference still carries a rule or correlation
// id — the question the scorer answers honestly with a miss when a pack
// change removed one, rather than erroring a run into silence.
func (r *Reference) has(kind, id string) bool {
	switch kind {
	case ExpectRule:
		_, ok := r.ruleQuiet[strings.ToLower(id)]
		return ok
	case ExpectCorrelation:
		return r.corrIDs[strings.ToLower(id)]
	}
	return false
}
