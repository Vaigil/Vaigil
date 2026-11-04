// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aertun/aertun/internal/telemetry"
)

// writeLines writes a JSONL fixture the tests splice over.
func writeLines(path string, lines ...string) error {
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// A corpus scenario, copied so a test can break it without breaking the
// corpus for the tests after it.
func copyScenario(t *testing.T, id string) *Scenario {
	t.Helper()
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := Corpus(ref)
	if err != nil {
		t.Fatal(err)
	}
	l := ByID(corpus, id)
	if l == nil {
		t.Fatalf("no scenario %s in the corpus", id)
	}
	body, err := json.Marshal(l.Scenario)
	if err != nil {
		t.Fatal(err)
	}
	var sc Scenario
	if err := json.Unmarshal(body, &sc); err != nil {
		t.Fatal(err)
	}
	return &sc
}

// The named refusals: every way a scenario can fail to be what it claims,
// each refused with the reason in the error. A validation that answered
// "invalid" would pass a test that checked only for failure; each case here
// pins the words an author actually reads.
func TestScenarioValidationRefusesByName(t *testing.T) {
	refIDs := func() *IDs {
		ref, err := LoadReference()
		if err != nil {
			t.Fatal(err)
		}
		return ref.ids()
	}()

	broken := map[string]func(*Scenario){
		"no benign twin": func(sc *Scenario) {
			sc.Twin = Twin{ID: "", Title: "x",
				Steps: []Step{sc.Steps[0]}}
		},
		"an empty twin": func(sc *Scenario) {
			sc.Twin = Twin{ID: "twin", Title: "x"}
		},
		"a family outside the closed set": func(sc *Scenario) {
			sc.Family = "phishing"
		},
		"a live phase": func(sc *Scenario) {
			sc.Phase = PhaseLive
		},
		"a safety class from a live phase": func(sc *Scenario) {
			sc.Safety = SafetyCanary
		},
		"a technique nobody carries": func(sc *Scenario) {
			sc.Technique = []string{"ASI99"}
		},
		"no declared blind": func(sc *Scenario) {
			sc.Blind = ""
		},
		"a binding outside the closed table": func(sc *Scenario) {
			sc.Bindings["tool"] = Binding{Value: "shell_exec"}
		},
		"a literal agent identity": func(sc *Scenario) {
			sc.Bindings["agent"] = Binding{Value: "refunder"}
		},
		"a generator outside the closed set": func(sc *Scenario) {
			sc.Bindings["trace"] = Binding{Gen: "uuid", Seed: 1}
		},
		"a destination that is not canary-shaped": func(sc *Scenario) {
			sc.Bindings["dest"] = Binding{Value: "https://evil.example.com/x"}
		},
		"a placeholder nothing binds": func(sc *Scenario) {
			sc.Steps[0].Emit.Message = "run ${tool}"
		},
		"steps out of event-time order": func(sc *Scenario) {
			sc.Steps[1].At = 0
		},
		"two steps with one name": func(sc *Scenario) {
			sc.Steps[1].Name = sc.Steps[0].Name
		},
		"a step carrying its own clocks": func(sc *Scenario) {
			sc.Steps[0].Emit.Time = fixtureDay
		},
		"no steps at all": func(sc *Scenario) {
			sc.Steps = nil
		},
		"a correlation asked to fire quietly": func(sc *Scenario) {
			sc.Expects[3].Verdict = VerdictFiresQuietly
		},
		"an expect of an unknown kind": func(sc *Scenario) {
			sc.Expects[0].Kind = "guess"
		},
		"an expect in an unknown verdict": func(sc *Scenario) {
			sc.Expects[0].Verdict = "should-probably"
		},
		"no expects": func(sc *Scenario) {
			sc.Expects = nil
		},
		"two expects naming one thing": func(sc *Scenario) {
			sc.Expects = append(sc.Expects, sc.Expects[0])
		},
		"a schema from another build": func(sc *Scenario) {
			sc.Schema = 2
		},
		"a lateness source outside the closed set": func(sc *Scenario) {
			sc.Lateness = "profile:satellite"
		},
		"no bindings at all": func(sc *Scenario) {
			sc.Bindings = map[string]Binding{}
		},
		"a preflight outside the closed set": func(sc *Scenario) {
			sc.Preflight = []PreflightCheck{{Check: "dns-resolves"}}
		},
		"a tool-label preflight naming no tool": func(sc *Scenario) {
			sc.Preflight = []PreflightCheck{{Check: CheckToolLabelled,
				Source: "otel/genai", Label: "untrusted-content"}}
		},
	}
	for what, breakIt := range broken {
		sc := copyScenario(t, "agent.trifecta-mailroom-exfil")
		breakIt(sc)
		err := sc.Validate(refIDs)
		if err == nil {
			t.Errorf("%s: the scenario validated. A refusal that does not "+
				"refuse is a corpus anybody can widen", what)
			continue
		}
		if strings.TrimSpace(err.Error()) == "" {
			t.Errorf("%s: refused with an empty message", what)
		}
	}
}

// The refusals that name the specific thing: the pack id nothing carries,
// the quiet verdict on a loud rule — the words an author needs to act on
// rather than only the fact of refusal.
func TestScenarioValidationNamesThePackSideRefusals(t *testing.T) {
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	ids := ref.ids()

	sc := copyScenario(t, "agent.mcp-rug-pull")
	sc.Expects = []Expect{{Kind: ExpectRule, ID: "otel.ghost-rule",
		Verdict: VerdictMustAlert}}
	err = sc.Validate(ids)
	if err == nil || !strings.Contains(err.Error(),
		"no rule called that is in the reference pack") {
		t.Errorf("an expect naming a rule the pack does not carry gave %v; "+
			"the refusal must say nothing answers to that id", err)
	}

	sc = copyScenario(t, "agent.mcp-rug-pull")
	sc.Expects = []Expect{{Kind: ExpectRule,
		ID: "collector.agent-config-changed", Verdict: VerdictFiresQuietly}}
	err = sc.Validate(ids)
	if err == nil || !strings.Contains(err.Error(), "that rule is loud") {
		t.Errorf("a quiet verdict on a loud rule gave %v; the refusal must "+
			"name the loudness, or every hit would be mislabelled", err)
	}

	sc = copyScenario(t, "agent.mcp-rug-pull")
	sc.Expects = []Expect{{Kind: ExpectCorrelation, ID: "corr.nope",
		Verdict: VerdictMustAlert}}
	err = sc.Validate(ids)
	if err == nil || !strings.Contains(err.Error(),
		"no correlation called that is in the reference pack") {
		t.Errorf("an expect naming a correlation the pack does not carry "+
			"gave %v", err)
	}
}

// The whole seed corpus validates against the pack as shipped — the
// co-fixture discipline: a pack change that removes or renames anything a
// scenario expects breaks here, before any scorecard can quietly miss it.
func TestScenarioCorpusValidatesAgainstTheShippedPack(t *testing.T) {
	ref, err := LoadReference()
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := Corpus(ref)
	if err != nil {
		t.Fatalf("the corpus refused to load: %v", err)
	}
	if len(corpus) != 6 {
		t.Fatalf("%d scenarios shipped; the seed corpus is six, and a count "+
			"that drifts silently is a corpus somebody edited without "+
			"deciding", len(corpus))
	}
	want := map[string]string{
		"agent.trifecta-mailroom-exfil":    FamilyTrifecta,
		"agent.mcp-rug-pull":               FamilyConfigRugPull,
		"agent.injection-hijack-via-issue": FamilyInjection,
		"agent.slopsquat-install":          FamilySlopsquat,
		"agent.recorder-blind-window":      FamilyRecorderBlind,
		"agent.cost-bomb-loop":             FamilyCostBomb,
	}
	for _, l := range corpus {
		family, ok := want[l.Scenario.ID]
		if !ok {
			t.Errorf("%s shipped unannounced; the six the build named are "+
				"the corpus", l.Scenario.ID)
			continue
		}
		if l.Scenario.Family != family {
			t.Errorf("%s declares family %s, the build's scenario is the %s",
				l.Scenario.ID, l.Scenario.Family, family)
		}
		if l.Scenario.Twin.ID == "" || len(l.Scenario.Twin.Steps) == 0 {
			t.Errorf("%s carries no working twin", l.Scenario.ID)
		}
		if strings.TrimSpace(l.Scenario.Blind) == "" {
			t.Errorf("%s declares no blind", l.Scenario.ID)
		}
		if len(l.Digest) != 64 {
			t.Errorf("%s has digest %q, which is not a sha256 in hex",
				l.Scenario.ID, l.Digest)
		}
	}
}

// A scenario file with a field this schema does not know refuses to load —
// the same refusal every versioned schema here makes, because fields change
// meaning between versions.
func TestScenarioCorpusRefusesAnUnknownField(t *testing.T) {
	var sc Scenario
	body := `{"schema":1,"id":"x","title":"t","family":"trifecta",
		"phase":"replay","safety":"synthetic-only","narrative":"n",
		"catalogue":"B2","technique":["ASI01"],
		"bindings":{"agent":{"gen":"agent-name","seed":1}},
		"steps":[{"name":"a","at":0,"emit":{"source":"otel/genai","message":"m",
		"class":6003,"actor":{"issuer":"otel","value":"${agent}"}}}],
		"expects":[{"kind":"rule","id":"otel.tool-call","verdict":"fires-quietly"}],
		"benign-twin":{"id":"t","title":"t","steps":[{"name":"b","at":0,
		"emit":{"source":"otel/genai","message":"m","class":6003,
		"actor":{"issuer":"otel","value":"${agent}"}}}]},
		"blind":"b","executor":"sh -c rm -rf /"}`
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sc); err == nil {
		t.Fatal("a scenario carrying an executor field parsed; the loader " +
			"must refuse fields this schema does not know, and an executor " +
			"is the one field this format exists to refuse")
	}
}

// Preflight refuses what it exists to refuse, by name: a source the stream
// never emitted, a label its boundary never stamped, and a collision with
// an identity the stream already owns.
func TestScenarioPreflightRefusesByName(t *testing.T) {
	sc := copyScenario(t, "agent.trifecta-mailroom-exfil")
	base := DefaultBase()

	err := Preflight(sc, base)
	if err != nil {
		t.Fatalf("the default base stream failed the trifecta's own "+
			"preflight: %v. The fixture and the scenario drifted apart", err)
	}

	sc2 := copyScenario(t, "agent.trifecta-mailroom-exfil")
	sc2.Preflight = []PreflightCheck{{Check: CheckSourceEmits,
		Source: "github/audit"}}
	if err := Preflight(sc2, base); err == nil ||
		!strings.Contains(err.Error(), "carries no event from") {
		t.Errorf("a source the stream never emitted gave %v; the refusal "+
			"names the source", err)
	}

	sc3 := copyScenario(t, "agent.trifecta-mailroom-exfil")
	sc3.Preflight = []PreflightCheck{{Check: CheckToolLabelled,
		Source: "otel/genai", Tool: "fetch", Label: "sensitive-data"}}
	if err := Preflight(sc3, base); err == nil ||
		!strings.Contains(err.Error(), "never carried the tool") {
		t.Errorf("a label the boundary never stamped gave %v", err)
	}

	// The built-in collision check: force the generated trace id onto an
	// event the base stream already carries.
	sc4 := copyScenario(t, "agent.trifecta-mailroom-exfil")
	values, err := Expand(sc4)
	if err != nil {
		t.Fatal(err)
	}
	collide := base[0]
	collide.Raw = map[string]string{"trace_id": values["trace"]}
	if err := Preflight(sc4, append([]telemetry.Event{collide},
		base...)); err == nil ||
		!strings.Contains(err.Error(), "already in the base stream") {
		t.Errorf("a generated trace id colliding with the stream's gave %v; "+
			"the disjoint ranges make it near-certain and the check makes "+
			"it certain", err)
	}

	if err := Preflight(sc, nil); err == nil ||
		!strings.Contains(err.Error(), "holds no events") {
		t.Errorf("an empty base stream gave %v", err)
	}
}

// ReadBase refuses a file that is not a stream of valid events, naming the
// line — a half-written stream must not quietly become the thing a
// scorecard names.
func TestScenarioReadBaseRefusesWhatTheSpoolWouldRefuse(t *testing.T) {
	dir := t.TempDir()
	bad := dir + "/bad.jsonl"
	if err := writeLines(bad, `{"source":"otel/genai","time":"2026-11-02T09:00:00Z","received":"2026-11-02T09:00:02Z","class":6003,"actor":{"issuer":"otel","value":"a"},"message":"m"}`,
		`{"source":"","time":"2026-11-02T09:01:00Z"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBase(bad); err == nil ||
		!strings.Contains(err.Error(), "line 2") {
		t.Errorf("an event with no source gave %v; the refusal names the "+
			"line, because the spool would refuse the same bytes later", err)
	}
	good := dir + "/good.jsonl"
	if err := writeLines(good,
		`{"source":"otel/genai","time":"2026-11-02T09:00:00Z","received":"2026-11-02T09:00:02Z","class":6003,"actor":{"issuer":"otel","value":"a"},"message":"m"}`); err != nil {
		t.Fatal(err)
	}
	base, err := ReadBase(good)
	if err != nil || len(base) != 1 {
		t.Fatalf("a well-formed stream refused to load: %v", err)
	}
}
