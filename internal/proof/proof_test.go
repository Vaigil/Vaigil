// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package proof

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/telemetry"
)

var tnow = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func mustKey(t *testing.T) *pack.Key {
	t.Helper()
	k, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The rule under test is one the reference pack ships, so these tests prove
// a real rule rather than one shaped to pass them.
func ruleBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../detect/pack/okta.mfa-reset.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func oktaEvent(eventType string) telemetry.Event {
	var e telemetry.Event
	body := `{"source":"okta/system","time":"2026-10-01T09:00:00Z",` +
		`"received":"2026-10-01T09:00:03Z","class":6003,"disposition":1,` +
		`"actor":{"issuer":"okta","value":"00u9"},"message":"` + eventType + `",` +
		`"raw":{"eventType":"` + eventType + `","person":"lee@acme.com"}}`
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		panic(err)
	}
	return e
}

func corpusOf(t *testing.T, entries ...detect.Labelled) []byte {
	t.Helper()
	var b strings.Builder
	for _, l := range entries {
		line, err := json.Marshal(l)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func prove(t *testing.T, corpus []byte) *Statement {
	t.Helper()
	in := DetectionInput{RuleName: "okta.mfa-reset.json", Rule: ruleBytes(t),
		Author: Author{By: "agent:drafter", Model: "local/qwen"}, Program: "test", Now: tnow}
	if corpus != nil {
		entries, err := detect.ParseCorpus(strings.NewReader(string(corpus)))
		if err != nil {
			t.Fatal(err)
		}
		in.CorpusName, in.Corpus, in.Entries = "corpus.jsonl", corpus, entries
	}
	st, err := ProveDetection(in)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func goodCorpus(t *testing.T) []byte {
	return corpusOf(t,
		detect.Labelled{Name: "reset by helpdesk impostor", Event: oktaEvent("user.mfa.factor.reset_all"),
			Expect: []string{"okta.mfa-reset"}},
		detect.Labelled{Name: "self-service enrolment", Event: oktaEvent("user.mfa.factor.activate")},
		// From a source the rule does not read: not counted as a negative,
		// because quiet there is not evidence of anything.
		detect.Labelled{Name: "a github push", Event: telemetry.Event{Source: "github/audit",
			Time: tnow, Received: tnow}},
	)
}

// DSSE's own test vector, so the bytes signed here are the bytes any DSSE
// implementation signs.
func TestPAEMatchesTheDSSEVector(t *testing.T) {
	got := string(pae("http://example.com/HelloWorld", []byte("hello world")))
	if want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"; got != want {
		t.Errorf("PAE is %q, want %q", got, want)
	}
}

func TestARuleThatHoldsIsProvenAndTheProofRoundTrips(t *testing.T) {
	st := prove(t, goodCorpus(t))
	if st.Predicate.Verdict != Proven {
		t.Fatalf("verdict %s, checks %+v", st.Predicate.Verdict, st.Predicate.Checks)
	}
	ev := st.Predicate.Detection
	if ev.Positives != 1 || ev.Caught != 1 || ev.Negatives != 1 || ev.Quiet != 1 || ev.Fixtures != 4 {
		t.Errorf("evidence %+v", ev)
	}
	// One positive is a proof, and a weak one: the bound says so.
	if ev.RecallLow > 0.25 {
		t.Errorf("recall lower bound %.2f over one example claims too much", ev.RecallLow)
	}
	k := mustKey(t)
	env, err := Seal(st, k)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(env, k.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(st)
	b, _ := json.Marshal(got)
	if string(a) != string(b) {
		t.Errorf("the statement changed in transit:\n%s\n%s", a, b)
	}
	if got.Subject[0].Digest["sha256"] != SHA256(ruleBytes(t))["sha256"] {
		t.Error("the subject is not the rule file's digest")
	}
}

// The Ed25519 half is plain DSSE: a verifier that knows nothing about this
// program checks it with the public key alone.
func TestTheEd25519HalfIsPlainDSSE(t *testing.T) {
	k := mustKey(t)
	env, err := Seal(prove(t, goodCorpus(t)), k)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	sig, _ := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	pub, _ := base64.StdEncoding.DecodeString(k.PublicKey().Ed25519)
	if !strings.HasSuffix(env.Signatures[0].KeyID, suffixEd) ||
		!ed25519.Verify(ed25519.PublicKey(pub), pae(PayloadType, payload), sig) {
		t.Error("the Ed25519 signature does not verify as plain DSSE")
	}
}

func TestWithoutACorpusTheBestVerdictIsInconclusive(t *testing.T) {
	st := prove(t, nil)
	if st.Predicate.Verdict != Inconclusive {
		t.Errorf("a rule checked only against its own fixtures is %s", st.Predicate.Verdict)
	}
}

func TestAMissedEntryRefutes(t *testing.T) {
	st := prove(t, corpusOf(t,
		detect.Labelled{Name: "factor swapped by attacker", Event: oktaEvent("user.mfa.factor.update"),
			Expect: []string{"okta.mfa-reset"}},
		detect.Labelled{Name: "self-service enrolment", Event: oktaEvent("user.mfa.factor.activate")},
	))
	if st.Predicate.Verdict != Refuted || !hasFailure(st, "missed: factor swapped by attacker") {
		t.Errorf("verdict %s, checks %+v", st.Predicate.Verdict, st.Predicate.Checks)
	}
}

// A false positive somebody recorded and nobody fixed passes the replay
// gate, deliberately, and fails a proof: a proof is the stricter claim.
func TestAKnownFalsePositiveStillRefutes(t *testing.T) {
	st := prove(t, corpusOf(t,
		detect.Labelled{Name: "reset by helpdesk impostor", Event: oktaEvent("user.mfa.factor.reset_all"),
			Expect: []string{"okta.mfa-reset"}},
		detect.Labelled{Name: "admin cleaning up a leaver", Event: oktaEvent("user.mfa.factor.deactivate"),
			Pending: true, From: "okta.mfa-reset"},
	))
	if st.Predicate.Verdict != Refuted || !hasFailure(st, "fired on: admin cleaning up a leaver") {
		t.Errorf("verdict %s, checks %+v", st.Predicate.Verdict, st.Predicate.Checks)
	}
	if ev := st.Predicate.Detection; ev.Negatives != 1 || ev.Quiet != 0 {
		t.Errorf("evidence %+v", ev)
	}
}

// An entry expecting a different rule is one this rule must stay quiet on,
// and a rule nobody wrote is no reason to refuse the proof.
func TestEntriesForOtherRulesAreNegatives(t *testing.T) {
	st := prove(t, corpusOf(t,
		detect.Labelled{Name: "reset", Event: oktaEvent("user.mfa.factor.reset_all"),
			Expect: []string{"okta.mfa-reset"}},
		detect.Labelled{Name: "api token minted", Event: oktaEvent("system.api_token.create"),
			Expect: []string{"okta.api-token-created"}},
	))
	if st.Predicate.Verdict != Proven || st.Predicate.Detection.Negatives != 1 {
		t.Errorf("verdict %s, evidence %+v", st.Predicate.Verdict, st.Predicate.Detection)
	}
}

func TestAnInvalidRuleIsRefutedBeforeAnythingRuns(t *testing.T) {
	var r map[string]any
	if err := json.Unmarshal(ruleBytes(t), &r); err != nil {
		t.Fatal(err)
	}
	delete(r, "fixtures")
	b, _ := json.Marshal(r)
	st, err := ProveDetection(DetectionInput{RuleName: "bad.json", Rule: b, Now: tnow})
	if err != nil {
		t.Fatal(err)
	}
	if st.Predicate.Verdict != Refuted || len(st.Predicate.Checks) != 1 ||
		st.Predicate.Checks[0].Name != "valid" {
		t.Errorf("verdict %s, checks %+v", st.Predicate.Verdict, st.Predicate.Checks)
	}
}

func TestATamperedPayloadIsRefused(t *testing.T) {
	k := mustKey(t)
	env, _ := Seal(prove(t, goodCorpus(t)), k)
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	edited := strings.Replace(string(payload), `"verdict":"proven"`, `"verdict":"refuted"`, 1)
	if edited == string(payload) {
		t.Fatal("the test did not edit anything")
	}
	env.Payload = base64.StdEncoding.EncodeToString([]byte(edited))
	if _, err := Open(env, k.PublicKey()); err == nil {
		t.Error("an edited verdict opened")
	}
}

func TestOneHalfIsNeverEnough(t *testing.T) {
	k := mustKey(t)
	for _, drop := range []int{0, 1} {
		env, _ := Seal(prove(t, goodCorpus(t)), k)
		env.Signatures = append(env.Signatures[:drop], env.Signatures[drop+1:]...)
		want := []string{"no Ed25519", "no ML-DSA-65"}[drop]
		if _, err := Open(env, k.PublicKey()); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("with one half dropped: %v, want %q", err, want)
		}
	}
}

func TestAnotherKeysProofIsRefused(t *testing.T) {
	env, _ := Seal(prove(t, goodCorpus(t)), mustKey(t))
	if _, err := Open(env, mustKey(t).PublicKey()); err == nil ||
		!strings.Contains(err.Error(), "nothing in this envelope was signed by the trusted key") {
		t.Errorf("a foreign key's proof: %v", err)
	}
}

func TestADuplicatedSignatureIsRefused(t *testing.T) {
	k := mustKey(t)
	env, _ := Seal(prove(t, goodCorpus(t)), k)
	env.Signatures = append(env.Signatures, env.Signatures[0])
	if _, err := Open(env, k.PublicKey()); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a duplicated signature: %v", err)
	}
}

// A signed statement carrying a field this version does not read is
// refused, not read around: otherwise a signer could say something the
// verifier never looked at.
func TestAFieldThisVersionDoesNotKnowIsRefused(t *testing.T) {
	k := mustKey(t)
	var generic map[string]any
	b, _ := json.Marshal(prove(t, goodCorpus(t)))
	_ = json.Unmarshal(b, &generic)
	generic["predicate"].(map[string]any)["also_proves"] = "everything"
	payload, _ := json.Marshal(generic)
	env := signed(t, k, payload, Context)
	if _, err := Open(env, k.PublicKey()); err == nil ||
		!strings.Contains(err.Error(), "not one this version reads") {
		t.Errorf("an unknown field: %v", err)
	}
}

// An ML-DSA signature made in another domain's context does not open as a
// proof, even over the right bytes with the right key.
func TestAnotherDomainsSignatureIsRefused(t *testing.T) {
	k := mustKey(t)
	payload, _ := json.Marshal(prove(t, goodCorpus(t)))
	env := signed(t, k, payload, "aertun/windtunnel-scorecard/v1")
	if _, err := Open(env, k.PublicKey()); err == nil ||
		!strings.Contains(err.Error(), "ML-DSA-65 signature does not verify") {
		t.Errorf("a cross-domain signature: %v", err)
	}
}

func TestAVerdictThatContradictsItsChecksIsRefused(t *testing.T) {
	st := prove(t, goodCorpus(t))
	st.Predicate.Checks[1].Passed = false
	if _, err := Seal(st, mustKey(t)); err == nil || !strings.Contains(err.Error(), "does not agree") {
		t.Errorf("a proven verdict over a failed check: %v", err)
	}
}

func TestAFailureListIsCapped(t *testing.T) {
	var entries []detect.Labelled
	for i := 0; i < MaxFailures+7; i++ {
		entries = append(entries, detect.Labelled{Name: "fp-" + string(rune('A'+i%26)) + strings.Repeat("x", i),
			Event: oktaEvent("user.mfa.factor.deactivate")})
	}
	st := prove(t, corpusOf(t, entries...))
	c := st.Predicate.Checks[2]
	if len(c.Failures) != MaxFailures || !strings.Contains(c.Detail, "7 more failures") {
		t.Errorf("%d failures listed, detail %q", len(c.Failures), c.Detail)
	}
	if _, err := Seal(st, mustKey(t)); err != nil {
		t.Errorf("a capped refutation does not seal: %v", err)
	}
}

func signed(t *testing.T, k *pack.Key, payload []byte, context string) *Envelope {
	t.Helper()
	edSig, mlSig, err := k.DualSign(pae(PayloadType, payload), context)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := KeyID(k.PublicKey())
	return &Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{
			{KeyID: id + suffixEd, Sig: base64.StdEncoding.EncodeToString(edSig)},
			{KeyID: id + suffixML, Sig: base64.StdEncoding.EncodeToString(mlSig)},
		}}
}

func hasFailure(st *Statement, want string) bool {
	for _, c := range st.Predicate.Checks {
		for _, f := range c.Failures {
			if f == want {
				return true
			}
		}
	}
	return false
}
