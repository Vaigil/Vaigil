// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
)

// The evidence half is tested against a real log: a seeded chain written by
// the audit package itself, signed by a real head signer, and verified back
// the way a third party would — from the marshaled document and the public
// keys, with no access to the log.

var packTime = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

// seedLog writes a small chain whose shape exercises the matcher: AC-5's
// dual-control and setting records, an unrelated token issue, and an AI
// actor's refused tool call, all under a pseudonymisation key so the
// no-free-text checks see the log as it is really kept.
func seedLog(t *testing.T) []audit.Event {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := audit.New(audit.Options{
		Path:   path,
		Key:    bytes.Repeat([]byte{1}, 32),
		Source: "aertun-test@host",
	})
	if err != nil {
		t.Fatal(err)
	}
	records := []audit.Record{
		{Action: "token.issue", Resource: "/", Outcome: audit.Success,
			Principal: "ada", Kind: audit.KindHuman, Verified: true},
		{Action: "dual.proposed", Resource: "/pending/1", Outcome: audit.Success,
			Principal: "ada", Kind: audit.KindHuman, Verified: true,
			Detail: map[string]string{"kind": "grant", "for": "grace"}},
		{Action: "dual.approved", Resource: "/pending/1", Outcome: audit.Success,
			Principal: "ben", Kind: audit.KindHuman, Verified: true},
		{Action: "config.set", Resource: "/settings", Outcome: audit.Success,
			Principal: "ada", Kind: audit.KindHuman, Verified: true,
			// The detail keys the real writer uses, which matters here:
			// the audit package refuses a key that looks like a secret,
			// and a seeded log that could not have been written is a
			// fixture lying about the system it tests.
			Detail: map[string]string{"setting": "session.idle",
				"from": "60m", "to": "15m"}},
		{Action: "mcp.call", Resource: "tools/terminal", Outcome: audit.Denied,
			Principal: "assistant", Kind: audit.KindAI, Model: "test-model"},
	}
	for _, r := range records {
		if _, err := l.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	events, err := audit.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != len(records) {
		t.Fatalf("the seeded log has %d entries, want %d", len(events), len(records))
	}
	return events
}

// testSigner is deterministic, so a head over the same events is the same
// head and two packs generated in one test can be mixed freely.
func testSigner(t *testing.T) *audit.HeadSigner {
	t.Helper()
	s, err := audit.NewHeadSigner(
		bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEvidencePackCarriesProofsThatVerifyOffline(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	events := seedLog(t)
	signer := testSigner(t)

	pack, err := EvidencePack(m, "AC-5", events, signer, packTime)
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Records) != 3 {
		t.Fatalf("AC-5 gathered %d records; dual.proposed, dual.approved "+
			"and config.set are in the seeded log, so 3 are expected",
			len(pack.Records))
	}
	if pack.Head.Size != len(events) {
		t.Errorf("the head covers %d entries; the log it was built over has "+
			"%d", pack.Head.Size, len(events))
	}
	if len(pack.Head.Algorithms) != 2 || pack.Head.MLDSA == "" {
		t.Error("the head does not carry both signatures, and a head with " +
			"half its argument proves half as much")
	}
	if len(pack.Entries) != len(m.EntriesFor("AC-5")) {
		t.Errorf("the pack carries %d entries; the mapping maps %d to AC-5",
			len(pack.Entries), len(m.EntriesFor("AC-5")))
	}
	if len(pack.Satisfies) != 0 {
		t.Error("a pack with records also says what would satisfy the " +
			"control, which is the empty pack's line to say")
	}

	// The third-party path: bytes and public keys, nothing else.
	body, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	back, err := VerifyPack(body, signer.Verifier())
	if err != nil {
		t.Fatalf("the pack does not verify offline: %v", err)
	}
	if back.Control != "AC-5" || len(back.Records) != 3 {
		t.Errorf("the verified pack came back wrong: control %q, %d records",
			back.Control, len(back.Records))
	}
}

// A broken chain cannot yield evidence, even when the broken entry is not
// one of the matched records: the proofs would pin honest records into a
// tree grown over a rewritten log, which is a stronger-looking document
// than an honest log and worth exactly nothing.
func TestEvidencePackRefusesABrokenChain(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	events := seedLog(t)
	signer := testSigner(t)

	tampered := append([]audit.Event(nil), events...)
	tampered[0].Action = "token.issue-tampered"
	_, err = EvidencePack(m, "AC-5", tampered, signer, packTime)
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("a pack was built over a log whose first entry was altered: %v", err)
	}

	// And a deletion, which the sequence gap catches even though every
	// remaining entry still hashes to itself.
	gapped := append([]audit.Event(nil), events[:2]...)
	gapped = append(gapped, events[3:]...)
	_, err = EvidencePack(m, "AC-5", gapped, signer, packTime)
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("a pack was built over a log with a deleted entry: %v", err)
	}
}

// Tampering a record in the saved document fails verification, both when the
// hash field is left alone (the content check names it) and when the tamperer
// is careful enough to re-hash the record — which is the case that proves the
// inclusion proof, not the content hash, is the load-bearing check.
func TestVerifyPackRefusesATamperedRecord(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	events := seedLog(t)
	signer := testSigner(t)
	pack, err := EvidencePack(m, "AC-5", events, signer, packTime)
	if err != nil {
		t.Fatal(err)
	}

	// Careless: the action changes and the hash stays.
	lazy := *pack
	lazy.Records = append([]PackRecord(nil), pack.Records...)
	lazy.Records[0].Action = "dual.approved"
	body, _ := json.Marshal(&lazy)
	if _, err := VerifyPack(body, signer.Verifier()); err == nil ||
		!strings.Contains(err.Error(), "does not match its own hash") {
		t.Errorf("a record altered without re-hashing was accepted: %v", err)
	}

	// Careful: the action changes and the hash is recomputed to suit. The
	// record now agrees with itself and disagrees with the tree.
	careful := *pack
	careful.Records = append([]PackRecord(nil), pack.Records...)
	careful.Records[0].Action = "dual.approved"
	h, err := contentHash(careful.Records[0].Event)
	if err != nil {
		t.Fatal(err)
	}
	careful.Records[0].Hash = h
	body, _ = json.Marshal(&careful)
	if _, err := VerifyPack(body, signer.Verifier()); err == nil ||
		!strings.Contains(err.Error(), "inclusion proof") {
		t.Errorf("a re-hashed forgery was accepted, so the proof is not "+
			"doing the work it exists to do: %v", err)
	}
}

// A pack whose records are all genuine but one of which the pack never
// claimed to gather: padding, chosen for its impression. The claimed-actions
// check refuses it even though the record carries a valid proof, because a
// pack that misdescribes its own contents is not made honest by cryptography.
func TestVerifyPackRefusesRecordsThePackDidNotClaim(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	events := seedLog(t)
	signer := testSigner(t)
	// Same events, same signer, same time: one head, two packs under it.
	ac5, err := EvidencePack(m, "AC-5", events, signer, packTime)
	if err != nil {
		t.Fatal(err)
	}
	ac2, err := EvidencePack(m, "AC-2", events, signer, packTime)
	if err != nil {
		t.Fatal(err)
	}

	padded := *ac5
	padded.Records = append([]PackRecord(nil), ac5.Records...)
	for _, r := range ac2.Records {
		if r.Action == "token.issue" {
			padded.Records = append(padded.Records, r)
		}
	}
	body, _ := json.Marshal(&padded)
	if _, err := VerifyPack(body, signer.Verifier()); err == nil ||
		!strings.Contains(err.Error(), "nothing the pack says it gathered") {
		t.Errorf("an AC-5 pack padded with a token issue was accepted: %v", err)
	}
}

func TestVerifyPackRefusesASubstitutedHead(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	events := seedLog(t)
	pack, err := EvidencePack(m, "AC-5", events, testSigner(t), packTime)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(pack)

	// Different keys: this is the auditor who was handed somebody else's
	// key file, and the refusal is the whole value of the signature.
	other, err := audit.NewHeadSigner(
		bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPack(body, other.Verifier()); err == nil ||
		!strings.Contains(err.Error(), "head does not verify") {
		t.Errorf("a head signed by other keys was accepted: %v", err)
	}

	// And no keys at all, which is the pack asked to vouch for itself.
	if _, err := VerifyPack(body, nil); err == nil {
		t.Error("a pack verified without any public keys was accepted")
	}
}

func TestVerifyPackRefusesARewrittenVerifyStatement(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	pack, err := EvidencePack(m, "AC-5", seedLog(t), testSigner(t), packTime)
	if err != nil {
		t.Fatal(err)
	}
	liar := *pack
	liar.Verify = []string{"check the signatures; the records are fine"}
	body, _ := json.Marshal(&liar)
	if _, err := VerifyPack(body, testSigner(t).Verifier()); err == nil ||
		!strings.Contains(err.Error(), "verify statement") {
		t.Errorf("a pack instructing its reader to check less was accepted: %v", err)
	}
}

func TestVerifyPackRefusesADifferentSchema(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	pack, err := EvidencePack(m, "AC-5", seedLog(t), testSigner(t), packTime)
	if err != nil {
		t.Fatal(err)
	}
	pack.Schema = "aertun/evidence/v0"
	body, _ := json.Marshal(pack)
	if _, err := VerifyPack(body, testSigner(t).Verifier()); err == nil ||
		!strings.Contains(err.Error(), "schema") {
		t.Errorf("a document of another schema was read as this one: %v", err)
	}
}

// A control whose queries match nothing gets an honest empty pack: the
// entries, the head, and a satisfies section naming what a record would have
// carried. It verifies like any other pack, because "we looked and there was
// nothing" is a checkable claim when the looking is signed.
func TestEvidencePackForAControlWithNoRecords(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// IA-2's actions are session.start and signin.oidc; the seeded log has
	// neither, and the control is mapped — the honest-empty case.
	events := seedLog(t)
	signer := testSigner(t)
	pack, err := EvidencePack(m, "IA-2", events, signer, packTime)
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Records) != 0 {
		t.Fatalf("IA-2 gathered %d records from a log with no sign-ins",
			len(pack.Records))
	}
	if len(pack.Satisfies) == 0 {
		t.Fatal("an empty pack said nothing about what would satisfy the " +
			"control, which turns a fact about the log into a shrug")
	}
	said := strings.Join(pack.Satisfies, "\n")
	if !strings.Contains(said, "authn.phishing-resistant") ||
		!strings.Contains(said, "session.start") {
		t.Errorf("the satisfies section does not name the entry and the "+
			"actions a record would have carried:\n%s", said)
	}
	body, _ := json.Marshal(pack)
	if _, err := VerifyPack(body, signer.Verifier()); err != nil {
		t.Fatalf("an empty pack does not verify: %v", err)
	}
}

func TestEvidencePackRefusesAnUnmappedControl(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// IR-8 is a real control this program has no entry for — well formed,
	// in the catalogue's id shape, and mapped to nothing.
	_, err = EvidencePack(m, "IR-8", seedLog(t), testSigner(t), packTime)
	if err == nil {
		t.Fatal("a pack was generated for a control the mapping does not " +
			"cover, which is a claim about coverage wearing a record's clothes")
	}
	if !strings.Contains(err.Error(), "IR-8") {
		t.Errorf("the refusal does not name the control: %v", err)
	}
	if got := fmt.Sprint(err); !strings.Contains(got, ErrUnmappedControl.Error()) {
		t.Errorf("the refusal is not the named error: %v", err)
	}
}

// The pack carries no free text: principals and sources as the log
// pseudonymised them, outcomes and kinds from their closed sets, actions
// from the patterns the pack claims, proofs as hex. Anything a reader could
// be persuaded by and cannot check has no business in an evidence document.
func TestThePackCarriesNoFreeText(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	events := seedLog(t)
	signer := testSigner(t)
	pack, err := EvidencePack(m, "AC-5", events, signer, packTime)
	if err != nil {
		t.Fatal(err)
	}

	pseudonym := regexp.MustCompile(`^p_[0-9a-f]{32}$`)
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	outcomes := map[string]bool{"success": true, "failure": true, "denied": true}
	kinds := map[string]bool{"human": true, "service": true, "ai": true, "unknown": true}

	// The closed set of actions the mapping's AC-5 patterns can match.
	claimable := map[string]bool{}
	for _, e := range m.EntriesFor("AC-5") {
		for _, p := range e.Evidence.Actions {
			claimable[p] = true
		}
	}
	if len(pack.Records) == 0 {
		t.Fatal("no records to check; the seeded log should have matched")
	}
	for _, r := range pack.Records {
		if !pseudonym.MatchString(r.Principal) {
			t.Errorf("record %d carries principal %q; the log pseudonymises "+
				"them and the pack must not undo that", r.Seq, r.Principal)
		}
		if !pseudonym.MatchString(r.Source) {
			t.Errorf("record %d carries source %q; a hostname is a person's "+
				"name on a single-user machine and the log pseudonymises it",
				r.Seq, r.Source)
		}
		if !outcomes[string(r.Outcome)] {
			t.Errorf("record %d carries outcome %q, which is not one of the "+
				"three there are", r.Seq, r.Outcome)
		}
		if !kinds[string(r.Kind)] {
			t.Errorf("record %d carries kind %q, which is not one of the "+
				"four there are", r.Seq, r.Kind)
		}
		if !claimable[r.Action] && !m.actionsMatch(r.Action, "AC-5") {
			t.Errorf("record %d carries action %q, which no AC-5 pattern "+
				"gathers", r.Seq, r.Action)
		}
		for _, h := range r.Proof {
			if !hex64.MatchString(h) {
				t.Errorf("record %d's proof carries %q, which is not a hash",
					r.Seq, h)
			}
		}
		if _, err := time.Parse(time.RFC3339, r.At); err != nil {
			t.Errorf("record %d's time is not RFC 3339: %v", r.Seq, err)
		}
	}
}

// actionsMatch reports whether any pattern the control's entries declare
// gathers this action — ActionsFor's matcher, wrapped for the tests above.
func (m *Mapping) actionsMatch(action, control string) bool {
	for _, p := range m.ActionsFor(control) {
		if MatchAction(p, action) {
			return true
		}
	}
	return false
}
