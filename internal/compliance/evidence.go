// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/audit"
)

// Evidence packs: the mapping's second half, where a control stops being a
// claim and becomes a document somebody else can check.
//
// # What an assessor is normally handed
//
// A compliance export is usually a spreadsheet: control ids beside feature
// names, true because somebody typed true. The one property it cannot have is
// the property that matters — that the statements in it follow from records
// nobody could have edited after the fact.
//
// This program already keeps those records. The audit chain commits every
// action, the Merkle tree over it proves a single entry to somebody holding
// only a handful of hashes, and the tree head is signed with two algorithms
// that fail independently. An evidence pack is those three things arranged
// for one control:
//
//	entries    what the mapping says demonstrates the control, with the
//	           one-line statement of what a matched record establishes
//	records    the matching audit entries, as stored (principals already
//	           pseudonymised by the log, never by the pack), each with its
//	           index and inclusion proof
//	head       the signed tree head the proofs land in — Ed25519 and
//	           ML-DSA-65, both required
//	verify     the steps a third party performs offline, with no access to
//	           the log and no cooperation from this program
//
// NIST asks for audit records you can trust; this ships audit records you can
// prove. AU-9 asks that audit information be protected from modification —
// the pack lets somebody who was not there verify that it was, using about
// twenty hashes per record rather than the confidential log.
//
// # What a pack refuses to be
//
// A pack is not a report. It carries no conclusions beyond the mapping's own
// proves lines, no summary judgements, and no field this program computed and
// a reader must take on faith: everything in it is either the mapping shipped
// in the binary, a record the log already held, or the cryptographic material
// to check the records against the head. An empty pack is emitted rather than
// a refused one, and says what would have satisfied the control — "no
// evidence" and "no answer" are different facts, and the difference is the
// whole reason the mapping exists.

// PackSchema is the evidence document this package writes and reads.
const PackSchema = "aertun/evidence/v1"

// ErrUnmappedControl names a control the mapping has no entry for. Generation
// refuses rather than emitting an empty pack, because a control this program
// never assessed is not a control with no records — one is a fact about the
// log, the other is a claim about coverage, and confusing them is how a
// mapping turns into decoration.
var ErrUnmappedControl = errors.New(
	"the mapping names no entry for this control")

// Pack is a generated evidence document.
type Pack struct {
	Schema      string            `json:"schema"`
	Control     string            `json:"control"`
	GeneratedAt string            `json:"generated_at"`
	Catalogs    map[string]string `json:"catalogs"`

	// Entries are the mapping's statements about what demonstrates the
	// control, in the mapping's own order, with the actions each is
	// evidenced by.
	Entries []PackEntry `json:"entries"`

	// Head is the signed tree head over the whole log at generation time.
	// The proofs below land in this head; the head's two signatures are
	// what stop a proof from being about a tree nobody vouched for.
	Head audit.SignedHead `json:"head"`

	// Records are the matching audit entries, in chain order, each with the
	// index and inclusion proof that pin it to Head.
	Records []PackRecord `json:"records"`

	// Satisfies is present only when no record matched. It says what would
	// have evidenced the control — the entries and the actions a record
	// would have carried — assembled from the mapping's own fields rather
	// than written for the occasion.
	Satisfies []string `json:"satisfies,omitempty"`

	// Verify states the offline steps. Pinned by VerifyPack, so a pack
	// cannot carry instructions that quietly ask less of its reader than
	// the format deserves.
	Verify []string `json:"verify"`
}

// PackEntry is one mapped statement inside a pack.
type PackEntry struct {
	ID      string   `json:"id"`
	Kind    string   `json:"kind"`
	Title   string   `json:"title"`
	Actions []string `json:"actions"`
	Proves  string   `json:"proves"`
}

// PackRecord is one audit entry and its proof. The event is embedded whole —
// the leaf hash commits to the entire record, so nothing can be trimmed from
// it without the proof failing, and "as stored" is the honest shape:
// principals were pseudonymised when the log wrote them, not for the pack.
type PackRecord struct {
	audit.Event
	Index int      `json:"index"`
	Proof []string `json:"proof"`
}

// verifySteps is what a third party performs, in order, with this document
// and the site's published public keys — and nothing else. Stated in the pack
// itself so the document explains its own checking, and pinned by VerifyPack
// so nobody can hand an auditor a pack whose instructions ask less.
var verifySteps = []string{
	"Check the head's Ed25519 signature and its ML-DSA signature against the " +
		"site's published public keys; both must verify, and a head with only " +
		"one is a head with half its argument",
	"Recompute each record's hash from its own content (the record with its " +
		"hash field emptied, marshaled, SHA-256) and check it equals the hash " +
		"the record carries",
	"Recompute each record's Merkle leaf from the pair (recomputed content " +
		"hash, stored hash, prev) and run the RFC 6962 inclusion walk with the " +
		"record's index and proof against the head's root and size",
	"Confirm every record's action matches one of the actions the pack's " +
		"entries say they gathered, so the pack describes its own records",
}

// VerifySteps returns the offline steps a pack states, for a caller that
// wants to print them beside a pack it is handing over.
func VerifySteps() []string {
	return append([]string(nil), verifySteps...)
}

// EvidencePack builds the evidence document for one control.
//
// The mapping says which entries demonstrate the control; each entry's action
// patterns select records from events, which must be the whole log as read —
// the chain is verified end to end first, because a proof taken from a broken
// chain is a proof about nothing, and every matched record's inclusion proof
// is built into one head signed by signer with both algorithms.
//
// Generation refuses on the two conditions that would make the pack a lie
// about itself: a control the mapping does not cover (ErrUnmappedControl),
// and a log whose chain does not verify. A control whose queries match
// nothing is not a refusal — it is an honest empty pack that says what would
// satisfy it.
func EvidencePack(m *Mapping, control string, events []audit.Event,
	signer *audit.HeadSigner, now time.Time) (*Pack, error) {
	if m == nil {
		return nil, errors.New(
			"evidence needs the mapping: Load() it and pass the result")
	}
	if signer == nil {
		return nil, errors.New(
			"evidence needs the head signer; an unsigned head is three " +
				"fields anybody can type")
	}
	entries := m.EntriesFor(control)
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrUnmappedControl, control)
	}
	// The whole chain, before anything is taken from it. Verifying only the
	// matched records would be exactly wrong: an entry whose hash checks can
	// still sit in a log that was rewritten around it, and the inclusion
	// proof would then pin a record into a tree the operator regrew after
	// tampering. The chain check is what says the log itself is intact.
	if ok, problems := audit.Verify(events); !ok {
		p := problems[0]
		return nil, fmt.Errorf(
			"the audit log does not verify, so no evidence can be taken from "+
				"it: entry %d: %s", p.Seq, p.Reason)
	}

	head, err := audit.TreeHead(events, now)
	if err != nil {
		return nil, err
	}
	signed, err := signer.Sign(head)
	if err != nil {
		return nil, err
	}

	// Gather the records. One pass over the log in chain order; an entry
	// matching several patterns (dual.approved evidences two AC-5 entries)
	// appears once, because the pack answers "what is in the log", not
	// "how many ways can each entry be described".
	patterns := m.ActionsFor(control)
	var records []PackRecord
	for i := range events {
		e := events[i]
		matched := false
		for _, p := range patterns {
			if MatchAction(p, e.Action) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		// The proof is built over the same events the head commits to, so
		// the two cannot disagree. The index is the record's position in
		// that slice — the third party never sees the slice, which is why
		// the index travels inside the pack.
		proof, _, err := audit.Inclusion(events, e.Seq)
		if err != nil {
			return nil, fmt.Errorf(
				"entry %d cannot be proved into the head: %w", e.Seq, err)
		}
		records = append(records, PackRecord{Event: e, Index: i, Proof: proof})
	}

	out := &Pack{
		Schema:      PackSchema,
		Control:     control,
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Catalogs:    m.Catalogs,
		Head:        signed,
		Records:     records,
		Verify:      VerifySteps(),
	}
	for _, e := range entries {
		out.Entries = append(out.Entries, PackEntry{
			ID: e.ID, Kind: e.Kind, Title: e.Title,
			Actions: e.Evidence.Actions, Proves: e.Evidence.Proves,
		})
	}
	if len(records) == 0 {
		out.Satisfies = satisfies(entries)
	}
	return out, nil
}

// satisfies says what would have evidenced a control nothing matched, built
// from the mapping's own ids and patterns. Written per entry rather than per
// control, because "what would satisfy AC-5" is only answerable one mapped
// thing at a time, and the entry is where the mapping keeps that answer.
func satisfies(entries []Entry) []string {
	var out []string
	for _, e := range entries {
		if len(e.Evidence.Actions) > 0 {
			out = append(out, fmt.Sprintf(
				"%s would be evidenced by audit records whose action is one "+
					"of: %s", e.ID, strings.Join(e.Evidence.Actions, ", ")))
			continue
		}
		// No action pattern: the entry's evidence is not records in this
		// chain, and its proves line already says what it is instead.
		out = append(out, fmt.Sprintf(
			"%s is evidenced by %s", e.ID, e.Evidence.Proves))
	}
	return out
}

// VerifyPack checks a saved evidence document offline: the third-party path.
//
// It takes the document as bytes and the site's published public keys, and
// needs nothing else — not the log, not the store, not the cooperation of
// the program that generated the pack. The keys are an argument rather than
// a field inside the pack for the same reason a signature is not carried
// beside the key that made it: a pack that vouched for itself would be a
// claim checking itself.
//
// Every check the pack's own verify statement names is performed here: both
// head signatures, each record's own hash, each inclusion proof against the
// head's root, and the pack's description of its records. On success the
// parsed pack is returned, so a caller can report what was verified without
// re-decoding.
func VerifyPack(body []byte, keys *audit.HeadVerifier) (*Pack, error) {
	var p Pack
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("the document is not an evidence pack: %w", err)
	}
	if p.Schema != PackSchema {
		return nil, fmt.Errorf(
			"the document declares schema %q; this verifies %q",
			p.Schema, PackSchema)
	}
	if strings.TrimSpace(p.Control) == "" {
		return nil, errors.New("the pack names no control")
	}
	if keys == nil {
		return nil, errors.New(
			"verification needs the published public keys for the head. A " +
				"pack checked against keys found inside itself would be a " +
				"claim checking itself")
	}
	if err := keys.Verify(p.Head); err != nil {
		return nil, fmt.Errorf("the signed tree head does not verify: %w", err)
	}
	if len(p.Verify) != len(verifySteps) {
		return nil, errors.New(
			"the pack's verify statement does not match this program's, so " +
				"it asks its reader for less than the format requires")
	}
	for i := range verifySteps {
		if p.Verify[i] != verifySteps[i] {
			return nil, errors.New(
				"the pack's verify statement does not match this program's, " +
					"so it asks its reader for less than the format requires")
		}
	}

	seen := map[int64]bool{}
	for i := range p.Records {
		r := p.Records[i]
		if r.Index < 0 || r.Index >= p.Head.Size {
			return nil, fmt.Errorf(
				"record %d claims index %d in a head of %d entries",
				r.Seq, r.Index, p.Head.Size)
		}
		if seen[r.Seq] {
			return nil, fmt.Errorf(
				"record %d appears twice; the pack misdescribes its own "+
					"contents", r.Seq)
		}
		seen[r.Seq] = true
		if _, err := time.Parse(time.RFC3339, r.At); err != nil {
			return nil, fmt.Errorf(
				"record %d's timestamp is not RFC 3339: %w", r.Seq, err)
		}
		// The record's own hash, recomputed. The leaf check below also
		// catches a doctored record — the leaf commits to the pair — but
		// this check says which thing lied: a record whose content does
		// not hash to its hash field was altered, wherever it came from.
		want, err := contentHash(r.Event)
		if err != nil {
			return nil, fmt.Errorf(
				"record %d cannot be re-hashed: %w", r.Seq, err)
		}
		if want != r.Hash {
			return nil, fmt.Errorf(
				"record %d does not match its own hash; it was altered after "+
					"the log wrote it", r.Seq)
		}
		// The proof against the signed root: about twenty hashes, no log.
		if err := audit.VerifyInclusion(r.Event, r.Index, r.Proof, p.Head.Head); err != nil {
			return nil, fmt.Errorf(
				"record %d's inclusion proof does not check against the "+
					"head: %w", r.Seq, err)
		}
		// The pack may only carry records its entries say they gathered.
		// Without this a pack could include a record chosen for its
		// impression rather than its control, and a reader counting
		// records would count padding.
		claimed := false
		for _, e := range p.Entries {
			for _, a := range e.Actions {
				if MatchAction(a, r.Action) {
					claimed = true
				}
			}
		}
		if !claimed {
			return nil, fmt.Errorf(
				"record %d's action %q matches nothing the pack says it "+
					"gathered, so the pack misdescribes its own records",
				r.Seq, r.Action)
		}
	}
	return &p, nil
}

// contentHash recomputes an event's own hash the way the log did: the event
// with its hash field emptied, marshaled, SHA-256.
//
// Written here rather than exported from audit because it is three lines over
// a type this package already holds, and a copy over the same type cannot
// drift: adding a field to audit.Event changes both marshalings identically,
// which is what would silently break if the bytes were re-implemented by
// hand rather than produced from the same struct.
func contentHash(e audit.Event) (string, error) {
	c := e
	c.Hash = ""
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
