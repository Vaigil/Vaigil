// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// The GDPR-facing surface: what a data subject is owed, said honestly.
//
// This program's stores are append-only on purpose. The audit log is a hash
// chain whose heads are signed twice and anchored in Bitcoin, and the event
// spool is sealed segment by segment with digests recorded in that log. That
// design is what makes the records evidence rather than claims, and it is
// also what makes "erase this person's rows" a request this codebase will not
// pretend to satisfy: an erasure that quietly rewrote sealed evidence would
// be exactly the tampering the seals exist to catch.
//
// So the honest answer to a data-protection regime has three parts, and each
// is a command here:
//
//	access    a data-subject export — every event whose actor or target is
//	          the subject, with the fields that carry personal data
//	retention bounded, floorable, and holdable — the spool deletes whole
//	          sealed segments on a plan an operator saw, never rows
//	pseudonymisation
//	          the audit log's principals are HMAC handles, not names
//
// What this file refuses to do is tell an erasure lie. Erasure of individual
// events from an append-only chain is a claim this codebase will not make;
// erasureMeaning below says precisely what erasure does mean here, and the
// statement command prints it where a regulator can read it.

// erasureMeaning is the one paragraph the export's cover page and the
// statement both carry, kept in one place because a data subject must not be
// told two different things about erasure depending on which document they
// were handed.
//
// Every clause is checked against the code rather than aspired to: segments
// are digested at seal (spool.Segment.Digest) and the digests anchored in the
// signed log (anchorSealed); retention deletes whole sealed segments only
// (Spool.Retain candidates); the audit chain breaks visibly on any removal
// (audit.Verify); and the detail fields of audit entries can carry free text
// even though content bodies and secrets are refused at the door
// (audit.ForbiddenKey) — which is why "the chain keeps hashes, not content"
// is a sentence this program does not say.
const erasureMeaning = "Erasure here means retention, not row deletion. The " +
	"event spool is append-only: each sealed segment carries a SHA-256 " +
	"digest recorded in the signed audit log, retention deletes whole " +
	"sealed segments on a plan an operator has seen, and no single " +
	"person's events can be removed from a sealed segment without an edit " +
	"the digests are built to catch. The audit log is never rewritten and " +
	"never expires: deleting one of its entries breaks the hash chain at " +
	"that point, which is the tampering the chain exists to make visible. " +
	"It holds principals pseudonymised rather than named, and although its " +
	"entries carry action, resource and free-text detail values rather " +
	"than message content or credentials, an individual entry still cannot " +
	"be erased from it at all."

// cmdPrivacy dispatches the privacy command family.
func cmdPrivacy(root string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf(
			"usage: aertun privacy export SUBJECT [--out FILE] [--audit] " +
				"[--pseudonym p_…] | statement")
	}
	switch args[0] {
	case "export":
		return privacyExport(root, args[1:])
	case "statement":
		return privacyStatement(root)
	default:
		return fmt.Errorf(
			"unknown privacy command %q; try export or statement", args[0])
	}
}

// privacySubject is who the export is about, in the form the operator named.
//
// The clear forms are matched directly against the identifiers the events
// carry: a bare value ("u-1043") matches any directory that issued it, an
// issuer:value ("okta:u-1043") matches that directory only. A pseudonym
// cannot be reversed without the log's key, so --pseudonym matches one
// directly instead of pretending a name was resolved.
type privacySubject struct {
	named     string // exactly what the operator typed, empty for a pseudonym
	issuer    string // set when named was issuer:value
	value     string
	pseudonym string // set when --pseudonym was given
}

// parsePrivacySubject reads the operator's argument.
func parsePrivacySubject(named string) (privacySubject, error) {
	named = strings.TrimSpace(named)
	m := privacySubject{named: named, value: named}
	if i := strings.Index(named, ":"); i > 0 {
		m.issuer, m.value = named[:i], named[i+1:]
	}
	if strings.TrimSpace(m.value) == "" {
		return m, fmt.Errorf(
			"a subject is an identifier: u-1043, or okta:u-1043 to name the " +
				"directory that issued it")
	}
	return m, nil
}

// matchesID reports whether one event identifier is the subject's.
func (m privacySubject) matchesID(id telemetry.ID) bool {
	if m.value == "" || id.Value != m.value {
		return false
	}
	// A bare value matches whichever directory issued it. Two directories
	// issuing the same string for different people is the case the issuer
	// field exists for, so the forms that matched are reported in the
	// document rather than collapsed into one.
	return m.issuer == "" || id.Issuer == m.issuer
}

// clearForms are the spellings of the subject as written, for a store that
// holds identifiers in the clear.
func (m privacySubject) clearForms() []string {
	if m.value == "" {
		return nil
	}
	forms := []string{m.value}
	if m.issuer != "" {
		forms = append(forms, m.issuer+":"+m.value)
	}
	return forms
}

// privacyEvent is one matching event, as a data-protection officer reads it:
// when, from where, what kind, what happened to it, and the fields that can
// carry personal data — which in this store is the actor, the target, the
// device, the message, the observables and anything the source put in raw.
type privacyEvent struct {
	Time        time.Time              `json:"time"`
	Received    time.Time              `json:"received"`
	Source      string                 `json:"source"`
	Class       uint32                 `json:"class"`
	Activity    uint8                  `json:"activity"`
	Disposition string                 `json:"disposition"`
	Severity    uint8                  `json:"severity"`
	Actor       string                 `json:"actor,omitempty"`
	Target      string                 `json:"target,omitempty"`
	Device      string                 `json:"device,omitempty"`
	Message     string                 `json:"message,omitempty"`
	Observables []telemetry.Observable `json:"observables,omitempty"`
	Raw         map[string]string      `json:"raw,omitempty"`
	// Matched says which of the event's identifiers are the subject's, so a
	// reader can tell being the actor from being acted on.
	Matched []string `json:"matched"`
}

// privacyAudit is one matching audit entry. Principal and identity detail
// values are reported as stored — pseudonymised — because the export adds no
// re-identification the log does not already contain.
type privacyAudit struct {
	Seq       int64             `json:"seq"`
	At        string            `json:"at"`
	Action    string            `json:"action"`
	Resource  string            `json:"resource"`
	Outcome   string            `json:"outcome"`
	Principal string            `json:"principal"`
	Kind      string            `json:"kind"`
	Verified  bool              `json:"verified"`
	Model     string            `json:"model,omitempty"`
	Detail    map[string]string `json:"detail,omitempty"`
	// Matched says whether the subject is the principal of the entry or was
	// found in one of its identity detail values.
	Matched []string `json:"matched"`
}

// privacyRetention is the retention policy as it stands, not as it is
// described. Keep and floor are in days because that is how a policy is
// written and how a regulator reads it.
type privacyRetention struct {
	Keep              int        `json:"keep_days"`
	Cap               int64      `json:"cap_bytes"`
	Floor             int        `json:"floor_days,omitempty"`
	HoldsActive       int        `json:"holds_active"`
	SegmentsDeletable int        `json:"segments_deletable_now"`
	WouldAnswerFrom   *time.Time `json:"would_answer_from,omitempty"`
	PlanInForce       string     `json:"plan_in_force"`
}

// privacyHold is one legal hold, on the record.
type privacyHold struct {
	Name  string     `json:"name"`
	By    string     `json:"by"`
	At    time.Time  `json:"at"`
	Until *time.Time `json:"until,omitempty"`
	Why   string     `json:"why"`
}

// privacyStoreCover is the cover page: what kind of store this came from,
// what it covers, and what governs deletion from it. Every field is taken
// from the store as it stands, so two exports of one store cannot disagree
// about the store.
type privacyStoreCover struct {
	Kind        string           `json:"kind"`
	AppendOnly  bool             `json:"append_only"`
	Integrity   string           `json:"integrity"`
	Identifiers string           `json:"identifiers"`
	Segments    int              `json:"segments"`
	Events      int              `json:"events"`
	Bytes       int64            `json:"bytes"`
	AnswersFrom *time.Time       `json:"answers_from,omitempty"`
	Retention   privacyRetention `json:"retention"`
	LegalHolds  []privacyHold    `json:"legal_holds"`
	Erasure     string           `json:"erasure"`
}

// privacyRequest says who the document is about and how they were matched.
type privacyRequest struct {
	Subject   string `json:"subject,omitempty"`
	Pseudonym string `json:"pseudonym,omitempty"`
	// Matched is the identifier forms the export actually found, which is
	// the honest answer when a bare value is issued by two directories.
	Matched []string `json:"matched,omitempty"`
	How     string   `json:"how"`
}

// privacyDocument is the artefact handed over: the subject's events, plus
// the cover page that says what kind of store holds them.
type privacyDocument struct {
	Schema    string            `json:"schema"`
	Generated time.Time         `json:"generated"`
	Request   privacyRequest    `json:"request"`
	Store     privacyStoreCover `json:"store"`
	Events    []privacyEvent    `json:"events"`
	Audit     []privacyAudit    `json:"audit,omitempty"`
	Notes     []string          `json:"notes,omitempty"`
}

// privacyExport produces a data-subject access export. It reads the spool
// and, with --audit, the audit log; it writes nothing back.
func privacyExport(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	outPath := fs.String("out", "", "write the document here rather than stdout")
	withAudit := fs.Bool("audit", false,
		"walk the audit log as well as the event spool")
	pseudonym := fs.String("pseudonym", "",
		"match this pseudonym (p_…) directly in the audit log, rather than "+
			"naming a subject; implies --audit")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) == 0 && strings.TrimSpace(*pseudonym) == "" {
		return fmt.Errorf("usage: aertun privacy export SUBJECT [--out " +
			"FILE] [--audit] [--pseudonym p_…]")
	}
	if len(pos) > 0 && strings.TrimSpace(*pseudonym) != "" {
		return fmt.Errorf(
			"name a subject or a pseudonym, not both: the pseudonym is the " +
				"subject, and a value cannot be matched both ways at once")
	}

	var subject privacySubject
	if len(pos) > 0 {
		var err error
		if subject, err = parsePrivacySubject(pos[0]); err != nil {
			return err
		}
	} else {
		p := strings.TrimSpace(*pseudonym)
		if !strings.HasPrefix(p, "p_") {
			return fmt.Errorf(
				"a pseudonym looks like p_ followed by 32 hex characters — "+
					"the form every principal in the audit log takes. %q is "+
					"not one", p)
		}
		subject = privacySubject{pseudonym: p}
		// A pseudonym has exactly one home: the audit log, whose principals
		// are pseudonymised. The spool's identifiers are clear-form, so
		// there is nothing for a pseudonym to match there, and the walk
		// below says so in the document rather than returning an empty
		// events array that reads as "this person has no events".
		*withAudit = true
	}

	doc, err := buildPrivacyExport(root, subject, *withAudit,
		time.Now().UTC())
	if err != nil {
		return err
	}

	// The act of exporting one person's history is itself recorded — the
	// subject's identifier is pseudonymised in the log's detail like every
	// other identity value, so the record of the request does not become a
	// second, clearer copy of the identifier than the export was for.
	caller := resolveCaller(root, flagToken)
	record(root, caller.auditRecord("privacy.export", "/privacy/export",
		audit.Success, map[string]string{
			"subject": subjectDisplay(subject),
			"events":  fmt.Sprint(len(doc.Events)),
			"entries": fmt.Sprint(len(doc.Audit)),
		}))

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if *outPath == "" {
		// The document is the artefact, so it goes to stdout whole in either
		// mode: a --json caller parses the same bytes a person reads.
		fmt.Println(string(body))
		return nil
	}
	if err := os.WriteFile(*outPath, append(body, '\n'), 0o600); err != nil {
		return err
	}
	if w.JSON(map[string]any{"written": *outPath,
		"events": len(doc.Events), "audit_entries": len(doc.Audit)}) {
		return nil
	}
	w.Human("%s%d event(s) and %d audit entr%s about %s written to %s%s\n",
		bold, len(doc.Events), len(doc.Audit), entrySuffix(len(doc.Audit)),
		subjectDisplay(subject), *outPath, reset)
	w.Human("  %sthe store was read and nothing in it was modified%s\n",
		dim, reset)
	return nil
}

// subjectDisplay is how the document names who it is about.
func subjectDisplay(s privacySubject) string {
	if s.pseudonym != "" {
		return s.pseudonym
	}
	return s.named
}

// buildPrivacyExport walks the stores and builds the document. Split from
// the command so the matching rules and the cover page are testable without
// capturing stdout, and so it is visible that no step here writes anything.
func buildPrivacyExport(root string, subject privacySubject,
	withAudit bool, now time.Time) (*privacyDocument, error) {

	doc := &privacyDocument{
		Schema:    "aertun/privacy-export/v1",
		Generated: now,
	}
	matched := map[string]bool{}

	if subject.pseudonym == "" {
		s, err := openSpoolReadOnly(root)
		if err != nil {
			return nil, err
		}
		if err := s.Range(time.Time{}, time.Time{},
			func(e telemetry.Event) error {
				var where []string
				for _, place := range []struct {
					name string
					id   telemetry.ID
				}{{"actor", e.Actor}, {"target", e.Target}} {
					if !place.id.Zero() && subject.matchesID(place.id) {
						where = append(where, place.name)
						matched[place.id.String()] = true
					}
				}
				if len(where) == 0 {
					return nil
				}
				doc.Events = append(doc.Events, privacyEvent{
					Time: e.Time, Received: e.Received, Source: e.Source,
					Class: uint32(e.Class), Activity: e.Activity,
					Disposition: e.Disposition.String(),
					Severity:    uint8(e.Severity),
					Actor:       e.Actor.String(), Target: e.Target.String(),
					Device: e.Device.String(), Message: e.Message,
					Observables: e.Observables, Raw: e.Raw,
					Matched: where,
				})
				return nil
			}); err != nil {
			return nil, err
		}
		cover, err := privacyStoreFacts(s, now)
		if err != nil {
			return nil, err
		}
		doc.Store = cover
	} else {
		// A pseudonym matches nothing in the spool: its identifiers are
		// clear-form. Said in the notes rather than left to an empty events
		// array, which a reader would take for "no events about this
		// person" rather than "this form names nobody here".
		cover, err := privacyStoreFactsForPseudonym(root, now)
		if err != nil {
			return nil, err
		}
		doc.Store = cover
		doc.Notes = append(doc.Notes,
			"the event spool holds actor, target and device identifiers in "+
				"their clear, issuer-qualified form, so a pseudonym matches "+
				"nothing there; only the audit log was walked")
		doc.Request.How = "a pseudonym matched directly in the audit log"
	}

	if subject.pseudonym != "" {
		doc.Request.Pseudonym = subject.pseudonym
	} else {
		doc.Request.Subject = subject.named
		doc.Request.Matched = sortedKeys(matched)
		doc.Request.How = "the clear identifier forms the operator named, " +
			"matched against each event's actor and target"
	}

	if withAudit {
		entries, how, notes, err := auditEntriesFor(root, subject)
		if err != nil {
			return nil, err
		}
		doc.Audit = entries
		doc.Notes = append(doc.Notes, notes...)
		if how != "" {
			doc.Request.How += "; " + how
		}
	}

	doc.Notes = append(doc.Notes,
		"nothing in the event spool or the audit log was modified by this "+
			"export")
	return doc, nil
}

// openSpoolReadOnly opens the spool without ever sealing or releasing it.
//
// An access export that modified the store it walked would itself be a
// processing of personal data the subject did not ask for. Closing a spool
// seals its open segment — writes a digest, a sidecar and a new index — so
// this handle is simply never closed: a handle that only reads holds no open
// segment and writes nothing. The spool directory must already exist, so an
// export cannot bring a store into being either.
func openSpoolReadOnly(root string) (*spool.Spool, error) {
	if _, err := os.Stat(spoolDir(root)); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf(
				"there is no event store at %s yet, so there is nothing to "+
					"export: %w", spoolDir(root), err)
		}
		return nil, err
	}
	return openSpool(root, spool.Options{})
}

// privacyStoreFacts is the cover page from the spool as it stands, and from
// the retention plan a read of it cannot help but state: the plan is the
// policy in force expressed against this store, which is why the cover reads
// its limits out of the plan rather than out of a configured number nobody
// can check against the store.
func privacyStoreFacts(s *spool.Spool, now time.Time) (privacyStoreCover, error) {
	plan := s.Retain()
	cover := privacyStoreCover{
		Kind:       "append-only event spool",
		AppendOnly: true,
		Integrity: "segments sealed with SHA-256; the digests are recorded " +
			"in the signed audit log, so rewriting a sealed segment means " +
			"forging what that log can prove",
		Identifiers: "actor, target and device identifiers are stored in " +
			"their clear, issuer-qualified form",
		Segments: len(s.Segments()),
		Events:   s.Events(),
		Bytes:    s.Bytes(),
		Retention: privacyRetention{
			Keep:              int(plan.Keep / (24 * time.Hour)),
			Cap:               plan.Cap,
			Floor:             int(plan.Floor / (24 * time.Hour)),
			HoldsActive:       len(s.Holds()),
			SegmentsDeletable: len(plan.Drop),
			PlanInForce:       plan.Why(),
		},
		Erasure: erasureMeaning,
	}
	if oldest := s.Oldest(); !oldest.IsZero() {
		cover.AnswersFrom = &oldest
	}
	if !plan.Covers.IsZero() {
		would := plan.Covers
		cover.Retention.WouldAnswerFrom = &would
	}
	for _, h := range s.Holds() {
		ph := privacyHold{Name: h.Name, By: h.By, At: h.At, Why: h.Why}
		if !h.Until.IsZero() {
			until := h.Until
			ph.Until = &until
		}
		cover.LegalHolds = append(cover.LegalHolds, ph)
	}
	return cover, nil
}

// privacyStoreFactsForPseudonym is the cover for an export that names no
// subject, which still owes the reader the same facts about the store. A
// store that does not exist is a fact on the cover rather than a failure:
// the pseudonym's home is the audit log, which may exist alone.
func privacyStoreFactsForPseudonym(root string, now time.Time) (privacyStoreCover, error) {
	s, err := openSpoolReadOnly(root)
	if err != nil {
		if os.IsNotExist(err) {
			return privacyStoreCover{
				Kind: "append-only event spool (none exists in this store)",
			}, nil
		}
		return privacyStoreCover{}, err
	}
	return privacyStoreFacts(s, now)
}

// auditEntriesFor walks the audit log for the subject.
//
// The log's principals are pseudonymised, so a named subject is matched by
// deriving the subject's pseudonym under the log's key and comparing — the
// one-way derivation audit.Pseudonym exists for. The key is not always
// readable, and the three cases are distinguished because they promise
// different things: a key in hand matches by derivation; a log that was
// never pseudonymised is matched in the clear; a pseudonymised log whose
// key is gone matches nothing but a --pseudonym, and says so.
func auditEntriesFor(root string, subject privacySubject) ([]privacyAudit, string, []string, error) {
	var notes []string
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return nil, "", nil, err
	}
	// A DSAR export is evidence handed to a third party, so it is held to
	// the same standard as the SIEM export: a broken chain is refused, not
	// laundered into a document that looks authoritative.
	if ok, problems := audit.Verify(events); !ok {
		return nil, "", nil, fmt.Errorf(
			"the audit chain does not verify (%d break(s), first at seq "+
				"%d), so its entries are not evidence of anything and will "+
				"not be handed over as though they were",
			len(problems), problems[0].Seq)
	}

	var matchers []string
	how := ""
	key, kerr := os.ReadFile(auditKeyPath(root))
	haveKey := kerr == nil && len(key) > 0
	pseudonymised := anyPseudonymised(events)
	switch {
	case subject.pseudonym != "":
		matchers = []string{subject.pseudonym}
		how = "the pseudonym was matched directly against the audit log"
	case haveKey:
		for _, form := range subject.clearForms() {
			p := audit.Pseudonym(key, form)
			if !containsString(matchers, p) {
				matchers = append(matchers, p)
			}
		}
		how = "the audit log was matched by deriving the subject's " +
			"pseudonym under its key, which this account holds"
	case pseudonymised:
		// The log protects its principals and the key that would match them
		// is not in this account's hand. Refused rather than matched
		// partially: an export that silently omitted the log half would be
		// an access request answered by its smaller half.
		notes = append(notes,
			"the audit log's principals are pseudonymised and its key "+
				"could not be read, so they cannot be matched to a name "+
				"from here; a pseudonym can be matched directly with "+
				"--pseudonym")
		return nil, how, notes, nil
	default:
		matchers = subject.clearForms()
		how = "the audit log holds principals in the clear, so the subject " +
			"was matched against them directly"
	}

	var out []privacyAudit
	for _, e := range events {
		var where []string
		if containsString(matchers, e.Principal) {
			where = append(where, "principal")
		}
		// Identity detail values are pseudonymised by the log itself with
		// the same derivation, so the same matchers apply to them.
		for k, v := range e.Detail {
			if audit.IdentityKeys[k] && containsString(matchers, v) {
				where = append(where, "detail."+k)
			}
		}
		if len(where) == 0 {
			continue
		}
		out = append(out, privacyAudit{
			Seq: e.Seq, At: e.At, Action: e.Action, Resource: e.Resource,
			Outcome: string(e.Outcome), Principal: e.Principal,
			Kind: string(e.Kind), Verified: e.Verified, Model: e.Model,
			Detail: e.Detail, Matched: where,
		})
	}
	if how != "" {
		notes = append(notes,
			"principals and identity detail values in the audit log are "+
				"reported as stored, pseudonymised; this export derives "+
				"nothing in the other direction")
	}
	return out, how, notes, nil
}

// anyPseudonymised reports whether the log's principals look pseudonymised.
func anyPseudonymised(events []audit.Event) bool {
	for _, e := range events {
		if strings.HasPrefix(e.Principal, "p_") {
			return true
		}
	}
	return false
}

// -- the statement ------------------------------------------------------------

// statementAudit is what the statement says about the audit log, which is a
// different store from the spool and is described separately because almost
// every privacy property differs between them.
type statementAudit struct {
	Entries       int    `json:"entries"`
	AppendOnly    bool   `json:"append_only"`
	Expires       bool   `json:"expires"`
	Pseudonymised bool   `json:"pseudonymised"`
	ChainIntact   bool   `json:"chain_intact"`
	Detail        string `json:"detail"`
}

// statementFacts is the statement as data: every number computed from this
// store at the moment of asking, and every claim a paragraph of the prose
// below is allowed to make. The prose renders these; it cannot invent.
type statementFacts struct {
	Schema    string             `json:"schema"`
	Generated time.Time          `json:"generated"`
	Spool     *privacyStoreCover `json:"spool,omitempty"`
	Audit     statementAudit     `json:"audit"`
	Erasure   string             `json:"erasure"`
	Access    string             `json:"access"`
}

// privacyStatement prints the honest privacy posture of this store: what is
// stored, for how long, in what form, what erasure means, and where the
// data-subject export is. This is the document that makes an append-only
// design defensible — by stating the design and its limits rather than
// describing a product that deletes rows on request.
func privacyStatement(root string) error {
	facts, err := buildStatementFacts(root, time.Now().UTC())
	if err != nil {
		return err
	}
	if w.JSON(facts) {
		return nil
	}
	renderStatement(facts)
	return nil
}

// buildStatementFacts gathers the store as it stands.
func buildStatementFacts(root string, now time.Time) (*statementFacts, error) {
	facts := &statementFacts{
		Schema:    "aertun/privacy-statement/v1",
		Generated: now,
		Erasure:   erasureMeaning,
		Access: "aertun privacy export SUBJECT [--audit] collects every " +
			"event whose actor or target is the subject, with this store's " +
			"cover page, and modifies nothing",
	}
	if s, err := openSpoolReadOnly(root); err == nil {
		cover, cerr := privacyStoreFacts(s, now)
		if cerr != nil {
			return nil, cerr
		}
		facts.Spool = &cover
	} else if !os.IsNotExist(err) {
		// A store that exists but cannot be opened is a fault worth failing
		// on; a store that has never existed is a fact worth stating.
		return nil, err
	}

	events, err := audit.Read(auditPath(root))
	if err != nil {
		return nil, err
	}
	intact, _ := audit.Verify(events)
	_, kerr := os.ReadFile(auditKeyPath(root))
	pseudonymised := kerr == nil && (len(events) == 0 || anyPseudonymised(events))
	facts.Audit = statementAudit{
		Entries:       len(events),
		AppendOnly:    true,
		Expires:       false,
		Pseudonymised: pseudonymised,
		ChainIntact:   intact,
		Detail: "entries carry action, resource, outcome and free-text " +
			"detail values; content bodies, tool arguments and credentials " +
			"are refused when the entry is written, not redacted after",
	}
	return facts, nil
}

// renderStatement writes the prose, which is allowed to say only what the
// facts say. Where a number appears in the prose it is interpolated from the
// facts, so the two cannot drift.
func renderStatement(f *statementFacts) {
	w.Human("%sWhat this store holds%s\n", bold, reset)
	if f.Spool == nil {
		w.Human("  no event store exists yet; nothing has been collected\n")
	} else {
		w.Human("  the event spool: %d event(s) in %d segment(s), %d byte(s)",
			f.Spool.Events, f.Spool.Segments, f.Spool.Bytes)
		if f.Spool.AnswersFrom != nil {
			w.Human(", answering from %s\n",
				f.Spool.AnswersFrom.Format(time.RFC3339))
		} else {
			w.Human("\n")
		}
		w.Human("  %severy event carries who did it and what it was done to "+
			"as issuer-qualified identifiers in their clear form, plus the "+
			"message and raw fields the source produced%s\n", dim, reset)
	}
	w.Human("  the audit log: %d entr%s, hash-chained, tree heads signed "+
		"with Ed25519 and ML-DSA-65, append-only with no expiry\n",
		f.Audit.Entries, entrySuffix(f.Audit.Entries))
	if f.Audit.Entries > 0 && !f.Audit.ChainIntact {
		w.Human("  %sthe chain does not verify as it stands; every claim "+
			"below about what the log proves is suspended until it does%s\n",
			red, reset)
	}
	if f.Audit.Pseudonymised {
		w.Human("  %sprincipals and identity-bearing detail values are "+
			"pseudonymised (HMAC-SHA256, p_…) under a key held beside the "+
			"log, so the log alone identifies nobody%s\n", dim, reset)
	} else {
		w.Human("  %sthis log holds principals in the clear: no "+
			"pseudonymisation key exists for it%s\n", yellow, reset)
	}
	w.Human("  %s%s%s\n", dim, f.Audit.Detail, reset)

	w.Human("\n%sHow long it is kept%s\n", bold, reset)
	if f.Spool == nil {
		w.Human("  nothing, until a store exists\n")
	} else {
		r := f.Spool.Retention
		w.Human("  the spool: keep %d day(s) and cap %d byte(s), whichever "+
			"binds first; retention is a plan an operator applies, never a "+
			"side effect of a query\n", r.Keep, r.Cap)
		if r.Floor > 0 {
			w.Human("  a retention floor of %d day(s) is in force: nothing "+
				"younger is deleted, whatever the cap says\n", r.Floor)
		} else {
			w.Human("  %sno retention floor is set: the byte cap can delete "+
				"evidence of any age once the disk is full enough%s\n",
				yellow, reset)
		}
		if r.HoldsActive > 0 {
			w.Human("  %d legal hold(s) suspend deletion entirely:%s\n",
				r.HoldsActive, reset)
			for _, h := range f.Spool.LegalHolds {
				w.Human("    %s%s by %s: %s%s\n", yellow, h.Name, h.By,
					h.Why, reset)
			}
		}
		w.Human("  the plan as it stands: %s\n", r.PlanInForce)
		if f.Spool.AnswersFrom != nil {
			w.Human("  %sthe honest number is the one above: answering from "+
				"%s is what this store can actually produce, not what the "+
				"policy promises%s\n", dim,
				f.Spool.AnswersFrom.Format(time.RFC3339), reset)
		}
	}
	w.Human("  the audit log: kept forever. Nothing is ever removed from " +
		"it, by design\n")

	w.Human("\n%sWhat erasure means here%s\n", bold, reset)
	// Wrapped rather than one long line, because this paragraph is the one a
	// regulator reads and a wall of terminal-width text hides its own
	// sentences.
	for _, para := range strings.Split(f.Erasure, ". ") {
		para = strings.TrimSuffix(para, ".")
		if para == "" {
			continue
		}
		w.Human("  %s%s.%s\n", dim, para, reset)
	}

	w.Human("\n%sWhere a data subject's export is%s\n", bold, reset)
	w.Human("  %s\n", f.Access)
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
