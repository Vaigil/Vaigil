// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/compliance"
	"github.com/aertun/aertun/internal/config"
)

// The Compliance board: what this program maps to, and what the audit chain
// can prove of it.
//
// Every compliance surface in this industry is a spreadsheet somebody typed:
// control ids beside feature names, true because somebody wrote true. The two
// things that make this screen different are already in the binary — the
// mapping (internal/compliance), which is checked against the program rather
// than asserted, and the signed chain, which holds the records the mapping
// says evidence each entry. So the board is computed, per request, from those
// two, and carries no number it did not count.
//
// # The one distinction the board exists to make
//
// An entry can be mapped and evidenced, or mapped with queries that have
// matched nothing yet, or mapped with no chain queries at all because its
// evidence is the design itself (one event shape for every source; a head
// signed twice). Those are three different facts, and a percentage would
// flatten them into one number an assessor would read as coverage. So every
// count carries its denominator — entries mapped, of how many; entries
// evidenced, of those mapped — and the Recover function of CSF 2.0 and the
// Map function of the AI RMF are listed at zero rather than dropped, because
// a roll-up that quietly hides its empty parts answers a different question
// than the one asked.
//
// Evidence here means one thing, said plainly: records in this deployment's
// chain whose action matches an entry's query. Not "the control works" — the
// records that say it operated, which an assessor checks with the evidence
// command named beside each control. When the chain cannot be read from this
// server, the counts say unknown rather than zero, because an empty log and
// no access look identical and mean opposite things.

// csfFunctions is CSF 2.0's six functions in the framework's own order. All
// six are listed even when the mapping names nothing under one, for the
// reason above.
var csfFunctions = [][2]string{
	{"GV", "Govern"}, {"ID", "Identify"}, {"PR", "Protect"},
	{"DE", "Detect"}, {"RS", "Respond"}, {"RC", "Recover"},
}

// aiRMFFunctions is the AI RMF 1.0's four, likewise.
var aiRMFFunctions = [][2]string{
	{"GV", "Govern"}, {"MP", "Map"}, {"ME", "Measure"}, {"MG", "Manage"},
}

// controlFamilies names the SP 800-53 families the mapping's closed control
// catalog can draw from. A family outside this list falls back to its own
// letters, said as that, rather than guessed at.
var controlFamilies = map[string]string{
	"AC": "Access Control",
	"AT": "Awareness and Training",
	"AU": "Audit and Accountability",
	"CA": "Assessment, Authorization, and Monitoring",
	"IA": "Identification and Authentication",
	"IR": "Incident Response",
	"RA": "Risk Assessment",
	"SA": "System and Services Acquisition",
	"SC": "System and Communications Protection",
	"SI": "System and Information Integrity",
}

// complianceEntry is one mapping entry as the board shows it, with the one
// number the board adds: whether this deployment's chain holds what the
// entry says evidences it.
type complianceEntry struct {
	ID, Kind, Title, Proves string
	// Queried says the entry's evidence is records in this chain; false
	// means the entry's own proves line says what its evidence is instead.
	Queried bool
	// Records is how many records in the chain matched the entry's queries.
	// Zero on a queried entry is a fact worth showing, not a failure to
	// hide: the control may simply not have operated here yet.
	Records int
	// RecordsWord is the entry's evidence as a sentence, built here so the
	// template states rather than decorates.
	RecordsWord string
}

// complianceControl is one control and the entries mapped under it.
type complianceControl struct {
	ID, Family string
	Entries    []complianceEntry
	// Evidenced is how many of the entries have records, of len(Entries).
	Evidenced int
	// Command is the evidence command for this control, which builds the
	// signed pack an assessor checks offline.
	Command string
}

// complianceFamily is one SP 800-53 family's controls.
type complianceFamily struct {
	Name, Label string
	Controls    []complianceControl
}

// frameworkFunction is one row of a roll-up.
type frameworkFunction struct {
	Code, Name string
	// Mapped is how many entries name a category under this function.
	Mapped int
	// Evidenced is how many of those have records in this chain. Counted
	// only when the chain was readable; the template says unknown otherwise.
	Evidenced int
}

// complianceMode is the NIST profile's state on this deployment.
type complianceMode struct {
	// Known says the configuration was readable from this server. Off is
	// its answer when it was; Unknown says why it could not be read.
	Known bool
	On    bool
	// Governed are the settings the mode holds floors on, keys in
	// declaration order.
	Governed []string
	// WeakerRunning are the settings running weaker while the mode is on —
	// weakened before the mode was switched on, or set by hand. The mode
	// refuses new weakening; it does not rewrite the file, and a board that
	// hid them would be the one dishonest thing on this screen.
	WeakerRunning []config.Effective
	// IdleDefault and IdleAdmin are the two NIST idle caps, stated on the
	// card because the mode is named for them and they hold without it.
	IdleDefault, IdleAdmin string
	Unknown                string
}

// complianceBoard is everything the screen shows.
type complianceBoard struct {
	GeneratedAt string
	Catalogs    map[string]string

	CSF, AIRMF []frameworkFunction
	Families   []complianceFamily

	// Entries is every entry in the mapping: the denominator under every
	// other number on the screen.
	Entries int
	// Queried is how many entries' evidence is records in this chain.
	Queried int
	// Evidenced is how many of those matched at least one record — counted,
	// and only meaningful, when the chain was read.
	Evidenced int
	// ChainRead says the chain was read whole: Evidenced is a count when it
	// is set and a question this server cannot answer when it is not.
	ChainRead bool
	// RecordsRead is how many records the chain held, the denominator
	// behind "evidenced": zero records and an unreadable chain both give
	// Evidenced 0, and only this count tells them apart.
	RecordsRead int
	// ChainWord says which of the three chain states this page counted:
	// read (with its size), absent from this server, or unreadable.
	ChainWord string

	Mode complianceMode
}

// buildComplianceBoard computes the board from the mapping and the chain.
//
// The chain arrives as the whole log and a flag saying it could be read; the
// board counts per distinct action rather than per record, because the
// mapping's queries are about actions and a chain of a million records holds
// at most a few dozen of them.
func buildComplianceBoard(m *compliance.Mapping, events []audit.Event, chainRead bool, chainWord string, mode complianceMode) complianceBoard {
	b := complianceBoard{
		GeneratedAt: m.Generated,
		Catalogs:    m.Catalogs,
		Mode:        mode,
		ChainWord:   chainWord,
		ChainRead:   chainRead,
		Entries:     len(m.Entries),
		RecordsRead: len(events),
	}

	actions := map[string]int{}
	for _, e := range events {
		actions[e.Action]++
	}

	// The entry rows and the totals in one pass: Queried, Evidenced and the
	// per-entry records word all turn on the same match.
	byControl := map[string][]complianceEntry{}
	evidenced := map[string]bool{} // entry id -> any record matched
	recordsOf := map[string]int{}  // entry id -> matched records
	for _, ent := range m.Entries {
		entry := complianceEntry{
			ID: ent.ID, Kind: ent.Kind, Title: ent.Title,
			Proves:  ent.Evidence.Proves,
			Queried: len(ent.Evidence.Actions) > 0,
		}
		if entry.Queried {
			b.Queried++
			for a, n := range actions {
				for _, p := range ent.Evidence.Actions {
					if compliance.MatchAction(p, a) {
						recordsOf[ent.ID] += n
					}
				}
			}
			entry.Records = recordsOf[ent.ID]
			switch {
			case entry.Records > 0:
				evidenced[ent.ID] = true
				b.Evidenced++
				entry.RecordsWord = fmt.Sprintf("%d record%s in this chain",
					entry.Records, pluralS(entry.Records))
			default:
				entry.RecordsWord = "no records matched yet — the control may " +
					"simply not have operated here"
			}
		} else {
			entry.RecordsWord = "evidence is the design itself, not records " +
				"the chain could hold"
		}
		for _, c := range ent.NIST.Controls {
			byControl[c] = append(byControl[c], entry)
		}
	}

	// The roll-ups count each entry once under every function it names, and
	// only once per function however many categories it names there — an
	// entry carrying DE.AE and DE.CM is one entry under Detect, which is
	// the denominator the board promises.
	for _, fn := range csfFunctions {
		row := frameworkFunction{Code: fn[0], Name: fn[1]}
		for _, ent := range m.Entries {
			for _, c := range ent.NIST.CSF {
				if strings.HasPrefix(c, fn[0]+".") {
					row.Mapped++
					if evidenced[ent.ID] {
						row.Evidenced++
					}
					break
				}
			}
		}
		b.CSF = append(b.CSF, row)
	}
	for _, fn := range aiRMFFunctions {
		row := frameworkFunction{Code: fn[0], Name: fn[1]}
		for _, ent := range m.Entries {
			for _, c := range ent.NIST.AIRMF {
				if strings.HasPrefix(c, fn[0]+"-") {
					row.Mapped++
					if evidenced[ent.ID] {
						row.Evidenced++
					}
					break
				}
			}
		}
		b.AIRMF = append(b.AIRMF, row)
	}

	// Controls grouped by family, in the catalog's own order: sorted ids,
	// which puts families together and controls in order inside them.
	for _, c := range m.Controls() {
		family := c
		if len(family) >= 2 {
			family = family[:2]
		}
		entries := byControl[c]
		ctrl := complianceControl{
			ID: c, Family: family, Entries: entries,
			Command: "aertun compliance evidence " + c,
		}
		for _, e := range entries {
			if e.Records > 0 {
				ctrl.Evidenced++
			}
		}
		label := controlFamilies[family]
		if label == "" {
			label = family
		}
		var fam *complianceFamily
		for i := range b.Families {
			if b.Families[i].Name == family {
				fam = &b.Families[i]
				break
			}
		}
		if fam == nil {
			b.Families = append(b.Families, complianceFamily{Name: family, Label: label})
			fam = &b.Families[len(b.Families)-1]
		}
		fam.Controls = append(fam.Controls, ctrl)
	}
	return b
}

// pluralS is "s" for a count that is not one. countOf (used by the
// templates) makes a whole phrase; this is the one letter.
func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// minutesIn is a duration in whole minutes, as the idle caps are stated.
func minutesIn(d time.Duration) string {
	return fmt.Sprintf("%d minutes", int(d.Minutes()))
}

// handleCompliance is the Compliance board.
func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// An administrator's, like the Settings screen it sits beside: the board
	// names every detection this deployment runs and the state of its
	// floors, which is a target list and a posture statement in one.
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	data := map[string]any{
		"Title": "Compliance", "Nav": "compliance", "Principal": p,
	}

	m, err := compliance.Load()
	if err != nil {
		// The mapping ships in the binary and is validated by its own
		// package's tests, so this is close to unreachable — and it is said
		// rather than rendered as zeros, because a board that cannot read
		// its map is not a board that mapped nothing.
		data["Unavailable"] = "the control mapping could not be read: " +
			err.Error()
		s.render(w, r, "compliance.html", data)
		return
	}

	// The chain: read whole when this server can, said otherwise. The three
	// states are different facts and the page's denominators depend on
	// which one holds.
	var events []audit.Event
	chainWord := ""
	chainRead := false
	switch {
	case s.LoadAudit == nil:
		chainWord = "this server was started without access to the audit " +
			"log, so what the chain evidences is unknown here — not zero"
	default:
		evs, aerr := s.LoadAudit()
		if aerr != nil {
			chainWord = "the audit log could not be read: " + aerr.Error()
		} else {
			events = evs
			chainRead = true
			chainWord = fmt.Sprintf("read whole: %d record%s",
				len(events), pluralS(len(events)))
		}
	}

	// The mode: read from the configuration when there is one, with the
	// floors it holds and — honestly — anything already running weaker.
	mode := complianceMode{
		IdleDefault: minutesIn(DefaultIdle),
		IdleAdmin:   minutesIn(auth.PrivilegedIdle),
	}
	switch {
	case s.Settings == nil || s.Settings.Load == nil:
		mode.Unknown = "this server was started without the configuration, " +
			"so whether NIST mode is on cannot be read here"
	default:
		cfg, cerr := s.Settings.Load()
		if cerr != nil || cfg == nil {
			mode.Unknown = "the configuration could not be read: " +
				errString(cerr)
		} else {
			mode.Known = true
			mode.On = cfg.Bool(config.NISTModeKey)
			mode.Governed = config.NISTGoverned()
			if mode.On {
				mode.WeakerRunning = cfg.Weakened()
			}
		}
	}

	board := buildComplianceBoard(m, events, chainRead, chainWord, mode)
	data["Board"] = board
	s.render(w, r, "compliance.html", data)
}

// errString says an error, or nothing when there is none. Readability
// shorthand for the two-field cases above.
func errString(err error) string {
	if err == nil {
		return "no configuration was returned"
	}
	return err.Error()
}
