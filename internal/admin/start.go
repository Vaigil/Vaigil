// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/quilzo/vaigil/internal/auth"
)

// The screen somebody sees first.
//
// # Why a checklist of real state rather than a tour
//
// A carousel of screenshots says the same thing to everybody and cannot say
// anything true, because it does not know what this installation holds.
// This reads the store instead. Every step is a question about this
// installation answered at request time: does anything send events here,
// are detections on, is the estate known, does anybody besides you hold a
// role. A step that is done says so and stays visible, because "what did I
// already do" is the question somebody coming back after a week has.
//
// # Why it explains what will refuse them
//
// The separations of duty are the thing about this program that surprises
// people, and being surprised by a refusal is how somebody decides a tool
// is broken rather than careful. So the last section lists what will stop
// them, before the first time it does.

// StartDismissedCookie records that somebody has finished with this screen.
//
// A cookie rather than a stored flag on the person: onboarding is a fact
// about a screen somebody has read. The cost is that a new machine shows it
// again, which is the right failure.
const StartDismissedCookie = "vaigil_started"

// step is one thing to do, and whether this store shows it done.
type step struct {
	Title string
	// Body says what the step is for. Never what to click — a screen that
	// narrates its own buttons goes stale the moment one is renamed.
	Body string
	// Where is the screen that does it, and What names the link.
	Where string
	What  string
	// Done is read from the store at request time.
	Done bool
	// DoneNote states what was found, so a tick is evidence rather than a
	// claim.
	DoneNote string
}

// startState answers each step against the store.
func (s *Server) startState(p principal, now time.Time) []step {
	feeds := 0
	if s.Feeds != nil && s.Feeds.List != nil {
		if got, err := s.Feeds.List(); err == nil {
			for _, f := range got {
				if !f.Off {
					feeds++
				}
			}
		}
	}
	rules := 0
	if s.Detections != nil && s.Detections.Load != nil {
		if v, err := s.Detections.Load(now); err == nil {
			rules = len(v.Rules)
		}
	}
	tools := 0
	if s.Workforce != nil && s.Workforce.Status != nil {
		if st, err := s.Workforce.Status(); err == nil {
			tools = st.Tools
		}
	}
	// People other than whoever is looking, because "you have an account" is
	// not a step and counting yourself would tick it on a fresh store.
	others := 0
	if s.Policy != nil {
		for _, name := range s.Policy.Principals() {
			if name != p.Name {
				others++
			}
		}
	}

	return []step{
		{
			Title: "Bring events in",
			Body: "A feed is an address another system sends its events to: " +
				"an identity provider's security events, or a signed webhook. " +
				"Each event is checked and kept before any detection reads it.",
			Where: "/security/feeds", What: "Feeds",
			Done: feeds > 0, DoneNote: counted(feeds, "feed", "feeds"),
		},
		{
			Title: "Decide what counts as wrong",
			Body: "A detection is a rule over the events, written here or " +
				"imported as Sigma. A new rule runs in a ring that only " +
				"records what it would raise, until its record shows it is " +
				"worth somebody's attention.",
			Where: "/security/detections", What: "Detections",
			Done: rules > 0, DoneNote: counted(rules, "rule", "rules"),
		},
		{
			Title: "Know the estate",
			Body: "The people and machines the company's tools know about, " +
				"each measured against the controls, so a finding names whose " +
				"account and which machine rather than an address.",
			Where: "/workforce", What: "Workforce risk",
			Done: tools > 0, DoneNote: counted(tools, "tool read", "tools read"),
		},
		{
			Title: "Decide who else may do what",
			Body: "Roles follow the work of a security team: viewer, analyst, " +
				"responder and admin, and the jobs engineer, vuln-manager and " +
				"auditor. Everybody signs in with a second factor, and a " +
				"change to who may do what takes two administrators.",
			Where: "/people", What: "People",
			Done: others > 0, DoneNote: counted(others, "other person", "other people"),
		},
	}
}

// counted renders "1 page" or "3 pages", so a completed step states what was
// found rather than only that something was.
func counted(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// gate is something that will refuse, said before it does.
type gate struct {
	Name string
	What string
}

// gates is the list of refusals, in the order somebody meets them.
var gates = []gate{
	{"A second factor", "Everybody signs in with a passkey, or with a " +
		"password and a second factor. There is no setting that turns it off."},
	{"Lockout by place", "Failed sign-ins lock out the place they come from, " +
		"not the person, so somebody guessing cannot lock a colleague out."},
	{"Two people for an act", "Disabling an account or isolating a machine on " +
		"another platform is asked for by one person and approved by another. " +
		"Whoever asked cannot approve it."},
	{"Two people for a playbook", "A playbook run is proposed by one person " +
		"and approved by another, or by whoever commands the case."},
	{"Two administrators", "Making somebody an administrator, an " +
		"administrator's token, a weaker setting and moving the audit log " +
		"each take a second administrator's approval."},
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActView, "/") {
		return
	}

	steps := s.startState(p, time.Now())
	done := 0
	for _, st := range steps {
		if st.Done {
			done++
		}
	}

	s.render(w, r, "start.html", map[string]any{
		"Title": "Get started", "Principal": p, "Nav": "start",
		"Steps": steps, "Done": done, "Total": len(steps),
		"Gates":     gates,
		"Dismissed": startDismissed(r),
	})
}

// handleStartDone records that somebody is finished with this screen.
func (s *Server) handleStartDone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// Authenticated, because it sets a cookie on this origin and nothing
	// unauthenticated has a reason to.
	if _, ok := s.requireAuth(w, r); !ok {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: StartDismissedCookie, Value: "1", Path: "/",
		MaxAge: 365 * 24 * 3600, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil || s.behindTLSProxy(),
	})
	http.Redirect(w, r, startPath(r), http.StatusSeeOther)
}

// startDismissed reports whether this person has finished with the screen.
func startDismissed(r *http.Request) bool {
	c, err := r.Cookie(StartDismissedCookie)
	return err == nil && c.Value == "1"
}
