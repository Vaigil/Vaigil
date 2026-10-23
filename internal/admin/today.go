// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"slices"
	"time"

	"github.com/quilzo/vaigil/internal/incident"
)

// Today: the first screen after signing in.
//
// What somebody needs first is what is waiting for them, and then what is
// wrong in the parts of the estate they work in. So the screen is a fixed
// frame in that order, the same every day, and nothing on it is generated:
// people find their way faster in a screen they can learn than in one that
// rearranges itself.
//
// Each part is shown by the same grant check as the menu, so nobody sees a
// count for a screen they cannot open, and every figure is a link to the
// records it counts.

// startPath is where a sign-in lands.
func startPath(*http.Request) string { return "/today" }

// todayWaitingShown is how many waiting items Today lists before pointing
// at Approvals for the rest.
const todayWaitingShown = 7

// todayLine is one figure and where its records are.
type todayLine struct {
	N          int
	Text, Href string
	// Warn marks a figure that is about something going wrong.
	Warn bool
}

func (s *Server) handleToday(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	now := time.Now().UTC()

	waiting := s.waitingItems(p, now)
	slices.SortStableFunc(waiting, func(a, b approvalItem) int {
		if d := slices.Index(commitsOrder, a.Commits) - slices.Index(commitsOrder, b.Commits); d != 0 {
			return d
		}
		return a.Since.Compare(b.Since)
	})
	total := len(waiting)
	if len(waiting) > todayWaitingShown {
		waiting = waiting[:todayWaitingShown]
	}

	visible := map[string]bool{}
	for _, d := range visibleTo(s, p) {
		visible[d.Key] = true
	}
	var lines []todayLine
	add := func(n int, one, many, href string, warn bool) {
		if n == 0 {
			return
		}
		text := many
		if n == 1 {
			text = one
		}
		lines = append(lines, todayLine{N: n, Text: text, Href: href, Warn: warn})
	}
	if visible["findings"] && s.Findings != nil && s.Findings.Queue != nil {
		if q, _, err := s.Findings.Queue(now); err == nil {
			add(len(q), "Finding to triage", "Findings to triage", "/findings", true)
		}
	}
	if visible["cases"] && s.Cases != nil && s.Cases.List != nil {
		if all, err := s.Cases.List(); err == nil {
			n := 0
			for _, inc := range all {
				if inc.State == incident.Open {
					n++
				}
			}
			add(n, "Case open", "Cases open", "/security/cases", true)
		}
	}
	if visible["vulns"] && s.Vulns != nil && s.Vulns.Load != nil {
		if v, err := s.Vulns.Load(now); err == nil {
			add(len(v.Matched), "Advisory that matches something in the estate",
				"Advisories that match something in the estate", "/security/vulns", true)
		}
	}
	if visible["automations"] && s.Automations != nil && s.Automations.Engine != nil {
		if runs, err := s.Automations.Engine.Runs(); err == nil {
			n := 0
			for _, run := range runs {
				if now.Sub(run.At) <= 24*time.Hour && run.State != "waiting" {
					n++
				}
			}
			add(n, "Automation ran in the last day", "Automations ran in the last day", "/security/automations", false)
		}
	}

	s.render(w, r, "today.html", map[string]any{
		"Title": "Today", "Nav": "today", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"Waiting": waiting, "WaitingTotal": total, "MoreWaiting": total - len(waiting),
		"Lines": lines, "Date": now.Format("Monday 2 January"),
	})
}
