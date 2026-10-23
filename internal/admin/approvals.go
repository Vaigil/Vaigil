// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/vaigil/vaigil/internal/auth"
	"github.com/vaigil/vaigil/internal/incident"
)

// Approvals: everything waiting for a person, in one place.
//
// What waits lives where it belongs: an act on another platform with its
// case, a run an automation held with its rule, a change to people or
// settings with the request for a second administrator. This screen reads
// each of them and lists what the person looking may decide, so that
// nothing waits unseen because it waited somewhere nobody opened. Each is
// decided on its own page, one at a time.

// approvalItem is one thing waiting.
type approvalItem struct {
	Source, From, Title, Detail, Commits, Href, When string
	Since                                            time.Time
}

// waitingItems is everything waiting that a person may decide, as Approvals
// and Today both list it.
func (s *Server) waitingItems(p principal, now time.Time) []approvalItem {
	// A read-only credential decides nothing, so it is offered nothing to
	// decide.
	if p.Limits.ReadOnly {
		return nil
	}
	var out []approvalItem
	if s.allows(p, auth.ActApprove, auth.AreaSecurity) && s.Cases != nil && s.Cases.List != nil {
		if list, err := s.Cases.List(); err == nil {
			for _, inc := range list {
				for _, a := range inc.Acts {
					// Whoever asked for an act does not approve it.
					if a.State != incident.ActRequested || strings.EqualFold(a.Requested.By, p.Name) {
						continue
					}
					out = append(out, approvalItem{Source: "case", From: "case " + inc.ID,
						Title: a.Title + " on " + a.Target, Detail: "asked by " + a.Requested.By + ": " + clipText(a.Requested.Why, 160),
						Commits: "acts", Href: caseHref(inc.ID), Since: a.Requested.At})
				}
			}
		}
	}
	if s.allows(p, auth.ActApprove, auth.AreaSecurity) && s.Automations != nil && s.Automations.Engine != nil {
		if runs, err := s.Automations.Engine.Runs(); err == nil {
			for _, run := range runs {
				if run.State != "waiting" {
					continue
				}
				out = append(out, approvalItem{Source: "automation", From: firstNonEmpty(run.Name, run.Rule),
					Title: "Let " + firstNonEmpty(run.Name, run.Rule) + " act", Detail: clipText(run.Event.Summary, 160),
					Commits: "acts", Href: "/security/automations", Since: run.At})
			}
		}
	}
	for _, r := range s.pendingRows(p, now) {
		if !r.CanDecide {
			continue
		}
		out = append(out, approvalItem{Source: "people", From: r.By, Title: r.What,
			Detail: clipText(r.Why, 160), Commits: "changes", Href: "/people#pending", Since: r.At})
	}
	for i := range out {
		out[i].When = agoText(now.Sub(out[i].Since))
	}
	return out
}

// commitsOrder is what deciding commits to, most urgent first: acting on
// another platform reaches outside, and a change to who may do what
// cannot be taken back by the person it lets in.
var commitsOrder = []string{"acts", "changes"}

// approvalGroup is the waiting items from one place.
type approvalGroup struct {
	Name  string
	Items []approvalItem
}

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	now := time.Now().UTC()
	data := map[string]any{"Title": "Approvals", "Nav": "approvals", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	items := s.waitingItems(p, now)
	only := r.URL.Query().Get("commits")
	counts := map[string]int{}
	for _, it := range items {
		counts[it.Commits]++
	}
	if only != "" {
		kept := items[:0]
		for _, it := range items {
			if it.Commits == only {
				kept = append(kept, it)
			}
		}
		items = kept
	}
	byName := map[string]*approvalGroup{}
	var order []string
	for _, it := range items {
		g := byName[it.From]
		if g == nil {
			g = &approvalGroup{Name: it.From}
			byName[it.From] = g
			order = append(order, it.From)
		}
		g.Items = append(g.Items, it)
	}
	var groups []approvalGroup
	for _, name := range order {
		g := byName[name]
		sort.SliceStable(g.Items, func(i, j int) bool { return g.Items[i].Since.Before(g.Items[j].Since) })
		groups = append(groups, *g)
	}
	sort.SliceStable(groups, func(i, j int) bool { return len(groups[i].Items) > len(groups[j].Items) })
	type chip struct {
		Name  string
		Count int
	}
	var chips []chip
	for _, c := range commitsOrder {
		if counts[c] > 0 {
			chips = append(chips, chip{c, counts[c]})
		}
	}
	data["Groups"], data["Chips"], data["Only"], data["Total"] = groups, chips, only, len(items)
	s.render(w, r, "approvals.html", data)
}
