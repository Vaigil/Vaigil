// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/vaigil/internal/auth"
	"github.com/quilzo/vaigil/internal/incident"
)

// `vaigil approvals`: everything waiting for a person, in one list — acts
// on other platforms a case is waiting to have approved, runs an
// automation held for a person, and changes waiting for a second
// administrator. Each line says what deciding commits to and the command
// that decides it, as the Approvals screen lists them.

// waitingItem is one thing waiting, for the command line.
type waitingItem struct {
	Source  string    `json:"source"`
	From    string    `json:"from,omitempty"`
	What    string    `json:"what"`
	Why     string    `json:"why,omitempty"`
	Commits string    `json:"commits"`
	Since   time.Time `json:"since"`
	Decide  string    `json:"decide"`
}

// waitingFor lists what the caller may decide.
func waitingFor(root string, c *Caller, now time.Time) ([]waitingItem, error) {
	// A read-only credential decides nothing, so it is offered nothing.
	if c.Limits.ReadOnly {
		return nil, nil
	}
	var out []waitingItem
	if authorise(root, c, auth.ActApprove, auth.AreaSecurity) == nil {
		list, err := listIncidents(root)
		if err != nil {
			return nil, err
		}
		for _, inc := range list {
			for _, a := range inc.Acts {
				// Whoever asked for an act does not approve it.
				if a.State != incident.ActRequested || strings.EqualFold(a.Requested.By, c.Name) {
					continue
				}
				out = append(out, waitingItem{Source: "case", From: "case " + inc.ID,
					What: a.Title + " on " + a.Target, Why: "asked by " + a.Requested.By + ": " + a.Requested.Why,
					Commits: "acts", Since: a.Requested.At,
					Decide: fmt.Sprintf("vaigil incident act-approve %s %d", inc.ID, a.ID)})
			}
		}
		runs, err := automationEngine(root).Runs()
		if err != nil {
			return nil, err
		}
		for _, r := range runs {
			if r.State != "waiting" {
				continue
			}
			out = append(out, waitingItem{Source: "automation", From: r.Name, What: "let " + r.Name + " act",
				Why: r.Event.Summary, Commits: "acts", Since: r.At, Decide: "vaigil automate approve " + r.ID})
		}
	}
	pend, err := dualStore(root).Pending(now)
	if err != nil {
		return nil, err
	}
	alone := onlyAdministrator(root, c.Name)
	admin := authorise(root, c, auth.ActGrant, "/") == nil
	for _, r := range pend {
		if !admin || !r.Open(now) || (strings.EqualFold(r.By, c.Name) && !alone) {
			continue
		}
		out = append(out, waitingItem{Source: "people", From: r.By, What: r.What, Why: r.Why,
			Commits: "changes", Since: r.At, Decide: "vaigil pending approve " + r.ID})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Since.Before(out[j].Since) })
	return out, nil
}

func cmdApprovals(root string, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: vaigil approvals")
	}
	now := time.Now().UTC()
	items, err := waitingFor(root, resolveCaller(root, ""), now)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"waiting": items}) {
		return nil
	}
	if len(items) == 0 {
		fmt.Println("  nothing is waiting for you")
		return nil
	}
	for _, it := range items {
		who := it.From
		if who == "" {
			who = it.Source
		}
		fmt.Printf("  %s%-9s%s %-18s %s  %s%s%s\n", bold, it.Commits, reset, truncate(onOneLine(who), 18),
			truncate(printable(it.What), 60), dim, it.Since.Format("2 Jan 15:04"), reset)
		if it.Why != "" {
			fmt.Printf("            %s%s%s\n", dim, truncate(printable(it.Why), 100), reset)
		}
		fmt.Printf("            %s\n", it.Decide)
	}
	return nil
}
