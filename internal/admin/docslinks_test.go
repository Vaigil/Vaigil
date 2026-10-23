// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"sort"
	"strings"
	"testing"
)

// The manual used to be compiled in, and a test read it to prove that the Help
// link on every screen landed on a section that existed.
//
// It is published separately now, so that proof is no longer available at
// compile time. What is available is the contract: docSections names every
// anchor the site carries, and these tests hold both ends of it — no screen
// may point outside the list, and nothing may sit in the list that no screen
// and no reading path needs.
//
// The site checks the other half, that its own pages actually carry these
// anchors. Neither half proves the other. Each fails loudly on its own side,
// and the failure a reader suffers — Help landing on nothing — needs both to
// be wrong at once.

func TestEveryScreenPointsAtASectionTheManualCarries(t *testing.T) {
	if len(docSections) < 20 {
		t.Fatalf("docSections has %d entries; that is not a manual and a test "+
			"checking against an empty list passes by checking nothing",
			len(docSections))
	}
	for _, d := range destinations {
		if d.Doc == "" {
			t.Errorf("%q names no documentation section. Every screen has to "+
				"be explained somewhere, and the Help link in its footer is "+
				"where somebody looks.", d.Key)
			continue
		}
		if !docSections[d.Doc] {
			t.Errorf("%q sends Help to #%s, which is not a section the manual "+
				"publishes. Add it to the site and to docSections, or point "+
				"the screen at the section that replaced it.", d.Key, d.Doc)
		}
	}
}

// Nothing sits in the list unused.
//
// The other direction, and the one that rots quietly: a screen is renamed, its
// anchor stops being referenced, and the entry stays behind describing a
// section nobody arrives at. The standalone set is the exception, written out
// so that each unlinked section is a decision rather than a leftover.
func TestNoDeclaredSectionIsUnaccountedFor(t *testing.T) {
	linked := map[string]bool{}
	for _, d := range destinations {
		linked[d.Doc] = true
	}
	// Sections no screen owns, because they explain a concept or a surface
	// rather than a destination.
	standalone := map[string]bool{
		"install":  true,
		"roles":    true,
		"cli":      true,
		"mcp":      true,
		"security": true,
		"licence":  true,
	}
	var loose []string
	for id := range docSections {
		if !linked[id] && !standalone[id] {
			loose = append(loose, id)
		}
	}
	if len(loose) > 0 {
		sort.Strings(loose)
		t.Errorf("these sections are declared and nothing points at them:\n  %s\n"+
			"Either link a screen to it or list it as standalone.",
			strings.Join(loose, "\n  "))
	}
}

// The footer links have to be absolute, and to the published manual.
//
// A relative "/docs#..." survived a move once already: it kept rendering, kept
// looking like a link, and 404'd on every screen against an origin that had
// stopped serving documentation. An absolute URL fails visibly at the target
// instead of invisibly at the source.
func TestTheFooterLinksToThePublishedManual(t *testing.T) {
	srv, token := setup(t)
	w := get(t, srv, "/today", token)
	body := w.Body.String()

	if !strings.Contains(body, DocsBase) {
		t.Fatalf("no screen links to the manual at %s", DocsBase)
	}
	// Help lands on the section for the screen being looked at, not the top.
	want := DocURL("start")
	if !strings.Contains(body, want) {
		t.Errorf("Today does not send Help to %s, so Help means "+
			"\"help\" rather than \"help with this\"", want)
	}
	// Leaving this origin without handing the target a window handle.
	if !strings.Contains(body, `rel="noopener noreferrer"`) {
		t.Error("the outbound documentation links carry no rel=noopener")
	}
}

// Every navigation destination is served, and every screen is a destination.
//
// This lived in docs_test.go, which went when the manual did. It has nothing to
// do with documentation and is one of the load-bearing structural checks: the
// navigation is data, so the link test cannot see its hrefs, and without this
// a screen can be registered in the mux and reachable by nobody.
func TestEveryDestinationIsServedAndEveryScreenIsADestination(t *testing.T) {
	served := servedRoutes(t)
	for _, d := range destinations {
		if !resolves(served, d.Path) {
			t.Errorf("the navigation offers %q at %s and nothing serves it",
				d.Label, d.Path)
		}
	}

	// The other direction: a screen registered in the mux and absent from the
	// table is a screen nobody can navigate to. Sub-paths and write endpoints
	// are not destinations, so only top-level GET screens are required.
	inNav := map[string]bool{}
	for _, d := range destinations {
		inNav[d.Path] = true
	}
	for route := range served {
		if strings.Count(route, "/") != 1 || strings.HasSuffix(route, "/") {
			continue // a sub-path, or the root pattern
		}
		if _, excused := notADestination[route]; inNav[route] || excused {
			continue
		}
		t.Errorf("%s is served and is not in the navigation table, so nobody "+
			"can reach it by clicking. Add a row, or list it as not a "+
			"destination with a reason.", route)
	}
}

// notADestination is every top-level route that is not a place to navigate to.
var notADestination = map[string]string{
	"/theme":     "a preference toggle",
	"/sidebar":   "a preference toggle",
	"/signin":    "reached when not signed in",
	"/signout":   "a form target",
	"/style.css": "a stylesheet",
	"/admin.js":  "the console's script, fetched by every page's head",
	"/icon.svg":  "the mark, fetched as a favicon; an image, not a screen",
}
