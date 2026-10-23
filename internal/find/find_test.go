// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package find

import (
	"strings"
	"testing"
)

func sources() Sources {
	return Sources{
		Screens: []Destination{
			{Title: "Feeds", Path: "/security/feeds", Group: "Detection",
				Also: []string{"ingest", "webhook"}},
			{Title: "Cases", Path: "/security/cases", Group: "Operations"},
			{Title: "People", Path: "/people", Group: "Administration",
				Also: []string{"permission", "role"}},
		},
		Settings: []Option{
			{Key: "token.api.ttl.default", Summary: "how long an API token lives"},
			{Key: "api.rate.per_minute", Summary: "requests a caller may make"},
		},
	}
}

// The thing somebody is looking for is usually a screen, and a screen is
// findable by the word they would use rather than the word it was named.
func TestAScreenIsFoundByTheWordSomebodyWouldUse(t *testing.T) {
	for query, want := range map[string]string{
		"feeds":      "/security/feeds",
		"feed":       "/security/feeds", // a prefix, which is what people type
		"ingest":     "/security/feeds", // a synonym
		"webhook":    "/security/feeds",
		"permission": "/people",
		"cases":      "/security/cases",
	} {
		hits := Search(query, sources(), 10)
		if len(hits) == 0 {
			t.Errorf("%q found nothing", query)
			continue
		}
		var paths []string
		found := false
		for _, h := range hits {
			paths = append(paths, h.Path)
			if h.Kind == Screen && h.Path == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q did not find the %s screen; got %v", query, want, paths)
		}
	}
}

// A setting is findable by what it does, not only by its key.
//
// Seventy keys, each with a summary written for somebody deciding whether to
// change it, and no way to search that text until now.
func TestASettingIsFoundByWhatItDoes(t *testing.T) {
	for _, query := range []string{"token", "ttl", "how long an API token lives"} {
		var found bool
		for _, h := range Search(query, sources(), 10) {
			if h.Kind == Setting && h.Title == "token.api.ttl.default" {
				found = true
			}
		}
		if !found {
			t.Errorf("%q did not find token.api.ttl.default", query)
		}
	}
}

// Every result says what matched: a result somebody cannot account for is a
// result they do not trust.
func TestEveryResultSaysWhyItIsThere(t *testing.T) {
	for _, query := range []string{"feeds", "token", "cases", "people", "rate"} {
		for _, h := range Search(query, sources(), 20) {
			if strings.TrimSpace(h.Why) == "" {
				t.Errorf("%q returned a %s (%q) with nothing saying why",
					query, h.Kind, h.Title)
			}
			if strings.TrimSpace(h.Title) == "" {
				t.Errorf("%q returned a %s with no title", query, h.Kind)
			}
		}
	}
}

// There is no syntax, and nothing that looks like syntax does anything.
//
// A colon, a quote, a bracket, a minus sign and a star are characters in a
// word here and mean nothing else — so there is no expression to inject
// into, because there is no expression.
func TestNothingThatLooksLikeSyntaxIsSyntax(t *testing.T) {
	src := sources()

	// A field-scoped query in the shape every other CMS accepts finds what the
	// words find, not what the operator would mean.
	scoped := Search("title:feeds", src, 10)
	plain := Search("title feeds", src, 10)
	if len(scoped) != len(plain) {
		t.Errorf("`title:feeds` returned %d hits and `title feeds` returned "+
			"%d; the colon is doing something", len(scoped), len(plain))
	}

	// Negation is not negation.
	if hits := Search("-feeds", src, 10); len(hits) == 0 {
		t.Error("`-feeds` excluded something, so the minus sign is an operator")
	}

	// And none of these is an error, a panic, or a way to reach anything.
	for _, query := range []string{
		`" OR 1=1 --`, `{{ body }}`, `../../etc/passwd`, `*`, `()`,
		`feeds AND token`, `feeds|token`, `\x00`, strings.Repeat("a", 5000),
	} {
		for _, h := range Search(query, src, 10) {
			if h.Kind != Screen && h.Kind != Setting {
				t.Errorf("%q produced a hit of kind %q, which is not one of "+
					"the two", query, h.Kind)
			}
		}
	}
}

// An empty or wordless query finds nothing rather than everything.
func TestAWordlessQueryFindsNothing(t *testing.T) {
	for _, query := range []string{"", "   ", "\t\n", "a", "-", "!!!"} {
		if hits := Search(query, sources(), 10); len(hits) != 0 {
			t.Errorf("%q returned %d hits; a query with no words in it should "+
				"return nothing rather than everything", query, len(hits))
		}
	}
}

// The caller decides what may be searched.
//
// Sources is passed in rather than opened here, so access rules are applied
// before anything is looked at. Filtering results afterwards is how the
// count of hits leaks what the list contained.
func TestNothingIsFoundInASourceThatWasNotSupplied(t *testing.T) {
	empty := Sources{}
	for _, query := range []string{"feeds", "token", "cases", "people"} {
		if hits := Search(query, empty, 10); len(hits) != 0 {
			t.Errorf("%q found %d things in an empty Sources", query, len(hits))
		}
	}

	// And a viewer given no settings finds no settings, while still finding
	// the screens they may open.
	reader := Sources{Screens: sources().Screens}
	for _, h := range Search("token", reader, 10) {
		if h.Kind == Setting {
			t.Errorf("a caller that supplied no settings found one: %q", h.Title)
		}
	}
}

// The same search twice gives the same order.
//
// Map iteration is random in Go, so a finder that ranks straight out of one
// reorders between two identical searches — which makes somebody think the
// store changed underneath them.
func TestTheSameSearchTwiceGivesTheSameOrder(t *testing.T) {
	first := Search("feeds token cases", sources(), 20)
	for i := 0; i < 20; i++ {
		again := Search("feeds token cases", sources(), 20)
		if len(again) != len(first) {
			t.Fatalf("run %d returned %d hits, the first returned %d",
				i, len(again), len(first))
		}
		for j := range first {
			if again[j].Title != first[j].Title {
				t.Fatalf("run %d put %q where the first put %q",
					i, again[j].Title, first[j].Title)
			}
		}
	}
}

// The limit is a limit.
func TestTheLimitHolds(t *testing.T) {
	if hits := Search("feeds token cases people rate", sources(), 2); len(hits) > 2 {
		t.Errorf("asked for 2 and got %d", len(hits))
	}
}

// A term matches the start of a word, not any run of letters inside one.
//
// Searching "pen" returned network.mode, because its summary contains "open".
// These strings are short, so a spurious hit is a large fraction of a small
// list rather than noise at the bottom of a big one.
func TestATermMatchesTheStartOfAWordAndNotTheMiddle(t *testing.T) {
	src := Sources{
		Settings: []Option{
			{Key: "network.mode", Summary: "whether this deployment may reach " +
				"the network: open or offline"},
			{Key: "token.api.ttl.default", Summary: "how long an API token lives"},
		},
		Screens: []Destination{
			{Title: "Feeds", Path: "/security/feeds", Group: "Detection"},
			{Title: "Start", Path: "/start", Group: "Reference"},
		},
	}

	// Inside a word: no.
	for _, query := range []string{"pen", "art", "oke"} {
		if hits := Search(query, src, 10); len(hits) != 0 {
			t.Errorf("%q matched %d things on a run of letters inside a word: "+
				"%s", query, len(hits), hits[0].Title)
		}
	}

	// The start of a word: yes, because that is what people type.
	for query, want := range map[string]string{
		"fee":   "Feeds",
		"feeds": "Feeds",
		"star":  "Start",
		"token": "token.api.ttl.default",
		"ttl":   "token.api.ttl.default",
		"netw":  "network.mode",
	} {
		hits := Search(query, src, 10)
		found := false
		for _, h := range hits {
			if h.Title == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q did not find %q; people type the beginning of a word",
				query, want)
		}
	}
}
