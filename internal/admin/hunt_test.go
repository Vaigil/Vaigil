// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aeroprove/aeroprove/internal/auth"
	"github.com/aeroprove/aeroprove/internal/detect"
	"github.com/aeroprove/aeroprove/internal/spool"
	"github.com/aeroprove/aeroprove/internal/telemetry"
)

// huntStore is a store where one account signs in from the usual address a
// hundred times and from an odd one once.
func huntStore(t *testing.T, srv *Server) {
	t.Helper()
	dir := t.TempDir()
	sp, err := spool.Open(dir, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	add := func(who, ip, msg string, minutesAgo int) {
		at := now.Add(-time.Duration(minutesAgo) * time.Minute)
		if _, err := sp.Append(telemetry.Event{Source: "okta/system",
			Class:       telemetry.ClassAuthentication,
			Disposition: telemetry.DispositionAllowed,
			Actor:       telemetry.ID{Issuer: "okta", Value: who},
			Observables: []telemetry.Observable{{Kind: telemetry.ObservableIP, Value: ip}},
			Message:     msg, Time: at, Received: at}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 100; i++ {
		add("dana", "198.51.100.7", "signed in", 600-i)
	}
	add("dana", "203.0.113.66", `signed in <script>alert(1)</script>`, 5)
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	srv.Events = &Events{Open: func() (*spool.Spool, func() error, error) {
		s, err := spool.Open(dir, spool.Options{})
		if err != nil {
			return nil, nil, err
		}
		return s, s.Close, nil
	}}
}

func TestAHuntPutsTheRareValueFirst(t *testing.T) {
	srv, token := setup(t)
	huntStore(t, srv)
	body := get(t, srv, "/security/hunt?field=ip&hours=24", token).Body.String()
	if strings.Contains(body, "render error") || !strings.Contains(body, "</html>") {
		t.Fatal("the page did not render to the end")
	}
	odd, usual := strings.Index(body, "203.0.113.66"), strings.Index(body, "198.51.100.7")
	if odd < 0 || usual < 0 || odd > usual {
		t.Errorf("the address seen once is not above the one seen a hundred "+
			"times (at %d and %d)", odd, usual)
	}
	if !strings.Contains(body, "101 events read") {
		t.Error("the page does not say how much it read")
	}
	// With no field chosen it says what the events carry, not nothing.
	first := get(t, srv, "/security/hunt", token).Body.String()
	if !strings.Contains(first, "What these events carry") ||
		!strings.Contains(first, "<code>ip</code>") {
		t.Error("with no field chosen the screen did not list the fields")
	}
	if strings.Contains(first, `value="message"`) {
		t.Error("free text written by whoever can reach the log was offered " +
			"as a field to hunt on")
	}
}

func TestAHuntShowsTheEventsAndADraftRuleAndSavesNothing(t *testing.T) {
	srv, token := setup(t)
	huntStore(t, srv)
	q := url.Values{"field": {"ip"}, "hours": {"24"}, "show": {"203.0.113.66"},
		"where": {"actor.value"}, "op": {"equals"}, "is": {"dana"}}
	body := get(t, srv, "/security/hunt?"+q.Encode(), token).Body.String()
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("an event's message reached the page as markup")
	}
	for _, want := range []string{"As the start of a rule", "hunt.rename-me",
		"203.0.113.66", "found while hunting", "okta/system"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(body, "198.51.100.7") {
		t.Error("events from the usual address were listed for the odd one")
	}
	// A comparison that is not one of the closed set falls back to equals
	// rather than being evaluated as whatever was sent.
	q.Set("op", "regex")
	if w := get(t, srv, "/security/hunt?"+q.Encode(), token); w.Code != 200 ||
		strings.Contains(w.Body.String(), "render error") {
		t.Errorf("an unknown comparison: %d", w.Code)
	}
}

// A condition narrows what is stacked, and the page says by how much.
func TestAHuntsConditionNarrowsWhatIsStacked(t *testing.T) {
	srv, token := setup(t)
	huntStore(t, srv)
	q := url.Values{"field": {"actor.value"}, "hours": {"24"},
		"where": {"ip"}, "op": {"prefix"}, "is": {"203.0."}}
	body := get(t, srv, "/security/hunt?"+q.Encode(), token).Body.String()
	if !strings.Contains(body, "101 events read, 1 matching") {
		t.Error("the condition did not narrow the hunt to the one event")
	}
	// An hour back holds the odd sign-in and few of the usual ones.
	hour := get(t, srv, "/security/hunt?field=ip&hours=1", token).Body.String()
	if strings.Contains(hour, "101 events read") {
		t.Error("the period was not applied")
	}
}

// Events name people and what they did: an author sees none of it.
// Hunting reads the raw events, which is an analyst's: a viewer reads the
// queue.
func TestAViewerDoesNotHunt(t *testing.T) {
	srv, _ := setup(t)
	huntStore(t, srv)
	if err := srv.Policy.Grant(auth.Binding{Principal: "writer",
		Role: auth.RoleViewer, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	secret, _, err := srv.Tokens.IssueSession("w", "writer", auth.RoleViewer, "/",
		time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	w := get(t, srv, "/security/hunt?field=ip&hours=24", secret)
	if w.Code == 200 || strings.Contains(w.Body.String(), "203.0.113.66") {
		t.Errorf("a viewer hunted through the events: %d", w.Code)
	}
}

func TestWithoutAStoreTheHuntSaysSo(t *testing.T) {
	srv, token := setup(t)
	body := get(t, srv, "/security/hunt", token).Body.String()
	if !strings.Contains(body, "without a telemetry") ||
		strings.Contains(body, "0 events read") {
		t.Error("an unwired store was shown as an empty one")
	}
}

// The draft is a rule the engine can read and that matches what was found:
// a draft that does not parse is a transcription job, not a head start.
func TestADraftRuleIsOneTheEngineReadsAndThatMatchesWhatWasFound(t *testing.T) {
	found := telemetry.Event{Source: "okta/system",
		Class: telemetry.ClassAuthentication,
		Actor: telemetry.ID{Issuer: "okta", Value: "dana"},
		Observables: []telemetry.Observable{{Kind: telemetry.ObservableIP,
			Value: "203.0.113.66"}}, Time: time.Now().UTC()}
	where := detect.Match{Field: "actor.value", Op: detect.Equals,
		Values: []string{"dana"}}
	var r detect.Rule
	if err := json.Unmarshal([]byte(draftRule("ip", "203.0.113.66", where,
		true, map[string]bool{"okta/system": true}, found)), &r); err != nil {
		t.Fatal(err)
	}
	if !r.Matches(found) {
		t.Error("the draft does not match the event it was drawn from")
	}
	other := found
	other.Actor.Value = "sam"
	if r.Matches(other) {
		t.Error("the draft dropped the condition the hunt was narrowed by")
	}
	// It is refused as it stands, for want of an event it must not match.
	if r.Validate() == nil {
		t.Error("a rule shown only to fire was accepted as finished")
	}
}

// A condition the sidecar blooms can answer prunes whole segments from the
// hunt. The page must answer exactly what the full read would have — same
// rows, and a count that still covers every event in the period, because a
// bloom-pruned segment was decided over, not quietly dropped the way a
// budget shortfall is.
func TestAHuntPrunedByABloomAnswersWhatAFullReadWould(t *testing.T) {
	srv, token := setup(t)
	dir := t.TempDir()
	sp, err := spool.Open(dir, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	day := func(d int, src, ip string, n int) {
		for i := range n {
			at := now.Add(-time.Duration(d*24) * time.Hour).
				Add(time.Duration(i) * time.Second)
			if _, err := sp.Append(telemetry.Event{Source: src,
				Class:       telemetry.ClassAuthentication,
				Disposition: telemetry.DispositionAllowed,
				Actor:       telemetry.ID{Issuer: "okta", Value: "dana"},
				Observables: []telemetry.Observable{{Kind: telemetry.ObservableIP, Value: ip}},
				Message:     "signed in", Time: at, Received: at}); err != nil {
				t.Fatal(err)
			}
		}
		if err := sp.Seal(); err != nil {
			t.Fatal(err)
		}
	}
	day(4, "github/audit", "198.51.100.7", 100)
	day(3, "github/audit", "198.51.100.7", 100)
	day(2, "okta/system", "203.0.113.66", 100)
	day(1, "proxy/egress", "198.51.100.7", 100)
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	srv.Events = &Events{Open: func() (*spool.Spool, func() error, error) {
		s, err := spool.Open(dir, spool.Options{})
		if err != nil {
			return nil, nil, err
		}
		return s, s.Close, nil
	}}

	// Four hundred events across four sealed segments; one segment holds
	// every okta/system event and is the only one a full read could have
	// matched. The other three are refused by their blooms, and the page
	// must still report four hundred decided over.
	okta := get(t, srv, "/security/hunt?field=ip&hours=168&where=source&"+
		"op=equals&is=okta%2Fsystem", token).Body.String()
	if !strings.Contains(okta, "400 events read, 100 matching") {
		t.Error("a bloom-pruned hunt did not report the whole period as " +
			"decided over")
	}
	if !strings.Contains(okta, "203.0.113.66") {
		t.Error("the one segment that could match was pruned or misread")
	}
	// And the condition the other way: three hundred matching events from
	// the segments the okta hunt refused, with the okta segment pruned.
	other := get(t, srv, "/security/hunt?field=ip&hours=168&where=source&"+
		"op=equals&is=github%2Faudit", token).Body.String()
	if !strings.Contains(other, "400 events read, 200 matching") ||
		strings.Contains(other, "203.0.113.66") {
		t.Error("the hunt over the other sources lost or gained rows")
	}
}
