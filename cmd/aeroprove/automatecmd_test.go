// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aeroprove/aeroprove/internal/automate"
	"github.com/aeroprove/aeroprove/internal/geo"
	"github.com/aeroprove/aeroprove/internal/out"
)

func geoOffices(t *testing.T, root string) {
	t.Helper()
	b, _ := json.Marshal(geoConfig{Networks: []geo.Network{
		{Prefix: "198.51.100.0/24", Place: geo.Place{Network: "London office", Kind: "office", City: "London", Country: "GB", Lat: 51.5074, Lon: -0.1278}},
		{Prefix: "203.0.113.0/24", Place: geo.Place{City: "Sydney", Country: "AU", Lat: -33.8688, Lon: 151.2093}},
		{Prefix: "192.0.2.0/24", Place: geo.Place{Network: "Corporate VPN", Kind: "vpn"}},
	}})
	if err := os.WriteFile(geoPath(root), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// settled is the history once the background steps have finished, as they
// do on the server.
func settled(t *testing.T, root string) []automate.Run {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		runs, _ := automationEngine(root).Runs()
		busy := false
		for _, r := range runs {
			for _, st := range r.Steps {
				busy = busy || st.Pending
			}
		}
		if !busy || time.Now().After(deadline) {
			return runs
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestNotifyPersonIsResolvedFromRecordsNotFromTheLog.
//
// to=person mails the person the event is about, and who that is comes
// from this program's records. A finding's subject is the entity a log
// supplied — whoever is being detected chose it — so an address found
// there is a delivery the attacker aims, at anybody's mailbox, and not a
// person. Nothing is sent when nobody is on record.
func TestNotifyPersonIsResolvedFromRecordsNotFromTheLog(t *testing.T) {
	if w == nil {
		w = out.New(false)
	}
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := saveAliases(root, map[string]alias{
		// A link a person made, with `aeroprove identity link`.
		"okta:00u1dana":              {Person: "dana@corp.example", How: "linked", At: time.Now()},
		"okta:intruder@evil.example": {Person: "dana@corp.example", How: "linked", At: time.Now()},
		// A pairing a log taught, when an event carried a person field.
		"okta:svc-backup": {Person: "backup@corp.example", How: "learned", At: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}
	finding := func(subject string) automate.Event {
		return automate.Event{Kind: "finding", Subject: subject,
			Summary: "Impossible travel: " + subject}
	}

	// The entity looks like a mail address; the person on record is mailed,
	// and the entity's own address never is.
	to, err := personAddress(root, finding("okta:intruder@evil.example"))
	if err != nil {
		t.Fatalf("a linked identifier did not resolve: %v", err)
	}
	if to != "dana@corp.example" {
		t.Errorf("mail was aimed at %q, not the record's person", to)
	}
	if to == "okta:intruder@evil.example" || to == "intruder@evil.example" {
		t.Errorf("the entity's own address was mailed: %q", to)
	}
	// An identifier that is not an address at all resolves the same way.
	if to, err = personAddress(root, finding("okta:00u1dana")); err != nil ||
		to != "dana@corp.example" {
		t.Errorf("okta:00u1dana resolved to %q (%v)", to, err)
	}
	// A pairing a log taught is the log's word about who somebody is, and
	// the log does not choose who is mailed.
	if to, err = personAddress(root, finding("okta:svc-backup")); err == nil {
		t.Errorf("a pairing learned from a log chose who was mailed: %q", to)
	}
	// The estate's record of who owns a machine, and a principal this
	// program authenticated, stand.
	if to, err = personAddress(root, automate.Event{Kind: "device",
		Subject: "macbook-42", Fields: map[string]string{"owner": "sam@corp.example"}}); err != nil ||
		to != "sam@corp.example" {
		t.Errorf("the estate's owner resolved to %q (%v)", to, err)
	}
	if to, err = personAddress(root, automate.Event{Kind: "signin",
		Subject: "dana@corp.example"}); err != nil || to != "dana@corp.example" {
		t.Errorf("a AeroProve principal resolved to %q (%v)", to, err)
	}

	// Nobody on record: the refusal is recorded in the run's history and
	// nothing is sent — not the entity, not anything else.
	notify := automationActions(root)["notify"]
	_, err = notify.Run(finding("okta:nobody@evil.example"),
		map[string]string{"to": "person"})
	if err == nil || !strings.Contains(err.Error(), "not a person") {
		t.Fatalf("an unknown entity was mailed on: %v", err)
	}
	// An identifier that resolves gets as far as the mail relay; with none
	// configured, the refusal that follows is the relay's.
	_, err = notify.Run(finding("okta:00u1dana"), map[string]string{"to": "person"})
	if err == nil || !strings.Contains(err.Error(), "no mail is set up") {
		t.Fatalf("a resolved person with no relay: %v", err)
	}

	// Through the engine, the refusal is what the run's history says.
	if _, err := automationEngine(root).Save(automate.Rule{
		Name: "tell the person", Enabled: true, Mode: "act", When: "finding",
		If:   []automate.Condition{{Field: "source", Op: "is", Value: "okta/system"}},
		Then: []automate.Step{{Action: "notify", With: map[string]string{"to": "person"}}},
	}, "dana"); err != nil {
		t.Fatal(err)
	}
	if _, err := automationEngine(root).Handle(automate.Event{Kind: "finding",
		Subject: "okta:nobody@evil.example", Summary: "Impossible travel",
		Fields: map[string]string{"source": "okta/system"}}); err != nil {
		t.Fatal(err)
	}
	runs, err := automationEngine(root).Runs()
	if err != nil || len(runs) != 1 {
		t.Fatalf("one event, %d run(s) (%v)", len(runs), err)
	}
	if runs[0].Steps[0].OK || !strings.Contains(runs[0].Steps[0].Said,
		"not a person this program has on record") {
		t.Fatalf("the run's history says %q", runs[0].Steps[0].Said)
	}
}
