// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aeroprove/aeroprove/internal/spool"
	"github.com/aeroprove/aeroprove/internal/telemetry"
)

// privacyEvent seeds one event with a named actor and target.
func privacySeed(t *testing.T, root string, actor, target telemetry.ID, at time.Time) {
	t.Helper()
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	if _, err := sp.AppendBatch([]telemetry.Event{{
		Time: at, Received: at.Add(time.Second),
		Source: "okta/system", Class: telemetry.ClassAuthentication,
		Disposition: telemetry.DispositionAllowed,
		Actor:       actor,
		Target:      target,
		Message:     "user.session.start",
		Raw:         map[string]string{"country": "NL"},
	}}); err != nil {
		t.Fatal(err)
	}
}

// treeDigest is every file's content under the store, hashed in order: the
// proof that a walk that claims to touch nothing touched nothing.
func treeDigest(t *testing.T, root string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		fmt.Fprintln(h, rel)
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		h.Write(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// The export holds the subject's events and nobody else's: a bare value
// matches whichever directory issued it, an issuer:value matches that one
// directory only, and the cover states the store's own facts.
func TestAPrivacyExportHoldsOnlyTheSubjectsEvents(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	dana := telemetry.ID{Issuer: "okta", Value: "u-1043"}
	alsoDana := telemetry.ID{Issuer: "duo", Value: "u-1043"}
	sam := telemetry.ID{Issuer: "okta", Value: "u-777"}
	app := telemetry.ID{Issuer: "app", Value: "reports"}
	privacySeed(t, root, dana, app, at)
	privacySeed(t, root, alsoDana, app, at.Add(time.Minute))
	privacySeed(t, root, sam, app, at.Add(2*time.Minute))

	subject, err := parsePrivacySubject("u-1043")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := buildPrivacyExport(root, subject, false, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Events) != 2 {
		t.Fatalf("%d events for u-1043, want the okta and the duo one", len(doc.Events))
	}
	for _, e := range doc.Events {
		if strings.Contains(e.Actor, "u-777") {
			t.Errorf("another person's event is in the export: %v", e)
		}
	}

	subject, err = parsePrivacySubject("okta:u-1043")
	if err != nil {
		t.Fatal(err)
	}
	doc, err = buildPrivacyExport(root, subject, false, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Events) != 1 || !strings.Contains(doc.Events[0].Actor, "okta:u-1043") {
		t.Fatalf("the issuer-scoped subject matched %d events: %+v", len(doc.Events), doc.Events)
	}

	// A subject with nothing is an honest empty document, not an error.
	subject, err = parsePrivacySubject("okta:nobody")
	if err != nil {
		t.Fatal(err)
	}
	doc, err = buildPrivacyExport(root, subject, false, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Events) != 0 {
		t.Errorf("events matched a subject who never acted: %+v", doc.Events)
	}
}

// The export reads the store and changes nothing: a data-subject access
// request is answered from the evidence, not taken out on it.
func TestAPrivacyExportTouchesNothing(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Hour)
	privacySeed(t, root, telemetry.ID{Issuer: "okta", Value: "u-1043"},
		telemetry.ID{Issuer: "app", Value: "reports"}, at)
	before := treeDigest(t, root)
	subject, err := parsePrivacySubject("u-1043")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildPrivacyExport(root, subject, false, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if after := treeDigest(t, root); after != before {
		t.Error("the export changed the store it walked")
	}
}

// A pseudonym is the audit log's own subject: it names one form, it is
// refused when it is not one, and it cannot be doubled with a clear name.
func TestAPseudonymIsTheAuditLogsOwnSubject(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := privacyExport(root, []string{"dana", "--pseudonym",
		"p_0123456789abcdef0123456789abcdef"}); err == nil ||
		!strings.Contains(err.Error(), "not both") {
		t.Errorf("a name and a pseudonym together were accepted: %v", err)
	}
	if err := privacyExport(root, []string{"--pseudonym", "dana"}); err == nil ||
		!strings.Contains(err.Error(), "pseudonym looks like") {
		t.Errorf("a value that is not a pseudonym was accepted: %v", err)
	}
}

// The statement says what the store itself says: the retention plan in
// force, or its absence, in this store's own words — and with no store at
// all it refuses rather than describing a store that does not exist.
func TestTheStatementNamesTheStoresOwnFacts(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := privacyStatement(root); err == nil ||
		!strings.Contains(err.Error(), "no event store") {
		t.Errorf("a store that does not exist was described anyway: %v", err)
	}
	privacySeed(t, root, telemetry.ID{Issuer: "okta", Value: "u-1043"},
		telemetry.ID{Issuer: "app", Value: "reports"}, time.Now().UTC())
	if err := privacyStatement(root); err != nil {
		t.Fatal(err)
	}
}
