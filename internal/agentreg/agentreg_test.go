// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package agentreg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func store(t *testing.T) Store {
	t.Helper()
	return Store{Path: filepath.Join(t.TempDir(), "agents.json")}
}

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func add(t *testing.T, s Store, name string) {
	t.Helper()
	if err := s.Add(Agent{Name: name, Owner: "dana@acme.example",
		Allow: []string{"vaigil_read"}, CreatedBy: "dana"}, t0); err != nil {
		t.Fatal(err)
	}
}

// TestAddStoresTheReviewableUnit: the entry carries what IA-9 asks to be
// able to review — who owns it, what it may call, who decided and when —
// and the file lands beside its siblings with their permissions.
func TestAddStoresTheReviewableUnit(t *testing.T) {
	s := store(t)
	if err := s.Add(Agent{Name: "watcher", Owner: " dana@acme.example ",
		Allow: []string{"vaigil_read", "vaigil_write", "vaigil_read"},
		Note:  "reads the queue overnight", CreatedBy: "dana"}, t0); err != nil {
		t.Fatal(err)
	}
	a, ok, err := s.Get("watcher")
	if err != nil || !ok {
		t.Fatalf("get after add: %v %v", ok, err)
	}
	if a.Owner != "dana@acme.example" {
		t.Errorf("the owner was not trimmed: %q", a.Owner)
	}
	if a.Status != Active {
		t.Errorf("a new agent arrives %s, not %s", Active, a.Status)
	}
	// Duplicates folded, order stable, so two adds typed differently store
	// the same allowlist and a diff of the file means a change.
	if strings.Join(a.Allow, ",") != "vaigil_read,vaigil_write" {
		t.Errorf("allowlist stored as %v", a.Allow)
	}
	if !a.CreatedAt.Equal(t0) || a.CreatedBy != "dana" || !a.ChangedAt.Equal(t0) {
		t.Errorf("provenance not recorded: %+v", a)
	}
	fi, err := os.Stat(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("the registry is %v, not 0600 like the token store", fi.Mode().Perm())
	}
}

// TestAddRefusesWhatItCannotLookUpLater: a name that could not be a key, a
// duplicate, an owner nobody could ask about, and a tool the interface does
// not serve. Each is refused rather than stored loosely, because an
// allowlist entry that names nothing enforceable grants the appearance of a
// boundary without one.
func TestAddRefusesWhatItCannotLookUpLater(t *testing.T) {
	s := store(t)
	for name, a := range map[string]Agent{
		"uppercase":    {Name: "Watcher", Owner: "dana", Allow: []string{"vaigil_read"}},
		"too short":    {Name: "w", Owner: "dana", Allow: []string{"vaigil_read"}},
		"punctuated":   {Name: "watch er", Owner: "dana", Allow: []string{"vaigil_read"}},
		"hyphen-first": {Name: "-watcher", Owner: "dana", Allow: []string{"vaigil_read"}},
		"no owner":     {Name: "watcher", Owner: "   ", Allow: []string{"vaigil_read"}},
		"no tools":     {Name: "watcher", Owner: "dana"},
		"unknown tool": {Name: "watcher", Owner: "dana", Allow: []string{"vaigil_read", "vaigil_decide"}},
		"all unknown":  {Name: "watcher", Owner: "dana", Allow: []string{"publish"}},
	} {
		if err := s.Add(a, t0); err == nil {
			t.Errorf("%s: accepted %+v", name, a)
		}
	}
	// Nothing above was stored, so the registry is still empty: a refused
	// add leaves no half-entry behind.
	if agents, err := s.Load(); err != nil || len(agents) != 0 {
		t.Fatalf("a refused add left something behind: %v %v", agents, err)
	}
	add(t, s, "watcher")
	if err := s.Add(Agent{Name: "watcher", Owner: "dana", Allow: []string{"vaigil_read"}}, t0); err == nil {
		t.Error("a duplicate name was accepted")
	}
}

// TestAbsentIsEmptyAndRefused: the fail-closed half. No file means no
// registered agents, and Get answers not-found rather than erroring — the
// enforcement turns that into a refusal, which is the safe direction.
func TestAbsentIsEmptyAndRefused(t *testing.T) {
	s := store(t)
	if agents, err := s.Load(); err != nil || agents != nil {
		t.Fatalf("absent is not empty: %v %v", agents, err)
	}
	if _, ok, err := s.Get("watcher"); err != nil || ok {
		t.Fatalf("absent is not not-found: %v %v", ok, err)
	}
}

// TestUnreadableIsNotSilentlyEmpty: present-and-broken is the one state
// where pretending the registry is empty would quietly re-register nobody
// and disable every kill switch at once. It is an error.
func TestUnreadableIsNotSilentlyEmpty(t *testing.T) {
	s := store(t)
	add(t, s, "watcher")
	if err := os.WriteFile(s.Path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("an unreadable registry read as empty")
	}
	if _, _, err := s.Get("watcher"); err == nil {
		t.Fatal("an unreadable registry answered a lookup")
	}
}

// TestDisableKeepsTheRowAndTheReason: the kill switch is a status change,
// not a deletion — the register is the review object, and the reason the
// switch was pulled is what whoever enables it again has to read.
func TestDisableKeepsTheRowAndTheReason(t *testing.T) {
	s := store(t)
	add(t, s, "watcher")
	if err := s.Disable("watcher", "proposing nonsense on closed findings", "responder@acme.example", t0); err != nil {
		t.Fatal(err)
	}
	a, ok, err := s.Get("watcher")
	if err != nil || !ok {
		t.Fatalf("disable removed the row: %v %v", ok, err)
	}
	if a.Status != Disabled || a.DisabledWhy != "proposing nonsense on closed findings" {
		t.Errorf("disable stored as %+v", a)
	}
	if a.ChangedBy != "responder@acme.example" || !a.ChangedAt.Equal(t0) {
		t.Errorf("who pulled the switch is not on record: %+v", a)
	}
	// And the switches that must not close silently:
	if err := s.Disable("watcher", "again", "dana", t0); err == nil {
		t.Error("disabling twice was accepted without saying so")
	}
	if err := s.Disable("nobody", "why", "dana", t0); err == nil {
		t.Error("disabling an unregistered agent was accepted")
	}
}

// TestEnableRestoresWithoutGrantingACredential: enable is the registry's
// half only. The entry goes back to active and the disable's provenance is
// replaced by the enable's; the tokens disable revoked stay revoked, which
// the command's tests check against the token store itself.
func TestEnableRestoresWithoutGrantingACredential(t *testing.T) {
	s := store(t)
	add(t, s, "watcher")
	if err := s.Disable("watcher", "why", "dana", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Enable("watcher", "dana@acme.example", t0); err != nil {
		t.Fatal(err)
	}
	a, _, _ := s.Get("watcher")
	if a.Status != Active {
		t.Fatalf("enable left the agent %s", a.Status)
	}
	if a.ChangedBy != "dana@acme.example" {
		t.Errorf("who re-enabled it is not on record: %+v", a)
	}
	if err := s.Enable("watcher", "dana", t0); err == nil {
		t.Error("enabling an active agent was accepted without saying so")
	}
	if err := s.Enable("nobody", "dana", t0); err == nil {
		t.Error("enabling an unregistered agent was accepted")
	}
}

// TestAllowAddsAndRemovesRealToolsOnly.
func TestAllowAddsAndRemovesRealToolsOnly(t *testing.T) {
	s := store(t)
	add(t, s, "watcher")
	if err := s.Allow("watcher", []string{"vaigil_write"}, nil, "dana", t0); err != nil {
		t.Fatal(err)
	}
	a, _, _ := s.Get("watcher")
	if !a.MayUse("vaigil_write") || !a.MayUse("vaigil_read") {
		t.Errorf("allow did not add: %v", a.Allow)
	}
	// Removing the last tool leaves a registered agent that may call
	// nothing: the interface refuses it everything, which is a narrower
	// leash than disable, not a broken one.
	if err := s.Allow("watcher", nil, []string{"vaigil_read", "vaigil_write"}, "dana", t0); err != nil {
		t.Fatal(err)
	}
	a, _, _ = s.Get("watcher")
	if len(a.Allow) != 0 || a.MayUse("vaigil_read") {
		t.Errorf("removal left %v", a.Allow)
	}
	// Only the three real tools, and never a tool both ways at once.
	if err := s.Allow("watcher", []string{"vaigil_decide"}, nil, "dana", t0); err == nil {
		t.Error("an unknown tool was allowed")
	}
	if err := s.Allow("watcher", []string{"vaigil_read"}, []string{"vaigil_read"}, "dana", t0); err == nil {
		t.Error("a tool was added and removed in one change")
	}
	if err := s.Allow("nobody", []string{"vaigil_read"}, nil, "dana", t0); err == nil {
		t.Error("an unregistered agent was allowed a tool")
	}
}

// TestMayUseTreatsAbsenceAsNothing: the allowlist's zero value must not
// mean "everything", because the zero value is what an entry corrupted to
// nothing would leave behind.
func TestMayUseTreatsAbsenceAsNothing(t *testing.T) {
	a := Agent{Name: "watcher", Status: Active}
	for _, tool := range Tools() {
		if a.MayUse(tool) {
			t.Errorf("%s allowed by an empty allowlist", tool)
		}
	}
}

// TestBindReadsTheNamingConvention: the whole credential binding, in one
// place, including the corners — no prefix, nothing after it, and a
// remainder that is not a registrable name (left to the registry to refuse
// rather than silently reinterpreted as a plain token).
func TestBindReadsTheNamingConvention(t *testing.T) {
	for name, want := range map[string]string{
		"agent:watcher": "watcher",
		"agent:a b":     "a b",
		"agent:x":       "x",
	} {
		got, ok := Bind(name)
		if !ok || got != want {
			t.Errorf("Bind(%q) = %q, %v; want %q, true", name, got, ok, want)
		}
	}
	for _, name := range []string{"watcher", "cli", "agent:", "email@acme.example", ""} {
		if got, ok := Bind(name); ok {
			t.Errorf("Bind(%q) = %q, true; a plain name claimed to be an agent", name, got)
		}
	}
}

// TestValidNameMatchesTheIdentifierShape.
func TestValidNameMatchesTheIdentifierShape(t *testing.T) {
	for _, good := range []string{"ab", "watcher", "triage-2", "a-1-b"} {
		if !ValidName(good) {
			t.Errorf("%q refused", good)
		}
	}
	// A trailing hyphen is allowed to match the feed names' shape exactly;
	// the point of the shared shape is that both are typed by people, and
	// two subtly different rules is a support answer nobody needs.
	for _, bad := range []string{"", "a", "-ab", "A b", "under_score",
		"watcher-with-a-name-far-too-long-for-the-register"} {
		if ValidName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
