// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package agentreg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mapStore is a mapping beside a registry that holds the agents the tests
// name, so the rows below vary the mapping and only the mapping.
func mapStore(t *testing.T) MapStore {
	t.Helper()
	dir := t.TempDir()
	s := MapStore{Path: filepath.Join(dir, "agentmaps.json"),
		Registry: filepath.Join(dir, "agents.json")}
	for _, name := range []string{"watcher", "triage", "docs-bot", "loader"} {
		add(t, Store{Path: s.Registry}, name)
	}
	return s
}

// TestMapDeclaresAndReadsBack: the declaration is the whole object — host,
// names, whose word it is — and it reads back in one piece, folded by case
// the way host names compare, because a recorder that spells the host
// differently from the operator is the common case and not an edge.
func TestMapDeclaresAndReadsBack(t *testing.T) {
	s := mapStore(t)
	if err := s.Map("build01", "watcher", "dana", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Map("build01", "triage", "dana", t0); err != nil {
		t.Fatal(err)
	}
	maps, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(maps) != 1 || maps[0].Host != "build01" {
		t.Fatalf("the mapping read back as %+v", maps)
	}
	if got := strings.Join(maps[0].Agents, ","); got != "triage,watcher" {
		t.Errorf("the declared names stored as %s, want sorted so the file "+
			"diffs like a declaration", got)
	}
	if maps[0].ChangedBy != "dana" || maps[0].ChangedAt != t0 {
		t.Errorf("whose word it is went missing: %+v", maps[0])
	}
	// The registry's own discipline, asserted the registry's own way: the
	// mapping names who acts in this store, so it is not world-readable.
	fi, err := os.Stat(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("the mapping is %v, not 0600 like the registry beside it",
			fi.Mode().Perm())
	}
	// The case fold, both directions, and the host nobody mapped.
	if got := AgentsFor(maps, "BUILD01"); strings.Join(got, ",") != "triage,watcher" {
		t.Errorf("a recorder spelling the host upper-case got %v; host names "+
			"compare folded or the join silently misses", got)
	}
	if got := AgentsFor(maps, "ci02"); got != nil {
		t.Errorf("an unmapped host carried %v; nothing declared means nothing",
			got)
	}
	if hosts := Hosts(maps, "watcher"); strings.Join(hosts, ",") != "build01" {
		t.Errorf("the register's listing half got %v", hosts)
	}
}

// TestMapRefusesNamesTheRegistryDoesNotHold: the mapping may only name
// registered agents, because its whole value is that evidence joined on a
// declared name is joined on a name the gates, the tokens and the review
// all know. A mapping to a name nobody registered would attribute evidence
// to nobody.
func TestMapRefusesNamesTheRegistryDoesNotHold(t *testing.T) {
	s := mapStore(t)
	if err := s.Map("build01", "ghost", "dana", t0); err == nil {
		t.Fatal("an unregistered agent was mapped")
	} else if !strings.Contains(err.Error(), "no agent") {
		t.Errorf("the refusal does not name the registry: %s", err)
	}
	if err := s.Map("build01", "Watcher", "dana", t0); err == nil {
		t.Error("a name that could not be a registry key was mapped")
	}
	// A registry that cannot be read is not an empty one.
	broken := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(broken, []byte("["), 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := MapStore{Path: filepath.Join(t.TempDir(), "agentmaps.json"),
		Registry: broken}
	if err := s2.Map("build01", "watcher", "dana", t0); err == nil {
		t.Error("a mapping was made against a registry that could not be read")
	}
}

// TestMapRefusesAnUnwritableHost: a host with a space in it is a paste that
// went wrong, and a host the recorder could never report is a declaration
// that matches nothing. Both refused, in words.
func TestMapRefusesAnUnwritableHost(t *testing.T) {
	s := mapStore(t)
	for _, host := range []string{"", "  ", "build 01", "build01\nci02",
		strings.Repeat("h", 254)} {
		if err := s.Map(host, "watcher", "dana", t0); err == nil {
			t.Errorf("%q was accepted as a host", host)
		}
	}
}

// TestMapCapsAHostAtFour: the cap is the difference between describing a
// shared box and writing an inference — a fifth agent on one host means
// somebody mapped a fleet instead of its machines, and the fifth is refused
// with the four it would sit beside.
func TestMapCapsAHostAtFour(t *testing.T) {
	s := mapStore(t)
	for _, agent := range []string{"watcher", "triage", "docs-bot", "loader"} {
		if err := s.Map("build01", agent, "dana", t0); err != nil {
			t.Fatal(err)
		}
	}
	add(t, Store{Path: s.Registry}, "fifth")
	err := s.Map("build01", "fifth", "dana", t0)
	if err == nil {
		t.Fatal("a fifth agent was mapped onto one host")
	}
	if !strings.Contains(err.Error(), "watcher") ||
		!strings.Contains(err.Error(), "loader") {
		t.Errorf("the refusal does not name the four already declared: %s", err)
	}
	// The cap is per host: another machine takes the fifth gladly.
	if err := s.Map("ci02", "fifth", "dana", t0); err != nil {
		t.Errorf("a fresh host refused the agent: %s", err)
	}
	// The same declaration twice is refused, so an operator told "mapped"
	// twice does not believe a second host was named.
	if err := s.Map("ci02", "watcher", "dana", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Map("ci02", "watcher", "dana", t0); err == nil {
		t.Error("the same declaration was accepted twice")
	}
}

// TestUnmapTakesTheDeclarationBack: unmap removes the name, and removing
// the last name takes the host's row with it — a host declared to run
// nothing and a host never mapped are the same machine, and the next push
// from either carries nothing.
func TestUnmapTakesTheDeclarationBack(t *testing.T) {
	s := mapStore(t)
	if err := s.Map("build01", "watcher", "dana", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Map("build01", "triage", "sam", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.Unmap("build01", "watcher", "sam", t0); err != nil {
		t.Fatal(err)
	}
	maps, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := AgentsFor(maps, "build01"); strings.Join(got, ",") != "triage" {
		t.Fatalf("after one unmap the host declares %v", got)
	}
	if err := s.Unmap("build01", "triage", "sam", t0); err != nil {
		t.Fatal(err)
	}
	if maps, err = s.Load(); err != nil || len(maps) != 0 {
		t.Fatalf("the empty row lingered: %+v (%v)", maps, err)
	}
	// Unmapping what was never mapped is refused, naming both halves.
	if err := s.Unmap("build01", "watcher", "sam", t0); err == nil {
		t.Error("an unmap of nothing was answered as done")
	}
}

// TestLoadRefusesWhatItCannotRead: an absent mapping is empty — every host
// unmapped, which is where every store starts — and a present one that
// cannot be parsed is an error, because a declaration that cannot be read
// is one nobody can review and ingest must not silently ship evidence as
// though nobody had ever declared anything.
func TestLoadRefusesWhatItCannotRead(t *testing.T) {
	s := MapStore{Path: filepath.Join(t.TempDir(), "agentmaps.json"),
		Registry: filepath.Join(t.TempDir(), "agents.json")}
	if maps, err := s.Load(); err != nil || maps != nil {
		t.Fatalf("an absent mapping loaded as %v, %v; it is empty", maps, err)
	}
	if err := os.WriteFile(s.Path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("a mapping that cannot be parsed loaded as empty")
	}
}
