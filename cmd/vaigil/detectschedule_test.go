// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vaigil/vaigil/internal/audit"
)

// auditHas reports whether the log holds an action whose details include
// every pair given.
func auditHas(t *testing.T, root, action string, detail map[string]string) bool {
	t.Helper()
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action != action {
			continue
		}
		ok := true
		for k, v := range detail {
			ok = ok && e.Detail[k] == v
		}
		if ok {
			return true
		}
	}
	return false
}

// A new store has the shipped rules as its own files; a store that keeps
// its own rules is left exactly as it is.
func TestANewStoreStartsWithTheShippedRules(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	rule := filepath.Join(root, "detections", "vaigil.admin-granted.json")
	if _, err := os.Stat(rule); err != nil {
		t.Fatalf("a new store has no rule about an administrator being made: %v", err)
	}
	if err := os.Remove(rule); err != nil {
		t.Fatal(err)
	}
	if err := ensureRules(root, "server-start"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rule); err == nil {
		t.Error("a rule the organisation removed from its own directory came back")
	}
}
