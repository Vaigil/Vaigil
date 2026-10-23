// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A rejected token is named by where it came from, and an old token file
// shadowing VAIGIL_TOKEN says so: the file is read first on purpose, and
// the refusal is where a person learns it.
func TestARejectedTokenSaysWhereItCameFrom(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.MkdirAll(filepath.Join(home, ".vaigil"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".vaigil", "token"),
		[]byte("vg_"+strings.Repeat("a", 52)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAIGIL_TOKEN", "vg_"+strings.Repeat("b", 52))
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	c := resolveCaller(root, "")
	if c.Verified {
		t.Fatal("an unknown token verified")
	}
	if !strings.Contains(c.Why, filepath.Join(home, ".vaigil", "token")) || !strings.Contains(c.Why, "VAIGIL_TOKEN is set too") {
		t.Fatalf("the refusal does not say which token was tried: %q", c.Why)
	}
	if c := resolveCaller(root, "vg_"+strings.Repeat("c", 52)); !strings.Contains(c.Why, "from --token") {
		t.Fatalf("an explicit token is not named as one: %q", c.Why)
	}
}
