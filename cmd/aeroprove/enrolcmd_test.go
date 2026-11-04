// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aeroprove/aeroprove/internal/enrol"
	"github.com/aeroprove/aeroprove/internal/out"
)

// A new store made with --admin has its first administrator, two factors
// from the first day, and the one link that gives that administrator a
// passkey; nobody is left holding a token to get in with.
func TestANewStoreStartsWithTwoFactorsAndAnEnrolmentLink(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(true)
	w.Out = &buf
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	if err := initAdmin(root, []string{"--admin", "dana@aeroprove.example"}, true); err != nil {
		t.Fatal(err)
	}
	var got struct {
		For  string `json:"for"`
		Link string `json:"link"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil || got.For != "dana@aeroprove.example" ||
		!strings.Contains(got.Link, "/enrol/"+enrol.Prefix) {
		t.Fatalf("%v %s", err, buf.String())
	}
	pol, _ := loadPolicy(root)
	if !holdsAny(pol, "dana@aeroprove.example") {
		t.Error("the first administrator was not granted")
	}
	if from, ok := mfaFromIfSet(root); !ok || time.Since(from) > time.Minute || time.Until(from) > time.Minute {
		t.Errorf("a new store's two factors start at %s %v, not now", from, ok)
	}
	secret := got.Link[strings.Index(got.Link, enrol.Prefix):]
	if l, err := enrolStore(root).Peek(secret, time.Now()); err != nil || l.Principal != "dana@aeroprove.example" {
		t.Errorf("the link printed is not waiting: %+v %v", l, err)
	}
	// A store that already has people is not taken over by naming
	// somebody new as its first administrator.
	if err := initAdmin(root, []string{"--admin", "mallory@aeroprove.example"}, false); err == nil {
		t.Error("init --admin made a second first administrator")
	}
}
