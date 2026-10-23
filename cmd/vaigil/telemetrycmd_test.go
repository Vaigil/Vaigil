// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vaigil/vaigil/internal/out"
	"github.com/vaigil/vaigil/internal/telemetry"
)

// A connector's output is checked line by line, and what a rule may name is
// read from the first event it produced.
//
// `detect fields` and `hunt` both send somebody here to find a field's name,
// so a command that is missing, or that passes a file a rule could not use,
// sends them on to write a rule that never fires.
func TestTelemetryChecksAConnectorsOutput(t *testing.T) {
	old := w
	w = out.New(false)
	t.Cleanup(func() { w = old })

	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	good, err := json.Marshal(signIn("okta/system", "dana",
		telemetry.DispositionFailed, "sign-in failed", at))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()

	usable := put(t, filepath.Join(dir, "usable.jsonl"), string(good)+"\n")
	if err := cmdTelemetry("", []string{"check", usable}); err != nil {
		t.Errorf("a usable event was refused: %v", err)
	}

	// An event with no source, and a line that is not an event at all.
	mixed := put(t, filepath.Join(dir, "mixed.jsonl"),
		string(good)+"\n{}\nnot json\n")
	err = cmdTelemetry("", []string{"check", mixed})
	if err == nil || !strings.Contains(err.Error(), "2 of 3") {
		t.Errorf("two unusable lines in three were reported as %v", err)
	}

	if err := cmdTelemetry("", []string{"fields", usable}); err != nil {
		t.Errorf("the fields of a usable event: %v", err)
	}
	if err := cmdTelemetry("", []string{"fields", mixed + ".missing"}); err == nil {
		t.Error("a file that is not there listed fields")
	}
	if err := cmdTelemetry("", []string{"fields"}); err != nil {
		t.Errorf("the fields of the example event: %v", err)
	}
	if err := cmdTelemetry("", []string{"tail"}); err == nil {
		t.Error("an unknown subcommand ran")
	}
}
