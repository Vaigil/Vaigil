// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vaigil/vaigil/internal/audit"
	"github.com/vaigil/vaigil/internal/finding"
	"github.com/vaigil/vaigil/internal/out"
	"github.com/vaigil/vaigil/internal/pack"
	"github.com/vaigil/vaigil/internal/telemetry"
)

// The content plane end to end, through the command surface: a pack is
// keyed, built, signed, verified, installed — and the detection run, which
// never learned that content packs exist, loads it and fires it. The run
// reading the files is the whole argument of the plane, so it is the thing
// asserted rather than assumed.

// contentRule is the rule the e2e pack carries: valid under the shipping
// validators, with must-match and must-refuse fixtures.
const contentRule = `{
  "id": "vaigil.e2e-privileged-failed",
  "title": "Failed sign-in to a privileged account",
  "why": "a guessed or sprayed administrator password",
  "sources": ["okta/system"],
  "severity": 4,
  "when": {"all": [
    {"match": {"field": "class", "op": "equals", "values": ["3002"]}},
    {"match": {"field": "disposition", "op": "equals", "values": ["failed"]}},
    {"match": {"field": "actor.value", "op": "prefix", "values": ["admin-"]}}
  ]},
  "fixtures": [
    {"name": "an admin fails", "match": true, "event": {
      "source": "okta/system", "time": "2026-09-01T00:00:00Z",
      "received": "2026-09-01T00:00:01Z", "class": 3002, "disposition": 4,
      "actor": {"issuer": "okta", "value": "admin-dana"}}},
    {"name": "an admin succeeds", "match": false, "event": {
      "source": "okta/system", "time": "2026-09-01T00:00:00Z",
      "received": "2026-09-01T00:00:01Z", "class": 3002, "disposition": 1,
      "actor": {"issuer": "okta", "value": "admin-dana"}}}
  ]
}`

// contentRuleTuned is v2: a narrower match, so the two versions differ in
// bytes and in what they fire on.
const contentRuleTuned = `{
  "id": "vaigil.e2e-privileged-failed",
  "title": "Failed sign-in to a privileged account",
  "why": "a guessed or sprayed administrator password, narrowed to ops",
  "sources": ["okta/system"],
  "severity": 4,
  "when": {"all": [
    {"match": {"field": "class", "op": "equals", "values": ["3002"]}},
    {"match": {"field": "disposition", "op": "equals", "values": ["failed"]}},
    {"match": {"field": "actor.value", "op": "suffix", "values": ["-ops"]}}
  ]},
  "fixtures": [
    {"name": "an ops admin fails", "match": true, "event": {
      "source": "okta/system", "time": "2026-09-01T00:00:00Z",
      "received": "2026-09-01T00:00:01Z", "class": 3002, "disposition": 4,
      "actor": {"issuer": "okta", "value": "admin-dana-ops"}}},
    {"name": "a plain admin fails", "match": false, "event": {
      "source": "okta/system", "time": "2026-09-01T00:00:00Z",
      "received": "2026-09-01T00:00:01Z", "class": 3002, "disposition": 4,
      "actor": {"issuer": "okta", "value": "admin-dana"}}}
  ]
}`

// contentCorrelation is the pack's correlation file.
const contentCorrelation = `title: One privileged account failed repeatedly
id: corr.e2e-privileged-failures
correlation:
    type: event_count
    rules:
        - vaigil.e2e-privileged-failed
    group-by:
        - actor.value
    timespan: 15m
    condition:
        gte: 5
level: high
`

// contentSite is a store with keys made and a pack directory laid out.
func contentSite(t *testing.T, rule string) (root, offline, dir string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if w == nil {
		w = out.New(false)
	}
	root = t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	offline = filepath.Join(t.TempDir(), "offline.key")
	if err := cmdContent(root, []string{"keygen", "--out", offline}); err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	for sub, body := range map[string]string{
		"detections/vaigil.e2e-privileged-failed.json": rule,
		"correlations/e2e.yml":                         contentCorrelation,
	} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(sub)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, sub), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, offline, dir
}

// signPackDir signs a laid-out pack at a version.
func signPackDir(t *testing.T, root, dir, version string) {
	t.Helper()
	if err := cmdContent(root, []string{"sign", dir,
		"--id", "vaigil.e2e", "--version", version,
		"--about", "the e2e pack"}); err != nil {
		t.Fatal(err)
	}
}

// capture redirects the human output for one command, because the checks
// a verify prints are the thing being asserted.
func capture(t *testing.T, run func() error) string {
	t.Helper()
	old := w.Out
	buf := &bytes.Buffer{}
	w.Out = buf
	defer func() { w.Out = old }()
	if err := run(); err != nil {
		return buf.String() + "\nERROR: " + err.Error()
	}
	return buf.String()
}

// contentSeedTelemetry gives a store its first stored event, so the shadow
// gate has an estate to ask about: a failed sign-in from a source the
// pack's rule does not read. The week is exercised, the pack is quiet, and
// the gate holds — for the tests whose subject is elsewhere.
func contentSeedTelemetry(t *testing.T, root string) {
	t.Helper()
	appendEvents(t, root, []labelled{{name: "a week with traffic", attack: false,
		event: signIn("github/audit", "admin-dana",
			telemetry.DispositionFailed, "sign-in",
			time.Now().UTC().Add(-time.Hour))}})
}

// TestContentEndToEnd: keygen, sign, install — through the shadow gate, on
// a store holding the week the rule was written for — and the detection run
// loads the pack's rule and fires it on a matching event, with the
// install, gate verdict and all, on the audit record.
func TestContentEndToEnd(t *testing.T) {
	root, offline, dir := contentSite(t, contentRule)
	signPackDir(t, root, dir, "2026.11.0")
	// The estate's week, already stored: one failure the rule would have
	// caught, so the gate runs with something to ask and the install is
	// the gate's answer rather than its absence.
	appendEvents(t, root, []labelled{{name: "last week's failure", attack: true,
		event: signIn("okta/system", "admin-dana",
			telemetry.DispositionFailed, "sign-in",
			time.Now().UTC().Add(-26*time.Hour))}})

	out := capture(t, func() error {
		return cmdContent(root, []string{"verify", dir})
	})
	for _, want := range []string{"root.json signature", "targets.json signature",
		"timestamp.json signature", "content validation"} {
		if !strings.Contains(out, want) {
			t.Fatalf("verify did not show %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "FAIL") {
		t.Fatalf("the freshly signed pack failed a check:\n%s", out)
	}

	out = capture(t, func() error {
		return cmdContent(root, []string{"install", dir})
	})
	if !strings.Contains(out, "vaigil.e2e 2026.11.0 installed") {
		t.Fatalf("install did not say what it did:\n%s", out)
	}
	if !strings.Contains(out, "shadow replay held") ||
		!strings.Contains(out, "would have fired 1") {
		t.Fatalf("the install does not report the gate's verdict:\n%s", out)
	}
	// The rule is where the run reads, at the layout the loaders walk.
	rulePath := filepath.Join(root, "detections",
		"vaigil.e2e-privileged-failed.json")
	if _, err := os.Stat(rulePath); err != nil {
		t.Fatalf("the rule was not placed where the run loads it: %v\n"+
			"install said:\n%s", err, out)
	}
	// The correlation lands flat beside the rules — the layout the
	// starter pack's own correlations.yml uses and the loaders walk.
	if _, err := os.Stat(filepath.Join(root, "detections", "e2e.yml")); err != nil {
		t.Fatalf("the correlation was not placed: %v", err)
	}

	// The run: an admin failing to sign in fires the pack's rule.
	at := time.Now().UTC().Add(-time.Minute)
	appendEvents(t, root, []labelled{
		{name: "an admin fails", attack: true,
			event: signIn("okta/system", "admin-dana",
				telemetry.DispositionFailed, "sign-in", at)},
		{name: "an admin succeeds", attack: false,
			event: signIn("okta/system", "admin-dana",
				telemetry.DispositionAllowed, "sign-in", at.Add(time.Second))},
	})
	if err := detectRun(root, nil); err != nil {
		t.Fatal(err)
	}
	var fired bool
	for _, f := range queue(t, root) {
		if f.Source == "vaigil.e2e-privileged-failed" {
			fired = true
		}
	}
	if !fired {
		t.Fatal("the installed pack's rule never fired on the event it " +
			"was written for; the plane is files the run does not read")
	}

	// The install is on the record, with what and how much.
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var noted bool
	for _, e := range events {
		if e.Action == "content.installed" &&
			e.Detail["pack"] == "vaigil.e2e" &&
			e.Detail["version"] == "2026.11.0" {
			noted = true
			if e.Detail["shadow"] != "held" || e.Detail["shadow_fired"] != "1" {
				t.Fatalf("the gate's verdict did not travel with the apply: "+
					"%v", e.Detail)
			}
		}
	}
	if !noted {
		t.Fatal("content.installed is not on the audit record with the " +
			"pack id and version")
	}

	// The offline key was written 0600 where the operator said, and the
	// release key sits 0600 in the store.
	for _, path := range []string{offline,
		filepath.Join(root, "content", "release.key")} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s is %v, not 0600", path, fi.Mode().Perm())
		}
	}
}

// TestContentTamperedRefused: a rule edited after signing. The install
// refuses, naming the digest mismatch, and nothing is placed.
func TestContentTamperedRefused(t *testing.T) {
	root, _, dir := contentSite(t, contentRule)
	signPackDir(t, root, dir, "2026.11.0")
	rulePath := filepath.Join(dir, "detections",
		"vaigil.e2e-privileged-failed.json")
	if err := os.WriteFile(rulePath,
		[]byte(strings.Replace(contentRule, "admin-dana", "admin-mallory", -1)),
		0o600); err != nil {
		t.Fatal(err)
	}

	out := capture(t, func() error {
		return cmdContent(root, []string{"install", dir})
	})
	if !strings.Contains(out, "FAIL") ||
		!strings.Contains(out, "does not match its manifest digest") {
		t.Fatalf("the refusal must name the digest mismatch:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(root, "detections",
		"vaigil.e2e-privileged-failed.json")); err == nil {
		t.Fatal("a tampered pack placed content")
	}
	// And the store's record still says nothing of this pack.
	if out := capture(t, func() error {
		return cmdContent(root, []string{"installed"})
	}); strings.Contains(out, "vaigil.e2e") {
		t.Fatalf("a refused pack is on the installed list:\n%s", out)
	}
}

// TestContentRollbackCommand: v1, then v2, then rollback — the previous
// bytes back, the removals of nothing, the audit record made, and the
// installed list saying v1 again.
func TestContentRollbackCommand(t *testing.T) {
	root, _, d1 := contentSite(t, contentRule)
	signPackDir(t, root, d1, "2026.11.0")
	contentSeedTelemetry(t, root)
	if err := cmdContent(root, []string{"install", d1}); err != nil {
		t.Fatal(err)
	}

	d2 := t.TempDir()
	for sub, body := range map[string]string{
		"detections/vaigil.e2e-privileged-failed.json": contentRuleTuned,
		"correlations/e2e.yml":                         contentCorrelation,
	} {
		if err := os.MkdirAll(filepath.Join(d2, filepath.Dir(sub)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d2, sub), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	signPackDir(t, root, d2, "2026.11.1")
	if err := cmdContent(root, []string{"install", d2}); err != nil {
		t.Fatal(err)
	}
	rulePath := filepath.Join(root, "detections",
		"vaigil.e2e-privileged-failed.json")
	body, err := os.ReadFile(rulePath)
	if err != nil || !strings.Contains(string(body), "narrowed to ops") {
		t.Fatalf("v2 is not what is installed: %v", err)
	}

	out := capture(t, func() error {
		return cmdContent(root, []string{"rollback"})
	})
	if !strings.Contains(out, "rolled back") {
		t.Fatalf("rollback did not say what it did:\n%s", out)
	}
	body, err = os.ReadFile(rulePath)
	if err != nil || string(body) != contentRule {
		t.Fatal("rollback did not restore the previous bytes")
	}
	list := capture(t, func() error {
		return cmdContent(root, []string{"installed"})
	})
	if !strings.Contains(list, "vaigil.e2e 2026.11.0") ||
		strings.Contains(list, "2026.11.1") {
		t.Fatalf("the installed list does not say v1:\n%s", list)
	}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var noted bool
	for _, e := range events {
		if e.Action == "content.rolled-back" && e.Detail["pack"] == "vaigil.e2e" {
			noted = true
		}
	}
	if !noted {
		t.Fatal("content.rolled-back is not on the audit record")
	}
}

// TestContentExpiredInstalledKeepsWorking: the report's rule, held to in
// the one place it could quietly break. A pack whose metadata has expired
// is still listed (with the freeze said out loud), and its rules still
// load and fire — expiry never disables content.
func TestContentExpiredInstalledKeepsWorking(t *testing.T) {
	root, _, dir := contentSite(t, contentRule)
	signPackDir(t, root, dir, "2026.11.0")
	contentSeedTelemetry(t, root)
	if err := cmdContent(root, []string{"install", dir}); err != nil {
		t.Fatal(err)
	}

	// Time passes: the installed record's expiry is moved into the past,
	// which is what "a hundred days later" looks like to a listing that
	// must not need the pack directory to answer. The record is rewritten
	// through the same struct, so it stays the document the store wrote.
	statePath := filepath.Join(root, "content", "installed.json")
	body, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		Packs map[string]struct {
			ID      string `json:"id"`
			Version string `json:"version"`
			Expires string `json:"expires"`
		} `json:"packs"`
	}
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatal(err)
	}
	rec := state.Packs["vaigil.e2e"]
	rec.Expires = "2020-01-01T00:00:00Z"
	state.Packs["vaigil.e2e"] = rec
	patched, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, patched, 0o600); err != nil {
		t.Fatal(err)
	}

	list := capture(t, func() error {
		return cmdContent(root, []string{"installed"})
	})
	if !strings.Contains(list, "vaigil.e2e 2026.11.0") {
		t.Fatalf("the expired pack is not listed:\n%s", list)
	}
	if !strings.Contains(list, "content frozen") ||
		!strings.Contains(list, "keeps running") {
		t.Fatalf("the staleness is not reported plainly:\n%s", list)
	}

	// And the run still loads and fires it.
	at := time.Now().UTC().Add(-time.Minute)
	appendEvents(t, root, []labelled{
		{name: "an admin fails", attack: true,
			event: signIn("okta/system", "admin-dana",
				telemetry.DispositionFailed, "sign-in", at)},
	})
	if err := detectRun(root, nil); err != nil {
		t.Fatalf("the run refuses with an expired pack installed: %v", err)
	}
	var fired bool
	for _, f := range queue(t, root) {
		if f.Source == "vaigil.e2e-privileged-failed" {
			fired = true
		}
	}
	if !fired {
		t.Fatal("an expired installed pack's rule stopped firing; expiry " +
			"must never disable content")
	}
}

// TestContentRollbackRefusesOlderPackThroughTheCommand: the version
// counters, through the surface people will actually use.
func TestContentRollbackRefusesOlderPackThroughTheCommand(t *testing.T) {
	root, _, d1 := contentSite(t, contentRule)
	signPackDir(t, root, d1, "2026.11.1")
	contentSeedTelemetry(t, root)
	if err := cmdContent(root, []string{"install", d1}); err != nil {
		t.Fatal(err)
	}

	// v1 signed after v2 by rewinding the producer's counter — a mirror
	// serving yesterday's release back.
	produced := filepath.Join(root, "content", "produced.json")
	if err := os.WriteFile(produced, []byte(`{"last":{"vaigil.e2e":0}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	d2 := t.TempDir()
	if err := os.MkdirAll(filepath.Join(d2, "detections"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(d2, "correlations"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d2, "detections",
		"vaigil.e2e-privileged-failed.json"), []byte(contentRuleTuned), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d2, "correlations", "e2e.yml"),
		[]byte(contentCorrelation), 0o600); err != nil {
		t.Fatal(err)
	}
	signPackDir(t, root, d2, "2026.11.0")

	out := capture(t, func() error {
		return cmdContent(root, []string{"install", d2})
	})
	if !strings.Contains(out, "rollback") {
		t.Fatalf("an older pack must be refused as a rollback:\n%s", out)
	}
}

// The shadow-replay gate through the command surface: the install between
// verification and placement that asks the pack over the estate's own
// stored week. Every case seeds events the way `spool add` does and asserts
// both what the person reads and what the store is left holding — the
// numbers, the refusal, the record, and the nothing that moves.

// contentShadowAudit is the content.installed record's shadow detail, so a
// test can assert the gate's verdict travelled with the apply.
func contentShadowAudit(t *testing.T, root string) map[string]string {
	t.Helper()
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var detail map[string]string
	for _, e := range events {
		if e.Action == "content.installed" {
			detail = e.Detail
		}
	}
	if detail == nil {
		t.Fatal("no content.installed record; the install is not on the " +
			"audit log")
	}
	return detail
}

// TestContentInstallShadowRefusesAFlood: thirty would-be findings from one
// rule over a quiet week refuse the install, the refusal names the count,
// the window, the budget and the override flag — and nothing is placed.
func TestContentInstallShadowRefusesAFlood(t *testing.T) {
	root, _, dir := contentSite(t, contentRule)
	signPackDir(t, root, dir, "2026.11.0")
	appendEvents(t, root, failures("admin-dana", closedWindow(), 30))

	out := capture(t, func() error {
		return cmdContent(root, []string{"install", dir})
	})
	for _, want := range []string{"shadow replay",
		"vaigil.e2e-privileged-failed would fire 30 time(s)",
		"the budget 20", "the budget for it is",
		"--max-fires-per-rule", "the shadow replay refused this pack"} {
		if !strings.Contains(out, want) {
			t.Errorf("the refusal must say %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "detections",
		"vaigil.e2e-privileged-failed.json")); err == nil {
		t.Fatal("a pack the budget refused placed its rule")
	}
	if _, err := os.Stat(filepath.Join(root, "detections", "e2e.yml")); err == nil {
		t.Fatal("a pack the budget refused placed its correlation")
	}
	if list := capture(t, func() error {
		return cmdContent(root, []string{"installed"})
	}); strings.Contains(list, "vaigil.e2e") {
		t.Fatalf("the refused pack is on the installed list:\n%s", list)
	}
}

// TestContentInstallOverrideIsAuditedAndShown: the operator who knows
// better states the number, the pack installs, and the override is on the
// audit record, on the installed record, and on the `content installed`
// screen — a budget argued with is a decision, and decisions belong to
// whoever made them.
func TestContentInstallOverrideIsAuditedAndShown(t *testing.T) {
	root, _, dir := contentSite(t, contentRule)
	signPackDir(t, root, dir, "2026.11.0")
	// Thirty failures a minute apart in a closed window: the rule would
	// fire thirty times, the correlation twice (minutes 1-14 and 15-29 of
	// the half hour), so thirty-two findings against a baseline of none.
	appendEvents(t, root, failures("admin-dana", closedWindow(), 30))

	out := capture(t, func() error {
		return cmdContent(root, []string{"install", dir,
			"--max-fires-per-rule", "40"})
	})
	if !strings.Contains(out, "vaigil.e2e 2026.11.0 installed") {
		t.Fatalf("the override did not install the pack:\n%s", out)
	}
	if !strings.Contains(out,
		"held after an override (--max-fires-per-rule 40)") {
		t.Fatalf("the install did not say the budget was overridden:\n%s", out)
	}
	detail := contentShadowAudit(t, root)
	for key, want := range map[string]string{
		"shadow": "overridden", "shadow_override": "--max-fires-per-rule 40",
		"shadow_days": "7", "shadow_events": "30", "shadow_fired": "32",
		"shadow_baseline": "0",
	} {
		if detail[key] != want {
			t.Errorf("the audit detail %q is %q, want %q", key,
				detail[key], want)
		}
	}
	// The installed record carries the same verdict, months-later-readable.
	st, err := pack.LoadInstalled(root)
	if err != nil {
		t.Fatal(err)
	}
	rec := st.Packs["vaigil.e2e"].Shadow
	if rec == nil || rec.Outcome != pack.ShadowOverridden ||
		rec.Override != "--max-fires-per-rule 40" || rec.Fired != 32 ||
		rec.Events != 30 || rec.Days != 7 {
		t.Fatalf("the installed record's shadow verdict is %+v", rec)
	}
	list := capture(t, func() error {
		return cmdContent(root, []string{"installed"})
	})
	if !strings.Contains(list, "skipped") &&
		!strings.Contains(list, "override (--max-fires-per-rule 40)") {
		t.Fatalf("the installed list does not show the override:\n%s", list)
	}
}

// TestContentInstallQuietPackNotesUnexercised: a pack whose rules match
// nothing the estate stored passes — silence is not a refusal — and both
// the install and the audit record say the rules were unexercised by this
// estate's week, which is the honest thing to say about content no
// question was asked of.
func TestContentInstallQuietPackNotesUnexercised(t *testing.T) {
	root, _, dir := contentSite(t, contentRule)
	signPackDir(t, root, dir, "2026.11.0")
	// A week with traffic in it, from a source the rule does not read.
	at := time.Now().UTC().Add(-time.Hour)
	appendEvents(t, root, []labelled{
		{name: "a github admin fails", attack: false,
			event: signIn("github/audit", "admin-dana",
				telemetry.DispositionFailed, "sign-in", at)},
		{name: "another", attack: false,
			event: signIn("github/audit", "admin-raj",
				telemetry.DispositionFailed, "sign-in", at.Add(time.Minute))},
	})

	out := capture(t, func() error {
		return cmdContent(root, []string{"install", dir})
	})
	if !strings.Contains(out, "vaigil.e2e 2026.11.0 installed") {
		t.Fatalf("a pack that would fire nothing was refused:\n%s", out)
	}
	if !strings.Contains(out, "unexercised by this estate's week") {
		t.Fatalf("the install does not note the unexercised rules:\n%s", out)
	}
	detail := contentShadowAudit(t, root)
	for key, want := range map[string]string{
		"shadow": "held", "shadow_fired": "0", "shadow_events": "2",
	} {
		if detail[key] != want {
			t.Errorf("the audit detail %q is %q, want %q", key,
				detail[key], want)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "detections",
		"vaigil.e2e-privileged-failed.json")); err != nil {
		t.Fatalf("the quiet pack's rule was not placed: %v", err)
	}
}

// TestContentInstallNoShadowOnAnEmptyStore: a store with no events cannot
// run the gate, and that refusal names the flag that skips it — without
// conjuring an event store to run it against. --no-shadow installs, says
// its risk out loud, and leaves the three words on the record and the
// screen.
func TestContentInstallNoShadowOnAnEmptyStore(t *testing.T) {
	root, _, dir := contentSite(t, contentRule)
	signPackDir(t, root, dir, "2026.11.0")

	out := capture(t, func() error {
		return cmdContent(root, []string{"install", dir})
	})
	for _, want := range []string{"no events at all", "--no-shadow",
		"ERROR:"} {
		if !strings.Contains(out, want) {
			t.Errorf("the refusal must say %q:\n%s", want, out)
		}
	}
	if _, err := os.Stat(spoolDir(root)); !os.IsNotExist(err) {
		t.Fatal("a refused install conjured an event store; the gate has no " +
			"business creating one")
	}

	out = capture(t, func() error {
		return cmdContent(root, []string{"install", dir, "--no-shadow"})
	})
	if !strings.Contains(out, "vaigil.e2e 2026.11.0 installed") {
		t.Fatalf("--no-shadow did not install the pack:\n%s", out)
	}
	if !strings.Contains(out, "skipping the shadow replay (--no-shadow)") {
		t.Fatalf("the skip does not say its risk out loud:\n%s", out)
	}
	detail := contentShadowAudit(t, root)
	if detail["shadow"] != "skipped" {
		t.Fatalf("the audit says %q, want the skip on the record",
			detail["shadow"])
	}
	list := capture(t, func() error {
		return cmdContent(root, []string{"installed"})
	})
	if !strings.Contains(list, "skipped (--no-shadow)") {
		t.Fatalf("the installed list does not say the gate never ran:\n%s",
			list)
	}
}

// TestContentInstallShadowMovesNoCursorAndNoRegister: trial-ring
// semantics through the whole command — a refusing replay and a passing
// one both leave the finding register, its cursors and the suppression
// state exactly as they were. The one thing an install may move is the
// content itself.
func TestContentInstallShadowMovesNoCursorAndNoRegister(t *testing.T) {
	root, _, dir := contentSite(t, contentRule)
	signPackDir(t, root, dir, "2026.11.0")
	appendEvents(t, root, failures("admin-dana", closedWindow(), 30))

	// A register with cursors in it, the shape a detect run leaves behind.
	reg, cursors, err := finding.Load(findingsPath(root))
	if err != nil {
		t.Fatal(err)
	}
	cursors[detectCursor] = closedWindow().Add(10 * time.Minute)
	cursors[correlateCursor] = closedWindow()
	if err := finding.Save(findingsPath(root), reg, cursors); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(findingsPath(root))
	if err != nil {
		t.Fatal(err)
	}

	if out := capture(t, func() error {
		return cmdContent(root, []string{"install", dir})
	}); !strings.Contains(out, "refused this pack") {
		t.Fatalf("the flood was not refused:\n%s", out)
	}
	after, err := os.ReadFile(findingsPath(root))
	if err != nil || string(after) != string(before) {
		t.Fatal("the refusing replay moved the register or its cursors")
	}
	if _, err := os.Stat(detectDir(root)); !os.IsNotExist(err) {
		t.Fatal("the refusing replay touched the tuning state")
	}

	if out := capture(t, func() error {
		return cmdContent(root, []string{"install", dir,
			"--max-fires-per-rule", "40"})
	}); !strings.Contains(out, "installed") {
		t.Fatalf("the override did not install:\n%s", out)
	}
	after, err = os.ReadFile(findingsPath(root))
	if err != nil || string(after) != string(before) {
		t.Fatal("the passing replay moved the register or its cursors")
	}
	if _, err := os.Stat(detectDir(root)); !os.IsNotExist(err) {
		t.Fatal("the passing replay touched the tuning state")
	}
	// The install really happened, so the assertion above is about the
	// gate and not about nothing.
	if _, err := os.Stat(filepath.Join(root, "detections",
		"vaigil.e2e-privileged-failed.json")); err != nil {
		t.Fatalf("the pack was not placed: %v", err)
	}
}

// TestContentInstallShadowWindowCanWiden: a store whose events all sit
// outside the default week is an empty window, refused with the wider
// window named — and --days asks the question over a week that does hold
// them.
func TestContentInstallShadowWindowCanWiden(t *testing.T) {
	root, _, dir := contentSite(t, contentRule)
	signPackDir(t, root, dir, "2026.11.0")
	old := time.Now().UTC().Add(-30 * 24 * time.Hour)
	appendEvents(t, root, []labelled{{name: "last month's spray", attack: true,
		event: signIn("okta/system", "admin-dana",
			telemetry.DispositionFailed, "sign-in", old)}})

	out := capture(t, func() error {
		return cmdContent(root, []string{"install", dir})
	})
	for _, want := range []string{"no event has arrived in the last 7 day(s)",
		"--days", "--no-shadow"} {
		if !strings.Contains(out, want) {
			t.Errorf("the empty-window refusal must say %q:\n%s", want, out)
		}
	}

	out = capture(t, func() error {
		return cmdContent(root, []string{"install", dir, "--days", "45"})
	})
	if !strings.Contains(out, "vaigil.e2e 2026.11.0 installed") {
		t.Fatalf("the widened window did not install the pack:\n%s", out)
	}
	if !strings.Contains(out, "over the last 45 day(s)") {
		t.Fatalf("the replay did not say which window it asked over:\n%s", out)
	}
	detail := contentShadowAudit(t, root)
	if detail["shadow_days"] != "45" || detail["shadow_fired"] != "1" {
		t.Fatalf("the record says days=%s fired=%s, want the forty-five-day "+
			"window and the one old failure counted",
			detail["shadow_days"], detail["shadow_fired"])
	}
}

// contentAudit finds the last record with an action, for asserting what a
// command left on the trail.
func contentAudit(t *testing.T, root, action string) map[string]string {
	t.Helper()
	events, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var detail map[string]string
	for _, e := range events {
		if e.Action == action {
			detail = e.Detail
		}
	}
	if detail == nil {
		t.Fatal("no " + action + " record on the audit log")
	}
	return detail
}

// TestContentRotateRootCommand: the ceremony through the command surface —
// the offline key comes back, the anchor moves to version 2 doubly signed,
// the fingerprints land on the audit record, and packs signed under the
// rotated chain verify and install. The refusals are the ceremony too: a
// key the anchor does not name, an incoming-key path that already exists,
// and a ceremony without both keys named.
func TestContentRotateRootCommand(t *testing.T) {
	root, offline, dir := contentSite(t, contentRule)
	signPackDir(t, root, dir, "2026.11.0")

	next := filepath.Join(t.TempDir(), "next-root.key")
	out := capture(t, func() error {
		return cmdContent(root, []string{"rotate-root",
			"--old-root-key", offline, "--new-root-key", next})
	})
	for _, want := range []string{"root rotated", "version 1 to 2",
		"move " + next + " away"} {
		if !strings.Contains(out, want) {
			t.Errorf("the ceremony did not say %q:\n%s", want, out)
		}
	}
	anchor, err := pack.LoadAnchor(root)
	if err != nil || anchor.Signed.Version != 2 || anchor.Previous == nil {
		t.Fatalf("the anchor did not move to a doubly-signed root: %v", err)
	}
	if fi, serr := os.Stat(next); serr != nil || fi.Mode().Perm() != 0o600 {
		t.Fatal("the incoming root key is not 0600 where the operator said")
	}
	detail := contentAudit(t, root, "content.root-rotated")
	if detail["from_version"] != "1" || detail["to_version"] != "2" ||
		detail["from_fingerprint"] == "" ||
		detail["from_fingerprint"] == detail["to_fingerprint"] {
		t.Fatalf("the rotation is not on the record with both "+
			"fingerprints: %v", detail)
	}

	// Packs signed under the rotated chain carry root version 2, verify,
	// and install.
	d2 := t.TempDir()
	for sub, body := range map[string]string{
		"detections/vaigil.e2e-privileged-failed.json": contentRuleTuned,
		"correlations/e2e.yml":                         contentCorrelation,
	} {
		if err := os.MkdirAll(filepath.Join(d2, filepath.Dir(sub)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d2, sub), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	signPackDir(t, root, d2, "2026.11.1")
	carried, err := pack.LoadRoot(d2)
	if err != nil || carried.Signed.Version != 2 {
		t.Fatalf("a pack signed after the rotation carries root version %d, "+
			"want the rotated 2", carried.Signed.Version)
	}
	contentSeedTelemetry(t, root)
	if vout := capture(t, func() error {
		return cmdContent(root, []string{"verify", d2})
	}); strings.Contains(vout, "FAIL") {
		t.Fatalf("the rotated-chain pack failed a check:\n%s", vout)
	}
	if err := cmdContent(root, []string{"install", d2}); err != nil {
		t.Fatalf("the rotated-chain pack did not install: %v", err)
	}

	// A key the anchor does not name: a rotation no client can walk.
	foreign, gerr := pack.GenerateKey()
	if gerr != nil {
		t.Fatal(gerr)
	}
	foreignAt := filepath.Join(t.TempDir(), "foreign.key")
	if err := pack.SaveKey(foreignAt, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	out = capture(t, func() error {
		return cmdContent(root, []string{"rotate-root",
			"--old-root-key", foreignAt,
			"--new-root-key", filepath.Join(t.TempDir(), "x.key")})
	})
	if !strings.Contains(out, "ERROR:") ||
		!strings.Contains(out, "anchor names") {
		t.Fatalf("a rotation by a foreign key must be refused:\n%s", out)
	}
	// An incoming-key path that already exists — keygen's refusal, again.
	out = capture(t, func() error {
		return cmdContent(root, []string{"rotate-root",
			"--old-root-key", next, "--new-root-key", offline})
	})
	if !strings.Contains(out, "ERROR:") ||
		!strings.Contains(out, "already exists") {
		t.Fatalf("a rotation over an existing key file must be refused:\n%s", out)
	}
	// And a ceremony without both keys named is a usage question.
	if out = capture(t, func() error {
		return cmdContent(root, []string{"rotate-root",
			"--old-root-key", next})
	}); !strings.Contains(out, "usage:") {
		t.Fatalf("a rotation missing a key path must be usage:\n%s", out)
	}
}

// TestContentInstallOverridesThroughTheCommand: the override decision
// matrix through the surface people use. A locally-edited rule file blocks
// the install with the file and both flags named; --keep-overrides
// installs around it with the edit intact, shown in `content installed`
// and audited with the file named; rollback restores the pack's previous
// set and leaves the edit alone; --adopt-overrides takes the pack's
// version, on the record.
func TestContentInstallOverridesThroughTheCommand(t *testing.T) {
	root, _, d1 := contentSite(t, contentRule)
	signPackDir(t, root, d1, "2026.11.0")
	contentSeedTelemetry(t, root)
	if err := cmdContent(root, []string{"install", d1}); err != nil {
		t.Fatal(err)
	}

	// The organisation tunes the rule by hand.
	ruleAt := filepath.Join(root, "detections",
		"vaigil.e2e-privileged-failed.json")
	edited := strings.Replace(contentRule, "admin-dana", "admin-prakash", -1)
	if err := os.WriteFile(ruleAt, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	// v2 tunes the rule AND the correlation, so "the pack's other files
	// landed" is a claim about bytes rather than file counts.
	layout := func(dir string) {
		t.Helper()
		tunedCorr := strings.Replace(contentCorrelation, "gte: 5", "gte: 8", 1)
		for sub, body := range map[string]string{
			"detections/vaigil.e2e-privileged-failed.json": contentRuleTuned,
			"correlations/e2e.yml":                         tunedCorr,
		} {
			if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(sub)), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, sub), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	d2 := t.TempDir()
	layout(d2)
	signPackDir(t, root, d2, "2026.11.1")

	// The default: refuse, naming the file and both flags, placing nothing.
	out := capture(t, func() error {
		return cmdContent(root, []string{"install", d2})
	})
	for _, want := range []string{"ERROR:", "vaigil.e2e-privileged-failed.json",
		"--keep-overrides", "--adopt-overrides"} {
		if !strings.Contains(out, want) {
			t.Errorf("the refusal must say %q:\n%s", want, out)
		}
	}
	if got, rerr := os.ReadFile(ruleAt); rerr != nil || string(got) != edited {
		t.Fatal("the refusing install touched the edit")
	}

	// --keep-overrides: the edit stands, the pack's other files land, the
	// screen shows the kept override, and the decision is audited with
	// the file named.
	out = capture(t, func() error {
		return cmdContent(root, []string{"install", d2, "--keep-overrides"})
	})
	for _, want := range []string{"vaigil.e2e 2026.11.1 installed",
		"local edit(s) kept", "vaigil.e2e-privileged-failed.json"} {
		if !strings.Contains(out, want) {
			t.Errorf("the keep install must say %q:\n%s", want, out)
		}
	}
	if got, rerr := os.ReadFile(ruleAt); rerr != nil || string(got) != edited {
		t.Fatal("--keep-overrides replaced the edit")
	}
	if got, rerr := os.ReadFile(filepath.Join(root, "detections", "e2e.yml")); rerr != nil ||
		!strings.Contains(string(got), "gte: 8") {
		t.Fatal("the pack's other files did not land around the edit")
	}
	list := capture(t, func() error {
		return cmdContent(root, []string{"installed"})
	})
	if !strings.Contains(list, "override(s) kept") ||
		!strings.Contains(list, "vaigil.e2e-privileged-failed.json") {
		t.Fatalf("the installed list does not show the kept override:\n%s", list)
	}
	kept := contentAudit(t, root, "content.override-kept")
	if kept["files"] != "detections/vaigil.e2e-privileged-failed.json" ||
		kept["version"] != "2026.11.1" {
		t.Fatalf("the kept decision is not on the record with the file: %v", kept)
	}

	// Rollback restores the pack's previous set and leaves the edit alone.
	out = capture(t, func() error {
		return cmdContent(root, []string{"rollback"})
	})
	if !strings.Contains(out, "rolled back") {
		t.Fatalf("rollback did not run:\n%s", out)
	}
	if got, rerr := os.ReadFile(ruleAt); rerr != nil || string(got) != edited {
		t.Fatal("rollback clobbered the override the install kept")
	}
	if got, rerr := os.ReadFile(filepath.Join(root, "detections", "e2e.yml")); rerr != nil ||
		!strings.Contains(string(got), "gte: 5") {
		t.Fatal("rollback did not restore the pack's previous correlation")
	}

	// --adopt-overrides on the next version: the pack's file replaces the
	// edit, the divergence ends on the record, and the adoption is
	// audited with the file named.
	d3 := t.TempDir()
	layout(d3)
	signPackDir(t, root, d3, "2026.11.2")
	out = capture(t, func() error {
		return cmdContent(root, []string{"install", d3, "--adopt-overrides"})
	})
	for _, want := range []string{"vaigil.e2e 2026.11.2 installed",
		"local edit(s) adopted over"} {
		if !strings.Contains(out, want) {
			t.Errorf("the adopt install must say %q:\n%s", want, out)
		}
	}
	if got, rerr := os.ReadFile(ruleAt); rerr != nil ||
		string(got) != contentRuleTuned {
		t.Fatal("--adopt-overrides did not take the pack's version")
	}
	adopted := contentAudit(t, root, "content.override-adopted")
	if adopted["files"] != "detections/vaigil.e2e-privileged-failed.json" {
		t.Fatalf("the adoption is not on the record with the file: %v", adopted)
	}
	list = capture(t, func() error {
		return cmdContent(root, []string{"installed"})
	})
	if !strings.Contains(list, "vaigil.e2e 2026.11.2") ||
		strings.Contains(list, "override(s) kept") {
		t.Fatalf("the adopted override lingers on the screen:\n%s", list)
	}
}
