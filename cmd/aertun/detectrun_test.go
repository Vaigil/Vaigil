// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/automate"
	"github.com/aertun/aertun/internal/detect"
	"github.com/aertun/aertun/internal/finding"
	"github.com/aertun/aertun/internal/out"
	"github.com/aertun/aertun/internal/spool"
	"github.com/aertun/aertun/internal/telemetry"
)

// A rule a real estate would run: a failed sign-in to a privileged account.
const privilegedFailRule = `{
  "id": "auth.privileged-failed",
  "title": "Failed sign-in to a privileged account",
  "why": "a guessed or sprayed administrator password",
  "sources": ["okta/system"],
  "severity": 4,
  "technique": ["T1110"],
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

// labelled is one event and whether a correct detection fires on it.
type labelled struct {
	name   string
	attack bool
	event  telemetry.Event
}

func signIn(src, who string, d telemetry.Disposition, msg string,
	at time.Time) telemetry.Event {
	return telemetry.Event{
		Source: src, Class: telemetry.ClassAuthentication, Disposition: d,
		Actor: telemetry.ID{Issuer: "okta", Value: who}, Message: msg,
		Time: at, Received: at.Add(2 * time.Second),
	}
}

// siemSite is a store with the rule on disk and a labelled corpus in the
// event store.
func siemSite(t testing.TB, corpus []labelled) (root, rules string) {
	t.Helper()
	if w == nil {
		w = out.New(false)
	}
	root = t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	rules = filepath.Join(t.TempDir(), "detections")
	if err := os.MkdirAll(rules, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rules, "privileged.json"),
		[]byte(privilegedFailRule), 0o600); err != nil {
		t.Fatal(err)
	}
	appendEvents(t, root, corpus)
	return root, rules
}

func appendEvents(t testing.TB, root string, corpus []labelled) {
	t.Helper()
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus {
		if _, err := sp.Append(c.event); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
}

func queue(t *testing.T, root string) []finding.Finding {
	t.Helper()
	q, err := loadQueue(root, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// TestDetectionTruePositivesAndFalsePositives.
//
// A labelled corpus: attacks the rule exists for, and the look-alikes that
// are how rules go wrong in production — the same account succeeding, a
// non-privileged account failing, the same failure from a source the rule
// does not read, and the words "admin" and "failed" in a message about
// somebody else. Precision and recall are asserted, not eyeballed: both must
// be exactly one on this corpus, and a change to the rule, the matcher or the
// runner that costs either fails here.
func TestDetectionTruePositivesAndFalsePositives(t *testing.T) {
	t0 := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	at := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	failed, allowed := telemetry.DispositionFailed, telemetry.DispositionAllowed
	corpus := []labelled{
		{"spray 1", true, signIn("okta/system", "admin-dana", failed, "", at(0))},
		{"spray 2", true, signIn("okta/system", "admin-dana", failed, "", at(1))},
		{"spray 3", true, signIn("okta/system", "admin-dana", failed, "", at(2))},
		{"second admin", true, signIn("okta/system", "admin-ops", failed, "", at(3))},

		{"admin succeeds", false, signIn("okta/system", "admin-dana", allowed, "", at(4))},
		{"ordinary user fails", false, signIn("okta/system", "dana", failed, "", at(5))},
		{"other source", false, signIn("github/audit", "admin-dana", failed, "", at(6))},
		{"words in a message", false, signIn("okta/system", "sam", failed,
			"admin-dana failed to approve the request", at(7))},
		{"admin prefix inside", false, signIn("okta/system", "not-admin-x", failed, "", at(8))},
	}
	root, rules := siemSite(t, corpus)
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}

	got := map[string]finding.Finding{}
	for _, f := range queue(t, root) {
		got[f.Entity.Value] = f
	}
	var tp, fp, fn int
	attacked := map[string]int{}
	for _, c := range corpus {
		if c.attack {
			attacked[c.event.Actor.Value]++
		}
	}
	for who, n := range attacked {
		f, ok := got[who]
		switch {
		case !ok:
			fn += n
		case f.Seen != n:
			t.Errorf("%s: seen %d, the corpus has %d attacks", who, f.Seen, n)
			tp += f.Seen
		default:
			tp += n
		}
	}
	for who, f := range got {
		if attacked[who] == 0 {
			fp += f.Seen
			t.Errorf("a false positive on %s: %s", who, f.Evidence[0].What)
		}
	}
	precision := float64(tp) / float64(tp+fp)
	recall := float64(tp) / float64(tp+fn)
	if precision != 1 || recall != 1 {
		t.Fatalf("precision %.2f recall %.2f (tp %d fp %d fn %d)",
			precision, recall, tp, fp, fn)
	}
	// Every detection finding needs a person, whatever else is true.
	for _, f := range got {
		if f.NeedsAPerson() == "" {
			t.Errorf("%s rests on log text and does not say a person decides", f.ID)
		}
	}
}

// TestARunNeverCountsAnEventTwice, and counts every new one.
func TestARunNeverCountsAnEventTwice(t *testing.T) {
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	root, rules := siemSite(t, []labelled{
		{"spray", true, signIn("okta/system", "admin-dana",
			telemetry.DispositionFailed, "", t0)},
	})
	for i := 0; i < 3; i++ {
		if err := detectRun(root, []string{"--rules", rules}); err != nil {
			t.Fatal(err)
		}
	}
	if q := queue(t, root); len(q) != 1 || q[0].Seen != 1 {
		t.Fatalf("three runs over one event: %+v", q)
	}
	appendEvents(t, root, []labelled{{"again", true, signIn("okta/system",
		"admin-dana", telemetry.DispositionFailed, "", t0.Add(time.Minute))}})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	if q := queue(t, root); q[0].Seen != 2 {
		t.Fatalf("a new event was not counted: seen %d", q[0].Seen)
	}
}

// TestAVerdictHoldsUntilItHappensAgain, through the real commands.
func TestAVerdictHoldsUntilItHappensAgain(t *testing.T) {
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	root, rules := siemSite(t, []labelled{
		{"spray", true, signIn("okta/system", "admin-dana",
			telemetry.DispositionFailed, "", t0)},
	})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	id := queue(t, root)[0].ID

	if err := findingDecide(root, []string{id, "false-positive",
		"--because", "a load test against the staging tenant"}); err != nil {
		t.Fatal(err)
	}
	if q := queue(t, root); q[0].State != finding.FalsePositive ||
		len(filterQueue(q, "", "")) != 0 {
		t.Fatalf("after a false-positive verdict: %s, %d open",
			q[0].State, len(filterQueue(q, "", "")))
	}

	appendEvents(t, root, []labelled{{"again", true, signIn("okta/system",
		"admin-dana", telemetry.DispositionFailed, "", time.Now().UTC())}})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	if q := queue(t, root); q[0].State != finding.Open {
		t.Fatalf("it happened again after the verdict and stayed %s", q[0].State)
	}
}

// TestNoEventsIsNotAQuietEstate.
func TestNoEventsIsNotAQuietEstate(t *testing.T) {
	if w == nil {
		w = out.New(false)
	}
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	rules := t.TempDir()
	if err := os.WriteFile(filepath.Join(rules, "r.json"),
		[]byte(privilegedFailRule), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := detectRun(root, []string{"--rules", rules}); err == nil {
		t.Fatal("a run against a site with no event store reported success")
	}
	if _, err := os.Stat(spoolDir(root)); !os.IsNotExist(err) {
		t.Fatal("the run created an empty event store")
	}
	if err := detectRun(root, []string{"--rules", t.TempDir()}); err == nil {
		t.Fatal("a run with no rules reported success")
	}
}

// TestTheRegisterIsNotWorldReadable.
func TestTheRegisterIsNotWorldReadable(t *testing.T) {
	root, rules := siemSite(t, []labelled{{"x", true, signIn("okta/system",
		"admin-dana", telemetry.DispositionFailed, "", time.Now().UTC())}})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(findingsPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("the register is %v", fi.Mode().Perm())
	}
	var l finding.Ledger
	b, _ := os.ReadFile(findingsPath(root))
	if err := json.Unmarshal(b, &l); err != nil || l.Cursors[detectCursor].IsZero() {
		t.Fatalf("no cursor was written: %v", err)
	}
}

// TestDetectTrialFindingsDoNotReachTheAutomations.
//
// A rule in its trial ring has not earned the queue, and it has not earned
// the automations either: nothing it raises may step somebody up, end their
// sessions or mail people, and there is no condition a rule author could
// write to let it — Kinds lists no "trial" field. The finding is still
// recorded, for the verdicts that will earn the rule its place. Promoted,
// what it raises reaches the automations like any other rule's.
func TestDetectTrialFindingsDoNotReachTheAutomations(t *testing.T) {
	t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	root, rules := siemSite(t, []labelled{{"spray", true, signIn("okta/system",
		"admin-dana", telemetry.DispositionFailed, "", t0)}})
	if _, err := automationEngine(root).Save(automate.Rule{
		Name: "a finding is raised", Enabled: true, Mode: "act",
		When: "finding",
		Then: []automate.Step{{Action: "open-case"}},
	}, "dana"); err != nil {
		t.Fatal(err)
	}
	if err := setRing(root, rules, "auth.privileged-failed", detect.Trial,
		"new, and unproven on this estate", "dana", audit.KindHuman); err != nil {
		t.Fatal(err)
	}
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	all := queue(t, root)
	if len(all) != 1 || !all[0].Trial {
		t.Fatalf("a trial rule's finding was not recorded: %+v", all)
	}
	if runs, _ := automationEngine(root).Runs(); len(runs) != 0 {
		t.Fatalf("%d automation run(s) came from a trial rule's finding; an "+
			"unearned rule acted", len(runs))
	}

	// Promoted, the next finding reaches them.
	if err := setRing(root, rules, "auth.privileged-failed", detect.Live, "",
		"dana", audit.KindHuman); err != nil {
		t.Fatal(err)
	}
	appendEvents(t, root, []labelled{{"again", true, signIn("okta/system",
		"admin-ops", telemetry.DispositionFailed, "", t0.Add(time.Minute))}})
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	runs, _ := automationEngine(root).Runs()
	if len(runs) != 1 || runs[0].State != "done" || !runs[0].Steps[0].OK {
		t.Fatalf("a live rule's finding reached %d run(s): %+v", len(runs), runs)
	}
}

// TestTheRulesTheCorrelationsAndTheIndicatorsKeepTheirOwnWindows.
//
// One scan now feeds all three, and each holds a cursor of its own; a run
// moves each only over what it read for itself. A fusion that shared one
// window would silently change all three answers at once — rules would
// re-count settled events, correlations would lose windows they should
// re-read, indicators would miss events or count them twice. So the three
// cursors are pulled apart between runs here — the rules' into the middle
// of what arrived, the correlations' and the indicators' back to the
// beginning — and each consumer must answer from its own window and no
// other's. This is the one test that fails if the fused scan starts
// anywhere but the earliest of the three windows, or filters any consumer
// by a window not its own.
func TestTheRulesTheCorrelationsAndTheIndicatorsKeepTheirOwnWindows(t *testing.T) {
	w0 := closedWindow() // a fifteen-minute window the watermark has passed
	b0 := w0.Add(time.Hour)
	corpus := append(failures("admin-dana", w0, 5),
		went("dana", "203.0.113.9", 175, "connect"))
	root, rules := corrSite(t, corpus)
	if err := cmdIntel(root, []string{"add", "203.0.113.9", "--source",
		"cert"}); err != nil {
		t.Fatal(err)
	}
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}
	seen := func(source, who string) int {
		for _, f := range queue(t, root) {
			if f.Source == source && f.Entity.Value == who {
				return f.Seen
			}
		}
		return 0
	}
	if n := seen("auth.privileged-failed", "admin-dana"); n != 5 {
		t.Fatalf("the first run counted %d of dana's five failures", n)
	}
	if n := len(correlated(t, root)); n != 1 {
		t.Fatalf("the first run raised %d correlation finding(s)", n)
	}
	if n := seen("intel/"+intelID(t, root, "203.0.113.9"), "dana"); n != 1 {
		t.Fatalf("the look back counted dana's connection %d times", n)
	}

	// What arrived since: another five failures, an hour on, and a second
	// connection to the listed address.
	appendEvents(t, root, append(failures("admin-raj", b0, 5),
		went("sam", "203.0.113.9", 60, "connect")))

	// The cursors pulled apart. The rules' sits inside raj's five, so the
	// rules see only their last three; the correlations' and the
	// indicators' are wiped, so those two read everything again.
	reg, cursors, err := finding.Load(findingsPath(root))
	if err != nil {
		t.Fatal(err)
	}
	cursors[detectCursor] = b0.Add(2*time.Minute + 30*time.Second)
	cursors[correlateCursor] = time.Time{}
	cursors[intelCursor] = time.Time{}
	if err := finding.Save(findingsPath(root), reg, cursors); err != nil {
		t.Fatal(err)
	}
	if err := detectRun(root, []string{"--rules", rules}); err != nil {
		t.Fatal(err)
	}

	// The rules answered from their own window: dana's settled finding was
	// not re-counted, and raj's counted only the three that arrived after
	// the cursor.
	if n := seen("auth.privileged-failed", "admin-dana"); n != 5 {
		t.Errorf("the rules re-read %d of dana's events they had already "+
			"counted", n-5)
	}
	if n := seen("auth.privileged-failed", "admin-raj"); n != 3 {
		t.Errorf("the rules counted %d of raj's three in-window failures", n)
	}
	// The correlations read the whole store again: raj's window fired, and
	// dana's — re-read but already raised — fired once, not twice.
	got := correlated(t, root)
	if len(got) != 2 {
		t.Fatalf("%d correlation finding(s), want dana's and raj's", len(got))
	}
	for _, f := range got {
		if f.Seen != 1 {
			t.Errorf("a window was raised %d times", f.Seen)
		}
	}
	// The indicators read the whole store again too: dana's finding counted
	// the connection twice, sam's once.
	id := intelID(t, root, "203.0.113.9")
	if n := seen("intel/"+id, "dana"); n != 2 {
		t.Errorf("dana's connection was counted %d times over two reads of "+
			"it", n)
	}
	if n := seen("intel/"+id, "sam"); n != 1 {
		t.Errorf("sam's connection was counted %d times", n)
	}
}

// intelID is the identifier of the one indicator holding a value.
func intelID(t *testing.T, root, value string) string {
	t.Helper()
	set, err := loadIndicators(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range set.All() {
		if i.Value == value {
			return i.ID
		}
	}
	t.Fatalf("no indicator holds %s", value)
	return ""
}
