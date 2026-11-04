// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aeroprove/aeroprove/internal/auth"
	"github.com/aeroprove/aeroprove/internal/finding"
	"github.com/aeroprove/aeroprove/internal/telemetry"
)

// fakeRegister is a finding register in memory with a decision log.
type fakeRegister struct {
	reg       *finding.Register
	decisions []finding.Decision
	produced  bool
}

func newFakeRegister(fs ...finding.Finding) *fakeRegister {
	fr := &fakeRegister{reg: finding.NewRegister(), produced: len(fs) > 0}
	for _, f := range fs {
		fr.reg.Record(f, f.First)
	}
	return fr
}

func (fr *fakeRegister) wire() *Findings {
	return &Findings{
		Queue: func(now time.Time) ([]finding.Finding, bool, error) {
			return finding.View(fr.reg, fr.decisions, now), fr.produced, nil
		},
		History: func(id string) ([]finding.Decision, error) {
			return finding.History(id, fr.decisions), nil
		},
		Decide: func(d finding.Decision) error {
			fr.decisions = append(fr.decisions, d)
			return nil
		},
	}
}

func detectionFinding(who, msg string, sev telemetry.Severity) finding.Finding {
	return finding.Finding{
		Kind: finding.FromDetection, Title: "Failed sign-in to a privileged account",
		Source: "auth.privileged-failed",
		Entity: telemetry.ID{Issuer: "okta", Value: who}, Severity: sev,
		State: finding.Open, First: time.Now().UTC().Add(-3 * time.Hour),
		Technique: []string{"T1110"},
		Evidence: []finding.Evidence{{At: time.Now().UTC().Add(-3 * time.Hour),
			What: msg, Source: "okta/system", Tainted: true}},
	}
}

func decideForm(t *testing.T, srv *Server, path, token string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// TestTheQueueSaysWhenNothingHasLooked.
//
// An empty register and one nothing has ever written are opposite facts
// that render the same. Only the first means nothing is wrong.
func TestTheQueueSaysWhenNothingHasLooked(t *testing.T) {
	srv, token := setup(t)
	body := get(t, srv, "/findings", token).Body.String()
	if !strings.Contains(body, "without a finding register") {
		t.Errorf("an unwired build did not say so")
	}
	srv.Findings = newFakeRegister().wire()
	body = get(t, srv, "/findings", token).Body.String()
	if !strings.Contains(body, "Nothing has looked yet") {
		t.Errorf("a never-written register read as a quiet one")
	}
	if strings.Contains(body, "Nothing needs attention") {
		t.Errorf("a never-written register said nothing needs attention")
	}
}

// TestTheQueueShowsWhatNeedsAttentionFirst.
func TestTheQueueShowsWhatNeedsAttentionFirst(t *testing.T) {
	srv, token := setup(t)
	fr := newFakeRegister(
		detectionFinding("admin-low", "a", telemetry.SeverityLow),
		detectionFinding("admin-crit", "b", telemetry.SeverityCritical),
	)
	srv.Findings = fr.wire()
	body := get(t, srv, "/findings", token).Body.String()
	crit, low := strings.Index(body, "okta:admin-crit"), strings.Index(body, "okta:admin-low")
	if crit < 0 || low < 0 || crit > low {
		t.Fatalf("the critical finding is not first (%d, %d)", crit, low)
	}
	if !strings.Contains(body, "a person decides") {
		t.Error("a finding resting on log text does not say a person decides")
	}
	// Filtering by severity.
	body = get(t, srv, "/findings?severity=critical", token).Body.String()
	if strings.Contains(body, "okta:admin-low") || !strings.Contains(body, "okta:admin-crit") {
		t.Error("the severity filter did not filter")
	}
}

// TestNothingAnAttackerWroteRunsOnTheScreen.
//
// Every field here came from outside: the message is log text from the
// source being attacked, and the entity is whatever name the attacker tried.
func TestNothingAnAttackerWroteRunsOnTheScreen(t *testing.T) {
	srv, token := setup(t)
	evil := `<script>alert(1)</script><img src=x onerror=alert(2)>`
	f := detectionFinding(`admin-"><svg onload=alert(3)>`, evil, telemetry.SeverityHigh)
	f.Title = "<b>title</b>"
	fr := newFakeRegister(f)
	srv.Findings = fr.wire()
	id := finding.View(fr.reg, nil, time.Now())[0].ID
	for _, path := range []string{"/findings", "/findings/" + id} {
		body := get(t, srv, path, token).Body.String()
		for _, raw := range []string{"<script>alert(1)", "<img src=x", "<svg onload", "<b>title</b>"} {
			if strings.Contains(body, raw) {
				t.Errorf("%s: %q reached the page unescaped", path, raw)
			}
		}
	}
}

// TestAVerdictIsRecordedAndApplied.
func TestAVerdictIsRecordedAndApplied(t *testing.T) {
	srv, token := setup(t)
	fr := newFakeRegister(detectionFinding("admin-dana", "failed", telemetry.SeverityHigh))
	srv.Findings = fr.wire()
	id := finding.View(fr.reg, nil, time.Now())[0].ID

	// No reason: refused, and nothing recorded.
	w := decideForm(t, srv, "/findings/decide", token, url.Values{
		"id": {id}, "to": {"false-positive"}})
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "e=") {
		t.Fatalf("a verdict with no reason: %d %q", w.Code, w.Header().Get("Location"))
	}
	if len(fr.decisions) != 0 {
		t.Fatal("a refused verdict was recorded")
	}

	w = decideForm(t, srv, "/findings/decide", token, url.Values{
		"id": {id}, "to": {"false-positive"}, "because": {"a load test"}})
	if w.Code != http.StatusSeeOther || len(fr.decisions) != 1 {
		t.Fatalf("a valid verdict: %d, %d recorded", w.Code, len(fr.decisions))
	}
	d := fr.decisions[0]
	if d.By != "editor" || d.To != finding.FalsePositive || d.Because != "a load test" {
		t.Fatalf("recorded %+v", d)
	}
	// Off the queue, and the reason is on the finding's page.
	if body := get(t, srv, "/findings", token).Body.String(); strings.Contains(body, "okta:admin-dana") {
		t.Error("a false positive is still in the queue")
	}
	if body := get(t, srv, "/findings/"+id, token).Body.String(); !strings.Contains(body, "a load test") {
		t.Error("the reason is not shown with the decision")
	}
}

// TestADecisionNeedsARealFindingAndTheRight.
func TestADecisionNeedsARealFindingAndTheRight(t *testing.T) {
	srv, token := setup(t)
	fr := newFakeRegister(detectionFinding("admin-dana", "failed", telemetry.SeverityHigh))
	srv.Findings = fr.wire()
	if w := decideForm(t, srv, "/findings/decide", token, url.Values{
		"id": {"not-a-finding"}, "to": {"fixed"}}); w.Code != http.StatusNotFound {
		t.Errorf("a decision about nothing answered %d", w.Code)
	}
	// Accepted must expire, in the future.
	id := finding.View(fr.reg, nil, time.Now())[0].ID
	for _, until := range []string{"", "2001-01-01", "tomorrow"} {
		decideForm(t, srv, "/findings/decide", token, url.Values{
			"id": {id}, "to": {"accepted"}, "because": {"x"}, "until": {until}})
	}
	if len(fr.decisions) != 0 {
		t.Fatalf("an acceptance with no future expiry was recorded: %+v", fr.decisions)
	}
	// A viewer reads the queue and decides nothing.
	viewer, vtoken := asRole(t, auth.RoleViewer)
	viewer.Findings = fr.wire()
	if w := get(t, viewer, "/findings", vtoken); w.Code != http.StatusOK {
		t.Errorf("a viewer cannot read the queue: %d", w.Code)
	}
	if w := decideForm(t, viewer, "/findings/decide", vtoken, url.Values{
		"id": {id}, "to": {"fixed"}}); w.Code == http.StatusSeeOther || len(fr.decisions) != 0 {
		t.Errorf("a viewer recorded a decision: %d", w.Code)
	}
	// An analyst triages, and does not accept a risk.
	analyst, atoken := asRole(t, auth.RoleAnalyst)
	analyst.Findings = fr.wire()
	if page := getPage(t, analyst, "/findings/"+id, atoken); strings.Contains(page, `value="accepted"`) {
		t.Error("an analyst is offered accepting a risk")
	}
	decideForm(t, analyst, "/findings/decide", atoken, url.Values{"id": {id}, "to": {"accepted"},
		"because": {"x"}, "until": {time.Now().AddDate(0, 0, 10).Format("2006-01-02")}})
	if len(fr.decisions) != 0 {
		t.Error("an analyst accepted a risk")
	}
	if w := decideForm(t, analyst, "/findings/decide", atoken, url.Values{
		"id": {id}, "to": {"triaged"}}); w.Code != http.StatusSeeOther || len(fr.decisions) != 1 {
		t.Errorf("an analyst could not triage: %d", w.Code)
	}
}

// TestAnAgentsSuggestionIsShownAsOne.
func TestAnAgentsSuggestionIsShownAsOne(t *testing.T) {
	srv, token := setup(t)
	fr := newFakeRegister(detectionFinding("admin-dana", "x", telemetry.SeverityHigh))
	caps := fr.wire()
	id := finding.View(fr.reg, nil, time.Now())[0].ID
	caps.Proposals = func(string) ([]finding.Proposal, error) {
		return []finding.Proposal{
			// One from an agent outside this program, one from the analyst
			// this program runs itself: the page must say which is which,
			// because the reason is free text either way, and beside the
			// buttons that decide.
			{Finding: id, At: time.Now(), By: "p_agent", For: "dana",
				To: finding.FalsePositive, Client: "ops-copilot",
				Because: "<script>alert(1)</script> the VPN egresses in NZ"},
			{Finding: id, At: time.Now().Add(-time.Minute), By: "p_analyst",
				For: "dana", To: finding.Triaged, Agent: "triage",
				Because: "the counts line up with the load test"},
		}, nil
	}
	srv.Findings = caps
	body := get(t, srv, "/findings/"+id, token).Body.String()
	if !strings.Contains(body, "Suggested by an agent") ||
		!strings.Contains(body, "Nothing here has changed") {
		t.Fatal("a proposal is not shown as a suggestion")
	}
	if strings.Contains(body, "<script>alert(1)") {
		t.Fatal("a model's reasoning reached the page unescaped")
	}
	// The two sources are named, and named differently: an outside agent by
	// its client, this program's own analyst as itself.
	if !strings.Contains(body, "proposed by an external agent: ops-copilot") {
		t.Error("an outside agent's proposal does not name its client")
	}
	if !strings.Contains(body, "proposed by the built-in analyst") {
		t.Error("the built-in analyst's proposal does not say what it is")
	}
	// And it did not change anything.
	if got := finding.View(fr.reg, fr.decisions, time.Now())[0].State; got != finding.Open {
		t.Fatalf("state %s", got)
	}
}

// TestTheEvidenceIsMetBeforeTheAdviceAndTheDecision.
//
// The page's order is its design: a reader who meets a verdict before the
// evidence takes the verdict — the automation-bias finding — so the evidence
// comes first, the form a person decides with follows it, and what a model
// suggested is last and closed until it is opened. And there is no accept
// button anywhere near a suggestion: adopting one in a press is the failure
// the order exists to prevent, so the block carries text and nothing that
// submits.
func TestTheEvidenceIsMetBeforeTheAdviceAndTheDecision(t *testing.T) {
	srv, token := setup(t)
	fr := newFakeRegister(detectionFinding("admin-dana", "failed sign-in", telemetry.SeverityHigh))
	caps := fr.wire()
	id := finding.View(fr.reg, nil, time.Now())[0].ID
	caps.Proposals = func(string) ([]finding.Proposal, error) {
		return []finding.Proposal{{Finding: id, At: time.Now(), By: "p_agent",
			For: "dana", To: finding.FalsePositive, Client: "ops-copilot",
			Because: "the VPN egresses in NZ"}}, nil
	}
	srv.Findings = caps
	body := get(t, srv, "/findings/"+id, token).Body.String()

	evidence := strings.Index(body, `<table class="evidence">`)
	decide := strings.Index(body, `action="/findings/decide"`)
	advice := strings.Index(body, `<details class="proposals">`)
	if evidence < 0 || decide < 0 || advice < 0 {
		t.Fatalf("the page is missing a part: evidence %d, decide %d, advice %d",
			evidence, decide, advice)
	}
	if !(evidence < decide && decide < advice) {
		t.Errorf("evidence (%d), decide (%d) and the advice (%d) are not in "+
			"that order. The evidence is what a decision is made from; the "+
			"advice is what it must be made against", evidence, decide, advice)
	}

	// Closed until it is opened — the reasoning is not on the page before
	// somebody has read the evidence above it.
	if strings.Contains(body, `<details class="proposals" open`) {
		t.Error("the suggestions arrive open; they are the last thing read, " +
			"not the first")
	}

	// No one-click adoption. The block holds words; anything that submits
	// from inside it would be an accept button by another name.
	block := body[advice:]
	if end := strings.Index(block, "</details>"); end >= 0 {
		block = block[:end]
	}
	for _, control := range []string{"<form", "<button", "<input"} {
		if strings.Contains(block, control) {
			t.Errorf("the suggestions carry a %q; a suggestion is agreed "+
				"with by deciding from the form above it, never by pressing "+
				"something beside it", control)
		}
	}

	// And the form says a suggestion is waiting, so recording one's own call
	// first is a choice the page offered rather than an order it implied.
	if !strings.Contains(body, "A suggestion is waiting below") {
		t.Error("the decide form does not say a suggestion is unopened below")
	}
}
