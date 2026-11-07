// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/config"
	"github.com/aertun/aertun/internal/dual"
	"github.com/aertun/aertun/internal/enrol"
)

// On the People screen, making somebody an administrator waits for a
// second administrator, who sees it there and approves it; whoever asked
// may only withdraw it.
func TestMakingAnAdministratorOnTheScreenTakesTwo(t *testing.T) {
	srv, editor := setup(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "lee", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	lee, _, err := srv.Tokens.IssueSession("lee", "lee", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	w := postForm(t, srv, "/people/grant", editor, url.Values{"principal": {"pat"}, "role": {"admin"}, "resource": {"/"}}.Encode())
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, "waits for a second administrator") {
		t.Fatalf("granting: %d %s", w.Code, loc)
	}
	if srv.Policy.Evaluate("pat", auth.ActGrant, "/").Allowed {
		t.Fatal("pat became an administrator on one administrator's word")
	}
	pend, _ := srv.Dual.Store.Pending(time.Now())
	if len(pend) != 1 {
		t.Fatalf("pending: %+v", pend)
	}
	mine := get(t, srv, "/people", editor).Body.String()
	if !strings.Contains(mine, "Waiting for a second administrator") || strings.Contains(mine, `value="approve"`) ||
		!strings.Contains(mine, `value="withdraw"`) {
		t.Error("the asker is offered the wrong buttons")
	}
	if !strings.Contains(get(t, srv, "/people", lee).Body.String(), `value="approve"`) {
		t.Fatal("another administrator is not offered to approve")
	}
	postForm(t, srv, "/people/pending", editor, url.Values{"id": {pend[0].ID}, "do": {"approve"}}.Encode())
	if srv.Policy.Evaluate("pat", auth.ActGrant, "/").Allowed {
		t.Fatal("the asker approved their own request")
	}
	postForm(t, srv, "/people/pending", lee, url.Values{"id": {pend[0].ID}, "do": {"approve"}}.Encode())
	if !srv.Policy.Evaluate("pat", auth.ActGrant, "/").Allowed {
		t.Fatal("approved, and pat is not an administrator")
	}
}

// A weaker setting from the Settings screen waits too, and is made when
// approved. The only administrator's own request waits out its delay: the
// screen offers them Decline at once and Approve only once it has passed.
func TestAWeakerSettingOnTheScreenTakesTwo(t *testing.T) {
	srv, editor := setup(t)
	// Read and written as bytes, as the file is: a change the handler
	// makes and does not save is not seen by the next read.
	saved := []byte("{}")
	srv.Settings = &Settings{
		Load: func() (*config.Config, error) { return config.Parse(saved) },
		Save: func(c *config.Config) error { b, err := c.Bytes(); saved = b; return err }}
	weaken := url.Values{"key": {"siem.stream.reveal"}, "value": {"true"}, "reason": {"the SIEM holds names already"}}.Encode()
	w := postForm(t, srv, "/settings/save", editor, weaken)
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); w.Code != http.StatusSeeOther ||
		!strings.Contains(loc, "You are the only administrator") {
		t.Fatalf("alone: %d %s", w.Code, loc)
	}
	if cfg, _ := srv.Settings.Load(); cfg.Bool("siem.stream.reveal") {
		t.Fatal("the only administrator weakened a setting with no delay")
	}
	solo, _ := srv.Dual.Store.Pending(time.Now())
	if len(solo) != 1 || solo[0].NotBefore.IsZero() {
		t.Fatalf("pending: %+v", solo)
	}
	page := get(t, srv, "/people", editor).Body.String()
	if strings.Contains(page, `value="approve"`) || !strings.Contains(page, `value="decline"`) {
		t.Error("during the delay the only administrator should be offered Decline and not Approve")
	}
	rows := srv.pendingRows(principal{Name: "editor"}, solo[0].NotBefore)
	if len(rows) != 1 || !rows[0].CanDecide {
		t.Errorf("after the delay the only administrator cannot approve: %+v", rows)
	}
	if _, err := srv.Dual.Store.Decide(solo[0].ID, "editor", false, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	saved = []byte("{}")
	if err := srv.Policy.Grant(auth.Binding{Principal: "lee", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	postForm(t, srv, "/settings/save", editor, weaken)
	if cfg, _ := srv.Settings.Load(); cfg.Bool("siem.stream.reveal") {
		t.Fatal("a weaker setting took effect on one administrator's word")
	}
	pend, _ := srv.Dual.Store.Pending(time.Now())
	if len(pend) != 1 || pend[0].Kind != dual.Setting {
		t.Fatalf("pending: %+v", pend)
	}
	lee, _, _ := srv.Tokens.IssueSession("lee", "lee", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	postForm(t, srv, "/people/pending", lee, url.Values{"id": {pend[0].ID}, "do": {"approve"}}.Encode())
	if cfg, _ := srv.Settings.Load(); !cfg.Bool("siem.stream.reveal") {
		t.Fatal("approved, and the setting did not change")
	}
}

// The only administrator making somebody an administrator on the People
// screen is told to write a reason when there is none, and nothing waits;
// with one, the request waits and the reason is in the request and in the
// audit record.
func TestTheOnlyAdministratorsRequestOnTheScreenNeedsAReason(t *testing.T) {
	srv, editor := setup(t)
	var recorded map[string]string
	srv.Audit = func(action, resource string, detail map[string]string) {
		if action == "dual.proposed" {
			recorded = detail
		}
	}
	w := postForm(t, srv, "/people/grant", editor,
		url.Values{"principal": {"pat"}, "role": {"admin"}, "resource": {"/"}}.Encode())
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, "needs a reason") {
		t.Fatalf("a grant made alone without a reason: %d %s", w.Code, loc)
	}
	if pend, _ := srv.Dual.Store.Pending(time.Now()); len(pend) != 0 {
		t.Fatalf("a request without a reason waits: %+v", pend)
	}
	w = postForm(t, srv, "/people/grant", editor, url.Values{"principal": {"pat"},
		"role": {"admin"}, "resource": {"/"}, "note": {"pat runs the night shift"}}.Encode())
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, "You are the only administrator") {
		t.Fatalf("a grant made alone with a reason: %d %s", w.Code, loc)
	}
	pend, _ := srv.Dual.Store.Pending(time.Now())
	if len(pend) != 1 || pend[0].Why != "pat runs the night shift" {
		t.Fatalf("pending: %+v", pend)
	}
	if recorded["why"] != "pat runs the night shift" {
		t.Errorf("the audit record of the request carries %q", recorded["why"])
	}
	if page := get(t, srv, "/people", editor).Body.String(); strings.Contains(page, "Optional, and worth writing") {
		t.Error("the screen still calls the reason optional")
	}
}

// The only administrator approving their own request after its delay must
// have signed in with their passkey in the last five minutes. An older
// session is marked to prove its person — durably — and sent to do it,
// and the request still waits; a fresh passkey session approves it.
func TestApprovingYourOwnRequestNeedsAFreshPasskey(t *testing.T) {
	srv, editor := setup(t)
	srv.Passkeys = &Passkeys{Save: func(*Passkeys) error { return nil },
		Credentials: []StoredCredential{{Principal: "editor"}}}
	saves := 0
	srv.SaveTokens = func(*auth.TokenStore) error { saves++; return nil }
	req, err := srv.Dual.Store.Propose(dual.Grant, "make pat admin on /",
		dual.GrantChange{Bindings: []auth.Binding{{Principal: "pat", Role: auth.RoleAdmin, Resource: "/"}}},
		"pat runs the night shift", "editor", true, time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// The sign-in was six minutes ago.
	for i := range srv.Tokens.Tokens {
		srv.Tokens.Tokens[i].AuthAt = time.Now().Add(-6 * time.Minute).Unix()
	}
	w := postForm(t, srv, "/people/pending", editor, url.Values{"id": {req.ID}, "do": {"approve"}}.Encode())
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/signin/verify" {
		t.Fatalf("an old session approving its own request: %d %s", w.Code, w.Header().Get("Location"))
	}
	if srv.Policy.Evaluate("pat", auth.ActGrant, "/").Allowed {
		t.Fatal("approved on a six-minute-old sign-in")
	}
	if saves == 0 || srv.Tokens.Tokens[0].StepUp == "" {
		t.Fatal("the session was not durably marked to prove its person")
	}
	// Another administrator letting the session in proves nothing about
	// its person.
	if err := srv.Tokens.ClearStepUp(srv.Tokens.Tokens[0].ID); err != nil {
		t.Fatal(err)
	}
	if w := postForm(t, srv, "/people/pending", editor, url.Values{"id": {req.ID}, "do": {"approve"}}.Encode()); w.Header().Get("Location") != "/signin/verify" {
		t.Fatalf("a session let in by somebody else approved its own request: %s", w.Header().Get("Location"))
	}

	// A passkey sign-in just now.
	fresh, _, err := srv.Tokens.IssueSession("passkey:editor", "editor", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	postForm(t, srv, "/people/pending", fresh, url.Values{"id": {req.ID}, "do": {"approve"}}.Encode())
	if !srv.Policy.Evaluate("pat", auth.ActGrant, "/").Allowed {
		t.Fatal("a fresh passkey session could not approve its own request")
	}
}

// The People screen's invitation: the grant and a working link in one
// step. A viewer is granted at once; an administrator waits for a second
// one and still gets the link, told it reaches nothing until then; a deny
// is not an invitation.
func TestInvitingOnTheScreenGrantsAndShowsTheLink(t *testing.T) {
	srv, editor := setup(t)
	srv.Enrol = &enrol.Store{Path: filepath.Join(t.TempDir(), "enrol.json")}
	if err := srv.Policy.Grant(auth.Binding{Principal: "lee", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	link := regexp.MustCompile(`/enrol/([A-Za-z0-9_-]+)`)

	w := postForm(t, srv, "/people/grant", editor, url.Values{"principal": {"pat"},
		"role": {"viewer"}, "resource": {"/"}, "invite": {"on"}}.Encode())
	body := w.Body.String()
	if !srv.Policy.Evaluate("pat", auth.ActView, "/").Allowed || !strings.Contains(body, "pat is now viewer") {
		t.Fatalf("the invitation did not grant: %d %s", w.Code, body)
	}
	m := link.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no link on the page: %s", body)
	}
	if l, err := srv.Enrol.Peek(m[1], time.Now()); err != nil || l.Principal != "pat" {
		t.Fatalf("the link does not open for pat: %+v %v", l, err)
	}

	w = postForm(t, srv, "/people/grant", editor, url.Values{"principal": {"sam"},
		"role": {"admin"}, "resource": {"/"}, "invite": {"on"}}.Encode())
	body = w.Body.String()
	if srv.Policy.Evaluate("sam", auth.ActGrant, "/").Allowed {
		t.Fatal("an administrator was made on one administrator's word")
	}
	if !strings.Contains(body, "holds nothing until it is approved") || link.FindStringSubmatch(body) == nil {
		t.Fatalf("a waiting administrator's invitation: %d %s", w.Code, body)
	}

	w = postForm(t, srv, "/people/grant", editor, url.Values{"principal": {"vic"},
		"role": {"viewer"}, "resource": {"/"}, "invite": {"on"}, "deny": {"on"}}.Encode())
	if loc, _ := url.QueryUnescape(w.Header().Get("Location")); !strings.Contains(loc, "A deny invites nobody") {
		t.Fatalf("a deny was taken for an invitation: %d %s", w.Code, loc)
	}
}
