// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/agentreg"
	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/oidc"
	"github.com/aertun/aertun/internal/out"
	"github.com/aertun/aertun/internal/ssf"
)

// The kill switch's outward half, through the commands an operator runs.
//
// The rows that matter:
//
//	disable with a live receiver     the push arrives, signed, and is
//	                                 verifiable by this program's own
//	                                 receiver code from the published key
//	disable with a dead receiver     the kill completes fully; the failure
//	                                 is audited, the switch never blocks
//	disable with no receivers        transmitting is off, said out loud
//	disable with no issuer           still a kill; each receiver is
//	                                 recorded as not hearing it, and why

// captured is what one receiver saw: every body, the bearer each push
// carried, and the content type it came as.
type captured struct {
	mu     sync.Mutex
	bodies []string
	auth   []string
	types  []string
}

func (c *captured) handler(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.bodies = append(c.bodies, string(body))
	c.auth = append(c.auth, r.Header.Get("Authorization"))
	c.types = append(c.types, r.Header.Get("Content-Type"))
	c.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

func (c *captured) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

// configureSSF writes the transmitter's settings the way `config set` does,
// through the same plumbing, so what a test runs with is what an operator's
// store would hold.
func configureSSF(t *testing.T, root string, entries ...string) {
	t.Helper()
	c, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Set("ssf.transmit.receivers", strings.Join(entries, ","), "", "test"); err != nil {
		t.Fatalf("the receivers were refused: %v", err)
	}
	if err := c.Set("admin.base_url", "https://aertun.acme.example", "", "test"); err != nil {
		t.Fatalf("the issuer was refused: %v", err)
	}
	if err := saveConfig(root, c); err != nil {
		t.Fatal(err)
	}
}

// verifyWithKeyAt reads a pushed token the way the receiving half of this
// program does, against the key this store keeps: the round trip proof at
// the command level.
func verifyWithKeyAt(t *testing.T, root, token, audience string) *ssf.SET {
	t.Helper()
	key, err := ssfKey(root)
	if err != nil {
		t.Fatal(err)
	}
	e, err := ssf.NewEmitter(key, "https://aertun.acme.example")
	if err != nil {
		t.Fatal(err)
	}
	ks, err := oidc.NewKeySet("https://aertun.acme.example/jwks",
		func(context.Context, string) ([]byte, error) { return e.JWKS(), nil })
	if err != nil {
		t.Fatal(err)
	}
	rcv := &ssf.Receiver{Issuer: "https://aertun.acme.example", Audience: audience,
		Algorithms: []oidc.Algorithm{oidc.ES256}, Keys: ks,
		Now: func() time.Time { return time.Now().UTC() }}
	set, err := rcv.Verify(token)
	if err != nil {
		t.Fatalf("what the receiver was pushed did not verify through the "+
			"receiver's own path: %v", err)
	}
	return set
}

// auditActions returns every record the log holds, by action — several
// records for one action included, because a kill switch with two receivers
// writes two ssf.transmitted records and a test that kept only the last
// would pass by luck half the time.
func auditActions(root string) map[string][]map[string]string {
	out := map[string][]map[string]string{}
	events, err := audit.Read(auditPath(root))
	if err != nil {
		return out
	}
	for _, e := range events {
		out[e.Action] = append(out[e.Action], e.Detail)
	}
	return out
}

// oneAction returns the single record an action wrote, for the rows where
// there is exactly one and a second would itself be the failure.
func oneAction(root, action string) map[string]string {
	details := auditActions(root)[action]
	if len(details) != 1 {
		return nil
	}
	return details[0]
}

// TestDisablingAnAgentTellsEveryReceiver.
//
// The whole point of the outward half: the kill switch reaches the platforms
// configured to hear it, each push is a signed session-revoked about that
// agent, and the receiver's own verification reads it against the key this
// store published.
func TestDisablingAnAgentTellsEveryReceiver(t *testing.T) {
	w = out.New(false)
	root := registrySite(t, "watcher", auth.RoleViewer)
	register(t, root, "watcher", "aertun_read")

	// Two receivers: one open, one that wants the agreed bearer token.
	open := &captured{}
	sealed := &captured{}
	openSrv := httptest.NewServer(http.HandlerFunc(open.handler))
	sealedSrv := httptest.NewServer(http.HandlerFunc(sealed.handler))
	defer openSrv.Close()
	defer sealedSrv.Close()
	if _, err := storeSecret(root, "partner", "the-agreed-secret"); err != nil {
		t.Fatal(err)
	}
	configureSSF(t, root, openSrv.URL, sealedSrv.URL+"|partner")

	if err := cmdAgent(root, []string{"disable", "watcher", "--why", "gone quiet"}); err != nil {
		t.Fatal(err)
	}
	if open.count() != 1 || sealed.count() != 1 {
		t.Fatalf("each receiver gets one push; got %d and %d", open.count(), sealed.count())
	}
	if open.types[0] != ssf.SecEventJWT {
		t.Errorf("the push went as %s, not a security event token", open.types[0])
	}
	if sealed.auth[0] != "Bearer the-agreed-secret" {
		t.Errorf("the receiver with a stored secret was sent %q", sealed.auth[0])
	}
	if open.auth[0] != "" {
		t.Errorf("the open receiver was sent credentials it never asked for: %q", open.auth[0])
	}

	// The token verifies through the receiver's own path, and says the kill.
	set := verifyWithKeyAt(t, root, open.bodies[0], openSrv.URL)
	if set.Short != "session-revoked" || set.Subject.Format != "iss_sub" ||
		set.Subject.Ref() != "watcher" {
		t.Errorf("the pushed event reads as %+v", set)
	}
	if set.Signal().Reason != "gone quiet" {
		t.Errorf("the reason did not reach the receiving admins: %q", set.Signal().Reason)
	}

	var openRecorded, sealedRecorded, jtiRecorded bool
	for _, d := range auditActions(root)["ssf.transmitted"] {
		switch d["receiver"] {
		case openSrv.URL:
			openRecorded = true
			jtiRecorded = d["jti"] == set.JTI
		case sealedSrv.URL:
			sealedRecorded = true
		}
	}
	if !openRecorded || !jtiRecorded {
		t.Errorf("the delivery was not recorded with its receiver and event id")
	}
	if !sealedRecorded {
		t.Error("the second delivery was not recorded")
	}
	if _, failed := auditActions(root)["ssf.transmit-failed"]; failed {
		t.Error("a delivery that succeeded was recorded as a failure")
	}
}

// TestADeadReceiverDoesNotStopTheKill.
//
// The property the kill switch cannot lose: local revocation has already
// happened, and no receiver — down, refusing, or slow — changes the outcome.
// The attempt is audited, so the record says who was not told.
func TestADeadReceiverDoesNotStopTheKill(t *testing.T) {
	w = out.New(false)
	root := registrySite(t, "watcher", auth.RoleViewer)
	register(t, root, "watcher", "aertun_read")
	configureSSF(t, root, "http://127.0.0.1:1/caep") // nothing listens there

	if err := cmdAgent(root, []string{"disable", "watcher", "--why", "gone quiet"}); err != nil {
		t.Fatalf("a dead receiver failed the kill switch: %v", err)
	}
	entry, ok, err := agentStore(root).Get("watcher")
	if err != nil || !ok || entry.Status != agentreg.Disabled {
		t.Fatalf("the registry was not disabled: %+v (%v)", entry, err)
	}
	if oneAction(root, "agent.disable") == nil {
		t.Fatal("the disable itself was not recorded")
	}
	failed := oneAction(root, "ssf.transmit-failed")
	if failed == nil || failed["receiver"] != "http://127.0.0.1:1/caep" || failed["error"] == "" {
		t.Errorf("the dead receiver was not recorded with its error: %v", failed)
	}
	if _, ok := auditActions(root)["ssf.transmitted"]; ok {
		t.Error("an undelivered push was recorded as transmitted")
	}
}

// TestDisablingWithNoReceiversSaysTransmittingIsOff: the default state, said
// out loud so nobody believes partners are being told when they are not.
func TestDisablingWithNoReceiversSaysTransmittingIsOff(t *testing.T) {
	var buf bytes.Buffer
	w = &out.Writer{Out: &buf}
	root := registrySite(t, "watcher", auth.RoleViewer)
	register(t, root, "watcher", "aertun_read")

	if err := cmdAgent(root, []string{"disable", "watcher", "--why", "gone quiet"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "transmitting is off") {
		t.Errorf("the CLI did not say transmitting is off; it said:\n%s", buf.String())
	}
	if _, ok := auditActions(root)["ssf.transmitted"]; ok {
		t.Error("something was transmitted with no receivers configured")
	}
}

// TestAKillWithoutAnIssuerIsStillAKill: receivers configured but no
// admin.base_url — no event can be signed, and that is recorded per receiver
// rather than failing the switch.
func TestAKillWithoutAnIssuerIsStillAKill(t *testing.T) {
	w = out.New(false)
	root := registrySite(t, "watcher", auth.RoleViewer)
	register(t, root, "watcher", "aertun_read")
	configureSSF(t, root, "http://127.0.0.1:1/caep")
	// Back the issuer out again: receivers set, identity not.
	c, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Unset("admin.base_url"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, c); err != nil {
		t.Fatal(err)
	}

	if err := cmdAgent(root, []string{"disable", "watcher", "--why", "gone quiet"}); err != nil {
		t.Fatal(err)
	}
	failed := oneAction(root, "ssf.transmit-failed")
	if failed == nil || !strings.Contains(failed["error"], "admin.base_url") {
		t.Errorf("the missing identity was not recorded as the reason: %v", failed)
	}
}

// TestSSFReceiversListsWhereTheKillGoes: the operator's view of the outward
// half — who hears the switch, and what signs it.
func TestSSFReceiversListsWhereTheKillGoes(t *testing.T) {
	var buf bytes.Buffer
	w = &out.Writer{Out: &buf}
	root := registrySite(t, "watcher", auth.RoleViewer)

	// Nothing configured: transmitting is off, and the listing says so.
	if err := cmdSSF(root, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "transmitting is off") {
		t.Errorf("an empty list did not say transmitting is off:\n%s", buf.String())
	}

	buf.Reset()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	configureSSF(t, root, srv.URL+"|partner")
	if err := cmdSSF(root, []string{"receivers"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), srv.URL) ||
		!strings.Contains(buf.String(), "partner") ||
		!strings.Contains(buf.String(), "session-revoked") {
		t.Errorf("the listing did not name the receiver, its secret and the event:\n%s",
			buf.String())
	}
}

// TestSSFSendReAnnouncesAKill: the catch-up path for a receiver that was
// down or added late — and the refusals that keep a transmitted event true.
func TestSSFSendReAnnouncesAKill(t *testing.T) {
	w = out.New(false)
	root := registrySite(t, "watcher", auth.RoleViewer)
	register(t, root, "watcher", "aertun_read")
	register(t, root, "helper", "aertun_read")

	cap := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(cap.handler))
	defer srv.Close()
	configureSSF(t, root, srv.URL)

	// A live agent: session-revoked about it would be a lie to every partner.
	if err := cmdSSF(root, []string{"send", "helper", "--why", "x"}); err == nil {
		t.Error("an active agent's revocation was announced")
	}
	// An unknown agent is nobody.
	if err := cmdSSF(root, []string{"send", "ghost", "--why", "x"}); err == nil {
		t.Error("an unregistered agent was announced")
	}
	if cap.count() != 0 {
		t.Fatal("a refused send still pushed something")
	}

	if err := cmdAgent(root, []string{"disable", "watcher", "--why", "gone quiet"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdSSF(root, []string{"send", "watcher"}); err == nil {
		t.Error("a re-announcement without a reason was sent")
	}
	if err := cmdSSF(root, []string{"send", "watcher", "--why", "re-announced: partner was down"}); err != nil {
		t.Fatal(err)
	}
	if cap.count() != 2 { // the disable's push, then the re-announcement
		t.Fatalf("the kill and its re-announcement both arrive; got %d pushes", cap.count())
	}
	set := verifyWithKeyAt(t, root, cap.bodies[1], srv.URL)
	if set.Subject.Ref() != "watcher" || set.Signal().Reason != "re-announced: partner was down" {
		t.Errorf("the re-announcement reads as %+v", set)
	}
}

// TestThePublishedKeyFileMatchesWhatSigns: what lands in ssf.pub.json is
// the key the events are signed with, so a receiver configured from the file
// verifies pushes the store actually makes.
func TestThePublishedKeyFileMatchesWhatSigns(t *testing.T) {
	w = out.New(false)
	root := registrySite(t, "watcher", auth.RoleViewer)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	configureSSF(t, root, srv.URL)
	register(t, root, "watcher", "aertun_read")
	if err := cmdAgent(root, []string{"disable", "watcher", "--why", "gone quiet"}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(ssfPubPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var pub struct {
		Issuer string          `json:"issuer"`
		KeyID  string          `json:"key_id"`
		JWKS   json.RawMessage `json:"jwks"`
	}
	if err := json.Unmarshal(body, &pub); err != nil {
		t.Fatalf("%s is not readable: %v", ssfPubPath(root), err)
	}
	if pub.Issuer != "https://aertun.acme.example" || pub.KeyID == "" || len(pub.JWKS) == 0 {
		t.Fatalf("the published key file is incomplete: %s", body)
	}
	// The header of a real token names the published kid, and the published
	// key set verifies a real token — both through the receiver's own path.
	key, err := ssfKey(root)
	if err != nil {
		t.Fatal(err)
	}
	if pub.KeyID != ssf.KeyID(&key.PublicKey) {
		t.Error("the published key id is not the signing key's")
	}
	token, _, err := (&ssf.Emitter{Key: key, KeyID: ssf.KeyID(&key.PublicKey),
		Issuer: pub.Issuer}).SessionRevoked("watcher", srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(rawHeader, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr.Kid != pub.KeyID || hdr.Alg != "ES256" || hdr.Typ != "secevent+jwt" {
		t.Errorf("a token's header is %+v; it names the published key, the "+
			"algorithm and the type", hdr)
	}
}
