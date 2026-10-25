// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vaigil/vaigil/internal/detect"
	"github.com/vaigil/vaigil/internal/spool"
	"github.com/vaigil/vaigil/internal/telemetry"
)

// The batches in testdata/quilzo-stream are real: a Quilzo store pointed at
// a local receiver by siem.stream.url, sent with `quilzo siem stream send`,
// the first holding records 1 to 43 and the second 44 to 46 (an
// administrator granted by the only one, and a token request). The keys are
// that store's `quilzo siem stream key --json`. Nothing here was built to
// pass: a change on either side that stops Vaigil reading what Quilzo
// actually sends fails this.

var signedAt = regexp.MustCompile(`created=(\d+)`)

// streamDelivery is one captured batch, as a proxy hands it on: an
// origin-form path to an internal host, over plain HTTP.
func streamDelivery(t *testing.T, n int, change func(string) string) (*http.Request, time.Time) {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("testdata/quilzo-stream/batch%d.json", n))
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(rec.URL)
	if err != nil {
		t.Fatal(err)
	}
	body := rec.Body
	if change != nil {
		body = change(body)
	}
	r := httptest.NewRequest(http.MethodPost, u.RequestURI(), strings.NewReader(body))
	r.Host = "vaigil.internal:8080"
	for k, v := range rec.Headers {
		if k != "Host" && k != "Content-Length" {
			r.Header.Set(k, v)
		}
	}
	m := signedAt.FindStringSubmatch(rec.Headers["Signature-Input"])
	if m == nil {
		t.Fatal("the capture has no signature time")
	}
	sec, _ := strconv.ParseInt(m[1], 10, 64)
	return r, time.Unix(sec, 0).Add(2 * time.Second)
}

func deliver(t *testing.T, inb *inboundServer, n int, change func(string) string) (int, int64) {
	t.Helper()
	r, at := streamDelivery(t, n, change)
	inb.now = func() time.Time { return at }
	w := httptest.NewRecorder()
	inb.ServeHTTP(w, r)
	var ans struct {
		Holds *int64 `json:"holds"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &ans)
	if ans.Holds == nil {
		return w.Code, -1
	}
	return w.Code, *ans.Holds
}

// Quilzo's audit log is taken batch by batch, only in order and only as it
// was signed, kept across a restart, and read by the quilzo.* rules.
func TestQuilzosAuditStreamIsTakenInOrderAndReadByTheRules(t *testing.T) {
	root := connectStore(t)
	if err := cmdConfig(root, []string{"set", "admin.base_url", "http://127.0.0.1:9911"}); err != nil {
		t.Fatal(err)
	}
	f, shown, err := makeFeed(root, "quilzo", "quilzo-shop",
		map[string]string{"keys": "testdata/quilzo-stream/keys.json"}, "boss")
	if err != nil {
		t.Fatal(err)
	}
	if f.Stream == nil || !strings.Contains(strings.Join(shown, "\n"), "siem.stream.url") {
		t.Fatalf("the feed did not pin the keys or say how to point Quilzo at it: %+v %v", f, shown)
	}
	inb := newInboundServer(root)

	// Out of order: the receiver holds nothing, and says so.
	if code, holds := deliver(t, inb, 2, nil); code != http.StatusConflict || holds != 0 {
		t.Fatalf("a batch that skips records 1 to 43 answered %d, holding %d", code, holds)
	}
	if code, holds := deliver(t, inb, 1, nil); code != http.StatusOK || holds != 43 {
		t.Fatalf("the first batch answered %d, holding %d", code, holds)
	}
	if n := storedFrom(t, root, "quilzo/audit"); n != 43 {
		t.Fatalf("%d events stored from 43 records", n)
	}
	// One record changed on the way: the body no longer has the digest it
	// was signed with.
	tampered := func(s string) string { return strings.Replace(s, `\"status\":\"success\"`, `\"status\":\"denied\"`, 1) }
	if code, _ := deliver(t, inb, 2, tampered); code != http.StatusUnauthorized {
		t.Fatalf("a changed batch answered %d", code)
	}
	if code, holds := deliver(t, inb, 2, nil); code != http.StatusOK || holds != 46 {
		t.Fatalf("the second batch answered %d, holding %d", code, holds)
	}
	// Sent again, as a sender that lost the answer would: refused with
	// where the receiver is, so the sender moves on.
	if code, holds := deliver(t, inb, 1, nil); code != http.StatusConflict || holds != 46 {
		t.Fatalf("a batch already held answered %d, holding %d", code, holds)
	}
	// A restart remembers the chain.
	again := newInboundServer(root)
	if code, holds := deliver(t, again, 2, nil); code != http.StatusConflict || holds != 46 {
		t.Fatalf("after a restart the second batch answered %d, holding %d", code, holds)
	}
	if n := storedFrom(t, root, "quilzo/audit"); n != 46 {
		t.Fatalf("%d events stored from 46 records", n)
	}

	// What the shipped rules make of it.
	files, err := detect.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var rules []detect.Rule
	for _, pf := range files {
		if strings.HasPrefix(pf.Name, "quilzo.") {
			var r detect.Rule
			if err := json.Unmarshal(pf.Body, &r); err != nil {
				t.Fatal(err)
			}
			rules = append(rules, r)
		}
	}
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Release()
	fired := map[string]bool{}
	_ = sp.Range(time.Time{}, time.Time{}, func(e telemetry.Event) error {
		for _, r := range rules {
			if r.Matches(e) {
				fired[r.ID] = true
			}
		}
		return nil
	})
	for _, want := range []string{"quilzo.admin-granted", "quilzo.admin-token-issued",
		"quilzo.privileged-change-alone", "quilzo.posture-drifted", "quilzo.shield-asked-for-a-case"} {
		if !fired[want] {
			ids := make([]string, 0, len(fired))
			for id := range fired {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			t.Errorf("%s did not fire on what Quilzo sent; fired: %v", want, ids)
		}
	}
	for _, quiet := range []string{"quilzo.break-glass", "quilzo.audit-log-moved", "quilzo.decoy-touched"} {
		if fired[quiet] {
			t.Errorf("%s fired on a stream with nothing of the kind in it", quiet)
		}
	}
}

// Without the configured origin, the address a proxy hands on is not the
// one Quilzo signed, and the batch is refused rather than taken unchecked.
func TestTheSignedAddressIsTheOneQuilzoWasGiven(t *testing.T) {
	root := connectStore(t)
	if _, _, err := makeFeed(root, "quilzo", "quilzo-shop",
		map[string]string{"keys": "testdata/quilzo-stream/keys.json"}, "boss"); err != nil {
		t.Fatal(err)
	}
	if code, _ := deliver(t, newInboundServer(root), 1, nil); code != http.StatusUnauthorized {
		t.Fatalf("a batch checked against an address it was not signed for answered %d", code)
	}
}

// A write that stopped part way through a leaf leaves the feed at the last
// whole one, and says so, rather than refusing everything after it.
func TestATornWriteOfTheChainIsCutBackToWhatWasWhole(t *testing.T) {
	root := connectStore(t)
	if err := cmdConfig(root, []string{"set", "admin.base_url", "http://127.0.0.1:9911"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := makeFeed(root, "quilzo", "quilzo-shop",
		map[string]string{"keys": "testdata/quilzo-stream/keys.json"}, "boss"); err != nil {
		t.Fatal(err)
	}
	if code, holds := deliver(t, newInboundServer(root), 1, nil); code != http.StatusOK || holds != 43 {
		t.Fatalf("the first batch answered %d, holding %d", code, holds)
	}
	path := streamLeavesPath(root, "quilzo-shop")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(b), "\n")
	// Forty leaves whole and the forty-first half written.
	torn := strings.Join(lines[:40], "") + lines[40][:20]
	if err := os.WriteFile(path, []byte(torn), 0o600); err != nil {
		t.Fatal(err)
	}
	inb := newInboundServer(root)
	if code, holds := deliver(t, inb, 2, nil); code != http.StatusConflict || holds != 40 {
		t.Fatalf("after a torn write the feed answered %d, holding %d; it holds forty whole leaves", code, holds)
	}
	after, _ := os.ReadFile(path)
	if !strings.HasSuffix(string(after), "\n") || strings.Count(string(after), "\n") != 40 {
		t.Fatalf("the half-written leaf was left in the file:\n%q", string(after)[len(after)-30:])
	}
}

// A feed of this kind needs the keys, and the keys must be keys.
func TestAQuilzoFeedNeedsItsPublishedKeys(t *testing.T) {
	root := connectStore(t)
	if _, _, err := makeFeed(root, "quilzo", "quilzo-shop", nil, "boss"); err == nil ||
		!strings.Contains(err.Error(), "--keys") {
		t.Fatalf("a feed with no keys: %v", err)
	}
	bad := t.TempDir() + "/keys.json"
	_ = os.WriteFile(bad, []byte(`{"key_id":"x","alg":"ed25519","public_key":"AAAA"}`), 0o600)
	if _, _, err := makeFeed(root, "quilzo", "quilzo-shop", map[string]string{"keys": bad}, "boss"); err == nil {
		t.Fatal("a key that is not an Ed25519 key was pinned")
	}
}
