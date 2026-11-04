// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package pii

import (
	"strings"
	"testing"

	"github.com/aeroprove/aeroprove/internal/secret"
)

func secretsAt(text string) [][2]int {
	// Stands in for secret.Spans: one fake key shape.
	if i := strings.Index(text, "sk-live-"); i >= 0 {
		return [][2]int{{i, i + len("sk-live-0123456789abcdef")}}
	}
	return nil
}

func TestWhatLeavesIsMaskedAndWhatComesBackIsRestored(t *testing.T) {
	m := &Masker{Allowed: []string{"paper.example"}, Secrets: secretsAt}
	text := "Ana (ana.lopez@mailhost.net, +44 20 7946 0958) paid with 4111 1111 1111 1111 and 5425233430109903. " +
		"Write to ana.lopez@mailhost.net again, or to shop@paper.example. Key sk-live-0123456789abcdef. " +
		"Refund to GB33BUKB20201555555555."
	out := m.Mask(text, false)
	for _, gone := range []string{"ana.lopez@mailhost.net", "7946", "5425233430109903", "sk-live", "GB33BUKB"} {
		if strings.Contains(out, gone) {
			t.Errorf("%q left in %s", gone, out)
		}
	}
	// The test card is nobody's and the site's own address is published.
	if !strings.Contains(out, "4111 1111 1111 1111") || !strings.Contains(out, "shop@paper.example") {
		t.Errorf("masked what is nobody's: %s", out)
	}
	// The same person is the same placeholder both times.
	if strings.Count(out, "<aeroprove:email:1>") != 2 || strings.Contains(out, "<aeroprove:email:2>") {
		t.Errorf("one address, two placeholders: %s", out)
	}
	if c := m.Masked(); c["email"] != 1 || c["phone"] != 1 || c["card"] != 1 || c["secret"] != 1 || c["iban"] != 1 {
		t.Errorf("counted %v", c)
	}
	answer := "I have refunded <aeroprove:card:1> and emailed <aeroprove:email:1>."
	if got := m.Restore(answer); got != "I have refunded 5425233430109903 and emailed ana.lopez@mailhost.net." {
		t.Errorf("restored %q", got)
	}
}

func TestARouteThatMayReceivePersonalDataStillGetsNoCardOrKey(t *testing.T) {
	m := &Masker{Secrets: secretsAt}
	out := m.Mask("ana@mailhost.net paid 5425233430109903 with sk-live-0123456789abcdef", true)
	if !strings.Contains(out, "ana@mailhost.net") || strings.Contains(out, "5425") || strings.Contains(out, "sk-live") {
		t.Fatalf("%s", out)
	}
	if (&Masker{}).Mask("nothing here", false) != "nothing here" {
		t.Fatal("text with nothing in it changed")
	}
}

// Where two finds overlap, the longer is masked once, and nothing is
// written twice.
func TestOverlappingFindsAreMaskedOnce(t *testing.T) {
	text := "creds: KEY(mira.k@mailhost.net:hunter2) end"
	m := &Masker{Secrets: func(s string) [][2]int {
		i := strings.Index(s, "KEY(")
		return [][2]int{{i, strings.Index(s, ") end") + 1}}
	}}
	out := m.Mask(text, false)
	if out != "creds: <aeroprove:secret:1> end" {
		t.Fatalf("%q", out)
	}
	if m.Restore(out) != text {
		t.Fatal("not restored")
	}
}

// The shape a whole prompt reaches the mask in: a state, marshalled, on
// one line between its fences. A bare PEM header planted in one value
// must cost that value the header — not cost the model the entity, the
// other evidence and the fence around the lot.
func TestABarePemHeaderCannotEraseTheRestOfAPrompt(t *testing.T) {
	m := &Masker{Secrets: secret.Spans}
	blob := `<<<state>>>{"title":"Brute force against admin",` +
		`"entity":"dana","evidence":["user-agent=-----BEGIN PRIVATE KEY-----",` +
		`"the mfa was reset","a token minted"]}<<<state>>>`
	out := m.Mask(blob, true)
	for _, keep := range []string{`"entity":"dana"`, "the mfa was reset",
		"a token minted", "<<<state>>>"} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q did not survive the mask: %s", keep, out)
		}
	}
	if n := strings.Count(out, "<aeroprove:secret:"); n != 1 {
		t.Errorf("%d placeholders for one header: %s", n, out)
	}
}

// A block that an END closes is masked whole, and only it: the credential
// leaves, what was said around it stays.
func TestAClosedPemBlockIsMaskedWholeAndNothingElse(t *testing.T) {
	m := &Masker{Secrets: secret.Spans}
	block := "-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXktdjEAAAAA" +
		" -----END OPENSSH PRIVATE KEY-----"
	out := m.Mask("evidence: "+block+" and then the mfa was reset", true)
	if !strings.Contains(out, "<aeroprove:secret:1>") ||
		strings.Contains(out, "b3BlbnNza") {
		t.Errorf("the key did not leave as one placeholder: %s", out)
	}
	if !strings.Contains(out, "and then the mfa was reset") {
		t.Errorf("what followed the block was taken with it: %s", out)
	}
}
