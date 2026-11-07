// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"strings"
	"testing"
)

func TestItFindsCredentials(t *testing.T) {
	for _, body := range []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"token: aet_6zukocv7ecidrejjyojgsdn7ekl3w2v3qph3ef6ylsm6usaqbtdq",
		"aws: AKIAIOSFODNN7EXAMPLE",
		"gh: ghp_16CharsAndThenSomeMoreCharacters1234",
		"openai: sk-proj-Ab3_kL9-mN2pQ7rS1tU4vW8xY0zA5bC6dE",
		"anthropic: sk-ant-api03-Zx9_Yw8-Vu7tS6rQ5pO4nM3lK2jI1hG0f",
		"postgres://admin:hunter2ButLonger@db.internal/app",
		`api_key = "9f8Xq2LmR7vT4wZ1pK6nD3sB5yH0jC8e"`,
	} {
		if len(Spans(body)) == 0 {
			t.Errorf("no credential found in: %s", body)
		}
	}
}

func TestPlaceholdersAreNotCredentials(t *testing.T) {
	for _, body := range []string{
		`api_key = "your-api-key-here"`,
		`secret: "changeme-please-change-me"`,
		`token = "{{ env.API_TOKEN }}"`,
		`password = "<redacted for the docs>"`,
		`api_key = "EXAMPLE_KEY_DO_NOT_USE"`,
		`secret = "${VAULT_SECRET}"`,
		`token = "short"`,
		"api_key = example",
	} {
		if s := Spans(body); len(s) != 0 {
			t.Errorf("a placeholder was taken for a credential: %s", body)
		}
	}
}

func TestSpansCoverTheWholeCredential(t *testing.T) {
	key := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"
	text := "before " + key + " after; and AKIAIOSFODNN7EXAMPLE; and password = \"hunter2hunter2hunter2X9\" nope"
	found := map[string]bool{}
	for _, s := range Spans(text) {
		found[text[s[0]:s[1]]] = true
	}
	if !found[key] || !found["AKIAIOSFODNN7EXAMPLE"] {
		t.Fatalf("%v", found)
	}
}

// A BEGIN that nothing closes is a header, not the start of everything
// after it. Whoever can write a log field could plant one and let the
// mask erase what the model was to read from there on: the entity, the
// other evidence, the fence around the lot.
func TestABeginWithNoEndMasksOnlyTheHeader(t *testing.T) {
	text := "sign-in failed for admin from -----BEGIN PRIVATE KEY-----" +
		" then the mfa was reset and a token minted"
	spans := Spans(text)
	if len(spans) != 1 ||
		text[spans[0][0]:spans[0][1]] != "-----BEGIN PRIVATE KEY-----" {
		t.Fatalf("spans %v of %q", spans, text)
	}
}

// An END only closes the BEGIN before it, and only within reach of a real
// key. One planted far away — or with none before it at all — masks
// nothing beyond what is already a credential.
func TestAnEndCannotBePlantedToEraseAMiddle(t *testing.T) {
	far := "-----BEGIN PRIVATE KEY-----" +
		strings.Repeat("filler ", 4<<10) + "-----END PRIVATE KEY-----"
	for name, text := range map[string]string{
		"an END beyond any real key": far,
		"an END with no BEGIN":       "a -----END PRIVATE KEY----- b",
		"an END label that never closes": "-----BEGIN PRIVATE KEY-----" +
			" filler -----END " + strings.Repeat("x", 65) + " end",
	} {
		for _, s := range Spans(text) {
			if got := text[s[0]:s[1]]; got != "-----BEGIN PRIVATE KEY-----" {
				t.Errorf("%s: the span took %q", name, got)
			}
		}
	}
}

// Two headers before one END are one masked stretch, and nothing after
// the END is taken with them.
func TestEachEndClosesTheBeginBeforeIt(t *testing.T) {
	end := "-----END PRIVATE KEY-----"
	text := "a -----BEGIN PRIVATE KEY----- b -----BEGIN RSA PRIVATE KEY----- c " +
		end + " and the mfa was reset"
	closes := strings.Index(text, end) + len(end)
	for _, s := range Spans(text) {
		if s[1] > closes {
			t.Fatalf("a span ran past the END into what follows: %q",
				text[s[0]:s[1]])
		}
	}
}
