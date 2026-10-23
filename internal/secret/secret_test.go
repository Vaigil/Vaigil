// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package secret

import "testing"

func TestItFindsCredentials(t *testing.T) {
	for _, body := range []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"token: vg_6zukocv7ecidrejjyojgsdn7ekl3w2v3qph3ef6ylsm6usaqbtdq",
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
