// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package calib

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/aertun/aertun/internal/pack"
)

// A certificate signs, verifies, and refuses for the wrong model.
func TestCertificateSignsAndVerifies(t *testing.T) {
	key, err := pack.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	cert := Certificate{
		Model:          "test-model",
		TemplateDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Epsilon:        0.10,
		Delta:          0.05,
		SampleSize:     200,
		Threshold:      0.92,
		ExpiresAt:      now.AddDate(1, 0, 0),
	}
	body, err := Sign(key, cert)
	if err != nil {
		t.Fatalf("signing the certificate: %v", err)
	}

	// Verify for the right model and template
	got, err := Verify(body, key.PublicKey(), "test-model", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", now)
	if err != nil {
		t.Fatalf("verifying the certificate: %v", err)
	}
	if got.Model != "test-model" {
		t.Errorf("model is %q, not test-model", got.Model)
	}
	if got.Threshold < 0.9 || got.Threshold > 0.95 {
		t.Errorf("threshold is %g, not near 0.92", got.Threshold)
	}

	// Wrong model: refused
	if _, err := Verify(body, key.PublicKey(), "other-model", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", now); err == nil {
		t.Error("a certificate for one model verified for another")
	}

	// Wrong template: refused
	if _, err := Verify(body, key.PublicKey(), "test-model", "wrong", now); err == nil {
		t.Error("a certificate for one template verified for another")
	}

	// Tampered body: the proof's signature catches it
	tampered := make([]byte, len(body))
	copy(tampered, body)
	// Change one byte in the payload
	var env map[string]any
	if err := json.Unmarshal(tampered, &env); err != nil {
		t.Fatal(err)
	}
	if p, ok := env["payload"].(string); ok {
		env["payload"] = p[:len(p)-2] + "AA=="
	}
	if tampered, err = json.Marshal(env); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(tampered, key.PublicKey(), "test-model", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", now); err == nil {
		t.Error("a tampered certificate verified")
	}
}
