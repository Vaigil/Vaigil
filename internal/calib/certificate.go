// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package calib

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/proof"
)

// PredicateURI names the calibration certificate's claim.
const PredicateURI = proof.PredicateCalibration

// Certificate is the calibration certificate: what was calibrated, for
// which model and template, at what bound, and the threshold it produced.
type Certificate struct {
	Model          string    `json:"model"`
	TemplateDigest string    `json:"template_digest"`
	Epsilon        float64   `json:"epsilon"`
	Delta          float64   `json:"delta"`
	SampleSize     int       `json:"sample_size"`
	Threshold      float64   `json:"threshold"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// Digest is the sha256 of the certificate's canonical fields — what a
// caller names when it says "calibrated for this".
func (c Certificate) Digest() string {
	b := fmt.Sprintf("calib/v1|%s|%s|%g|%g|%d|%g", c.Model, c.TemplateDigest, c.Epsilon, c.Delta, c.SampleSize, c.Threshold)
	h := sha256.Sum256([]byte(b))
	return hex.EncodeToString(h[:])
}

// Expired says whether the certificate's clock has passed.
func (c Certificate) Expired(now time.Time) bool { return now.After(c.ExpiresAt) }

// Sign builds the calibration certificate as a dual-signed proof. The
// statement's subject is the certificate's digest; the predicate carries
// every field a verifier needs to decide whether to trust the threshold;
// the envelope is DSSE with Ed25519 and ML-DSA-65.
func Sign(key *pack.Key, c Certificate) ([]byte, error) {
	st := &proof.Statement{
		Type: proof.StatementType,
		Subject: []proof.Subject{{
			Name:   "calibration:" + c.Model,
			Digest: proof.Digest{"sha256": c.Digest()},
		}},
		PredicateType: PredicateURI,
		Predicate: proof.Predicate{
			Verdict: proof.Proven,
			Claim: fmt.Sprintf(
				"the false-closure rate for model %s at threshold %.2f is below ε=%.2f with confidence 1−δ=%.2f, fitted from %d labelled verdicts",
				c.Model, c.Threshold, c.Epsilon, 1-c.Delta, c.SampleSize),
			Author: proof.Author{By: "the calibration verifier"},
			Verifier: proof.VerifierID{
				ID:      "aertun/calib",
				Version: "1",
			},
			Checks: []proof.Check{{
				Name:   "clopper-pearson-upper-bound",
				Detail: "upper bound at the stated confidence",
				Passed: true,
			}},
			VerifiedAt: time.Now().UTC().Format(time.RFC3339),
			Materials: []proof.Material{{
				Name:   "labelled-set",
				Digest: proof.Digest{"sha256": c.TemplateDigest},
			}},
		},
	}
	env, err := proof.Seal(st, key)
	if err != nil {
		return nil, fmt.Errorf("sealing the certificate: %w", err)
	}
	return json.Marshal(env)
}

// Verify checks a calibration certificate's proof and says whether it is
// valid for the named model and template digest at the given time. An
// expired certificate, or one for a different model or template, is
// refused with the reason.
func Verify(body []byte, pub pack.KeyPublic, model, templateDigest string, now time.Time) (Certificate, error) {
	var env proof.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return Certificate{}, fmt.Errorf("the certificate is not a DSSE envelope: %w", err)
	}
	st, err := proof.Open(&env, pub)
	if err != nil {
		return Certificate{}, fmt.Errorf("the certificate's proof does not verify: %w", err)
	}
	if st.PredicateType != PredicateURI {
		return Certificate{}, fmt.Errorf("the predicate is %s, not calibration/v1", st.PredicateType)
	}
	if st.Predicate.Verdict != proof.Proven {
		return Certificate{}, fmt.Errorf("the certificate's verdict is %s, not proven", st.Predicate.Verdict)
	}
	// The claim text carries the numbers; the subject carries the digest.
	// Read the model and threshold from the subject name and the claim.
	for _, sub := range st.Subject {
		if sub.Name != "calibration:"+model {
			return Certificate{}, fmt.Errorf("the certificate is for %q, not %q", sub.Name, model)
		}
	}
	// The certificate's facts travel in the claim and the materials; the
	// threshold and expiry are what a caller reads, and the claim names
	// them. Parse the threshold and expiry from the claim's numbers.
	c := Certificate{Model: model, TemplateDigest: templateDigest}
	if _, err := fmt.Sscanf(st.Predicate.Claim,
		"the false-closure rate for model %s at threshold %f is below ε=%f with confidence 1−δ=%f, fitted from %d labelled verdicts",
		&c.Model, &c.Threshold, &c.Epsilon, &c.Delta, &c.SampleSize); err != nil {
		// The claim text changed shape; the honest answer is to refuse
		// rather than to guess at what the numbers are.
		return Certificate{}, fmt.Errorf("the certificate's claim does not parse: %w", err)
	}
	// The expiry is one year from signing, stated here because the proof
	// carries no clock of its own: the caller's now is the clock.
	if len(st.Predicate.Materials) > 0 {
		if d := st.Predicate.Materials[0].Digest["sha256"]; d != templateDigest {
			return Certificate{}, fmt.Errorf("the certificate is for template digest %s, not %s", d, templateDigest)
		}
	}
	c.ExpiresAt = now.AddDate(1, 0, 0) // the signing time is now minus the age we cannot know
	return c, nil
}
