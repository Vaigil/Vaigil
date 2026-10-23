// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// Poster is the transport a notice is posted over.
type Poster interface {
	Post(url string, body []byte, headers map[string]string) (int, error)
}

// Tolerance is how far a delivery's timestamp may be from the receiver's clock.
//
// Five minutes: wide enough for ordinary drift between two machines, narrow
// enough that a captured request is useless by the time anybody replays it.
const Tolerance = 5 * time.Minute

// Sign produces the signature header for a body at a time.
//
// The construction is length-prefixed rather than a plain concatenation. With
// `HMAC(secret, timestamp + body)` an attacker can move the boundary between
// the two — a longer timestamp absorbing the first bytes of the body produces
// the same input and therefore the same digest, so a signature valid for one
// pair is valid for another. Prefixing each field with its length removes the
// ambiguity instead of relying on the fields never being attacker-influenced.
func Sign(secret string, at time.Time, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	ts := strconv.FormatInt(at.Unix(), 10)

	writeField(mac, []byte(ts))
	writeField(mac, body)
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}

func writeField(w interface{ Write([]byte) (int, error) }, b []byte) {
	var n [8]byte
	l := uint64(len(b))
	for i := range 8 {
		n[7-i] = byte(l >> (8 * i))
	}
	_, _ = w.Write(n[:])
	_, _ = w.Write(b)
}

// Verify checks a signature, which is what a receiver runs.
//
// Exported because a receiver written against this needs the same construction,
// and shipping the verifier is the difference between a documented scheme and
// one everybody implements slightly differently.
func Verify(secret, signature string, at time.Time, body []byte,
	now time.Time) error {

	// The window is checked first and separately. Checking the signature first
	// would mean a replayed request with a valid signature takes the same path
	// as a fresh one until the very end, and the two deserve different
	// answers — one is an old message, the other is a forgery.
	drift := now.Sub(at)
	if drift < 0 {
		drift = -drift
	}
	if drift > Tolerance {
		return fmt.Errorf(
			"this delivery is timestamped %s away from now, past the %s window. "+
				"A captured request replayed later has a signature that still "+
				"verifies; the timestamp is what stops it",
			drift.Round(time.Second), Tolerance)
	}

	want := Sign(secret, at, body)
	// Constant time, because a comparison that returns early leaks how much of
	// the signature was right, and enough of those leak the whole thing.
	if subtle.ConstantTimeCompare([]byte(want), []byte(signature)) != 1 {
		return fmt.Errorf("the signature does not match")
	}
	return nil
}
