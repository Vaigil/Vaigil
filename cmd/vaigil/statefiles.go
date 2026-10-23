// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"time"

	"github.com/quilzo/vaigil/internal/atomicfile"
	"github.com/quilzo/vaigil/internal/auth"
)

// The state files where a lost write undoes a security decision: who may
// do what, and which credentials are live. Each is changed under its lock,
// on what is stored at that moment (atomicfile.Update), rather than loaded
// early and written back whole later.

// updatePolicy changes the access policy as it is stored now, and returns
// it as it was written.
func updatePolicy(root string, change func(*auth.Policy) error) (*auth.Policy, error) {
	var out *auth.Policy
	err := atomicfile.Update(policyPath(root), func(p *auth.Policy) error {
		out = p
		return change(p)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// saveTokens writes a token store merged with the one stored now, so a
// token added or revoked elsewhere since ts was read is neither lost nor
// brought back (auth.TokenStore.MergeInto).
func saveTokens(root string, ts *auth.TokenStore) error {
	return atomicfile.Update(tokensPath(root), func(stored *auth.TokenStore) error {
		ts.MergeInto(stored, time.Now())
		return nil
	})
}
