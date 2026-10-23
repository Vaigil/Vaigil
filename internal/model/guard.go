// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"

	"github.com/vaigil/vaigil/internal/pii"
	"github.com/vaigil/vaigil/internal/plaintext"
	"github.com/vaigil/vaigil/internal/secret"
)

// Guarded is a model behind a privacy guard: what may not leave is masked
// before the prompt does, and put back in the answer. What draws nothing is
// taken out first, so text nobody could read on a screen is not sent to a
// model either (internal/plaintext).
type Guarded struct {
	Model Model
	// Personal says it may receive personal data.
	Personal   bool
	OwnDomains []string
	OnMasked   func(counts map[string]int)
}

func (g Guarded) Name() string { return g.Model.Name() }

func (g Guarded) Complete(ctx context.Context, system, user string) (string, error) {
	out, _, err := g.CompleteMetered(ctx, system, user)
	return out, err
}

func (g Guarded) CompleteMetered(ctx context.Context, system, user string) (string, Usage, error) {
	mask := &pii.Masker{Allowed: g.OwnDomains, Secrets: secret.Spans}
	sys, a := plaintext.Visible(system)
	usr, b := plaintext.Visible(user)
	sys, usr = mask.Mask(sys, g.Personal), mask.Mask(usr, g.Personal)
	var out string
	var used Usage
	var err error
	if mm, ok := g.Model.(Metered); ok {
		out, used, err = mm.CompleteMetered(ctx, sys, usr)
	} else {
		out, err = g.Model.Complete(ctx, sys, usr)
		used = Estimate(sys+usr, out)
	}
	counts := mask.Masked()
	if a+b > 0 {
		counts["invisible"] = a + b
	}
	if len(counts) > 0 && g.OnMasked != nil {
		g.OnMasked(counts)
	}
	return mask.Restore(out), used, err
}
