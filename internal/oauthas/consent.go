// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

// Package oauthas is AeroProve's authorization server: the smallest OAuth 2.1
// server that an AI agent's client can use honestly, and nothing more.
//
// # What it is, and what it refuses to be
//
// It implements exactly one flow: authorization code with PKCE (S256 only),
// client = a registered agent (internal/agentreg), client authentication =
// the DPoP key whose proof the token request carries (internal/dpop — a
// public client has no secret, and inventing one would be a secret nobody
// could keep), and one resource: /mcp. The person who approves is the person
// signed in to the console this server is mounted beside. Everything else an
// authorization server can do, this one answers with the spec's own error
// shapes rather than a silence a client might read as consent:
//
//   - no client-credentials grant. The store's own credentials already cover
//     what that grant is for — `aeroprove token issue` is the machine-to-machine
//     path, issued by an administrator to a named principal, revocable by id.
//     A second issuer of long-lived bearer tokens would be a second thing to
//     review, and nobody could say which one answered for what.
//   - no refresh tokens. A code is minutes-short and single-use; the durable
//     half of the design is the consent (which lives on, so the client asks
//     again and the person's answer still holds) and the run credential
//     (`aeroprove agent token`), which is the bounded thing an agent holds for a
//     working stretch. A refresh token would be a bearer credential with a
//     different name, outliving the very consent it was minted under.
//
// # Consent is the record, not the click
//
// The word "consent" in this package is a row in the register: who
// authorised which agent for which scope bundle, until when — listable by an
// administrator and revocable with one command (`aeroprove agent consents
// revoke` in cmd/aeroprove), and every token minted under it dies with it
// (auth.TokenStore.RevokeGrant). The screen the person clicks is how the row
// is made; the row is what the system enforces.
//
// # Honesty about scope
//
// A scope here is a bundle of the agent interface's tools under one word of
// the closed vocabulary the run credentials already use (internal/macaroon's
// purposes): observe reads, triage reads and proposes. There is no scope for
// anything this deployment cannot grant — no email, no profile, no offline —
// and the server's metadata says exactly the two words it means. An allowlist
// that accepted names nothing enforces would be a decoration; so would a
// metadata document advertising a grant it refuses.
//
// # Fail closed
//
// The registry decides who the client is: an unknown, unregistered or
// disabled agent is refused at /authorize, at /token, and again at the
// exchange, because the kill switch (docs/research/02-access-control.md
// §8.5) must reach a half-finished flow as surely as a finished one. No
// identity, no policy hook, no token store: each is refused rather than
// assumed empty.
package oauthas

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aeroprove/aeroprove/internal/agentreg"
	"github.com/aeroprove/aeroprove/internal/atomicfile"
	"github.com/aeroprove/aeroprove/internal/auth"
	"github.com/aeroprove/aeroprove/internal/macaroon"
)

// Bundle is one scope this server can grant: a word, the tools the word
// names, and the least authority those tools need.
//
// The words are macaroon's purposes rather than a second vocabulary, because
// a consent and a run credential that described the same reach with
// different words would be two labels for one fact — and the one place they
// meet (RFC 8693 exchange, where a run's caveats intersect a consent's
// bundle) is exactly where a third word for the same thing would go to be
// misread.
type Bundle struct {
	// Name is the scope word: observe or triage.
	Name string
	// Tools are the agent interface's tools the bundle names.
	Tools []string
	// Action is what the policy must grant the consenting person for the
	// bundle to mean anything: view for observe, triage for triage.
	Action auth.Action
	// Role is the least token role the tools need, and ReadOnly whether the
	// bundle writes nothing — the same pair the run-token mint derives
	// (cmd/aeroprove, issueRunToken), so a consented token and a run token with
	// the same word carry the same coarse bounds.
	Role     auth.Role
	ReadOnly bool
}

// bundles is the whole vocabulary. Two words because the interface has two
// behaviours: it reads, and it proposes. The day it can do more, a word is
// added here with its reach written beside it — not a scope string accepted
// unchecked.
var bundles = []Bundle{
	{
		Name: macaroon.PurposeObserve, Action: auth.ActView,
		Tools: []string{"aeroprove_find", "aeroprove_read"},
		Role:  auth.RoleViewer, ReadOnly: true,
	},
	{
		Name: macaroon.PurposeTriage, Action: auth.ActTriage,
		Tools: agentreg.Tools(),
		Role:  auth.RoleAnalyst,
	},
}

// Bundles lists the scope vocabulary, in order. A copy, so a caller cannot
// widen the set through it.
func Bundles() []Bundle {
	out := make([]Bundle, len(bundles))
	for i, b := range bundles {
		out[i] = b
		out[i].Tools = append([]string(nil), b.Tools...)
	}
	return out
}

// ScopesSupported is the words alone, for the metadata document.
func ScopesSupported() []string {
	out := make([]string, len(bundles))
	for i, b := range bundles {
		out[i] = b.Name
	}
	return out
}

// BundleFor is the bundle a scope word names, when it names one.
func BundleFor(scope string) (Bundle, bool) {
	for _, b := range bundles {
		if b.Name == scope {
			return b, true
		}
	}
	return Bundle{}, false
}

// Covers says whether an agent's registry allowlist holds every tool of the
// bundle: the whole bundle or none of it. A consent for half a bundle would
// be a consent whose word promised more than its token could do, and the
// narrowing belongs at the exchange, where a run credential's caveats are
// intersected with the consent — one place that narrows, rather than two
// that disagree.
func (b Bundle) Covers(allow []string) bool {
	for _, t := range b.Tools {
		found := false
		for _, a := range allow {
			if a == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// MaxConsentTTL is how long a consent may run: the same twelve hours a
// session may last, because a consent is the authorisation a family of
// short-lived tokens draws on, and nothing in this design should outlive a
// working day without a person looking at it again (`aeroprove agent consents`
// is the looking).
const MaxConsentTTL = 12 * time.Hour

// Consent is one person's answer to one agent's ask: the reviewable unit an
// administrator lists and revokes. The scope is one bundle word; the person
// is the principal who approved; the agent is the registry entry that asked.
type Consent struct {
	ID        string `json:"id"`
	Agent     string `json:"agent"`
	Scope     string `json:"scope"`
	Principal string `json:"principal"`
	ExpiresAt int64  `json:"expires_at"`

	// Revoked is set by the one command that ends a consent, keeping who
	// ended it and when, so the register reads as a decision rather than as
	// an absence.
	Revoked   bool   `json:"revoked,omitempty"`
	RevokedBy string `json:"revoked_by,omitempty"`
	RevokedAt int64  `json:"revoked_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// Until renders the expiry for a listing.
func (c Consent) Until() string {
	return time.Unix(c.ExpiresAt, 0).UTC().Format("2 Jan 2006 15:04")
}

// ErrNoConsent is a grant id no consent answers to.
type ErrNoConsent struct{ ID string }

func (e ErrNoConsent) Error() string {
	return fmt.Sprintf("there is no consent %q", e.ID)
}

// file is the stored document. A list, so the file reads in the order
// consents were given and diffs like a register rather than like a cache.
type file struct {
	Consents []Consent `json:"consents"`
}

// Store is the consent register as one JSON document at Path, changed whole
// under its lock (atomicfile), beside the policy and the registry it serves.
//
// The register records; it does not decide. Whether the agent is registered,
// whether the person holds what they are consenting to — those are the
// server's checks (it holds the registry and the policy), made before a row
// is written, so a row that exists is a row that was honoured at the moment
// it was made. What the register adds is the other half: the row outlives
// the click, is the thing an administrator reviews, and revoking it reaches
// every token minted under it.
type Store struct{ Path string }

// Load reads the register. An absent file is an empty register; a file that
// cannot be read is an error, because a register that silently forgot
// everybody is a register every token minted under it was minted on trust.
func (s Store) Load() ([]Consent, error) {
	b, err := os.ReadFile(s.Path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", s.Path, err)
	}
	return append([]Consent(nil), f.Consents...), nil
}

// Live is the consent a token's grant names, checked against the clock: the
// answer a mint needs. A consent that is gone is refused rather than
// narrowed, because what a revoked consent means was decided by whoever
// revoked it and is not this call's to revisit.
func (s Store) Live(id string, now time.Time) (Consent, error) {
	all, err := s.Load()
	if err != nil {
		return Consent{}, err
	}
	for _, c := range all {
		if c.ID != id {
			continue
		}
		switch {
		case c.Revoked:
			return Consent{}, fmt.Errorf("consent %s was revoked by %s", c.ID, c.RevokedBy)
		case now.Unix() >= c.ExpiresAt:
			return Consent{}, fmt.Errorf("consent %s ended at %s", c.ID,
				time.Unix(c.ExpiresAt, 0).UTC().Format(time.RFC3339))
		}
		return c, nil
	}
	return Consent{}, ErrNoConsent{ID: id}
}

// NewID is a consent's identifier: 12 hex of the CSPRNG, enough to name a
// row in a register and short enough to type into `aeroprove agent consents
// revoke`. Minted here so every consent gets it the same way.
func NewID() (string, error) {
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("cannot generate a consent id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// Record writes a consent. The caller has made the decisions (registry,
// policy, bundle); this refuses a row that could not be read back — no id,
// no agent, no scope word, no person, a duplicate id — so the register never
// holds a row that means nothing. Expiry is capped at MaxConsentTTL from now
// whatever the caller passed: the cap is the design's, not a parameter.
func (s Store) Record(c Consent, now time.Time) error {
	if c.ID == "" {
		return fmt.Errorf("a consent needs the id NewID minted for it")
	}
	if !agentreg.ValidName(c.Agent) {
		return fmt.Errorf("%q is not an agent name the registry could hold", c.Agent)
	}
	if _, ok := BundleFor(c.Scope); !ok {
		return fmt.Errorf("%q is not a scope this server grants; the words are %s",
			c.Scope, strings.Join(ScopesSupported(), " and "))
	}
	if strings.TrimSpace(c.Principal) == "" {
		return fmt.Errorf("a consent names the person who gave it")
	}
	c.CreatedAt = now
	c.ExpiresAt = now.Add(MaxConsentTTL).Unix()
	c.Revoked, c.RevokedBy, c.RevokedAt = false, "", 0
	return atomicfile.Update(s.Path, func(f *file) error {
		for _, x := range f.Consents {
			if x.ID == c.ID {
				return fmt.Errorf("there is already a consent %s", c.ID)
			}
		}
		f.Consents = append(f.Consents, c)
		return nil
	})
}

// Revoke ends a consent. The tokens minted under it are the token store's to
// revoke, not this register's: the command that owns both halves does them
// as one act, the same shape the agent kill switch takes (registry entry and
// credentials, together or loudly not).
func (s Store) Revoke(id, by string, now time.Time) (Consent, error) {
	var out Consent
	err := atomicfile.Update(s.Path, func(f *file) error {
		for i := range f.Consents {
			if f.Consents[i].ID != id {
				continue
			}
			if f.Consents[i].Revoked {
				return fmt.Errorf("consent %s is already revoked", id)
			}
			f.Consents[i].Revoked = true
			f.Consents[i].RevokedBy = by
			f.Consents[i].RevokedAt = now.Unix()
			out = f.Consents[i]
			return nil
		}
		return ErrNoConsent{ID: id}
	})
	if err != nil {
		return Consent{}, err
	}
	return out, nil
}

// Sorted is the register as a listing reads it: live consents first, newest
// first, then the revoked and expired — the review's question is "who may
// what now", and the answer to it should not scroll past the history.
func Sorted(all []Consent) []Consent {
	out := append([]Consent(nil), all...)
	sort.SliceStable(out, func(i, j int) bool {
		live := func(c Consent) bool { return !c.Revoked }
		if live(out[i]) != live(out[j]) {
			return live(out[i])
		}
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}
