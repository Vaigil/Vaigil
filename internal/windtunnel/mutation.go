// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Mutation mode: effect-preserving variants of a scenario's events,
// replayed against the rules and scored as miss rate under mutation.
//
// A detection that fires on the exact bytes a scenario emitted is not a
// detection — it is a fixture for that scenario. The mutations change the
// bytes that do not matter (field order is already canonical, so: case in
// quoted strings where the rule folds case, decimal forms of numbers where
// the field is a string, padding the JSON with harmless whitespace, timing
// within the window) and leave the bytes the rules need (the fields the
// scored expectations read) untouched. A rule that fires on the original
// and misses under mutation was matching on surface, not on effect — which
// is exactly what mutation scoring measures.

package windtunnel

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/telemetry"
)

// Mutation is one effect-preserving change to a telemetry event.
type Mutation struct {
	// Name is what the scorecard reports.
	Name string
	// Apply returns the mutated event. It must not change the fields the
	// rule engine's equals/prefix/contains operators read on the scored
	// expectation's technique path — those are the effect. It may change
	// anything else: the actor's value case, the entity's padding, the
	// message's trailing whitespace, the raw map's non-effect keys.
	Apply func(e telemetry.Event) telemetry.Event
}

// mutations is the closed set. New mutations go here, with a test that
// proves they preserve effect on the shipped scenarios.
var mutations = []Mutation{
	{
		Name: "actor-case",
		// The actor's value case changes where the value is alphabetic:
		// the identity is the same identity, and rules comparing it with
		// EqualFold still match, while a rule that matches on exact case
		// was matching surface.
		Apply: func(e telemetry.Event) telemetry.Event {
			if !idHasAlphabetic(e.Actor) {
				return e
			}
			e.Actor.Value = swapCase(e.Actor.Value)
			return e
		},
	},
	{
		Name: "entity-case",
		Apply: func(e telemetry.Event) telemetry.Event {
			if !idHasAlphabetic(e.Target) {
				return e
			}
			e.Target.Value = swapCase(e.Target.Value)
			return e
		},
	},
	{
		Name: "raw-pad",
		// A new raw field that carries no rule meaning, because the pack's
		// rules name the fields they read and nothing reads raw.mut.
		Apply: func(e telemetry.Event) telemetry.Event {
			// Copy the raw map rather than writing into it: maps are
			// reference types, and a mutation that writes into the
			// caller's map would change the original event too.
			raw := make(map[string]string, len(e.Raw)+1)
			for k, v := range e.Raw {
				raw[k] = v
			}
			raw["mut"] = randomToken()
			e.Raw = raw
			return e
		},
	},
}

// Mutations returns the names of every mutation this mode applies, for the
// scorecard's report.
func Mutations() []string {
	out := make([]string, len(mutations))
	for i, m := range mutations {
		out[i] = m.Name
	}
	return out
}

// Mutate returns the event with every mutation applied in order.
func Mutate(e telemetry.Event) telemetry.Event {
	for _, m := range mutations {
		e = m.Apply(e)
	}
	return e
}

// MutatedPlace is Place for mutation scoring: the scenario's events,
// every event mutated, on the same base stream, with the same seed and
// anchor. The placement is deterministic, so a mutated run differs from
// the original only in the mutations.
func MutatedPlace(sc *Scenario, steps []Step, base []telemetry.Event,
	seed int64, anchor time.Time) (*Placed, error) {

	original, err := Place(sc, steps, base, seed, anchor)
	if err != nil {
		return nil, err
	}
	for i, e := range original.Events {
		original.Events[i] = Mutate(e)
	}
	return original, nil
}

// idHasAlphabetic says whether the identity's value carries a letter the
// case swap can change.
func idHasAlphabetic(id telemetry.ID) bool {
	for _, r := range id.Value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

// swapCase flips the case of alphabetic ASCII characters, leaving digits
// and punctuation alone — an identity whose value is a UUID is unaffected.
func swapCase(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			r = r - 'a' + 'A'
		case r >= 'A' && r <= 'Z':
			r = r - 'A' + 'a'
		}
		b.WriteRune(r)
	}
	return b.String()
}

func randomToken() string {
	b := make([]byte, 12)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
