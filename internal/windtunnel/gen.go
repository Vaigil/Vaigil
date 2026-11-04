// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/aeroprove/aeroprove/internal/telemetry"
)

// The binding generators: Caldera's fact system with the interpreter
// removed. Each is an enumerated function in this one file, seeded and
// deterministic — no clock, no environment, no network — so the same scenario
// bytes plus the same seed give the same session identity on every machine,
// which is what makes a scorecard's scenario digests worth recording (the
// generate.go rule: two runs of the program produce byte-identical corpora).
//
// The drawn values sit in ranges deliberately disjoint from anything a real
// stream carries: generated agent names carry the wt- prefix and generated
// trace ids the ff- byte, so an overlap with recorded traffic is a finding
// about the recording, not a silent join — and preflight refuses it anyway.

// The closed generator set.
const (
	// GenAgentName draws a session agent name, "wt-" plus six hex.
	GenAgentName = "agent-name"
	// GenTraceID draws a 32-hex trace id whose first byte is ff — a range no
	// live SDK is issued, so the session cannot collide with recorded traces.
	GenTraceID = "trace-id"
	// GenDestCanary draws a destination from the canary list below.
	GenDestCanary = "dest-canary"
)

// Gens is every generator, for the refusal message that lists them.
func Gens() []string {
	return []string{GenAgentName, GenTraceID, GenDestCanary}
}

func genKnown(g string) bool {
	for _, k := range Gens() {
		if k == g {
			return true
		}
	}
	return false
}

// canaries are the destinations GenDestCanary draws from: reserved TLDs and
// internal hosts only, every one a name that cannot resolve into somebody's
// production. The list is short on purpose — a canary list nobody can read
// at a glance is not a canary list.
var canaries = []string{
	"https://canary.example.internal/hook",
	"https://windtunnel.example.test/exfil",
	"https://collector.example.invalid/beam",
}

// Generate draws one binding value: generator, seed, index. The index lets a
// generator serve a family of draws (the lateness sampler uses the same
// recipe with its own name) without any mutable state — the nth draw is a
// pure function, so an expansion can be replayed byte for byte from its
// inputs alone.
func Generate(gen string, seed int64, i int) (string, error) {
	switch gen {
	case GenAgentName:
		return "wt-" + draw(gen, seed, i, 3), nil
	case GenTraceID:
		// The first byte is forced to ff — the disjoint range — and the
		// remaining fifteen come from the draw.
		return "ff" + draw(gen, seed, i, 15), nil
	case GenDestCanary:
		b := drawBytes(gen, seed, i)
		return canaries[int(b[0])%len(canaries)], nil
	}
	return "", fmt.Errorf("%q is not a generator; the closed set is %s", gen,
		strings.Join(Gens(), ", "))
}

// draw is n bytes of deterministic entropy as hex (two characters each).
func draw(gen string, seed int64, i int, n int) string {
	b := drawBytes(gen, seed, i)
	return hex.EncodeToString(b[:n])
}

// drawBytes is the entropy itself: sha256 over the generator's name, the
// seed and the index. Every generator shares it because there is nothing to
// be gained from two hashes and one fewer place to get determinism wrong.
func drawBytes(gen string, seed int64, i int) [32]byte {
	h := sha256.New()
	h.Write([]byte(gen))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(seed, 10)))
	h.Write([]byte{0})
	h.Write([]byte(strconv.Itoa(i)))
	return [32]byte(h.Sum(nil))
}

// Expand resolves a scenario's binding table to its values. Deterministic:
// the values depend only on the file, so a scenario's session identity is
// stable across runs and seeds — the seed moves the clocks, never the
// session.
func Expand(sc *Scenario) (map[string]string, error) {
	out := make(map[string]string, len(sc.Bindings))
	for _, name := range sc.SortedBindingNames() {
		b := sc.Bindings[name]
		if b.Value != "" {
			out[name] = b.Value
			continue
		}
		v, err := Generate(b.Gen, b.Seed, 0)
		if err != nil {
			return nil, fmt.Errorf("%s: binding %q: %w", sc.ID, name, err)
		}
		out[name] = v
	}
	return out, nil
}

// Substitute resolves every ${name} in an event's string slots against the
// binding values. The same walk validateEmit checks, so a value that passes
// validation always resolves and a value that resolves always passed.
func Substitute(e telemetry.Event, values map[string]string) telemetry.Event {
	sub := func(s string) string {
		return placeholder.ReplaceAllStringFunc(s, func(m string) string {
			name := placeholder.FindStringSubmatch(m)[1]
			if v, ok := values[name]; ok {
				return v
			}
			return m
		})
	}
	e.Message = sub(e.Message)
	e.Actor = subID(e.Actor, values)
	e.Target = subID(e.Target, values)
	e.Device = subID(e.Device, values)
	if len(e.Raw) > 0 {
		raw := make(map[string]string, len(e.Raw))
		for k, v := range e.Raw {
			raw[k] = sub(v)
		}
		e.Raw = raw
	}
	if len(e.Observables) > 0 {
		obs := make([]telemetry.Observable, len(e.Observables))
		for i, o := range e.Observables {
			o.Value = sub(o.Value)
			obs[i] = o
		}
		e.Observables = obs
	}
	return e
}

func subID(id telemetry.ID, values map[string]string) telemetry.ID {
	if id.Issuer != "" {
		id.Issuer = sub1(id.Issuer, values)
	}
	if id.Value != "" {
		id.Value = sub1(id.Value, values)
	}
	return id
}

func sub1(s string, values map[string]string) string {
	return placeholder.ReplaceAllStringFunc(s, func(m string) string {
		name := placeholder.FindStringSubmatch(m)[1]
		if v, ok := values[name]; ok {
			return v
		}
		return m
	})
}
