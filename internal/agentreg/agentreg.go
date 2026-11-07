// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package agentreg is the registry of the AI agents this organisation runs.
//
// Before this existed the answer to "which agents hold access today, and who
// owns each one" was a shrug: a token in a file somewhere, acting as a
// principal the policy had granted, recorded in the log under the generic
// mcp-client. Nothing could be reviewed because nothing was enumerated, and
// nothing could be killed except by hunting credentials one at a time. SP
// 800-53 calls the first half IA-9 (services are identified and registered)
// and the second half AC-2 (accounts are managed, reviewed, and disableable)
// — and an agent with access is an account, whatever it runs on.
//
// The registry is deliberately the whole of the agent's identity in this
// phase, and it is small on purpose: a name, an owner who is a person, the
// tools it may call, a status, and who decided each of those things and
// when. Delegation chains, caveat tokens and per-operation scopes are later
// phases of the same design; none of
// them can be built on top of a registry that does not exist.
//
// # Binding to credentials
//
// An agent entry binds to tokens by a naming convention: a token issued as
// agent:NAME identifies as that agent (Bind). The convention is weak in the
// way the token-kind heuristic in cmd/aertun/caller.go is weak and is said
// out loud there — it is a claim the registry then has to honour or refuse,
// not a proof. What makes it safe is the direction of the failure: a token
// claiming an agent name is refused by every gate until a registry row says
// otherwise, so minting an agent:-prefixed name grants nothing by itself.
//
// # Fail closed
//
// Absent means refused. No registry file, no entry for a name, an unreadable
// file — each leaves the caller with no authority it did not already have as
// a plain credential, and the enforcement in cmd/aertun refuses the agent
// outright. An unregistered agent is nobody.
package agentreg

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/atomicfile"
)

// TokenPrefix is what a token's name begins with when it was issued to a
// registered agent: "agent:watcher" identifies as the agent "watcher".
//
// A prefix on the token name rather than a new field on the token record,
// because `aertun token issue` is the one path that mints credentials and it
// needs no change: the name the operator already chooses becomes the binding.
// The cost is that the convention is a string, so Bind validates nothing —
// the registry does the deciding.
const TokenPrefix = "agent:"

// tools is the closed set an entry may allow: the three tools the agent
// interface serves (internal/mcp). Anything else named at add time is
// refused, because an allowlist that accepted names nothing enforces would
// be a decoration — an agent "allowed" a tool that does not exist has been
// granted a permission nobody checks the meaning of.
var tools = []string{"aertun_find", "aertun_read", "aertun_write"}

// Tools lists what an entry may allow, in the order the interface presents
// them. A copy, so a caller cannot widen the set through it.
func Tools() []string {
	return append([]string(nil), tools...)
}

// ValidTool says whether t is one of the agent interface's tools.
func ValidTool(t string) bool {
	for _, x := range tools {
		if t == x {
			return true
		}
	}
	return false
}

// ValidName is the shape of an agent's name: 2 to 40 lowercase letters,
// digits and hyphens, not starting with a hyphen. The same shape as a feed's
// name (internal/inbound), because both become part of a token name and part
// of an audit resource, and both are typed by a person under pressure.
func ValidName(s string) bool {
	if len(s) < 2 || len(s) > 40 {
		return false
	}
	for i, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' && i > 0) {
			return false
		}
	}
	return true
}

// Bind is the agent a token name claims, and whether it claims one at all.
//
// Whatever follows the prefix is returned as claimed, valid or not: the
// registry decides whether the claim names anybody, and a name that could
// not have been registered never will. A token named exactly "agent:" claims
// nothing — there is no name after the colon — and behaves as the plain
// credential it is, which is today's behaviour and the honest reading of a
// name that says nothing.
func Bind(tokenName string) (string, bool) {
	name, ok := strings.CutPrefix(tokenName, TokenPrefix)
	if !ok || name == "" {
		return "", false
	}
	return name, true
}

// Status is whether an entry's agent may act. Two states, not three: a
// "revoked" state that kept the row forever while adding nothing over
// disabled-plus-a-note is a distinction for a later phase, and a status
// nobody can set is a status nobody will trust.
type Status string

const (
	Active   Status = "active"
	Disabled Status = "disabled"
)

// Agent is one registered agent: the reviewable unit IA-9 asks for.
type Agent struct {
	Name   string   `json:"name"`
	Owner  string   `json:"owner"`
	Status Status   `json:"status"`
	Allow  []string `json:"allow,omitempty"`

	// Note is whatever the registering admin wanted on record about why
	// this agent exists. Free text, shown by `agent list`.
	Note string `json:"note,omitempty"`

	// DisabledWhy is the reason the kill switch was pulled, kept so the
	// review — and whoever decides whether to enable the agent again —
	// reads what the responder said, not a paraphrase of it.
	DisabledWhy string    `json:"disabled_why,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	ChangedAt   time.Time `json:"changed_at"`
	ChangedBy   string    `json:"changed_by"`
}

// MayUse says whether the entry allows a tool of the agent interface.
// An absent allowlist allows nothing; absence is not "everything".
func (a Agent) MayUse(tool string) bool {
	for _, t := range a.Allow {
		if t == tool {
			return true
		}
	}
	return false
}

// file is the stored document. A list rather than a map so the file reads in
// a stable order and diffs like a register rather than like a cache.
type file struct {
	Agents []Agent `json:"agents"`
}

// Store is the registry as one JSON document at Path, changed whole under
// its lock (atomicfile): a disable that read the file before an allow was
// added must not write the allow away.
type Store struct{ Path string }

// Load reads the registry. An absent file is an empty registry, which is the
// fail-closed answer to "is this agent registered": no.
func (s Store) Load() ([]Agent, error) {
	b, err := os.ReadFile(s.Path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		// Unreadable is not empty. An entry that cannot be read cannot be
		// reviewed, so the caller is told rather than left with a registry
		// that silently forgot everybody — the same line the policy draws
		// (cmd/aertun policyInUse): present-and-broken means refuse.
		return nil, fmt.Errorf("%s: %w", s.Path, err)
	}
	out := append([]Agent(nil), f.Agents...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Get returns one entry by name.
func (s Store) Get(name string) (Agent, bool, error) {
	agents, err := s.Load()
	if err != nil {
		return Agent{}, false, err
	}
	for _, a := range agents {
		if a.Name == name {
			return a, true, nil
		}
	}
	return Agent{}, false, nil
}

// find returns the entry's place in the file, or -1.
func (f *file) find(name string) int {
	for i := range f.Agents {
		if f.Agents[i].Name == name {
			return i
		}
	}
	return -1
}

// Add registers an agent. Everything about the entry that is not a decision
// (name, owner, allowlist, note) is the caller's; the rest is set here so no
// two call sites can disagree about what "created" means.
//
// Refuses a name that could not be looked up again, a duplicate, an owner
// nobody could ask about, and any tool the agent interface does not serve.
func (s Store) Add(a Agent, now time.Time) error {
	return atomicfile.Update(s.Path, func(f *file) error {
		if !ValidName(a.Name) {
			return fmt.Errorf("%q is not an agent name: 2 to 40 lowercase letters, digits and hyphens", a.Name)
		}
		if f.find(a.Name) >= 0 {
			return fmt.Errorf("there is already an agent %q", a.Name)
		}
		if strings.TrimSpace(a.Owner) == "" {
			return fmt.Errorf("an agent needs an owner: a person who answers for what it does")
		}
		allow, err := cleanTools(a.Allow)
		if err != nil {
			return err
		}
		if len(allow) == 0 {
			return fmt.Errorf("an agent is registered with at least one of %s; one allowed nothing has nothing to register for",
				strings.Join(tools, ", "))
		}
		f.Agents = append(f.Agents, Agent{
			Name: a.Name, Owner: strings.TrimSpace(a.Owner),
			Status: Active, Allow: allow, Note: a.Note,
			CreatedAt: now, CreatedBy: a.CreatedBy,
			ChangedAt: now, ChangedBy: a.CreatedBy,
		})
		return nil
	})
}

// Disable pulls the kill switch for one agent, keeping the reason it was
// pulled. The entry stays — the review object is the register, and a
// disabled agent nobody can see is one nobody can ask about.
//
// Revoking the agent's tokens is the other half of the kill and is done by
// the command (cmd/aertun) in the same action, not here: the registry knows
// who the agent is and the token store is where the credentials live.
func (s Store) Disable(name, why, by string, now time.Time) error {
	return atomicfile.Update(s.Path, func(f *file) error {
		i := f.find(name)
		if i < 0 {
			return fmt.Errorf("there is no agent %q (aertun agent list)", name)
		}
		if f.Agents[i].Status == Disabled {
			// Refused rather than quiet, for the same reason revoking a
			// revoked token is: an operator told "done" twice may believe a
			// second agent was killed when the first was named again.
			return fmt.Errorf("agent %q is already disabled", name)
		}
		f.Agents[i].Status = Disabled
		f.Agents[i].DisabledWhy = why
		f.Agents[i].ChangedAt, f.Agents[i].ChangedBy = now, by
		return nil
	})
}

// Enable restores a disabled agent. Issuing it a fresh credential is not
// done here and not done by `agent enable`: disable revoked the tokens it
// had, and whether it gets new ones is its owner's separate decision to ask
// for — restoring the registry row restores the agent's authority, not the
// bearer credential somebody may already hold a copy of.
func (s Store) Enable(name, by string, now time.Time) error {
	return atomicfile.Update(s.Path, func(f *file) error {
		i := f.find(name)
		if i < 0 {
			return fmt.Errorf("there is no agent %q (aertun agent list)", name)
		}
		if f.Agents[i].Status != Disabled {
			return fmt.Errorf("agent %q is not disabled", name)
		}
		f.Agents[i].Status = Active
		f.Agents[i].ChangedAt, f.Agents[i].ChangedBy = now, by
		return nil
	})
}

// Allow adds or removes tools from an entry's allowlist. Removing is as
// real as adding — an agent whose last tool is removed stays registered and
// active, and the agent interface refuses it everything, which is a
// narrower leash than disable for an agent that must keep running for its
// owner to be told why.
func (s Store) Allow(name string, add, remove []string, by string, now time.Time) error {
	return atomicfile.Update(s.Path, func(f *file) error {
		i := f.find(name)
		if i < 0 {
			return fmt.Errorf("there is no agent %q (aertun agent list)", name)
		}
		add, err := cleanTools(add)
		if err != nil {
			return err
		}
		remove, err = cleanTools(remove)
		if err != nil {
			return err
		}
		for _, t := range add {
			if contains(remove, t) {
				return fmt.Errorf("%s is both added and removed; say one or the other", t)
			}
		}
		allow := append([]string(nil), f.Agents[i].Allow...)
		for _, t := range add {
			if !contains(allow, t) {
				allow = append(allow, t)
			}
		}
		for _, t := range remove {
			allow = drop(allow, t)
		}
		sort.Strings(allow)
		f.Agents[i].Allow = allow
		f.Agents[i].ChangedAt, f.Agents[i].ChangedBy = now, by
		return nil
	})
}

// cleanTools validates a caller-supplied tool list: each must be one the
// interface serves, and the answer is sorted with duplicates folded so the
// stored allowlist has one shape however it was typed.
func cleanTools(in []string) ([]string, error) {
	var out []string
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !ValidTool(t) {
			return nil, fmt.Errorf("%q is not a tool the agent interface serves; the tools are %s",
				t, strings.Join(tools, ", "))
		}
		if !contains(out, t) {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out, nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func drop(list []string, v string) []string {
	out := list[:0:0]
	for _, s := range list {
		if s != v {
			out = append(out, s)
		}
	}
	return out
}
