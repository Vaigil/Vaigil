// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package config

import "fmt"

// NIST mode: the compliance profile that turns the weakening floors from
// "allowed with a reason and a second administrator" into "not while this is
// on".
//
// The configuration model this package implements has one deliberate shape:
// nothing is forbidden and nothing is quiet. A value weaker than a setting's
// floor is allowed, needs a reason, is recorded, lapses after ninety days,
// and is reported until it is changed back. That is the right default, and it
// is not the right answer for a deployment that must hold a baseline — an
// assessor reading against SP 800-53 does not want to know that somebody had
// a reason; they want to know the floor held.
//
// So the profile is one setting, and what it changes is one branch: while it
// is on, the same IsWeaker predicate that would route a value through
// acceptance and dual control refuses it instead. Two properties follow from
// reusing that predicate rather than writing a second list, and both are the
// point:
//
//   - The settings the mode governs are exactly the settings whose weakening
//     already needed a second administrator — the list cannot drift from the
//     machinery it tightens, because it is the machinery.
//   - A setting with no floor is untouched. The mode tightens the settings
//     with a security dimension and leaves page preferences alone, the same
//     line the acceptance path already draws.
//
// The mode does not lock itself on. Turning it off is a plain recorded
// change: a profile that could not be left would be a rubber stamp the first
// time an organisation needed to leave it, and the audit chain — where every
// on and off lands — is the record an assessor actually wants.
//
// The caps the profile is named for need nothing from it. A console session
// nobody is using ends after an hour and after fifteen minutes for anybody
// who can grant access, at hard bounds no reason steps outside, for every
// deployment of this program; the mode says so on the Compliance screen
// rather than implying it added them.

// NISTModeKey is the setting that switches the NIST compliance profile on.
// Declared in the settings table like every other knob, so it is listed,
// explained and audited by the same surfaces.
const NISTModeKey = "compliance.nist_mode"

// ErrNISTMode is a value refused because the NIST compliance profile is on.
//
// A distinct type rather than a string so the settings screen and the command
// line can carry the refusal whole, and a future caller cannot flatten it
// into "invalid value" — which is the message somebody reads as "cannot",
// when the true message is "not while the mode is on".
type ErrNISTMode struct {
	Key, Value, Why string
}

func (e *ErrNISTMode) Error() string {
	return fmt.Sprintf(
		"%s = %s gives up security — %s — and NIST mode is on. While the "+
			"mode holds, nothing is weakened: no reason accepts this and no "+
			"second administrator can approve it. Turn %s off first, which is "+
			"itself a recorded change, or set a value the floor allows.",
		e.Key, e.Value, e.Why, NISTModeKey)
}

// nistRefusal is the guard: the value a setting's floor calls weaker,
// refused while the NIST compliance profile is on.
//
// Called from Set and Put after Validate, so a value that cannot parse never
// reaches it and a value inside its bounds can still be outside the profile.
// Every write path goes through one of those two, which is what makes the
// floor a floor: the command line, the settings screen and an approved
// dual-control change are refused alike.
func nistRefusal(c *Config, s Setting, value string) error {
	if !c.Bool(NISTModeKey) {
		return nil
	}
	if weaker, why := s.IsWeaker(value); weaker {
		return &ErrNISTMode{Key: s.Key, Value: value, Why: why}
	}
	return nil
}

// NISTGoverned lists the settings the NIST compliance profile holds floors
// on: the settings with a weakening floor at all, keys only, in declaration
// order. The Compliance screen shows this list, because a profile that
// refused things without saying what it holds is a lock, not a control.
func NISTGoverned() []string {
	var out []string
	for _, s := range settings {
		if s.Weaker != nil {
			out = append(out, s.Key)
		}
	}
	return out
}
