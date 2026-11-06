// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"strings"
	"testing"
)

// NIST mode holds the weakening floors. Each test here is one way the guard
// could have been written that would make it not a guard: refusing only the
// command line, refusing only some of the governed settings, refusing without
// saying whose floor was held, or locking the mode on so that leaving it
// needed a hand-edited file.

// nistOn is a configuration with the profile switched on, the way an
// administrator switches it: through Set, so the guard is exercised on the
// way in as well.
func nistOn(t *testing.T) *Config {
	t.Helper()
	c := New()
	if err := c.Set(NISTModeKey, "true", "", "test"); err != nil {
		t.Fatalf("switching NIST mode on was refused: %v", err)
	}
	return c
}

// TestNISTModeRefusesWeakerOnEveryGovernedSetting walks the whole governed
// list. A guard that covered the settings somebody thought of — the token
// lives, say — and left the disclosure switches or the proxy ranges alone
// would pass a test that only tried the settings somebody thought of, so the
// table is generated from the floors themselves and the weaker values are
// written per setting, because "weaker" is not a direction a test can turn.
func TestNISTModeRefusesWeakerOnEveryGovernedSetting(t *testing.T) {
	weaker := map[string]string{
		"token.ttl.default":         "3600h", // 150 days: a leaked token outlives a quarter
		"token.ttl.max":             "8800h", // past a year
		"token.api.ttl.default":     "48h",   // an API token living two days
		"session.max":               "10h",   // a sign-in outliving a working day
		"network.trusted_proxies":   "0.0.0.0/0",
		"siem.stream.allow_remote":  "true",
		"siem.stream.reveal":        "true",
		"ssf.transmit.allow_remote": "true",
	}
	governed := NISTGoverned()
	if len(governed) == 0 {
		t.Fatal("NIST mode governs nothing; the floors have gone missing")
	}
	if len(governed) != len(weaker) {
		t.Fatalf("the mode governs %d settings and the table knows %d. The "+
			"list and the test must name the same settings, or a new floor "+
			"ships untested", len(governed), len(weaker))
	}
	for _, key := range governed {
		value, ok := weaker[key]
		if !ok {
			t.Errorf("%s is governed and no weaker value for it is written "+
				"here; add one, because a floor never tried is a floor never "+
				"checked", key)
			continue
		}
		s, ok := Lookup(key)
		if !ok {
			t.Fatalf("%s is not a setting", key)
		}
		if w, _ := s.IsWeaker(value); !w {
			t.Errorf("%s = %s was written as the weaker value and the floor "+
				"does not call it weaker; the test has drifted from the "+
				"setting", key, value)
			continue
		}
		c := nistOn(t)
		// With a reason, because the mode's claim is that no reason accepts
		// this; without one the refusal could be the ordinary acceptance
		// path wearing the mode's name.
		err := c.Set(key, value, "assessor approved", "test")
		if err == nil {
			t.Errorf("%s = %s was saved while NIST mode was on", key, value)
			continue
		}
		var refused *ErrNISTMode
		if !errors.As(err, &refused) {
			t.Errorf("%s was refused with %v, which is not the mode's "+
				"refusal; the acceptance path ran as though the mode were off",
				key, err)
			continue
		}
		if refused.Key != key || refused.Value != value {
			t.Errorf("the refusal names %s = %s; it was %s = %s",
				refused.Key, refused.Value, key, value)
		}
		// The mode must be named, or a reader cannot tell this refusal from
		// a bad value.
		if !strings.Contains(err.Error(), "NIST mode") {
			t.Errorf("the refusal of %s does not name the mode: %v", key, err)
		}
		if c.Raw(key) == value {
			t.Errorf("%s was refused and still saved", key)
		}
	}
}

// TestNISTModeOffAllowsWhatTheModeRefuses is the other half: the same value,
// the same reason, no mode, and it saves through the ordinary acceptance
// path. A profile that refused weaker values whether on or off would not be
// a profile, and this test is what fails if the guard forgets to check.
func TestNISTModeOffAllowsWhatTheModeRefuses(t *testing.T) {
	c := New()
	if c.Bool(NISTModeKey) {
		t.Fatal("NIST mode defaults to on; a default like that changes every " +
			"deployment on upgrade")
	}
	if err := c.Set("session.max", "10h", "long shift", "test"); err != nil {
		t.Fatalf("a weaker value with a reason was refused without the mode: %v", err)
	}
	if c.Raw("session.max") != "10h" {
		t.Fatal("the weaker value did not save")
	}
	if len(c.Weakened()) != 1 {
		t.Fatalf("%d settings report as weakened; the acceptance path did not "+
			"record what the mode would have refused", len(c.Weakened()))
	}
	// And without a reason it is the acceptance question, not the mode's
	// refusal: the two are different facts and must stay distinguishable.
	err := New().Set("session.max", "10h", "", "test")
	var need *ErrNeedsAcceptance
	if !errors.As(err, &need) {
		t.Fatalf("a weaker value without a reason outside the mode asks for "+
			"acceptance; it got %v", err)
	}
}

// TestNISTModeLeavesEverythingElseAlone holds the line the acceptance path
// already draws: the mode tightens the settings with a floor and touches
// nothing else. A guard that also froze preferences would be a lock, and one
// that refused the mode's own switch would leave an organisation hand-editing
// the file to leave the profile — the quiet change the audit chain exists to
// prevent.
func TestNISTModeLeavesEverythingElseAlone(t *testing.T) {
	c := nistOn(t)
	for key, value := range map[string]string{
		"session.idle":           "30m", // inside its bounds; idle has no weakening floor
		"security.contact":       "mailto:security@example.com",
		"network.mode":           "offline",
		"passkey.authenticators": "adce0002-358c-4451-8d91-11babd95a357",
	} {
		if err := c.Set(key, value, "", "test"); err != nil {
			t.Errorf("%s = %s was refused under NIST mode: %v. The mode holds "+
				"floors, not preferences", key, value, err)
		}
	}
	// A floor setting at a value the floor allows is as settable as ever.
	if err := c.Set("session.max", "4h", "", "test"); err != nil {
		t.Errorf("a sign-in shorter than the floor's limit was refused: %v", err)
	}
	// The mode's own switch, both ways, while it is on. Turning it off is the
	// loud, recorded exit; refusing it would make the profile a trap.
	if err := c.Set(NISTModeKey, "false", "", "test"); err != nil {
		t.Fatalf("turning NIST mode off while on was refused: %v", err)
	}
	if c.Bool(NISTModeKey) {
		t.Fatal("the mode is still on after being turned off")
	}
	// And back on, for the deployment that left and returned.
	if err := c.Set(NISTModeKey, "true", "", "test"); err != nil {
		t.Fatalf("turning NIST mode back on was refused: %v", err)
	}
}

// TestNISTModeHoldsOnTheDualControlPathToo: Put is the two-administrator
// write, and a floor the second administrator can step outside is not a
// floor. The mode's answer to a weaker value is the same whoever approves.
func TestNISTModeHoldsOnTheDualControlPathToo(t *testing.T) {
	c := nistOn(t)
	err := c.Put("session.max", "10h", "two administrators approved", "approver")
	if err == nil {
		t.Fatal("a weaker value was saved by two administrators under NIST mode")
	}
	var refused *ErrNISTMode
	if !errors.As(err, &refused) {
		t.Fatalf("the dual-control path was refused with %v, which is not the "+
			"mode's refusal", err)
	}
	// Off, the same change is the organisation's to make.
	off := New()
	if err := off.Put("session.max", "10h", "approved", "approver"); err != nil {
		t.Fatalf("the dual-control path refused a weaker value without the "+
			"mode: %v", err)
	}
}

// TestTheModeItselfCarriesNoFloor keeps the switch out of its own scope. The
// mode has no weakening floor on either value, so no path through the guard
// can refuse the mode's own switch — which is the property that keeps the
// profile exitable and this package out of the locking-people-in business.
func TestTheModeItselfCarriesNoFloor(t *testing.T) {
	s, ok := Lookup(NISTModeKey)
	if !ok {
		t.Fatalf("%s is not a setting", NISTModeKey)
	}
	for _, v := range []string{"true", "false"} {
		if weaker, why := s.IsWeaker(v); weaker {
			t.Errorf("%s = %s is weaker (%s); a mode that calls leaving itself "+
				"a weakening cannot be left through any path this package "+
				"offers", NISTModeKey, v, why)
		}
	}
	for _, key := range NISTGoverned() {
		if key == NISTModeKey {
			t.Error("NIST mode governs itself; the switch and the profile it " +
				"switches must be different things")
		}
	}
}
