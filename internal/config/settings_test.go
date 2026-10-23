// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
)

// A security contact is a URI, checked when it is set. A bare address was
// accepted, published as a security.txt Contact line nothing can use, and
// skipped by the automations that mail the security team.
func TestASecurityContactIsAURI(t *testing.T) {
	s, ok := Lookup("security.contact")
	if !ok {
		t.Fatal("security.contact is not a setting")
	}
	for _, bad := range []string{"security@example.com", "mailto:",
		"mailto:sec@example.com, sec2@example.com", "ftp://example.com",
		"javascript:alert(1)"} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%q was accepted as a security contact", bad)
		}
	}
	for _, good := range []string{"", "mailto:security@example.com",
		"MAILTO:security@example.com", "https://example.com/report",
		"mailto:a@example.com, https://example.com/report, tel:+44-20-7946-0000"} {
		if err := s.Validate(good); err != nil {
			t.Errorf("%q was refused: %v", good, err)
		}
	}
}
