// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"
)

// What the sign-in screen tells somebody has to be both commands.
//
// This screen is the only instruction most people will ever read.
func TestTheSignInScreenNamesBothCommands(t *testing.T) {
	body, err := os.ReadFile("../../internal/admin/assets/signin.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(body)

	if !strings.Contains(page, "vaigil token issue") {
		t.Error("the sign-in screen does not say how to issue a token")
	}
	if !strings.Contains(page, "vaigil auth grant") {
		t.Error("the sign-in screen names no grant, so somebody following it " +
			"signs in\n  and is refused by every screen")
	}
}
