// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"strings"
	"testing"
)

// The screen has to render it, not merely have it in the map.
func TestTheSignInsTemplateRendersTheThrottleState(t *testing.T) {
	src, err := assets.ReadFile("assets/signins.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	for _, want := range []string{".Throttled", ".Failures", ".Locked", ".Alerted"} {
		if !strings.Contains(body, want) {
			t.Errorf("the sign-ins screen does not render %s", want)
		}
	}
	// And it must not claim to name anybody: the limiter holds HMACs, so the
	// screen cannot say who and must not imply it can.
	if strings.Contains(body, "{{.Principal}}</td>") {
		t.Error("the throttle table appears to name principals, and the " +
			"limiter cannot say who")
	}
}
