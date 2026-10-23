// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"strings"
	"testing"
)

// TestNoAdminPageIsCached, walking every screen.
//
// Five handlers said no-store and the rest said nothing, so the screens that
// list people, tokens, audit entries and security events were cacheable: on
// a shared machine, the back button after signing out showed them. The rule
// is now a default in the middleware, and this walks every route so a
// screen added later cannot slip past it.
func TestNoAdminPageIsCached(t *testing.T) {
	srv, token := fullyWired(t)
	// The two that are meant to be cached, and say for how long.
	cached := map[string]bool{"/style.css": true, "/admin.js": true, "/brand.css": true,
		"/fonts/vaigil-ui.woff2": true}
	for path := range servedRoutes(t) {
		if strings.HasSuffix(path, "/") || strings.Contains(path, "{") {
			continue
		}
		w := get(t, srv, path, token)
		cc := w.Header().Get("Cache-Control")
		if cached[path] {
			if cc == "no-store" {
				t.Errorf("%s is static and was marked no-store", path)
			}
			continue
		}
		if cc != "no-store" && !strings.HasPrefix(cc, "private") {
			t.Errorf("%s answered %d with Cache-Control %q", path, w.Code, cc)
		}
	}
	// And the sign-in page, which is reached without a credential.
	if cc := get(t, srv, "/signin", "").Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("/signin: Cache-Control %q", cc)
	}
}

// No screen of the console may be framed, by anybody.
func TestNoScreenMayBeFramed(t *testing.T) {
	srv, token := setup(t)
	for _, path := range []string{"/today", "/signin", "/findings", "/people"} {
		h := get(t, srv, path, token).Header()
		if !strings.Contains(h.Get("Content-Security-Policy"),
			"frame-ancestors 'none'") || h.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s can be framed: %q / %q", path,
				h.Get("Content-Security-Policy"), h.Get("X-Frame-Options"))
		}
	}
}

// TestIsolationHeadersAreSent.
func TestIsolationHeadersAreSent(t *testing.T) {
	srv, token := setup(t)
	h := get(t, srv, "/today", token).Header()
	for k, want := range map[string]string{
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	pp := h.Get("Permissions-Policy")
	for _, off := range []string{"camera=()", "microphone=()", "geolocation=()"} {
		if !strings.Contains(pp, off) {
			t.Errorf("Permissions-Policy leaves %s on: %q", off, pp)
		}
	}
	// Passkeys need credential access at this origin, so it is not listed.
	if strings.Contains(pp, "publickey-credentials") {
		t.Errorf("Permissions-Policy switches off passkeys: %q", pp)
	}
}
