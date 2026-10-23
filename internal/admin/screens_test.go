// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"strings"
	"testing"
)

// Every screen has to say something when its capability was not wired in.
//
// A server built without the hooks must not render an empty table: "you have
// none of these" and "this build cannot tell you" look identical on a page and
// mean opposite things. This opens every screen against a bare server and
// requires each to answer — 200 with an explanation, or 503 with one — rather
// than a 500 or a half-rendered page.
func TestEveryScreenSurvivesWithNothingWiredIn(t *testing.T) {
	srv, token := setup(t)

	for r := range servedRoutes(t) {
		if strings.HasSuffix(r, "/") && r != "/" {
			continue
		}
		if _, excused := notAScreen[r]; excused {
			continue
		}
		path := r
		t.Run(path, func(t *testing.T) {
			w := get(t, srv, path, token)
			switch w.Code {
			case http.StatusOK, http.StatusMethodNotAllowed,
				http.StatusServiceUnavailable:
			default:
				t.Fatalf("%s answered %d with nothing wired in; it should "+
					"explain itself rather than fail\n%s",
					path, w.Code, firstLines(w.Body.String(), 6))
			}
			if strings.Contains(w.Body.String(), "<!-- render error:") {
				t.Fatalf("%s rendered with a template error", path)
			}
		})
	}
}

// notAScreen is every registered route that a person cannot open, and why.
//
// Four of them, each for a different reason, and each written out rather than
// filtered by a pattern — a pattern would also excuse the next thing that
// happens to match it.
var notAScreen = map[string]string{
	"/": "sends a person to Today",
	"/signin/oidc": "starts an authorisation redirect, and answers 404 when " +
		"no identity provider is configured",
	"/auth/callback":         "receives one, and is never opened directly",
	"/signout":               "clears the cookie and redirects; there is nothing to render",
	"/session/alive":         "is posted to by admin.js and answers 204",
	"/token/exchange":        "is posted to by programs exchanging a token (RFC 8693); there is nothing to render",
	"/style.css":             "is a stylesheet",
	"/admin.js":              "is the console's script",
	"/fonts/vaigil-ui.woff2": "is the console's typeface",
	"/icon.svg":              "an image, not a screen",
}
