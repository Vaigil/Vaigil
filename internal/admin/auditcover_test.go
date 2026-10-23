// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"github.com/quilzo/vaigil/internal/enrol"

	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// A write through the browser is recorded, the same as a write from anywhere
// else.
//
// Three were not, and they were not the obscure ones. Saving a page is the
// most common write in the product and recorded nothing; rolling back moves
// what the public sees and recorded nothing; setting a provenance record —
// the assertion that later satisfies the Article 50 gate, so the one whose
// authorship somebody asking questions most needs — recorded nothing.
//
// Every other surface already did. `vaigil add` writes content.add, the agent
// interface writes mcp.write_page, and the content API writes through
// OnWrite. This interface recorded deleting a
// page, editing its sections and removing a selection of them, so the gap did
// not look like a policy — it looked like whichever handler somebody had in
// mind at the time.
//
// Driven rather than walked: what matters is that an entry comes out, not that
// a particular call appears in a particular function.
func TestEveryWriteThroughTheBrowserIsRecorded(t *testing.T) {
	for _, tc := range []struct {
		what, path, body, action string
	}{
		{"granting a role", "/people/grant",
			"principal=sam&role=viewer&resource=/", "access.grant"},
		{"issuing an enrolment link", "/people/enrol", "principal=editor", "enrol.issued"},
	} {
		t.Run(tc.what, func(t *testing.T) {
			srv, token := setup(t)
			srv.Enrol = &enrol.Store{Path: filepath.Join(t.TempDir(), "enrolments.json")}
			var got []string
			srv.Audit = func(action, resource string, _ map[string]string) {
				got = append(got, action+" "+resource)
			}

			w := postForm(t, srv, tc.path, token, tc.body)
			if w.Code >= 400 {
				t.Fatalf("%s answered %d: %s", tc.what, w.Code,
					strings.TrimSpace(w.Body.String())[:min(200, w.Body.Len())])
			}
			if !recorded(got, tc.action) {
				sort.Strings(got)
				t.Errorf("%s left no %q entry in the audit log; it recorded "+
					"%v. The same act from a script is recorded in full, so "+
					"the log is a record of who used which interface rather "+
					"than of what happened", tc.what, tc.action, got)
			}
		})
	}
}

func recorded(entries []string, action string) bool {
	for _, e := range entries {
		if strings.HasPrefix(e, action+" ") {
			return true
		}
	}
	return false
}
