// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vaigil/vaigil/internal/auth"
)

// Every command the dispatcher can reach must declare what it needs.
//
// This is the test that would have caught the bug. `publish` called authorise
// and nineteen other commands did not, so with a policy configured and no
// token presented, `auth grant mallory admin` and `token issue --role admin`
// both succeeded — the access-control model bypassed by anyone able to run the
// binary.
//
// It is deliberately a source walk rather than a list. A list would need
// updating by the same person who forgot to add the check, which is no
// guarantee at all. Parsing the switch means a command that exists is a
// command this test knows about, whether or not anybody remembered it.
func TestEveryDispatchedCommandDeclaresItsPrivilege(t *testing.T) {
	cases := dispatchedCommands(t)
	if len(cases) < 30 {
		t.Fatalf("found only %d commands in the dispatch switch; the parse is "+
			"probably wrong, and a test that finds nothing passes", len(cases))
	}
	for _, c := range cases {
		n, ok := commandNeeds[c]
		if !ok {
			t.Errorf("%q is dispatched but declares no privilege. Add it to "+
				"commandNeeds, with an action or with a reason it needs none.", c)
			continue
		}
		if n.action == "" && strings.TrimSpace(n.why) == "" {
			t.Errorf("%q requires no authority and does not say why. The "+
				"reason is the review: writing it down is what makes somebody "+
				"notice when it is wrong.", c)
		}
		if n.action != "" {
			if _, known := auth.Needs(n.action); !known {
				t.Errorf("%q needs action %q, which is not an action the "+
					"policy knows how to evaluate — so the check always "+
					"passes", c, n.action)
			}
		}
	}
}

// And the reverse: an entry for a command that no longer exists is dead weight
// that makes the table look more complete than it is.
func TestThePrivilegeTableHasNoEntriesForCommandsThatDoNotExist(t *testing.T) {
	live := map[string]bool{}
	for _, c := range dispatchedCommands(t) {
		live[c] = true
	}
	for key := range commandNeeds {
		base, _, isSub := strings.Cut(key, " ")
		if isSub {
			if !live[base] {
				t.Errorf("commandNeeds has %q but %q is not dispatched", key, base)
			}
			continue
		}
		if !live[key] {
			t.Errorf("commandNeeds has %q, which is not a command", key)
		}
	}
}

// A specific key must narrow its parent, never widen it.
//
// The two look equivalent and are not. An unlisted subcommand falls through to
// the parent, so a permissive parent with a strict child means the next
// subcommand somebody adds arrives unguarded — and it is the mutating ones
// that get added. A strict parent with permissive children means a new
// subcommand arrives over-guarded, which surfaces as a bug report rather than
// as a breach.
//
// This found `posture`, which defaulted to view with `posture suppress`
// needing grant. Accepting a security risk on the organisation's behalf was
// one forgotten table row away from being readable by anyone.
func TestReadOnlySubcommandsAreMoreNarrowThanTheirParents(t *testing.T) {
	// An action ranks as the role it needs when nothing is granted alone:
	// a permission is no narrower than the rung it follows.
	order := map[auth.Role]int{auth.RoleViewer: 1, auth.RoleAnalyst: 2, auth.RoleResponder: 3, auth.RoleAdmin: 4}
	rank := map[auth.Action]int{}
	for _, a := range auth.Actions() {
		need, _ := auth.Needs(a)
		rank[a] = order[need]
	}
	for key, n := range commandNeeds {
		base, _, isSub := strings.Cut(key, " ")
		if !isSub || n.action == "" {
			continue
		}
		parent, ok := commandNeeds[base]
		if !ok || parent.action == "" {
			continue
		}
		if rank[n.action] > rank[parent.action] {
			t.Errorf("%q needs %s but its parent %q needs only %s, so the "+
				"specific key widens access instead of narrowing it",
				key, n.action, base, parent.action)
		}
	}
}

// dispatchedCommands reads the case labels out of main's command switch.
func dispatchedCommands(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(".", "main.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	if err != nil {
		t.Fatal(err)
	}

	var out []string
	ast.Inspect(f, func(node ast.Node) bool {
		sw, ok := node.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		ident, ok := sw.Tag.(*ast.Ident)
		if !ok || ident.Name != "cmd" {
			return true
		}
		for _, stmt := range sw.Body.List {
			cl, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, expr := range cl.List {
				lit, ok := expr.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				out = append(out, strings.Trim(lit.Value, `"`))
			}
		}
		return true
	})
	return out
}

// -- and that the table is actually consulted --------------------------------

// A typo must not tell a user to edit a Go source file.
//
// Every unknown command took the developer's message for as long as this check
// has existed — "add it to commandNeeds in cmd/vaigil/privilege.go" — because
// "somebody added a command and forgot the table" and "somebody mistyped" were
// never distinguished. The first is a real condition worth a loud message; the
// second is the overwhelmingly common one.
//
// The developer case is prevented rather than reported: the test above walks
// the dispatch switch and fails when a command is missing from the table, so
// by the time this runs, an unrecognised name can only be a typo.
func TestATypoGetsAHumanMessage(t *testing.T) {
	for _, typo := range []string{"wibble", "aprove", "incidnet", "vlun"} {
		err := unknownCommand(typo)
		if err == nil {
			t.Fatalf("%q was accepted", typo)
		}
		msg := err.Error()
		if strings.Contains(msg, "commandNeeds") ||
			strings.Contains(msg, ".go") {
			t.Errorf("%q told a user to edit source: %s", typo, msg)
		}
		if !strings.Contains(msg, "vaigil help") {
			t.Errorf("%q does not say how to find the real commands: %s",
				typo, msg)
		}
	}
}

// A near-miss suggests the command it is near.
func TestANearMissSuggestsTheRealCommand(t *testing.T) {
	for typo, want := range map[string]string{
		"incidnet": "incident",
		"findng":   "finding",
		"detetc":   "detect",
		"workforc": "workforce",
	} {
		msg := unknownCommand(typo).Error()
		if !strings.Contains(msg, want) {
			t.Errorf("%q did not suggest %q: %s", typo, want, msg)
		}
	}
}

// A policy that cannot be read refuses everything.
//
// It used to permit everything. policyInUse discarded the load error and
// returned false, which reads as "nobody has been granted anything", which
// turns authorisation off — so truncating policy.json disabled access control
// for the whole store and the only symptom was that everything started
// working. An editor, a crash between write and rename, or a half-finished
// restore is enough; it does not need an attacker.
//
// Absent is different and stays different: a store nobody has configured is the
// case the zero-configuration design exists for. Present-and-unreadable is the
// one where refusing is the only safe answer.
func TestAnUnreadablePolicyRefusesEverything(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	// Absent: nothing to enforce, so nothing is refused.
	if err := authoriseCommand(root, "vuln", nil); err != nil {
		t.Fatalf("an unconfigured store refused a command: %v", err)
	}

	// Configured: refused without a credential.
	policy := `{"bindings":[{"principal":"alice","role":"admin","resource":"/"}]}`
	if err := os.WriteFile(policyPath(root), []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := authoriseCommand(root, "vuln", nil); err == nil {
		t.Fatal("a configured store allowed an unauthenticated write")
	}

	// Unreadable: refused, and the refusal says why rather than reporting the
	// store as unconfigured.
	if err := os.WriteFile(policyPath(root), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := authoriseCommand(root, "vuln", nil)
	if err == nil {
		t.Fatal("a store whose policy cannot be read allowed an " +
			"unauthenticated write; access control is off exactly when the " +
			"file guarding it is damaged")
	}
	if !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("the refusal does not say the policy is unreadable: %v", err)
	}

	// And a read is refused too, not only a write.
	if err := authoriseCommand(root, "diff", nil); err == nil {
		t.Error("a read was allowed against an unreadable policy")
	}
}

// The first token an admin issues can administer.
//
// `token issue` defaulted to reader, and the route there is the fix line
// `posture scan` prints: grant yourself admin, which turns identity enforcement
// on, then issue a token because the next command now needs one. That token
// could not issue another — issuing needs admin — so the store had exactly one
// credential, it was read-only, and there was no way forward from inside the
// tool. Reproduced by following that advice on a real store.
//
// Without --role a token now acts as the principal does; --role, --read-only
// and --api all still narrow it.
func TestATokenDefaultsToWhatItsPrincipalHolds(t *testing.T) {
	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{
		Principal: "rue", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	if err := pol.Grant(auth.Binding{
		Principal: "ida", Role: auth.RoleAnalyst, Resource: "/workshops"}); err != nil {
		t.Fatal(err)
	}

	if got := strongestRole(pol, "rue", "/"); got != auth.RoleAdmin {
		t.Errorf("an admin's token would carry %q, so the operator cannot "+
			"issue another one", got)
	}
	if got := strongestRole(pol, "ida", "/workshops"); got != auth.RoleAnalyst {
		t.Errorf("ida holds author on /workshops; got %q", got)
	}
	// Scoped bindings do not leak upward.
	if got := strongestRole(pol, "ida", "/"); got != auth.RoleNone {
		t.Errorf("a binding on /workshops gave %q on /", got)
	}
	// Somebody with no binding gets nothing, so the reader default still
	// applies to a principal the policy has never heard of.
	if got := strongestRole(pol, "nobody", "/"); got != auth.RoleNone {
		t.Errorf("an unknown principal got %q", got)
	}
}
