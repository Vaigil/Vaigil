// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
)

// A token's scope narrows what a credential may reach, beneath everything the
// policy already grants its principal: role (what may be done), resource
// (where), and read-only (writes refused outright). It only ever narrows: it
// is intersected with the policy's answer, never unioned, so a token issued
// by somebody who misunderstood it can be too narrow, never too wide.
type Scope struct {
	// ReadOnly refuses every write regardless of role.
	//
	// Separate from the role rather than folded into it, because the two
	// answer different questions. A responder who wants a read-only token
	// for a dashboard should not have to pretend to be a viewer — the token
	// still says who it acts for, and revoking it still cascades correctly.
	ReadOnly bool `json:"read_only,omitempty"`
}

// Empty reports whether the scope restricts nothing.
func (s Scope) Empty() bool { return !s.ReadOnly }

// String renders a scope for display and for the audit record.
func (s Scope) String() string {
	if s.ReadOnly {
		return "read-only"
	}
	return "unrestricted"
}

// Validate refuses a scope that cannot mean what it appears to. Every
// scope there is can.
func (s Scope) Validate() error { return nil }

// Narrow returns a scope that is this one further restricted by another:
// a session exchanged from a token can be narrower than it, never wider.
func (s Scope) Narrow(by Scope) Scope {
	return Scope{ReadOnly: s.ReadOnly || by.ReadOnly}
}

// AllowsAction reports whether the scope permits an action at all, before any
// policy is consulted.
func (s Scope) AllowsAction(a Action) bool {
	if !s.ReadOnly {
		return true
	}
	needed, ok := Needs(a)
	if !ok {
		// An action this version does not know about, under a read-only
		// token. Refused: a scope that fails open on the actions it has not
		// heard of is a scope that widens every time one is added.
		return false
	}
	return needed == RoleViewer
}

// Why explains a refusal, so a caller sees what stopped them rather than a
// bare "forbidden".
func (s Scope) Why(a Action) string {
	if !s.AllowsAction(a) {
		return fmt.Sprintf("this token is read-only and %s writes", a)
	}
	return ""
}

// -- the limits a credential itself carries ----------------------------------

// Covers reports whether a grant or a scope on `scope` reaches `target`.
//
// Exported because three surfaces ask this question and two of them had grown
// their own copy. Segment-aware: "/blog" must not cover "/blog-drafts", and a
// second implementation that got that wrong would be a hole in exactly one
// interface.
func Covers(scope, target string) bool { return covers(scope, target) }

// CheckCredential applies the limits a credential carries, over and above what
// the policy grants the principal holding it.
//
// A token narrows and never widens: its role caps the session, its resource
// caps where it reaches, and its scope caps the actions. The policy answers
// "may this person do this"; this answers "may they do it with the
// credential in their hand". Both have to hold, and every surface calls this
// rather than reimplementing the parts it remembers.
//
// Returns nil when the credential permits the action.
func CheckCredential(role Role, resource string, scope Scope, action Action,
	target string) error {

	need, known := Needs(action)
	if !known {
		// Refused rather than allowed, for the same reason Evaluate refuses:
		// a typo in a caller must not become a permission.
		return fmt.Errorf(
			"unknown action %q; refusing rather than guessing what it needs",
			action)
	}
	if !role.AtLeast(need) {
		return fmt.Errorf(
			"this credential carries %s and %s needs %s. A token limits the "+
				"session even when the principal holds more in general",
			role, action, need)
	}
	if resource != "" && !covers(resource, target) {
		return fmt.Errorf(
			"this credential is scoped to %s and does not reach %s",
			normalise(resource), normalise(target))
	}
	if !scope.AllowsAction(action) {
		return fmt.Errorf("%s", scope.Why(action))
	}
	return nil
}

// CheckGranted is CheckCredential for a decision already made: a grant of a
// permission on its own (permission.go) is capped by a credential that
// reaches any role at all, its path and its limits, rather than by the
// rung the permission follows when nobody granted it. Otherwise a viewer
// given approve could never use it through their own token, whose role is
// viewer. Everything else is capped as CheckCredential caps.
func CheckGranted(d Decision, role Role, resource string, scope Scope, action Action, target string) error {
	if d.Binding != nil && d.Binding.Permission == action && IsPermission(action) {
		if !role.Valid() {
			return fmt.Errorf("this credential carries no role, and %s needs one", action)
		}
		return CheckCredential(RoleAdmin, resource, scope, action, target)
	}
	return CheckCredential(role, resource, scope, action, target)
}
