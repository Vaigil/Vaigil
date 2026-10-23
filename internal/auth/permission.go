// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
	"strings"
)

// Permissions that can be granted on their own.
//
// The ladder decides how far somebody goes in the work of the queue. Some
// decisions are a different kind of work: approving somebody else's act,
// changing what counts as wrong, judging a vulnerability. Each is a
// permission of its own. By default it follows the rung that holds it, and
// it can also be granted alone, on part of the store, as a binding like any
// other: shown by the same explain, ended when it expires, and deniable.

const (
	// ActApprove decides what waits for a second person: an act on another
	// platform asked for in a case, and a run an automation held.
	ActApprove Action = "approve"
	// ActTune changes what counts as wrong: detections, their rings and
	// suppressions, Sigma imports, correlations and automation rules.
	ActTune Action = "tune"
	// ActAssess decides vulnerabilities: SSVC decisions, VEX statements,
	// asset tags and upgrade plans.
	ActAssess Action = "assess"
)

// Permission is one permission that can be granted on its own.
type Permission struct {
	Action Action
	// Summary says what holding it lets somebody do.
	Summary string
}

// Permissions are the permissions that can be granted on their own, in the
// order people read them.
var Permissions = []Permission{
	{ActApprove, "approve an act on another platform, or a run an automation held, that somebody else asked for"},
	{ActTune, "change detections, Sigma imports, correlations and automation rules"},
	{ActAssess, "decide vulnerabilities: SSVC, VEX statements, asset tags and upgrade plans"},
}

// IsPermission reports whether an action can be granted on its own.
func IsPermission(a Action) bool {
	for _, p := range Permissions {
		if p.Action == a {
			return true
		}
	}
	return false
}

// PermissionNamed finds a grantable permission by name.
func PermissionNamed(name string) (Permission, bool) {
	for _, p := range Permissions {
		if string(p.Action) == strings.TrimSpace(name) {
			return p, true
		}
	}
	return Permission{}, false
}

// What is what a binding grants, in words: a role, or a permission.
func (b Binding) What() string {
	if b.Permission != "" {
		return string(b.Permission)
	}
	return string(b.Role)
}

// grantsPermission reports whether a binding is a live grant of an action's
// permission over a target.
func grantsPermission(b *Binding, action Action, target string, liveAt int64) bool {
	if b.Permission != action || b.Deny || (b.Expires != 0 && liveAt >= b.Expires) {
		return false
	}
	if !covers(b.Resource, target) {
		return false
	}
	// A permission granted over the site reaches a guarded area only as a
	// role would: by being granted on the area itself.
	return IsArea(b.Resource) || !guarded(target)
}

// permissionText is a binding of a permission, for a reason or a trail.
func permissionText(b *Binding) string {
	return fmt.Sprintf("the %s permission on %s", b.Permission, normalise(b.Resource))
}

// AnywhereUnder reports whether a principal may perform an action on an
// area or on anything inside it: whether a screen for the area has
// anything to show them.
func (p *Policy) AnywhereUnder(principal string, action Action, area string) bool {
	if p.Evaluate(principal, action, area).Allowed {
		return true
	}
	p.mu.RLock()
	var inside []string
	for i := range p.Bindings {
		b := &p.Bindings[i]
		if b.Principal == principal && !b.Deny && covers(area, b.Resource) {
			inside = append(inside, b.Resource)
		}
	}
	p.mu.RUnlock()
	for _, r := range inside {
		if p.Evaluate(principal, action, r).Allowed {
			return true
		}
	}
	return false
}
