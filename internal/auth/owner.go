// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package auth

import "fmt"

// The Owner.
//
// A store starts with one person, its Owner, and everybody else is a
// collaborator somebody invited and gave a role. The Owner is not a rung
// above administrator: they hold the administrator role over the whole
// store like anybody else who does, and what makes them the Owner is that
// nobody can take it away. Not another administrator, not an identity
// provider's deprovisioning, not a deny, not an end date — the one way the
// Owner changes is a transfer the Owner asks for, which waits a day
// (internal/dual), announced, and can be declined by anybody until then.
//
// Without this, the second administrator an Owner invites can remove the
// first, and an administrator's stolen session is enough to lock the person
// who runs the store out of it. With it, the worst a stolen session does to
// ownership is ask for it, in the open, a day ahead.
//
// The rule is checked on the policy as a whole, after every change and
// before anything is written (CheckOwner), so it holds whichever surface
// made the change and however the change was assembled.

// CheckOwner reports whether the policy still keeps its Owner: a live,
// unending administrator binding over everything, and no deny naming them.
// A policy with no Owner passes; there is nothing yet to keep.
func (p *Policy) CheckOwner() error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.Owner == "" {
		return nil
	}
	held := false
	for _, b := range p.Bindings {
		if b.Principal != p.Owner {
			continue
		}
		if b.Deny {
			return fmt.Errorf("%s is the Owner, and nothing denies the Owner "+
				"anything; ownership changes by transfer (aertun auth owner "+
				"transfer NAME), not by a deny", p.Owner)
		}
		if b.Role == RoleAdmin && normalise(b.Resource) == "/" && b.Expires == 0 {
			held = true
		}
	}
	if !held {
		return fmt.Errorf("%s is the Owner and always administers the whole "+
			"store, with no end date; ownership changes by transfer (aertun "+
			"auth owner transfer NAME), never by revoking it", p.Owner)
	}
	return nil
}

// SetOwner names the Owner, refusing anybody the policy does not already
// make an administrator of the whole store: ownership is given to somebody
// trusted with the store, never used to make somebody trusted with it.
func (p *Policy) SetOwner(name string) error {
	p.mu.Lock()
	previous := p.Owner
	p.Owner = name
	p.mu.Unlock()
	if err := p.CheckOwner(); err != nil {
		p.mu.Lock()
		p.Owner = previous
		p.mu.Unlock()
		return fmt.Errorf("%s cannot be the Owner until they administer the "+
			"whole store, with no end date: grant that first", name)
	}
	return nil
}

// TransferOwner passes ownership from the principal who asked for it, who
// must still be the Owner — or, on a store with none, may be anybody the
// caller already let ask — so two transfers asked for in turn cannot both
// land.
func (p *Policy) TransferOwner(from, to string) error {
	if owner := p.OwnerName(); owner != "" && owner != from {
		return fmt.Errorf("the transfer was asked for by %s, and %s owns the store now", from, owner)
	}
	return p.SetOwner(to)
}

// OwnerName is the Owner, or empty — also for no policy at all.
func (p *Policy) OwnerName() string {
	if p == nil {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.Owner
}
