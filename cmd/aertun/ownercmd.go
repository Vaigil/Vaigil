// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/aertun/aertun/internal/audit"
	"github.com/aertun/aertun/internal/auth"
	"github.com/aertun/aertun/internal/dual"
)

// The Owner (internal/auth/owner.go): who it is, and passing it on.
//
// `aertun auth owner` names the Owner. `aertun auth owner transfer NAME`
// asks for ownership to pass to NAME, who must already administer the whole
// store. The request waits a day and is then confirmed by whoever asked, on
// the console's People screen with a passkey sign-in (dual.OwnProof);
// anybody with an administrator's session can decline it until then. Asking is the Owner's alone — or, on a store
// made before there were owners, any administrator's, which is how such a
// store gets one.
func authOwner(root string, args []string) error {
	if len(args) == 0 || args[0] == "show" {
		p, err := loadPolicy(root)
		if err != nil {
			return err
		}
		owner := p.OwnerName()
		if w.JSON(map[string]string{"owner": owner}) {
			return nil
		}
		if owner == "" {
			w.Human("this store has no Owner yet; an administrator claims it with " +
				"aertun auth owner transfer NAME, which waits a day\n")
			return nil
		}
		w.Human("%s owns this store and always administers all of it\n", owner)
		return nil
	}
	if args[0] != "transfer" {
		return errors.New("usage: aertun auth owner [show] | transfer <principal> [--note WHY]")
	}
	fs := flag.NewFlagSet("owner transfer", flag.ContinueOnError)
	note := fs.String("note", "", "why ownership is moving")
	pos, flags := leadingArgs(args[1:], 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 || fs.NArg() != 0 {
		return errors.New("usage: aertun auth owner transfer <principal> [--note WHY]")
	}
	to := pos[0]
	c := resolveCaller(root, "")
	if err := authorise(root, c, auth.ActGrant, "/"); err != nil {
		return err
	}
	if c.Kind == audit.KindAI {
		return errors.New("ownership is moved by a person, never by an agent")
	}
	p, err := loadPolicy(root)
	if err != nil {
		return err
	}
	owner := p.OwnerName()
	if owner != "" && owner != c.Name {
		return fmt.Errorf("only the Owner, %s, passes ownership on", owner)
	}
	if owner == to {
		return fmt.Errorf("%s already owns this store", to)
	}
	// Checked now so the request is not a day's wait for a refusal: the
	// new Owner must already administer the whole store with no end date.
	trial := &auth.Policy{Bindings: p.Snapshot()}
	if err := trial.SetOwner(to); err != nil {
		return err
	}
	now := time.Now()
	r, err := dualStore(root).Propose(dual.Owner, "make "+to+" the Owner",
		dual.OwnerChange{To: to}, *note, c.Name, false, now)
	if err != nil {
		return err
	}
	if err := recordE(root, c.auditRecord("dual.proposed", "/", audit.Success,
		ownerDetail(r, to))); err != nil {
		return err
	}
	if w.JSON(r) {
		return nil
	}
	w.Human("%sownership passes to %s when you confirm it%s, from %s (request %s)\n",
		yellow, to, reset, r.NotBefore.UTC().Format("15:04 MST on 2 Jan"), r.ID)
	w.Human("  %sconfirm it on the People screen of the console, which asks for your passkey; any administrator can decline it until then%s\n",
		dim, reset)
	return nil
}

// applyOwner makes a confirmed transfer: the one who asked must still be
// the Owner (or the store still have none), so two transfers asked for in
// turn cannot both land.
func applyOwner(root string, r dual.Request, ch dual.OwnerChange) error {
	_, err := updatePolicy(root, func(p *auth.Policy) error { return p.TransferOwner(r.By, ch.To) })
	return err
}

// ownerDetail is what the log keeps of an ownership request: who it names,
// when it may be approved, and the reason when one was given.
func ownerDetail(r dual.Request, to string) map[string]string {
	d := map[string]string{"request": r.ID, "kind": dual.Owner, "what": r.What,
		"to": to, "not_before": r.NotBefore.UTC().Format(time.RFC3339)}
	if r.Why != "" {
		d["why"] = r.Why
	}
	return d
}
