// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/vaigil/vaigil/internal/agentreg"
	"github.com/vaigil/vaigil/internal/atomicfile"
	"github.com/vaigil/vaigil/internal/audit"
	"github.com/vaigil/vaigil/internal/auth"
	"github.com/vaigil/vaigil/internal/fetch"
)

// The register of agents this organisation runs — the IA-9 object, and the
// thing AC-2 asks to be able to review and to switch off.
//
// Two halves hold it up, and both live in this file's colleagues rather
// than here: the binding (a token named agent:NAME identifies as that
// agent, caller.go) and the enforcement (every gate consults the registry
// before the policy, and the agent interface allows an agent only the tools
// its entry lists, mcpsecurity.go). This file is the read-and-change
// surface over the same register, so `agent list` and the gate can never
// disagree about who exists.

// agentsPath is the registry, beside the policy and the token store, with
// their permissions: it names who may act, which is not world-readable
// material.
func agentsPath(root string) string { return filepath.Join(root, "agents.json") }

func agentStore(root string) agentreg.Store {
	return agentreg.Store{Path: agentsPath(root)}
}

func agentUsage() error {
	return fmt.Errorf("usage: vaigil agent list | add NAME --owner WHO --allow TOOL[,TOOL] [--note \"…\"] | " +
		"allow NAME (--add | --remove) TOOL[,TOOL] | disable NAME --why \"…\" | enable NAME --why \"…\" | help")
}

// cmdAgent manages the agent register.
func cmdAgent(root string, args []string) error {
	if len(args) == 0 {
		return agentHelp()
	}
	caller := resolveCaller(root, "")
	// note records a change to the register under the caller's own name:
	// who added what, who pulled which switch. The action is what the
	// detections and the access reviews read, so it names the verb and the
	// register in the log's dotted style (agent.add, agent.disable).
	note := func(action, name string, extra map[string]string) error {
		d := map[string]string{"agent": name}
		for k, v := range extra {
			d[k] = v
		}
		return recordE(root, caller.auditRecord(action, "/agents/"+name,
			audit.Success, d))
	}
	switch args[0] {
	case "help":
		return agentHelp()
	case "list":
		return agentList(root)
	case "add":
		return agentAdd(root, caller, args[1:], note)
	case "allow":
		return agentAllow(root, caller, args[1:], note)
	case "disable":
		return agentDisable(root, caller, args[1:], note)
	case "enable":
		return agentEnable(root, caller, args[1:], note)
	}
	return agentUsage()
}

func agentList(root string) error {
	agents, err := agentStore(root).Load()
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"agents": agents}) {
		return nil
	}
	if len(agents) == 0 {
		w.Human("  no agents are registered; vaigil agent help says what that buys\n")
		return nil
	}
	for _, a := range agents {
		state := green + "active" + reset
		if a.Status == agentreg.Disabled {
			state = red + "disabled" + reset
		}
		allow := strings.Join(a.Allow, ", ")
		if allow == "" {
			allow = dim + "no tools" + reset
		}
		w.Human("  %s%s%s  %s  owner %s  %s\n", bold, a.Name, reset, state, a.Owner, allow)
		if a.Note != "" {
			w.Human("    %s\n", a.Note)
		}
		if a.Status == agentreg.Disabled && a.DisabledWhy != "" {
			w.Human("    %sdisabled: %s%s\n", yellow, a.DisabledWhy, reset)
		}
		w.Human("    %sregistered %s by %s; changed %s by %s%s\n", dim,
			a.CreatedAt.Format("2 Jan 2006"), a.CreatedBy,
			a.ChangedAt.Format("2 Jan 2006"), a.ChangedBy, reset)
	}
	w.Human("\n  %sa token named agent:NAME identifies as that agent and is "+
		"refused by every gate unless it is registered here%s\n", dim, reset)
	return nil
}

// agentAdd registers an agent. The privilege is the dispatch table's: an
// administrator's, because adding one decides what may act in this store.
func agentAdd(root string, caller *Caller, args []string,
	note func(string, string, map[string]string) error) error {

	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	owner := fs.String("owner", "", "the person who answers for what this agent does")
	allow := fs.String("allow", "", "the tools it may call, comma-separated: "+
		strings.Join(agentreg.Tools(), ", "))
	noteText := fs.String("note", "", "why this agent exists, on the record")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return agentUsage()
	}
	a := agentreg.Agent{Name: pos[0], Owner: *owner, Allow: splitList(*allow),
		Note: strings.TrimSpace(*noteText), CreatedBy: caller.Name}
	if err := agentStore(root).Add(a, time.Now().UTC()); err != nil {
		return err
	}
	w.Human("registered %s%s%s (owner %s, allowed %s)\n", bold, pos[0], reset,
		*owner, strings.Join(splitList(*allow), ", "))
	// The register does not mint the credential: issuing a token named
	// agent:NAME is the owner's separate act with `token issue`, and the
	// two are separate on purpose — a register that issued credentials
	// could not be a list anybody dared to add to.
	w.Human("  %sno credential exists yet; a token issued as %s%s%s binds to "+
		"this entry:%s\n", dim, agentreg.TokenPrefix, pos[0], "", reset)
	w.Human("    vaigil token issue %s%s --principal %s --role viewer\n",
		agentreg.TokenPrefix, pos[0], pos[0])
	return note("agent.add", pos[0], map[string]string{
		"owner": *owner, "allow": strings.Join(splitList(*allow), ",")})
}

// agentAllow widens or narrows an entry's tool allowlist.
func agentAllow(root string, caller *Caller, args []string,
	note func(string, string, map[string]string) error) error {

	fs := flag.NewFlagSet("allow", flag.ContinueOnError)
	add := fs.String("add", "", "tools to allow, comma-separated")
	remove := fs.String("remove", "", "tools to refuse, comma-separated")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 || (*add == "" && *remove == "") {
		return agentUsage()
	}
	s := agentStore(root)
	if err := s.Allow(pos[0], splitList(*add), splitList(*remove), caller.Name,
		time.Now().UTC()); err != nil {
		return err
	}
	a, _, err := s.Get(pos[0])
	if err != nil {
		return err
	}
	w.Human("%s now allowed %s\n", pos[0], strings.Join(a.Allow, ", "))
	action := "agent.allow"
	extra := map[string]string{"allow": strings.Join(a.Allow, ",")}
	if *remove != "" {
		// A distinct action for the narrowing half, because "allow" reading
		// backwards in a log search is how a removed tool goes unnoticed.
		action = "agent.disallow"
		extra["removed"] = *remove
	}
	if *add != "" {
		extra["added"] = *add
	}
	return note(action, pos[0], extra)
}

// agentDisable is the kill switch: responder-grade on purpose, because the
// person who needs to stop an agent at 3am is the one holding the pager,
// not necessarily an administrator.
//
// Two things happen as one act: the registry entry goes disabled, and every
// token bound to the agent is revoked. Either alone is half a switch —
// revoking tokens but leaving the entry active lets somebody issue a fresh
// token that works, and disabling the entry but leaving tokens live leaves
// credentials that fail at the registry rather than at the door. Together
// the bearer dies at the next request and a new one cannot be born until
// somebody enables the entry and the owner asks for a credential.
func agentDisable(root string, caller *Caller, args []string,
	note func(string, string, map[string]string) error) error {

	fs := flag.NewFlagSet("disable", flag.ContinueOnError)
	why := fs.String("why", "", "the reason it was killed, kept on the record")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return agentUsage()
	}
	if strings.TrimSpace(*why) == "" {
		return fmt.Errorf("disabling an agent needs --why: the next person to " +
			"read this register — the review, or whoever decides to enable it " +
			"again — has to know what happened, and \"ask around\" is not a record")
	}
	if err := agentStore(root).Disable(pos[0], strings.TrimSpace(*why),
		caller.Name, time.Now().UTC()); err != nil {
		return err
	}
	revoked, err := revokeAgentTokens(root, pos[0])
	if err != nil {
		// The registry is disabled, which is the half that stops fresh
		// credentials; a failure to reach the token store is reported loudly
		// rather than rolled back, because the tokens that could not be
		// revoked are still refused by the registry gate on their next use.
		return fmt.Errorf("%s is disabled in the registry, but its tokens "+
			"could not be revoked: %v\n  they are refused by the registry "+
			"gate until this is fixed; revoke them by hand with `vaigil "+
			"token list` and `vaigil token revoke ID`", pos[0], err)
	}
	w.Human("%s%s%s is disabled%s\n", bold, pos[0], reset,
		whySuffix(revoked))
	noteErr := note("agent.disable", pos[0], map[string]string{
		"why": *why, "revoked": fmt.Sprintf("%d", revoked)})
	// The outward half of the switch (docs/research/02-access-control.md
	// §8.5): tell every configured receiver. Best-effort by contract — the
	// local kill has already happened, and a receiver that is unreachable
	// must never be allowed to fail or delay the switch that stops the
	// agent. Each attempt is audited on its own, success or failure, so the
	// record says who heard about the kill and who did not.
	transmitAgentRevocation(root, caller, pos[0], strings.TrimSpace(*why))
	return noteErr
}

// transmitAgentRevocation pushes a session-revoked event about one agent to
// every configured SSF receiver (internal/ssf, the transmitter half).
//
// Never returns an error, because nothing here is allowed to change the
// outcome of the kill: with no receivers configured it says transmitting is
// off, and with a receiver that refuses or cannot be reached it says so and
// writes ssf.transmit-failed beside the ssf.transmitted records that did
// succeed. The audit records use record rather than recordE for the same
// reason — a full disk must not fail the kill switch's reporting path.
func transmitAgentRevocation(root string, caller *Caller, agent, why string) {
	cfg := mustConfig(root)
	receivers := ssfReceiverList(cfg)
	if len(receivers) == 0 {
		w.Human("  %stransmitting is off: no receivers are configured, so "+
			"only this store knows%s\n", dim, reset)
		return
	}
	e, err := ssfEmitter(root)
	if err != nil {
		// No key or no issuer. Recorded per receiver rather than once, so
		// the log answers "who was told about this kill" receiver by
		// receiver, which is the question somebody reading it has.
		for _, r := range receivers {
			record(root, caller.auditRecord("ssf.transmit-failed",
				"/agents/"+agent, audit.Failure, map[string]string{
					"receiver": r.URL, "error": err.Error()}))
			w.Human("  %s%s did not hear it: %v%s\n", yellow, r.URL, err, reset)
		}
		return
	}
	secrets, serr := loadSecrets(root)
	if serr != nil {
		secrets = map[string]string{}
	}
	reach := fetch.OnThisNetwork
	if cfg.Bool("ssf.transmit.allow_remote") {
		reach = fetch.Anywhere
	}
	client := fetch.Speaking("signals", reach, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, r := range receivers {
		token, jti, terr := e.SessionRevoked(agent, r.URL, why)
		if terr != nil {
			record(root, caller.auditRecord("ssf.transmit-failed",
				"/agents/"+agent, audit.Failure, map[string]string{
					"receiver": r.URL, "error": terr.Error()}))
			w.Human("  %s%s did not hear it: %v%s\n", yellow, r.URL, terr, reset)
			continue
		}
		bearer := ""
		if r.Secret != "" {
			var ok bool
			if bearer, ok = secrets[r.Secret]; !ok || strings.TrimSpace(bearer) == "" {
				record(root, caller.auditRecord("ssf.transmit-failed",
					"/agents/"+agent, audit.Failure, map[string]string{
						"receiver": r.URL, "jti": jti, "error": "no stored secret " + r.Secret}))
				w.Human("  %s%s did not hear it: no stored secret %q holds "+
					"its token%s\n", yellow, r.URL, r.Secret, reset)
				continue
			}
		}
		if derr := e.Deliver(ctx, client, r.URL, token, bearer); derr != nil {
			record(root, caller.auditRecord("ssf.transmit-failed",
				"/agents/"+agent, audit.Failure, map[string]string{
					"receiver": r.URL, "jti": jti, "error": derr.Error()}))
			w.Human("  %s%s did not hear it: %v%s\n", yellow, r.URL, derr, reset)
			w.Human("    %sthe kill stands here; the audit record says who "+
				"was not told%s\n", dim, reset)
			continue
		}
		record(root, caller.auditRecord("ssf.transmitted", "/agents/"+agent,
			audit.Success, map[string]string{"receiver": r.URL, "jti": jti}))
		w.Human("  %stold %s — session-revoked, id %s%s\n", green, r.URL,
			jti[:8], reset)
	}
}

// agentEnable restores an entry. Deliberately the administrator's act, not
// the responder's: whoever pulled the switch under pressure is exactly who
// should not be able to quietly put it back.
func agentEnable(root string, caller *Caller, args []string,
	note func(string, string, map[string]string) error) error {

	fs := flag.NewFlagSet("enable", flag.ContinueOnError)
	why := fs.String("why", "", "the reason it is being restored, on the record")
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return agentUsage()
	}
	if strings.TrimSpace(*why) == "" {
		return fmt.Errorf("enabling an agent needs --why: the register is " +
			"the review, and an entry that switched itself back on with no " +
			"word from anybody is one nobody can trust either way")
	}
	if err := agentStore(root).Enable(pos[0], caller.Name, time.Now().UTC()); err != nil {
		return err
	}
	w.Human("%s%s%s is active again\n", bold, pos[0], reset)
	// Said out loud because it is the honest limit of what was done: the
	// kill revoked the tokens, and enabling the entry does not un-revoke
	// them. That is a feature — a credential that outlived its agent's
	// disablement is a credential nobody had to think about — but only if
	// whoever enabled the entry knows a fresh one must be issued.
	w.Human("  %sits old tokens are still revoked; its owner asks for a fresh one:%s\n", dim, reset)
	w.Human("    vaigil token issue %s%s --principal %s --role viewer\n",
		agentreg.TokenPrefix, pos[0], pos[0])
	return note("agent.enable", pos[0], map[string]string{"why": *why})
}

// revokeAgentTokens marks revoked every live token bound to an agent by the
// naming convention, cascading to whatever sessions were minted from them
// (auth.TokenStore.Revoke). Returns how many of the agent's own tokens it
// killed; the cascade is the tokens' business and is not double-counted.
//
// Changed on the file as it is stored now, under its lock, so a token
// issued elsewhere since this process read the store is neither missed nor
// resurrected — the same discipline saveTokens holds.
func revokeAgentTokens(root, name string) (int, error) {
	revoked := 0
	err := atomicfile.Update(tokensPath(root), func(stored *auth.TokenStore) error {
		for _, t := range stored.Tokens {
			if t.Revoked {
				continue
			}
			if bound, ok := agentreg.Bind(t.Name); !ok || bound != name {
				continue
			}
			if _, err := stored.Revoke(t.ID); err != nil {
				return err
			}
			revoked++
		}
		return nil
	})
	return revoked, err
}

func whySuffix(revoked int) string {
	if revoked == 0 {
		return " (it held no live tokens)"
	}
	return fmt.Sprintf(" — and its %d live token(s) are revoked, so the bearers die at the next request", revoked)
}

func agentHelp() error {
	w.Human(`  Agents are registered before they act, and can be stopped as one act.

  An agent is a principal of its own: a token issued as agent:NAME binds to
  a registry entry, and every gate — the policy check included — refuses
  that token unless the entry exists, is active, and lists the tool being
  called in its allowlist. An unregistered agent is nobody.

  vaigil agent add watcher --owner dana@acme.example --allow vaigil_read
  vaigil token issue agent:watcher --principal watcher --role viewer
  The register decides who the agent is; the token is its credential, and
  the owner asks for a fresh one whenever it needs one.

  vaigil agent list                     who is registered, what each may call
  vaigil agent allow watcher --add vaigil_write
  vaigil agent allow watcher --remove vaigil_read

  The kill switch
  vaigil agent disable watcher --why "proposing nonsense on closed findings"
  This is a responder's act, deliberately: the person who needs to stop an
  agent is the one holding the pager. It disables the entry and revokes the
  agent's tokens in the same action, so the bearers die at the next request
  rather than at the next registry check. Enabling the entry back is an
  administrator's act with a reason; the old tokens stay dead either way.

  When receivers are configured (vaigil ssf receivers says who), the same
  act tells them: a signed session-revoked event reaches every one of them,
  best-effort, so a platform that trusted the agent kills its sessions too.
  A receiver that is down is recorded as not hearing it and the kill here
  stands regardless — the switch must work offline.

  There is deliberately no "disable all agents" here. A switch that turns
  off every agent at once is an availability weapon — one command, every
  responder's helper gone — and the design (docs/research/02-access-control
  §8.5) holds it behind dual control until that is built. Agents are killed
  one at a time, by name, on the record.
`)
	return nil
}
