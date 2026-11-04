// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Command aeroprove is security operations for the systems an organisation
// runs: collection, detection, cases, response and vulnerability
// management, with the command line, the console and the agent interface in
// one binary. Every action is on the command line, so a person, a script and
// an agent reach the same things.
package main

import (
	"errors"
	"fmt"
	"github.com/aeroprove/aeroprove/internal/egress"
	"os"
	"strings"

	"github.com/aeroprove/aeroprove/internal/out"
)

const defaultRoot = ".aeroprove"

// Colours are resolved at startup from whether stdout is a terminal, so piping
// or capturing output yields clean text. They were unconditional constants
// before, which put escape codes into every captured demo in this project's
// own history.
var (
	bold, dim, green, yellow, red, reset string
	w                                    *out.Writer

	// flagToken holds a --token given anywhere on the command line.
	//
	// Set by the global pass in main, which also removes it, so every
	// subcommand accepts it and none has to declare it. Read through
	// tokenFromArgs so the one authorisation call site did not have to change.
	flagToken string
)

func overrideNote(forced bool, reason string) string {
	if !forced {
		return ""
	}
	return reason
}

// errBlocked marks a refusal by a gate rather than a failure of the command.
type errBlocked struct{ error }

func (e errBlocked) Unwrap() error { return e.error }

var version = "dev"

func usage() {
	fmt.Print(`aeroprove — the wind tunnel for AI agents
  (the short name apv runs this same binary: apv serve, apv windtunnel run)

  aeroprove init [--admin NAME]               create a store, and its first administrator
  aeroprove serve [--addr HOST:PORT]          the console, on loopback by default
  aeroprove mcp [--list]                      the agent interface, over stdio

Collecting what happens
  aeroprove connect catalogue | list          the connectors that ship, and those installed
  aeroprove connect add NAME [--region R]     install a shipped connector as a readable file
  aeroprove connect secret NAME               store a credential, from the environment
  aeroprove connect check NAME|FILE           read a manifest and say what it may touch
  aeroprove connect probe NAME ENDPOINT       what shape a tool's response is, never its values
  aeroprove connect run NAME [ENDPOINT] [--save]   pull records, one JSON object per line
  aeroprove collect run [SOURCE]              read each platform's new log records, map them, store them
  aeroprove collect file ISSUER/STREAM FILE   the same for a log that arrives as a file
  aeroprove collect status | auto 15m|off     what each source did last, and the schedule
  aeroprove source list | add MAPPING.json --sample RECORDS.json | check --source S RECORDS.json
  aeroprove telemetry check [FILE] | fields [FILE]   can a source's events be used, and what a rule may name
  aeroprove inbound list | add okta|webhook|ssf|quilzo NAME | connect NAME | verify NAME | status NAME
  aeroprove inbound rotate NAME | on NAME | off NAME | remove NAME | help
  aeroprove spool add [FILE] | stats | verify | retain [--apply] | hold NAME --why W | lift NAME
  aeroprove identity list | link ISSUER:VALUE PERSON@… | unlink ISSUER:VALUE

Detecting and deciding
  aeroprove detect test | list | fields | run [--rules DIR] | stats | pack [install]
  aeroprove detect ring RULE live|trial|off --because "…"   move a rule in or out of the queue
  aeroprove detect suppress RULE FIELD=VALUE --owner W --until DATE --because "…" | unsuppress ID | suppressions
  aeroprove detect replay [--strict] | learn FINDING
  aeroprove content keygen | rotate-root | sign DIR | verify DIR | install DIR | list [DIR] | installed | rollback
                                        signed detection packs, updated without a binary release
  aeroprove sigma import ./rules              bring your own detections, in the open standard
  aeroprove correlate demo                    detections about several events, and when a window closes
  aeroprove triage [FILE] --rules DIR         run the rules, rank what they found
  aeroprove hunt --field F [FILE]             what is rare, which is what is worth a look
  aeroprove finding list [--state S --kind K] | risk | decide ID STATE | story [ID]
  aeroprove intel import FILE --source NAME | add VALUE --source NAME | list | remove ID
  aeroprove analyst plan | triage [--limit N] [--dry-run] | eval [--k 3]
  aeroprove bench run [--stub] [--out F] [--k N] | report FILE   the labelled corpus, and how the analyst scored on it
  aeroprove windtunnel list-scenarios | preflight | run | scorecard | verify   breach simulation by replay, scored and signed
  aeroprove automate list | templates | add TEMPLATE | runs   rules: when this happens, do this
  aeroprove automate mode ID watch|ask|act | on ID | off ID | remove ID | approve RUN | decline RUN
  aeroprove geo status | network add PREFIX NAME --kind office|vpn | network remove PREFIX | help   where sign-ins come from

Cases and response
  aeroprove incident declare --title T --grade sev2 [--finding ID]   open one, under the regimes set
  aeroprove incident list | show ID | decide ID aware --because "…" | discharge|waive ID "REGIME" --because "…"
  aeroprove incident note|assign|link|watch|reopen|close ID …   the rest of the record
  aeroprove incident playbooks [show ID | check FILE] | propose|approve|withdraw ID PLAYBOOK
  aeroprove incident step ID PLAYBOOK STEP done|skip|undo --because "…"
  aeroprove incident act ID ACTION ISSUER:VALUE --because "…" | act-approve ID N
  aeroprove incident regimes [eu nis2 …] | duties | demo
  aeroprove action catalogue | list | add NAME --org ORG | remove NAME
  aeroprove notify add|object|erase ISSUER:VALUE | contacts | draft --kind K --subject S | list
  aeroprove notify plan|send|publish NOTICE | inbox ISSUER:VALUE
  aeroprove work demo                         four states, and what the other statuses really were

Vulnerabilities and code
  aeroprove vuln load | import [--bom F --where A] [--osv P] [--kev F] [--epss F] | reach --source DIR --where A
  aeroprove vuln queue [INVENTORY] | plan | why CVE-ID | reasons | assets | ssvc-tree FILE
  aeroprove vuln asset MATCH --exposure E --impact I --because "…"
  aeroprove vuln assess CVE PKG STATUS | accept CVE PKG --owner W --until DATE --because "…"
  aeroprove vuln vex --author A --id URL      the decisions as an OpenVEX draft
  aeroprove feed status                       what the scanner is working from, and how old it is
  aeroprove sca scan --bom sbom.json --osv db.json   which dependencies you can actually fix
  aeroprove sarif read results.sarif          import any scanner's findings, and what it left out
  aeroprove appsec triage | gate | accept ALERTS.jsonl | rotated FINGERPRINT

The estate and its people
  aeroprove estate show | build | scores [--limit N] | sync [--remind] | auto --every 24h | sample [--remove]
  aeroprove workforce coverage | propose | people | gaps [FILE] | link A B --because W
  aeroprove remind preview | enable | disable | send
  aeroprove vendor list | show ID | reconcile | review ID
  aeroprove access open ID [FILE] --scope S | items ID | decide ID ACCOUNT VERDICT | close ID [FILE] | list

People, sign-in and changes
  aeroprove auth grant WHO ROLE [--on PATH]   viewer | analyst | responder | admin
  aeroprove auth grant WHO JOB [--for 30d]    engineer | vuln-manager | auditor (must end)
  aeroprove auth deny|revoke WHO ROLE [--on PATH] | explain WHO [ACTION] | list | roles
  aeroprove auth enrol WHO [--for 24h]        a one-time link that adds their passkey (--revoke ends it)
  aeroprove auth unlock WHO                   let them sign in again after a lockout
  aeroprove auth recover                      break-glass when every admin token is lost
  aeroprove oidc configure | status | check   sign in with an OpenID Connect provider
  aeroprove saml add | list | show | metadata | presets | remove   sign in with a SAML provider
  aeroprove scim status | token | map GROUP ROLE|JOB | unmap GROUP   provisioning from your identity provider
  aeroprove token issue NAME --principal WHO | exchange | keygen FILE | proof | list | revoke ID | stale
  aeroprove agent list | add NAME --owner WHO --allow TOOL | allow NAME --add|--remove TOOL | maps NAME --host HOST | disable NAME --why "…" | enable NAME --why "…" | token NAME --tools TOOL[,TOOL] --for-run ID | consents [revoke ID] | help
                                        the register of AI agents: who runs, what each may call, where each runs, one kill switch each, what was consented to
  aeroprove ssf receivers | key | send NAME --why "…" | help
                                        where the kill switch is announced: receivers hearing session-revoked
  aeroprove pending [list] | approve | decline | withdraw | redeem ID   privileged changes, approved by a second administrator
  aeroprove approvals                         everything waiting for you to decide

Its own record and settings
  aeroprove privacy export SUBJECT [--out FILE] [--audit] [--pseudonym p_…] | statement
                                        a data subject's events as a handover document, and the honest privacy posture
  aeroprove auditlog dir | verify | show SEQ | export -o FILE | head --save | verify-head FILE | prove SEQ | consistency
  aeroprove auditlog anchor [submit|upgrade|status]   the log head, committed to Bitcoin
  aeroprove logd [status]                     the log writer, run as its own account
  aeroprove siem ocsf|cef|jsonl --envelope F | verify FILE --envelope F   its own audit log, still verifiable
  aeroprove siem stream [status] | key | send  its own audit log, pushed to a SIEM as it is written
  aeroprove compliance controls | evidence CONTROL [--out FILE] | verify FILE [--keys KEYS]
                                        SP 800-53: the map, and evidence packs proved from the signed log
  aeroprove vault status | enable | rotate | rewrap   the keyring credentials are sealed under
  aeroprove config show | list | explain KEY | set KEY VALUE | unset KEY
  aeroprove network                           what this may connect to, and whether
  aeroprove version                           what this binary is
  aeroprove --version                         version, copyright and licence
  aeroprove -V                                the same, shorter
  aeroprove --help | help                     this list

Every command takes --json, --root DIR and --token T.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	// --json is global rather than per-command, because a caller scripting this
	// should not have to remember which subcommands happen to support it.
	args := os.Args[1:]
	jsonMode := false
	filtered := args[:0]
	for _, a := range args {
		if a == "--json" {
			jsonMode = true
			continue
		}
		filtered = append(filtered, a)
	}
	args = filtered

	w = out.New(jsonMode)
	bold, dim = w.Bold(), w.Dim()
	green, yellow, red, reset = w.Green(), w.Yellow(), w.Red(), w.Reset()

	root := defaultRoot
	// A tiny hand-rolled global flag pass, so `--root` and `--token` work
	// before the subcommand as well as after it.
	//
	// --token is here because it was read globally and removed nowhere. The
	// authorisation check picked it out of the raw arguments, then handed the
	// same arguments to the subcommand's own flag set — which rejected an
	// undeclared flag. Seven of eighty-one flag sets declared it, so `publish
	// --token X` worked and `add --token X` exited 1 with "flag provided but
	// not defined: -token".
	//
	// The command that mattered most was the one printing the advice. Every
	// refusal in this program ends "Present one with --token,
	// ~/.aeroprove/token, or AEROPROVE_TOKEN", and for `aeroprove add` on a store with
	// access control the first of those three could not be done at all.
	//
	// Stripping it here makes the sentence true everywhere, and the seven
	// local declarations are gone rather than left to shadow it.
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--root" && i+1 < len(args) {
			root = args[i+1]
			i++
			continue
		}
		if v, ok := strings.CutPrefix(args[i], "--root="); ok {
			root = v
			continue
		}
		if args[i] == "--token" && i+1 < len(args) {
			flagToken = args[i+1]
			i++
			continue
		}
		if v, ok := strings.CutPrefix(args[i], "--token="); ok {
			flagToken = v
			continue
		}
		rest = append(rest, args[i])
	}
	if len(rest) == 0 {
		usage()
		os.Exit(2)
	}

	cmd, cmdArgs := rest[0], rest[1:]

	// The network boundary, applied once for every command before any of them
	// runs.
	//
	// Here rather than in the two servers, because an isolated deployment is
	// not only a running site: `import`, `fediverse`, `auditlog anchor` and
	// the chat bots all reach the network from the command line, and a
	// boundary that only the server honoured would be one somebody steps over
	// by running a command.
	//
	// A mode that cannot be read leaves the default. Refusing to run because
	// a config file is unreadable would make an unrelated fault look like a
	// network policy.
	if cfg, cerr := loadConfig(root); cerr == nil {
		if m := strings.TrimSpace(cfg.Raw("network.mode")); m != "" {
			if serr := egress.SetMode(egress.Mode(m)); serr != nil {
				fmt.Fprintf(os.Stderr,
					"network.mode is %q; it is open or offline\n", m)
				os.Exit(2)
			}
		}
	}

	// Authorisation happens here, once, for every command. See privilege.go
	// for why it is a table rather than a call at the top of each one.
	if cmd != "help" && cmd != "-h" && cmd != "--help" {
		if err := authoriseCommand(root, cmd, cmdArgs); err != nil {
			w.Error(err)
			os.Exit(out.ExitFailure)
		}
	}

	var err error
	switch cmd {
	case "init":
		_, existed := os.Stat(root)
		if err = cmdInit(root); err == nil {
			err = initAdmin(root, cmdArgs, existed != nil)
		}
	case "auditlog":
		err = cmdAuditLog(root, cmdArgs)
	case "network":
		err = cmdNetwork(root, cmdArgs)
	case "logd":
		if len(cmdArgs) > 0 && cmdArgs[0] == "status" {
			err = cmdLogdStatus(root)
		} else {
			err = cmdLogd(root, cmdArgs)
		}
	case "oidc":
		err = cmdOIDC(root, cmdArgs)
	case "saml":
		err = cmdSAML(root, cmdArgs)
	case "siem":
		if len(cmdArgs) > 0 && cmdArgs[0] == "verify" {
			err = cmdSiemVerify(root, cmdArgs[1:])
		} else if len(cmdArgs) > 0 && cmdArgs[0] == "stream" {
			err = cmdSiemStream(root, cmdArgs[1:])
		} else {
			err = cmdSiem(root, cmdArgs)
		}
	case "detect":
		err = cmdDetect(root, cmdArgs)
	case "hunt":
		err = cmdHunt(root, cmdArgs)
	case "triage":
		err = cmdTriage(root, cmdArgs)
	case "finding":
		err = cmdFinding(root, cmdArgs)
	case "scim":
		err = cmdSCIM(root, cmdArgs)
	case "automate":
		err = cmdAutomate(root, cmdArgs)
	case "geo":
		err = cmdGeo(root, cmdArgs)
	case "telemetry":
		err = cmdTelemetry(root, cmdArgs)
	case "inbound":
		err = cmdInbound(root, cmdArgs)
	case "spool":
		err = cmdSpool(root, cmdArgs)
	case "privacy":
		err = cmdPrivacy(root, cmdArgs)
	case "notify":
		err = cmdNotify(root, cmdArgs)
	case "estate":
		err = cmdEstate(root, cmdArgs)
	case "remind":
		err = cmdRemind(root, cmdArgs)
	case "workforce":
		err = cmdWorkforce(root, cmdArgs)
	case "connect":
		err = cmdConnect(root, cmdArgs)
	case "vuln":
		err = cmdVuln(root, cmdArgs)
	case "intel":
		err = cmdIntel(root, cmdArgs)
	case "collect":
		err = cmdCollect(root, cmdArgs)
	case "identity":
		err = cmdIdentity(root, cmdArgs)
	case "action":
		err = cmdAction(root, cmdArgs)
	case "analyst":
		err = cmdAnalyst(root, cmdArgs)
	case "bench":
		err = cmdBench(root, cmdArgs)
	case "windtunnel":
		err = cmdWindtunnel(root, cmdArgs)
	case "vendor":
		err = cmdVendor(root, cmdArgs)
	case "access":
		err = cmdAccess(root, cmdArgs)
	case "appsec":
		err = cmdAppsec(root, cmdArgs)
	case "work":
		err = cmdWork(cmdArgs)
	case "sigma":
		err = cmdSigma(cmdArgs)
	case "sarif":
		err = cmdSarif(cmdArgs)
	case "sca":
		err = cmdSCA(cmdArgs)
	case "correlate":
		err = cmdCorrelate(cmdArgs)
	case "incident":
		err = cmdIncident(root, cmdArgs)
	case "pending":
		err = cmdPending(root, cmdArgs)
	case "feed":
		err = cmdFeed(cmdArgs)
	case "content":
		err = cmdContent(root, cmdArgs)
	case "source":
		err = cmdSource(root, cmdArgs)
	case "mcp":
		err = cmdMCP(root, cmdArgs)
	case "serve":
		err = cmdServe(root, cmdArgs)
	case "auth":
		err = cmdAuth(root, cmdArgs)
	case "token":
		err = cmdToken(root, cmdArgs)
	case "agent":
		err = cmdAgent(root, cmdArgs)
	case "ssf":
		err = cmdSSF(root, cmdArgs)
	case "vault":
		err = cmdVault(root, cmdArgs)
	case "config":
		err = cmdConfig(root, cmdArgs)
	case "approvals":
		err = cmdApprovals(root, cmdArgs)
	case "compliance":
		err = cmdCompliance(root, cmdArgs)
	// --version and --help as well as the subcommands.
	//
	// The GNU Coding Standards ask for both as options, and the reason is not
	// ceremony: a script or a packaging tool checking a program's version
	// tries `--version` and nothing else. `aeroprove version` printed the same
	// string and was unreachable to everything that looks for it.
	case "version", "--version", "-V":
		fmt.Printf("aeroprove %s\n", version)
		fmt.Println("Copyright (C) 2026 Rashik Adhikari")
		fmt.Println("Licensed under the Apache License, Version 2.0 " +
			"<https://www.apache.org/licenses/LICENSE-2.0>.")
		fmt.Println("There is NO WARRANTY, to the extent permitted by law.")
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		w.Error(err)
		// A gate refusing is a different outcome from the command breaking, and
		// a caller branching on exit status should be able to tell which.
		var blocked errBlocked
		if errors.As(err, &blocked) {
			os.Exit(out.ExitBlocked)
		}
		os.Exit(out.ExitFailure)
	}
}

// open is the one place any command gets a store, which is why encryption is
// wired here: every command inherits it, including the ones added next year by
// somebody who has not read this file.
// reorder moves flags ahead of positional arguments.
//
// Go's flag package stops parsing at the first non-flag argument, so
// `add index=home.json -m "msg"` treats -m as a filename. That is the natural
// order to type and the CLI has to accept it, so flags are lifted out first.
// `valued` names the flags that consume the following argument; a boolean flag
// must not swallow the token after it.
func reorder(args []string, valued map[string]bool) []string {
	flags, positional := splitFlags(args, valued)
	return append(flags, positional...)
}

// splitFlags separates the flags, and the values they consume, from the
// positional arguments.
//
// Pulled out of reorder because the privilege gate needs the positional
// arguments too: it has to know which page a command is about before the
// command has parsed anything, so that a grant or a deny scoped to part of the
// site is enforced here as well as in the browser.
//
// One function rather than two readings of the same arguments. A second copy
// of "which flags take a value" would drift, and a drifted copy reads as a
// page name the word the command reads as a flag value — which authorises one
// resource and acts on another, and a check on the wrong resource is not a
// check.
func splitFlags(args []string, valued map[string]bool) (flags, positional []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if n, _, hasEq := strings.Cut(name, "="); hasEq {
			_ = n
			continue // --flag=value carries its own value
		}
		if valued[name] && i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return flags, positional
}

// cmdInit makes the store: a directory private to this account, with the
// detection rules that ship.
func cmdInit(root string) error {
	// main builds the writer; a test calling this first has not.
	if w == nil {
		w = out.New(false)
	}
	_, existed := os.Stat(root)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	if existed != nil {
		w.Human("created %s\n", root)
		return ensureRules(root, "init")
	}
	w.Human("reusing %s\n", root)
	return nil
}
