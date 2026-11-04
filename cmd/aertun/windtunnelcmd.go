// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/pack"
	"github.com/aertun/aertun/internal/telemetry"
	"github.com/aertun/aertun/internal/windtunnel"
)

// The wind tunnel: scripted malicious-agent sessions spliced into a recorded
// stream, measured by whether the reference pack caught them, and written up
// as a sealed, dual-signed scorecard. It attests test results, never
// production actions.
//
// # The shape this command inherits from the bench command
//
// No subcommand opens the store. The scenario corpus is embedded, the base
// stream defaults to a synthetic morning that ships with the program, and
// the scratch spools a run writes go to a directory the operator named or a
// temporary one — never the live store. A benchmark that could not run in CI
// could not gate anything, and a replay that needed the store would need the
// estate it is only pretending to attack.
//
// And no bare word starts anything. `run` is the one subcommand that could
// someday spend something (phase 3's live fire), so it is a word somebody
// types on purpose, with flags they chose — the model-budget discipline of
// `bench`, held for the blast-radius discipline this command will need.
//
// `scorecard` and `verify` are offline by construction: a document carries
// its own digest and both signatures, so a third party with the file and a
// public key needs nothing from this deployment, and CI can gate on
// `verify`'s exit code alone.
func cmdWindtunnel(root string, args []string) error {
	if len(args) == 0 {
		// No default: the one subcommand that writes a scratch spool and a
		// signed document should never start because a bare word was typed.
		return fmt.Errorf("windtunnel needs list-scenarios, preflight, run, " +
			"scorecard or verify")
	}
	switch args[0] {
	case "list-scenarios":
		return windtunnelList()
	case "preflight":
		return windtunnelPreflight(args[1:])
	case "run":
		return windtunnelRun(args[1:])
	case "scorecard":
		return windtunnelScorecard(args[1:])
	case "verify":
		return windtunnelVerify(args[1:])
	default:
		return fmt.Errorf("unknown windtunnel command %q; try list-scenarios, "+
			"preflight, run, scorecard or verify", args[0])
	}
}

// windtunnelCorpus loads the reference pack and the corpus validated against
// it — the one loader every subcommand starts from, so a scenario meets the
// same refusal everywhere.
func windtunnelCorpus() ([]*windtunnel.Loaded, error) {
	ref, err := windtunnel.LoadReference()
	if err != nil {
		return nil, err
	}
	return windtunnel.Corpus(ref)
}

// windtunnelBaseStream resolves the --over flag: the recorded stream the
// operator named, or the synthetic morning that ships with the program.
func windtunnelBaseStream(over string) ([]telemetry.Event, error) {
	if over == "" {
		return windtunnel.DefaultBase(), nil
	}
	return windtunnel.ReadBase(over)
}

// windtunnelBaseName is what the screens call the base stream.
func windtunnelBaseName(over string) string {
	if over == "" {
		return windtunnel.FixtureName
	}
	return filepath.Base(over)
}

func windtunnelList() error {
	corpus, err := windtunnelCorpus()
	if err != nil {
		return err
	}
	if w.JSON(corpus) {
		return nil
	}
	w.Human("%d scenario(s), corpus %s — every one replay-only and "+
		"synthetic-only, every one with its benign twin:\n", len(corpus),
		windtunnel.CorpusName)
	for _, l := range corpus {
		sc := l.Scenario
		w.Human("  %-38s %s\n", sc.ID, sc.Title)
		w.Human("      family %s, %s; catalogue %s; techniques %s\n", sc.Family,
			sc.Safety, sc.Catalogue, strings.Join(sc.Technique, ", "))
		w.Human("      twin %s\n", sc.Twin.ID)
	}
	return nil
}

func windtunnelPreflight(args []string) error {
	fs := flag.NewFlagSet("windtunnel preflight", flag.ContinueOnError)
	scenario := fs.String("scenario", "", "the scenario id to check, as "+
		"list-scenarios names it")
	over := fs.String("over", "", "the recorded base stream to check "+
		"against: a JSONL file or a directory of spool segments. The "+
		"synthetic morning that ships with the program is the default")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scenario == "" {
		return fmt.Errorf("preflight needs --scenario ID: the checks are " +
			"what one scenario declared, asked of one base stream")
	}
	corpus, err := windtunnelCorpus()
	if err != nil {
		return err
	}
	l := windtunnel.ByID(corpus, *scenario)
	if l == nil {
		return fmt.Errorf("there is no scenario called %q in the seed corpus; "+
			"list-scenarios names what ships", *scenario)
	}
	base, err := windtunnelBaseStream(*over)
	if err != nil {
		return fmt.Errorf("reading the base stream: %w", err)
	}
	// Preflight refuses on the first check that fails, so reaching the
	// summary means every check held — including the two collision checks
	// every scenario pays for whether it declared them or not.
	if err := windtunnel.Preflight(l.Scenario, base); err != nil {
		return err
	}
	if w.JSON(map[string]any{"scenario": l.Scenario.ID,
		"base": windtunnelBaseName(*over), "held": true}) {
		return nil
	}
	w.Human("%s over %s: every check held\n", l.Scenario.ID,
		windtunnelBaseName(*over))
	for _, p := range l.Scenario.Preflight {
		switch p.Check {
		case windtunnel.CheckSourceEmits:
			w.Human("  the base stream carries events from %s\n", p.Source)
		case windtunnel.CheckToolLabelled:
			w.Human("  the base stream has carried the tool %s labelled %s\n",
				p.Tool, p.Label)
		}
	}
	w.Human("  the generated session identity collides with nothing in the " +
		"stream\n")
	return nil
}

func windtunnelRun(args []string) error {
	fs := flag.NewFlagSet("windtunnel run", flag.ContinueOnError)
	scenario := fs.String("scenario", "", "the scenario id to run; a "+
		"comma-separated list runs several; empty runs the whole seed corpus")
	over := fs.String("over", "", "the recorded base stream to splice into: "+
		"a JSONL file or a directory of spool segments. The synthetic "+
		"morning that ships with the program is the default")
	into := fs.String("into", "", "the scratch root for the spliced spools "+
		"(a temporary directory is made when empty); the live store is "+
		"never written")
	seed := fs.Int64("seed", 7, "the seed the arrival-delay draws come "+
		"from; the same base stream, scenarios and seed splice to the "+
		"same bytes")
	score := fs.String("score", "", "the scoring mode: reference (the "+
		"default) — this program's own pack as the calibrated instrument")
	key := fs.String("key", "", "a dual key file to sign the scorecard with "+
		"(both algorithms, in the wind tunnel's own context); without it "+
		"the document is written unsigned and says so")
	publicKey := fs.String("public-key", "", "with --key, where to write "+
		"the public half for the verifiers you hand the scorecard to")
	out := fs.String("out", "", "write the scorecard document to FILE")
	drafts := fs.String("draft-misses", "", "after the run, draft a "+
		"detection for every miss whose events the telemetry carried: a "+
		"proposal rule per draft in DIR, in the pack's own format, with "+
		"must-match fixtures from the scenario's own events and "+
		"must-not-match from its benign twin's, plus the audit record. The "+
		"loop proposes and never deploys — a person promotes through the "+
		"ring — and a miss the telemetry cannot distinguish from its twin "+
		"is declared a gap, not forced into a rule")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *publicKey != "" && *key == "" {
		return fmt.Errorf("--public-key needs --key: the file it writes is " +
			"the public half of the key that signed, and there is no " +
			"point publishing the verification half of nothing")
	}
	var ids []string
	for _, id := range strings.Split(*scenario, ",") {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	opts := windtunnel.RunOptions{Scenarios: ids, Base: *over, Into: *into,
		Seed: *seed, ScoreMode: *score, Now: time.Now().UTC()}
	if *key != "" {
		k, err := pack.LoadKey(*key)
		if err != nil {
			return err
		}
		opts.Signer = k
	}
	card, err := windtunnel.Run(opts)
	if err != nil {
		return err
	}
	// The purple loop, when it was asked for: the run's misses drafted into
	// proposals in the named directory. It runs after the scorecard is
	// sealed because its fixtures are the run's own placed events and its
	// replay is over the run's own scratch spools — the draft is a function
	// of evidence the scorecard attests, and drafting anywhere else in the
	// command would be drafting from a memory.
	var purple []windtunnel.DraftRecord
	if *drafts != "" {
		ref, err := windtunnel.LoadReference()
		if err != nil {
			return err
		}
		purple, err = windtunnel.Draft(card, ref, windtunnel.DraftOptions{
			Dir: *drafts})
		if err != nil {
			return fmt.Errorf("drafting the run's misses: %w", err)
		}
	}
	doc, err := card.Document()
	if err != nil {
		return err
	}
	if *out != "" {
		// 0o600 like every operator-named document: a scorecard names the
		// estate's stream and the detections that did and did not catch a
		// scripted attack on it.
		if err := os.WriteFile(*out, doc, 0o600); err != nil {
			return err
		}
	}
	if *publicKey != "" {
		if err := windtunnel.WritePublicKey(*publicKey,
			opts.Signer.PublicKey()); err != nil {
			return err
		}
	}
	// The JSON shape grows the loop's records when drafting was asked for,
	// and stays exactly the scorecard when it was not — a caller's parse
	// should not move because a flag it never passed exists.
	if purple == nil {
		if w.JSON(card) {
			return nil
		}
	} else if w.JSON(map[string]any{"scorecard": card, "purple": purple}) {
		return nil
	}
	w.Human("%s", card.Summarize())
	if purple != nil {
		windtunnelPurpleScreen(purple, *drafts)
	}
	if *out != "" {
		w.Human("  %swritten to %s; render it again with windtunnel "+
			"scorecard%s\n", dim, *out, reset)
	}
	if *publicKey != "" {
		w.Human("  %spublic half written to %s; a verifier needs it, the "+
			"document, and nothing from this deployment%s\n", dim,
			*publicKey, reset)
	}
	return nil
}

// windtunnelPurpleScreen renders the loop's ledger under the scorecard it
// answered: each draft with the counts a person reads before promoting, each
// declared gap with its sentence. The refusal is printed as prominently as
// the draft — a gap honestly declared is a result, not an apology.
func windtunnelPurpleScreen(purple []windtunnel.DraftRecord, dir string) {
	drafted, refused := 0, 0
	for _, r := range purple {
		if r.Outcome == windtunnel.DraftOutcomeDrafted {
			drafted++
			continue
		}
		refused++
	}
	w.Human("  purple loop: %d draft(s), %d declared gap(s)\n", drafted,
		refused)
	for _, r := range purple {
		if r.Outcome == windtunnel.DraftOutcomeDrafted {
			w.Human("    %sdrafted %s%s — %s/%s.json\n", bold, r.RuleID,
				reset, dir, r.RuleID)
			w.Human("      %sfixtures %d matched, %d refused; caught the "+
				"session %d fire(s) above ambient; ambient %d on the "+
				"base stream%s\n", dim, r.MatchFixtures, r.RefuseFixtures,
				r.CaughtFires, r.AmbientFires, reset)
			w.Human("      %spromote by copying the proposal into the "+
				"pack, on the record — the loop deploys nothing%s\n", dim,
				reset)
			continue
		}
		w.Human("    %srefused %s%s\n", bold, r.Scenario, reset)
		w.Human("%s\n", wrapAt(r.Reason, 72, "      "))
	}
}

func windtunnelScorecard(args []string) error {
	fs := flag.NewFlagSet("windtunnel scorecard", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("scorecard takes one FILE, the document a run wrote")
	}
	b, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var card windtunnel.Scorecard
	dec := json.NewDecoder(strings.NewReader(string(b)))
	// A field this schema does not know is a document from a later release
	// wearing this one's number; rendering it without the fields that made
	// its numbers would be the same as inventing them.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&card); err != nil {
		return fmt.Errorf("%s is not a scorecard: %w", fs.Arg(0), err)
	}
	// The digest check before any number is rendered: a figure quoted from
	// an edited scorecard is a figure somebody typed in wearing a digest.
	if err := card.Verify(); err != nil {
		return fmt.Errorf("%s: %w", fs.Arg(0), err)
	}
	if w.JSON(card) {
		return nil
	}
	w.Human("%s", card.Summarize())
	return nil
}

func windtunnelVerify(args []string) error {
	fs := flag.NewFlagSet("windtunnel verify", flag.ContinueOnError)
	key := fs.String("key", "", "the public key file the signer published "+
		"(a run writes it with --public-key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("verify takes one FILE, the scorecard a run wrote")
	}
	if *key == "" {
		return fmt.Errorf("verify needs --key FILE: a signature is checked " +
			"against a public key the verifier was handed, and trusting " +
			"the document to supply its own verifier would be the forgery " +
			"this command exists to refuse")
	}
	b, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var card windtunnel.Scorecard
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&card); err != nil {
		return fmt.Errorf("%s is not a scorecard: %w", fs.Arg(0), err)
	}
	if err := card.Verify(); err != nil {
		return fmt.Errorf("%s: %w", fs.Arg(0), err)
	}
	if card.Signature == nil {
		return fmt.Errorf("%s carries no signature: it was written without "+
			"a key and says so itself. An unsigned document makes no claim "+
			"a signature would back, and there is nothing here to verify",
			fs.Arg(0))
	}
	pub, err := windtunnel.LoadPublicKey(*key)
	if err != nil {
		return err
	}
	if err := windtunnel.VerifyScorecard(&card, *card.Signature, pub); err != nil {
		return fmt.Errorf("%s: %w", fs.Arg(0), err)
	}
	if w.JSON(map[string]any{"verified": card.SHA256,
		"key": card.Signature.KeyID}) {
		return nil
	}
	w.Human("verified: both signatures hold, in context %s, by key %s; "+
		"document sha256 %s…\n", windtunnel.ScorecardContext,
		card.Signature.KeyID, card.SHA256[:12])
	return nil
}
