// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aertun/aertun/internal/analyst"
	"github.com/aertun/aertun/internal/bench"
	"github.com/aertun/aertun/internal/decide"
)

// The benchmark command: the labelled corpus, and how the analyst did on it.
//
// `run` measures a model against the corpus that ships with the program —
// the same corpus, model seam and asking path as the analyst's own triage,
// so a number here is a number about the thing that runs. Without --stub it
// uses the configured model through modelForAnalyst, the same seam the
// analyst uses, and refuses with the same honest message when none is
// configured. With --stub it runs the built-in stub, which exercises the
// pipeline's arithmetic and never the analyst; the document says so in its
// mode and model fields, because a stub's scores are not measurements.
//
// `report` renders a document a run wrote: it verifies the document's own
// digest before rendering, so a figure quoted from a report is pinned to the
// file it came from or exposed as edited.
//
// Neither subcommand opens the store. The corpus is embedded and synthetic,
// the results document is the record of a run and carries its own digest,
// and the one thing that would belong in the audit log — what the masked
// model was shown — is recorded by the model seam itself when masking
// happens. A benchmark that could not run without a store could not run in
// CI, and the stub run is for CI.

func cmdBench(root string, args []string) error {
	if len(args) == 0 {
		// No default: the model half of this command spends the model
		// budget, and a bare word on a command line should not be able
		// to do that by accident.
		return fmt.Errorf("bench needs run or report")
	}
	switch args[0] {
	case "run":
		return benchRun(root, args[1:])
	case "report":
		return benchReport(args[1:])
	default:
		return fmt.Errorf("unknown bench command %q; try run or report",
			args[0])
	}
}

func benchRun(root string, args []string) error {
	fs := flag.NewFlagSet("bench run", flag.ContinueOnError)
	stub := fs.Bool("stub", false, "run the built-in stub, which exercises "+
		"the arithmetic and measures nothing")
	out := fs.String("out", "", "write the results document to FILE")
	k := fs.Int("k", 3, "how many times each case is run (pass^k); 1 for a "+
		"cheaper run against a real model")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *k < 1 || *k > analyst.MaxK {
		return fmt.Errorf("--k is between 1 and %d", analyst.MaxK)
	}
	corpus, err := bench.Load()
	if err != nil {
		return err
	}
	var m decide.Model
	mode := bench.ModeModel
	if *stub {
		m = &bench.Stub{}
		mode = bench.ModeStub
	} else {
		// The same seam as the analyst, for the same reason: one place
		// where the model comes from, so a benchmark number and a triage
		// suggestion are always about the same configured model. And the
		// refusal is the analyst's own message, not a new one written
		// here that would drift from it.
		var why string
		m, why = modelForAnalyst(root)
		if m == nil {
			return fmt.Errorf("%s", why)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	res, err := bench.Run(ctx, m, corpus, mode, *k, time.Now().UTC())
	if err != nil {
		return err
	}
	doc, err := res.Document()
	if err != nil {
		return err
	}
	if *out != "" {
		// 0o600 like every operator-named document: a benchmark names the
		// model and the corpus, and the file convention here does not
		// distinguish documents by how sensitive they are today.
		if err := os.WriteFile(*out, doc, 0o600); err != nil {
			return err
		}
	}
	if w.JSON(res) {
		return nil
	}
	w.Human("%s", res.Summarize())
	if *out != "" {
		w.Human("  %swritten to %s; render it again with bench report%s\n",
			dim, *out, reset)
	}
	if mode == bench.ModeStub {
		w.Human("  %sstub mode exercises the arithmetic, never the "+
			"analyst: every score above is a hash landing where it landed%s\n",
			dim, reset)
	}
	return nil
}

func benchReport(args []string) error {
	fs := flag.NewFlagSet("bench report", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("report takes one FILE, the document a run wrote")
	}
	b, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var res bench.Results
	dec := json.NewDecoder(strings.NewReader(string(b)))
	// A field this schema does not know is a document from a later release
	// wearing this one's number; rendering it without the fields that made
	// its numbers would be the same as inventing them.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&res); err != nil {
		return fmt.Errorf("%s is not a benchmark document: %w", fs.Arg(0),
			err)
	}
	if err := res.Verify(); err != nil {
		return fmt.Errorf("%s: %w", fs.Arg(0), err)
	}
	if w.JSON(res) {
		return nil
	}
	w.Human("%s", res.Summarize())
	return nil
}
