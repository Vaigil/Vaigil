// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vaigil/vaigil/internal/indicator"
	"github.com/vaigil/vaigil/internal/out"
	"github.com/vaigil/vaigil/internal/telemetry"
)

// BenchmarkDetectRun is one full pass as the server runs it: a first run
// over a store nobody has run against, so every window is new work for the
// rules, the correlations and the indicators together. The site is built
// untimed; only the run is measured, and a fresh site each iteration keeps
// the cursors from making later iterations cheaper than the first.
func BenchmarkDetectRun(b *testing.B) {
	if w == nil {
		w = out.New(false)
	}
	t0 := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	var corpus []labelled
	for i := range 5000 {
		e := signIn("okta/system", fmt.Sprintf("user-%d", i%200),
			telemetry.DispositionFailed, "sign-in failed",
			t0.Add(time.Duration(i)*time.Second))
		if i%50 == 0 {
			e.Observables = []telemetry.Observable{{
				Kind:  telemetry.ObservableIP,
				Value: fmt.Sprintf("203.0.113.%d", i%254+1), Name: "dst"}}
		}
		corpus = append(corpus, labelled{fmt.Sprintf("e%d", i), i%50 == 0, e})
	}
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		root, rules := siemSite(b, corpus)
		if err := os.WriteFile(filepath.Join(rules, "spray.yml"),
			[]byte(sprayCorrelation), 0o600); err != nil {
			b.Fatal(err)
		}
		bad, err := indicator.New(indicator.IP, "203.0.113.9", "cert", "",
			time.Time{}, time.Time{}, time.Now().UTC())
		if err != nil {
			b.Fatal(err)
		}
		if err := saveIndicators(root, indicator.NewSet([]indicator.Indicator{bad})); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		if err := detectRun(root, []string{"--rules", rules}); err != nil {
			b.Fatal(err)
		}
	}
}
