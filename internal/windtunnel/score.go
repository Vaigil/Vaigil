// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"fmt"
	"sort"

	"github.com/aertun/aertun/internal/stats"
)

// The scoring: a miss rate with Wilson bounds over categorical outcomes, and
// the family and technique grids beneath it — never instead of it (decision
// 4).
//
// The primary number is the miss rate over must-alert scenarios, because a
// scenario that expects only quiet legs is a precision claim, not a
// detection claim, and folding it into a coverage percentage is how a
// benchmark sells telemetry as detection.

// rate is n over d, or 0 when d is 0 — no evidence reads as no evidence.
func rate(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}

// aggregate folds the rows into the scorecard's numbers: the miss rate with
// its Wilson bounds over the must-alert scenarios, the twin-false-fire
// count, and the family and technique grids.
func (c *Scorecard) aggregate() error {
	sortRows(c.Rows)
	sort.Slice(c.Scenarios, func(i, j int) bool {
		return c.Scenarios[i].ID < c.Scenarios[j].ID
	})
	sort.Slice(c.Blinds, func(i, j int) bool {
		return c.Blinds[i].Scenario < c.Blinds[j].Scenario
	})

	agg := &Aggregate{}
	families := map[string]*FamilyRow{}
	techniques := map[string]*TechniqueRow{}
	for i := range c.Rows {
		row := &c.Rows[i]
		agg.Scenarios++
		f := families[row.Family]
		if f == nil {
			f = &FamilyRow{Family: row.Family}
			families[row.Family] = f
		}
		f.Tested++
		switch row.Outcome {
		case OutcomeMissed:
			agg.MustAlert++
			agg.Missed++
			f.Missed++
			if row.MissKind() == MissLateness {
				agg.MissedLateness++
			}
		case OutcomeCaughtAlert:
			agg.MustAlert++
			agg.Caught++
			f.Caught++
		case OutcomeWronglyQuiet:
			agg.WronglyQuiet++
			f.WronglyQuiet++
		case OutcomeCaughtTelemetry:
			agg.TelemetryOnly++
			f.TelemetryOnly++
		}
		if row.Twin.Outcome == TwinFalseFire {
			agg.TwinFires++
			f.TwinFires++
		}
		for _, tech := range row.Techniques {
			tt := techniques[tech]
			if tt == nil {
				tt = &TechniqueRow{Technique: tech}
				techniques[tech] = tt
			}
			tt.Tested++
			if row.Outcome == OutcomeCaughtAlert {
				tt.Caught++
			}
		}
	}
	agg.MissRate = rate(agg.Missed, agg.MustAlert)
	agg.MissRateLow, agg.MissRateHigh = stats.Wilson(agg.Missed, agg.MustAlert)
	c.Aggregate = agg

	for _, f := range Families() {
		if row, ok := families[f]; ok {
			c.Families = append(c.Families, *row)
		}
	}
	techs := make([]string, 0, len(techniques))
	for t := range techniques {
		techs = append(techs, t)
	}
	sort.Strings(techs)
	for _, t := range techs {
		c.Techniques = append(c.Techniques, *techniques[t])
	}

	// The heatmap is the same rows as the technique grid, as words in a
	// square — computed beside them so the two cannot drift.
	c.Heatmap = buildHeatmap(c.Rows)

	// A document with no must-alert scenario has no primary number, and
	// rendering a 0% miss rate over nothing would be exactly the naked
	// percentage this schema exists to refuse.
	if agg.MustAlert == 0 {
		return fmt.Errorf("no scenario in this run carries a must-alert " +
			"expectation, so there is no miss rate to bound and no document " +
			"to seal")
	}
	return nil
}
