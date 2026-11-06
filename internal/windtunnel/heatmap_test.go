// SPDX-FileCopyrightText: 2026 Rashik Adhikari
//
// SPDX-License-Identifier: Apache-2.0

package windtunnel

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// heatCard is a full-corpus run at a fixed moment, the document whose
// grid every assertion reads.
func heatCard(t *testing.T) *Scorecard {
	t.Helper()
	card, err := Run(RunOptions{Seed: 7,
		Now: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	return card
}

// The grid is complete and honest: one row per technique any scenario
// stages, one cell per scenario in the run — a word from the closed set
// in every cell, na where the scenario does not stage the technique —
// and the margin counts that make a row readable without any colour.
func TestHeatmapWordsAndCountsInEveryCell(t *testing.T) {
	card := heatCard(t)

	byID := map[string]Row{}
	for _, r := range card.Rows {
		byID[r.Scenario] = r
	}
	seen := map[string]bool{}
	for _, hr := range card.Heatmap {
		if seen[hr.Technique] {
			t.Errorf("%s appears twice; the grid is a table, not a list",
				hr.Technique)
		}
		seen[hr.Technique] = true
		if len(hr.Cells) != len(card.Rows) {
			t.Errorf("%s has %d cell(s) for %d scenario(s); a technique row "+
				"carries the whole run, na and all", hr.Technique,
				len(hr.Cells), len(card.Rows))
		}
		tested, caught, telemetry, missed, quiet := 0, 0, 0, 0, 0
		for _, c := range hr.Cells {
			if !heatWordKnown(c.Outcome) {
				t.Errorf("%s/%s carries %q, which is not one of the five "+
					"outcome words", hr.Technique, c.Scenario, c.Outcome)
			}
			row, ok := byID[c.Scenario]
			if !ok {
				t.Errorf("%s has a cell for %s, which the run never scored",
					hr.Technique, c.Scenario)
				continue
			}
			if c.Outcome == HeatNA {
				if containsTechnique(row.Techniques, hr.Technique) {
					t.Errorf("%s stages %s and the cell says na", c.Scenario,
						hr.Technique)
				}
				continue
			}
			if !containsTechnique(row.Techniques, hr.Technique) {
				t.Errorf("%s does not stage %s and the cell claims %s",
					c.Scenario, hr.Technique, c.Outcome)
			}
			if c.Outcome != row.Outcome {
				t.Errorf("%s/%s says %s; the scenario's row says %s — the "+
					"grid and the rows are the same facts or the grid is "+
					"a second opinion", c.Scenario, hr.Technique, c.Outcome,
					row.Outcome)
			}
			tested++
			switch c.Outcome {
			case OutcomeCaughtAlert:
				caught++
			case OutcomeCaughtTelemetry:
				telemetry++
			case OutcomeMissed:
				missed++
			case OutcomeWronglyQuiet:
				quiet++
			}
		}
		if hr.Tested != tested || hr.Caught != caught ||
			hr.Telemetry != telemetry || hr.Missed != missed ||
			hr.WronglyQuiet != quiet {
			t.Errorf("%s margins %+v do not match its cells (tested %d, "+
				"caught %d, telemetry %d, missed %d, quiet %d)", hr.Technique,
				hr, tested, caught, telemetry, missed, quiet)
		}
	}
	for _, r := range card.Rows {
		for _, tech := range r.Techniques {
			if !seen[tech] {
				t.Errorf("%s stages %s and no grid row carries it", r.Scenario,
					tech)
			}
		}
	}
	// The technique grid and the heatmap agree on what was tested — two
	// renderings of the same rows, so their denominators are the same.
	if len(card.Heatmap) != len(card.Techniques) {
		t.Errorf("%d heatmap row(s) against %d technique-grid row(s); the "+
			"two grids are the same facts", len(card.Heatmap),
			len(card.Techniques))
	}
}

// The grid's order is deterministic — techniques sorted, cells in
// scenario-id order — so two documents diff as tables.
func TestHeatmapIsSortedAndDeterministic(t *testing.T) {
	card := heatCard(t)
	var techs []string
	for _, hr := range card.Heatmap {
		techs = append(techs, hr.Technique)
	}
	for i := 1; i < len(techs); i++ {
		if techs[i-1] >= techs[i] {
			t.Errorf("techniques out of order: %s then %s", techs[i-1],
				techs[i])
		}
	}
	for _, hr := range card.Heatmap {
		for i := 1; i < len(hr.Cells); i++ {
			if hr.Cells[i-1].Scenario >= hr.Cells[i].Scenario {
				t.Errorf("%s's cells are not in scenario-id order (%s then "+
					"%s)", hr.Technique, hr.Cells[i-1].Scenario,
					hr.Cells[i].Scenario)
			}
		}
	}
}

// The accessibility contract: the human render carries the outcome words
// in the cells, the counts on every row, the statement that nothing is
// colour alone — and not one escape sequence anywhere in it.
func TestHeatmapRenderNeverEncodesByHueAlone(t *testing.T) {
	card := heatCard(t)
	s := card.Summarize()
	// The render wraps its sentences for a terminal, so the assertions
	// read them the way a person does: as words.
	flat := strings.Join(strings.Fields(s), " ")
	for _, want := range []string{
		"technique heatmap",
		"every cell says its outcome in words",
		"nothing in this grid is colour alone",
		"caught-telemetry", // the longest word, in full, in cells
		HeatNA,
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("the render never says %q", want)
		}
	}
	if strings.Contains(s, "\x1b[") {
		t.Error("the summary carries an escape sequence; a grid whose " +
			"meaning needed the colour would be hue-only encoding")
	}
	// Every scenario is named in the legend, so a cell's column resolves
	// to a session a reader can point at.
	for _, r := range card.Rows {
		if !strings.Contains(s, r.Scenario) {
			t.Errorf("the legend never names %s", r.Scenario)
		}
	}
	// And every row ends in its counts, words and numbers together.
	rows := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, " caught") &&
			strings.Contains(line, "/") &&
			!strings.Contains(line, "heatmap") {
			rows++
		}
	}
	if rows != len(card.Heatmap) {
		t.Errorf("%d rendered row(s) carry margin counts; %d technique "+
			"row(s) are in the grid", rows, len(card.Heatmap))
	}
}

// The JSON face round-trips: the grid as it was sealed comes back out of
// the document's own bytes as the same grid, cells, margins and all —
// the machine face and the human face are the same facts.
func TestHeatmapJSONRoundTrips(t *testing.T) {
	card := heatCard(t)
	doc, err := card.Document()
	if err != nil {
		t.Fatal(err)
	}
	var back Scorecard
	if err := json.Unmarshal(doc, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Heatmap) != len(card.Heatmap) {
		t.Fatalf("%d row(s) came back from %d", len(back.Heatmap),
			len(card.Heatmap))
	}
	asWritten, err := json.Marshal(card.Heatmap)
	if err != nil {
		t.Fatal(err)
	}
	asRead, err := json.Marshal(back.Heatmap)
	if err != nil {
		t.Fatal(err)
	}
	if string(asWritten) != string(asRead) {
		t.Fatalf("the grid did not round-trip:\n%s\nvs\n%s", asWritten,
			asRead)
	}
}
