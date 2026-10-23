// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/quilzo/vaigil/internal/anchor"
	"github.com/quilzo/vaigil/internal/fetch"
)

// The audit log head, committed to Bitcoin through OpenTimestamps
// calendars: `vaigil auditlog anchor` submits, `anchor upgrade` collects
// the block attestations once they exist, and `anchor status` lists them.

func anchorPath(root string) string { return filepath.Join(root, "anchors.json") }

type anchorFile struct {
	Proofs []anchor.Proof `json:"proofs"`
}

func anchorUpgrade(root string) error {
	file := &anchorFile{}
	if err := loadJSON(anchorPath(root), file); err != nil {
		return err
	}
	if len(file.Proofs) == 0 {
		return fmt.Errorf("nothing has been submitted")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sub := httpSubmitter{fetch.For("anchor")}

	var upgraded, waiting int
	for i := range file.Proofs {
		if file.Proofs[i].Anchored() {
			continue
		}
		out, err := anchor.Upgrade(ctx, sub, file.Proofs[i], time.Now())
		if errors.Is(err, anchor.ErrNotYet) {
			waiting++
			continue
		}
		if err != nil {
			w.Human("  %s%s: %v%s\n", yellow, file.Proofs[i].Calendar, err, reset)
			continue
		}
		if out.Anchored() {
			upgraded++
			w.Human("  %sanchored%s  %s  block %d\n",
				green, reset, out.Calendar, out.Height)
		}
		file.Proofs[i] = out
	}
	if err := saveJSON(anchorPath(root), file); err != nil {
		return err
	}
	if upgraded == 0 {
		w.Human("  %s%d proof(s) still waiting for a block; commitments take "+
			"hours%s\n", dim, waiting, reset)
	}
	return anchorStatus(root)
}

// httpSubmitter routes calendar traffic through the SSRF-hardened fetcher.
//
// Calendar URLs are configuration, and a pending attestation inside a proof
// names a URL this program later fetches — so one of these addresses arrives
// from a file somebody else produced. That is exactly the case the fetcher's
// connect-time check exists for.
type httpSubmitter struct{ c *fetch.Client }

func anchorStatus(root string) error {
	file := &anchorFile{}
	if err := loadJSON(anchorPath(root), file); err != nil {
		return err
	}
	if w.JSON(file) {
		return nil
	}
	if len(file.Proofs) == 0 {
		w.Human("nothing has been anchored\n")
		w.Human("  %svaigil auditlog anchor — commit the log head%s\n", dim, reset)
		w.Human("  %sone hash over the whole log. Nothing about a record or a\n"+
			"  person goes to a public ledger, because a ledger cannot forget.%s\n",
			dim, reset)
		return nil
	}

	for _, p := range file.Proofs {
		state := yellow + string(p.State) + reset
		if p.Anchored() {
			state = green + "anchored" + reset
		}
		w.Human("  %-10s %-46s %s\n", state, p.Calendar, short(p.Digest))
		if p.Anchored() {
			w.Human("             %sBitcoin block %d%s\n", dim, p.Height, reset)
		} else {
			w.Human("             %swaiting %s%s\n", dim,
				anchor.Age(p, time.Now()).Round(time.Minute), reset)
		}
	}
	w.Human("\n  %sverify independently:  ots verify <proof>%s\n", dim, reset)
	w.Human("  %sthis walks the proof and recomputes the commitment; whether a\n"+
		"  block contains it needs block headers, which this does not have%s\n",
		dim, reset)
	return nil
}

func (h httpSubmitter) Post(ctx context.Context, url string, body []byte) ([]byte, error) {
	res, err := h.c.Post(ctx, url, body, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	return res.Body, nil
}

func (h httpSubmitter) Get(ctx context.Context, url string) ([]byte, error) {
	res, err := h.c.Get(ctx, url)
	if err != nil {
		return nil, err
	}
	return res.Body, nil
}
