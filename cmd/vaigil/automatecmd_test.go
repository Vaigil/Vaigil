// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/vaigil/vaigil/internal/automate"
	"github.com/vaigil/vaigil/internal/geo"
)

func geoOffices(t *testing.T, root string) {
	t.Helper()
	b, _ := json.Marshal(geoConfig{Networks: []geo.Network{
		{Prefix: "198.51.100.0/24", Place: geo.Place{Network: "London office", Kind: "office", City: "London", Country: "GB", Lat: 51.5074, Lon: -0.1278}},
		{Prefix: "203.0.113.0/24", Place: geo.Place{City: "Sydney", Country: "AU", Lat: -33.8688, Lon: 151.2093}},
		{Prefix: "192.0.2.0/24", Place: geo.Place{Network: "Corporate VPN", Kind: "vpn"}},
	}})
	if err := os.WriteFile(geoPath(root), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// settled is the history once the background steps have finished, as they
// do on the server.
func settled(t *testing.T, root string) []automate.Run {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		runs, _ := automationEngine(root).Runs()
		busy := false
		for _, r := range runs {
			for _, st := range r.Steps {
				busy = busy || st.Pending
			}
		}
		if !busy || time.Now().After(deadline) {
			return runs
		}
		time.Sleep(20 * time.Millisecond)
	}
}
