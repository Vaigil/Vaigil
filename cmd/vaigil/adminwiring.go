// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"

	"github.com/quilzo/vaigil/internal/admin"
	"github.com/quilzo/vaigil/internal/config"
)

// What the console needs that only this package knows.
//
// Every function here exists because internal/admin deliberately does not know
// where this store keeps its files, and should not learn: the moment the
// console knows the layout there are two places that decide it, and one of
// them will be wrong after the next change.

func profilesPath(root string) string { return filepath.Join(root, "profiles.json") }

// loadProfiles reads the self-supplied details.
//
// A missing file is an empty map rather than an error: a store where nobody
// has set a display name is the ordinary state, not a broken one.
func loadProfiles(root string) (map[string]admin.PersonDetails, error) {
	out := map[string]admin.PersonDetails{}
	if err := loadJSON(profilesPath(root), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// mustConfig reads configuration, falling back to defaults.
//
// The defaults are the recommended configuration, so a store whose config file
// is missing gets the safe values rather than zero values — which for a rate
// limit would mean no limit at all.
func mustConfig(root string) *config.Config {
	c, err := loadConfig(root)
	if err != nil || c == nil {
		return config.New()
	}
	return c
}
