// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The program is Vaigil, and Quilzo is named only where Vaigil means Quilzo.
//
// The code began as part of Quilzo, and a name left behind in a message, a
// cookie, an environment variable or a command example is a sentence that
// tells somebody the wrong program. So every source and asset file is read,
// and the only mentions allowed are the ones that are about Quilzo itself.
func TestQuilzoIsNamedOnlyWhereItIsMeant(t *testing.T) {
	allowed := []*regexp.Regexp{
		// The context Quilzo signs its audit heads in, for a receiver of its
		// stream.
		regexp.MustCompile(`quilzo/audit-head/v1`),
		// The service provider address the signed SAML fixtures were captured
		// for: a signature covers it, so it is kept as it was signed.
		regexp.MustCompile(`quilzo\.example/saml`),
		// The kind of feed that receives Quilzo's audit log, in the usage
		// and in what the README says Vaigil collects.
		regexp.MustCompile(`\|ssf\|quilzo NAME`),
		regexp.MustCompile(`Quilzo's audit log`),
	}
	// The files whose whole job is Quilzo: receiving its audit stream, and
	// the rules over what it sends. Named there because there Vaigil means
	// Quilzo, which is the one case this test allows.
	about := regexp.MustCompile(`^(internal/inbound/quilzo(_test)?\.go|cmd/vaigil/quilzofeed(_test)?\.go|internal/detect/pack/quilzo\.[a-z-]+\.json)$`)
	// "uilzo" as well: a fragment of the old name, such as a logotype that
	// spelled it after its mark, is still the wrong name.
	any := regexp.MustCompile(`(?i)uilzo`)
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// .git is history; testdata holds fixtures captured from real
			// identity providers, signed as they were captured.
			if d.Name() == ".git" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".go", ".html", ".css", ".js", ".json", ".yml", ".yaml", ".md":
		default:
			if d.Name() != "Makefile" && d.Name() != "Dockerfile" {
				return nil
			}
		}
		if strings.HasSuffix(path, "_test.go") && filepath.Base(path) == "name_test.go" {
			return nil
		}
		if about.MatchString(filepath.ToSlash(path)) {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for n, line := range strings.Split(string(b), "\n") {
			rest := line
			for _, a := range allowed {
				rest = a.ReplaceAllString(rest, "")
			}
			if any.MatchString(rest) {
				t.Errorf("%s:%d names Quilzo: %s", path, n+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
