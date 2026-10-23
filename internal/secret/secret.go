// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package secret finds credentials in text, for a caller that has to take
// them out rather than report them: the privacy guard in front of a model
// masks them before a prompt leaves.
//
// Pattern matching for the credential formats that are recognisable, plus
// entropy to confirm one that looks like an assignment. Entropy never decides
// alone: a bare high-entropy string is as likely to be a hash, an id or a
// base64 image as a key.
package secret

import (
	"math"
	"regexp"
	"strings"
)

// kind is one shape a credential takes.
type kind struct {
	name    string
	pattern *regexp.Regexp
	// confirm, when set, has to agree before a match counts.
	confirm func(match string) bool
}

var kinds = []kind{
	{name: "private-key", pattern: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----`)},
	{name: "token", pattern: regexp.MustCompile(`\bvg_[a-z0-9]{40,}\b`)},
	{name: "cloud-key", pattern: regexp.MustCompile(`\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-(?:proj|svcacct|admin|ant-api\d\d|ant-admin\d\d)-[A-Za-z0-9_-]{32,}|sk-[A-Za-z0-9]{32,}|glpat-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35})\b`)},
	{name: "connection-string", pattern: regexp.MustCompile(`(?i)\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]+@`)},
	{name: "assignment", pattern: regexp.MustCompile(`(?i)\b(api[_-]?key|secret|token|passwd|password|credential|auth[_-]?token|private[_-]?key)\b\s*[:=]\s*["'` + "`" + `]?[A-Za-z0-9+/_=-]{16,}`), confirm: looksSecret},
}

// Spans are where credentials are in text, as byte offsets. A private key is
// the whole block, through its END line, not only the line that names it.
func Spans(text string) [][2]int {
	var out [][2]int
	for _, k := range kinds {
		for _, loc := range k.pattern.FindAllStringIndex(text, -1) {
			start, end := loc[0], loc[1]
			if k.confirm != nil && !k.confirm(text[start:end]) {
				continue
			}
			if k.name == "private-key" {
				if i := strings.Index(text[end:], "-----END "); i >= 0 {
					end += i + len("-----END ")
					if j := strings.Index(text[end:], "-----"); j >= 0 {
						end += j + len("-----")
					}
				} else {
					end = len(text) // no end in sight: everything after it is the key
				}
			}
			out = append(out, [2]int{start, end})
		}
	}
	return out
}

// entropy is Shannon entropy in bits per byte.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]float64
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// looksSecret confirms a credential-shaped assignment: long enough, not a
// placeholder, and random enough not to be a word.
func looksSecret(match string) bool {
	i := strings.IndexAny(match, "=:")
	if i < 0 {
		return true // the whole match is a credential format, not an assignment
	}
	value := strings.Trim(strings.TrimSpace(match[i+1:]), `"'`+"`")
	if len(value) < 16 {
		return false
	}
	lower := strings.ToLower(value)
	for _, p := range []string{
		"example", "changeme", "your-", "xxx", "todo", "placeholder", "redacted",
		"<", "{{", "${", "...", "abc123", "secret", "password",
	} {
		if strings.Contains(lower, p) {
			return false
		}
	}
	return entropy(value) > 3.5
}
