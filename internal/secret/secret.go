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

// Spans are where credentials are in text, as byte offsets. A private key
// is the whole block, through its END line, when that END is there to
// close it; without one, the header alone (pemEnd says where each ends).
func Spans(text string) [][2]int {
	var out [][2]int
	for _, k := range kinds {
		for _, loc := range k.pattern.FindAllStringIndex(text, -1) {
			start, end := loc[0], loc[1]
			if k.confirm != nil && !k.confirm(text[start:end]) {
				continue
			}
			if k.name == "private-key" {
				end = pemEnd(text, end)
			}
			out = append(out, [2]int{start, end})
		}
	}
	return out
}

// A PEM block is bounded. The largest private key in common use, RSA-4096,
// is about 3,400 bytes wrapped; 8 KiB covers every format with room to
// spare. Past that, what follows a BEGIN is not a key waiting for its END
// but whatever somebody put there, and a mask that ran on would hand them
// everything said after it.
const maxPEM = 8 << 10

// maxPEMLabel bounds the label between "-----END " and the dashes that
// close it: "CERTIFICATE REQUEST" and its kin are under thirty bytes, and
// a label that runs longer is content wearing the token as a hat.
const maxPEMLabel = 64

// pemEnd is where a private-key header's span ends: through the END token
// of the block it opens when that END is present and within reach of a
// real key, and otherwise the header itself, never past it.
//
// Whoever can write a log field can write a BEGIN there, and a mask that
// took everything to the end of the text would let them erase what the
// model was to read after it — the entity, the other evidence, the fence
// around the lot. An END closes only the BEGIN before it, so a planted
// one cannot reach back over an arbitrary stretch either.
func pemEnd(text string, headerEnd int) int {
	room := headerEnd + maxPEM
	if room > len(text) {
		room = len(text)
	}
	i := strings.Index(text[headerEnd:room], "-----END ")
	if i < 0 {
		return headerEnd
	}
	e := headerEnd + i + len("-----END ")
	till := e + maxPEMLabel
	if till > len(text) {
		till = len(text)
	}
	j := strings.Index(text[e:till], "-----")
	if j < 0 {
		return headerEnd
	}
	return e + j + len("-----")
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
