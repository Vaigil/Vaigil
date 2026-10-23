// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"

	"github.com/vaigil/vaigil/internal/auth"
)

// printable is a string with control characters replaced, so that what an
// agent read cannot write to the terminal of whoever reads the run.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return ' '
		}
		return r
	}, s)
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func firstLine(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func appendJSONL(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	line, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// wrapAt breaks a sentence to a width, indenting continuations.
func wrapAt(s string, width int, indent string) string {
	out, line := "", ""
	for _, word := range splitWords(s) {
		if len(line)+len(word)+1 > width && line != "" {
			out += line + "\n" + indent
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	return out + line
}

func splitWords(s string) []string {
	var out []string
	start := -1
	for i, r := range s {
		if r == ' ' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

func short(oid string) string {
	if len(oid) > 12 {
		return oid[:12]
	}
	return oid
}

// onlyAdministrator reports whether this person is the only one who could
// approve: an install with one administrator is not left unable to change
// anything, and the history says the change was made alone.
func onlyAdministrator(root, by string) bool {
	pol, err := loadPolicy(root)
	if err != nil {
		return false
	}
	// Whoever the policy would let administer the whole site now: a
	// binding that has ended, or one a deny outranks, is nobody.
	admins := map[string]bool{}
	for _, b := range pol.Bindings {
		if !b.Deny && b.Role == auth.RoleAdmin && pol.Evaluate(b.Principal, auth.ActGrant, "/").Allowed {
			admins[b.Principal] = true
		}
	}
	return len(admins) == 0 || (len(admins) == 1 && admins[by])
}

// eventFileArgs parses flags that may sit on either side of a file name.
//
// Go's flag package stops at the first argument that does not start with a
// dash, so `vaigil triage events.jsonl --rules detections` parses no flags at
// all. Nothing fails: the command runs happily against whatever the defaults
// were, reports on rules the operator did not ask for, and says nothing about
// it. That is the worst kind of wrong for a security tool, because the output
// looks exactly like a clean run.
//
// Every command whose own help reads `COMMAND [FILE] --flags` has to split
// the leading positional off before parsing, or its help is a lie.
func eventFileArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	pos, flags := leadingArgs(args, 1)
	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	return append(pos, fs.Args()...), nil
}

// MaxTelemetryLine bounds one event.
//
// A log line is attacker-influenced — whoever can write to the source chooses
// much of its content — so the reader is bounded rather than trusting the
// newline to arrive.
const MaxTelemetryLine = 1 << 20

// Content on its way to a terminal.
//
// # What this is for
//
// Several commands echo content back: a search excerpt, a scan finding, a
// commit message. That content was written by whoever can write content,
// which on a site with contributors is not the person running the command.
//
// A terminal is not a text box. A string carrying ESC sequences can move the
// cursor, clear the line above, change what is already on the screen, or set
// the window title -- so a page whose body begins with the right escape can
// make `vaigil search` print something other than what is in the store, and
// the operator reading the output has no way to tell. It is the same shape as
// log injection, on a surface where the reader is a person rather than a
// parser.
//
// # What it does
//
// Removes the C0 and C1 control characters, keeping tab and newline, which
// are the two that mean something in this output. Everything else is
// replaced with a visible marker rather than dropped: content that contained
// a control character is a fact worth seeing, and silently removing it hides
// both the escape and the reason somebody put it there.
//
// It does not attempt to be a sanitiser for anything else. Content going into
// a page is escaped by the template engine, which knows the context it is
// landing in; this knows only that the destination is a terminal.
func forTerminal(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			// C0, and DEL.
			b.WriteString("�")
		case r >= 0x80 && r <= 0x9f:
			// C1, which some terminals accept as escapes in their own right.
			b.WriteString("�")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// onOneLine is forTerminal for a value that is printed inside one line of
// output: a name, an identifier, a sentence of detail. A line break is
// replaced as well, because in that position it lets whatever wrote the
// value start a line of its own, and a line of this program's output is
// read as this program speaking.
func onOneLine(s string) string {
	// forTerminal first, because it keeps a newline on purpose; the line
	// breaks are replaced last so that nothing after this can put one back.
	s = forTerminal(s)
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.ReplaceAll(s, "\n", " ")
}
