// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

// Package pack is the signed content plane: versioned content packs that
// update Vaigil's detections without a binary release.
//
// # Packs are data, and only data
//
// A pack is a directory of JSON rule files and YAML correlations plus signed
// metadata saying what they are. There is no plugin host, no scripting, no
// expression grammar, no WASM and no code execution path of any kind, and
// that is not a limitation to work around — it is the sandbox. The design
// exists in the shadow of CrowdStrike's July 19 2024, where content steered
// an interpreter into an out-of-bounds read and 8.5 million machines
// bugchecked. Here there is no interpreter to steer: a rule is a closed tree
// of nine comparison operators over fields the telemetry publishes
// (internal/detect), a correlation counts across rules (internal/correlate),
// and the engines that consume a pack are the same engines that consume files
// a customer typed by hand. The worst a malicious but well-formed pack can
// do, even signed, is raise wrong findings — which is loud, and visible, and
// a person's problem rather than a kernel's.
//
// # Verification is the gate
//
// Nothing from a pack reaches the rules directory until the whole metadata
// chain verifies. The chain is TUF-shaped and dual-signed: root.json (the
// offline trust anchor, naming the online release key), targets.json (the
// release key's word on the manifest's exact bytes, at a monotonic integer
// version) and timestamp.json (pinning targets.json's bytes and version).
// Every signature is Ed25519 and ML-DSA-65 both — two algorithms that fail
// differently, per internal/audit/sign.go — and there is no option to accept
// one, for the reason that package gives: a verifier that can be told "one
// is enough" is a verifier that will be told so under time pressure.
//
// The checks run in a fixed order, cheap and stateless first (see Verify):
// signatures, then version counters against the installed state (rollback
// refusal — the counters live in this store, not in anything the pack
// carries, so serving an old pack again refuses), then digests, then bounds,
// then the content itself validated by the shipping loaders — the same
// `Rule.Validate` the run uses. There is deliberately no separate "content
// validator": CrowdStrike's channel file 291 passed a validator that checked
// against a definition file which disagreed with the compiled sensor. The
// only validator here is the engine that will run the content.
//
// # What expiry does and does not do
//
// Expiry protects the update path, never the running system. An expired pack
// is refused as an update, with a clear error; an expired pack that is
// already installed keeps working, because nothing in the detection run
// consults pack metadata at all — the rules are files on disk by then. A
// detection engine that switched itself off because a clock said so would be
// a self-inflicted fleet outage, which is the one failure this whole design
// exists to not repeat. Staleness is reported, not silent: `content
// installed` says when an installed pack's metadata expired.
//
// # No network
//
// Packs arrive by file — copied, mailed, carried on a USB stick. Trust is in
// the signatures, not the transport, so no mirror needs protecting; this
// package makes no network calls and has no way to.
//
// # What is deliberately not here yet
//
// Deferred, with the reasons, rather than half-built: the shadow replay's
// afterlife — the trial-ring bake of new rules after an apply, and the
// automatic rollback on a budget breach measured on live traffic (the replay
// before an apply and its false-positive budget are in, shadow.go; manual
// rollback is in, install.go); channels beyond the pinned field
// (stable/beta/edge is recorded, nothing fetches by it yet); the marketplace
// and third-party delegation; binary self-update (the content plane never
// carries binaries).
//
// No longer deferred: root rotation (keys.go's ceremony, sign.go's
// RotateRoot, verify.go's continuity-and-handover walk — the anchor moves up
// one version at a time, signed by both keys, and never down) and local
// overrides (install.go — an install that would overwrite a locally-edited
// pack file refuses, and keeps or adopts the edit on the record when told
// to; user edits win, recorded, shown).
package pack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/vaigil/vaigil/internal/correlate"
	"github.com/vaigil/vaigil/internal/detect"
)

// Bounds on a pack, refused before anything is interpreted (§5.1 step 2 of
// the design: refuse the weird before parsing it). A pack is a handful of
// kilobyte-scale text files; anything near these limits is a generator
// malfunctioning or an attack, and both are better named here than trusted
// into a decoder.
const (
	// MaxPackBytes bounds one pack's content files in total.
	MaxPackBytes = 64 << 20
	// MaxPackFiles bounds how many files one pack may carry.
	MaxPackFiles = 5000
	// MaxFileBytes bounds one file of the pack, metadata included.
	MaxFileBytes = 2 << 20
	// MaxPathBytes bounds one content path.
	MaxPathBytes = 128
)

// Content types a pack may carry. Day one is detections only; the type
// names are the top-level directory names inside the pack, so a pack's own
// layout states what each file is.
const (
	TypeDetection   = "detections"
	TypeCorrelation = "correlations"
)

// Channel is the pack's release lane. Recorded and pinned in the manifest;
// nothing fetches by it in this slice.
type Channel string

// The channels, cumulative bake periods on the producer's side.
const (
	Stable Channel = "stable"
	Beta   Channel = "beta"
	Edge   Channel = "edge"
)

func (c Channel) known() bool {
	switch c {
	case Stable, Beta, Edge:
		return true
	}
	return false
}

// idPattern is a pack id: lowercase letters, digits, dots and hyphens, 3 to
// 64 bytes, `vaigil.*` reserved for first-party content and third parties
// domain-reversed (`com.example.phishing`). One shape for both, because the
// namespace rule is a convention the producer owns, not something the
// installer could usefully police.
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,62}[a-z0-9]$`)

// File is one content file of the pack, pinned by digest in the manifest.
type File struct {
	// Path is relative to the pack directory, slash-separated, under the
	// directory named by its type: "detections/okta.signin-failed.json".
	Path string `json:"path"`
	// Type is detections or correlations.
	Type string `json:"type"`
	// SHA256 is the file's digest, hex.
	SHA256 string `json:"sha256"`
	// Size is the file's length in bytes.
	Size int64 `json:"size"`
}

// Engine is the version negotiation half of the manifest.
type Engine struct {
	// MinimumBinary is the oldest Vaigil release that understands this
	// pack's schemas, X.Y.Z. Empty means no floor is claimed.
	MinimumBinary string `json:"minimum_binary,omitempty"`
}

// Manifest is manifest.json: what the pack is, and the digest of every file
// it owns. Unsigned itself — targets.json carries this file's digest, which
// is how the signature reaches the content.
type Manifest struct {
	ID      string  `json:"id"`
	Version string  `json:"version"`
	Channel Channel `json:"channel"`
	About   string  `json:"about"`
	Engine  Engine  `json:"engine"`
	Files   []File  `json:"files"`
}

// Metadata file names inside a pack directory, written by the signer and
// read by the chain walk in Verify.
const (
	ManifestName  = "manifest.json"
	RootName      = "root.json"
	TargetsName   = "targets.json"
	TimestampName = "timestamp.json"
)

// Version parts. A pack's human version is X.Y.Z; rollback protection never
// reasons about it (the signed integer version in targets.json is the
// authority), but it must still parse, because a version that cannot be
// compared cannot be shown beside another in a list.
const maxVersionPart = 1 << 24

// ParseVersion reads an X.Y.Z version into comparable integers.
func ParseVersion(s string) ([3]int, error) {
	var out [3]int
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, fmt.Errorf("%q is not X.Y.Z", s)
	}
	for i, p := range parts {
		n := 0
		for _, c := range []byte(p) {
			if c < '0' || c > '9' {
				return out, fmt.Errorf("%q is not X.Y.Z", s)
			}
			n = n*10 + int(c-'0')
			if n > maxVersionPart {
				return out, fmt.Errorf("%q has a part too large to compare", s)
			}
		}
		out[i] = n
	}
	return out, nil
}

// CompareVersions orders two already-parsed versions: -1, 0 or 1.
func CompareVersions(a, b [3]int) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

// Validate checks what the manifest claims about itself. What it claims
// about its files is checked against reality by Read.
func (m *Manifest) Validate() error {
	if !idPattern.MatchString(m.ID) {
		return fmt.Errorf("%q is not a pack id: 3 to 64 bytes of lowercase "+
			"letters, digits, dots and hyphens, starting and ending with a "+
			"letter or digit", m.ID)
	}
	if _, err := ParseVersion(m.Version); err != nil {
		return fmt.Errorf("the pack version: %w", err)
	}
	if !m.Channel.known() {
		return fmt.Errorf("the channel is %q; it is stable, beta or edge",
			m.Channel)
	}
	if m.Engine.MinimumBinary != "" {
		if _, err := ParseVersion(m.Engine.MinimumBinary); err != nil {
			return fmt.Errorf("engine.minimum_binary: %w", err)
		}
	}
	if len(m.About) > 300 {
		return fmt.Errorf("the description is %d bytes; keep it under 300, "+
			"it is a line in a list", len(m.About))
	}
	if len(m.Files) == 0 {
		return fmt.Errorf("the pack carries no files, so there is nothing " +
			"to install and nothing to sign")
	}
	if len(m.Files) > MaxPackFiles {
		return fmt.Errorf("the pack lists %d files; the bound is %d",
			len(m.Files), MaxPackFiles)
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		if err := checkContentPath(f.Path); err != nil {
			return err
		}
		if !knownType(f.Type) {
			return fmt.Errorf("%s: %q is not a content type this binary "+
				"knows; it may have been written for a newer Vaigil",
				f.Path, f.Type)
		}
		if err := typeMatchesPath(f.Type, f.Path); err != nil {
			return err
		}
		if _, err := hex.DecodeString(f.SHA256); err != nil || len(f.SHA256) != sha256.Size*2 {
			return fmt.Errorf("%s: %q is not a hex sha256", f.Path, f.SHA256)
		}
		if f.Size < 0 || f.Size > MaxFileBytes {
			return fmt.Errorf("%s claims %d bytes; one file is at most %d",
				f.Path, f.Size, MaxFileBytes)
		}
		if seen[f.Path] {
			return fmt.Errorf("%s is listed twice", f.Path)
		}
		seen[f.Path] = true
	}
	// Sorted, so two listings of one pack read the same and a diff of two
	// versions is a diff of content rather than of order.
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	return nil
}

func knownType(t string) bool { return t == TypeDetection || t == TypeCorrelation }

// typeMatchesPath ties the declared type to the path's directory and
// extension, so a YAML file cannot present itself as a rule and a rule
// cannot land where the correlation loader would read it.
func typeMatchesPath(t, path string) error {
	dir, base := filepath.Split(path)
	switch t {
	case TypeDetection:
		if dir != TypeDetection+"/" || !strings.HasSuffix(base, ".json") {
			return fmt.Errorf("%s: a detection lives at detections/*.json", path)
		}
	case TypeCorrelation:
		if dir != TypeCorrelation+"/" ||
			(!strings.HasSuffix(base, ".yml") && !strings.HasSuffix(base, ".yaml")) {
			return fmt.Errorf("%s: a correlation lives at correlations/*.yml", path)
		}
	default:
		return fmt.Errorf("%s: %q is not a content type", path, t)
	}
	return nil
}

// pathPattern is the bytes a content path may be made of. The charset is
// deliberately tiny: no spaces, no unicode, no backslashes, nothing a shell
// or another tool would want to interpret. The pack format is read by
// machines and written by tools, and neither needs a flexible filename.
var pathPattern = regexp.MustCompile(`^[a-z0-9._-]+(/[a-z0-9._-]+)*$`)

// checkContentPath enforces the path rules: relative, slash-separated, the
// charset above, no `.` or `..` element, no leading dot (nothing hidden), at
// most MaxPathBytes.
func checkContentPath(p string) error {
	if p == "" {
		return fmt.Errorf("a file has no path")
	}
	if len(p) > MaxPathBytes {
		return fmt.Errorf("%s is %d bytes; a content path is at most %d",
			p, len(p), MaxPathBytes)
	}
	if strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return fmt.Errorf("%q is not a relative slash-separated path", p)
	}
	if !pathPattern.MatchString(p) {
		return fmt.Errorf("%q is not [a-z0-9._-/] with no empty, . or .. "+
			"element", p)
	}
	for _, el := range strings.Split(p, "/") {
		if el == "." || el == ".." || strings.HasPrefix(el, ".") {
			return fmt.Errorf("%q: %q is not a directory or file name a "+
				"pack carries", p, el)
		}
	}
	return nil
}

// Pack is a pack directory read into memory, bounds-checked, with every
// content file's digest and body held. Read refuses on the first problem it
// meets and says which file and why; a pack that half-loads is a pack that
// must never reach the digest checks with a claim of completeness.
type Pack struct {
	Dir      string
	Manifest Manifest
	// Bodies are the content files by manifest path.
	Bodies map[string][]byte
}

// Read loads a pack directory: the manifest, then every file it lists, with
// the bounds and the digests checked against reality as each file is read.
// Metadata files (root.json, targets.json, timestamp.json) are not read
// here — the chain walk in Verify owns those, because their failure modes
// are signature failures, not content failures, and the two must never be
// conflated into one error message.
func Read(dir string) (*Pack, error) {
	mbody, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", ManifestName, err)
	}
	if len(mbody) > MaxFileBytes {
		return nil, fmt.Errorf("%s is %d bytes; it is at most %d",
			ManifestName, len(mbody), MaxFileBytes)
	}
	var m Manifest
	if err := decodeStrict(mbody, &m); err != nil {
		return nil, fmt.Errorf("%s is not a manifest: %w", ManifestName, err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", ManifestName, err)
	}

	p := &Pack{Dir: dir, Manifest: m, Bodies: map[string][]byte{}}
	var total int64
	for _, f := range m.Files {
		full := filepath.Join(dir, filepath.FromSlash(f.Path))
		// Lstat, not stat: a symlink is not content, it is a pointer to
		// something outside the pack, and a pack that carries one is refused
		// rather than followed — following it is how "data only" stops being
		// a promise about which bytes get read.
		fi, serr := os.Lstat(full)
		if serr != nil {
			return nil, fmt.Errorf("%s: %w", f.Path, serr)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file; a pack carries "+
				"files, not links or devices", f.Path)
		}
		if fi.Size() > MaxFileBytes {
			return nil, fmt.Errorf("%s is %d bytes; one file is at most %d",
				f.Path, fi.Size(), MaxFileBytes)
		}
		body, rerr := os.ReadFile(full)
		if rerr != nil {
			return nil, fmt.Errorf("%s: %w", f.Path, rerr)
		}
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != f.SHA256 {
			return nil, fmt.Errorf("%s does not match its manifest digest: "+
				"the file hashes to %s and the manifest says %s. Either the "+
				"file changed after the manifest was built, or the manifest "+
				"was built for something else", f.Path, got, f.SHA256)
		}
		if int64(len(body)) != f.Size {
			return nil, fmt.Errorf("%s is %d bytes and the manifest says %d",
				f.Path, len(body), f.Size)
		}
		total += int64(len(body))
		if total > MaxPackBytes {
			return nil, fmt.Errorf("the pack passes %d bytes in content; the "+
				"bound is %d", MaxPackBytes, total)
		}
		p.Bodies[f.Path] = body
	}
	if err := p.noExtraFiles(); err != nil {
		return nil, err
	}
	return p, nil
}

// noExtraFiles refuses a file the manifest does not list. An extra file is
// not harmless clutter: it is exactly what a tampered pack looks like when
// somebody added something and forgot (or did not try) to re-sign, and the
// bounds step's job is to refuse the unexplained before anything interprets
// it.
func (p *Pack) noExtraFiles() error {
	known := map[string]bool{ManifestName: true, RootName: true,
		TargetsName: true, TimestampName: true}
	for _, f := range p.Manifest.Files {
		known[f.Path] = true
	}
	var extra []string
	err := filepath.WalkDir(p.Dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, rerr := filepath.Rel(p.Dir, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if !known[rel] {
			extra = append(extra, rel)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("the pack carries %s, which the manifest does not "+
			"list. Nothing is installed that the signed metadata does not "+
			"account for", strings.Join(extra, ", "))
	}
	return nil
}

// ValidateContent runs every content file through the loader the detection
// run itself uses — the shipping engine, not a validator beside it. A rule
// that would be refused by `detect run` is refused here, before anything is
// installed: the CrowdStrike failure shape was a validator that agreed with
// a definition file and disagreed with the runtime, and the only defence is
// for there to be one validator.
func (p *Pack) ValidateContent() error {
	ruleIDs := map[string]string{}
	corrIDs := map[string]string{}
	var rules, corrs int
	for _, f := range p.Manifest.Files {
		body := p.Bodies[f.Path]
		switch f.Type {
		case TypeDetection:
			var r detect.Rule
			if err := decodeStrict(body, &r); err != nil {
				return fmt.Errorf("%s is not a rule: %w", f.Path, err)
			}
			if err := r.Validate(); err != nil {
				return fmt.Errorf("%s: %w", f.Path, err)
			}
			for _, res := range r.Test() {
				if !res.OK() {
					return fmt.Errorf("%s: fixture %q: %s", f.Path,
						res.Fixture, res.Why())
				}
			}
			if where, dup := ruleIDs[r.ID]; dup {
				return fmt.Errorf("%s and %s are both called %q, and a "+
					"finding has to say which rule raised it", where,
					f.Path, r.ID)
			}
			ruleIDs[r.ID] = f.Path
			rules++
		case TypeCorrelation:
			parsed, err := correlate.Read(body)
			if err != nil {
				return fmt.Errorf("%s is not a correlation: %w", f.Path, err)
			}
			for _, c := range parsed {
				if strings.TrimSpace(c.ID) == "" {
					return fmt.Errorf("%s: %q has no id, and a finding has "+
						"to say which correlation raised it", f.Path, c.Title)
				}
				if where, dup := corrIDs[c.ID]; dup {
					return fmt.Errorf("%s and %s both define %q", where,
						f.Path, c.ID)
				}
				corrIDs[c.ID] = f.Path
			}
			corrs++
		}
	}
	return nil
}

// Counts is what each type contributed, for a listing.
func (p *Pack) Counts() (rules, correlations int) {
	for _, f := range p.Manifest.Files {
		switch f.Type {
		case TypeDetection:
			rules++
		case TypeCorrelation:
			correlations++
		}
	}
	return
}

// decodeStrict decodes with unknown fields refused, so a pack written for a
// newer schema fails loudly on an older binary instead of loading
// half-meaningful content — the report's version-negotiation rule, applied
// where it costs nothing.
func decodeStrict(body []byte, into any) error {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("there is more than one JSON document")
	}
	return nil
}
