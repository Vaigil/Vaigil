// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package pack

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aertun/aertun/internal/atomicfile"
)

// Building a pack for signing: the producer's half.
//
// The producer's flow is deliberately dumb — files in a directory, one
// command — because the alternative is a project or an export format, and
// neither is needed to put eight rule files and a correlation on a
// customer's machine. Build reads what is there, refuses what does not
// belong, hashes what does, and writes the manifest. Sign then pins that
// manifest with the release key.

// BuildOptions is what the producer says about a pack. Everything else —
// every digest and size — is derived from the files as they stand.
type BuildOptions struct {
	ID        string
	Version   string
	Channel   Channel
	About     string
	MinBinary string
}

// Build writes DIR/manifest.json from the content files in DIR and returns
// the pack as Read would load it. The content layout is the contract:
// detections/*.json and correlations/*.yml; a file anywhere else in the
// directory is refused rather than skipped, because a pack that silently
// ignored part of itself is a pack whose producer thought more shipped than
// did.
func Build(dir string, opts BuildOptions) (*Pack, error) {
	m := Manifest{
		ID: opts.ID, Version: opts.Version, Channel: opts.Channel,
		About:  opts.About,
		Engine: Engine{MinimumBinary: opts.MinBinary},
	}

	var files []File
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		switch {
		case rel == ManifestName || rel == RootName || rel == TargetsName ||
			rel == TimestampName:
			// Derived, or about to be rewritten.
			return nil
		}
		var typ string
		switch {
		case strings.HasPrefix(rel, TypeDetection+"/") && strings.HasSuffix(rel, ".json"):
			typ = TypeDetection
		case strings.HasPrefix(rel, TypeCorrelation+"/") &&
			(strings.HasSuffix(rel, ".yml") || strings.HasSuffix(rel, ".yaml")):
			typ = TypeCorrelation
		default:
			return fmt.Errorf("%s is not content this pack format carries: "+
				"detections/*.json and correlations/*.yml. A pack is data, "+
				"and only data — nothing else has a place in one", rel)
		}
		if err := checkContentPath(rel); err != nil {
			return err
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if int64(len(body)) > MaxFileBytes {
			return fmt.Errorf("%s is %d bytes; one file is at most %d",
				rel, len(body), MaxFileBytes)
		}
		files = append(files, File{Path: rel, Type: typ,
			SHA256: sha256Hex(body), Size: int64(len(body))})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s carries no detections and no "+
			"correlations; there is nothing to sign", dir)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	m.Files = files
	// Validated whole, with the files in it: the claims about the id,
	// version and channel and the claims about the paths and digests are
	// one manifest, and half of it is not checked ahead of the other.
	if err := m.Validate(); err != nil {
		return nil, err
	}

	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := atomicfile.Write(filepath.Join(dir, ManifestName),
		append(body, '\n'), 0o644); err != nil {
		return nil, err
	}
	p, err := Read(dir)
	if err != nil {
		return nil, err
	}
	// The gate runs on the producer too: signing a pack whose rules this
	// binary's own validators refuse would only move the refusal to the
	// customer, with this producer's signature on it.
	if err := p.ValidateContent(); err != nil {
		return nil, err
	}
	return p, nil
}
