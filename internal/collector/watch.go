// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The watch pack: the agent-evidence core of the collector.
//
// A declarative list of files and directories — key material, environment
// files, agent configuration, session directories — polled each cycle. What
// is noticed is metadata only: the path, the kind of thing it is, the size,
// the SHA-256 of the content, and which of created, changed or removed
// happened. The content itself is never read except to hash it, and never
// kept: a private key must not cross this boundary, and the fact that it
// changed is the whole of the evidence a detection needs. That is what
// "evidence-grade metadata, not capture" means here, in the package comment,
// and it is a property of the code, not a setting.
//
// Polling, not inotify: a watcher that asks the kernel to tell it things is
// a watcher whose queue the kernel bounds and drops from silently under
// load, and stdlib polling — mtime and size, hash on change — is one page
// that works everywhere and never quietly misses. The cycle is seconds; the
// things watched change rarely; the difference is not worth a kernel
// dependency.
type Watch struct {
	// entries is the pack, resolved: tilde expanded, absolute.
	entries []resolvedEntry
	// Host is what each record says the machine is.
	Host string
	// Logf is told about files it cannot look at, once each, because a watch
	// that cannot see is a watch the operator believes is running.
	Logf func(string, ...any)

	// state is the last poll's knowledge: size, mtime and hash per path.
	state map[string]watchedFile
	// baseline is whether the first poll has been taken. The first poll
	// learns what is there; it does not announce it — every enrollment would
	// otherwise be a flood of "created" events for files that have been
	// there for years, and a flood is how a signal gets muted.
	baseline bool
	// warned keeps the paths said aloud already.
	warned map[string]bool
}

type resolvedEntry struct {
	WatchEntry
	// dir is whether the path was a directory when the pack was resolved.
	dir bool
}

type watchedFile struct {
	size  int64
	mtime int64
	sha   string
	kind  string
	typ   string
}

// Change is one thing that happened to one watched path.
type Change struct {
	Path   string
	Kind   string
	Op     string // created, changed, removed
	SHA256 string
	Size   int64
	// Type is empty for a regular file, and otherwise names what the path
	// has become — a fifo, a device, a socket. Nothing is read from those,
	// and a watched file replaced by one is the change worth seeing: it is
	// how a recorder that hashes what it watches would be made to stall.
	Type string
}

// Ops.
const (
	OpCreated = "created"
	OpChanged = "changed"
	OpRemoved = "removed"
)

// NewWatch resolves a pack against a home directory (for ~ paths) and the
// host's name. Entries that name nothing yet are kept, not refused: a
// watched path that does not exist is a watch whose most interesting event,
// its creation, has not happened yet.
func NewWatch(pack []WatchEntry, home, host string) (*Watch, error) {
	w := &Watch{Host: host, state: map[string]watchedFile{}, warned: map[string]bool{}}
	for _, e := range pack {
		path, err := expandHome(e.Path, home)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(path)
		w.entries = append(w.entries, resolvedEntry{WatchEntry: e,
			dir: err == nil && info.IsDir()})
	}
	return w, nil
}

func expandHome(path, home string) (string, error) {
	if path == "~" {
		return home, nil
	}
	if v, ok := strings.CutPrefix(path, "~/"); ok {
		if home == "" {
			return "", fmt.Errorf("%q is relative to a home directory and "+
				"none could be found", path)
		}
		return filepath.Join(home, v), nil
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("watch path %q is not absolute and does not "+
			"begin with ~. A pack that names a relative path watches wherever "+
			"the collector happens to be started from, which is no watch at "+
			"all", path)
	}
	return filepath.Clean(path), nil
}

// Poll looks at every entry and returns what changed since the last look.
func (w *Watch) Poll() []Change {
	seen := map[string]bool{}
	var out []Change
	for _, e := range w.entries {
		paths := []string{e.Path}
		if e.dir {
			paths = w.dirEntries(e)
		}
		for _, p := range paths {
			seen[p+":"+e.Kind] = true
			out = append(out, w.one(p, e.Kind)...)
		}
	}
	// A path known before and not seen now — because the pack changed or a
	// directory's entry went away — is removed, the same as a file deleted
	// in place. A watch that quietly forgot is a watch that lies.
	for key, prev := range w.state {
		if seen[key] {
			continue
		}
		path := key[:strings.LastIndexByte(key, ':')]
		out = append(out, Change{Path: path, Kind: prev.kind, Op: OpRemoved})
		delete(w.state, key)
	}
	if !w.baseline {
		w.baseline = true
		return nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// dirEntries is a directory entry's direct children matching its glob. One
// level, no recursion, per the pack's own contract: a pack that means a
// tree says the tree.
func (w *Watch) dirEntries(e resolvedEntry) []string {
	d, err := os.Open(e.Path)
	if err != nil {
		w.once(e.Path, "cannot read %s: %v", e.Path, err)
		return nil
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		w.once(e.Path, "cannot list %s: %v", e.Path, err)
		return nil
	}
	var out []string
	for _, n := range names {
		if e.Glob != "" {
			if ok, gerr := filepath.Match(e.Glob, n); gerr != nil || !ok {
				continue
			}
		}
		out = append(out, filepath.Join(e.Path, n))
	}
	return out
}

// one compares a single path against what the last poll knew.
func (w *Watch) one(path, kind string) []Change {
	key := path + ":" + kind
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			if prev, ok := w.state[key]; ok {
				delete(w.state, key)
				return []Change{{Path: path, Kind: prev.kind, Op: OpRemoved}}
			}
			return nil
		}
		// Not gone, just not readable: a file the collector may not look at
		// is a file it cannot claim to have watched, and pretending either
		// way would be worse than saying so once.
		w.once(path, "cannot look at %s: %v", path, err)
		return nil
	}
	prev, known := w.state[key]
	if info.IsDir() {
		// A directory inside a watched one is not a file, and its own
		// contents are listed when its entry says so.
		return nil
	}
	if typ := fileType(info.Mode()); typ != "" {
		if known && prev.typ == typ {
			return nil
		}
		w.state[key] = watchedFile{mtime: info.ModTime().UnixNano(), kind: kind, typ: typ}
		op := OpChanged
		if !known {
			op = OpCreated
		}
		return []Change{{Path: path, Kind: kind, Op: op, Type: typ}}
	}
	// The cheap signals first: size and mtime decide whether hashing — the
	// only part that reads content — is worth doing at all.
	if known && prev.typ == "" && prev.size == info.Size() &&
		prev.mtime == info.ModTime().UnixNano() {
		return nil
	}
	sha := hashFile(path, info)
	if sha == "" {
		w.once(path, "cannot hash %s; it is watched but not readable", path)
		return nil
	}
	next := watchedFile{size: info.Size(), mtime: info.ModTime().UnixNano(),
		sha: sha, kind: kind}
	w.state[key] = next
	if !known {
		return []Change{{Path: path, Kind: kind, Op: OpCreated,
			SHA256: sha, Size: info.Size()}}
	}
	// A touch — new mtime, same content — is not a change. Content is the
	// truth; the metadata was only the hint that looking was due.
	if prev.typ == "" && prev.sha == sha && prev.size == info.Size() {
		return nil
	}
	return []Change{{Path: path, Kind: kind, Op: OpChanged,
		SHA256: sha, Size: info.Size()}}
}

// MaxHashed bounds how much of one file a poll reads. A watched file is a
// configuration file, a key, a script; past this the digest covers the
// first MaxHashed bytes and the size covers the rest, so a file grown to
// terabytes costs one bounded read rather than the recorder's afternoon.
const MaxHashed = 64 << 20

// fileType names a path that is not a regular file, or returns "" for one
// that is. Directories are handled before this is asked.
func fileType(m os.FileMode) string {
	switch {
	case m.IsRegular():
		return ""
	case m&os.ModeNamedPipe != 0:
		return "fifo"
	case m&os.ModeSocket != 0:
		return "socket"
	case m&os.ModeDevice != 0 || m&os.ModeCharDevice != 0:
		return "device"
	default:
		return "irregular"
	}
}

// hashFile is the one place content is read, and it leaves with only a
// digest. Streamed, not slurped, and bounded by MaxHashed.
//
// The file is opened without blocking and checked to be the regular file
// that was stat'd: a path swapped for a fifo between the stat and the open
// would otherwise block the open until somebody wrote to it, and the
// recorder with it.
func hashFile(path string, stat os.FileInfo) string {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(stat, opened) {
		return ""
	}
	h := sha256.New()
	if _, err := io.CopyN(h, f, MaxHashed); err != nil && err != io.EOF {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (w *Watch) once(path, format string, args ...any) {
	if w.warned[path] {
		return
	}
	w.warned[path] = true
	if w.Logf != nil {
		w.Logf(format, args...)
	}
}

// Records is the poll's changes as shippable records.
func (w *Watch) Records(now time.Time) []map[string]any {
	changes := w.Poll()
	out := make([]map[string]any, 0, len(changes))
	for _, c := range changes {
		rec := map[string]any{
			"path": c.Path, "kind": c.Kind, "op": c.Op,
			"sha256": c.SHA256, "size": strconv.FormatInt(c.Size, 10),
			"host": w.Host,
		}
		if c.Type != "" {
			rec["type"] = c.Type
		}
		out = append(out, rec)
	}
	return out
}
