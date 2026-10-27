// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

// Package collector is the endpoint half of the collector: the read-only,
// user-space recorder that watches what the agentless estate cannot see
// (docs/research/12-xdr-ndr-tip-iam.md §8).
//
// # It records; it never judges; it never blocks
//
// This is an evidence recorder, not a sensor product. There is no kernel
// driver on any OS and never will be, no on-endpoint detection engine, no
// prevention: every decision runs in the Vaigil server's rule engine, where
// the trial ring and the fixture discipline already live. The reason is the
// CrowdStrike July 2024 RCA — an interpreted content file met a template
// expecting one more value and took 8.5 million hosts down through a kernel
// path — and the three lessons of it are the shape of this package:
//
//  1. No interpreted content executes on the endpoint. The configuration is
//     a declarative watch list — paths and kinds and rates — decoded by a Go
//     struct with unknown fields refused. It is data this program reads,
//     never a program this program runs.
//  2. User-space only, fail-dead-silent. This process may die; the host must
//     not notice. Everything it opens, it opens read-only.
//  3. Evidence-grade metadata, not capture. A watched file's content is
//     never read except to hash it: what ships is the path, the kind of thing
//     it is, the size, the SHA-256 and what happened to it. A private key
//     never crosses this boundary; the fact that it changed does.
//
// # What it watches, and what it says about itself
//
// Three streams, each shipped as records the server turns into events: the
// auditd tail (execve and connect, in the exact shape the existing
// auditd/events mapping reads, so rules written against that source read
// collector events unchanged), the watch pack (key material, environment
// files, agent configuration — the files an agent or an intruder changes
// first), and a heartbeat every minute with the host, the uptime and how
// much evidence was shipped or dropped.
//
// The heartbeat is the recorder-blind signal: an agent that has stopped
// telling the truth stops sending one, and *noticing* that — the missing
// heartbeat detection — is server-side content, deliberately not this
// binary's. A recorder that detected its own silence would be judging.
//
// # What is not here, on purpose
//
// DNS and SNI observation (an AF_PACKET socket under CAP_NET_RAW) is named
// in the design brief as the collector's phase-2 network half and is not in
// this MVP: no raw sockets and no packet parsing ship in this version. The
// same for eBPF (a build-tagged experiment at best, never a dependency) and
// for the Windows and macOS substrates. Everything here is ordinary files
// and an ordinary HTTP client, which is the whole point: a program this
// small has a security story a person can actually read.
//
// # The permission reality, said plainly
//
// Reading /var/log/audit/audit.log needs root, the adm group, or a service
// grant (CAP_AUDIT_READ under systemd); reading a developer's ~/.ssh needs
// to run as that developer or with their consent. The collector is designed
// to run as a dedicated unprivileged user added to the group that can read
// the audit log, with a watch pack naming files that user may read — and
// where it cannot read something, it says nothing about that something
// rather than pretending it looked.
package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/vaigil/vaigil/internal/fetch"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vaigil/vaigil/internal/atomicfile"
)

// The record sources this collector ships, and the server's endpoint knows.
// Named here once because both halves of the wire import this package: a
// source string spelled differently on the two sides is a stream that stores
// nothing and errors nowhere.
const (
	// SourceAuditd is the existing auditd source's name (internal/source:
	// issuer "auditd", stream "events"). Collector auditd records go through
	// that mapping on the server, unchanged.
	SourceAuditd = "auditd/events"
	// SourceWatch is the watch pack's stream.
	SourceWatch = "collector/watch"
	// SourceHeartbeat is the one-minute liveness record.
	SourceHeartbeat = "collector/heartbeat"
)

// WatchEntry is one thing the watch pack names.
//
// A path, and the kind of thing it is. The kind is declared by whoever wrote
// the pack rather than guessed from a file name, because a name is a hint
// and a pack is a claim: "~/.ssh/id_ed25519" is a key because the operator
// said the .ssh directory holds keys, not because of the characters in its
// name — which is exactly the reasoning an attacker renaming a key would
// want us to do.
type WatchEntry struct {
	// Path is absolute, or begins with ~ for the invoking user's home.
	Path string `json:"path"`
	// Kind is one of Kinds. Empty is refused: a watch that does not say what
	// it is watching ships records a rule cannot tell apart.
	Kind string `json:"kind"`
	// Glob limits a directory entry to the names it names ("id_*"). Empty
	// watches every direct child. One level only, no recursion: a pack that
	// means a tree says the tree, entry by entry.
	Glob string `json:"glob,omitempty"`
}

// Kinds are what a watched thing can be. Closed on purpose: a kind a rule
// has never heard of is a label, not a signal.
const (
	KindKey         = "key"          // SSH keys, authorized_keys, *.pem
	KindEnv         = "env"          // .env and friends: credentials in files
	KindMCPConfig   = "mcp-config"   // .mcp.json: the agent's tool grants
	KindAgentConfig = "agent-config" // CLAUDE.md, AGENTS.md, .cursorrules, settings
	KindOther       = "other"        // anything the pack wants seen anyway
)

func validKind(k string) bool {
	switch k {
	case KindKey, KindEnv, KindMCPConfig, KindAgentConfig, KindOther:
		return true
	}
	return false
}

// Config is the declarative watch-and-rate pack. Validated, cached, never
// executed — the CrowdStrike lesson in struct form: whatever arrives is data
// this program reads, and a field it does not know is an error rather than
// an instruction.
type Config struct {
	// Hostname is what records say the machine is, when the log itself does
	// not say it. The kernel's idea (os.Hostname) when empty.
	Hostname string `json:"hostname,omitempty"`
	// AuditLog is the auditd log to tail.
	AuditLog string `json:"audit_log,omitempty"`
	// AuditFrom says where a first run with no position starts: "end" (the
	// default — a fresh recorder does not replay weeks of history) or
	// "start".
	AuditFrom string `json:"audit_from,omitempty"`
	// Watch is the pack.
	Watch []WatchEntry `json:"watch,omitempty"`

	// Rates. Seconds are integers because a fraction of a second of polling
	// is a way to burn a laptop's battery, not a way to see sooner.
	CycleSeconds    int `json:"cycle_seconds,omitempty"` // watch+tail+ship pass
	BeatSeconds     int `json:"heartbeat_seconds,omitempty"`
	BatchSeconds    int `json:"batch_seconds,omitempty"`     // or BatchMax events
	BatchMax        int `json:"batch_max,omitempty"`         // events per batch
	SpoolMaxBatches int `json:"spool_max_batches,omitempty"` // outage bound
	// Gzip the batch bodies. On by default; the wire is the same either way
	// and the signature covers the uncompressed records.
	Gzip bool `json:"gzip"`
}

// Defaults are the values an absent field keeps. A config that says nothing
// still gets a defensible recorder rather than a zero that polls every
// nanosecond.
func Defaults() Config {
	return Config{
		AuditLog:        "/var/log/audit/audit.log",
		AuditFrom:       "end",
		CycleSeconds:    5,
		BeatSeconds:     60,
		BatchSeconds:    10,
		BatchMax:        200,
		SpoolMaxBatches: 500,
		Gzip:            true,
	}
}

// DefaultWatch is the pack a config with no watch list gets: the developer
// machine and agent files the research names as what changes first. Paths
// are resolved against the home directory at run time; a file that does not
// exist is watched anyway, because "created" is the most interesting thing a
// watched path can do.
func DefaultWatch() []WatchEntry {
	return []WatchEntry{
		{Path: "~/.ssh/authorized_keys", Kind: KindKey},
		{Path: "~/.ssh", Kind: KindKey, Glob: "id_*"},
		{Path: "~/.mcp.json", Kind: KindMCPConfig},
		{Path: "~/CLAUDE.md", Kind: KindAgentConfig},
		{Path: "~/AGENTS.md", Kind: KindAgentConfig},
		{Path: "~/.cursorrules", Kind: KindAgentConfig},
		{Path: "~/.claude/settings.json", Kind: KindAgentConfig},
		{Path: "~/.claude/projects", Kind: KindAgentConfig},
		{Path: "~/.env", Kind: KindEnv},
	}
}

// Validate refuses a config that cannot be what it claims.
//
// Every refusal is a sentence rather than a bool, because a pack an operator
// cannot deploy is a pack they delete, and the sentence is the difference
// between deleted and fixed.
func (c Config) Validate() error {
	for i, e := range c.Watch {
		if strings.TrimSpace(e.Path) == "" {
			return fmt.Errorf("watch entry %d has no path", i+1)
		}
		if !validKind(e.Kind) {
			return fmt.Errorf(
				"watch entry %q names kind %q. A kind is one of key, env, "+
					"mcp-config, agent-config, other — a kind a rule has "+
					"never heard of is a label, not a signal", e.Path, e.Kind)
		}
	}
	switch c.AuditFrom {
	case "", "end", "start":
	default:
		return fmt.Errorf(
			"audit_from is %q; it is \"end\" or \"start\". A first run "+
				"either joins the log where it is or replays it, and which "+
				"one must be a decision rather than a typo", c.AuditFrom)
	}
	if c.CycleSeconds < 1 || c.CycleSeconds > 3600 {
		return fmt.Errorf("cycle_seconds is %d; it is between 1 and 3600", c.CycleSeconds)
	}
	if c.BeatSeconds < 10 || c.BeatSeconds > 86400 {
		return fmt.Errorf("heartbeat_seconds is %d; it is between 10 and 86400. "+
			"A heartbeat is what the server watches for silence, and one "+
			"faster than ten seconds or slower than a day is noise either way",
			c.BeatSeconds)
	}
	if c.BatchSeconds < 1 || c.BatchSeconds > 600 {
		return fmt.Errorf("batch_seconds is %d; it is between 1 and 600", c.BatchSeconds)
	}
	if c.BatchMax < 1 || c.BatchMax > 10000 {
		return fmt.Errorf("batch_max is %d; it is between 1 and 10000", c.BatchMax)
	}
	if c.SpoolMaxBatches < 1 {
		return fmt.Errorf("spool_max_batches is %d; it is at least 1", c.SpoolMaxBatches)
	}
	return nil
}

// parse reads a config, refusing unknown fields.
//
// Unknown fields refused is the whole CrowdStrike lesson in one decoder
// setting: a config key this program does not know is a typo or a version
// skew, and both must stop the program rather than be silently ignored —
// the ignored one is the watched path that was never watched.
func parse(b []byte) (Config, error) {
	cfg := Defaults()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("not a collector config: %w", err)
	}
	if len(cfg.Watch) == 0 {
		cfg.Watch = DefaultWatch()
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// LoadFile reads the config a deployment hands over on disk.
func LoadFile(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return parse(b)
}

// CachePath is where a fetched config is kept inside the state directory, so
// an unreachable server at startup is an outage, not a collector that
// forgets its watch list and silently ships the default one.
func CachePath(stateDir string) string {
	return filepath.Join(stateDir, "config.json")
}

// FetchConfig reads the pack from the server that will receive the evidence.
//
// The GET proves itself with the same credential a batch does. What comes
// back is validated here before it is cached: a pack the server serves that
// this program cannot obey is a deployment error, and discovering it on the
// endpoint at cache time is better than at outage time.
func FetchConfig(ctx context.Context, server, name, secret string, client *http.Client) (Config, []byte, error) {
	if client == nil {
		client = fetch.Speaking("collector", fetch.Anywhere, 30*time.Second)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimSuffix(server, "/")+"/v1/collector/config", nil)
	if err != nil {
		return Config{}, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("X-Vaigil-Token", name)
	res, err := client.Do(req)
	if err != nil {
		return Config{}, nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return Config{}, nil, fmt.Errorf("the server has no collector config")
	}
	if res.StatusCode != http.StatusOK {
		return Config{}, nil, fmt.Errorf("the server answered %s for the config",
			res.Status)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 256<<10))
	if err != nil {
		return Config{}, nil, err
	}
	cfg, err := parse(b)
	if err != nil {
		return Config{}, nil, fmt.Errorf("the server's config is unusable: %w", err)
	}
	return cfg, b, nil
}

// LoadOrFetch is the startup order: a --config file wins (the operator's own
// hands beat the wire), then the server, then the cache the last successful
// fetch left. Only when all three fail does it fall back to the built-in
// defaults, and it says so in the returned note rather than quietly shipping
// a different watch list than the one that was deployed.
func LoadOrFetch(ctx context.Context, file, server, name, secret, stateDir string, client *http.Client) (Config, string, error) {
	if file != "" {
		cfg, err := LoadFile(file)
		return cfg, "file " + file, err
	}
	if server != "" && secret != "" {
		cfg, b, err := FetchConfig(ctx, server, name, secret, client)
		if err == nil {
			if werr := atomicfile.Write(CachePath(stateDir), b, 0o600); werr != nil {
				return cfg, "server (cache not written)", nil
			}
			return cfg, "server", nil
		}
		if cfg, cerr := LoadFile(CachePath(stateDir)); cerr == nil {
			return cfg, fmt.Sprintf("cache (%s)", err), nil
		}
		return Defaults().withDefaults(), fmt.Sprintf("defaults (%s)", err), nil
	}
	cfg, err := LoadFile(CachePath(stateDir))
	if err != nil {
		return Defaults().withDefaults(), "defaults", nil
	}
	return cfg, "cache", nil
}

// withDefaults fills a watch list and validates, for the fallback path where
// Defaults() must still be a legal config.
func (c Config) withDefaults() Config {
	if len(c.Watch) == 0 {
		c.Watch = DefaultWatch()
	}
	return c
}
