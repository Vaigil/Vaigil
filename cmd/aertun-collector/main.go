// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0

// Command aertun-collector is aertun's read-only endpoint recorder: the
// small user-space agent that watches what the agentless estate cannot see
// — the auditd tail, key and agent-configuration files, and its own
// heartbeat — and ships the evidence to a aertun server in signed batches
// (docs/research/12-xdr-ndr-tip-iam.md §8).
//
// It records; it never judges; it never blocks. There is no kernel driver,
// no on-endpoint detection and no prevention in this program, on any OS,
// ever — the CrowdStrike July 2024 lesson is the design brief, and the
// whole of it: nothing this program reads off the wire is executed, the
// configuration is a declarative watch list validated into a Go struct, and
// every decision about what the evidence means runs on the server, where
// the rule engine and its fixtures live.
//
// Its configuration comes from a local file or from the server, cached
// locally — and it is never executed, only read.
//
// Usage:
//
//	AERTUN_COLLECTOR_TOKEN=… aertun-collector \
//	    --server https://aertun.example --token inbound-build01 \
//	    [--config PACK.json] [--state DIR]
//
// The credential is an environment variable rather than a flag on purpose:
// a flag is readable in any process listing, and the credential is the one
// secret this process holds. The server side makes it with:
//
//	AERTUN_CONNECT_SECRET=… aertun connect secret inbound-build01
//
// # Permissions, said here because they are the deployment
//
// Reading /var/log/audit/audit.log needs root, membership of the group the
// log belongs to (adm, or the audit group on some distributions), or a
// service grant — CAP_AUDIT_READ under systemd, ReadFromPath under SELinux
// with a policy for it. The collector is designed to run as a dedicated
// unprivileged user in that group, with a watch pack naming files that user
// may read; where it cannot read a watched file it says nothing about that
// file rather than pretending it looked, and where it cannot read the audit
// log it keeps watching for it and says so once.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aertun/aertun/internal/collector"
	"github.com/aertun/aertun/internal/fetch"
)

// tokenEnv is where the credential comes from.
const tokenEnv = "AERTUN_COLLECTOR_TOKEN"

// version is stamped by the Makefile's linker flags, as in cmd/aertun.
var version = "dev"

func main() {
	server := flag.String("server", "", "the aertun server's base URL")
	name := flag.String("token", "", "this collector's credential name on the server (the secret itself comes from "+tokenEnv+")")
	config := flag.String("config", "", "a declarative config file (otherwise fetched from the server and cached)")
	state := flag.String("state", "", "the state directory: position, config cache, spool (default ~/.aertun-collector)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, `aertun-collector — the read-only endpoint recorder

It records; it never judges; it never blocks.

  AERTUN_COLLECTOR_TOKEN=… aertun-collector --server URL --token NAME
      [--config PACK.json] [--state DIR]

The watch list and rates come from --config, or from the server, or from
the cache the last fetch left, or from the built-in defaults — in that
order. Whatever arrives is read, never executed.
`)
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Printf("aertun-collector %s\n", version)
		return
	}
	secret := os.Getenv(tokenEnv)
	if *server == "" || *name == "" || secret == "" {
		flag.Usage()
		fmt.Fprintf(os.Stderr, "\n--server, --token and %s are all required; the "+
			"secret is an environment variable because a flag is readable in "+
			"any process listing\n", tokenEnv)
		os.Exit(2)
	}
	if !collector.ValidName(*name) {
		fmt.Fprintf(os.Stderr, "--token %q: a collector's name is two to forty "+
			"lower-case letters, digits and hyphens, the same shape the "+
			"server's feed names use\n", *name)
		os.Exit(2)
	}
	dir := *state
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "no --state and no home directory: %v\n", err)
			os.Exit(2)
		}
		dir = filepath.Join(home, ".aertun-collector")
	}
	logf := func(format string, args ...any) {
		fmt.Printf("  "+format+"\n", args...)
	}

	// The config: the operator's file, the server, the cache, the defaults.
	// Which one won is said out loud, because a collector quietly running a
	// different watch list than the one that was deployed is a recorder
	// whose operator believes in a pack it is not holding.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := fetch.Speaking("collector", fetch.Anywhere, 30*time.Second)
	cfg, from, err := collector.LoadOrFetch(ctx, *config, *server, *name, secret,
		dir, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "the config is unusable: %v\n", err)
		os.Exit(2)
	}
	logf("config from %s: %d watch path(s), cycle %ds, heartbeat %ds",
		from, len(cfg.Watch), cfg.CycleSeconds, cfg.BeatSeconds)
	logf("audit log %s; evidence to %s%s as %s",
		cfg.AuditLog, *server, collector.CollectorPath, *name)

	collector.Version = version
	agent := &collector.Agent{
		Config: cfg, Name: *name, Secret: secret, Server: *server,
		StateDir: dir, Logf: logf,
	}
	if err := agent.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "collector: %v\n", err)
		os.Exit(1)
	}
}
