// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

// The agent: one loop that owns the rhythm.
//
// Tail, watch, heartbeat and ship on a single cycle, in that order. Not a
// goroutine per concern: a recorder whose parts each had a timer is a
// recorder with four ways to interleave badly on a laptop that suspends,
// and the cycle is short enough that nothing notices the difference.
//
// The heartbeat says the host, how long this process has been running, and
// how much evidence left or was dropped. It is the recorder-blind signal:
// an agent machine that has stopped telling the truth stops sending one.
// What that means — noticing the silence, correlating it with what the
// machine's other telemetry says, deciding it is worth a person — is
// server-side content, written as rules against collector/heartbeat, and
// deliberately not a judgement this binary makes about itself.

// Version is what each heartbeat says built it. Set by the linker stamp in
// the Makefile, the same stamp the server's own binary carries.
var Version = "dev"

// Agent is a configured collector run.
type Agent struct {
	Config Config
	// Name is the collector's identity and the name of its credential on
	// the server ("inbound-build01"). Validated with the same shape the
	// server's feed names use, because it becomes a path segment and a
	// store key there.
	Name string
	// Secret is the credential itself, from the environment, never a flag:
	// flags are readable in any process listing.
	Secret string
	// Server is the base URL evidence ships to.
	Server string
	// StateDir holds the position file, the config cache and the spool.
	StateDir string
	// Now is the clock; tests set it. Logf is the diagnostic line.
	Now  func() time.Time
	Logf func(string, ...any)

	ship *Shipper
	// started is when this process began, for the uptime the heartbeat
	// carries. An uptime that resets on restart is itself information: it
	// says the recorder was restarted, and the server's rules can read it.
	started time.Time
}

// ValidName is the collector-name shape, deliberately the same characters
// as the server's feed names (internal/inbound.ValidName): a name that
// becomes a key and a path on the other side of the wire agrees with that
// side's rules or arrives refused.
func ValidName(s string) bool {
	if len(s) < 2 || len(s) > 40 {
		return false
	}
	for i, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' && i > 0) {
			return false
		}
	}
	return true
}

func (a *Agent) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

func (a *Agent) logf(format string, args ...any) {
	if a.Logf != nil {
		a.Logf(format, args...)
	}
}

func (a *Agent) hostname() string {
	if a.Config.Hostname != "" {
		return a.Config.Hostname
	}
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// Run is the loop, until ctx is done. It returns what it managed to do
// on the way out.
func (a *Agent) Run(ctx context.Context) error {
	if err := os.MkdirAll(a.StateDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(a.StateDir, "spool"), 0o700); err != nil {
		return err
	}
	home := ""
	if u, err := user.Current(); err == nil {
		home = u.HomeDir
	}
	host := a.hostname()
	tail := &Tailer{
		LogPath: a.Config.AuditLog,
		PosPath: filepath.Join(a.StateDir, "auditd-position.json"),
		Host:    host,
		From:    a.Config.AuditFrom,
		Logf:    a.logf,
	}
	if _, err := os.Stat(a.Config.AuditLog); err != nil {
		a.logf("audit log %s is not readable yet (%v). Reading /var/log/audit "+
			"needs root, the adm group, or a service grant such as "+
			"CAP_AUDIT_READ; the collector keeps watching for it either way",
			a.Config.AuditLog, err)
	}
	watch, err := NewWatch(a.Config.Watch, home, host)
	if err != nil {
		return err
	}
	a.ship = &Shipper{
		Name: a.Name, Secret: a.Secret, Server: a.Server,
		Dir:          filepath.Join(a.StateDir, "spool"),
		MaxBatches:   a.Config.SpoolMaxBatches,
		BatchMax:     a.Config.BatchMax,
		BatchSeconds: a.Config.BatchSeconds,
		Gzip:         a.Config.Gzip,
		Now:          a.now, Logf: a.logf,
	}
	a.ship.Resume()
	a.started = a.now()

	tick := time.NewTicker(time.Duration(a.Config.CycleSeconds) * time.Second)
	defer tick.Stop()
	var beat time.Time
	for {
		a.pass(ctx, tail, watch, &beat)
		select {
		case <-ctx.Done():
			a.logf("stopping: sealing and sending what was noticed")
			for _, rec := range tail.Flush() {
				_ = a.ship.Add(Record{Source: SourceAuditd, At: a.now(), Data: rec})
			}
			a.ship.Flush(context.Background())
			c := a.ship.Counters()
			a.logf("stopped: %d records shipped, %d dropped, %d retries",
				c.Shipped, c.Dropped, c.Retries)
			return nil
		case <-tick.C:
		}
	}
}

// pass is one cycle: what the kernel did, what the watched files did,
// whether the heart is due, and whatever can leave.
func (a *Agent) pass(ctx context.Context, tail *Tailer, watch *Watch, beat *time.Time) {
	now := a.now()
	recs, err := tail.Poll()
	if err != nil {
		a.logf("audit tail: %v", err)
	}
	for _, rec := range recs {
		// The record's own @timestamp is the event's time; At is when this
		// process noticed it. Both travel: an event time that is not arrival
		// time is the difference a late delivery needs to be seen by.
		_ = a.ship.Add(Record{Source: SourceAuditd, At: now, Data: rec})
	}
	for _, rec := range watch.Records(now) {
		_ = a.ship.Add(Record{Source: SourceWatch, At: now, Data: rec})
	}
	if beat.IsZero() {
		*beat = now
	} else if now.Sub(*beat) >= time.Duration(a.Config.BeatSeconds)*time.Second {
		*beat = now
		_ = a.ship.Add(Record{Source: SourceHeartbeat, At: now,
			Data: a.heartbeat(now)})
	}
	if err := a.ship.Tick(ctx); err != nil {
		a.logf("shipping: %v", err)
	}
}

// heartbeat is the one-minute "the recorder is here" record. Every field is
// something the server's silence-detection or an operator wants at a
// glance, and nothing else: the heartbeat is a signal, not a status page.
func (a *Agent) heartbeat(now time.Time) map[string]any {
	c := Counts{}
	if a.ship != nil {
		c = a.ship.Counters()
	}
	return map[string]any{
		"host":           a.hostname(),
		"uptime_seconds": strconv.FormatInt(int64(now.Sub(a.started).Seconds()), 10),
		"shipped":        strconv.FormatInt(c.Shipped, 10),
		"dropped":        strconv.FormatInt(c.Dropped, 10),
		"batches":        strconv.FormatInt(c.Batches, 10),
		"retries":        strconv.FormatInt(c.Retries, 10),
		"version":        Version,
		"go":             runtime.Version(),
	}
}
