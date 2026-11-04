// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aeroprove/aeroprove/internal/agentreg"
	"github.com/aeroprove/aeroprove/internal/atomicfile"
	"github.com/aeroprove/aeroprove/internal/audit"
	"github.com/aeroprove/aeroprove/internal/automate"
	"github.com/aeroprove/aeroprove/internal/collector"
	"github.com/aeroprove/aeroprove/internal/detect"
	"github.com/aeroprove/aeroprove/internal/fetch"
	"github.com/aeroprove/aeroprove/internal/inbound"
	"github.com/aeroprove/aeroprove/internal/oidc"
	"github.com/aeroprove/aeroprove/internal/otlp"
	"github.com/aeroprove/aeroprove/internal/source"
	"github.com/aeroprove/aeroprove/internal/spool"
	"github.com/aeroprove/aeroprove/internal/ssf"
	"github.com/aeroprove/aeroprove/internal/telemetry"
	"github.com/aeroprove/aeroprove/internal/upkeep"
)

// Events pushed to the server, the moment they happen.
//
// A feed's endpoint is /feeds/NAME on the admin. What arrives is proved
// (internal/inbound, internal/ssf), stored in the event store like anything
// collected, read by the rules at once, and — when it says something a rule
// can act on — put to the automations as a signal. See internal/inbound for
// how each kind proves where it came from.

// spoolMu is the server's one way to the event store. Everything in this
// process that writes there takes it, because two handles on one store each
// keep their own index, and whichever saves last would lose the other's
// segments.
var spoolMu sync.Mutex

// withSpool opens the store, does fn and lets the store go without sealing
// the segment, so the next writer adds to it rather than starting another.
func withSpool(root string, fn func(*spool.Spool) error) error {
	spoolMu.Lock()
	defer spoolMu.Unlock()
	return useSpool(root, fn)
}

func useSpool(root string, fn func(*spool.Spool) error) error {
	sp, err := openSpool(root, spool.Options{})
	if err != nil {
		return err
	}
	ferr := fn(sp)
	if rerr := sp.Release(); ferr == nil {
		ferr = rerr
	}
	return ferr
}

// detectInServer runs the rules over what has arrived and gives what they
// raise to the automations. A site with no rules has nothing to run, which
// is not a failure here; anything else that stops the pass is recorded.
func detectInServer(root string, sp *spool.Spool) {
	_, _ = detectAs(root, sp, "detect-on-arrival")
}

// detectAs runs one pass as a service with the name given, and says how
// many findings it opened.
func detectAs(root string, sp *spool.Spool, name string) (int, error) {
	caller := &Caller{Name: name, Kind: audit.KindService, Verified: true}
	sum, err := detectPass(root, "", 0, caller, sp)
	if errors.Is(err, errNoRules) {
		return 0, nil
	}
	if err != nil {
		record(root, audit.Record{Action: "detect.run", Resource: "/findings", Outcome: audit.Failure,
			Principal: caller.Name, Kind: caller.Kind, Model: caller.Model, Verified: true,
			Detail: map[string]string{"error": onOneLine(err.Error())}})
		return 0, err
	}
	automateFindings(root, sum.New)
	return len(sum.New), nil
}

// detectJob runs the rules over AeroProve's own log on the server's timer.
//
// The rules about AeroProve itself, what agents did and the correlations
// across them ran when somebody typed `aeroprove detect run`, when a feed
// pushed events, or when scheduled collection brought some in. An
// installation that governs agents and collects from nowhere ran none of
// them, and nothing was checked in a quiet hour even where collection was
// set up. Now each tick in which the log has grown past what the rules
// last read runs a pass, and what it raises goes to the automations like
// anything that arrives.
func detectJob(root string) upkeep.Job {
	return upkeep.Job{Name: "detect", Do: func(now time.Time) (int, error) {
		grew, err := selfLogGrew(root)
		if err != nil || !grew {
			return 0, err
		}
		opened := 0
		err = withSpool(root, func(sp *spool.Spool) error {
			n, derr := detectAs(root, sp, "detect-schedule")
			opened = n
			return derr
		})
		return opened, err
	}}
}

// -- feeds, kept --------------------------------------------------------------

func inboundDir(root string) string        { return filepath.Join(root, "inbound") }
func feedsPath(root string) string         { return filepath.Join(inboundDir(root), "feeds.json") }
func feedStatusPath(root string) string    { return filepath.Join(inboundDir(root), "status.json") }
func feedSecretName(name string) string    { return "inbound-" + name }
func feedSourceName(f inbound.Feed) string { return "feed/" + f.Name }

var feedsMu sync.Mutex

func loadFeeds(root string) (map[string]inbound.Feed, error) {
	out := map[string]inbound.Feed{}
	b, err := os.ReadFile(feedsPath(root))
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%s is unreadable: %w", feedsPath(root), err)
	}
	return out, nil
}

func saveFeeds(root string, m map[string]inbound.Feed) error {
	if err := os.MkdirAll(inboundDir(root), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(feedsPath(root), b, 0o600)
}

// changeFeed reads, changes and writes one feed under the lock.
func changeFeed(root, name string, fn func(*inbound.Feed) error) error {
	feedsMu.Lock()
	defer feedsMu.Unlock()
	m, err := loadFeeds(root)
	if err != nil {
		return err
	}
	f, ok := m[name]
	if !ok {
		return fmt.Errorf("there is no feed %q (aeroprove inbound list)", name)
	}
	if err := fn(&f); err != nil {
		return err
	}
	m[name] = f
	return saveFeeds(root, m)
}

// inboundStatus is what a feed has done, for the screen and the command.
type inboundStatus struct {
	Deliveries int         `json:"deliveries"`
	Records    int         `json:"records"`
	Stored     int         `json:"stored"`
	Known      int         `json:"known"`
	Missed     int         `json:"missed"`
	Field      string      `json:"field,omitempty"`
	Signals    int         `json:"signals"`
	Refused    int         `json:"refused"`
	LastAt     time.Time   `json:"last_at,omitempty"`
	LastRefuse time.Time   `json:"last_refused,omitempty"`
	Why        string      `json:"why,omitempty"`
	Error      string      `json:"error,omitempty"`
	Seen       []string    `json:"seen,omitempty"`
	Recent     []signalRow `json:"recent,omitempty"`
}

// signalRow is one signal as the screen lists it.
type signalRow struct {
	At       time.Time `json:"at"`
	Type     string    `json:"type"`
	Person   string    `json:"person"`
	Severity string    `json:"severity"`
	Reason   string    `json:"reason,omitempty"`
}

func loadFeedStatus(root string) (map[string]*inboundStatus, error) {
	out := map[string]*inboundStatus{}
	b, err := os.ReadFile(feedStatusPath(root))
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%s is unreadable: %w", feedStatusPath(root), err)
	}
	return out, nil
}

// -- the endpoint -------------------------------------------------------------

// inboundServer answers /feeds/NAME.
type inboundServer struct {
	root string
	now  func() time.Time
	seen inbound.Seen
	// keyClient reads a transmitter's keys.
	keyClient *fetch.Client

	mu        sync.Mutex
	status    map[string]*inboundStatus
	receivers map[string]cachedReceiver
	// streams are the audit streams' receivers, by feed.
	streams map[string]*heldStream
	queue   []pushed
	signals []automate.Event
	rate    map[string]*rateWindow
	work    chan struct{}
	dirty   bool
	// fresh is that events were stored since the rules last ran, by the
	// worker or by a delivery that found the store free.
	fresh bool
}

type cachedReceiver struct {
	key string
	r   *ssf.Receiver
}

// pushed is one delivery waiting for the store.
type pushed struct {
	feed inbound.Feed
	docs []any
	set  *ssf.SET
	at   time.Time
}

type rateWindow struct {
	start time.Time
	n     int
}

// feedRate is how many deliveries a feed may make in a minute. Okta's cap
// is 400,000 events a day across every hook, a few a second; this is far
// above anything legitimate and far below what fills a disk.
const feedRate = 3000

// queueCap bounds what waits in memory while the store is busy.
const queueCap = 10_000

func newInboundServer(root string) *inboundServer {
	c := fetch.New()
	c.Purpose = "signals"
	c.UserAgent = "aeroprove/1 (+shared signals receiver)"
	s := &inboundServer{root: root, now: time.Now, keyClient: c, receivers: map[string]cachedReceiver{},
		rate: map[string]*rateWindow{}, work: make(chan struct{}, 1)}
	if st, err := loadFeedStatus(root); err == nil {
		s.status = st
	} else {
		s.status = map[string]*inboundStatus{}
	}
	return s
}

// run is the worker: it takes what waits, stores it, runs the rules and the
// automations, and writes the status. It stops with ctx.
func (s *inboundServer) run(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			s.process()
			s.flush()
			return
		case <-s.work:
			// A burst arrives as several deliveries; one pass takes them all.
			select {
			case <-ctx.Done():
			case <-time.After(300 * time.Millisecond):
			}
			s.process()
			s.flush()
		case <-tick.C:
			s.flush()
		}
	}
}

func (s *inboundServer) poke() {
	select {
	case s.work <- struct{}{}:
	default:
	}
}

// process stores what waits, runs the rules over it, then the automations.
func (s *inboundServer) process() {
	err := withSpool(s.root, func(sp *spool.Spool) error {
		s.drain(sp)
		s.mu.Lock()
		fresh := s.fresh
		s.fresh = false
		s.mu.Unlock()
		if fresh {
			detectInServer(s.root, sp)
		}
		return nil
	})
	if err != nil {
		record(s.root, audit.Record{Action: "inbound.store", Resource: "/feeds", Outcome: audit.Failure,
			Principal: automateBy, Kind: audit.KindService, Verified: true,
			Detail: map[string]string{"error": onOneLine(err.Error())}})
	}
	s.mu.Lock()
	sigs := s.signals
	s.signals = nil
	s.mu.Unlock()
	if len(sigs) == 0 {
		return
	}
	engine := automationEngine(s.root)
	for _, ev := range sigs {
		_, _ = engine.Handle(ev)
	}
}

// drain writes what waits into sp, under spoolMu, and reports how many
// events it stored.
func (s *inboundServer) drain(sp *spool.Spool) int {
	s.mu.Lock()
	q := s.queue
	s.queue = nil
	s.mu.Unlock()
	if len(q) == 0 {
		return 0
	}
	aliases, _ := loadAliases(s.root)
	if aliases == nil {
		aliases = map[string]alias{}
	}
	stored, learned := 0, false
	for _, p := range q {
		n, l := s.store(sp, p, aliases)
		stored += n
		learned = learned || l
	}
	if learned {
		_ = saveAliases(s.root, aliases)
	}
	if stored > 0 {
		s.mu.Lock()
		s.fresh = true
		s.mu.Unlock()
	}
	return stored
}

// store maps one delivery into events and appends them, and turns what it
// says into signals for the automations.
func (s *inboundServer) store(sp *spool.Spool, p pushed, aliases map[string]alias) (int, bool) {
	s.mu.Lock()
	st := s.statusOf(p.feed.Name)
	s.mu.Unlock()
	var events []telemetry.Event
	var sigs []automate.Event
	learned := false
	switch {
	case p.set != nil:
		e, sig := setEvent(p.feed, p.set, aliases, p.at)
		events = append(events, e)
		if sig != nil {
			sigs = append(sigs, *sig)
		}
	default:
		src, err := s.mapping(p.feed)
		if err != nil {
			s.mu.Lock()
			st.Error = err.Error()
			s.dirty = true
			s.mu.Unlock()
			return 0, false
		}
		cs := collectStatus{Seen: st.Seen}
		events = mapRecords(src, p.docs, &cs, aliases, p.at)
		learned = cs.learned
		s.mu.Lock()
		st.Seen, st.Records, st.Known, st.Missed = cs.Seen, st.Records+cs.Records, st.Known+cs.Known, st.Missed+cs.Missed
		if cs.Field != "" {
			st.Field = cs.Field
		}
		s.mu.Unlock()
		if p.feed.Kind == inbound.Okta {
			for _, d := range p.docs {
				m, _ := d.(map[string]any)
				if sig := oktaSignalEvent(p.feed, m, p.at); sig != nil {
					sigs = append(sigs, *sig)
				}
			}
		}
	}
	stored := 0
	var serr error
	// One batch for one push: the writer's lock and the index's save are
	// taken once, and a bad event refuses the whole push rather than
	// leaving half of it stored around the failure.
	if _, err := sp.AppendBatch(events); err != nil {
		serr = err
	} else {
		stored = len(events)
	}
	s.mu.Lock()
	st.Stored += stored
	if serr != nil {
		st.Error = serr.Error()
	} else {
		st.Error = ""
	}
	for _, sig := range sigs {
		st.Signals++
		st.Recent = append([]signalRow{{At: p.at, Type: sig.Fields["type"], Person: sig.Subject,
			Severity: sig.Fields["severity"], Reason: sig.Fields["reason"]}}, st.Recent...)
		if len(st.Recent) > 50 {
			st.Recent = st.Recent[:50]
		}
	}
	s.signals = append(s.signals, sigs...)
	s.dirty = true
	s.mu.Unlock()
	return stored, learned
}

// mapping is the source mapping a feed's records go through.
func (s *inboundServer) mapping(f inbound.Feed) (source.Source, error) {
	name := f.Mapping
	if f.Kind == inbound.Okta {
		name = "okta/system"
	}
	return findSource(s.root, name)
}

func (s *inboundServer) statusOf(name string) *inboundStatus {
	st := s.status[name]
	if st == nil {
		st = &inboundStatus{}
		s.status[name] = st
	}
	return st
}

func (s *inboundServer) flush() {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return
	}
	b, err := json.MarshalIndent(s.status, "", " ")
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return
	}
	if os.MkdirAll(inboundDir(s.root), 0o700) == nil {
		_ = atomicfile.Write(feedStatusPath(s.root), b, 0o600)
	}
}

// refused counts a delivery that did not prove itself. Not written to the
// audit log one by one: whoever is failing would be choosing how fast it
// grows. The count and the last reason are on the feed's status.
func (s *inboundServer) refused(name, why string) {
	s.mu.Lock()
	st := s.statusOf(name)
	st.Refused++
	st.LastRefuse = s.now().UTC()
	st.Why = why
	s.dirty = true
	s.mu.Unlock()
}

func (s *inboundServer) allow(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	w := s.rate[name]
	if w == nil || now.Sub(w.start) >= time.Minute {
		w = &rateWindow{start: now}
		s.rate[name] = w
	}
	w.n++
	return w.n <= feedRate
}

// accept queues a delivery and stores it now if the store is free.
func (s *inboundServer) accept(p pushed) error {
	s.mu.Lock()
	if len(s.queue) >= queueCap {
		s.mu.Unlock()
		return errors.New("busy")
	}
	s.queue = append(s.queue, p)
	st := s.statusOf(p.feed.Name)
	st.Deliveries++
	st.LastAt = p.at
	s.dirty = true
	s.mu.Unlock()
	// Written before the answer when nothing else holds the store, so a
	// sender told "received" was; otherwise right after whoever holds it.
	if spoolMu.TryLock() {
		_ = useSpool(s.root, func(sp *spool.Spool) error {
			s.drain(sp)
			return nil
		})
		spoolMu.Unlock()
	}
	s.poke()
	return nil
}

func (s *inboundServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	name := strings.TrimPrefix(r.URL.Path, "/feeds/")
	if !inbound.ValidName(name) {
		http.NotFound(w, r)
		return
	}
	feeds, err := loadFeeds(s.root)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	f, ok := feeds[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if f.Off {
		http.Error(w, "this feed is switched off", http.StatusServiceUnavailable)
		return
	}
	if !s.allow(name) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many deliveries", http.StatusTooManyRequests)
		return
	}
	limit := int64(1 << 20)
	switch f.Kind {
	case inbound.SSF:
		limit = ssf.MaxToken
	case inbound.AuditStream:
		limit = streamBodyLimit
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		http.Error(w, "the body is too large", http.StatusRequestEntityTooLarge)
		return
	}
	switch f.Kind {
	case inbound.Okta:
		s.okta(w, r, f, body)
	case inbound.Webhook, inbound.GitHub:
		s.webhook(w, r, f, body)
	case inbound.SSF:
		s.shared(w, r, f, body)
	case inbound.AuditStream:
		s.auditStream(w, r, f, body)
	default:
		http.NotFound(w, r)
	}
}

func (s *inboundServer) okta(w http.ResponseWriter, r *http.Request, f inbound.Feed, body []byte) {
	if !inbound.StaticMatches(inbound.BearerOrRaw(r.Header.Get("Authorization")), f.TokenHash) {
		s.refused(f.Name, "the Authorization header does not hold this feed's secret")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		b, ok := inbound.OktaChallenge(r)
		if !ok {
			http.Error(w, "a GET here is Okta's verification, with its challenge header", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	case http.MethodPost:
		d, err := inbound.ParseOkta(body)
		if err != nil {
			s.refused(f.Name, err.Error())
			http.Error(w, "not an event hook delivery", http.StatusBadRequest)
			return
		}
		if d.EventID != "" && !s.seen.First(f.Name+":"+d.EventID, s.now()) {
			w.WriteHeader(http.StatusOK)
			return
		}
		docs := make([]any, 0, len(d.Data.Events))
		for _, e := range d.Data.Events {
			docs = append(docs, e)
		}
		if err := s.accept(pushed{feed: f, docs: docs, at: s.now().UTC()}); err != nil {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
	}
}

func (s *inboundServer) webhook(w http.ResponseWriter, r *http.Request, f inbound.Feed, body []byte) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	secrets, err := loadSecrets(s.root)
	secret := secrets[f.Secret]
	if err != nil || secret == "" {
		http.Error(w, "this feed has no secret to check against", http.StatusServiceUnavailable)
		return
	}
	var id string
	if f.Kind == inbound.GitHub {
		id, err = inbound.VerifyGitHub(r.Header, body, secret)
	} else {
		id, err = inbound.VerifyStandard(r.Header, body, secret, s.now())
	}
	if err != nil {
		s.refused(f.Name, err.Error())
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !s.seen.First(f.Name+":"+id, s.now()) {
		w.WriteHeader(http.StatusOK)
		return
	}
	docs, err := inbound.Records(body)
	if err != nil {
		s.refused(f.Name, err.Error())
		http.Error(w, "the body is not JSON records", http.StatusBadRequest)
		return
	}
	if err := s.accept(pushed{feed: f, docs: docs, at: s.now().UTC()}); err != nil {
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func setError(w http.ResponseWriter, status int, e *ssf.Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(e)
}

func (s *inboundServer) shared(w http.ResponseWriter, r *http.Request, f inbound.Feed, body []byte) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if f.TokenHash != "" && !inbound.StaticMatches(inbound.BearerOrRaw(r.Header.Get("Authorization")), f.TokenHash) {
		s.refused(f.Name, "the Authorization header does not hold this stream's secret")
		setError(w, http.StatusUnauthorized, &ssf.Error{Code: "authentication_failed", Description: "the push did not carry this stream's authorization"})
		return
	}
	ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if ct != "application/secevent+jwt" && ct != "application/jwt" {
		setError(w, http.StatusBadRequest, &ssf.Error{Code: "invalid_request", Description: "a push is a security event token, content type application/secevent+jwt"})
		return
	}
	rcv, err := s.receiver(f)
	if err != nil {
		setError(w, http.StatusServiceUnavailable, &ssf.Error{Code: "access_denied", Description: "this receiver cannot verify events right now"})
		return
	}
	set, err := rcv.Verify(string(body))
	if err != nil {
		var e *ssf.Error
		if !errors.As(err, &e) {
			e = &ssf.Error{Code: "invalid_request", Description: err.Error()}
		}
		s.refused(f.Name, e.Error())
		setError(w, http.StatusBadRequest, e)
		return
	}
	if !s.seen.First(f.Name+":"+set.JTI, s.now()) {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch set.Short {
	case "verification":
		state, _ := set.Claims["state"].(string)
		if set.Subject.ID == f.StreamID || f.StreamID == "" {
			_ = changeFeed(s.root, f.Name, func(x *inbound.Feed) error {
				if x.State != "" && state != "" && inbound.StaticMatches(state, x.State) {
					x.Verified, x.State = s.now().UTC(), ""
				}
				return nil
			})
		}
		w.WriteHeader(http.StatusAccepted)
		return
	case "stream-updated":
		status, _ := set.Claims["status"].(string)
		_ = changeFeed(s.root, f.Name, func(x *inbound.Feed) error {
			if status == "enabled" || status == "paused" || status == "disabled" {
				x.Status = status
			}
			return nil
		})
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if err := s.accept(pushed{feed: f, set: set, at: s.now().UTC()}); err != nil {
		setError(w, http.StatusServiceUnavailable, &ssf.Error{Code: "access_denied", Description: "busy; send it again"})
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// receiver is a stream's verifier, kept while its configuration stands.
func (s *inboundServer) receiver(f inbound.Feed) (*ssf.Receiver, error) {
	key := f.Issuer + "|" + f.Audience + "|" + f.JWKSURI
	s.mu.Lock()
	c, ok := s.receivers[f.Name]
	s.mu.Unlock()
	if ok && c.key == key {
		return c.r, nil
	}
	ks, err := oidc.NewKeySet(f.JWKSURI, func(ctx context.Context, u string) ([]byte, error) {
		res, err := s.keyClient.Get(ctx, u)
		if err != nil {
			return nil, err
		}
		return res.Body, nil
	})
	if err != nil {
		return nil, err
	}
	r := &ssf.Receiver{Issuer: f.Issuer, Audience: f.Audience, Keys: ks,
		Algorithms: []oidc.Algorithm{oidc.RS256, oidc.ES256, oidc.PS256}}
	s.mu.Lock()
	s.receivers[f.Name] = cachedReceiver{key: key, r: r}
	s.mu.Unlock()
	return r, nil
}

// -- what a delivery means ----------------------------------------------------

var signalWords = map[string]string{
	"session-revoked": "session ended", "credential-change": "credential changed",
	"device-compliance-change": "device compliance changed", "assurance-level-change": "assurance changed",
	"risk-level-change": "risk changed", "token-claims-change": "claims changed",
	"account-disabled": "account disabled", "account-enabled": "account enabled", "account-purged": "account deleted",
	"account-credential-change-required": "credential change required", "credential-compromise": "credential compromised",
	"identifier-changed": "identifier changed", "identifier-recycled": "identifier recycled",
	"recovery-activated": "account recovery started", "recovery-information-changed": "recovery details changed",
	"reported": "suspicious activity reported", "threat": "threat detected", "session-moved": "session context changed",
}

func signalSummary(feed, typ, person, reason string) string {
	words := signalWords[typ]
	if words == "" {
		words = typ
	}
	out := fmt.Sprintf("%s: %s for %s", feed, words, person)
	if reason != "" {
		out += " (" + reason + ")"
	}
	return out
}

// setEvent is a shared signal as an event for the store, and as a signal for
// the rules when it is about somebody.
func setEvent(f inbound.Feed, set *ssf.SET, aliases map[string]alias, at time.Time) (telemetry.Event, *automate.Event) {
	sig := set.Signal()
	issuer := f.Alias
	if issuer == "" {
		issuer = f.Name
	}
	person := set.Subject.Person()
	ref := set.Subject.Ref()
	if person == "" && ref != "" {
		if a, ok := aliases[issuer+":"+ref]; ok {
			person = a.Person
		}
	}
	who := person
	if who == "" {
		who = ref
	}
	if who == "" {
		who = "an unnamed subject"
	}
	when := set.IssuedAt
	if ts, ok := set.Claims["event_timestamp"].(float64); ok && ts > 0 {
		when = time.Unix(int64(ts), 0)
	}
	sev := map[string]telemetry.Severity{"high": telemetry.SeverityHigh, "medium": telemetry.SeverityMedium,
		"low": telemetry.SeverityLow}[sig.Severity]
	e := telemetry.Event{Time: when.UTC(), Received: at, Class: telemetry.ClassAccountChange, Activity: 99,
		Severity: sev, Source: feedSourceName(f), Message: signalSummary(f.Name, sig.Type, who, sig.Reason),
		Raw: map[string]string{"type": sig.Type, "jti": set.JTI, "event": set.Type}}
	if ref != "" || person != "" {
		v := ref
		if v == "" {
			v = person
		}
		e.Actor = telemetry.ID{Issuer: issuer, Value: v}
	}
	if person != "" {
		e.Raw[source.PersonField] = person
	}
	for k, v := range sig.Fields {
		e.Raw[k] = v
	}
	if person == "" {
		return e, nil
	}
	fields := map[string]string{"type": sig.Type, "severity": sig.Severity, "source": f.Name, "issuer": f.Issuer, "reason": sig.Reason}
	for _, k := range []string{"current_level", "previous_level", "change_type", "credential_type", "current_status", "principal"} {
		if v := sig.Fields[k]; v != "" {
			fields[k] = v
		}
	}
	if v := sig.Fields["initiating_entity"]; v != "" {
		fields["initiator"] = v
	}
	return e, &automate.Event{Kind: "signal", Subject: person, At: at, Fields: fields,
		Summary: e.Message}
}

// oktaSignalEvent is the signal an Okta event carries, if any.
func oktaSignalEvent(f inbound.Feed, ev map[string]any, at time.Time) *automate.Event {
	typ, person, fields, ok := inbound.OktaSignal(ev)
	if !ok {
		return nil
	}
	sev := inbound.OktaSeverity(typ, fields)
	out := map[string]string{"type": typ, "severity": sev, "source": f.Name, "issuer": "okta"}
	for k, v := range fields {
		if k == "okta_event" {
			out["reason"] = v
			continue
		}
		out[k] = v
	}
	return &automate.Event{Kind: "signal", Subject: person, At: at, Fields: out,
		Summary: signalSummary(f.Name, typ, person, fields["okta_event"])}
}

// feedNames lists feeds in order, for the command and the screen.
func feedNames(m map[string]inbound.Feed) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// -- OpenTelemetry traces -----------------------------------------------------

// otelCarriesTheToolLabels stamps each GenAI tool call with the labels the
// tool-label table declares for its tool — the same boundary, the same
// honesty, as the join name above: declared data renamed onto the event,
// never a judgement the program made.
//
// The table is the declaration the lethal trifecta stands on (catalogue B2:
// untrusted read → sensitive read → egress, one session). What a tool reads
// and whether it sends outward are facts about the tool, not about any one
// call's arguments — arguments are attacker-influenced text and never enter
// the store — so the label arrives the way the recorder-host mapping's names
// do: looked up from a file somebody wrote, stamped at ingest, and read by
// rules as data. Three honesty rules, and they are the whole design:
//
// Declared, not inferred. A tool listed in the table carries its labels and
// a tool nothing lists carries nothing at all — no empty list, no guess from
// the tool's name, no fallback. An unlabelled fetcher joins no chain, which
// is the honest miss: the table can lag a tool rename, and a leg that
// quietly disappears is recoverable in triage where a fabricated label
// would not be.
//
// The event's own word wins. A raw.labels the deployment's mapping already
// wrote is left alone, exactly as the span's own raw.agent is above — the
// mapping is the deployment's, and this boundary renames what was declared
// elsewhere rather than overwriting it.
//
// Read per push, never cached. The table is loaded for each delivery, so an
// edit reaches the next push and never rewrites what was stored before it —
// the same reach the recorder-host mapping has, for the same reason.
func otelCarriesTheToolLabels(events []telemetry.Event, labels detect.ToolLabels) {
	for i := range events {
		e := &events[i]
		if e.Source != "otel/genai" {
			continue
		}
		tool := e.Raw["tool"]
		if tool == "" {
			continue
		}
		if _, said := e.Raw["labels"]; said {
			continue
		}
		declared := labels.DeclaredFor(tool)
		if declared == "" {
			continue
		}
		if e.Raw == nil {
			e.Raw = map[string]string{}
		}
		e.Raw["labels"] = declared
	}
}

// loadToolLabels reads the deployment's tool-label table from the rules
// directory, where the pack installed it and the organisation tunes it.
//
// An absent table is an empty one — nothing declared, nothing stamped, no
// chain that needs a label can fire — which is the fail-closed answer to
// "nobody said what this tool reads" and exactly the absent-file line the
// recorder-host mapping draws. A table that is there and cannot be read is
// an error, not an empty table: storing the push as though nobody had
// declared anything would silently undo every declaration in the file, and
// the honest failure is the loud one that refuses the push.
func loadToolLabels(root string) (detect.ToolLabels, error) {
	b, err := os.ReadFile(filepath.Join(rulesDir(root, ""), detect.ToolLabelsFile))
	if os.IsNotExist(err) {
		return detect.ToolLabels{}, nil
	}
	if err != nil {
		return detect.ToolLabels{}, err
	}
	labels, perr := detect.ParseToolLabels(b)
	if perr != nil {
		return detect.ToolLabels{}, fmt.Errorf(
			"the tool-label table cannot be read, so no GenAI evidence can "+
				"be labelled against it: %w", perr)
	}
	return labels, nil
}

// otelCarriesTheJoinName copies each GenAI span's actor into the raw field
// the recorder-side declaration writes — the way every cross-source
// correlation in the pack joins, on one named field both sides carry
// (raw.person for the identity rules, actor.value for the platform ones).
//
// Nothing is inferred: the span's actor is a fact the SDK stated, and this
// renames it into the join field rather than deciding anything. The two
// halves then meet in corr.watch-then-call — the watch leg carrying the
// name an operator declared for the host, this leg carrying the name the
// SDK claims for itself — and where those are the same string, the join is
// as honest as either half: the operator said the agent runs there, and the
// agent said it did this. Where they differ, nothing joins and nothing is
// forced to.
//
// A raw.agent the span itself carried is left alone: the source's own word
// about its agent beats a rename of the typed actor.
func otelCarriesTheJoinName(events []telemetry.Event) {
	for i := range events {
		e := &events[i]
		if e.Source != "otel/genai" || e.Actor.Value == "" {
			continue
		}
		if e.Raw == nil {
			e.Raw = map[string]string{}
		}
		if _, said := e.Raw["agent"]; !said {
			e.Raw["agent"] = e.Actor.Value
		}
	}
}

// mountOTLP puts the OTLP/HTTP-JSON traces endpoint beside the console, on
// the same port and outside its session middleware, the way the agent
// interface is mounted: it answers a bearer credential, not a cookie.
//
// A push proves itself with the credential a feed's would (a sealed token
// from the store, compared in constant time — made with `aeroprove connect
// secret inbound-otlp`), is mapped by the same machinery anything else
// that arrives is (the otel/genai source), and is written to the store
// before the answer says it was, then read by the rules at once like every
// other delivery. GenAI spans carry prompt and completion content; that is
// dropped at the boundary and only its length survives (internal/otlp).
// What is added at the boundary is declared, never inferred: the span's
// actor into the join field, and the tool-label table's labels into
// raw.labels for the tool the span names (both below).
func mountOTLP(mux *http.ServeMux, root string) {
	mux.Handle("/v1/traces", &otlp.Handler{
		Token: func() (string, error) {
			s, err := loadSecrets(root)
			if err != nil {
				return "", err
			}
			return s[otlp.SecretName], nil
		},
		Mapping: func() (source.Source, error) {
			return findSource(root, "otel/genai")
		},
		Store: func(events []telemetry.Event) error {
			otelCarriesTheJoinName(events)
			// The labels are read per push and a broken table refuses it:
			// the spans go back to the exporter as unstored rather than in
			// as unlabelled, because a chain that quietly lost its legs is
			// recoverable in triage and a table nobody was told was broken
			// is not.
			labels, err := loadToolLabels(root)
			if err != nil {
				return err
			}
			otelCarriesTheToolLabels(events, labels)
			return withSpool(root, func(sp *spool.Spool) error {
				if _, err := sp.AppendBatch(events); err != nil {
					return err
				}
				// The store is already held here, so the rules run over
				// what has just arrived the way they do for a feed's
				// worker: a push that waited for a timer is a push a quiet
				// hour never checks.
				detectInServer(root, sp)
				return nil
			})
		},
		// The feeds' own figure: far above anything a collector sends and
		// far below what fills a disk.
		Limit: feedRate,
	})
}

// -- the collector endpoint ---------------------------------------------------

// mountCollector puts the endpoint recorder's door beside the console and
// the OTLP one: /v1/collector for the batches, /v1/collector/config for the
// declarative watch pack the collector fetches at startup. Outside the
// session middleware, answering a bearer credential, exactly like every
// other thing that pushes.
//
// The collector is the read-only endpoint agent (docs/research/
// 12-xdr-ndr-tip-iam.md §8), and the boundary here is where its evidence
// stops being that program's and becomes this one's. Three properties of
// that boundary are load-bearing enough to be named:
//
// One credential per collector. The X-AeroProve-Token header names it in the
// sealed store (`aeroprove connect secret inbound-build01`), the bearer value
// is compared through a digest in constant time the way every push
// credential here is, and revoking one collector's credential is one
// rotation rather than a fleet's.
//
// Signed bodies. The batch is HMAC-SHA256 over the batch id, the send time
// and the body, keyed with that same credential — one provisioned secret,
// not two to drift. The timestamp is refused outside the five-minute window
// every signed delivery here is held to, and the batch id is remembered, so
// the collector's own retry after a lost answer stores nothing twice.
//
// Metadata, not content. What a watched file's record carries is the path,
// the kind, the size, the SHA-256 and the operation — the collector hashes
// content and never ships it, and there is nothing at this boundary that
// could receive it even if it did. Evidence-grade means the fact a key
// changed is here and the key is not.
func mountCollector(mux *http.ServeMux, root string) {
	e := &collectorEndpoint{root: root, now: time.Now}
	mux.Handle("/v1/collector", e)
	mux.Handle("/v1/collector/config", e)
}

// collectorConfigPath is the deployment's watch pack. One file for the
// fleet, written by an operator, served only after it parses as the
// collector's own struct has validated it: a pack this server cannot obey
// is never handed to a collector that then ships the default one and calls
// it deployed.
func collectorConfigPath(root string) string {
	return filepath.Join(root, "collector", "config.json")
}

// collectorBody caps one batch. The collector batches at a few hundred
// records and gzips; four megabytes is far above that and far below what
// fills a disk from outside.
const collectorBody = 4 << 20

// classSystem is OCSF's System Activity class (1011). internal/telemetry
// carries the classes every mapped source needs; a heartbeat is neither a
// file activity nor a process activity, and the arithmetic that makes 1011
// well-formed (category*1000 + index) is the part of OCSF this project
// borrowed on purpose.
const classSystem = telemetry.Class(1011)

type collectorStatus struct {
	Batches int `json:"batches"`
	Records int `json:"records"`
	Stored  int `json:"stored"`
	// Duplicates counts batch ids a retry carried. The collector's own
	// answer-loss semantics make these ordinary, not hostile.
	Duplicates int       `json:"duplicates"`
	Refused    int       `json:"refused"`
	LastAt     time.Time `json:"last_at,omitempty"`
	LastRefuse time.Time `json:"last_refused,omitempty"`
	Why        string    `json:"why,omitempty"`
	Error      string    `json:"error,omitempty"`
}

type collectorEndpoint struct {
	root string
	now  func() time.Time
	seen inbound.Seen

	mu      sync.Mutex
	status  collectorStatus
	window  rateWindow
	stopped bool
}

func (e *collectorEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !e.allow() {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many deliveries", http.StatusTooManyRequests)
		return
	}
	name, secret, ok := e.authenticate(w, r)
	if !ok {
		return
	}
	if strings.HasSuffix(r.URL.Path, "/config") {
		e.config(w, r, name, secret)
		return
	}
	e.batch(w, r, name, secret)
}

// allow is the feeds' own window, reused for the same reason: far above
// anything one collector legitimately sends, far below what fills a disk.
func (e *collectorEndpoint) allow() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	if e.window.start.IsZero() || now.Sub(e.window.start) >= time.Minute {
		e.window = rateWindow{start: now}
	}
	e.window.n++
	return e.window.n <= feedRate
}

// authenticate proves the delivery against the collector's own credential,
// named in the header, before anything else is read.
func (e *collectorEndpoint) authenticate(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	name := r.Header.Get(collector.HeaderToken)
	if !inbound.ValidName(name) {
		e.refused("the delivery names no credential this store could hold")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", "", false
	}
	secrets, err := loadSecrets(e.root)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return "", "", false
	}
	secret := secrets[name]
	if secret == "" {
		e.refused("there is no credential " + name + " in the store " +
			"(aeroprove connect secret " + name + ")")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", "", false
	}
	if !inbound.StaticMatches(inbound.BearerOrRaw(r.Header.Get("Authorization")), inbound.Digest(secret)) {
		e.refused("the Authorization header does not hold " + name + "'s credential")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", "", false
	}
	return name, secret, true
}

func (e *collectorEndpoint) refused(why string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.status.Refused++
	e.status.LastRefuse = e.now().UTC()
	e.status.Why = why
}

// config answers GET with the deployment's watch pack.
func (e *collectorEndpoint) config(w http.ResponseWriter, r *http.Request, name, secret string) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	b, err := readBounded(collectorConfigPath(e.root), 256<<10)
	if os.IsNotExist(err) {
		http.Error(w, "this server has no collector config; the collector "+
			"will use its cached or built-in pack", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	// Validated with the collector's own rules before it is served, because
	// a pack a collector would refuse is worse than no pack: the collector
	// falls back to defaults silently on some versions and loudly on others.
	if _, err := collector.LoadFile(collectorConfigPath(e.root)); err != nil {
		http.Error(w, "the deployment's collector config is unusable: "+
			err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

// batch takes one signed delivery of evidence.
func (e *collectorEndpoint) batch(w http.ResponseWriter, r *http.Request, name, secret string) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, code, why := readCollectorBody(r)
	if code != 0 {
		http.Error(w, why, code)
		return
	}
	// The replay windows: a timestamp outside the tolerance every signed
	// delivery here is held to, then the signature over id, time and body.
	at, err := strconv.ParseInt(r.Header.Get(collector.HeaderTime), 10, 64)
	if err != nil || at <= 0 {
		e.refused("the batch carries no usable time header")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if d := e.now().Sub(time.Unix(at, 0)); d > inbound.Tolerance || d < -inbound.Tolerance {
		e.refused(fmt.Sprintf("the batch is signed %s from now", d.Round(time.Second)))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := r.Header.Get(collector.HeaderBatch)
	if id == "" || len(id) > 128 {
		e.refused("the batch carries no id")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !collector.VerifyBatch(secret, id, time.Unix(at, 0), body,
		r.Header.Get(collector.HeaderSignature)) {
		e.refused("the batch signature does not match its credential")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// The honest duplicate policy: a batch id is remembered for the day the
	// feeds remember delivery ids, and a repeat is answered as taken without
	// being stored again. The collector retries a batch whenever the answer
	// was lost — a 200 that arrived nowhere — and the retry semantics are
	// the collector's own; this side's job is to make them safe, not to
	// punish them.
	if !e.seen.First(name+":"+id, e.now()) {
		e.mu.Lock()
		e.status.Duplicates++
		e.mu.Unlock()
		writeCollectorAnswer(w, 0, true)
		return
	}
	var batch collector.Batch
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&batch); err != nil {
		e.refused(err.Error())
		http.Error(w, "the body is not a collector batch", http.StatusBadRequest)
		return
	}
	if len(batch.Records) > 10000 {
		http.Error(w, "a batch of that many records is not one this collector sends",
			http.StatusRequestEntityTooLarge)
		return
	}
	events, err := e.events(name, batch, e.now().UTC())
	if err != nil {
		e.refused(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	e.mu.Lock()
	e.status.Batches++
	e.status.Records += len(batch.Records)
	e.status.LastAt = e.now().UTC()
	e.mu.Unlock()
	stored := 0
	if len(events) > 0 {
		if serr := withSpool(e.root, func(sp *spool.Spool) error {
			if _, aerr := sp.AppendBatch(events); aerr != nil {
				return aerr
			}
			// What arrived is read by the rules at once, the way every
			// other delivery's is: an authorized_keys change that waits
			// for a timer is a change a quiet hour never checks.
			detectInServer(e.root, sp)
			return nil
		}); serr != nil {
			e.mu.Lock()
			e.status.Error = serr.Error()
			e.mu.Unlock()
			http.Error(w, "the event store did not take the batch; send it again",
				http.StatusServiceUnavailable)
			return
		}
		stored = len(events)
	}
	e.mu.Lock()
	e.status.Stored += stored
	e.status.Error = ""
	e.mu.Unlock()
	writeCollectorAnswer(w, stored, false)
}

func writeCollectorAnswer(w http.ResponseWriter, stored int, duplicate bool) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"stored": stored, "duplicate": duplicate})
}

// readCollectorBody takes the body, decoding the one compression the OTLP
// endpoint also takes and capping the decompressed size.
func readCollectorBody(r *http.Request) ([]byte, int, string) {
	raw := io.LimitReader(r.Body, collectorBody+1)
	var in io.Reader = raw
	switch strings.ToLower(strings.TrimSpace(
		r.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip":
		gz, err := gzip.NewReader(raw)
		if err != nil {
			return nil, http.StatusBadRequest, "the body says it is gzip and does not open as gzip"
		}
		defer gz.Close()
		in = gz
	default:
		return nil, http.StatusUnsupportedMediaType, "this endpoint reads identity and gzip bodies only"
	}
	body, err := io.ReadAll(io.LimitReader(in, collectorBody+1))
	if err != nil {
		return nil, http.StatusBadRequest, "the body did not arrive whole"
	}
	if len(body) > collectorBody {
		return nil, http.StatusRequestEntityTooLarge, "the body is larger than this endpoint reads"
	}
	return body, 0, ""
}

// events turns one batch's records into store events. The auditd records
// go through the existing auditd mapping — the same one `aeroprove collect
// file` uses — so every rule written against auditd/events reads collector
// evidence unchanged; the watch and heartbeat records become events here,
// because no mapping exists for them and inventing one to read three known
// fields through would be ceremony, not reuse.
//
// The watch and heartbeat records are also where the recorder-host to agent
// mapping is read (aeroprove agent maps, internal/agentreg): once per batch,
// never cached across pushes, so a mapping change is in force on the next
// push and not on some later restart. A mapping that cannot be read refuses
// the batch — the same line the registry draws — because storing evidence
// as though nobody had ever declared anything would silently undo every
// declaration on the file, and the honest failure is the loud one.
//
// Records with a source this endpoint does not know refuse the whole batch:
// a version skew is a deployment error to surface, not half a batch to
// store and half to drop, and the spool's append-only batch is the unit
// either way.
func (e *collectorEndpoint) events(name string, batch collector.Batch, now time.Time) ([]telemetry.Event, error) {
	maps, err := agentMapStore(e.root).Load()
	if err != nil {
		return nil, fmt.Errorf("the recorder-host mapping cannot be read, so "+
			"no collector evidence can be stored against it: %w", err)
	}
	var auditd []any
	var out []telemetry.Event
	for _, rec := range batch.Records {
		switch rec.Source {
		case collector.SourceAuditd:
			auditd = append(auditd, rec.Data)
		case collector.SourceWatch:
			ev, err := collectorWatchEvent(name, rec, now,
				agentreg.AgentsFor(maps, recString(rec.Data, "host")))
			if err != nil {
				return nil, err
			}
			out = append(out, ev)
		case collector.SourceHeartbeat:
			ev, err := collectorHeartbeatEvent(name, rec, now,
				agentreg.AgentsFor(maps, recString(rec.Data, "host")))
			if err != nil {
				return nil, err
			}
			out = append(out, ev)
		default:
			return nil, fmt.Errorf("record %d names source %q, which this "+
				"endpoint does not know; nothing in the batch was stored",
				len(out)+len(auditd)+1, rec.Source)
		}
	}
	if len(auditd) > 0 {
		src, err := findSource(e.root, collector.SourceAuditd)
		if err != nil {
			return nil, err
		}
		aliases, _ := loadAliases(e.root)
		if aliases == nil {
			aliases = map[string]alias{}
		}
		cs := collectStatus{}
		out = append(out, mapRecords(src, auditd, &cs, aliases, now)...)
		if cs.Missed > 0 {
			field, n := cs.Field, cs.Missed
			if field == "" {
				field = "(not a usable event)"
			}
			return nil, fmt.Errorf("%d of %d auditd record(s) did not map; "+
				"%s was missing from %d. Nothing in the batch was stored",
				cs.Missed, len(auditd), field, n)
		}
	}
	return out, nil
}

// declaredAgents writes the operator's host-to-agent declaration into a
// collector event's raw fields. Three honesty rules, and they are the whole
// design:
//
// The event says what the OPERATOR declared, not what the program guessed.
// The collector saw a file change on a host and nothing else; every name
// below is one a person wrote into the mapping beside the registry, and an
// event from a host nobody mapped carries nothing at all — not an empty
// list, not a guessed one.
//
// No actor is invented. The recorder's device id stays the event's only
// who-or-where; stamping an Actor from the declaration would turn "these
// agents run here" into "this agent did it", which is exactly the false
// precision the pack's refusal was refusing.
//
// The closed list travels whole (raw.agents), and the single name a join
// needs (raw.agent) travels only when the list has exactly one entry. A
// host declared to run two agents is not attributed between them — the
// program refuses to choose, which is why the join leg below carries
// nothing for a shared box and says so in its blind.
func declaredAgents(e telemetry.Event, declared []string) telemetry.Event {
	if len(declared) == 0 {
		return e
	}
	if e.Raw == nil {
		e.Raw = map[string]string{}
	}
	e.Raw["agents"] = strings.Join(declared, ",")
	if len(declared) == 1 {
		e.Raw["agent"] = declared[0]
	}
	return e
}

// collectorWatchEvent is one watched-path change as an event. The raw
// fields are the whole of what the collector noticed — path, kind, sha256,
// size, op — plus, when the recorder's host has been mapped to agent(s), the
// names the operator declared there (declaredAgents above).
func collectorWatchEvent(name string, r collector.Record, at time.Time,
	declared []string) (telemetry.Event, error) {
	path := recString(r.Data, "path")
	kind := recString(r.Data, "kind")
	op := recString(r.Data, "op")
	if path == "" {
		return telemetry.Event{}, fmt.Errorf(
			"a watch record names no path, so it is evidence about nothing")
	}
	switch op {
	case collector.OpCreated, collector.OpChanged, collector.OpRemoved:
	default:
		return telemetry.Event{}, fmt.Errorf(
			"a watch record says %q happened; it is created, changed or removed", op)
	}
	if kind == "" {
		kind = collector.KindOther
	}
	when := r.At
	if when.IsZero() {
		when = at
	}
	e := telemetry.Event{
		Time: when.UTC(), Received: at,
		Class: telemetry.ClassFileActivity, Activity: 1,
		Severity: telemetry.SeverityInfo,
		Source:   collector.SourceWatch,
		Message:  fmt.Sprintf("%s %s (%s)", path, op, kind),
		Device:   telemetry.ID{Issuer: "collector", Value: name},
		Raw: map[string]string{"path": path, "kind": kind, "op": op,
			"sha256": recString(r.Data, "sha256"),
			"size":   recString(r.Data, "size"),
			"host":   recString(r.Data, "host")},
	}
	e = declaredAgents(e, declared)
	if e.Raw["sha256"] != "" {
		e.Observables = append(e.Observables, telemetry.Observable{
			Kind: telemetry.ObservableHash, Value: e.Raw["sha256"], Name: "sha256"})
	}
	e.Observables = append(e.Observables, telemetry.Observable{
		Kind: telemetry.ObservableFile, Value: path, Name: "path"})
	if err := e.Validate(); err != nil {
		return telemetry.Event{}, err
	}
	return e, nil
}

// collectorHeartbeatEvent is the recorder's one-minute "still here". The
// missing-heartbeat detection is a rule written against this source, run
// here on the server — a recorder that noticed its own silence would be a
// recorder that judged, and judging is not its job. A mapped host's
// heartbeat carries the declared names too (declaredAgents), so a host's
// liveness and its agents can be asked about in one place.
func collectorHeartbeatEvent(name string, r collector.Record, at time.Time,
	declared []string) (telemetry.Event, error) {
	when := r.At
	if when.IsZero() {
		when = at
	}
	host := recString(r.Data, "host")
	e := telemetry.Event{
		Time: when.UTC(), Received: at,
		Class: classSystem, Activity: 1,
		Severity: telemetry.SeverityInfo,
		Source:   collector.SourceHeartbeat,
		Device:   telemetry.ID{Issuer: "collector", Value: name},
	}
	if host != "" {
		e.Message = fmt.Sprintf("recorder alive on %s", host)
		e.Observables = append(e.Observables, telemetry.Observable{
			Kind: telemetry.ObservableHostname, Value: host, Name: "host"})
	} else {
		e.Message = "recorder alive"
	}
	raw := map[string]string{"host": host}
	for _, k := range []string{"uptime_seconds", "shipped", "dropped",
		"batches", "retries", "version", "go"} {
		if v := recString(r.Data, k); v != "" {
			raw[k] = v
		}
	}
	e.Raw = raw
	e = declaredAgents(e, declared)
	if err := e.Validate(); err != nil {
		return telemetry.Event{}, err
	}
	return e, nil
}

// recString reads a record's field whatever side of JSON it arrived from:
// the collector sends strings, but a body rebuilt through encoding/json
// hands numbers back as float64, and a value that changes type on its way
// through a decoder is a value a rule cannot match.
func recString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return fmt.Sprint(x)
	}
}
