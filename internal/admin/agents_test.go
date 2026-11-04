// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aeroprove/aeroprove/internal/agentreg"
	"github.com/aeroprove/aeroprove/internal/spool"
	"github.com/aeroprove/aeroprove/internal/telemetry"
)

// The Agents board, from a spool holding both sources that watch agents.

// agentEv is one event from an agent source, as the sidecar or the GenAI
// mapping stores it: closed words in Raw, the agent as the actor.
func agentEv(src string, actor telemetry.ID, disp telemetry.Disposition,
	minutesAgo int, raw map[string]string) telemetry.Event {

	at := time.Now().UTC().Add(-time.Duration(minutesAgo) * time.Minute)
	if raw == nil {
		raw = map[string]string{}
	}
	return telemetry.Event{Source: src, Class: telemetry.ClassAPIActivity,
		Disposition: disp, Actor: actor, Raw: raw, Time: at, Received: at}
}

// agentBoard is a console over a spool holding these events.
func agentBoard(t *testing.T, in ...telemetry.Event) (*Server, string) {
	t.Helper()
	srv, token := setup(t)
	ev, _ := spoolWith(t, spool.Options{}, in...)
	srv.Events = ev
	return srv, token
}

// va, ci and quiet are the three actors the fixtures observe. va's events
// name the agent "ci-agent", which is ci's own actor value: the two rows the
// sources produce for what may be one agent, which the board must say
// rather than merge.
var (
	va    = telemetry.ID{Issuer: "aeroprove", Value: "ana"}
	ci    = telemetry.ID{Issuer: "otel", Value: "ci-agent"}
	quiet = telemetry.ID{Issuer: "otel", Value: "quiet-bot"}
)

func agentFixture() []telemetry.Event {
	return []telemetry.Event{
		// aeroprove:ana — three allowed calls, one refused, one proposal.
		agentEv(agentSidecar, va, telemetry.DispositionAllowed, 6000,
			map[string]string{"action": "mcp.call", "tool": "fs.read",
				"model": "analyst", "agent": "ci-agent"}),
		agentEv(agentSidecar, va, telemetry.DispositionAllowed, 4320,
			map[string]string{"action": "mcp.call", "tool": "fs.read",
				"model": "analyst", "agent": "ci-agent"}),
		agentEv(agentSidecar, va, telemetry.DispositionAllowed, 120,
			map[string]string{"action": "mcp.call", "tool": "gh.pr",
				"model": "analyst", "agent": "ci-agent"}),
		agentEv(agentSidecar, va, telemetry.DispositionBlocked, 60,
			map[string]string{"action": "mcp.call", "tool": "gh.push",
				"model": "analyst", "why": "outside its scope",
				"agent": "ci-agent"}),
		agentEv(agentSidecar, va, telemetry.DispositionAllowed, 90,
			map[string]string{"action": "proposal.finding", "finding": "f-1",
				"to": "false-positive", "confidence": "0.8", "agent": "ci-agent"}),
		// otel:ci-agent — two allowed tool calls, one model call that failed.
		agentEv(agentOtel, ci, telemetry.DispositionAllowed, 30,
			map[string]string{"operation": "execute_tool", "tool": "web.fetch",
				"model": "claude-4", "tokens_in": "1000", "tokens_out": "300",
				"trace_id": "t-1"}),
		agentEv(agentOtel, ci, telemetry.DispositionAllowed, 20,
			map[string]string{"operation": "execute_tool", "tool": "web.fetch",
				"model": "claude-4", "tokens_in": "2500", "tokens_out": "0",
				"trace_id": "t-2"}),
		agentEv(agentOtel, ci, telemetry.DispositionFailed, 10,
			map[string]string{"operation": "invoke_chat_model",
				"model": "gpt-5.3", "status": "error", "trace_id": "t-3"}),
		// otel:quiet-bot — one call, three days ago.
		agentEv(agentOtel, quiet, telemetry.DispositionAllowed, 4320,
			map[string]string{"operation": "execute_tool", "tool": "calc",
				"tokens_in": "12", "tokens_out": "4"}),
	}
}

// TestTheBoardCountsWhatEachAgentDid.
//
// One row per observed actor, the counts the events gave, sorted by the
// most recent activity, and the two sources' naming kept apart rather than
// joined.
func TestTheBoardCountsWhatEachAgentDid(t *testing.T) {
	srv, token := agentBoard(t, agentFixture()...)
	body := get(t, srv, "/security/agents", token).Body.String()
	if strings.Contains(body, "render error") || !strings.Contains(body, "</html>") {
		t.Fatal("the board did not render to the end")
	}
	// A row per actor, as stored — the pseudonym and the SDK's identifier.
	for _, key := range []string{"aeroprove:ana", "otel:ci-agent", "otel:quiet-bot"} {
		if !strings.Contains(body, "<code>"+key+"</code>") {
			t.Errorf("no row for %s", key)
		}
	}
	// Most recently active first: ci-agent called ten minutes ago, ana an
	// hour, quiet-bot three days.
	ciAt, anaAt, quietAt := strings.Index(body, "otel:ci-agent"),
		strings.Index(body, "aeroprove:ana"), strings.Index(body, "otel:quiet-bot")
	if ciAt < 0 || anaAt < 0 || quietAt < 0 || !(ciAt < anaAt && anaAt < quietAt) {
		t.Errorf("not sorted by recent activity (%d, %d, %d)", ciAt, anaAt, quietAt)
	}
	// Counters: 9 agent events read; 1 refused of them; 1 proposal.
	if !strings.Contains(body, "9 agent events") {
		t.Error("the board does not say how much it read")
	}
	if !strings.Contains(body, `<a href="/logs">1</a>`) {
		t.Error("the refused figure is not the one refused call, linked to the log that holds it")
	}
	if !strings.Contains(body, "<dt>Proposals made</dt><dd>1</dd>") {
		t.Error("the one proposal was not counted")
	}
	// The states the data derives: two active within the day, one quiet.
	if strings.Count(body, "active today") != 2 {
		t.Errorf("active today appears %d times, want 2 (the count tile and two rows)",
			strings.Count(body, "active today"))
	}
	if !strings.Contains(body, ">quiet<") {
		t.Error("the three-day-old agent is not marked quiet")
	}
	// Tools as chips, tokens as a person reads them.
	for _, want := range []string{"web.fetch", "fs.read", "3.5k in / 300 out"} {
		if !strings.Contains(body, want) {
			t.Errorf("the board lacks %q", want)
		}
	}
	// The two sources name agents differently, and the board says so rather
	// than resolving it.
	if !strings.Contains(body, "one agent may hold two rows") {
		t.Error("the board does not say its two sources may double-name one agent")
	}
}

// TestAnAgentsPageHoldsItsCountsAndTheirDenominators.
func TestAnAgentsPageHoldsItsCountsAndTheirDenominators(t *testing.T) {
	srv, token := agentBoard(t, agentFixture()...)
	body := get(t, srv, "/security/agents/aeroprove:ana", token).Body.String()
	if strings.Contains(body, "render error") {
		t.Fatal("the page did not render")
	}
	// Four calls — three allowed, one refused — and a proposal counted
	// apart from them, each with its denominator.
	for _, want := range []string{
		"<dt>Calls</dt><dd>4</dd>",
		"<dt>Refused, of its calls</dt><dd>1 of 4</dd>",
		"<dt>Failed, of its calls</dt><dd>0 of 4</dd>",
		"<dt>Proposals made</dt><dd>1</dd>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	// The sidecar's source reports no tokens; that is said, not shown as zero.
	if !strings.Contains(body, "none reported") || strings.Contains(body, "3.5k") {
		t.Error("a sidecar-only agent's tokens were not stated as unreported")
	}
	// The honesty box: what the identity is, which sources saw it, and the
	// other row it may or may not share an agent with.
	for _, want := range []string{
		"the pseudonym the audit log gave the agent",
		"<code>aeroprove/agent</code>, 5 events",
		"named the agent",
		"<code>ci-agent</code>",
		"May or may not be the same agent as",
		"<code>otel:ci-agent</code>",
		"never resolved into a name nobody recorded",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the honesty box lacks %q", want)
		}
	}
	// The timeline: the events' own closed words, newest first, the
	// refusal's reason carried with the label such text has earned.
	for _, want := range []string{"mcp.call", "proposal.finding", "Blocked",
		"untrusted", "outside its scope"} {
		if !strings.Contains(body, want) {
			t.Errorf("the timeline lacks %q", want)
		}
	}
	if strings.Index(body, "proposal.finding") < strings.Index(body, "mcp.call") {
		t.Error("the timeline is not newest first: the refusal (an hour ago) is below the proposal (90 minutes)")
	}

	// The GenAI-fed agent: its tokens, its failed model call, its tools.
	body = get(t, srv, "/security/agents/otel:ci-agent", token).Body.String()
	for _, want := range []string{"<dt>Calls</dt><dd>3</dd>",
		"<dt>Failed, of its calls</dt><dd>1 of 3</dd>",
		">3.5k<", ">300<", "execute_tool", "invoke_chat_model", "Failed",
		"<code>web.fetch</code>", "1 distinct tool, most called first, of 3 calls"} {
		if !strings.Contains(body, want) {
			t.Errorf("the otel agent's page lacks %q", want)
		}
	}
	if !strings.Contains(body, "the identity its own telemetry carried") {
		t.Error("the otel agent's identity was not described as what its telemetry carried")
	}
}

// TestTheBoardsSourceFilterFollowsTheChips.
func TestTheBoardsSourceFilterFollowsTheChips(t *testing.T) {
	srv, token := agentBoard(t, agentFixture()...)

	otel := get(t, srv, "/security/agents?source=otel", token).Body.String()
	if !strings.Contains(otel, "otel:ci-agent") || strings.Contains(otel, "aeroprove:ana") {
		t.Error("the otel filter did not narrow the board to otel's agents")
	}
	if !strings.Contains(otel, `href="/security/agents?source=otel" class="on"`) {
		t.Error("the otel chip is not marked as the current filter")
	}
	aeroprove := get(t, srv, "/security/agents?source=aeroprove", token).Body.String()
	if !strings.Contains(aeroprove, "aeroprove:ana") || strings.Contains(aeroprove, "otel:ci-agent") {
		t.Error("the aeroprove filter did not narrow the board to the sidecar's agents")
	}
	// An unknown value is no filter, never a comparison nobody wrote.
	odd := get(t, srv, "/security/agents?source=everything", token).Body.String()
	if !strings.Contains(odd, "otel:ci-agent") || !strings.Contains(odd, "aeroprove:ana") {
		t.Error("an unknown filter value narrowed the board")
	}
}

// TestTheBoardsEmptyStatesSayWhichAbsenceTheyAre.
//
// A build with no store, a site where nothing was ever collected, and a
// store holding nothing from agents are three different facts, and only
// the last says anything about agents.
func TestTheBoardsEmptyStatesSayWhichAbsenceTheyAre(t *testing.T) {
	srv, token := setup(t)
	body := get(t, srv, "/security/agents", token).Body.String()
	if !strings.Contains(body, "without a telemetry store") ||
		strings.Contains(body, "No agent has been observed") {
		t.Errorf("an unwired build was shown as a board with no agents")
	}

	srv, token = setup(t)
	srv.Events = &Events{Open: func() (*spool.Spool, func() error, error) {
		return nil, nil, fmt.Errorf("site: %w", ErrNeverCollected)
	}}
	body = get(t, srv, "/security/agents", token).Body.String()
	if !strings.Contains(body, "Nothing has ever been collected here") {
		t.Errorf("a never-collected site was not said to be one")
	}

	// A store with events, none from the two sources that watch agents.
	at := time.Now().UTC().Add(-time.Minute)
	srv, token = agentBoard(t, telemetry.Event{Source: "okta/system",
		Class: telemetry.ClassAuthentication, Message: "signed in",
		Time: at, Received: at})
	body = get(t, srv, "/security/agents", token).Body.String()
	if !strings.Contains(body, "No agent has been observed") ||
		!strings.Contains(body, "none from") {
		t.Errorf("a busy store with no agent events was not told apart from an empty one")
	}
	if strings.Contains(body, "Nothing has ever been collected here") {
		t.Error("a store with events claimed nothing was ever collected")
	}

	// An empty spool: collected, but nothing in it at all.
	srv, token = agentBoard(t)
	body = get(t, srv, "/security/agents", token).Body.String()
	if !strings.Contains(body, "Nothing is in the store") {
		t.Errorf("an empty store's absence was not said for what it is")
	}
}

// TestNothingAnAgentOrItsSourcesWroteRunsOnTheScreen.
//
// Every field on the board came from outside: the actor value, the tool and
// model names, the refusal's reason. Fields the page does not read — the
// span, the status, the resource, the message — must not appear at all, in
// either form. The trace and conversation ids are read now: they name the
// session the timeline groups an event under, shown escaped like every
// identifier the events carry, which is why the hostile strings here go in
// the fields that stay unread.
func TestNothingAnAgentOrItsSourcesWroteRunsOnTheScreen(t *testing.T) {
	evil := `<script>alert(1)</script><img src=x onerror=alert(2)>`
	nasty := telemetry.ID{Issuer: "otel", Value: `agent-"><svg onload=alert(3)>`}
	fromOtel := agentEv(agentOtel, nasty, telemetry.DispositionAllowed, 5,
		map[string]string{"operation": "execute_tool", "tool": "web.fetch",
			"trace_id": "t-x", "conversation": "c-x",
			"span_id": evil, "status": evil})
	fromOtel.Message = evil
	fromSidecar := agentEv(agentSidecar,
		telemetry.ID{Issuer: "aeroprove", Value: "ev"},
		telemetry.DispositionAllowed, 4,
		map[string]string{"action": "mcp.call", "tool": "fs.read",
			"resource": evil, "client": evil})
	fromSidecar.Message = evil
	srv, token := agentBoard(t, fromOtel, fromSidecar)
	board := get(t, srv, "/security/agents", token).Body.String()
	page := get(t, srv, agentHref(nasty), token).Body.String()
	for name, body := range map[string]string{"board": board, "page": page} {
		for _, raw := range []string{
			`<script>alert(1)`, `<img src=x`, `<svg onload`,
		} {
			if strings.Contains(body, raw) {
				t.Errorf("%s: %q reached the page unescaped", name, raw)
			}
		}
		// The fields the page does not read are absent in both forms: the
		// escaped entity would say the value was rendered, only safely.
		for _, escaped := range []string{
			`&lt;script&gt;alert(1)&lt;/script&gt;`,
			`&lt;img src=x`,
		} {
			if strings.Contains(body, escaped) {
				t.Errorf("%s: an unread field (%q) was rendered at all", name, escaped)
			}
		}
		// The closed fields are shown — the tool on the board, the
		// operation on the page — and the hostile actor value only ever as
		// text.
		if !strings.Contains(board, "web.fetch") {
			t.Error("board: the tool the page counts is missing")
		}
		if !strings.Contains(page, "execute_tool") {
			t.Error("page: the event's operation is missing")
		}
	}
	if !strings.Contains(page, "&lt;svg onload=alert(3)&gt;") {
		t.Error("the hostile actor value is missing from its own page")
	}
}

// TestAnUnknownAgentIsAnHonestNotFound.
//
// Quiet and absent are different facts, and the page that separates them is
// a 404 rather than an empty agent page pretending the identity is known.
func TestAnUnknownAgentIsAnHonestNotFound(t *testing.T) {
	srv, token := agentBoard(t, agentFixture()...)
	w := get(t, srv, "/security/agents/aeroprove:nobody", token)
	if w.Code != http.StatusNotFound {
		t.Fatalf("an unknown agent answered %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "No agent has been observed under that identity") {
		t.Error("the refusal does not say what was looked in")
	}
	if !strings.Contains(body, "in the last seven days") {
		t.Error("the refusal does not say over what period")
	}
	if strings.Contains(body, "render error") {
		t.Error("the refusal page did not render")
	}
	// The subtree root is the board.
	if w := get(t, srv, "/security/agents/", token); w.Code != http.StatusSeeOther {
		t.Errorf("the bare subtree answered %d", w.Code)
	}
}

// TestTheBoardCarriesTheLiveHooks.
//
// The script is not unit-tested here; the contract is: the badge that opens
// the stream, and the figure the stream's agent events move, named the way
// the wrapper looks for. Both are in the server's render, so both are
// testable without a browser.
func TestTheBoardCarriesTheLiveHooks(t *testing.T) {
	srv, token := agentBoard(t, agentFixture()...)
	body := get(t, srv, "/security/agents", token).Body.String()
	if !strings.Contains(body, "data-live-badge") {
		t.Error("the board carries no live badge for the stream to speak through")
	}
	if !strings.Contains(body, `data-live-count="/security/agents"`) {
		t.Error("the refused figure is not named for the stream to move")
	}
}

// TestTheBoardSaysWhenTheBudgetCutItsWindow.
//
// A board that quietly counted less than its stated week would call an
// agent quiet that was busy before the cut.
func TestTheBoardSaysWhenTheBudgetCutItsWindow(t *testing.T) {
	// A segment per arrival day, so the cut lands between days whatever
	// time of day the test runs at.
	day := time.Now().UTC().Truncate(24 * time.Hour)
	at := func(when time.Time, actor telemetry.ID) telemetry.Event {
		return telemetry.Event{Source: agentOtel,
			Class:       telemetry.ClassAPIActivity,
			Disposition: telemetry.DispositionAllowed, Actor: actor,
			Raw:  map[string]string{"operation": "execute_tool"},
			Time: when, Received: when}
	}
	srv, token := agentBoard(t,
		at(day.Add(-72*time.Hour), telemetry.ID{Issuer: "otel", Value: "long-gone"}),
		at(day, telemetry.ID{Issuer: "otel", Value: "today-bot"}),
	)
	srv.Events.Budget = 1 // smaller than any segment: the newest only
	body := get(t, srv, "/security/agents", token).Body.String()
	if !strings.Contains(body, "stayed inside its byte budget") {
		t.Fatal("a budget-cut window was not said")
	}
	if strings.Contains(body, "long-gone") {
		t.Error("an agent whose only call was outside the budget was shown")
	}
	if !strings.Contains(body, "today-bot") {
		t.Error("the newest segment was not read; it always should be")
	}
}

// The registry join. The board is observed telemetry; the registry is what
// was declared; the join runs from the events to the registry and never the
// other way, because a row standing on events that do not exist would be a
// security screen showing a fiction.

// withRegistry points the board's join at a registry for this test only,
// built through the store's own API so the file it reads is a file the
// registry could have written.
func withRegistry(t *testing.T, build func(agentreg.Store)) {
	t.Helper()
	st := agentreg.Store{Path: filepath.Join(t.TempDir(), "agents.json")}
	build(st)
	old := AgentRegistry
	AgentRegistry = st
	t.Cleanup(func() { AgentRegistry = old })
}

// addAgent registers one agent, an hour ago, refusing loudly if it cannot.
func addAgent(t *testing.T, st agentreg.Store, a agentreg.Agent) {
	t.Helper()
	if err := st.Add(a, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

// bot is the actor whose events name the registered agent ci-bot: the token
// the sidecar saw was issued agent:ci-bot, which is the whole of the claim
// the join is allowed to act on.
var bot = telemetry.ID{Issuer: "aeroprove", Value: "bot-1"}

func botEvent(mins int, client string) telemetry.Event {
	return agentEv(agentSidecar, bot, telemetry.DispositionAllowed, mins,
		map[string]string{"action": "mcp.call", "tool": "fs.read", "client": client})
}

// TestTheRegistryIsJoinedWhereARowsEventsNamedIt.
//
// A row whose events carried a clear name — the token's name in raw.client —
// that names a registry entry shows what the registry holds: the registered
// chip, the owner, the allowed tools, the status. The page says where the
// join came from, and the header counts the registry beside the window.
func TestTheRegistryIsJoinedWhereARowsEventsNamedIt(t *testing.T) {
	withRegistry(t, func(st agentreg.Store) {
		addAgent(t, st, agentreg.Agent{Name: "ci-bot", Owner: "Ana",
			Allow: []string{"aeroprove_find", "aeroprove_read"},
			Note:  "triages CI failures", CreatedBy: "dana"})
	})
	srv, token := agentBoard(t, botEvent(20, "agent:ci-bot"))
	body := get(t, srv, "/security/agents", token).Body.String()
	for _, want := range []string{
		`<span class="tag tag-ok">registered</span>`,
		"<code>ci-bot</code>",
		"owner Ana",
		`<span class="chip-small">aeroprove_find</span>`,
		`<span class="wf-word good">active</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the board lacks %q", want)
		}
	}
	if strings.Contains(body, "not registered") {
		t.Error("a matched row was also shown as not registered")
	}
	// The header states the registry beside the window, both as counts.
	for _, want := range []string{"1 agent registered",
		"1 agent observed in the window",
		"silent, not absent"} {
		if !strings.Contains(body, want) {
			t.Errorf("the header count line lacks %q", want)
		}
	}
	// The agent's page: a Registry section holding what the registry
	// records, attributed to whoever wrote it.
	page := get(t, srv, "/security/agents/aeroprove:bot-1", token).Body.String()
	for _, want := range []string{"<h2>Registry</h2>", "<dt>Owner</dt><dd>Ana</dd>",
		`<span class="chip-small">aeroprove_find</span>`,
		"triages CI failures", "Last changed", "by dana",
		"The join runs one way"} {
		if !strings.Contains(page, want) {
			t.Errorf("the agent's Registry section lacks %q", want)
		}
	}
}

// TestADisabledRegisteredAgentIsTheLoudestThingOnItsRow.
//
// The registry's kill switch, shown where the agent is still being observed:
// the serious tone, the date its calls have been refused since, and — on the
// agent's page — the reason the responder recorded, with its author beside
// it rather than paraphrased.
func TestADisabledRegisteredAgentIsTheLoudestThingOnItsRow(t *testing.T) {
	withRegistry(t, func(st agentreg.Store) {
		addAgent(t, st, agentreg.Agent{Name: "ci-bot", Owner: "Ana",
			Allow: []string{"aeroprove_read"}, CreatedBy: "dana"})
		if err := st.Disable("ci-bot", "found exfiltration in its build logs",
			"responder", time.Now().UTC().Add(-30*time.Minute)); err != nil {
			t.Fatal(err)
		}
	})
	srv, token := agentBoard(t, botEvent(20, "agent:ci-bot"))
	body := get(t, srv, "/security/agents", token).Body.String()
	if !strings.Contains(body, `<span class="wf-word critical">disabled — refused since`) {
		t.Error("a disabled registered agent was not the loud state on its row")
	}
	if strings.Contains(body, `<span class="wf-word good">active</span>`) {
		t.Error("the disabled entry was shown as active")
	}
	page := get(t, srv, "/security/agents/aeroprove:bot-1", token).Body.String()
	for _, want := range []string{
		"<h2>Registry</h2>",
		"Why it was disabled",
		"found exfiltration in its build logs",
		"recorded by responder",
		"disabled — refused since",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the disabled agent's page lacks %q", want)
		}
	}
}

// TestAnObservedAgentNoEntryMatchesIsSaidAsNotRegistered.
//
// The built-in analyst names itself "triage" in the agent field. A registry
// holding other agents must not claim it, and the row says the honest thing:
// not registered, on a board that still shows everything observed about it.
func TestAnObservedAgentNoEntryMatchesIsSaidAsNotRegistered(t *testing.T) {
	withRegistry(t, func(st agentreg.Store) {
		addAgent(t, st, agentreg.Agent{Name: "ci-bot", Owner: "Ana",
			Allow: []string{"aeroprove_read"}, CreatedBy: "dana"})
	})
	analyst := agentEv(agentSidecar,
		telemetry.ID{Issuer: "aeroprove", Value: "ana"}, telemetry.DispositionAllowed, 15,
		map[string]string{"action": "proposal.finding", "agent": "triage"})
	srv, token := agentBoard(t, analyst)
	body := get(t, srv, "/security/agents", token).Body.String()
	if !strings.Contains(body, `<span class="chip-small">not registered</span>`) {
		t.Error("an agent no entry matches was not said to be not registered")
	}
	if strings.Contains(body, "<code>ci-bot</code>") {
		t.Error("the registry's entry reached a row that never named it")
	}
	page := get(t, srv, "/security/agents/aeroprove:ana", token).Body.String()
	if !strings.Contains(page, "No registry entry matches any name this agent used") {
		t.Error("the agent's honesty box does not say no entry matches")
	}
	if strings.Contains(page, "<h2>Registry</h2>") {
		t.Error("a Registry section was shown for an agent with no match")
	}
}

// TestOneActorThatUsedTwoRegisteredTokensShowsBoth.
//
// An actor may hold two tokens, each naming a different registered agent.
// The row shows both entries rather than picking one, because to drop one
// would be to hide half of what that actor is allowed to do.
func TestOneActorThatUsedTwoRegisteredTokensShowsBoth(t *testing.T) {
	withRegistry(t, func(st agentreg.Store) {
		addAgent(t, st, agentreg.Agent{Name: "one-bot", Owner: "Ana",
			Allow: []string{"aeroprove_read"}, CreatedBy: "dana"})
		addAgent(t, st, agentreg.Agent{Name: "two-bot", Owner: "Sam",
			Allow: []string{"aeroprove_write"}, CreatedBy: "dana"})
	})
	srv, token := agentBoard(t,
		botEvent(30, "agent:one-bot"), botEvent(20, "agent:two-bot"))
	body := get(t, srv, "/security/agents", token).Body.String()
	for _, want := range []string{"<code>one-bot</code>", "<code>two-bot</code>",
		"owner Ana", "owner Sam", "more than one registered name"} {
		if !strings.Contains(body, want) {
			t.Errorf("a two-token actor's row lacks %q", want)
		}
	}
	if strings.Count(body, `tag tag-ok">registered`) != 2 {
		t.Error("the two entries were not both shown")
	}
}

// TestARegisteredAgentNobodyObservedIsACountNotARow.
//
// The join never runs backwards. A registry entry with no observed events
// cannot buy a row on the board; it is a count in the header, beside the
// window's observations, with the words that silence is not absence.
func TestARegisteredAgentNobodyObservedIsACountNotARow(t *testing.T) {
	withRegistry(t, func(st agentreg.Store) {
		addAgent(t, st, agentreg.Agent{Name: "ci-bot", Owner: "Ana",
			Allow: []string{"aeroprove_read"}, CreatedBy: "dana"})
	})
	// A busy store holding nothing from the two sources that watch agents.
	at := time.Now().UTC().Add(-time.Minute)
	srv, token := agentBoard(t, telemetry.Event{Source: "okta/system",
		Class: telemetry.ClassAuthentication, Message: "signed in",
		Time: at, Received: at})
	body := get(t, srv, "/security/agents", token).Body.String()
	if !strings.Contains(body, "No agent has been observed") {
		t.Fatal("the empty board did not say which absence it is")
	}
	if !strings.Contains(body, "1 agent registered") ||
		!strings.Contains(body, "0 agents observed in the window") {
		t.Error("a registered-but-silent agent was not counted in the header")
	}
	if strings.Contains(body, "<code>ci-bot</code>") || strings.Contains(body, "registered</span>") {
		t.Error("a registry entry with no observed events was given a row")
	}

	// And where nothing has ever been collected, the registry is still a
	// fact the page can state: declared, and never observed, because
	// nothing is watching.
	srv, token = setup(t)
	srv.Events = &Events{Open: func() (*spool.Spool, func() error, error) {
		return nil, nil, fmt.Errorf("site: %w", ErrNeverCollected)
	}}
	body = get(t, srv, "/security/agents", token).Body.String()
	if !strings.Contains(body, "The registry, separately, holds 1 agent") {
		t.Error("a never-collected site did not say what the registry holds")
	}
}

// TestTheRegistrysFreeTextIsRenderedAsTextAndNeverAsALink.
//
// The note and the disable's reason are operator-written free text. That
// earns plain rendering with escaping, not the untrusted label a model's
// reason carries — and never an attribute, a link, or anything else the
// page would act on.
func TestTheRegistrysFreeTextIsRenderedAsTextAndNeverAsALink(t *testing.T) {
	hostile := `<script>alert(1)</script>"><a href="https://evil.example/x">click</a>`
	withRegistry(t, func(st agentreg.Store) {
		addAgent(t, st, agentreg.Agent{Name: "ci-bot", Owner: "Ana",
			Allow: []string{"aeroprove_read"}, Note: hostile, CreatedBy: "dana"})
		if err := st.Disable("ci-bot", hostile, "responder",
			time.Now().UTC().Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
	})
	srv, token := agentBoard(t, botEvent(20, "agent:ci-bot"))
	for name, body := range map[string]string{
		"board": get(t, srv, "/security/agents", token).Body.String(),
		"page":  get(t, srv, "/security/agents/aeroprove:bot-1", token).Body.String(),
	} {
		if strings.Contains(body, "<script>alert(1)") {
			t.Errorf("%s: the registry's note ran as markup", name)
		}
		if strings.Contains(body, `<a href="https://evil.example`) {
			t.Errorf("%s: the registry's note became a link", name)
		}
		if strings.Contains(body, "untrusted") {
			t.Errorf("%s: an operator-written reason was labelled untrusted", name)
		}
	}
	// The note and the reason are shown, as text: escaped whole, on the
	// page that renders them. html.EscapeString is the same table
	// html/template escapes text nodes with, so this asserts the page's
	// own escaping rather than a hand-copied guess at it.
	page := get(t, srv, "/security/agents/aeroprove:bot-1", token).Body.String()
	escaped := html.EscapeString(hostile)
	if strings.Count(page, escaped) != 2 {
		t.Errorf("the note and the reason appear %d times escaped, want 2 (once each)",
			strings.Count(page, escaped))
	}
	if strings.Contains(get(t, srv, "/security/agents", token).Body.String(), "evil.example") {
		t.Error("the board rendered the registry's note at all")
	}
}

// TestAnUnreadableRegistryWithholdsTheJoinRatherThanEmptyingIt.
//
// agentreg's rule: present-and-broken means refuse. The board cannot match
// against a registry it cannot read, and "not registered" would claim a fact
// it cannot check — so the join is withheld and said, and every observed
// fact on the page stands.
func TestAnUnreadableRegistryWithholdsTheJoinRatherThanEmptyingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agents.json")
	if err := os.WriteFile(path, []byte(`{"agents":[{"name":`), 0o600); err != nil {
		t.Fatal(err)
	}
	old := AgentRegistry
	AgentRegistry = agentreg.Store{Path: path}
	t.Cleanup(func() { AgentRegistry = old })

	srv, token := agentBoard(t, botEvent(20, "agent:ci-bot"))
	body := get(t, srv, "/security/agents", token).Body.String()
	if !strings.Contains(body, "could not be read") {
		t.Error("an unreadable registry was not said to be one")
	}
	if strings.Contains(body, `<span class="chip-small">not registered</span>`) {
		t.Error("an unreadable registry was shown as holding nobody")
	}
	if !strings.Contains(body, "registry unreadable") {
		t.Error("the rows did not say the registry was the thing that failed")
	}
	if strings.Contains(body, "registered</span>") {
		t.Error("the join ran against a registry it could not read")
	}
	if !strings.Contains(body, "aeroprove:bot-1") {
		t.Error("the observed row did not stand")
	}
	page := get(t, srv, "/security/agents/aeroprove:bot-1", token).Body.String()
	if !strings.Contains(page, "The registry could not be read") {
		t.Error("the agent's page did not say the registry was unreadable")
	}
}

// The session timeline: the agent's window grouped by the one edge its
// events draw themselves — a shared trace id — and laid out as a timeline a
// finding's evidence can cite.

// otelAt is one GenAI span, minutes ago, on this program's clock.
func otelAt(actor telemetry.ID, disp telemetry.Disposition, mins int,
	raw map[string]string) telemetry.Event {
	return agentEv(agentOtel, actor, disp, mins, raw)
}

// TestSessionsAreTheTracesTheEventsDrewThemselves.
//
// Two traces are two sessions, newest first, each carrying the conversation
// id its events named; the counts, tools, models and tokens are that
// session's own, with the session's calls as the denominator.
func TestSessionsAreTheTracesTheEventsDrewThemselves(t *testing.T) {
	res := telemetry.ID{Issuer: "otel", Value: "research"}
	srv, token := agentBoard(t,
		otelAt(res, telemetry.DispositionAllowed, 40, map[string]string{
			"operation": "execute_tool", "tool": "web.fetch", "model": "claude-4",
			"tokens_in": "100", "tokens_out": "50", "trace_id": "trace-alpha",
			"conversation": "conv-7"}),
		otelAt(res, telemetry.DispositionAllowed, 39, map[string]string{
			"operation": "execute_tool", "tool": "web.fetch", "model": "claude-4",
			"tokens_in": "50", "tokens_out": "10", "trace_id": "trace-alpha",
			"conversation": "conv-7"}),
		otelAt(res, telemetry.DispositionAllowed, 20, map[string]string{
			"operation": "execute_tool", "tool": "gh.pr", "model": "claude-4",
			"tokens_in": "20", "tokens_out": "5", "trace_id": "trace-beta",
			"conversation": "conv-7", "duration_ms": "1200"}),
	)
	body := get(t, srv, "/security/agents/otel:research", token).Body.String()
	if strings.Contains(body, "render error") {
		t.Fatal("the page did not render")
	}
	// Two sessions, and the newest trace is the one to read first.
	alpha, beta := strings.Index(body, "<code>trace-alpha</code>"),
		strings.Index(body, "<code>trace-beta</code>")
	if alpha < 0 || beta < 0 || beta > alpha {
		t.Errorf("two traces did not render as two sessions, newest first (%d, %d)",
			alpha, beta)
	}
	// The conversation id, named by both, shown with each.
	if strings.Count(body, "conversation <code>conv-7</code>") != 2 {
		t.Error("each session does not carry the conversation id its events named")
	}
	// Each session's own numbers: counts with their denominator, tools in
	// order of first use with counts, tokens, and the wall span between
	// first and last arrival.
	for _, want := range []string{
		"2 calls — 2 allowed, 0 failed, 0 blocked",
		"1 call — 1 allowed, 0 failed, 0 blocked",
		"<code>web.fetch</code> ×2",
		"<code>gh.pr</code> ×1",
		"150 in / 60 out",
		"20 in / 5 out",
		"1m 0s",
		"0 ms",
		// The span that reported its duration carries it; the page's own
		// arithmetic (the session's wall span) is never confused with it.
		"1.2 s",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the session summary lacks %q", want)
		}
	}
	// The timeline itself: time, operation, tool, model, outcome — the
	// closed fields — in the order they arrived.
	for _, want := range []string{
		`<code>execute_tool</code> <code>gh.pr</code>`,
		`<span class="wf-word good">Allowed</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the timeline lacks %q", want)
		}
	}
	// The citation anchor: a session is a page of its own.
	if !strings.Contains(body,
		`href="/security/agents/otel:research?session=trace-beta"`) {
		t.Error("a session is not addressable by its trace id")
	}
}

// TestTheSidecarsEventsAreOneStreamNotInventedSessions.
//
// aeroprove/agent events carry no trace id. The honest answer is one
// chronological stream, said as that: no session edge is invented for events
// that never named one, and the sidecar-only agent's page says both facts —
// no session can be grouped, and these events are a stream by arrival order,
// not a session.
func TestTheSidecarsEventsAreOneStreamNotInventedSessions(t *testing.T) {
	srv, token := agentBoard(t, agentFixture()...)
	body := get(t, srv, "/security/agents/aeroprove:ana", token).Body.String()
	if strings.Contains(body, "render error") {
		t.Fatal("the page did not render")
	}
	if strings.Contains(body, "<h3>Session") {
		t.Error("a session was invented for events that carry no trace id")
	}
	if !strings.Contains(body,
		"No GenAI telemetry arrived in the window, so there is no session to group") {
		t.Error("the sessions section does not say its absence is telemetry not arriving")
	}
	if !strings.Contains(body, "Sidecar and analyst events — one stream") ||
		!strings.Contains(body, "cannot be split into sessions") {
		t.Error("the stream section does not say what it is")
	}
	// The stream's own counts, with the analyst's proposals apart.
	if !strings.Contains(body, "4 calls of 5 events — 3 allowed, 0 failed, 1 blocked") {
		t.Error("the stream's calls and their outcomes were not counted with their denominator")
	}
	if !strings.Contains(body, "1 proposal from the analyst") {
		t.Error("the analyst's proposal was not counted apart from calls")
	}
	// Arrival order, oldest first: the operation-and-tool pair on one line
	// is the timeline's own shape, so the fs.read call from four days ago
	// comes first and this hour's refusal last, the proposal between.
	first := strings.Index(body, "<code>mcp.call</code> <code>fs.read</code>")
	refusal := strings.Index(body, "<code>mcp.call</code> <code>gh.push</code>")
	proposal := strings.Index(body, "<code>proposal.finding</code>")
	if first < 0 || refusal < 0 || !(first < proposal && proposal < refusal) {
		t.Errorf("the stream is not in arrival order (fs.read %d, proposal %d, gh.push %d)",
			first, proposal, refusal)
	}
	// The first-use marks run here too: three tools, three marks, and the
	// second fs.read is not marked again.
	if got := strings.Count(body, "first use of"); got != 3 {
		t.Errorf("%d first-use marks in the stream, want 3 (fs.read, gh.pr, gh.push)", got)
	}
}

// TestFirstUseIsMarkedOncePerToolInTheWindow.
//
// The mark is arithmetic over the window, not over one session: whichever
// session first used a tool carries the mark, the later use in the other
// session does not, and each session's tool list marks only its window-first
// tools. Two sessions that each used the other's tool first prove the mark
// follows the window and not the section.
func TestFirstUseIsMarkedOncePerToolInTheWindow(t *testing.T) {
	res := telemetry.ID{Issuer: "otel", Value: "research"}
	span := func(trace, tool string, mins int) telemetry.Event {
		return otelAt(res, telemetry.DispositionAllowed, mins, map[string]string{
			"operation": "execute_tool", "tool": tool, "trace_id": trace})
	}
	srv, token := agentBoard(t,
		span("s-one", "fs.read", 50),   // fs.read's first use in the window
		span("s-two", "web.fetch", 45), // web.fetch's first use in the window
		span("s-one", "web.fetch", 40), // repeat, after s-two used it
		span("s-two", "fs.read", 35),   // repeat, after s-one used it
	)
	body := get(t, srv, "/security/agents/otel:research", token).Body.String()
	for _, want := range []string{
		"first use of fs.read in 7 days",
		"first use of web.fetch in 7 days",
	} {
		if strings.Count(body, want) != 1 {
			t.Errorf("%q appears %d times, want exactly once at the first use",
				want, strings.Count(body, want))
		}
	}
	// The repeats are not marked: two tools, two marks, nothing more.
	if got := strings.Count(body, "first use of"); got != 2 {
		t.Errorf("%d inline first-use marks, want 2", got)
	}
	// Each session's tool summary marks only the tool whose window-first
	// use happened there: s-one marks fs.read, s-two marks web.fetch.
	if got := strings.Count(body, ">first use in 7 days<"); got != 2 {
		t.Errorf("%d tool-summary marks, want 2 (one per session, on the window-first tool)", got)
	}
}

// TestASessionCanBeLinkedToAndFilteredTo.
//
// ?session= is the citation anchor: the page narrows to that one session,
// the others are gone rather than hidden, and the way back is a link.
func TestASessionCanBeLinkedToAndFilteredTo(t *testing.T) {
	srv, token := agentBoard(t, agentFixture()...)
	body := get(t, srv, "/security/agents/otel:ci-agent?session=t-1", token).Body.String()
	if !strings.Contains(body, "<code>t-1</code>") {
		t.Fatal("the named session did not render")
	}
	for _, gone := range []string{"<code>t-2</code>", "<code>t-3</code>"} {
		if strings.Contains(body, gone) {
			t.Errorf("%s rendered under a filter that names another session", gone)
		}
	}
	if !strings.Contains(body, "Show every session") {
		t.Error("the filtered page does not offer the way back to every session")
	}
	if !strings.Contains(body, "1k in / 300 out") {
		t.Error("the filtered session does not carry its own token totals")
	}
}

// TestAnUnknownTraceIdIsAnHonestEmpty.
//
// The agent's page stands; the session list renders below the miss, and the
// notice says where a trace id that is not here may live. A value no trace
// id resembles is not echoed back.
func TestAnUnknownTraceIdIsAnHonestEmpty(t *testing.T) {
	srv, token := agentBoard(t, agentFixture()...)
	body := get(t, srv, "/security/agents/otel:ci-agent?session=trace-nope", token).Body.String()
	for _, want := range []string{
		"No session under trace", "<code>trace-nope</code>",
		"may belong to another agent, or have arrived before the window began",
		"Every session this page did group is below", "<code>t-1</code>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the honest empty lacks %q", want)
		}
	}
	// A value too long to be a trace id anybody cited is refused as a
	// lookup and never echoed by the page's own words — the shell's re-auth
	// form carries the address separately, as it does on every page.
	long := strings.Repeat("x", 600)
	body = get(t, srv, "/security/agents/otel:ci-agent?session="+long, token).Body.String()
	if !strings.Contains(body, "a value no trace id in these events resembles") {
		t.Error("a value no trace id resembles was not said to be one")
	}
	if strings.Contains(body, "<code>"+long) {
		t.Error("a 600-character query value was echoed as if it were a trace id")
	}
}

// TestGenAIEventsWithoutATraceIdBelongToNoSession.
//
// An otel event with no trace id cannot be grouped, and the page says the
// count rather than fencing it into a session of one.
func TestGenAIEventsWithoutATraceIdBelongToNoSession(t *testing.T) {
	loose := telemetry.ID{Issuer: "otel", Value: "loose"}
	srv, token := agentBoard(t,
		otelAt(loose, telemetry.DispositionAllowed, 30, map[string]string{
			"operation": "execute_tool", "tool": "web.fetch"}),
		otelAt(loose, telemetry.DispositionAllowed, 25, map[string]string{
			"operation": "invoke_chat_model", "model": "gpt-5.3"}),
	)
	body := get(t, srv, "/security/agents/otel:loose", token).Body.String()
	if strings.Contains(body, "<h3>Session") {
		t.Error("a session was invented for events that carry no trace id")
	}
	if !strings.Contains(body,
		"GenAI telemetry arrived — 2 events — none of it carrying a trace id") {
		t.Error("untraceable GenAI events were not counted and said")
	}
	// The events themselves still stand, in Recent events.
	if !strings.Contains(body, "execute_tool") {
		t.Error("an untraceable event vanished with the session it could not join")
	}
}

// TestTheSessionTimelineRendersOnlyTheClosedFields.
//
// The timeline's fields are closed words: the operation, the tool, the
// model, the disposition, the span's duration. Everything else the event
// carries — the span id, the status, a duration that is not a number —
// reaches nothing, in either form. The identifiers the page does read (the
// trace, the conversation) render as text: escaped whole, never as markup.
func TestTheSessionTimelineRendersOnlyTheClosedFields(t *testing.T) {
	evil := `<script>alert(1)</script><img src=x onerror=alert(2)>`
	conv := `conv"><script>x</script>`
	res := telemetry.ID{Issuer: "otel", Value: "research"}
	srv, token := agentBoard(t, otelAt(res, telemetry.DispositionAllowed, 5,
		map[string]string{"operation": "execute_tool", "tool": "web.fetch",
			"model": "claude-4", "trace_id": "t-safe", "conversation": conv,
			"span_id": evil, "status": evil, "duration_ms": "not-a-number"}))
	body := get(t, srv, "/security/agents/otel:research?session=t-safe", token).Body.String()
	for _, raw := range []string{`<script>alert(1)`, `<script>x`, `<img src=x`} {
		if strings.Contains(body, raw) {
			t.Errorf("%q reached the timeline unescaped", raw)
		}
	}
	// The unread fields are absent in both forms: the escaped entity would
	// say the value was rendered, only safely.
	for _, escaped := range []string{
		`&lt;script&gt;alert(1)&lt;/script&gt;`, `&lt;img src=x`,
	} {
		if strings.Contains(body, escaped) {
			t.Errorf("a field the timeline does not read (%q) was rendered at all", escaped)
		}
	}
	// The identifiers the timeline does read are shown, as text.
	if !strings.Contains(body, html.EscapeString(conv)) {
		t.Error("the conversation id the events carried is missing from its session")
	}
	// A duration that does not parse is no duration, not a zero one.
	if strings.Contains(body, "not-a-number") || strings.Contains(body, "NaN") {
		t.Error("an unparsable duration reached the page")
	}
	for _, want := range []string{"<code>t-safe</code>", "execute_tool",
		"web.fetch", "claude-4", `<span class="wf-word good">Allowed</span>`} {
		if !strings.Contains(body, want) {
			t.Errorf("the closed field %q is missing from the timeline", want)
		}
	}
}
