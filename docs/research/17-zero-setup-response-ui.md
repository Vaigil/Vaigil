# 17 — Zero-setup onboarding and the live response console

Date: 2026-10-25. Scope: the full UI design for zero-setup onboarding, live
dashboards, agent-monitoring surfaces and a durable customization model, on top
of the console as it exists today. Everything here is implementable in Go
`html/template` + one small vanilla `admin.js` + one `style.css`, with SSE
(server-sent events) for live updates and no JS frameworks, no external assets.

What was read: `README.md`; `internal/admin/server.go`, `today.go`, `start.go`,
`findings.go`, `approvals.go`, `nav.go`; templates `layout.html`, `today.html`,
`start.html`, `findings.html`, `finding.html`, `case.html`, `vulns.html`,
`risk.html`, `events.html`, `hunt.html`, `feeds.html`, `enrol.html`,
`find.html`; `assets/admin.js` and the token block of `assets/style.css`; the
40 pre-rendered pages in `/home/rashik/vaigil-research/sources/ux/render/`
(light + dark); `docs/research/2026-10-24-master-report.md` §4.3–4.4;
`docs/research/13-startup-and-agent-failures.md` (catalogue headers, telemetry
prerequisite, "what ships first"); `docs/research/16-nist-mapping.md` §5.3.
All contrast ratios in §6 were computed with the WCAG 2.x relative-luminance
formula, not estimated. Web sources are in §8.

---

## 0. What exists today, evaluated honestly

**Get started** (`internal/admin/start.go`, `assets/start.html`). Four steps —
bring events in, decide what counts as wrong, know the estate, decide who else
may do what — each ticked from the store at request time, plus a "what will
stop you" gates list and a three-surfaces table. This is already better than a
tour: a checklist of *real state* is the right idea (Vanta's coverage-driven
checklist works the same way). Three gaps:

1. The steps are about the *product's* concepts (feeds, detections, workforce),
   not about the customer's outcome ("you are protected"). Nothing on the
   screen says how much of the estate is watched or what one more connector
   would buy.
2. The AI-agent story — the differentiator per the master report §4.3 — is not
   a step at all. A startup in 2026 brings six coding agents on day one; the
   console never asks about them.
3. The screen gives up after dismissal (a cookie). Nothing walks the user to a
   *first decision* or a *first armed automation*, which are the two moments a
   security product becomes real.

**Today** (`today.go`, `today.html`). Two sections: waiting items (max 7, from
`waitingItems`, sorted acts-first) and a stats row of counts. It is static —
"Counted now, from the records each figure links to" — with no refresh of any
kind. `layout.html` already carries an unused hook for a poll fallback
(`{{with .Refresh}}<meta http-equiv="refresh">`), which §3 uses.

**Findings / finding** (`findings.go`). The queue is genuinely good: chips with
counts, "nothing has looked yet" vs "nothing is wrong" distinction, trial-ring
quarantine, evidence runs folded, an *untrusted* tag on tainted evidence, and a
decision vocabulary that records false-positive/benign as first-class verdicts.
The finding page's section order is the problem: chips → warning → declare
hint → metadata → **Decide form → history → Evidence last**. The decision form
arrives before the evidence it is a decision about; the AI proposal block (when
present) sits *above* both history and evidence. That order is an
automation-bias risk: the thing the model suggested is the second block on the
page and the raw evidence is the last.

**Case** (`case.html`). Regulatory clocks with explicit "decisions nobody has
made" states are excellent and unusual. But "The record" is a plain table at
the bottom while the events that *belong* on a timeline (clock starts,
playbook approvals, acts, notes) are scattered across five sections. The
obligation hint texts run 40+ words inside table cells.

**Vulnerabilities** (`vulns.html`). Tiles, a "what to change" upgrade plan with
risk-removed meters, the SSVC tag editor, an SVG trend with a table fallback —
the best-structured screen in the console. Missing: BOD 26-04 remediation
clocks (the master report §4.5 confirms the four-factor regime) — deadlines
today are implicit in the ranking.

**Risk** (`risk.html`). Entity rollup with score meters and an inline
"these look like one thing: declare an incident" offer. Good; no trend, no
comparison to yesterday.

**The shell** (`layout.html`, `admin.js`, `nav.go`). A real command palette
(Ctrl/⌘+K, ARIA combobox, destinations only), `/` to search, popover nav,
rail + flyouts, card-stacking tables on phones, an idle-warning dialog with
in-place passkey re-sign-in, a three-state theme toggle, per-user nav order as
a cookie, and a CSP of `default-src 'none'` with `connect-src 'self'` — which
already permits same-origin EventSource. The plumbing for a live console
exists; nothing uses it.

**What the renders feel like** (§6 has the full critique): calm, dense,
honest, and *still*. Google-app surfaces, AAA text contrast (verified), strong
empty-state honesty — and no pulse: nothing on any screen changes by itself.

---

## 1. First 24 hours to "protected"

### 1.1 The principle, from the products that got it right

- **Vanta/Drata**: the checklist *is* the product; every row is a connector
  whose OAuth click moves a coverage number. The gap is the motivator — a
  "63%" with three one-click ways to raise it converts better than any tour
  ([vanta.com/resources/vanta-vs-drata-for-enterprises](https://www.vanta.com/resources/vanta-vs-drata-for-enterprises),
  [drata.com](https://drata.com)).
- **Wiz**: read-only API connection, no agents, first scan in minutes, full
  estate picture in ~24h — value before configuration
  ([wiz.io/academy/cloud-security/agentless-scanning](https://www.wiz.io/academy/cloud-security/agentless-scanning),
  [appsecsanta.com/wiz](https://appsecsanta.com/wiz)).
- **Aikido**: sign in with GitHub → grant → scans start → **first findings in
  ~1 minute**; the whole flow is under five minutes
  ([help.aikido.dev: connect repositories](https://help.aikido.dev/getting-started/setting-up-your-account/create-account-and-connect-your-repositories),
  [connect GitHub org](https://help.aikido.dev/code-scanning/connect-your-source-code/connect-github-account-to-aikido)).
- **Panther**: sample detections pre-loaded so the first alert exists before
  the user writes a rule
  ([docs.panther.com/quick-start/onboarding-guide](https://docs.panther.com/quick-start/onboarding-guide),
  [panther-labs/panther-analysis](https://github.com/panther-labs/panther-analysis)).
- **Tailscale**: value with zero configuration, adoption incremental — every
  step must leave the product *more* useful, never half-broken
  ([tailscale.com/compare/legacy-vpn-premigration](https://tailscale.com/compare/legacy-vpn-premigration)).
- **Huntress**: onboarding ends in a *report you can show someone*, not a
  settings screen
  ([huntress partner onboarding](https://www.huntress.com/resources/technical-partner-onboarding-with-huntress-session-march-1)).

For a self-hosted binary the translation is: `vaigil init → link → passkey`
already exists and is already zero-config. What is missing between first
sign-in and "protected" is: (a) one screen that measures protection, (b)
connectors that are one paste away, (c) detections that are already on, and
(d) the agent-telemetry hookup. Nothing below requires OAuth server-side
callback infrastructure on day one — every connector in today's console is a
paste-an-address-or-secret flow (`feeds.html` already does this well).

### 1.2 Get protected — the redesigned first screen

`/start` becomes **Get protected**, a single screen with a coverage meter at
the top and the eight steps under it. Steps keep the existing discipline:
state is read from the store at request time; a tick states what was found.
The gates list and the three-surfaces table stay (they are good), below the
fold.

```
┌──────────────────────────────────────────────────────────────────────┐
│ Get protected                                        5 of 8 · 62%    │
│                                                                      │
│   ╭──────────────────────────────────────────────────────────────╮   │
│   │   Coverage ring:  ▣ identity ▣ code ▣ agents ▢ cloud ▢ ends… │   │
│   │   3 of 5 estate sources watched · 6 agents reporting          │   │
│   │   The fastest next step: connect AWS CloudTrail  →  5 min     │   │
│   ╰──────────────────────────────────────────────────────────────╯   │
│                                                                      │
│   1. ✔ You are in          passkey "My laptop" added just now        │
│   2. ✔ One thing you use   okta event hook · 41,208 events kept      │
│   3. ✔ Your agents         6 agents via OTLP · last heartbeat 2 min  │
│   4. ✔ Detections are on   62 rules, 15 in the ship-first bundle     │
│   5. ▶ First look          2 findings waiting · open the top one     │
│   6. ⬚ Arm your first watch  "tell me at 9am if anything critical"   │
│   7. ⬚ Somebody else       nobody else can sign in yet               │
│   8. ⬚ Know your machines  no estate source has been synced          │
│                                                                      │
│   What will stop you (5) ▸   Three ways in ▸   The manual ▸          │
└──────────────────────────────────────────────────────────────────────┘
```

The ring is the Vanta move: coverage is computed from what sources have ever
delivered events (`Events` store watermarks, as `events.html`'s senders table
already knows) mapped onto five estate slots — **identity, code, cloud,
endpoints, agents**. The gap text under it always names the single fastest
next connector, with the time it takes. The meter makes the gap the motivator
and never invents a denominator it cannot see: with no estate source at all it
says "watching 1 of 5 known source kinds" rather than a fake percentage of
machines.

### 1.3 The eight steps, screen by screen

**Step 1 — You are in.** Already done when the screen first renders (the user
signed in with a passkey from the enrol link). The tick's evidence line names
the passkey label and time. Purpose: the first row is *already green*, which
is the Aikido lesson — momentum before work.

**Step 2 — One thing you use (defer to Sources/Feeds).** A card row of the
four highest-yield sources, each a link into the existing feed builder
(`feeds.html` add form) pre-selected for that kind:

```
┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│ ◉ Okta      │ │ ◉ GitHub    │ │ ◉ Entra ID  │ │ ◉ Slack     │
│ event hook  │ │ webhook     │ │ via SSF     │ │ audit logs  │
│ 5 min       │ │ 3 min       │ │ 6 min       │ │ 4 min       │
└─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
   … or anything that signs a webhook ▸ all sources
```

Each card's destination screen shows the address to paste and the per-product
instructions exactly as `feeds.html`'s "Added" panel already does ("In Okta:
Workflow, Event Hooks, Create…"). Connector adds beyond these defer to
Integrations (the connector framework, credentials in the vault) — onboarding
never grows a second settings surface. The step is ticked by `feeds > 0`, as
today, and the DoneNote gains "· N events kept".

**Step 3 — Your agents (the differentiator).** Two paths, both paste-and-go,
based on the telemetry prerequisite in report 13 (`mcp/proxy` and
`agent/registry` sources):

```
┌─────────────────────────────────────────────────────────────────────┐
│ Watch your AI agents                                                │
│ Agents delete their own traces when asked to (5 of 6 major          │
│ harnesses). Vaigil watches from outside the agent — two ways:       │
│                                                                     │
│  A · Send telemetry here (OTLP/JSON over HTTP — no collector):      │
│    ┌────────────────────────────────────────────┐  [Copy]          │
│    │ OTEL_EXPORTER_OTLP_HTTP_ENDPOINT=          │                  │
│    │   https://vaigil.example.com/feeds/otlp    │                  │
│    │ VAIGIL_FEED_SECRET=vg-feed-…               │                  │
│    └────────────────────────────────────────────┘                  │
│    Works with any OpenTelemetry GenAI-instrumented agent or         │
│    gateway today.                                                   │
│                                                                     │
│  B · Route MCP through the sidecar (one line):                      │
│    ┌────────────────────────────────────────────┐  [Copy]          │
│    │ vaigil mcp proxy --upstream http://localhost:6277            │ │
│    │   --report-to https://vaigil.example.com/feeds/mcp           │ │
│    └────────────────────────────────────────────┘                  │
│    Records every tool call, its effect class and schema hash —     │
│    never the arguments.                                             │
│                                                                     │
│  Waiting for the first heartbeat…  (this page updates when one     │
│  arrives — you can leave and come back)                             │
└─────────────────────────────────────────────────────────────────────┘
```

Copy buttons use the existing `data-copy` machinery in `admin.js` (hidden
without a secure context, text still selectable). The step ticks when the
first `mcp/proxy` or GenAI event arrives; the DoneNote names the agent count
and last heartbeat age, which the Agents board (§2, §5) supplies.

**Step 4 — Detections are on (default bundle).** The ship-first fifteen from
report 13 (A4, A12, A14, A19, A20, A21, A27, A36, A37, A1, A6, A10, B1, B3,
B4, plus B2 the trifecta) load enabled. This step never unticks; its body is
reassurance rather than work:

> On: 62 rules. The 15 that matter on day one are already running — the
> patterns that actually breach startups, and the agent failures nobody else
> detects. New rules start in a trial ring that only records, and are promoted
> by what their record shows. You have nothing to tune this week.

Statistical rules (Tier 2) show as "learning · 12 of 30 observations" and stay
silent below their denominator, which the `internal/baseline` model already
enforces — surfaced here as a visible "self-tuning in week one" line: a small
stacked bar of rules by state (on / learning / trial / off), which is the
honest version of "self-tuning".

**Step 5 — First look.** Deep-link to the top of the findings queue; the step
ticks when any decision has been recorded (`Findings.History` non-empty). With
zero findings the card offers the safe substitute: **"Nothing to look at yet —
generate a test finding"**, which runs a fixture event through a marked
`selftest` rule and flags the resulting finding `test`, so the user practises
the decide form on data that is provably synthetic (the canary idea from §4.3,
reused as onboarding).

**Step 6 — Arm your first watch.** One form, one mode: *watch*. "Tell me at
09:00 if anything critical is open, and immediately if an agent reaches data
it should not." Defaults to email/webhook to the admin's own address; the ask
and act modes are named but greyed with the two-person rule as the reason.
Ticks when any automation exists and has run once.

**Step 7 — Somebody else.** Enrolment link (existing `/people/enrol` flow)
plus, if the user is the only admin, the second-admin prompt with the
dual-control explanation. Ticks on `others > 0` as today.

**Step 8 — Know your machines.** `vaigil estate sync` instructions with copy
buttons, or the connector cards for endpoint tools (Endpoint Central, Jamf).
Ticks on `tools > 0` as today.

### 1.4 The "do nothing wrong" defaults — stated on the screen, enforced in code

The Get protected screen carries a collapsed **"What is already on, and why it
is safe"** section — the gates list's positive twin — because a founder's
first question is "what did you just turn on against my production?":

| On by default | Why it is safe |
|---|---|
| Ship-first detection bundle (15 rules) | Rules only *raise findings*; a finding changes nothing anywhere |
| Trial ring for every new rule | Records what it would raise; touches no queue until its record earns it |
| Automations in watch mode | Watch notifies; ask needs a second person; act needs approval by someone else |
| Agent telemetry (hashes, not payloads) | Tool arguments are hashed (`tool_args_hash`), prompts hashed by default; content only ever by explicit opt-in |
| The AI analyst, if a model endpoint is configured | One word from a closed set + confidence, below threshold not shown; reason assembled from counts; cannot record a decision |
| Passkey-only sign-in, throttling, lockout-by-place | Existing posture; no default account, no password anywhere |
| Append-only audit chain | Every action above is written, hash-chained and signed; nothing is silent |

Everything default-on is *read-only towards the estate*; the first thing that
touches another platform will still ask two people. That sentence, verbatim,
is the summary line under the table.

---

## 2. Information architecture and navigation

### 2.1 Sitemap (changes marked)

```
Operations                     what is wrong now, and what is being done
  Today                        (redesigned, §3)
  Approvals
  Findings
  Cases
  Risk
Investigation                  what happened
  Agents             [NEW]     the AI-agent story, first-class (§2.2)
  Events
  Hunt
  Indicators
Detection                       what counts as wrong, and what arrives
  Sources            [RENAME]  was Feeds; absorbs the connector list —
                               one screen: pushed feeds + pulled connectors
  Detections
  Automations
  Sign-ins
Exposure                        where the estate is weak
  Vulnerabilities    [+ BOD 26-04 clocks]
  Coverage           [NEW]     the estate-coverage board (§5)
  Workforce risk
Assurance             [NEW GROUP]
  Compliance         [NEW]     NIST mode: CSF 2.0 + AI RMF board (§5)
Administration                 who may do what
  People · Provisioning · SSO · Passkeys · Settings · Log
Reference
  Find · Get protected [RENAME of Get started] · You
```

Rationale. "Feeds" is Vaigil jargon; the screen already lists connectors and
pushed feeds side by side in the customer's mind, and onboarding step 2 sends
people there — the label should say what it is for. "Get started" becomes
"Get protected" to name the outcome. Assurance becomes a group rather than a
tab inside Settings because the NIST-mode board (§5) is a *view the auditor
opens*, and it must not sit under Administration where a viewer cannot see it.
The `destinations` table in `nav.go` gains three rows and one group; every
existing mechanism (grant filtering, doc anchors, stored order, palette
contents) inherits them for free.

### 2.2 Agents — a first-class object beside Findings and Cases

One destination, four tabs, all built on the two new sources from report 13:

```
/security/agents            Agents
├── Map                     every agent, MCP server and skill, by state
├── Sessions                list: agent · started · tools called · tokens · state
├── Session  …/agents/session/ID     replay view (§4.4)
└── Tool calls              the flat log: effect class, taint, result
```

**Map** (SVG, server-rendered, like the vulns trend):

```
   you (6 reporting, 1 quiet ▲)
   ┌────────────────────────────────────────────────────────┐
   │   [claude-code]──[filesystem]      [support-bot]──[zdesk] │
   │        └──[github]                    └──[gmail]         │
   │   [ci-agent]───[k8s]  ⚠ schema changed (B1)                │
   │   [research]──[web]──► egress 4.2× its own history (B22)   │
   └────────────────────────────────────────────────────────┘
   node = agent/skill/tool · edge = called in last 24h ·
   ⚠ = a finding sits on this edge · ▲ = heartbeat quiet (B7)
```

Nodes carry the declared-vs-observed distinction from the agent registry
(`raw.declared`): undeclared components draw with a dashed border — a
*picture* of shadow AI (A39/B10) that a list cannot give. Clicking a node
opens the entity page (`/security/entity/agent:name`, the existing entity
screen). The SVG is `role="img"` with a full aria-label and a
`<details>` table fallback, exactly the discipline the vulnerability trend
chart already uses.

**Sessions** is a standard queue table (the console's strongest component):
agent, purpose class, started, duration, tool calls, tokens, egress bytes,
state — sortable, filterable by the same chip mechanism as findings, with
toxic-flow findings linked in the last column.

### 2.3 The command palette, extended

The palette already reads destinations from the nav (so it can never offer a
forbidden screen). Extend its source list in this order — still one `<dialog>`,
no new dependencies:

1. **Screens** (today) — jump.
2. **Entities** — `agent:ci-agent`, `okta:dana`, `CVE-2026-1001`; type a few
   characters, Enter opens the entity/finding/vuln page.
3. **Open findings** — title substring, top 5 by rank; Enter opens.
4. **Commands** — `Decide: triaged` (on a finding page), `Declare incident
   about this`, `Arm watch on this rule`, `Copy id`, `Refresh now`,
   `Toggle theme`, `Export view`. Commands are only offered when the current
   screen and the user's grants make them legal — the same `allows()` check
   the nav uses.

Bindings: `Ctrl/⌘K` palette (exists); `/` search (exists); **`g` then a key**
Gmail-style jumps: `g t` Today, `g f` Findings, `g a` Agents, `g c` Cases,
`g v` Vulnerabilities, `g r` Risk, `g s` Sources, `?` the shortcut sheet (a
`<dialog>` listing them, also linked from the footer for discovery).

**Keyboard-first investigation** (queue screens): `j`/`k` move a row cursor
(visible focus ring, scroll-into-view), `o`/`Enter` open, `Esc` returns focus
to the cursor after `history.back()`. On a finding page: `e` jump to evidence,
`d` focus the decide form, `u` next/prev is `k`/`j` on the *queue* only. No
single-key verdicts — a decision is a deliberate act with a name attached, and
`1..7` selecting radio buttons would make rubber-stamping faster than
reading. Every binding lives in `admin.js` and is additive: the page is fully
usable with script blocked.

---

## 3. The Today page, redesigned

Today becomes a queue-first inbox with a live pulse. It keeps the fixed frame
the code comment promises ("the same every day") — the three sections never
reorder themselves; only their contents update.

```
┌───────────────────────────────────────────────────────────────────────┐
│ Today                                     ● live · updated 4s ago ⟳   │
│ Saturday 25 October · 3 sources watched · 6 agents reporting           │
├───────────────────────────────────────────────────────────────────────┤
│ WAITING ON YOU (3)                                        [Approvals →] │
│ ┌───────────────────────────────────────────────────────────────────┐ │
│ │ ACTS ON OTHER PLATFORMS (1)                                       │ │
│ │ ⏱ Suspend okta:dana · asked by li 2h ago · case inc-…-aa  open →  │ │
│ │ AUTOMATIONS HELD (1)                                              │ │
│ │ ⏱ Notify #sec of KEV match · held 40m · rule watch-kev     open →  │ │
│ │ SECOND ADMINISTRATOR (1)                                          │ │
│ │ ⏱ Make sam an admin · asked yesterday                      open →  │ │
│ └───────────────────────────────────────────────────────────────────┘ │
├───────────────────────────────────────────────────────────────────────┤
│ RISK PULSE                                                             │
│ events/min ▁▂▂▄▃▂▂▅▇▆▅ (60 min) · store watermarked 42s ago ·          │
│ no source quiet · 0 trial-ring raises in the last hour                 │
├───────────────────────────────────────────────────────────────────────┤
│ IN YOUR ESTATE                                                         │
│ [Findings to triage 4] [Cases open 1] [Agents 6 live · 1 quiet]       │
│ [Advisories matching 6] [Automations ran 12]                          │
└───────────────────────────────────────────────────────────────────────┘
```

Changes from today's `today.html`:

- **Waiting-on-you is grouped** by what waiting *means* (acts / held
  automations / dual-control), reusing the `Commits` field
  `waitingItems` already computes, instead of sorting it away inside one
  table. Each group heading names the two-person rule in six words.
- **Risk pulse** is new: a 60-minute events-per-minute sparkline (SVG,
  server-rendered from the store's per-minute counts), the watermark lag that
  `events.html` already computes ("complete up to"), quiet sources, and
  trial-ring activity. This is the strip that makes the console feel alive
  and answers "is the pipe healthy" without opening Events.
- The stats row keeps its shape but gains agent and coverage figures, and
  tiles are links (they already are).
- The `● live` badge: a labelled status (`aria-live="polite"`) that states
  what it is doing — `● live`, `○ reconnecting…`, `○ every 60s` — never a
  bare spinner.

### 3.1 SSE — the event stream

One endpoint, `GET /live`, `text/event-stream`, same-origin (the CSP's
`connect-src 'self'` already allows it). Server keeps one channel per
subscribed store writer via the existing fan-out points (feeds arriving,
detection runs, decisions, automation state, case clocks, agent heartbeats).
No websockets anywhere; SSE reconnects itself and carries `Last-Event-ID` for
gap-filling (`id:` = the audit-log sequence number, so a replay is a
range-scan of the chain — the log is already the journal).

```
event: hello
id: 8412
data: {"cursor":8412,"when":"2026-10-25T09:41:02Z"}

event: waiting
id: 8413
data: {"added":[{"title":"Suspend okta:dana","group":"acts","href":
       "/security/case/inc-20260930-0000aa","since":"2h"}],
       "removed":[],"total":3}

event: finding
id: 8414
data: {"id":"e3f0…","title":"Agent sent data to a destination it never
       has, right after reading untrusted content","severity":"high",
       "kind":"detection","state":"open"}

event: decision
id: 8415
data: {"finding":"263849b1…","to":"false-positive","by":"sam"}

event: pulse
data: {"events_per_min":[3,4,4,8,6,4,4,10,14,12,10],"watermark_lag_s":42,
       "quiet_sources":[],"trial_raises":0}

event: coverage
data: {"watched":3,"kinds":5,"agents_reporting":6,"agents_total":7}

event: case
data: {"id":"inc-…-aa","regime":"GDPR Article 33","due_in_h":39.5,
       "started":true}

event: agent
data: {"agent":"ci-agent","session":"s-91","state":"egress-anomaly"}

: ping          ← a comment line every 15s; proxies that idle-close
                  are the reason the interval exists
```

Fan-out discipline: counters (waiting, pulse, coverage) are sent at most every
5s (coalesced); item events (finding, decision, case, agent) are sent as they
happen; `pulse` every 60s or on change. Every `id` is the audit sequence, so
a browser reconnecting with `Last-Event-ID: 8412` gets a replay of 8413+ from
the chain rather than a stale snapshot.

### 3.2 Fallback and optimistic UI

- **No JS**: every screen remains a complete server-rendered page. Today
  renders a plain "Refresh" form button (GET to the same URL) where the live
  badge sits. The existing unused `Refresh` hook in `layout.html`
  (`{{with .Refresh}}<meta http-equiv="refresh">{{end}}`) is used exactly
  once: after SSE has failed three reconnects, `admin.js` sets a
  `vaigil_poll` cookie and reloads; the server then renders Today with
  `Refresh=60`. The page says which mode it is in ("every 60s"), so the
  fallback is visible, not silent — the console never pretends to be live.
- **Optimistic UI, one rule**: only decisions are optimistic, because only
  decisions are idempotent-ish to display and hard to fake honestly. The
  decide form posts via `fetch`; the row flips to its new state with a
  "recording…" tag; the `decision` SSE event (or the redirect, on failure)
  replaces the tag with "recorded" and the audit id. If the POST fails, the
  row reverts and the existing flash message explains. Everything else waits
  for its event — no client-side invention of findings that the server has
  not raised.

---

## 4. The investigation experience

### 4.1 The finding page — evidence first, advice last

New order, driven by the anti-automation-bias rules:

```
1. Title · chips (severity · kind · state · owner)
2. Summary line (the counts-based why, from .F.Why)
3. EVIDENCE            ← moved up from last
   runs folded, untrusted tags, raw text never interpreted
4. WHAT HAS BEEN DECIDED  (history)
5. SUGGESTED BY A MODEL — unverified   ← collapsed by default
6. DECIDE  (the form; sticky right column ≥1280px)
7. Metadata dl (id, ATT&CK, source, span)
```

**The AI block, precisely** (extends the existing `Proposals` machinery in
`findings.go`):

- Lives *below* the evidence and the history. The reader meets the evidence
  before the advice — the ordering finding of the cognitive-forcing
  literature ([Buçinca et al., partial explanations and cognitive forcing](https://www.researchgate.net/publication/391907859_Cognitive_Forcing_for_Better_Decision-Making_Reducing_Overreliance_on_AI_Systems_Through_Partial_Explanations),
  [UXmatters: designing for doubt](https://www.uxmatters.com/mt/archives/2026/06/designing-for-doubt-how-to-prevent-automation-complacency-in-ai-workflows.php)).
- Collapsed `<details>` whose summary is the verdict word and confidence only:
  `Suggested: false-positive · 0.81 confidence — show the reasoning`. The
  full reason is counts-assembled (already the product's rule) and is labelled
  *unverified* with the same `tag-warn` treatment evidence taint gets.
- **Source label**: which model endpoint and plan version produced it
  (`gpt-5.3 via VAIGIL_MODEL_URL · plan triage-v3 · 2026-10-25 09:14`), so a
  suggestion can be audited like any other evidence.
- **No accept button.** The person still chooses from the radio list. The
  closest affordance is a link, "fill the form with this", that *selects* the
  radio and focuses the why-field, leaving the submit to a deliberate press.
- **Pre-decision recording**: when a suggestion exists and is unopened, the
  decide form notes "a suggestion is available below — record your own call
  first, or open it". If the person decides before opening it, the audit
  detail records `suggestion_unopened: true`. Over time that field measures
  independence instead of assuming it (the adherence-measurement method from
  [Nagendran et al., Nature/PMC 2023](https://pmc.ncbi.nlm.nih.gov/articles/PMC10630476)).
- **Canary known-answers**: one proposal in N is served on a finding whose
  verdict the pack already knows (fixture findings, marked `test`). Agreement
  with known answers is shown on the Detections screen — "suggestions agreed
  with 36 of 37 known answers (97%)" — so trust in the model is earned with a
  number, not a disclaimer ([canary-evaluation definition](https://arize.com/glossary/canary-evaluation-ai-systems);
  the manipulation risk of pretty citations is why Vaigil's reasons are
  count-assembled rather than model prose — [Zenity: phantom references in Copilot](https://labs.zenity.io)).
- Below threshold → not shown at all (existing behaviour, kept).

### 4.2 The case timeline

One vertical timeline replaces the bottom-of-page "The record" table and
collects what is currently scattered across five sections. HTML only — a
`<ol>` with a time gutter, the same shapes as the notelist:

```
09:14 ─ li declared this · Sev 2 · from risk rollup
09:15 ─ li asked: Suspend okta:dana (waiting on approval ▸)
09:31 ─ sam approved: Suspend okta:dana · the tool answered 204
09:32 ─ CLOCK · "aware" recorded · GDPR Art. 33 · 72h starts
       └ due Mon 28 Oct 09:32 · 39.5h left ▮▮▮▮▮▮▮░░░
09:33 ─ Playbook "account compromise" approved by sam
10:02 ─ Step 3/7 recorded: sessions ended on okta:dana
─────  now ─────────────────────────────────────────────
[ Add to the record …            ]
```

Each entry links to its section anchor; the sections (clocks, playbooks,
acts) remain the working surfaces, but the timeline is where the case is
*read*. Clock rows embed the existing `wf-meter` progress bar with hours-left
numbers. Obligation hint texts (40+ words today) move into `<details>` inside
the clocks table — the words stay (they are excellent), the wall does not.

### 4.3 Session replay for agents

`/security/agents/session/ID` — one session as a horizontal tool-call
timeline plus a detail pane. Server-rendered SVG + table; `admin.js` adds
scrubbing only.

```
agent research · session s-91 · 14:02–14:11 · 38 tool calls · 214k tokens

 14:02  read.untrusted  read.sensitive   egress ✗        14:11
   │├────┤├────────┤├───┤   …
   ▼     ▼          ▼      ▼
 [web.fetch 14:02] [fs.read ~/.env 14:04 ★] [http.post api.stats-de… 14:05 ⚠]

 ── taint chain ★ ──────────────────────────────────────────────
 read (sensitivity: secret) 14:04 ──► sent to api.stats-dev.cn 14:05
 2.1 MB · destination first seen this session · B2 toxic-flow finding ↗
```

- Each call is a block: width = duration, colour = effect class (see §6
  palette), pattern = taint (striped when the source is untrusted), a star
  when `sensitivity: secret` was touched.
- **What-was-read → what-was-sent**: the taint chain strip is the query the
  trifecta correlation already answers — for one session it is drawn as two
  linked rows, so "your agent read `.env` and then POSTed 2.1 MB somewhere
  new" is a picture, not a rule name.
- Scrubbing (`j`/`k` or arrows) moves a cursor; the detail pane below shows
  the selected call: tool, server, schema hash vs pinned (`raw.verified`),
  effect, tokens. Arguments are never shown — only their hash — and the pane
  says why in one line.
- `<details>` table of all 38 calls is the no-SVG fallback and the
  copy-able record.

### 4.4 The toxic-flow graph

On the finding page for a B2 completion, between summary and evidence: a
left-to-right SVG DAG, server-rendered in the template (paths computed in Go —
three fixed columns, no layout engine):

```
 ┌────────┐      ┌───────────────┐      ┌──────────────┐      ┌──────────────┐
 │ agent  │ ───► │ tool: web.fetch│ ──► │ data: page    │ ──► │ egress: POST │
 │research│      │ read.untrusted│      │ taint: untrust│      │ api.stats-…  │
 └────────┘      └───────────────┘      └──────┬───────┘      └──────────────┘
                                              │ read again, as secret
                                       ┌──────▼───────┐
                                       │ file ~/.env  │
                                       │ sensitivity: │
                                       │ secret       │
                                       └──────────────┘
   legend: ──► observed order · dashed = untrusted input · red edge = secret
```

Implementation notes: pure `<svg>` with `<defs><marker>` arrowheads, inline in
the template; `role="img"` + `aria-label` naming the whole flow in words;
`<details>Show as a table</details>` with the three events, exactly the
trend-chart pattern. No JS, no external library, ~40 lines of Go computing
x/y for ≤ 12 nodes (the correlation caps the story it tells; longer flows get
the table first with the graph behind `<details>`).

---

## 5. The dashboard suite

Six boards. Each answers one question, has named live elements, and has a
3am-mobile version — what renders at 380px, one-handed, half-asleep (the
on-call lesson: escalate push → SMS → call, and give the woken person
*acknowledge* and *who else is up*, not a settings screen
([incident.io on-call guide](https://incident.io/blog/on-call-best-practices-guide-2026),
[All Quiet: multi-channel escalation](https://allquiet.app/blog/multi-channel-incident-alerting))).

| Board | The one question | Live elements (SSE) | 3am on a phone |
|---|---|---|---|
| **Today** (`/today`) | What is waiting for me, and is the pipe healthy? | `waiting`, `finding`, `decision`, `pulse`, `coverage` | Waiting groups as stacked cards, one tap to approve/refuse with the why-field; pulse strip becomes two numbers (events/min, watermark lag); everything ≥48px targets |
| **Agents** (`/security/agents`) | Which of my agents is doing something it should not? | `agent` (state changes, heartbeats); map redraws on event | Map collapses to a list of exceptions ("1 schema change, 1 egress anomaly, 1 quiet heartbeat"), each opening the session replay |
| **Estate coverage** (`/security/coverage`) | What am I *not* watching yet? | `coverage`, `finding` (a quiet source raises one) | The ring as five labelled rows with connect buttons; "fastest next step" pinned on top |
| **Risk** (`/security/risk`) | Who or what is most exposed right now? | `finding`, `decision` (scores recomputed server-side) | Top 3 entities as cards with score meters and "declare incident" |
| **Vulnerabilities** (`/security/vulns`) | What must I patch, by when, and what is already being exploited? | `finding` (KEV feed update changes tiles), `case` | Tiles only: open · exploited · 2 BOD 26-04 clocks expiring; each CVE row is "due in 2d 4h" with the clock bar |
| **Compliance** (`/security/compliance`) | What can I prove, from the signed chain, per framework? | `decision` (evidence counts move) | One number per function (CSF: 6, AI RMF: 4), amber/red entries listed beneath |

Two of these deserve detail:

**Vulnerabilities + BOD 26-04.** The queue gains a *clock column*: for each
CVE with KEV+exposure, the remediation deadline from the four-factor table
(exposure × KEV × automation × impact), rendered as the existing `wf-meter`
bar plus "due in 2d 4h" — the same shape the case clocks use, so deadline is
a learned vocabulary. The tiles row gains "on a BOD 26-04 clock: N". The
clock recomputes when the KEV feed updates (SSE `finding` event), which is the
dynamic-recompute behaviour BOD 26-04 actually specifies (master report §4.5).

**Compliance / NIST mode** (per `16-nist-mapping.md` §5.3, unchanged in
substance, specified as UI): two function rows (CSF 2.0: GV/ID/PR/DE/RS/RC;
AI RMF: GV/MP/ME/MG) as horizontal segmented bars; each segment's percentage
is *entries with at least one signed record in the window*. Segment states:
demonstrated (filled), tagged-but-no-evidence (amber outline), query-error
(red). A baseline selector (Low/Moderate/High from the in-repo 800-53B OSCAL)
switches the denominator. Drilling a function lists entries; drilling an
entry runs its evidence query. Every rendered percentage is dated and carries
its chain reference; the footer says "no self-attestation on this screen".

---

## 6. Aesthetics — critique, then a system

### 6.1 Honest critique of the current console (from the renders)

**What works.** The Google-family surfaces read calm and professional; text
contrast is genuinely AAA (verified below); every state has a word, not just a
colour; empty states tell the truth ("Nothing has looked yet" is better than
any competitor's "All clear ✨"); tables are consistent; dark mode is a real
paired scheme, not an inverted filter; the palette already has a 4-step
severity system with words (`critical/high/medium/low`) and icons in
`wf-band`.

**What does not.**

1. **Severity hues blur at the top.** critical (#f9dedc container, error
   hue), high (#ffdbc8, orange), medium (#ffe8a3, amber) are three
   warm-adjacent pastels; at pill size (24px) the distinction rests on the
   word. Fine — but the *meter fills* rest on hue alone.
2. **Two viz tokens fail 1.4.11.** As strokes/fills on the light page,
   `--viz-warning: #f9ab00` is **1.93:1** and `--viz-serious: #e8710a` is
   **2.95:1** — both below the 3:1 required for graphical objects
   (computed; the `.wf-meter .serious`/warning fills are the offenders).
   `--viz-critical: #d93025` passes at 4.56:1.
3. **Walls of grey text.** Every screen stacks lead + hint + hint + help.
   The writing is excellent; the *quantity* competes with data. The case
   page carries ~180 words of hint prose inside tables before the timeline
   starts.
4. **A single density.** Everything is body-md tables. Nothing breathes:
   Today's stats row, the vulns tiles and the finding page all have the same
   rhythm, so nothing signals "this is the number that matters".
5. **No live-ness.** Every page is a photograph. "As of 09:41" honesty is
   right; total stillness is not, for a SOC.
6. **No motion vocabulary in use.** The M3 spring tokens exist and are
   almost unused — a live console needs "new row arrives" and "value
   changed" to be *seen* without being loud.
7. **Empty states explain, but don't act.** "Nothing has looked yet" is
   followed by a CLI command to copy — correct for the medium, but the
   primary next action should also be a button in the page where a grant
   allows it.
8. **Numbers are proportional-font numbers.** Counts in tables jitter as
   they update; tabular numerals are unset.

### 6.2 The palette — severity, WCAG-checked

Keep the Material-token architecture and the Google surfaces. Lock severity
as **text-on-container pairs** (all ratios computed against the actual hexes;
4.5:1 = AA, 7:1 = AAA):

| Severity | Light: text / container | ratio | Dark: text / container | ratio |
|---|---|---|---|---|
| critical | `#410e0b` on `#f9dedc` | **12.77** | `#f9dedc` on `#8c1d18` | **7.17** |
| high | `#331200` on `#ffdbc8` | **13.22** | `#ffdbc8` on `#6b2c00` | **8.17** |
| medium | `#5f4100` on `#ffe8a3` | **7.72** | `#fdd663` on `#291800` | **12.23** |
| low | `#0f5223` on `#c4eed0` | **7.32** | `#6dd58c` on `#072711` | **8.83** |
| info | `#07357f` on `#d3e3fd` | **8.86** | `#a8c7fa` on `#041e49` | **9.49** |

(These are the existing error/warn/ok/primary tokens — the current pairs
already pass; the table's job is to *freeze* them as the contract that
`contrast_test.go` keeps checking.)

New dedicated **stroke/marker tokens** at ≥3:1 on both pages (the fix for
critique 2), verified:

```
--viz-critical-stroke: light-dark(#b3261e, #f2b8b5);   /* 6.25 / 10.87 */
--viz-serious-stroke:  light-dark(#b05a00, #ffb59d);   /* 4.66 / 10.92 */
--viz-warning-stroke:  light-dark(#8f4a00, #fdd663);   /* 6.38 / 13.24 */
--viz-good-stroke:     light-dark(#0f5223, #6dd58c);   /* 8.92 / 10.21 */
--viz-series-stroke:   light-dark(#0842a0, #a8c7fa);   /* 8.74 / 10.80 */
```

Rules: area *fills* in charts keep the brighter hues but must carry an
adjacent numeral (the meters mostly do); anything 2px or thinner — borders,
markers, sparkline strokes, the flow-graph edges — uses the stroke tokens.
Colour never carries meaning alone: severity always has its word, agent
states always have their icon (already true of `wf-band`; extend to every new
component). The five categorical hues for graphs (blue, green, amber, orange,
red) differ in lightness as well as hue, which is what survives deuteranopia
([USWDS color guidance](https://designsystem.digital.gov/design-tokens/color/overview),
[Section508 color usage](https://www.section508.gov/create/making-color-usage-accessible),
[Harvard accessible palettes](https://accessibility.huit.harvard.edu/color),
[ColorPal dashboard combos](https://colorpalapp.vercel.app/guides/accessible-dashboard-color-combinations)).

### 6.3 Type, spacing, motion

- **Type**: keep the M3 roles. Add three rules: one `lead` per screen (lead
  paragraphs are currently rivaled by three hints); hints ≤ 20 words or move
  into `<details>`; `font-feature-settings: "tnum" 1` on every count, score
  and clock.
- **Spacing**: an 8px base grid (M3's 4px half-step allowed inside
  components). One new macro rule: boards separate sections with 32px and a
  hairline, so dashboards get a rhythm queue tables never had.
- **Motion**: two effects only, both `prefers-reduced-motion`-safe:
  `row-in` (new row: background flash from `--secondary-95` to transparent,
  600ms, effect-spring) and `value-tick` (a number that changed: 150ms
  opacity dip). No springs on data — colour that overshoots lands on a hue
  nobody chose (the stylesheet's own rule).

### 6.4 Component inventory — 30, no more

Existing, keep (19): top bar · sidenav+groups · rail · skip-link · page-head
(h1+chips) · lead · notice (ok/warn/bad) · chip row (filter) · pill (severity/
state) · tag (untrusted/test) · stats tile · meter bar · queue table
(+stacks) · kv list · notelist · code block + copy · paging · empty state ·
palette dialog.

New, add (11): **coverage ring** · **sparkline** · **live badge** ·
**clock row** (deadline meter + "due in") · **timeline item** (case record) ·
**session strip** (tool-call blocks) · **flow graph** (toxic-flow SVG) ·
**agent map node/edge** · **gate card** (onboarding step) · **canary chip**
(known-answer status) · **shortcut sheet**. Every new one is HTML+SVG+CSS
only; four of them are specialisations of existing parts (clock row = meter
bar + text; gate card = step card grown up).

### 6.5 Fifty polish fixes — a checklist, grounded in the screens

Order is roughly by screen, not by value; ☐ = not started. Each names the
file it belongs to.

**Finding page (`finding.html`)**
1. ☐ Move `Suggested by an agent` below Evidence and History; collapsed by
   default; label *unverified*.
2. ☐ Add source label to each proposal: model, plan version, timestamp.
3. ☐ Show confidence as a number beside the verdict word, not a bar.
4. ☐ Add "fill the form with this" link (selects radio, focuses why-field) —
   no accept button.
5. ☐ Record `suggestion_unopened` in the audit detail when decided-before-
   opened; note it under the form.
6. ☐ Move Evidence above the Decide form (evidence is the decision's input).
7. ☐ Sticky decide column ≥1280px; full-width form below on narrow screens.
8. ☐ Metadata `dl` (id, ATT&CK, span) collapses under `<details>` below the
   summary; the ID copy button uses `data-copy`.
9. ☐ When every evidence row is tainted, hoist the taint into the table
   caption ("All evidence from sources whoever is being detected can write")
   and drop the per-row tag.
10. ☐ Declared-incident hint (line 22) moves next to the Chips row as a
    button, not prose.

**Today (`today.html`, `today.go`)**
11. ☐ Group waiting items by `Commits` (acts / automations held / second
    administrator) with six-word group headers.
12. ☐ Add the risk pulse strip (sparkline + watermark lag + quiet sources +
    trial raises).
13. ☐ Add the live badge with three honest states (live / reconnecting /
    every 60s).
14. ☐ Add agents tile to the stats row (live · quiet counts).
15. ☐ Waiting rows: age ("2h") in its own column, right-aligned, `tnum`.
16. ☐ `todayWaitingShown` 7 → 10 now that groups carry scanning.
17. ☐ Add a Refresh button (GET form) beside the badge for the no-JS case.

**Case (`case.html`)**
18. ☐ Build the unified timeline (`<ol>`) and anchor each section to its
    entries.
19. ☐ Obligation hint texts >20 words into `<details>` inside the clocks
    table.
20. ☐ Clock rows gain hours-left + the meter bar in the Due column (some
    have it; make it universal, add `tnum`).
21. ☐ "Decisions that start a clock" forms: label the submit button with the
    trigger ("Record aware, as of now") — the generic "Record it" forces a
    re-read of the row.
22. ☐ Grade word (Sev 2) gets its severity colour pair, not `serious`
    regardless of grade.

**Vulnerabilities (`vulns.html`, `vulns.go`)**
23. ☐ Add the BOD 26-04 clock column (meter + "due in Nd Nh") to the queue;
    KEV+exposed rows only.
24. ☐ Tiles row: add "on a 26-04 clock: N" tile with stroke-token border.
25. ☐ Trend chart: add `tnum` to axis labels; y-axis 0-line labelled.
26. ☐ "What you say about your machines" section: untagged warning names the
    fastest fix as a link, not only an example string.

**Risk (`risk.html`)**
27. ☐ Add a 14-day score sparkline per entity (second column, narrow).
28. ☐ "Compare with yesterday" line under the hint (counts moved ±).
29. ☐ Score meters adopt the stroke tokens for the fill outline.

**Events (`events.html`)**
30. ☐ A quiet source raises its row to a warning band (it is the one signal
    the screen exists for; today it is only sorted first).
31. ☐ Watermark lag gets a live badge when the store is behind by >5 min.

**Hunt (`hunt.html`)**
32. ☐ First result row auto-focused (keyboard `o` opens), so a hunt is two
    keystrokes after submit.
33. ☐ Draft-rule block gets a copy button (`data-copy`).

**Agents (new screens)**
34. ☐ Map: dashed border for undeclared components; ⚠ on edges with open
    findings; legend inline.
35. ☐ Sessions table: egress-bytes column formatted `bytes` template fn
    (already exists).
36. ☐ Session replay: taint chain strip always rendered for sessions with a
    B2 finding, even when collapsed.

**Sources/Feeds (`feeds.html`)**
37. ☐ Rename heading to Sources; two subsections: "pushed to us" / "we
    collect" (connectors), matching onboarding step 2.

**Onboarding (`start.html`, `start.go`)**
38. ☐ Coverage ring + fastest-next-step line at top (§1.2).
39. ☐ Steps 5–6 with their deep links; test-finding generator for empty
    queues, findings marked `test`.
40. ☐ "What is already on, and why it is safe" table (§1.4) as `<details>`.
41. ☐ Keep the gates list; cross-link each gate to the manual anchor it
    already has.

**Shell / global (`layout.html`, `admin.js`, `style.css`)**
42. ☐ `/live` SSE endpoint + the eight event types of §3.1; `id:` = audit
    sequence; 15s comment ping.
43. ☐ Poll fallback via the existing `Refresh` hook + `vaigil_poll` cookie;
    visible mode in the badge.
44. ☐ Palette: entities, open findings, and grant-checked commands (§2.3).
45. ☐ `g`-prefixed jumps + `?` shortcut sheet; `j/k/o` row cursor on queues.
46. ☐ `row-in` and `value-tick` animations, `prefers-reduced-motion` safe.
47. ☐ `font-feature-settings: "tnum" 1` on `.num`, `.wf-points`, clock and
    tile values.
48. ☐ Replace `--viz-warning`/`--viz-serious` uses on thin strokes with the
    new stroke tokens (critique 2; the two failures).
49. ☐ Document icons for Agents/Coverage/Compliance in `icons.go` and add
    the three `destinations` rows + Assurance group in `nav.go`.
50. ☐ 48px targets and stacked-card tables verified on every new screen at
    380px (the 3am pass, §5).

---

## 7. Customization that survives updates

The model already exists twice in this codebase: the nav order is a **cookie
overlay on a shipped table** whose merge rule is "unknown keys keep their
place" (`applyOrder` in `nav.go`), and the content plane keeps **local
overrides** apart from shipped content. User customization becomes the same
thing, as data, never as modified defaults.

**One overlay per user**, stored server-side (not a cookie — it can hold
saved views and notification rules, and should follow the person; the
existing `Profile` store is the natural home), versioned, readable as text:

```json
{
  "version": 1,
  "user": "li",
  "defaults": { "landing": "/today", "theme": "dark" },
  "views": [
    { "key": "my-6am", "screen": "findings",
      "filters": { "state": "", "severity": ["critical","high"] },
      "sort": "rank", "columns": ["severity","finding","open-for"],
      "pinned": ["e3f0…","2638…"], "shared": false }
  ],
  "notifications": [
    { "when": "severity=critical", "channel": "email",
      "quiet_hours": "22:00–07:30 Europe/Paris", "override_for": "critical" }
  ]
}
```

Merge semantics — the rules that make it survive content updates:

1. **Referenced by stable key, never by label.** Views name screens and
   filter values by the same keys the URLs use (`state=""` is "needs
   attention"), so rewording a chip label or renaming a screen group never
   breaks a saved view. A renamed *path* is handled the way `destinations.Key`
   already handles it: the key stays, the path moves.
2. **Unknown values are dropped loudly, not silently.** A view naming a
   filter value the current build does not know renders with "this view named
   a filter that no longer exists" and the rest of the view intact — the
   opposite of silently showing the wrong subset, which is the failure mode
   that destroys trust in saved views.
3. **Shipped views are content, user views are overlay.** The pack ships
   views ("KEV only", "Waiting on you", "Agent anomalies") exactly as it
   ships rules; a user pinning or copying one makes an *overlay entry*
   referencing the shipped key, so an update improves the shipped view and
   the user's copy of its pins survives. `shared: true` promotes a personal
   view to a team view — an admin action, written to the audit chain like
   every other grant.
4. **Additive only.** The overlay never deletes shipped anything; "reset to
   shipped" is one button that empties the overlay entry, not a hunt through
   settings.
5. **Notification rules evaluate server-side** against the same events SSE
   carries, are per-user, and always include the fallback: no channel
   configured means the Today waiting group, so a rule can never quietly
   drop a critical finding. Quiet hours are per-user with the explicit
   critical override, and the escalation ladder (push → SMS → call after N
   minutes unacknowledged) is configured once per site, not per person —
   the pattern that keeps 3am pages survivable
   ([All Quiet](https://allquiet.app/blog/multi-channel-incident-alerting),
   [incident.io](https://incident.io/blog/on-call-best-practices-guide-2026)).

Why not more: themes-beyond-light/dark, custom fields, and layout editing are
deliberately out — every one of them has, in some other product, produced a
console only its author can read during an incident. The customization here
is *what I look at*, never *how the truth is presented*.

---

## 8. Sources

**Onboarding and time-to-value**
- https://www.vanta.com/resources/vanta-vs-drata-for-enterprises — Vanta's connector-breadth, coverage-driven positioning
- https://drata.com — Drata: guided remediation, continuous monitoring
- https://sprinto.com/blog/drata-vs-vanta — third-party comparison of the two onboarding philosophies
- https://www.wiz.io/academy/cloud-security/agentless-scanning — Wiz agentless model
- https://appsecsanta.com/wiz — first scan in minutes, full profile ≈24h
- https://cipherssecurity.com/wiz-onboarding-first-scan-guide — first-scan walkthrough
- https://help.aikido.dev/getting-started/setting-up-your-account/create-account-and-connect-your-repositories — Aikido: connect repos, six scans immediately
- https://help.aikido.dev/code-scanning/connect-your-source-code/connect-github-account-to-aikido — first findings ≈1 minute
- https://docs.panther.com/quick-start/onboarding-guide — Panther quickstart
- https://github.com/panther-labs/panther-analysis — pre-loaded sample detections
- https://panther.com/blog/writing-your-first-python-detection-in-30-minutes-with-okta-and-panther — "first detection in 30 minutes"
- https://www.huntress.com/resources/technical-partner-onboarding-with-huntress-session-march-1 — Huntress guided partner onboarding
- https://itecsonline.com/post/how-to-deploy-huntress — staged-deployment runbook
- https://tailscale.com/compare/legacy-vpn-premigration — incremental adoption as a design principle
- https://tailscale.com/enterprise — subnet-router incremental adoption

**Live dashboards, SSE, palettes, on-call**
- https://web.dev/articles/eventsource-basics — EventSource basics, auto-reconnect
- https://shopify.engineering/server-sent-events-data-streaming — SSE at scale behind proxies/LBs
- https://www.pubnub.com/guides/server-sent-events — SSE limits (why fallback polling)
- https://docs.cloud.google.com/chronicle/docs/reports/curated-dashboards/dashboard-queries-entities — Google SecOps curated dashboards
- https://cloud.google.com/security/products/security-operations — Google SecOps overview
- https://www.datadoghq.com/blog/observability-pipelines-google-secops — pipeline-then-dashboard pattern
- https://help.inky.com/articles/6584918-command-palette-cmdk — Cmd+K in a security product
- https://ux.stackexchange.com/questions/153299/how-did-cmd-k-come-to-be-the-standard-for-both-adding-a-hyperlink-and-o — ⌘K history and conflicts
- https://designsystem.digital.gov/design-tokens/color/overview — USWDS accessible color grades
- https://www.section508.gov/create/making-color-usage-accessible — color-usage accessibility
- https://accessibility.huit.harvard.edu/color — vary lightness, not just hue
- https://colorpalapp.vercel.app/guides/accessible-dashboard-color-combinations — dashboard severity combos, label-always rule
- https://incident.io/blog/on-call-best-practices-guide-2026 — on-call rotations, alert fatigue
- https://allquiet.app/blog/multi-channel-incident-alerting — push→SMS→call escalation
- https://ably.com/blog/best-practices-for-on-call-processes — alert quality and sleep

**AI explainability / anti-automation-bias**
- https://uxmatters.com/mt/archives/2026/06/designing-for-doubt-how-to-prevent-automation-complacency-in-ai-workflows.php — complacency vs automation bias, workflow countermeasures
- https://uxuiprinciples.com/en/principles/automation-bias-prevention — UI affordances that shape deference
- https://getthematic.com/insights/human-review-ai-insights-automation-bias — human review catches fewer errors than assumed
- https://www.researchgate.net/publication/391907859_Cognitive_Forcing_for_Better_Decision-Making_Reducing_Overreliance_on_AI_Systems_Through_Partial_Explanations — partial explanations / cognitive forcing
- https://iis.seas.harvard.edu/papers/bucinca2025contrastive.pdf — contrastive explanations against bias
- https://pmc.ncbi.nlm.nih.gov/articles/PMC10630476 — measuring adherence to AI recommendations (method for `suggestion_unopened`)
- https://arize.com/glossary/canary-evaluation-ai-systems — canary evaluation
- https://blogs.microsoft.com/blog/2023/03/28/introducing-microsoft-security-copilot-empowering-defenders-at-the-speed-of-ai — Security Copilot's accuracy caveat
- https://labs.zenity.io — phantom-reference manipulation of Copilot citations (why reasons are count-assembled here)
