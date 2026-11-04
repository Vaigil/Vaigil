> Written in October 2026, when this project was named Vaigil. The program is AeroProve now; the history below keeps its original name.

# Vaigil master report — deep dive, prior work, and the road to the SOC for AI agents

Date: 2026-10-24. Repo state: `main` @ 2751fac (split commit c023212). Sources: a full
technical audit of the codebase; recovery of the previous assistant's research (reports
04/06/07, the workflow plan `wfcheck.mjs`, verification journals); fresh web research on
AI-agent SOC, SIEM/SOAR state of the art, and vulnerability management (live feeds measured
2026-10-24). Every claim carries a file:line, a URL, or a measurement note.

---

## 0. The ten decisions that matter

1. **Vaigil's identity is already right; its subject is not.** The platform is an
   unusually principled SOC (fixtures on every rule, trial rings, dual control,
   hash-chained + ML-DSA + OpenTimestamps audit log, a model that can only suggest).
   But it monitors a traditional IT estate. **Nothing ingests AI-agent activity.** The
   one agent dataset it already owns — its own MCP call audit log — is deliberately
   excluded from detection (`cmd/vaigil/selfwatch.go:73-75` skips `audit.KindAI`).
2. **The market gap is real and measured**: of 66 agent-security vendors on the Agent
   Security Map (Oct 2026), only **3** are in "detection, response & audit" — and none
   is open, self-hosted, or evidence-grade. The consolidation wave (Protect AI→Palo Alto,
   Lakera→Check Point, Invariant→Snyk, Panther→Databricks, TheHive going closed-source)
   left the neutral layer open.
3. **The flagship feature is already half-built**: "evidence the agent cannot erase."
   Vaigil has Merkle + Ed25519 + ML-DSA + OpenTimestamps anchoring; extending it to
   out-of-process agent action receipts (SCITT-shaped) is the moat no incumbent will
   copy, because their business model keeps evidence in their cloud.
4. **Speed is an architecture problem, not a tuning problem.** Per-event double-fsync
   index rewrites, per-rule-per-event regex recompilation, and three full scans per
   detect run cap the platform at ~500–2,000 events/sec and minutes-long full hunts.
   The fix is known and zero-dependency (VictoriaLogs blueprint: batched writes,
   per-day partitions, columnar blocks, bloom filters, RAM metaindex).
5. **Detection quality**: the discipline (fixtures, trial rings, Wilson-bounded
   precision) is better than most commercial SIEMs. What's missing is Sigma 2.1
   correlation parity, RBA-style entity risk accumulation (proven 50–90% alert
   reduction), UEBA-in-pure-Go, and streaming evaluation on ingest.
6. **SOAR is a checklist, not an engine.** Playbooks are non-executable checklists with
   2 actions in the catalogue. The 2026 consensus model is a CACAO v2 DAG (branching,
   parallel, approvals, SLA timers, rollback) plus agent-specific containment actions
   (kill switch, MCP quarantine, credential revocation).
7. **The vuln pipeline decides well but scans nothing.** First-party scanning of
   lockfiles, secrets, model files, and `.mcp.json`/agent configs is implementable in
   pure Go stdlib and is the differentiator no SCA has. Prioritization must move to the
   **BOD 26-04 four-factor model** (June 2026: exposure, KEV, automation, impact) —
   CVSS is no longer federal policy.
8. **The agentic analyst must go "agentic, not autonomous."** Investigation becomes
   agentic (typed evidence queries, separate judge, citation verification, conformal
   abstention); action stays behind deterministic policy and two-person approval. The
   evidence base: harness beats model (F1 0.744→0.958 with the same model), empty
   retrievals cause missed attacks, restraint is the calibration gap, only
   architectural defenses hold against prompt injection.
9. **Everything maps to NIST.** Ship a machine-readable control-mapping file (800-53r5
   control IDs × AI RMF function × AI 600-1 category × OWASP ASI ID × ATLAS technique)
   with every detection. CISA's May 2026 agentic-AI guide names "obscure event records"
   as a core risk — Vaigil is the answer to exactly that sentence.
10. **Content must flow without binary releases.** A signed, staged, auto-rolling-back
    content plane (TUF-style, Ed25519/ML-DSA, shadow-ring validation) is the solo-dev
    unlock and the CrowdStrike-July-2024 lesson applied.

---

## 1. Where Vaigil stands today (verified audit)

146,578 lines of Go across ~68 internal packages, zero third-party dependencies, Go
1.27.3. Events: connectors/push → declarative per-source mappings (`internal/source`) →
one OCSF-inspired event shape (`internal/telemetry`) → append-only JSONL segments
(`internal/spool`, 64 MiB/day rolls, SHA-256-sealed). Detection is batch over a cursor
(`internal/detect`, `internal/correlate`, `internal/indicator`); findings land in a JSON
register; response is human-centric (playbook checklists + a 2-entry action catalogue +
watch/ask/act automations); the AI analyst is a closed-set suggestion pipeline. 1,432
test functions; meta-tests enforce that README claims match artifacts (`docs_claims_test.go`,
`wired_test.go`). No fake features found; the gaps are scope gaps.

### Speed ceiling (the honest numbers)

| Path | Today | Ceiling | Fix |
|---|---|---|---|
| Ingest | Every `Append` rewrites the whole index with fsync (`spool.go:254`, `atomicfile.go:66-80`) | ~500–2,000 events/sec sustained | Batch writes, one sync per batch; persist index on roll only |
| Hunt/search | Budget-capped 64 MiB full JSON scan per page (`admin/hunt.go:124-130`) | ~0.5–2 s per 100–160K events; full 16 GiB store = 3–7 min | Per-segment sidecar index: sorted (offset,time) + FNV bloom filters on source/class/actor; parallel pread/mmap |
| Rule eval | `Fields()` map rebuilt once per rule per event (`rule.go:202-207`); regexes recompiled per value per event (`rule.go:291`) | 100 rules × 1M events ≈ 100M map builds + minutes of `regexp.Compile` | Compile once at load; build fields once per event |
| Detect run | Three independent full scans of the same window (`detectrun.go:267`, `detectcorrelate.go:215`, `intelcmd.go:106`) | 3× wasted IO | Single fused pass |
| Concurrency | `Spool` has no lock; two writers race on `index.json` (spool.go:182-188) | corruption risk | Lock file like `automate`'s |

Also found: `wired_test.go:71-77` still excuses `internal/selfvuln` and `internal/fedramp`,
which the split deleted — stale registry entries (and a hint of what the previous project once had).

### Detection engine — solid core, partial breadth

- Predicate-tree rules with mandatory must-match/must-not-match fixtures; trial ring
  with measured precision (Wilson intervals, 10-verdict floor); suppressions ≤90 days
  with owner+reason. This loop is better than what most commercial SIEMs ship.
- **Real bug**: `correlate/engine.go:145-149` claims adjacent-window evaluation for
  temporal types; `evaluate()` (250-312) implements no such thing — two in-timespan
  events that straddle a window boundary silently never correlate.
- Sigma import: supports contains/startswith/endswith/re/cidr/gt/lt/all/base64offset/
  windash/`1 of` wildcards; **refuses** bare keyword lists, `gte`/`lte`, aggregations
  (`count() by`), and silently drops `timeframe`. A large fraction of the SigmaHQ
  corpus skips (honestly counted in the import report).
- `internal/baseline` (UEBA-lite with denominators-mandatory discipline) exists but is
  hunt-CLI-only, in-memory, never wired into detection.
- No entity risk accumulation (RBA), no online anomaly detection, no sequence models.

### SOAR — deliberate but thin

A playbook is a static checklist (`incident/playbook.go:16-37`): steps with Why, acyclic
Needs, evidence-note requirement, Undo text; runs are proposed→approved→worked with full
attribution. Nothing executes. The action catalogue is two Okta actions. `automate` is
the real engine (5 event kinds, flat conditions, watch/ask/act with hourly limits,
author-cannot-approve). Missing vs the 2026 consensus (CACAO v2 + commercial practice):
executable steps, branching, parallel, SLA timers, wait-for-event, variables, evidence
attachment beyond text, versioning, import/export, integration breadth, rollback.

### Vulnerability management — decides well, scans nothing

Strong: SBOM ingest (CycloneDX+SPDX), OSV matching with fix-path analysis, KEV/EPSS
weighted ranking with explained terms, SSVC from CERT/CC CSV, OpenVEX output, SARIF
2.1.0, and **first-party Go reachability** via `go/parser` (`internal/reach`). But every
input must be pre-built by a third party: no lockfile reading, no secret scanning, no
config audits, no container parsing. `internal/secret` and `internal/pii` already
contain most of the pattern machinery a first-party scanner needs.

### The AI-agent gap (the vision's core)

- As a **client** of Vaigil: solid. MCP server (8 ops/4 tools, progressive disclosure,
  fail-closed auth, refusal code -32001, every call audited, AI actors distinguished in
  the OCSF export).
- As a **subject** of monitoring: absent. 18 log sources, none is an LLM/agent source.
  No agent identity class, no per-agent allowlists, no agent detections in
  `detect/pack` (28 rules, all traditional + 6 self-watch).
- **Highest-leverage one-line change in the repo**: stop skipping `audit.KindAI` in
  `selfwatch.go:73-75` — Vaigil's own MCP audit log (tool, operation, principal, model,
  outcome) becomes its first agent telemetry source, through the existing chained,
  OCSF-exportable pipeline.

---

## 2. What the previous assistant (Claude) was doing, and what survived

On 2026-10-24 Claude ran a 9-workflow, ~16-agent research program (`wfcheck.mjs`,
re-runnable in modes gather→design→master):

- **7 code audits** (architecture, access, integrations, ux, self-monitoring,
  detection/SOAR, vuln) — **all failed** at the session limit (~3.04M tokens burned).
- **7 research tracks** (competitors, XDR/NDR/TIP/IAM, startup+agent failures,
  auto-update content plane, agent roles/memory, NIST mapping, zero-setup/response/UI)
  — **all failed**.
- **Adversarial verification** of 10 prior findings — 3 completed (A1 CONFIRMED-medium,
  A2 PLAUSIBLE-medium with an executed reproduction test at
  `work-ai-A2-trace/repo/internal/analyst/zz_pem_probe_test.go`), 7 died mid-run.
- **3 designs + hostile critiques + 00-master-report.md** — never started.

**Completed earlier that morning** (these survive in
`/tmp/claude-1000/-home-rashik-vaigil/05d585f9-2ebb-4a3d-9f1c-8415ee79b904/scratchpad/`):

- `04-ai-layer.md` — the AI/agentic layer audit (bugs A1–A16, M1–M7, AU1–AU4) plus a
  full design for going agentic (CaMeL-style dual-LLM, capability tokens, verifier-
  checked citations, conformal abstention, L0–L4 autonomy).
- `06-market.md` — the market map (66 vendors, consolidation table, 15 white-space
  areas with verdicts, positioning, moat ranking, build order).
- `07-agentic-research.md` — the evidence dossier for the agentic analyst (harness
  patterns with adopt/reject verdicts, calibration, injection defense table, decision
  policy, eval methodology, per-alert control flow, model tiers, year-1 targets).
- Salvaged source material: NIST 800-53r5 OSCAL catalog + baselines, DBIR + M-Trends
  text, CrowdStrike July-2024 RCA, OWASP ASI PDF, Sommer-Paxson, ~40 console renders,
  and a full passing `go test ./...` record.

**Caution for any re-run**: the workflow marked ai-trial, ai-supp, ai-notify as
`survives:false` — that is an artifact of zero verifier votes, **not** refutation. They
remain plausible and cheap to fix (trial findings reach automation, `detectrun.go:326`;
suppression token-evasion via `raw.*`, `tuning.go:205`; notify can email the
attacker-controlled entity, `automatecmd.go:236`).

### Verified/known bug list to fix now (from 04-ai-layer §7, ordered)

**Status 2026-10-24 (build pass):** fixed and tested — items 1 (A2), 2 (A1/M1),
3 (A7), 4 (AU1/AU2), 5 (suppression), 6 (A3/A4, as a new `internal/untrusted`
package), 7 (A5 typed Sources), 10's stdio-read auditing and old-text cleanup
(the HTTP MCP endpoint remains unwired), and 11's response-body cap. Also fixed
beyond the list: the correlation adjacent-window bug, the missing spool writer
lock, the stale wired_test excuses, and the missing `storeAgentEvents` — model
records now reach the event store under the `vaigil/agent` source with the
agent as actor, which is the first piece of the agent-monitoring substrate.
Still open: A6 (trust classes on Facts), A8 (temperature/seed hardening), A9
(as-of eval), Usage into budgets, mounting the MCP HTTP transport.

1. **A2** PEM header without END erases the rest of the analyst prompt (`secret.go:46-55`
   through `pii/mask.go:94-102`) — mask per field, bounded span, regression test.
2. **A1/M1** MCP proposal free-text `because` rendered unlabeled next to the decide form
   (`mcpsecurity.go:313-383`, `finding.html:48`); `By` never rendered. Replace with
   closed reason-codes + event-ID citations; label source; strip bidi/invisible.
3. **A7** model outage recorded as "abstained" and never retried (`analystcmd.go:216-241`).
4. **AU1/AU2** trial findings trigger automation (`detectrun.go:326-331`); notify emails
   the log entity (`automatecmd.go:236-242`, `:409-413`).
5. Suppression `Hides` matches any whitespace token of any non-blocklisted field
   (`tuning.go:195-213`) — restrict to declared multi-value fields, refuse `raw.*`.
6. **A3/A4** shared `untrusted.Clean` (canonicalize→strip→fence→rune-safe truncate).
7. **A5/A6** typed Sources (no parsing " and " from titles), trust classes on Facts.
8. **A8** no temperature/seed/nonce — fake self-consistency behind caching gateways.
9. **A9** eval leakage — as-of fold (the register is event-sourced; cheap).
10. **M2/M3** wire or delete the unused HTTP MCP endpoint + dead OAuth comments; audit
    stdio reads; delete the old project's tool descriptions and dead `vaigil_check`.
11. Consume `Usage`; cap response body (`model.go:238`).

---

## 3. The strategic position (from the market research)

- The agent-security market consolidated brutally (Apr 2025–Aug 2026): nearly every
  standalone vendor was acquired. Independent survivors with funding are all closed SaaS.
- Guardrails/AI-firewalls is the most crowded category (14/66). **Detection, response &
  audit has 3 vendors.** Nobody sells an open, self-hosted SOC for agents combining
  inventory, posture/vuln, detection, response and evidence.
- OSS landscape: Wazuh 5.0 still RC and no agent monitoring; Security Onion paywalls
  agentic AI in Pro; Elastic's best AI needs a license; TheHive 5 is closed-source;
  Matano is dead. SigmaHQ has no GenAI logsource taxonomy; OCSF 1.9 has `ai_agent`/
  `ai_model` objects but **no agent-activity event class** — the schema slot is open.
- Agents delete their own traces in 5 of 6 major harnesses without tripping guardrails
  (arXiv 2609.30266); Gartner's first Guardian Agents guide stresses independence from
  the watched platform. Both point at Vaigil's exact shape: self-hosted,
  tamper-evident, vendor-neutral.
- Positioning line: *"The flight recorder, SIEM and SOAR for AI agents. Open,
  self-hosted, and evidence-grade."*

---

## 4. The improvement program, by pillar

### 4.1 Speed — rebuild the storage floor (zero-dependency)

Follow the VictoriaLogs blueprint (single-binary Go log DB; references in the research):
per-day partitions; immutable parts progressing in-memory→small→big; per-stream blocks
(~2 MiB) sorted by time; columnar per-field files with dictionary + delta encoding;
per-(block,column) **bloom filters** (~2 bytes/token) and min/max zone maps; a
RAM-resident metaindex so queries prune parts→blocks→columns before reading data;
per-CPU ingest shards flushing ~1s; background merge. Published reference numbers:
~1 GiB/s logs/sec on cheap disks, ~10:1 compression, p99 3.6× faster than Loki, 30×
less RAM than Elasticsearch. Keep JSONL as the durable export format; the index is
derived and rebuildable. Targets for Vaigil: 20K+ events/sec ingest, sub-second point
queries, 16 GiB full hunts in seconds.

Order: (1) `AppendBatch` + lock file; (2) compiled rule programs + single fused detect
pass; (3) per-segment sidecar indexes; (4) the columnar engine; (5) streaming
evaluation on ingest for push sources (the `automate` engine already proves the
synchronous pattern on sign-ins).

### 4.2 SIEM / detection

- **Sigma 2.1 parity**: add `gte`/`lte`, keyword-list support, and auto-conversion of
  `count()` aggregations + `timeframe` into `correlate` rules. This is the difference
  between "Sigma import" as feature vs checkbox.
- **RBA (risk-based alerting)**: per-entity risk accumulators fed by rule verdicts and
  anomalies, decaying over time, emitting incidents at thresholds — Splunk community
  reports 50–90% alert-volume reduction; it is also exactly how Google SecOps UEBA and
  Elastic entity risk actually work.
- **UEBA in pure Go**: EWMA baselines + MAD-based robust z-scores; peer groups by
  attribute with the dual test (self-deviation AND peer-deviation); Markov transition
  matrices over tool/command sequences; hashed-shingling session similarity. Wire the
  existing `internal/baseline` package into `detectPass` and persist profiles.
- **Streaming-first**: evaluate single-event and threshold rules on the ingest path;
  the store serves hunting, backfills, and temporal correlations.
- **FP machinery**: keep the fixture/trial-ring discipline; add 24h-default expiring
  suppressions applied at emit time; one-click "this was FP" writes the exception and
  offers the exact predicate; feed dispositions back as replay corpus.
- Fix the correlation boundary bug (adjacent windows).

### 4.3 The AI-agent core (the product)

**Ingest** (make agents a first-class monitored subject):
- New sources: OpenAI audit-logs API and Anthropic Compliance API pollers (both are
  plain JSON/HTTP — pure Go); Bedrock via CloudTrail delivery; Vertex via audit logs;
  OTel GenAI OTLP/HTTP-JSON ingestion (the semconv dictionary is Development-status but
  the de-facto vocabulary: `gen_ai.agent.*`, `gen_ai.usage.*`, `execute_tool`,
  `invoke_agent` spans); an MCP-traffic push endpoint reusing `internal/inbound`.
- Stop dropping `KindAI` in selfwatch — Vaigil monitors its own agent traffic first.
- Normalize to 4 primitives: `model_call`, `tool_call`, `retrieval`, `agent_step`,
  keyed by trace + conversation id. Prompts hashed by default; content opt-in.

**Identity**: an agent registry (id, owner, allowed tools, issuance record) joined via
`telemetry.ID{Issuer:"agent"}`; MCP tokens bound to agent principals with per-agent
operation allowlists enforced in `Authorise`; carry `on_behalf_of`, delegation chain
(RFC 8693 `act`), credential binding (bearer vs DPoP), audience. Alert on audience
mismatch, bearer-where-DPoP, delegation depth.

**Detections** (deterministic first — the ADR two-tier lesson: zero FP at the alert
tier, accept lower recall; LLM only as second-tier enrichment):
- Tool-definition hash change after approval (MCP rug pull); new/unsigned MCP server;
  tool call outside declared allowlist; secrets in tool args/outputs.
- **Toxic-flow / lethal-trifecta completion**: untrusted read → sensitive read →
  egress to new destination, one session, windowed — implement as `correlate` sequence
  rules over labeled tools (label from inventory + AI-BOM).
- Per-agent baselines (tool mix, egress volume, token spend, time-of-day, delegation
  depth) with drift-from-declared-purpose vs the agent's manifest.
- First-use-of-tool (via baseline), session cost anomalies (token z-score),
  injection-marker telemetry (an injection attempt in a log is itself an indicator).
- Content packs: import ATR (~800 YAML agent rules) and sigma-ai via the existing
  sigma package; tag everything with OWASP ASI + ATLAS IDs.

**Standards contribution (cheap, high-leverage)**: register a Sigma
`logsource.category: ai_agent` taxonomy and an **OCSF extension** for agent activity
(riding `api_activity` + the 1.9 `ai_agent`/`ai_model` objects, and the 1.9
`record_integrity` profile for tamper-evident event chains). Whoever defines the
logsource owns the content ecosystem.

**Evidence flagship**: out-of-process agent action receipts (SCITT-shaped:
hash-chained, signed, transparency-log-verifiable) in the existing
Merkle+Ed25519+ML-DSA+OpenTimestamps chain; collect via sidecar/MCP-proxy/OTel outside
the agent trust boundary; heartbeat gap detection flagged "recorder blind" (agents
delete their own traces in 5 of 6 harnesses — arXiv 2609.30266).

**Agent-aware SOAR actions**: kill switch (revoke agent sessions via CAEP transmit —
the SSF/CAEP machinery already exists), disable Entra blueprint, quarantine MCP tool
schema (pin description hashes), block skill hash, cut A2A delegation, zero a token
budget. Dual-control where access-affecting.

### 4.4 SOAR / playbooks

- Move playbooks from checklists to a **CACAO v2-subset DAG**: steps of type action /
  condition / parallel-and-or / approval / delay-SLA / sub-playbook; variables passed
  between steps; evidence attached per step; per-step undo; playbook versioning and
  import/export (CACAO JSON serialization for interop).
- Executable steps reference catalogue actions (still fixed requests, still
  dual-control); add step timers/SLAs and wait-for-event steps.
- The execution state log rides the existing JSONL/audit-chain design (a playbook run
  is an event-sourced object — fits the zero-dep store).
- Keep the human gates: maker-checker, author-cannot-approve, watch/ask/act with
  hourly fallback. Add an optional `llm_agent` step type (user-supplied key) for
  triage/enrichment inside the DAG — "agentic, not autonomous."

### 4.5 Vulnerability scanner (first-party, pure Go)

Priorities shift confirmed by live measurement (2026-10-24):
- **EPSS is v5** (since 2026-06-15; 2.77 MB/day, ~395K CVEs, ranking skill 0.514→0.633).
- **KEV: 1,756 entries** (1.8 MB). **BOD 26-04** (June 2026) revokes BOD 22-01 and
  replaces CVSS-driven deadlines with four factors: exposure, KEV, automation, impact
  (3 days for exposed+KEV; clocks recompute dynamically).
- **NVD abandoned universal enrichment** (Apr 15, 2026): full analysis only for KEV/
  federal/critical CVEs. **OSV is the primary matching corpus** (purl-first), NVD is a
  secondary join. Data budget: selective OSV ecosystems ~283 MB, hourly incrementals.

Build first-party (all stdlib):
1. Lockfile/manifest readers (package-lock.json, requirements.txt, go.mod subset,
   Cargo.lock subset, pom.xml) emitting purl inventories directly into the existing
   OSV matcher — removes the "bring a pre-built SBOM" precondition.
2. Secret scanning (regex + Shannon entropy, gitleaks-class; `internal/secret` already
   has the shapes).
3. **AI-stack checks — the differentiator**: pickle opcode scan with nullifAI
   heuristics (null-byte obfuscation, cloud-loader functions), safetensors/GGUF header
   validation, Sigstore model-transparency signature verification (JSON/HTTP + stdlib
   crypto), `.mcp.json`/MCP manifest scanning (curl|sh patterns, unpinned `npx -y`,
   env harvesting, tool-description hash pinning), agent-config scanning
   (`.cursorrules`/`CLAUDE.md`/`AGENTS.md`/hooks injection markers), slopsquatting
   near-miss detection (edit distance vs popular names + hallucination corpus).
4. Config policy subset (Dockerfile, K8s JSON) with fixtures, like detect rules.
5. Composite priority = BOD 26-04 four factors (exposure ∧ KEV → Act ≤3d); EPSS delta
   alerting (score jumps reprioritize); SSVC tree evaluation consuming Vulnrichment
   JSON; emit the BOD 26-04 decision table and the 7-day machine-readable
   exposed-asset export.
6. SBOM quality scoring (17-field 2026 minimum elements); CycloneDX 1.7 ML-BOM
   (AI-BOM) generation; CSAF VEX export alongside OpenVEX.

Keep ingesting: Trivy/Checkov SARIF for deep IaC, govulncheck JSON for Go call-graph
reachability (the existing first-party `internal/reach` covers scanning source
directly), TruffleHog verified secrets, Nuclei safe templates as validation evidence.

### 4.6 The agentic analyst — accuracy program

Evidence base (07-agentic-research, all arXiv-cited): harness beats model (F1 0.744 →
0.958 same model; a 9B open model hits 0.952 in the harness); same-context self-review
harms (Self-Refine −63 net, CoVe −107); a separate judge with asymmetric evidence rules
is the only significant ablation; empty retrievals dismiss ≥88% of attacks in 4 of 5
baselines; frontier models contain 100% of real threats but at 45–82.5% FP rates —
restraint must be deterministic policy, not model judgment; adaptive attacks break 12
published defenses at >90% — only architecture holds (CaMeL, FIDES, Progent); a
deterministic policy verifier removed 466 non-compliant actions from LLM IR plans with
no recall loss.

Design (04-ai-layer §6, in phases):
- **Phase 1**: investigation ledger (append-only, hash-chained, into the audit chain);
  typed evidence query library (deterministic Go: baseline rarity, correlate
  neighbours, identity resolve, travel judge, vuln reach, incident history — no LLM);
  playbook DAGs per rule family with closed hypothesis sets and discriminating
  evidence; shadow mode only; eval harness with as-of replay + injection suite
  (extend `analyst.plants`).
- **Phase 2**: quarantined reader (tainted text → typed extractions, no tools);
  strategist commits a thesis; **separate judge from a different model family** with
  asymmetric rules (dismiss needs affirmative trusted benign evidence; empty is never
  benign); citation verifier (claims must reference real event IDs; echo check;
  counterfactual ablation — untrusted text may only push toward escalation);
  Mondrian conformal gate per rule family; **auto-close only on {benign} singleton at
  α=0.01 with ≥1 trusted benign evidence and 5% random human audit**.
- **Phase 3**: policy engine + plan verifier; A3 reversible containment with TTL/
  auto-undo; agent-threat detections on Vaigil's own ledger (dogfooding).
- Model tiers via the existing OpenAI-compatible interface: judge ≠ strategist family;
  9–30B open model (Qwen3.5-9B class) for air-gapped triage; sub-2B classifier for
  PII/routing; precedent memory exact-key-first.
- **Year-1 targets** (publish them — no vendor does): recall ≥97%; malicious share of
  auto-closed ≤1%; escalation ≤20%; FP containment ≤2%; executed policy violations 0;
  action-path hijacks 0 (≤2% verdicts under adaptive suite); ECE ≤0.05; pass^5 ≥0.9;
  ≤$0.10/alert; air-gapped F1 within 3 pts of cloud.

### 4.7 NIST alignment

- Ship a machine-readable mapping file tagging every detection with 800-53r5 control
  IDs (AU-2/3/12, AC-2/3/6, SI-4, SI-19), AI RMF function, AI 600-1 category, OWASP
  Agentic Top-10 ID (ASI01–10), ATLAS technique. CISA's May 2026 "Careful Adoption of
  Agentic AI" guide names **"obscure event records"** as a core risk — Vaigil's agent
  receipts + existing chain are the direct answer.
- Note corrections from fresh research: adversarial-ML taxonomy is **AI 100-2e2025**
  (not 800-226, which is differential privacy); there is no NIST AI 100-8; the agentic
  AI-RMF overlay is still RFI-stage (NIST AI Agent Standards Initiative); 800-53r5
  remains current.
- Vuln side: SSDF PW.8.2/8.3 and RV.1 evidence mode; BOD 26-04 decision table; the
  800-53r5.2.0 OSCAL catalog is already downloaded in the salvaged material.
- Compliance evidence packs (EU AI Act Art. 12 logging / Art. 14 oversight with a
  global "agent mode: watch" stop control; ISO 42001) generated from the signed log —
  high-risk obligations land Dec 2027/Aug 2028; being ready early is a differentiator.

### 4.8 Content plane (the solo-dev unlock)

Signed content packs (detections, parsers, playbooks, scanner checks, feeds, prompts,
eval sets) with TUF-style rollback/freeze/mix-and-match protection (Ed25519 + ML-DSA,
stdlib-only); channels stable/beta/edge; staged rollout with shadow-ring replay
validation, canary %, auto-rollback on FP spike (the CrowdStrike July-2024 RCA —
salvaged — is the canonical failure mode to design against); local overrides that
survive updates; air-gapped bundles; AI-drafted detections validated by replay before
human promotion, never auto-deployed.

---

## 5. Phased roadmap

**Now (bug-fix release, ~days)**: the verified list in §2 (A2 PEM masking; A1 MCP
proposal hardening; A7 abstention-vs-outage; AU1/AU2; suppression token restriction;
`untrusted.Clean`; typed Sources; temperature/seed; as-of eval; M2/M3 MCP cleanup;
Usage/budgets; correlation adjacent-window fix; stale `wired_test` excuses; spool lock).

**Release N — "SOC for AI agents" substrate (0–3 months)**:
storage batch+lock+compiled-rules+fused-pass; stop dropping KindAI; **mount the
already-written MCP HTTP endpoint** (02: it is complete but dead code) and wire the
agent principal design (02: `agent:<name>` in the existing policy + registry + caveat
tokens); OTel GenAI/OTLP ingestion + OpenAI/Anthropic audit APIs as data-only
manifests (03); the **ship-first 15 detections** from 13 (near-zero-FP deterministic
set) + ATR/sigma-ai import; agent receipts in the existing chain with recorder-blind
detection; `vaigil-collector` MVP per 12 (auditd follow, config-file watch pack,
agent-transcript tails, DNS/SNI observation — the out-of-process recorder); CAEP kill
switch (02: SSF transmitter half) + MCP quarantine + blueprint-disable actions; Sigma
`ai_agent` logsource + OCSF extension proposal; lockfile + secret scanning
first-party; BOD 26-04 composite priority (16: RA-5 gap); fix the five integration
issues from 03 (IP-blocklist bypass, array-path mappings, vault-by-default, replay
cache, `connect probe` auth); agentic harness phase 1 in shadow.

**Release N+1 — earned autonomy + content plane (3–6 months)**: columnar storage
engine; judge+citations+conformal; A2 auto-close for passing families; A3 reversible
containment; policy engine + plan verifier; CACAO playbooks with executable steps;
RBA entity risk + UEBA wiring; toxic-flow correlation over the labeled tool graph;
AI-BOM→VEX/SSVC for agent components; malicious-skill + MCP-CVE feeds; **the signed
content plane per 14** (TUF-shaped, data-only packs, shadow-replay gate, local
overrides); the `/live` SSE dashboard + "Get protected" funnel per 17; ITDR depth per
12 §5; red-team→rule loop.

**Release N+2 — moat completion (6–12 months)**: VaigilBench (open benchmark of
agentic-SOC accuracy incl. false-closure rate — the number no vendor publishes);
AuthZEN PDP adapter; UEBA per blueprint; A2A posture+monitoring; compliance evidence
packs + NIST mode per 16 (ahead of Dec 2027); air-gap reference profile with published
eval numbers; streaming detection everywhere; Windows/macOS collector phases.

---

## 6. Companion reports (continuation pass, same day)

The continuation pass completed the remaining audits and design tracks of the original
program as separate reports beside this one:

| Report | Verdict in one line |
|---|---|
| [02-access-control.md](02-access-control.md) | Enforcement is centralized and fail-closed on all three surfaces, dual control covers the four take-over moves — but it is silently bypassable with store filesystem access, the **MCP HTTP transport is dead code** (never mounted by `serve`), agents have a label but no identity, and the head-signing keys sit in the audit dir. The target design: `agent:<name>` principals inside the existing policy, the already-written OAuth 2.1/DPoP/token-exchange primitives wired, macaroon caveat tokens, maker-checker between model families, CAEP-transmit kill switch. |
| [03-integrations.md](03-integrations.md) | 7 of 8 connectors solid/secure (EVM/Blockscout partial); the engine is data-driven — GET-only, declared-field reads, watermark-on-complete-run. Five real issues (connector dials bypass the IP blocklist; CrowdStrike/K8s mappings read array paths the path language drops; plaintext credential fallback is the default until `vault enable`; inbound replay cache is process-local; `connect probe` is unauthorised and unaudited). Most new integrations — including the OpenAI/Anthropic audit APIs — need **no new engine code**, only manifests: the content-plane thesis holds. |
| [12-xdr-ndr-tip-iam.md](12-xdr-ndr-tip-iam.md) | EDR: integrate the OSS fleet as sources + build exactly one thing — a read-only, user-space `vaigil-collector` that doubles as the out-of-process agent-telemetry recorder (no kernel drivers, ever). NDR: flow logs + DNS/SNI from the collector. TIP: a light feed manager, never a platform — and curate the malicious-MCP/agent feed as first-mover content. ITDR: the deepest build, over already-ingested IdP data. |
| [13-startup-and-agent-failures.md](13-startup-and-agent-failures.md) | 40 startup + 30 AI-agent failure modes with detection logic in vaigil's actual model (rules / Sigma-v2 correlations / baseline rarity), ATT&CK + ATLAS + OWASP ASI tags, fixtures, and response options — the detection content backlog. Ship-first 15 are near-zero-FP deterministic signals; six shared correlation patterns serve ~25 entries. Five telemetry gaps named (tool-args classification, egress/DNS, SaaS data-plane logs, workflow telemetry, consent labels). |
| [14-auto-update-content-plane.md](14-auto-update-content-plane.md) | Packs are **data only** (no interpreter to attack); minimal TUF with offline root, dual Ed25519+ML-DSA; the customer's own estate is the last gate (shadow-ring replay, FP budget, trial-ring bake); expiry never disables content; user edits win and are recorded; the shipping binary is the only validator; binary self-update deliberately out of scope. All five CrowdStrike RCA lessons mapped to concrete countermeasures. |
| [16-nist-mapping.md](16-nist-mapping.md) | Full 800-53r5.2/CSF 2.0/AI RMF mapping with file:line verification; the 10 significant gaps ranked (kill switch, IA-9 agent registry, selfwatch one-liner, evidence queries, retention floors, BOD 26-04 four-factor, first-party scanning, taint/toxic-flow, executable playbooks, AI-BOM + signed packs); the machine-readable mapping-file format with worked examples; the "NIST mode" design. Note: 800-53r5.2 added SA-15(13) Logging Syntax — literally vaigil's ingest design; COSAiS was renamed COSIS on 2026-10-20. |
| [17-zero-setup-response-ui.md](17-zero-setup-response-ui.md) | The 8-step "Get protected" funnel (coverage ring as motivator); Agents as a first-class board with session replay and the toxic-flow SVG; Today as queue-first inbox with a real `/live` SSE spec (8 event types, the CSP already permits it); finding page reordered evidence-first with anti-automation-bias AI placement; WCAG-AAA severity palette (two current viz tokens fail 1.4.11 — fixes specified); 50-item grounded polish checklist; customization as per-user overlays that survive content updates. |

## 7. Source index

- Prior session artifacts: `/tmp/claude-1000/-home-rashik-vaigil/05d585f9-2ebb-4a3d-9f1c-8415ee79b904/scratchpad/`
  (04-ai-layer.md, 06-market.md, 07-agentic-research.md, wfcheck.mjs, work-*/ sources)
  and journals under `~/.claude/projects/-home-rashik-vaigil/.../subagents/workflows/`.
  These live in /tmp and may not survive a reboot — copy what matters into the repo.
- Key external references: AIDA/alert benchmark arXiv 2610.10608; CaMeL 2503.18813;
  FIDES 2505.23643; Progent 2504.11703; SOCpilot verifier 2605.05501; agent
  self-deletion 2609.30266; OpenSec 2601.21083; LogJack 2604.15368; adaptive injection
  2510.09023. VictoriaLogs internals blog; Exabeam-on-ClickHouse; Sigma 2.1 spec;
  CACAO v2.0; OCSF 1.9 releases; OTel semantic-conventions-genai repo; MCP
  authorization spec 2026-07-28; CISA agentic-AI guide (May 2026); BOD 26-04; EPSS v5
  (FIRST); OSV data docs; CycloneDX 1.7/ECMA-424; nullifAI (ReversingLabs); Sigstore
  model-transparency. Full URLs are preserved in the research agents' reports and the
  scratchpad documents.
