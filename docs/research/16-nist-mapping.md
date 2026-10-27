# Vaigil — the NIST alignment map

Date: 2026-10-25. Repo state: `main` @ 2751fac. Scope: what Vaigil must implement, what it
already does (verified in code, `file:line`), and the gap — control by control, plus the
machine-readable mapping format, a "NIST mode" design, and the where-we-exceed column.
Sources: the codebase; the OSCAL catalog of SP 800-53 Rev 5.2.0 and the Rev 5.2.0 baselines
(`/home/rashik/vaigil-research/sources/nist/`); the master report (§4.7); fresh web research
(measured 2026-10-25, URLs in §8).

Corrections carried forward from the master report, kept here so they stop being repeated:
the adversarial-ML taxonomy is **NIST AI 100-2e2025** (final, March 2025) — not SP 800-226,
which is differential privacy; there is no "NIST AI 100-8"; **SP 800-53r5 is current, with
the Release 5.2.0 update (Aug 2025)**; the NIST agentic-AI RMF overlay is still
RFI/concept-stage (CAISI's AI Agent Standards Initiative, Feb 2026); CISA's five-eyes
*Careful Adoption of Agentic AI Services* (May 2026) names **"obscure event records"** as a
core risk.

---

## 1. Executive summary

- **Vaigil is already an unusually literal implementation of the AU, AC-5, IA-2 and SC-13
  families.** The audit package is written against the AU control text field-by-field
  (`internal/audit/audit.go` labels every field `AU-3(a)`…`AU-3(f)`); settings carry the
  exact SP 800-53 organisation-defined parameters by OSCAL id (`ac-07_odp.01`,
  `internal/config/settings.go:41`); four packages cite 800-53 controls in their doc
  comments. Alignment here is not retrofit — it is the design.
- **The two things a NIST story needs that Vaigil lacks are (1) agent identity (IA-9) and
  (2) evidence retrieval per control (CA-2/CA-7).** Both are buildable on what exists: the
  audit `Kind` already separates `ai` from `human` and `service`
  (`audit.go:80-97`), and the RFC 6962 log already proves inclusion and consistency
  (`internal/audit/merkle.go:30-32`), so per-control evidence queries are a query layer
  over a signed log, not new infrastructure.
- **A machine-readable mapping file should ship in-repo and tag every detection, playbook,
  SOAR action and audit event** with 800-53 IDs × CSF 2.0 category × AI RMF function ×
  AI 600-1 risk category × OWASP Agentic Top-10 ID × MITRE ATLAS technique (§4). Detections
  already carry ATT&CK IDs; this extends rather than replaces.
- **"NIST mode" (§5) = stricter defaults + evidence packs generated from the signed chain +
  a CSF 2.0 / AI RMF dashboard.** The differentiator is that the evidence is a Merkle
  inclusion proof with two signatures over it — not a checkbox.
- **Vaigil exceeds NIST minimums in three places worth marketing (§6):** dual
  Ed25519+ML-DSA-65 (FIPS 204) signed tree heads; RFC 6962 inclusion/consistency proofs so
  an auditor verifies one decision without seeing the log; OpenTimestamps anchoring that
  outlives any certificate authority. AU-9 asks for "protection"; Vaigil ships provable
  append-onlyness.
- **The single highest-leverage gap for the agent vision:** `cmd/vaigil/selfwatch.go:73-75`
  still skips `audit.KindAI`, so Vaigil's own MCP audit records (tool, operation,
  principal, model, outcome — exactly what the CISA guide says agents obscure) never reach
  detection. One line, then the pipeline exists.
- **October 2026 status in one line each:** 800-53r5.2 current (catalog last-modified
  2026-10-22); 800-63-4 final Aug 2025; 800-61r3 final Apr 2025 (CSF-2.0-structured);
  800-92r1 still draft; 800-218A final Jul 2024; BOD 26-04 (Jun 2026) replaced BOD 22-01
  with the four-factor model; COSAiS overlays draft-stage (and renamed COSIS on
  2026-10-20 — see §2.6).

---

## 2. Framework inventory, October 2026 status

Everything below verified 2026-10-25. (→ = what it means for Vaigil.)

### 2.1 The control catalog and baselines

| Document | Status (Oct 2026) | Note for Vaigil |
|---|---|---|
| **SP 800-53 Rev 5** | Current. **Release 5.2.0** published Aug 26–27 2025; outcome-based wording, software-supply-chain alignment (EO 14306), new **SA-15(13) Logging Syntax** enhancement, SI-7(12) revised. OSCAL catalog in-repo, last-modified 2026-10-22. | SA-15(13) is literally Vaigil's event-shape design (one OCSF-inspired schema for 18 sources). Cite it. |
| **SP 800-53B Rev 5.2.0** baselines | Low 149 / **Moderate 287** / High 370 controls (parsed from in-repo OSCAL). | Moderate is the claim to target: it includes AC-2(2)/(3), AC-5, AC-6(9), AC-12, IA-2(1)/(2), AU-3(1), IR-4(1), SI-4(2); it excludes AU-10, IA-9, SI-19, AC-2(12) (those are Low-selected/high or not baselined) — see §3 membership column. |
| **NIST CSF 2.0** (CSWP 29) | Final Feb 26 2024. 6 functions (GV/ID/PR/DE/RS/RC), 22 categories, 106 subcategories. | The dashboard (§5) and mapping file (§4) use function+category. |

### 2.2 Operational guides

| Document | Status | Note |
|---|---|---|
| **SP 800-61r3** (incident response) | **Final Apr 3 2025.** Organised by CSF 2.0 functions, not the old four phases. | Vaigil's cases/clocks/playbooks are the Respond function; the clock list (`incident/duty.go`) is RS.CO made executable. |
| **SP 800-92r1** (log management planning) | **Draft only** (initial public draft 2023); original 800-92 (2007) still the final word. | Do not cite 92r1 as final. The 2007 guide's core ask — centralised, protected, reviewable logs — is what `auditstream` + `logd` implement. |
| **SP 800-150** (threat info sharing) | 2016 original, current; no revision found. | STIX 2.1 indicator ingest + feed exports map here. |
| **SP 800-40r4** (enterprise patching) | Final Apr 2022. **No r5 exists** despite the name floating around. | Vaigil's remediation plan + reminders are the workflow; BOD 26-04 supplies the 2026 prioritisation model. |
| **SP 800-161r1** (+ Upd 1) (C-SCRM) | Final May 2024; Update 1 (late 2024) adds AI-specific supply-chain considerations. | SBOM/OSV/reachability + the planned AI-BOM and content-plane signing live here. |
| **CISA BOD 26-04** | **Jun 10 2026.** Supersedes BOD 22-01 *and* BOD 19-02. Four factors — exposure, KEV, automation, impact; 3-day clock for exposed+KEV; CVSS demoted as a scheduling signal. | Vaigil ranks with KEV+EPSS and decides with SSVC — one factor (automation) and the exposure join are the missing pieces (RA-5 row). |

### 2.3 Identity, crypto, and architecture

| Document | Status | Note |
|---|---|---|
| **FIPS 140-3** | Current (annexes/IG updated periodically). | The Go stdlib's `crypto/mldsa` degrades under GOFIPS140 builds; Vaigil handles that honestly (`audit/sign.go:156-169`). |
| **FIPS 203 / 204 / 205** (ML-KEM / ML-DSA / SLH-DSA) | Final Aug 13 2024. ML-DSA-65 = NIST security category 3. | **Vaigil already signs audit heads with ML-DSA-65** (`audit/sign.go:152,264-297`) — the "exceeds" column, §6. |
| **SP 800-208** (hash-based signatures) | Final Oct 2020. | Future option for long-lived head signing; not needed now. |
| **SP 800-57** (key management) | Part 1 Rev 5 current. | Head-signing seeds: 32-byte seeds, vault-stored (`sign.go:137-152`) — consistent with 800-57 practice. |
| **SP 800-63-4** (digital identity, 4 volumes) | **Final Aug 1 2025**; 63B-4 is the authenticator volume. Vaigil's code already cites "NIST SP 800-63B-4" (README:120-121, `auth.go:788-789`). | Passkey user-verification requirement = AAL2/AAL3 phishing-resistant MFA (IA-2 row). |
| **SP 800-207 / 207A** (zero trust) | 207 final Aug 2020; 207A (cloud-native access control) final 2024. | Per-request authz in `mcp.go:439-445` and role/scope model are the ZTA shape; document as such. |
| **SP 800-204 series** (ZT cloud-native) | Current. | Design vocabulary for the console/agents boundary. |
| **SP 800-228** (distributed ledger security/privacy) | Final Oct 2022. | Directly governs the anchoring design — `internal/anchor` already argues the EDPB/commitment-only pattern (§6). |

### 2.4 AI-specific NIST instruments

| Document | Status | Note |
|---|---|---|
| **AI RMF 1.0** (AI 100-1) | Final Jan 2023. 4 functions (Govern/Map/Measure/Manage), 17 categories (GV-1..7, MP-1..5, ME-1..5, MG-1..4), 72 subcategories. | The second dashboard axis (§5). |
| **AI 600-1** (Generative AI Profile) | Final Jul 2024. 12 risk categories; the ones that matter to agent monitoring: **Information Security** and **Human-AI Configuration**. | Tag detections/actions with the risk category, not invented action codes. |
| **AI 100-2e2025** (adversarial ML taxonomy) | **Final Mar 24 2025.** | The correct citation for prompt-injection/poisoning taxonomy (NOT 800-226). Maps ATLAS/OWASP tags to NIST vocabulary. |
| **AI 800-1** (dual-use foundation-model misuse) | Second public draft stage as of early 2026. | Watch; relevant to the content plane (AI-drafted detections). |
| **COSAiS overlays → renamed "COSIS"** | Concept paper Aug 14 2025; Predictive-AI overlay annotated outline Jan 8 2026 (workshop Jan 14, comments Feb 13 2026); Generative/assistant and **agent** overlays planned, none drafted. **Per the CSRC project page, renamed Oct 20 2026 to "Control Overlays for Super Intelligence Systems" following the Sept 29 2026 Executive Order** replacing "AI" terminology. No final overlays exist. | Vaigil should track the agent overlay and be ready to import it as a config profile the day it lands — being first with a machine-readable implementation of a NIST overlay is cheap differentiation. |

### 2.5 The agentic-AI standards front (the vision's regulatory context)

- **CAISI AI Agent Standards Initiative** — launched **Feb 17 2026** (nist.gov). Interoperable,
  secure agent adoption; industry-led standards; RFI-stage. There is **no NIST agentic AI-RMF
  overlay yet** — anything claiming one is pre-draft.
- **NCCoE concept paper** *"Accelerating the Adoption of Software and AI Agent Identity"*
  (Feb 5 2026) — proposes demonstrating identity standards for software/AI agents. This is
  the WIMSE-direction signal: **agent identity is becoming an IA-9 problem**, and Vaigil's
  agent registry design (§3, IA-9 row) should match its vocabulary (workload identity,
  delegation chains, `on_behalf_of`).
- **CISA et al., *Careful Adoption of Agentic AI Services*** — May 1 2026, joint with NSA,
  ASD/ACSC, CCCS, NCSC-UK, NCSC-NZ. Five risk categories, ~100 recommendations; treats
  agents as an IAM problem; names **"obscure event records"** (agents generating telemetry
  nobody can audit) among core risks and asks for logs covering agent-to-agent handoffs.
  Vaigil's answer is the entire §3 AU column plus the SCITT-shaped receipts plan.

### 2.6 Numbering hygiene (things that are easy to get wrong)

- 800-53 is **Rev 5, Release 5.2.0** — not "Rev 6", not "r5.3".
- Adversarial ML = **AI 100-2e2025**. **800-226 is differential privacy** (draft). There is
  **no AI 100-8**.
- 800-92**r1 is a draft**; 800-40**r5 does not exist**; 800-61**r3 is final**.
- COSAiS → **COSIS** rename (Oct 20 2026) is fresh; older references will disagree.

---

## 3. The mapping table

Legend: **Mod** = in the 800-53B Moderate baseline (287 controls). "Already does" cites are
verified `file:line` at 2751fac. Effort: S ≤ days, M ≤ a release, L > a release.

### AC — Access Control

| Control (Mod?) | MUST implement (as a product) | Already does | GAP |
|---|---|---|---|
| **AC-2** Account management (Mod) | Account lifecycle: create/enable/disable/review; role/group membership criteria; notifications. | Roles ladder + jobs (`viewer/analyst/responder/admin`, `engineer/vuln-manager/auditor` with self-expiring grants) — README:99-118; bindings readable via `vaigil auth roles`; access reviews closed by next import (README:53); token issuance capped by issuer's role (`auth.go:861-866` — "token creation becomes a privilege-escalation path"). | Reviews exist but produce no **AC-2 review evidence pack** (who had what when, signed). Effort S. |
| **AC-2(2)** Temporary/emergency accounts (Mod) | Automated expiry of temporary/emergency accounts. | Auditor job grants end by themselves (README:113-115); time-boxed tokens; AcceptedRisk max 90 days (`config/config.go:80-98`). | No distinct **emergency-account class** with auto-disable at event close. Fold into agent kill-switch work. Effort S. |
| **AC-2(3)** Disable accounts (Mod) — *the agent kill switch* | Disable within a defined time period for departure, risk, inactivity; **for agents: immediate revocation on detection**. | SSF/CAEP machinery **receives** `session-revoked`, `credential-change`, `assurance-level-change` (`ssf/ssf.go:57-65`) and maps them to detections; Okta action catalogue can suspend/end-sessions on another platform (dual-control, README:126-127). | **No transmit-side CAEP / generic kill switch as a first-class SOAR action** — the two catalogue actions are Okta-only; no "revoke agent sessions" action exists. Effort M. This is the flagship gap. |
| **AC-2(5)** Inactivity logout (Mod) | Org-defined inactivity logout. | `session.idle` = org parameter, cited as **ac-02.05_odp** in code (`admin/idle.go:12`); hard cap **15 min privileged idle** (`auth.go:791`), 12 h MaxSessionTTL (`auth.go:785`), 60 min federated (`auth.go:1232`); idle detection includes keystrokes so it doesn't log out people mid-work (`admin/idle.go:12-20`). | None material. Note: code already treats this as an ODP. |
| **AC-2(12)** Atypical usage monitoring (not Mod) | Monitor accounts for atypical usage. | Impossible-travel judge with VPN exclusions and honest history notes (`internal/travel`); lockout by familiar-place table (`lockout/lockout.go:44-52`); UEBA-lite `internal/baseline` (hunt-CLI only). | Baselines not wired into detection; no per-agent baselines yet. Effort S to wire, M for agents. |
| **AC-3** Access enforcement (Mod) | Approved authorisations enforced. | `Authorise func(Operation)` consulted before **every** MCP operation (`mcp/mcp.go:167,439-445`); per-op role gates (`cmd/vaigil/mcpsecurity.go:45-314`, `NeedsRole` viewer/analyst); scopes narrow tokens to read-only (`auth.go` IssueScoped); DPoP package for sender-bound tokens (`internal/dpop`). | Per-agent allowlists (which *agent* may call which op) absent — see IA-9. |
| **AC-4** Information flow enforcement (Mod) | Enforce approved flows; **for agents: untrusted-read → sensitive-read → egress control**. | The AI analyst pipeline is a flow-control design: fixed plan in code, counts separated from quoted text, closed-set output (README:61-72); privacy guard masks PII/credentials before model calls and strips invisible characters (README:71-72, `internal/pii`, `internal/secret`); connectors are read-only by design (`incident/playbook.go:18-22`). | No general **taint/label mechanism for agent tool chains** (toxic-flow correlation is master-report §4.3 planned work). Effort M. |
| **AC-5** Separation of duties (Mod) | Separate duties of individuals; dual authorisation. | Whole package: `internal/dual` — grant/token/setting-weakening/auditlog-move need a second admin, doc-cites **AC-5, CM-5(4), AU-9(5)** (`dual/dual.go:5-6,38-49`); actions on other platforms: asked by one, approved by another (`action/action.go:168,217`); **rule author cannot approve their automation's runs** (`automate/automate.go:718-724`); playbook runs proposed→approved→worked (`incident/playbook.go:29-31`). | Dual-control scope is fixed in code (good); NIST mode should widen it to vuln risk-acceptance and content-pack promotion (§5). Effort S. |
| **AC-6 / AC-6(2) / AC-6(9)** Least privilege (Mod) | Least privilege; non-privileged use for non-security functions; **log use of privileged functions**. | Role ladder + jobs separate watching/deciding/acting/administering (README:99-118); AI can only *propose* — `internal/finding refuses a decision from an AI actor` (`finding/decision.go:55`, `mcpsecurity.go:36`); admin actions audited with actor+role (`caller.go:149`); every privileged change lands in the chain. | Agents have no least-privilege *per-tool* model (allowlist per agent principal). Effort M (with IA-9). |
| **AC-7** Unsuccessful logons (Mod) | Limit attempts; lock on threshold. | Threshold 10 / 30-min lock / 100-attempt ceiling (`lockout/lockout.go:38-45`, ODPs cited: `ac-07_odp.01/.03/.05`, `settings.go:41-84`); **locks the place, not the person** — no account-denial weapon (README:123-124). | None. Exceeds typical implementations (place-based lockout is kinder and DoS-resistant). |
| **AC-12** Session termination (Mod) | Terminate after org-defined conditions. | Idle + absolute caps + sign-out revocation; ended sessions answer "that session ended" for a day, not "no such token" (`auth.go:855-858,924`). | None material. |

### AT — Awareness and Training (the "agent training" governance reading)

| Control (Mod?) | MUST | Already does | GAP |
|---|---|---|---|
| **AT-2/AT-3/AT-4** (Mod) | Literacy, role-based training, **training records**. | For **agents**, the analogous artefact half-exists: automation rules carry owner+reason with expiry (`detect/tuning.go` suppressions ≤90 days); playbook steps require evidence notes; the AI analyst's "training" is the fixed plan + fixture corpus, reviewable in-repo. | No first-class **agent capability manifest** (declared purpose, allowed tools, owner, review date) that AT-style governance can key on — and no human training records (arguably out of product scope; the manifest is not). Effort M with IA-9. |

### AU — Audit and Accountability (the spine)

| Control (Mod?) | MUST | Already does | GAP |
|---|---|---|---|
| **AU-2** Event logging (Mod) | Log the right events, review the list. | The audit package is *built against the AU family* (`audit/audit.go:4`); `Kind` separation human/service/**ai** labelled `AU-3(f)` (`audit.go:75-97`); MCP calls audited per-operation with model + outcome (`audit.go:152`). | **AU-2(3) review**: the logged-event list is code-fixed, never re-reviewed against the estate; no documented periodic review. Effort S (docs + evidence query). |
| **AU-3 / AU-3(1)** Content of audit records (Mod) | Date/time, action, resource, source, outcome, **identity; additional info (1)**. | Every field is labelled in code: `At AU-3(b)`, `Action AU-3(a)`, `Resource AU-3(c)`, `Source AU-3(d)`, `Outcome AU-3(e)` (Success/Failure/**Denied kept apart**), `Principal AU-3(f) pseudonymised`, `Verified` distinguishes proved vs asserted identity (`audit/audit.go:118-153`); `Detail` carries extra results; `Model` present when `Kind==ai`. | For agent actions specifically: no **tool args hash / decision citation** fields yet (planned receipts). Effort S–M. |
| **AU-4(1) / AU-9 / AU-9(2)** Protection & transfer (Mod; (1)/(2) not) | Protect the log from modification/deletion; transfer to alternate storage. | Hash chain (`Prev`, `audit.go:129-130`); **RFC 6962 Merkle tree with inclusion + consistency proofs** (`audit/merkle.go:30-32,192`; `translog/translog.go:1-30`); **logd runs the writer as another account so the console cannot rewrite the log** (`logd/logd.go:1-25`); **SIEM push stream** with signed tree head + RFC 9421 message signatures + RFC 9530 content digests, doc-cites **AU-4(1), AU-9(2)** (`auditstream/stream.go:5-24`); auditlog *moves* require dual control (`dual/dual.go:48`). | None — this row is why Vaigil can claim evidence-grade. |
| **AU-9(5)** Dual authorization (not Mod) | Dual authorisation to modify/delete audit info. | Exactly the `dual` AuditLog kind (`dual/dual.go:47-48,69-72`). | None. |
| **AU-10** Non-repudiation (not baselined) | Prove who did it. | Signed tree heads (two algorithms); finding decisions are an append-only fold with signatures referenced (`finding/decision.go:27`); `Verified` flag keeps asserted vs proved identity honest (`audit.go:141-152`). | Decisions inside a batch are covered by the head, not individually signed; fine cryptographically, worth documenting for auditors. Effort S (docs). |
| **AU-11** Retention (Mod) | Org-defined retention. | Sessions pruned after 24 h (`auth.go:924`); audit log itself **append-only forever** with day-rolled segments (64 MiB, SHA-256-sealed). | **No configurable retention policy or floors** (e.g. "keep 400 days, then export-then-delete"), and no legal-hold marker. NIST mode needs AU-11 floors (§5). Effort S–M. |
| **AU-12 / AU-12(1)** Generation, system-wide correlated trail (Mod) | Generate for all users; time-correlated trail. | Every code path writes through the audit writer; `logd` + stream cover the "system-wide" reading; OCSF export orders events across sources (README:49, 147-150). | Correlation is by event time; no single clock-authority statement (NTP config doc). Effort S (docs). |
| **AU-5** Response to audit failures (Mod) | Alert on audit failure. | Failure of the log writer is treated distinctly: agents stopped, humans warned — code-cites **SP 800-53 AU-5** (`cmd/vaigil/auditlog.go:189-245`). | None found. |

### CA — Assessment and Continuous Monitoring

| Control (Mod?) | MUST | Already does | GAP |
|---|---|---|---|
| **CA-2** Control assessments (Mod) | Periodically assess controls. | Meta-tests enforce README claims match artifacts (`docs_claims_test.go`, `wired_test.go`); detection rules *prove themselves* against fixtures and trial-ring statistics (see SI-4). | No assessment evidence output per control (the §5 evidence queries are this). Effort S once queries exist. |
| **CA-7 / CA-7(4)** Continuous monitoring (Mod) | Ongoing monitoring, **risk monitoring (4)**. | The product *is* continuous monitoring: scheduled detection runs, connector refresh, KEV/EPSS re-ranking, estate risk rebuild, upkeep package; Today screen = state dashboard. | No **framework roll-up** (CSF/AI RMF percentages) and no monitoring-plan document; CA-7(4) risk monitoring exists in substance (risk acceptance expiry, suppression expiry) without the label. Effort S (§5). |

### IA — Identification and Authentication

| Control (Mod?) | MUST | Already does | GAP |
|---|---|---|---|
| **IA-2 / IA-2(1) / IA-2(2)** (Mod) | MFA for privileged and non-privileged. | **Passkeys with mandatory user verification — no setting turns it off** (`webauthn/webauthn.go:62-66`, refusal `:355` + `ErrUserNotVerified :83-88`); SSO must assert two factors, ACR values forwarded (`oidc/provider.go:442-444,512-513`); AAL computed from methods (`auth.go:713-735`); code cites **800-63B-4** AAL3 inactivity limit for the 15-min admin idle (`auth.go:787-791`). | None for humans. This row exceeds typical products. |
| **IA-5 / IA-5(1)** (Mod) | Authenticator management. | No passwords at all; tokens are 256-bit CSPRNG, single SHA-256 storage with the argument for why no KDF is needed (`auth.go:819-833`); vault = AES-256-GCM per **SP 800-38D** (`vault/vault.go:74-77`); passkey attestation recorded at registration (`webauthn/attestation.go`). | None material. |
| **IA-9** Service identification (not Mod) — *agents as non-human identity* | Unique identification of services/agents; mutual auth. | `KindService` vs `KindAI` vs `KindHuman` in every audit record (`audit.go:80-97`) — the *ledger* side exists; MCP tokens scoped and sender-bound (DPoP available); AI actors distinguished in OCSF export (README:125-127). | **No agent registry** (id, owner, allowed tools, issuance record, delegation chain `on_behalf_of`). The NCCoE Feb 2026 concept paper is exactly this; Vaigil should implement the WIMSE-direction shape. Effort M — see digest. |

### IR — Incident Response

| Control (Mod?) | MUST | Already does | GAP |
|---|---|---|---|
| **IR-4 / IR-4(1)** (Mod) | Handle incidents; **automated processes (1)**. | Cases/incidents with status, notes, replays; playbook checklists with dependencies, evidence notes, undo text, full attribution (`incident/playbook.go:16-37`); automations watch/ask/act with hourly limits and author-cannot-approve. | Playbooks don't **execute** (by design so far); IR-4(1) is honest to claim only for automations + the two Okta actions. Executable DAG is master-report §4.4. Effort L. |
| **IR-6** Reporting (Mod) | Report to org-defined parties in time. | The clock table is the control: GDPR 72 h (and immediate data-subject notice), NIS2 24 h/72 h/30 d, DORA 4 h, SEC 4 business days, HIPAA 60 days, CIRCIA — each keyed to the decision that starts it (`incident/duty.go:40-120`). | No machine-readable *export* of clock state for a regulator (evidence query solves it). Effort S. |
| **IR-8** IR plan (Mod) | Documented plan with structure. | Playbooks + duty table + notification addresses are the executable plan. | No narrative IR-plan template the org fills (docs gap). Effort S (docs). |

### RA — Risk Assessment and Vulnerability Management

| Control (Mod?) | MUST | Already does | GAP |
|---|---|---|---|
| **RA-3** Risk assessment (Mod) | Periodic risk assessment. | Estate risk build, workforce risk, vendor risk, device risk from the org's own tools (README:53; `internal/estate`, `internal/vendor`, `internal/workforce`). | Findings/vuln risk is not folded into one estate-level risk statement with trend. Effort M. |
| **RA-5 / RA-5(1)** (Mod) | Scan, monitor, **update tool capability (1)**. | SBOM ingest (CycloneDX+SPDX) → OSV matching with fix-path analysis (`internal/sca`); KEV and EPSS-weighted ranking with **explained terms** (`vuln/advisory.go:14,108-110,28`); SSVC decisions from CERT/CC CSV (`vuln/ssvc.go:15`); OpenVEX publication (`vuln/plan.go:304-352`, five justifications fixed `vuln/vex.go:68`); **first-party Go reachability via go/parser** (`internal/reach`); SARIF ingest (`internal/sarif`). | **Scans nothing first-party** (lockfiles, secrets, `.mcp.json`, model files — master-report §4.5); no **BOD 26-04 automation-factor** or exposure join in the composite ranking; no dynamic clock recompute. Effort M for scanner+model. |
| **RA-7** Risk response (Mod) | Take action on risk. | Risk acceptance with reason, owner, **90-day expiry** (`config/config.go:80-98`); SSVC decision → OpenVEX statement = the recorded response; reminders to owners. | Acceptance decisions aren't yet tied to the signed evidence of what was known when (evidence queries fix). Effort S. |

### SA — System and Services Acquisition / Supply Chain

| Control (Mod?) | MUST | Already does | GAP |
|---|---|---|---|
| **SA-9 / SA-9(1)** (Mod) | External services risk-assessed and approved. | Vendor risk from the org's own tools (README:53); connectors' credentials vaulted, read-only; per-connector approval implied by admin role. | No **AI-service register** (which LLM endpoints, which model versions, approved by whom) — needed for agents and for the AI RMF Map function. Effort S–M. |
| **SA-11 + SP 800-218/218A** (Mod) | Developer testing; SSDF for GenAI. | Detection-as-code with **mandatory fixtures that must match and must not** (`detect/rule.go:45-47,142-151,194`); trial ring with Wilson-bounded precision and a 10-verdict floor before a rule goes live (`detect/tuning.go:34,60-63,397-403`); 1,432 test functions incl. meta-tests; **zero third-party dependencies** (the cleanest SBOM in the industry — go.mod proves it); release binaries with build provenance (README:154-157). | No **AI-BOM** (CycloneDX 1.7 ML-BOM) for the models/agents Vaigil itself uses or monitors; content plane (signed packs, master-report §4.8) is the missing in-toto/TUF-shaped piece. Effort M. |
| **SA-15(13) Logging syntax** (5.2.0) | Common logging syntax. | One OCSF-inspired event shape for 18 sources (`internal/source`, `internal/telemetry`, README:91-97). | This is a cite-it row: the newest control in 800-53 is Vaigil's ingest design. None. |

### SC — System and Communications Protection

| Control (Mod?) | MUST | Already does | GAP |
|---|---|---|---|
| **SC-8 / SC-8(1)** (Mod) | Transmission confidentiality/integrity; crypto-protected. | Outbound audit stream: TLS receiver URL + **RFC 9421 HTTP message signatures over RFC 9530 digests** (`auditstream/stream.go:14-24`); deploy/ ships Caddy TLS config; HTTPS webhooks signature-verified. | No **built-in TLS** for the console (reverse proxy required; `admin.behind_tls_proxy`, `settings.go:203`). Standalone deployments default to localhost HTTP. Effort S to document loudly; M for built-in TLS. |
| **SC-13 / SC-28** (Mod) | Cryptographic protection; at-rest protection. | Ed25519 + **ML-DSA-65 (FIPS 204)** double-signed heads (`audit/sign.go:152,264-297`); AES-256-GCM vault per 800-38D (`vault/vault.go:74-77`); SHA-256-sealed segments; domain separation everywhere (`sign.go:68,374-385`). | None. Exceeds (§6). |

### SI — System and Information Integrity

| Control (Mod?) | MUST | Already does | GAP |
|---|---|---|---|
| **SI-2** Flaw remediation (Mod) | Patch in time. | Vulnerability plan with BOD-relevant ranking, reminders, fix-path analysis (RA-5 row). | No enforced clock tracking against **BOD 26-04** dynamic deadlines. Effort S–M. |
| **SI-3** Malicious code protection (Mod) | Detect/act on malicious code. | Fixture discipline + self-watch detections (`detect/pack`, 28 rules incl. 6 self-watch); secrets/PII pattern machinery (`internal/secret`, `internal/pii`) used for masking; indicator matching from STIX/lists (README:50). | No first-party scanning of artifacts for malicious content (pickle/Pickle opcode scan, model-file validation — master-report §4.5.3). Effort M. |
| **SI-4 / SI-4(2)** (Mod) | System monitoring; **real-time analysis (2)**. | Detection engine with predicate-tree rules, correlations, suppressions that end, trial ring (above); hunt; **automations already act synchronously on sign-ins** (`automate`, 5 event kinds). | Evaluation is **batch**, not streaming (SI-4(2) "real-time" claim must be honest: minutes, not seconds); **`selfwatch.go:73-75` skips `audit.KindAI`** so agent activity inside Vaigil is not detected. Effort S (unskip) / M (streaming). |
| **SI-7** Software/firmware integrity (Mod) | Integrity checks. | Hash chain + Merkle + signatures on the log; signed statements for exported packages (`audit/sign.go:391-430`); build provenance for releases. | Content packs (detections from outside) not yet signature-verified — the content plane. Effort M. |
| **SI-19** De-identification (not Mod) | Remove identifying info. | Principals pseudonymised in the audit log (`audit.go:132`); ended sessions stored as 16-hex fingerprints, never secrets (`auth.go:852-858`); masking before model calls; anchoring keeps **only commitments** on-chain per EDPB guidance (`anchor/anchor.go:19-26`). | Prompts/content opt-in is designed but agent telemetry defaults not yet written down as a de-identification policy. Effort S (docs). |

### AI RMF functions (Govern / Map / Measure / Manage) — the agent-monitoring column

| Function | What it asks | Vaigil already | Gap |
|---|---|---|---|
| **Govern (GV)** | Accountability structures, policies, oversight. | Dual control, roles, auditor job, signed decisions, README as plain-language policy. | Agent **ownership** (every agent principal maps to an accountable human) needs the registry. Effort M. |
| **Map (MP)** | Context, intended purpose, risk. | Estate inventory; connectors; vuln exposure; SSVC decision context. | **Agent inventory + declared purpose** (manifest) — the AI-600-1 "Human-AI Configuration" category. Effort M. |
| **Measure (ME)** | Track metrics. | Wilson-bounded precision, trial-ring stats, detection_stats MCP op, queue metrics. | Agent-behaviour metrics (tool mix, drift-from-declared-purpose) don't exist yet — no telemetry. Effort M (after ingest). |
| **Manage (MG)** | Prioritise/mitigate/respond. | Automations with limits, playbook runs, kill-path via Okta actions. | CAEP transmit + agent containment actions. Effort M. |

---

## 4. The machine-readable mapping file

### 4.1 Design

One file class, `*.mapping.json`, shipped in-repo (and later inside signed content packs),
validated by a `mapping` package (stdlib JSON + tests). Rules:

1. **Everything actionable is tagged**: detection rules, playbook templates, SOAR action
   catalogue entries, and audit event *kinds* (the join from `Action` strings to controls).
2. IDs are **arrays**, never a single value — one detection genuinely serves several
   controls (that is the point of the map).
3. **Empty is legal, absent is not**: `"controls": []` means "considered, none apply";
   omitting the key fails validation. This is the difference between a map and decoration.
4. Every entry carries an `evidence` object: a **query** (see §5) that returns the signed
   records demonstrating the control operating, so the mapping is checkable against the
   chain, not asserted.
5. Tag vocabulary is closed and versioned at the top of the file; unknown IDs fail load
   (typo protection, same philosophy as fixture-refusal).
6. `until` on any entry: mappings go stale when a control revision lands; an expired
   mapping is a loud warning, not silence.

### 4.2 Schema

```json
{
  "$schema": "https://vaigil.github.io/schema/mapping-v1.json",
  "schema": "vaigil/mapping/v1",
  "generated": "2026-10-25T00:00:00Z",
  "catalogs": {
    "nist-sp-800-53": "5.2.0",
    "nist-csf": "2.0",
    "nist-ai-rmf": "1.0",
    "nist-ai-600-1": "1.0",
    "owasp-agentic": "2026",
    "mitre-atlas": "2026-10",
    "mitre-attack": "16"
  },
  "entries": [
    {
      "id": "detect.impossible-travel",
      "kind": "detection",
      "title": "Sign-in from two places too far apart",
      "nist": {
        "controls": ["AC-2(12)", "AC-7", "AU-12", "SI-4", "SI-4(2)"],
        "csf": ["DE.AE", "DE.CM", "RS.AN"],
        "ai_rmf": [],
        "ai_600_1": []
      },
      "owasp_agentic": [],
      "atlas": [],
      "attack": ["T1078"],
      "evidence": {
        "query": "audit:action=sign-in outcome=failure window=90d",
        "proves": "AC-7 threshold and lockout decisions, signed in the chain"
      }
    }
  ]
}
```

Field semantics (validated):

- `kind`: `detection | playbook | soar-action | audit-event | setting | feed`.
- `nist.controls`: SP 800-53 IDs in the catalog's own form (`AC-2(12)`, `SA-15(13)`),
  checkable against the OSCAL catalog shipped in-repo — a meta-test fails on any ID the
  catalog does not contain, same trick as `docs_claims_test.go`.
- `nist.csf`: CSF 2.0 `FUNCTION.CATEGORY` codes (e.g. `PR.AA`, `DE.CM`, `GV.SC`).
- `nist.ai_rmf`: `GV-…|MP-…|ME-…|MG-…` categories (AI RMF 1.0).
- `nist.ai_600_1`: named risk categories from the Generative AI Profile — for agent
  monitoring chiefly **Information Security** and **Human-AI Configuration**.
- `owasp_agentic`: OWASP Top 10 for Agentic Applications 2026 IDs (`ASI01` Agent Goal
  Hijack, `ASI02` Tool Misuse and Exploitation, `ASI03` Identity and Privilege Abuse, …).
- `atlas`: MITRE ATLAS technique IDs (AML.T…), used when the detection is genuinely
  adversarial-ML; empty otherwise. `attack`: classic ATT&CK (already carried by rules —
  this file joins, not duplicates).

### 4.3 Three fully-worked examples

**Detection — MCP tool call outside the agent's declared allowlist** (planned rule, shown
with its full intended tagging; exists-after registry):

```json
{
  "id": "detect.agent.tool-outside-allowlist",
  "kind": "detection",
  "title": "Agent called an MCP operation outside its registered allowlist",
  "nist": {
    "controls": ["AC-3", "AC-4", "AC-6", "AU-12", "IA-9", "SI-4"],
    "csf": ["DE.CM", "PR.AA", "GV.RR"],
    "ai_rmf": ["GV-4", "ME-3", "MG-3"],
    "ai_600_1": ["Information Security", "Human-AI Configuration"]
  },
  "owasp_agentic": ["ASI03", "ASI02"],
  "atlas": ["AML.T0051"],
  "attack": ["T1218"],
  "evidence": {
    "query": "audit:kind=ai action=mcp resource=~propose outcome=denied window=30d",
    "proves": "per-agent authorisation enforced and logged, with signed tree head"
  },
  "until": ""
}
```

**Playbook — account compromise:**

```json
{
  "id": "playbook.account-compromise",
  "kind": "playbook",
  "title": "Account compromise response",
  "nist": {
    "controls": ["IR-4", "IR-4(1)", "IR-6", "IR-8", "AC-2(3)", "AU-6", "SI-4"],
    "csf": ["RS.MA", "RS.MI", "RS.CO", "DE.AE"],
    "ai_rmf": ["MG-3"],
    "ai_600_1": ["Information Security"]
  },
  "owasp_agentic": [],
  "atlas": [],
  "attack": ["T1078", "T1531"],
  "evidence": {
    "query": "playbook:runs of account-compromise with approvals and step evidence, 90d",
    "proves": "maker-checker response executed per IR-4(1), each run in the chain"
  },
  "until": ""
}
```

**SOAR action — suspend Okta account:**

```json
{
  "id": "action.okta.suspend",
  "kind": "soar-action",
  "title": "Suspend an Okta account (asked by one, approved by another)",
  "nist": {
    "controls": ["AC-2(3)", "AC-5", "AC-6(9)", "IR-4", "IR-4(1)"],
    "csf": ["RS.MI", "PR.AA"],
    "ai_rmf": ["MG-3"],
    "ai_600_1": ["Information Security"]
  },
  "owasp_agentic": ["ASI03"],
  "atlas": [],
  "attack": [],
  "evidence": {
    "query": "audit:action=action.request action=action.approve resource=okta.suspend 90d",
    "proves": "every account disable is dual-controlled and signed by two principals"
  },
  "until": ""
}
```

Bootstrapping: a `vaigil mapping export` command emits the skeleton for every existing
detection (28 pack rules), playbook, action and automation kind with `attack` pre-filled
from rules and everything else empty — then humans fill the rest in PRs, and a meta-test
fails on any artifact missing from the file. Roughly 60 entries to hand-tag; S effort.

---

## 5. "NIST mode" — design

One setting, `compliance.profile: nist`, that changes three things. It is **a profile of
defaults, not a different product** — every knob it tightens is an existing org-defined
parameter, now set at or above Moderate-baseline values, with dual control over weakening
them (which already exists, `dual/dual.go:46-48`).

### 5.1 Stricter defaults (all existing ODPs, tightened)

| Setting | Default | NIST mode | Control |
|---|---|---|---|
| `session.idle` | 60 min | 15 min for all roles (today: admins only) | AC-2(5), 800-63B-4 AAL3 |
| `session.max_ttl` | 12 h | 8 h | AC-12 |
| Dual-control scope | grants, admin tokens, setting-weakening, auditlog move | + vuln risk acceptance, content-pack promotion, connector credential rotation | AC-5, AU-9(5) |
| `auditlog.retention` | unlimited | floor set per policy (e.g. 400 days), export-then-delete above it, legal-hold marker | AU-11 |
| `siem.stream.url` | unset | **required** — NIST mode refuses to start without an off-box copy of the audit log | AU-4(1), AU-9(2) |
| `logd` | optional | required (separate-account writer) | AU-9 |
| TLS | localhost/p-proxy | require `admin.behind_tls_proxy` or built-in TLS; refuse plain-HTTP bind | SC-8 |
| Detection ring promotion | 10-verdict floor | same (already stricter than anyone) | CA-7, SI-4 |

Turning NIST mode on is itself a dual-control change and lands in the audit log with both
signatures — the mode is provable from the chain.

### 5.2 Evidence from the chain (the anti-theatre core)

`vaigil compliance evidence --control AC-2(3)` runs a named query over the signed log and
emits a pack: matching records, their Merkle **inclusion proofs** to the latest signed head,
the head's dual signatures, anchor state, and a human summary. Pack is verifiable by a
third party with the published public keys and zero access to the rest of the log (the
`translog` property). Per-control queries to ship first:

- **AC-2(3)**: every emergency disable, who asked, who approved, signatures.
- **AC-5**: every dual-control request with approver ≠ requester (or the recorded
  sole-administrator exception).
- **AC-7**: lockout decisions per place, threshold and ceiling honoured.
- **AU-2/AU-12**: event-kind histogram over the period (proves logging scope).
- **AU-9/AU-10**: chain integrity — head verification + latest anchor, both algorithms.
- **IA-2**: sign-ins by method/AAL; passkey-UV refusals.
- **IR-6**: clock table state export for a given incident (started/remaining/who).
- **RA-5**: KEV/EPSS/SSVC decisions with their inputs and the OpenVEX statement id.
- **SI-4**: detection runs, per-rule verdict counts, trial-ring promotions (proves the
  monitoring actually ran — the thing auditors can never get from commercial SIEMs).

Output formats: JSON (machine), markdown (auditor), OCSF (SIEM). This is the feature no
checkbox-GRC product can copy without first building a provable log.

### 5.3 CSF 2.0 + AI RMF dashboard

The Today screen gains a framework view computed *from the mapping file + the evidence
queries*, not hand-entered:

- Two rows: **CSF 2.0** (GV/ID/PR/DE/RS/RC) and **AI RMF** (GV/MP/ME/MG).
- Per function: percentage of mapped entries for which the evidence query returned at
  least one signed record in the window — i.e. *demonstrated in this deployment*, with a
  count and last-seen time. An entry with a tag but no evidence is amber; a tag whose
  query errors is red.
- Baseline selector (Low/Moderate/High from the in-repo 800-53B OSCAL): shows which
  baseline controls have any mapped implementation at all — the honest FedRAMP-readiness
  number, family by family.
- Drilling a function lists the entries; drilling an entry runs its query.

Percentages are computed, dated, and themselves written to the audit log, so a screenshot
of "DE 92%" carries a chain reference. No self-attestation anywhere.

---

## 6. Where Vaigil exceeds NIST (the marketing column)

1. **Post-quantum-signed evidence.** Audit tree heads are signed **twice** — Ed25519 *and*
   ML-DSA-65 (FIPS 204, category 3), verification requires both, with an explicit,
   recorded FIPS-module degradation path (`audit/sign.go:50-58,152,264-297,305-352`).
   AU-9 asks that audit information be "protected from modification"; Vaigil protects it
   against an adversary that breaks one algorithm entirely — including a future quantum
   one ("harvest now, forge later" is the design rationale written in the file). Almost
   no SIEM signs its audit log at all.
2. **RFC 6962 transparency-log proofs.** Inclusion and consistency proofs mean an auditor,
   insurer or regulator verifies that *one specific decision* is in the log — and that the
   log was never rewritten between two dates — from a handful of hashes, **without seeing
   the rest of the confidential log** (`translog/translog.go:1-30`, `audit/merkle.go`).
   AU-9/AU-10 ask for protection and non-repudiation; Vaigil provides third-party
   verifiability with confidentiality, which the controls never thought to ask for.
3. **Blockchain anchoring that outlives every CA.** Heads are committed to Bitcoin via
   OpenTimestamps, with pending-vs-anchored state reported honestly and only commitments
   (never personal data) on-chain (`internal/anchor`, `cmd/vaigil/auditanchor.go`) —
   consistent with SP 800-228 and the EDPB off-chain pattern (`anchor/anchor.go:19-26`).
   A fifteen-year-old dispute can be settled with a Bitcoin block.
4. **Honest defaults**: passkey user verification that cannot be turned off
   (`webauthn/webauthn.go:62-66`); place-based lockout instead of account lockout;
   `Verified` flag separating proved from asserted identity in every record
   (`audit.go:141-152`); six rules the AI cannot break stated in the README and enforced
   by meta-tests. Most products ship weaker defaults and call them configurable.

One-line version for the website: *NIST asks for audit records you can trust; Vaigil ships
audit records you can prove.*

---

## 7. Gaps ranked by effort

| # | Gap | Controls | Effort | Notes |
|---|---|---|---|---|
| 1 | Stop skipping `audit.KindAI` in self-watch | SI-4, AU-12 | **S** | One line (`selfwatch.go:73-75`) + fixtures; first agent telemetry through an existing signed pipeline. |
| 2 | Ship `*.mapping.json` + validator + meta-test | CA-2, CA-7 | **S** | ~60 hand-tagged entries; bootstrapped by export command (§4). |
| 3 | Retention policy + legal hold + AU-11 floors | AU-11 | **S–M** | Config + export-then-delete in upkeep. |
| 4 | Evidence queries + `compliance evidence` packs | CA-2, CA-7, AU-9 | **S–M** | Query layer over translog; 9 named queries (§5.2). |
| 5 | NIST mode profile (§5) | many | **M** | Mostly wiring existing ODPs; dashboard needs #2+#4. |
| 6 | CAEP transmit + generic kill switch action | AC-2(3), IR-4 | **M** | Receive side exists (`ssf/ssf.go`); action catalogue grows beyond Okta. |
| 7 | Agent registry + per-agent allowlists + delegation chains | IA-9, AC-3, AC-6 | **M** | WIMSE-direction; keys the AT/MP governance story. |
| 8 | BOD 26-04 four-factor model + exposure join + dynamic clocks | RA-5, SI-2 | **M** | Automation factor is new data; exposure from estate. |
| 9 | First-party scanning (lockfiles, secrets, `.mcp.json`, model files) | RA-5, SI-3 | **M** | Master-report §4.5; the differentiator. |
| 10 | Agent telemetry ingest (OpenAI/Anthropic audit logs, OTel GenAI, MCP traffic) | AU-2, AU-12, SI-4 | **M** | Master-report §4.3. |
| 11 | Streaming evaluation on ingest | SI-4(2) | **M–L** | Depends on storage rebuild (master-report §4.1). |
| 12 | Taint/toxic-flow enforcement for agent tool chains | AC-4 | **M–L** | Correlate rules over labeled tools. |
| 13 | Executable playbooks (CACAO-subset DAG) | IR-4(1) | **L** | Keep human gates; master-report §4.4. |
| 14 | AI-BOM + signed content plane | SA-9, SA-11, SI-7 | **M** | CycloneDX 1.7 ML-BOM; TUF-style packs (master-report §4.8). |

Order of attack that tells the best story fastest: 1 → 2 → 4 → 6 (a kill switch you can
*prove* was used, with a receipt) → 7.

---

## 8. Sources

**Local**: OSCAL catalog + Low/Moderate/High baselines of SP 800-53/53B Rev 5.2.0
(`/home/rashik/vaigil-research/sources/nist/{catalog,low,mod,high}.json`; catalog
last-modified 2026-10-22); `53r520.txt`; master report `2026-10-24-master-report.md` §4.7;
codebase at 2751fac (all `file:line` cites above).

**Web (retrieved 2026-10-25)**:

- SP 800-53 r5 upd1 (Release 5.2.0) — https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final ;
  release news — https://csrc.nist.gov/News/2025/nist-releases-revision-to-sp-800-53-controls
- COSAiS/COSIS overlays project — https://csrc.nist.gov/projects/cosais (rename noted
  2026-10-20); Predictive overlay outline —
  https://csrc.nist.gov/csrc/media/Projects/cosais/documents/COSAiS-Predictive-AI-annotated-outline-Jan2026.pdf
- AI Agent Standards Initiative (Feb 17 2026) —
  https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative ;
  NCCoE agent-identity concept paper (Feb 5 2026) —
  https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd
- CISA et al., *Careful Adoption of Agentic AI Services* (May 1 2026) —
  https://www.cisa.gov/resources-tools/resources/careful-adoption-agentic-si-services ;
  PDF — https://media.defense.gov/2026/Apr/30/2003922823/-1/-1/0/CAREFULADOPTIONOFAGENTICAISERVICES_FINAL.PDF
- BOD 26-04 (Jun 10 2026) —
  https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
- SP 800-61r3 (final Apr 2025) — https://csrc.nist.gov/pubs/sp/800/61/r3/final
- SP 800-92r1 (draft) — https://csrc.nist.gov/pubs/sp/800/92/r1/ipd
- SP 800-218A (final Jul 2024) — https://csrc.nist.gov/pubs/sp/800/218/a/final
- SP 800-63-4 (final Aug 1 2025) — https://csrc.nist.gov/pubs/sp/800/63/4/final ;
  63B-4 — https://csrc.nist.gov/pubs/sp/800/63/b/4/final ; supersession note —
  https://pages.nist.gov/800-63-3
- AI 100-2e2025 (final Mar 24 2025) — https://csrc.nist.gov/pubs/ai/100/2/e2025/final
- AI RMF 1.0 — https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf ; AI 600-1 —
  https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- CSF 2.0 — https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP-29.pdf
- SP 800-40r4 — https://csrc.nist.gov/pubs/sp/800/40/r4/final ; SP 800-150 (2016) —
  https://csrc.nist.gov/pubs/sp/800/150/final
- OWASP Top 10 for Agentic Applications 2026 (ASI01 Agent Goal Hijack, ASI02 Tool Misuse,
  ASI03 Identity and Privilege Abuse) — https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026
- FIPS 203/204/205 — https://csrc.nist.gov/pubs/fips/204/final (and siblings);
  FIPS 140-3 — https://csrc.nist.gov/pubs/fips/140-3/final
- SP 800-228 (DLT) — https://csrc.nist.gov/pubs/sp/800/228/final ; SP 800-207 —
  https://csrc.nist.gov/pubs/sp/800/207/final
