# 12 — XDR, EDR, NDR, TIP and identity: what Vaigil builds, integrates, and refuses

October 2026. This report decides the sensor-and-intelligence strategy for the four
domains the vision names — EDR/XDR, NDR, TIP, IAM/PAM — against three constraints
that are not negotiable: **zero third-party dependencies in Go stdlib**, **one
solo developer**, and the **"SOC for AI agents"** differentiator from the master
report (`2026-10-24-master-report.md`, §0.2, §4.3). The method: read what
startups actually run (surveys, DBIR/M-Trends, the installed-vs-used literature),
price the OSS building blocks, and only then decide. Sources are cited inline
(URL or local file) and indexed in §10.

The one-paragraph verdict, before the evidence:

> A 50–200 person company does not have a fleet to sensor, a network to tap, or
> staff to tune any of it. Its real attack surface is the identity provider, the
> SaaS grant graph, the cloud control plane, and — in 2026 — the AI agents
> running with its credentials. Vaigil's answer is: **agentless-first** (IdP,
> SaaS, cloud, MDM logs — mostly already ingested), **one small read-only
> collector** where agentless cannot see (developer endpoints and servers),
> which is the same binary that carries **agent telemetry out-of-process** — the
> flagship no incumbent will copy — **flow-log NDR with DNS/SNI from that
> collector** instead of Zeek/Suricata sensors, a **feed manager with STIX-out**
> instead of a TIP platform, and **identity posture as the deepest build**,
> with the vault extended into a credential broker, never a full PAM.

---

## 1. Startup reality: what a 50–200 person company actually has

### 1.1 The estate and its telemetry volumes (estimate, labelled as such)

No survey publishes "events per day per startup", so this is arithmetic on
public figures, labelled an estimate. The shape of the estate at 100 people:

| Asset | Count (est.) | Daily events (est.) | Source of events Vaigil already reads |
|---|---|---|---|
| Laptops (macOS/Windows) | 100–200 (≈1.5–2/person; Huntress' SMB base averages ~30 endpoints per customer — [Underdefense](https://underdefense.com/blog/ai-soc-for-smb)) | agentless: MDM + EDR alerts, not raw endpoint telemetry | Jamf Pro, ManageEngine MDM/Endpoint Central, CrowdStrike Falcon (all already sources) |
| Cloud servers / containers | 10–60 | auditd exec-filtered: ~5–25K lines/host/day | Linux auditd (already a source) |
| IdP (Okta or Entra) | 1–2 domains | 5K–50K sign-in + admin + provisioning events | Okta, Entra ID, Duo (already) |
| Cloud accounts (AWS/GCP/Azure) | 1–3 | CloudTrail/GCP audit: 50K–500K | CloudTrail, Azure, Google Cloud (already) |
| SaaS (GitHub, Slack, Google Workspace, Salesforce, Snowflake) | 30–80 apps, 5–10 security-relevant | 5K–100K | all already sources |
| Egress network | 1–2 clouds + Cloudflare | VPC flow logs 10–100 GB/month; DNS 20–200K queries/day org-wide | Cloudflare (already); **VPC flow logs: not yet a source** |

Total lands around **1–10 GB/day, single-digit millions of events/day** — inside
even today's measured speed ceiling (~500–2,000 events/sec sustained, master
report §1). The storage rewrite in master report §4.1 is about the *agent-telemetry
and hunt* future, not a startup-ingest blocker. Note this honestly: at Vaigil's
current customer size, **volume is not the problem; coverage and staffing are**.

### 1.2 Staffing: nobody is watching the console

- Mid-market runs roughly **1 security person per 500–1,000 employees**; below
  ~200 people it is 0–3 people, often zero, often "the IT person"
  ([Techaisle 2025 SMB survey](https://techaisle.com/security-reports/260-2025-smb-midmarket-security-adoption-trends);
  community consensus in practitioner threads).
- **73% of SME security professionals have missed, ignored, or failed to act on
  critical alerts** (Trend Micro survey via [Help Net Security, 2024](https://www.helpnetsecurity.com/2024/04/25/73-of-sme-security-pros-missed-or-ignored-critical-alerts)).
- Field Effect documents the end state: fatigued small teams **disable EDR
  agents entirely** ([Field Effect](https://fieldeffect.com/blog/why-edr-solutions-are-not-enough)).
- SANS 2025 Detection & Response Survey: EDR is trusted (**89% rate it
  effective**) yet the report's own theme is *overreliance on endpoint*
  detection leaving cloud/identity blind ([SANS](https://www.sans.org/research/detection-response-report),
  [Stamus analysis](https://www.stamus-networks.com/blog/2025-sans-detection-response-survey-5-trends-you-cant-ignore));
  62% of orgs track MTTD, 67% MTTR ([survey PDF copy](https://www.scribd.com/document/994534524/SANS-2025-Detection-Response-Survey-251208)).

### 1.3 The installed-vs-used gap (CrowdStrike, Sentinel, Defender)

What "having an EDR" means at a startup, day to day:

- **Microsoft is the default** — Defender for Business is included/bundled for
  orgs up to 300 users ([Microsoft](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-business),
  [Learn](https://learn.microsoft.com/en-us/defender-business/mdb-overview)).
  Its honest limits: ~30-day retention, **no advanced hunting**, fewer
  specialisms than Defender for Endpoint P2
  ([ciaops comparison](https://blog.ciaops.com/2025/06/05/),
  [Jeffrey Appel](https://jeffreyappel.nl/microsoft-defender-for-business-how-to-use-it-and-what-are-the-differences)).
  So the "SIEM" a startup would need for endpoint history doesn't exist in the
  product they own.
- The gap between installed and used is the MDR industry's entire premise:
  Huntress exists because SMBs cannot watch the console
  ([Huntress](https://www.huntress.com/small-business-cybersecurity-guide/why-small-businesses-need-edr)).
  Surveys of SOC trigger sources show the overwhelming majority of IR starts
  from endpoint alerts (85% in the SANS SOC survey analysis) — i.e. teams use
  EDR as an *alert pager*, not as a telemetry lake; the telemetry-heavy
  features (processtree hunting, raw event search, threat intel graph joins)
  go unused at this size.
- Sentinel usage at startups, when it happens, is a handful of Microsoft-centric
  rules plus connector sprawl; theAnalytics-lite reality plus per-GB pricing is
  precisely the complaint Vaigil's flat self-hosted model answers.

**Consequence:** the buyer Vaigil serves has tools that *generate* findings but
no one to *decide* them. Vaigil's queue-of-decisions + AI-first-pass + signed
audit of every human action is aimed exactly at the installed-vs-used gap; the
sensor question is therefore *what minimum telemetry feeds good decisions*, not
*how to build a sensor empire*.

### 1.4 What actually breaches startups (recap, from local DBIR/M-Trends)

From the local extracts (cited fully in `13-startup-and-agent-failures.md`):
SMB breaches are 100% System Intrusion / Basic Web App Attacks / Social
Engineering; initial access splits **exploitation 26% / credential abuse 13% /
phishing 9%**; **third-party involvement 55%** (DBIR 2026,
`/home/rashik/vaigil-research/sources/pdf/dbir.txt`). M-Trends 2026 adds OAuth
tokens and session cookies as harvested loot, SaaS integration tokens as the
new perimeter, exploits the top vector six years running
(`mtrends.txt`). The 2026 addition: AI agents with real credentials as both
target and attacker path (MCP supply-chain incidents from April 2026 onward,
§2.5 below).

Map that to telemetry: **credential abuse, phishing, OAuth misuse → IdP/SaaS
logs (agentless, already ingested). Exploitation of the edge → vuln
management + flow logs + the collector's exec events on servers. Third-party →
vendor risk + SaaS grant hygiene. Agent risk → agent telemetry.** Nothing in
the startup breach picture requires kernel-level endpoint telemetry.

### 1.5 The 90% answer

Agentless (IdP, SaaS, cloud audit, MDM) + vulnerability posture covers the
breach catalogue except one slice: what runs *on* the machines — and that slice
is exactly where developer endpoints and build servers run AI agents with real
credentials. That slice gets the **vaigil-collector** (§8): a read-only,
user-space, single-binary agent that is 10% EDR and 90% *evidence recorder* —
and deliberately doubles as the agent-telemetry source the master report's
flagship needs.

---

## 2. EDR — integrate the OSS fleet, build one small collector, never a kernel

### 2.1 The OSS building blocks: ingest today vs ship-a-sensor

| Tool | What it gives | Status for Vaigil |
|---|---|---|
| **osquery / Fleet** | SQL over OS state; scheduled queries = streaming telemetry; Fleet = fleet server with an API ([Fleet](https://fleetdm.com/securing/osquery-as-a-threat-hunting-platform), [SANS paper on osquery+Fleet+Elastic as OSS EDR](https://www.sans.edu/cyber-research/39165)) | **Ingest as a source** — osquery JSON result logs / Fleet API → new source mapping. Zero shipping by Vaigil. |
| **Velociraptor** | VQL hunts, artifact collection, offline DFIR; used inside Rapid7 XDR for breadth ([Velociraptor setup 2026](https://tech-insider.org/velociraptor-dfir-setup-2026), [DFRWS paper](https://dfrws.org/wp-content/uploads/2021/03/DFRWS-EU-2021-Velociraptor-Digging-Deeper.pdf), [Rapid7](https://www.rapid7.com/blog/post/2023/09/29/unlock-broader-detections-forensics-with-velociraptor-in-rapid7-xdr)) | **Ingest as a source** — artifact exports are JSONL; mapping + a "hunt request" is a future connector, not MVP. |
| **Wazuh agent** | Agent + rules engine + FIM + vuln detection; 5.0 still RC (4.14 stable as of Apr 2026) ([release notes](https://documentation.wazuh.com/current/release-notes/index.html), [5.0 RC1](https://www.reddit.com/r/Wazuh/comments/1wzzqi1/wazuh_50_release_candidate_1_is_here), [osquery-in-Wazuh docs](https://documentation.wazuh.com/current/user-manual/capabilities/system-inventory/osquery.html)) | **Ingest as a source** — `alerts.json` mapping. Vaigil is not a Wazuh replacement pitch; it is where Wazuh alerts go to be *decided*. |
| **Sysmon (free, Microsoft)** | Rich Windows process/network/file events via Event Log | **Ingest as a source** — the collector (§8) reads the channel if present, else ships 4688/4104. |
| **CrowdStrike Falcon** | Commercial EDR telemetry | **Already a source** (README). |
| **Suricata / Zeek / Arkime** | Network sensors — see §3 | Ingest-onl (mappings), never shipped. |
| **Falco / Tetragon** | eBPF-based runtime (container/K8s) detection ([Tetragon process lifecycle](https://tetragon.io/docs/use-cases/process-lifecycle/privileged-execution), [Falco-vs-Tetragon critique](https://blog.ncse.tw/tetragon-ebpf-runtime-security-container-vps), [HN: eBPF was not designed for security](https://news.ycombinator.com/item?id=37942791)) | **Ingest as a source** (Falco JSON alerts / Tetragon exec events via K8s audit path — Kubernetes is already a source). Not a dependency; a peer. |

Decision rule used throughout: **if it already emits logs, Vaigil maps it
(~1 file in `internal/source`); Vaigil never re-ships someone else's agent.**

### 2.2 The CrowdStrike July 2024 lesson (local RCA)

The local RCA extract
(`/home/rashik/vaigil-research/sources/pdf/cs-rca.txt`) is worth restating in
one line: an interpreted content file (Channel File 291) supplied 20 values to
a template expecting 21; the mismatch crashed the sensor in its kernel path,
taking ≈8.5M Windows hosts down with it; recovery reached ~99% of sensors only
weeks later. The design lessons for anything called a "vaigil sensor":

1. **No interpreted content executes on the endpoint.** The collector ships
   *declarative* watch lists (paths, hashes), validated by a Go struct, never
   executed. All detection logic runs server-side where the trial-ring and
   fixture discipline already lives.
2. **User-space only, fail-dead-silent.** The collector may die; the host must
   not notice. No kernel drivers on any OS, ever — this is also what keeps a
   solo developer out of the kernel-certification business.
3. **Staged content with canary and auto-rollback** is already the master
   report's content-plane answer (§4.8 there); the collector inherits it for
   watch-list updates.

### 2.3 Platform honesty: eBPF / ETW / ESF

- **Linux eBPF:** loading eBPF from Go *without* the cilium/ebpf library is
  feasible — the library is itself pure Go over the raw `bpf(2)` syscall
  ([cilium/ebpf](https://github.com/cilium/ebpf),
  [pure-Go eBPF LPC talk](https://lpc.events/event/4/contributions/449/attachments/239/529/A_pure_Go_eBPF_library.pdf),
  [walkthrough](https://networkop.co.uk/post/2021-03-ebpf-intro)). The stdlib
  `syscall` package exposes `SYS_BPF`, `perf_event_open` and `ioctl` — so
  BPF_PROG_LOAD with a small clang-compiled (or hand-assembled) program,
  attached to *fixed tracepoints* (`sys_enter_execve`, `sys_enter_connect`)
  whose context layout is a stable ABI read from
  `/sys/kernel/tracing/events/.../format`, is roughly a few hundred lines of
  Go. **Honest difficulty: moderate for a fixed tracepoint set, high if we ever
  want CO-RE/kprobe portability across kernels — which we do not.** It stays
  optional and experimental (§8.4); auditd text is the MVP substrate because
  auditd already gives execve and connect syscalls with args, and **Vaigil
  already ingests auditd** (`internal/source/known.go:470`).
- **Windows ETW:** consuming ETW is user-mode and needs no driver — but the
  stdlib does not wrap `StartTrace/ProcessTrace`; calling them via
  `syscall.NewLazyDLL` is possible and tedious. MVP shortcut: read the Event
  Log channels (Security 4688 process, 4104 PowerShell script-block, Sysmon if
  installed) via `wevtutil` XML — pure `os/exec` + `encoding/xml`, both
  stdlib. ETW proper is a later, optional upgrade.
- **macOS ESF:** the Endpoint Security Framework is user-space (a system
  extension, not a kext) **but requires Apple-granted entitlement, Developer ID
  signing, notarisation and MDM allowlisting**
  ([Apple](https://developer.apple.com/documentation/endpointsecurity),
  [Huntress on ES](https://www.huntress.com/blog/endpoint-security-in-a-macos-world),
  [Elastic deep-dive](https://www.elastic.co/blog/mac-system-extensions-for-threat-detection-part-3)).
  That is a vendor-certificate treadmill a solo OSS project should not enter
  year one. MVP: `log stream` (unified log) + OpenBSM `praudit` subprocesses
  and polling file watches — stdlib `os/exec` only.

### 2.4 Decision (EDR)

**Integrate + build one minimal collector.** Map osquery/Fleet, Velociraptor
artifacts, Wazuh alerts, Sysmon (and keep Falcon) as sources — each is one
declarative mapping in `internal/source`. Build the **vaigil-collector** (§8)
because no OSS agent does the one thing the differentiator needs: out-of-process
**agent telemetry** (`.mcp.json` changes, agent transcript tails, LLM-API egress
observation, SSH/env file watch). Do **not** build kernel drivers, on-endpoint
detection engines, or prevention — CrowdStrike's own RCA plus the entitlement
regimes on Windows/macOS make that a multi-year, multi-person trap.

---

## 3. NDR — flow logs and DNS/SNI are enough at this scale

### 3.1 What sensors give, and why startups don't run them

Zeek/Suricata/Arkime class sensors give protocol metadata and IDS signatures
from packets. In cloud-first startups there is no span port: packet capture
means VPC traffic mirroring — expensive, per-region, and shallow coverage
([ExtraHop on wire vs log in cloud](https://www.extrahop.com/blog/wire-data-vs-log-data-cloud-security);
practitioner scepticism in NDR threads: "worthless unless fed good traffic").
Corelight's own pitch — Zeek cuts SIEM ingest 90% — is an *enterprise*
argument; at startup volumes nobody has an ingest problem to solve
([Corelight glossary](https://corelight.com/resources/glossary/network-flow-monitoring)).

### 3.2 What flow logs + DNS/SNI actually detect at startup scale

Already available or cheaply added: **Cloudflare** logs (already a source),
VPC flow logs (missing — add), and DNS/SNI observed per-host by the collector.
Detections that hold up with tiny teams and near-zero FPs:

1. **Egress to feed-listed badness** — ThreatFox/Feodo C2 IPs, URLhaus
   malware-distribution hosts, Tor exit lists (TIP feeds, §4 — the indicator
   sweep already exists).
2. **First-contact destination** — host/process talking to a domain never seen
   in 30 days, then again on a schedule (beaconing periodicity from flow logs:
   alt-port + regular inter-arrival).
3. **DNS anomalies** — label-length/entropy tunneling heuristic; hard-fail NXDOMAIN
   bursts; resolver changed to public DoH endpoints (`1.1.1.1`/`8.8.8.8` direct
   from a server that has no business doing so).
4. **SNI-based egress intent** — SNI of internal hostnames over external TLS
   (exfil posture), SNI missing on 443 (malware HTTPS), and — the agent angle —
   **which LLM/MCP endpoints each machine actually calls**, joined with who is
   supposed to call them.
5. **Cloud control-plane net-flow joins** — flow-log conversation to an IP that
   CloudTrail shows a key was used from minutes earlier (impossible-travel-lite
   without identity telemetry).

### 3.3 Optional sensor ingest, zero shipping

If a customer runs Suricata or Zeek anyway (a few do, on a legacy DMIM), both
emit JSON lines — Suricata `eve.json` ([docs](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html))
and Zeek via `LogAscii::use_json` / json-streaming-logs ([zeek.org](https://zeek.org/2026/04/how-to-write-zeek-logs-in-json-tsv-simultaneously));
even Google SecOps ingests Suricata EVE off-the-shelf ([Chronicle parser](https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/suricata-eve)).
Two source mappings, no more.

### 3.4 Decision (NDR)

**No sensors. Ever.** Add the missing cloud flow-log sources (AWS VPC Flow
Logs, GCP VPC Flow, Azure NSG Flow; Cloudflare analytics events beyond the
firewall subset if not already mapped) and take DNS/SNI from the collector.
Ship the ~10 startup-scale detections above as pack rules with fixtures. Zeek/
Suricata/Arkime remain *ingest-only* mappings for the rare customer that has
them. This is the domain where the answer is closest to "do almost nothing" —
and that is the correct answer, not a shortcut.

---

## 4. TIP — a feed manager with STIX out, not a platform

### 4.1 What a TIP adds beyond indicator matching

Feed management (fetch, schedule, freshness), dedup and identity resolution,
per-source confidence and scoring, expiry/decay, enrichment (ASN, malware
family), sharing (MISP communities, TAXII), analyst workflow (campaigns,
reports), and graph analytics (OpenCTI's knowledge graph). The full platforms
are heavy by construction: **OpenCTI needs Elasticsearch + RabbitMQ + Redis +
MinIO**; MISP is PHP/MySQL with an older UX
([comparison 1](https://obsidiancorps.com/en/blog/2026/06/misp-vs-opencti),
[comparison 2](https://www.decryptiondigest.com/blog/misp-vs-opencti-threat-intelligence-platform),
[AWS prescriptive guidance](https://docs.aws.amazon.com/prescriptive-guidance/latest/cyber-threat-intelligence-sharing/architecture-threat-intelligence-platform.html),
[OpenCTI](https://github.com/opencti-platform/opencti), [MISP](https://www.misp-project.org)).
Neither fits inside a zero-dep single binary, and a startup's question is never
"which TIP" — it is "are these feeds fresh and did anything hit?".

### 4.2 What Vaigil already has (be precise)

`internal/feed` already models scheduled feeds with **freshness semantics that
distinguish our silence from their silence** (feed_test.go), and drives KEV /
EPSS / OSV for vulnerabilities. `internal/indicator` normalises kinds, refangs,
tracks `from/until` liveness, and sweeps retrospectively (master report §1).
That is, embarrassingly for the TIP category, *the hard 30% of a TIP* — the
part that decides whether a feed is trustworthy — already built as a side
effect.

### 4.3 Build: the light feed manager (in-binary, stdlib)

1. **Feed registry with per-feed confidence and scope tags** (ip/domain/url/
   package/mcp): a feed is data the existing `feed` engine fetches on a
   schedule; confidence is an operator-editable prior that multiplies into
   finding risk.
2. **Dedup/merge** across feeds through `indicator.Set` (exists), with
   provenance kept per member — "3 feeds agree" is itself signal.
3. **Expiry and decay**: indicators age out (`Until` exists); feeds declare
   re-observation policy (a KEV-style list = replace; abuse.ch = append+expire).
4. **STIX 2.1 bundle OUT**: emit one's own indicators (abuse observed, phishing
   domains lured with) as a signed STIX bundle — sharing without a community
   server (stdlib JSON + the existing Ed25519 signing).
5. **TAXII 2.1 client (pull)**: discovery → API root → collections → objects is
   plain REST + JSON ([OASIS spec](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html));
   stdlib `net/http` + `encoding/json`, same shape as any connector.
6. **TAXII 2.1 server (minimal)**: the read-only subset (discovery, one API
   root, one or two collections, manifest) is a few hundred lines on the
   existing HTTP layer; it makes Vaigil a *source* other SOC tools can pull —
   good marketing, low priority (Q4 of the sequence, §9).

### 4.4 Integrate: never the platform, sometimes the pipes

MISP and OpenCTI remain external peers: ingest their exports (MISP's STIX/CSV
exports, OpenCTI's STIX streams) as feed formats — mapping-level interop, zero
operation of their stacks. Feeds a startup should get day one, all free:

| Feed | Use | Status |
|---|---|---|
| CISA KEV, FIRST EPSS, OSV | vuln priority | already wired |
| abuse.ch **ThreatFox** (IOCs; now run with Spamhaus), **Feodo** (C2 IPs), **URLhaus** (malware URLs), MalwareBazaar | network/host indicator sweep | add — plain CSV/JSON, now also real-time streams ([threatfox](https://threatfox.abuse.ch), [urlhaus](https://urlhaus.abuse.ch), [Spamhaus/abuse.ch streams](https://docs.spamhaus.com/real-time-feeds/docs/source/50-abuse-ch-real-time-feeds/600-feeds-ach.html)) |
| OpenSSF malicious-packages repo | dependency + slopsquatting join | add — GitHub raw JSON |
| **GreyNoise Community** | on-demand enrichment of scanner-vs-targeted IP, benign/malicious/unknown — **50 searches/week free**, so it is an enrichment API behind the analyst, not a bulk feed ([docs](https://docs.greynoise.io/docs/using-the-greynoise-community-api)) | add as enrichment |
| Google Threat Intelligence / VirusTotal free tier | hash/domain lookups, heavily rate-limited | optional, later |
| **MCP/agent feeds** — the new category: Valyu's 2026 MCP/agent CVE list ([CSV](https://www.valyu.ai/blogs/mcp-ai-agent-vulnerabilities)), security-advisory-derived malicious-MCP lists (OECD-logged lookalike-server campaign, Apr 2026 ([incident](https://oecd.ai/en/incidents/2026-04-29-8e04)); "43% of MCP servers carry command-injection flaws, 8.5% implement OAuth" ([State of MCP Security 2026](https://cybertizeweb.com/blog/ai/state-of-mcp-security-2026)); CSA's May 2026 systemic-flaws note ([PDF](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/05/CSA_research_note_MCP_security_crisis_20260504-csa-styled.pdf)); Adversa's monthly roundups incl. the "Deadbugz" delayed-payload campaign ([Adversa](https://adversa.ai/blog/top-mcp-security-resources-september-2026))) | agent supply-chain checks vs `.mcp.json` and the AI-BOM | **build — no incumbent feed exists; this is Vaigil's feed** |

### 4.5 Decision (TIP)

**Light feed manager + STIX-out + TAXII-client; a minimal TAXII read-server
late; never MISP/OpenCTI.** The differentiating move is the **agent-feed
category**: Vaigil curating the malicious-MCP/skills/CVE list is the first
threat-intel product for the agent estate, and it is content, not code.

---

## 5. Identity — the deepest build (ITDR), and an honest PAM-lite

### 5.1 Why identity is *the* startup attack surface

DBIR SMB: credential abuse 13% of initial access and climbing through stolen
session cookies/OAuth tokens (M-Trends: tokens outlive logout; SaaS integration
tokens are the new perimeter — local `mtrends.txt`). At startup scale every
identity is a privileged identity (small orgs; every admin is GA). The
category the market built for this — non-human identity — is consolidating
fast: **Cisco bought Astrix (~$400M, May 2026; standalone sales ended June 30,
2026)** ([CSA note on the acquisition and agent-identity consolidation](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisco-astrix-ai-agent-identity-market-cons),
[Astrix](https://astrix.security), [Menlo Ventures on the NHI frontier](https://menlovc.com/perspective/beyond-human-the-next-frontier-of-identity-security))
— leaving, again, no open neutral layer.

### 5.2 What Vaigil has (verified)

Entra ID and Okta as connectors *and* log sources with risk events; Duo; SCIM
2.0 user/group state (`internal/scim`) for joiner-mover-leaver; SSF/CAEP/RISC
signals; workforce/device risk (KnowBe4, Vanta, MDM); the sealed vault with
rotation and tamper-detection semantics (`internal/vault`); dual-control
actions (suspend Okta account, end sessions).

### 5.3 What "posture" means here — the build list

1. **Standing-privilege detection** (pure queries over ingested data):
   permanent Global Administrator / Okta Super Admin where PIM/JIT exists;
   role granted outside a change window; **dormant admin** (role held, no
   sign-in 30d); admin count >1 per function. Alert-only, fixtures trivial.
2. **OAuth grant hygiene**: new consent grant with high-impact scopes
   (`Mail.Read`, `Files.Read.All`, `AppRoleAssignment.ReadWrite`); unverified
   publisher; multi-tenant app consented by ≥2 users in 24h; grant unused 90d;
   the BEC pair — consent grant **plus** a mail-forwarding rule. All visible
   in Entra/Okta audit logs already ingested.
3. **Service-principal / non-human posture**: SP with password credential (vs
   certificate/federated); secrets expiring <14d; privileged SP unused 60d;
   SP with no owner; new federated-identity credential (token-trust
   substitution). Join with cloud audit (CloudTrail principal = SP) for
   "credential used but estate says dormant".
4. **Agent identity posture** — Entra's own answer is that **an agent identity
   is a special service principal created from an agent-identity blueprint**
   ([Microsoft Learn, May 2026](https://learn.microsoft.com/en-us/entra/agent-id/agent-identities),
   [Workload ID 101](https://www.microsoft.com/en-us/security/business/security-101/what-are-non-human-identities),
   [Guardz anatomy](https://guardz.com/blog/the-anatomy-of-entra-agent-id)).
   Vaigil should: ingest blueprint-creation/agent-identity events; treat each
   agent as an entity in the registry the master report defines (§4.3 there);
   and alert on **agent identity created + high-impact consent within 1h** —
   the NHI explosion with the AI multiplier, detected before the NHI vendors'
   enterprise price tag.
5. **Joiner-mover-leaver closure**: SCIM says gone → still has Okta session?
   GitHub org membership? active connector credential in the vault? an
   unexpired API token last used yesterday? Each is a signed-estate check the
   data already supports (`internal/workforce/gaps.go` is the shape of this).

### 5.4 PAM-lite: the honest scope

**In:** the vault as a **credential broker** — connectors unwrap secrets
short-lived, every unwrap lands in the signed audit log (the vault's sealed
object + rotation machinery already exists); **JIT elevation** as a
dual-control action ("grant Okta admin role for 4h" — the action framework and
maker-checker already exist); SSH-key hygiene via the collector's
`authorized_keys` watch; secret leakage detection via the first-party scanner
(master report §4.5).
**Out — said out loud:** no session recording, no connection proxying/brokering
into target systems, no endpoint privilege management, no target-system
password rotation. That is CyberArk's trench war, not a startup's need; the
startups' real PAM pain is "the AWS key in the shared 1Password vault that
ex-intern still knows", which vault + broker + JML closure actually solves.

### 5.5 Decision (ITDR/PAM)

**Deepest build of the four domains.** All of §5.3 is queries, correlations and
actions over telemetry Vaigil already ingests — no sensor, no new protocol, no
dependency; it is where a startup gets the most detection value per line of
Go. PAM stays honest: vault, broker, JIT, hygiene.

---

## 6. The decision matrix

| Domain | (a) What a startup needs | (b) Integrate path | (c) Build-minimal path (in-binary) | (d) **Decision and why** |
|---|---|---|---|---|
| **EDR/XDR** | Someone to *decide* endpoint alerts; process/file truth on servers; proof of what ran | Map osquery/Fleet, Velociraptor, Wazuh alerts, Sysmon, (Falcon already) — each one `internal/source` mapping | **vaigil-collector**: auditd follow, file/agent-config watches, DNS/SNI observation, heartbeat (§8) | **Both, weighted to integrate**; the collector is built *only because* it doubles as the agent-telemetry source (the differentiator). No kernel, no on-endpoint detection, no prevention — CrowdStrike RCA + entitlement regimes + solo dev. |
| **NDR** | "Is anything talking to something it shouldn't?" | Map Suricata eve.json + Zeek JSON for the rare existing sensor | Flow-log sources (VPC/NSG/Cloudflare) + DNS/SNI from the collector + ~10 fixture-backed detections | **Flow logs suffice** at 50–200 person scale; sensors solve enterprise problems (ingest cost, span ports) startups don't have. Zero shipping. |
| **TIP** | Fresh feeds, honest hits, no platform to run | Ingest MISP/OpenCTI *exports* as feed formats; TAXII 2.1 client pull | Feed registry (confidence, scope, decay) on existing `internal/feed`; STIX-out bundle; **the agent/MCP feed category**; minimal TAXII server late | **Light feed manager, not a platform.** MISP/OpenCTI are operationally impossible in-binary; and the missing feed category (malicious MCP/agents) is Vaigil's to own as content. |
| **ITDR/PAM** | Credential-abuse and grant-graph detection; NHI/agent sprawl control; a vault that is used | Nothing worth integrating at this weight (Astrix→Cisco et al. are enterprise SaaS) | Standing-privilege, OAuth-consent, SP/NHI, agent-identity, JML-closure detections (all over ingested data); vault→broker, JIT elevation, key hygiene | **Build deepest here.** Highest value/line-of-Go of the four; zero new telemetry required; and agent-identity posture is where the AI-agent differentiator meets the identity category everyone else monetises at enterprise prices. |

---

## 7. Competitive honesty: what Vaigil will not have, and how to sell that

**Will not have (say it in the README, once, plainly):**

- **Kernel-level EDR telemetry and prevention** — no processtree-from-callbacks,
  no on-sensor ML, no block/kill. CrowdStrike/Sentinel/Defender P2 keep that
  crown; Vaigil reads their alerts (Falcon already) and stays out of the kernel.
- **A global intelligence graph** — no billions-of-events-a-day sensor cloud, no
  Falcon-Adversary intel graph; Vaigil's intel is *feeds + your estate*, and
  increasingly the agent feed it curates itself.
- **Managed hunting / 24/7 MDR** — no OverWatch, no humans-for-hire. The
  agentic analyst (master report §4.6) is the honest substitute and its
  year-1 targets get published precisely because no vendor publishes them.
- **Network forensics depth** — no full-packet capture, no Arkime sessions,
  no Zeek protocol analyser breadth.
- **Full PAM** — no session recording, no brokering into targets (§5.4).

**The positioning for a startup buyer:** every incumbent sells telemetry a
small team cannot staff. The startup's real question is *"tell me what to
decide today, keep the evidence, and don't bill me per gigabyte for logs I
never open."* Vaigil's honest pitch: **agentless coverage of the 90% (IdP,
SaaS, cloud, MDM) that actually breaches startups, one read-only collector for
the 10% nobody else watches (developer machines and servers running AI agents),
and an AI analyst that writes the first pass without being able to decide
anything.** "EDR you never tune" loses to "you already own the telemetry; we
make it decidable" — and no competitor can chase the agent-telemetry flagship
without either shipping an endpoint agent themselves (they won't, at these
prices) or putting evidence in their cloud (their business model forbids
tamper-evidence outside it).

---

## 8. The vaigil-collector design brief (and its agent-telemetry role)

### 8.1 Purpose and non-purposes

A **read-only, user-space, single static Go binary** (`cmd/vaigil-collector`),
still zero third-party dependencies, deployed optionally on Linux servers and
developer machines. It records; it never judges; it never blocks. Detections
run in the Vaigil server's existing rule engine. It exists for exactly two
reasons: (1) the agentless estate cannot see files and processes; (2) **the
master report's flagship — "evidence the agent cannot erase" — needs an
out-of-process recorder** (§4.3 there: agents delete their own traces in 5 of
6 harnesses, arXiv 2609.30266).

### 8.2 MVP (Linux, ~weeks of work, stdlib only)

| Capability | Mechanism | Stdlib honesty |
|---|---|---|
| Process/exec events | follow `/var/log/audit/audit.log` (audisp preferred), reassemble multiline records, extract EXECVE args + SYSCALL (connect, execve) + USER_CMD; normalise into the existing auditd source shape (`internal/source/known.go:470`) | text parsing — trivial, already half-built |
| File watch pack | `syscall.InotifyInit1`/`InotifyAddWatch` (stdlib on Linux) on: `~/.ssh/authorized_keys`, `~/.ssh/id_*`, `.env`/`.env.*`, `*.pem` in home, `~/.mcp.json`, `.cursor/rules`, `CLAUDE.md`, `AGENTS.md`, `.claude/settings.json`, agent session dirs; **hash-on-change, ship hash + size + who, not content by default** (content ship is per-path opt-in, redacted by the same `internal/pii` mask server-side) | direct stdlib |
| Agent transcripts / receipts | tail agent session JSONL transcripts (`~/.claude/projects/…`, equivalents), shipping tool-call receipts (tool, args-hash, outcome, ts) **out-of-process** into the anchored chain | tail + JSON — the flagship's collection half |
| DNS/SNI egress observation | `AF_PACKET` raw socket (CAP_NET_RAW), parse Ether/IP/TCP/UDP with `encoding/binary`; keep only metadata: DNS qname/qtype, TLS ClientHello SNI, remote ip:port, direction; sample under load; **no packet storage, ever** | stdlib `syscall.Socket(AF_PACKET, …)`; classic-BPF filter optional via `SO_ATTACH_FILTER` with a hand-built `sock_fprog` (`unsafe`, contained) |
| LLM/API egress map | the DNS/SNI stream filtered to known LLM/MCP endpoints (api.anthropic.com, api.openai.com, *.mcp endpoints) per host → joins the agent registry: *which machine talked to which model endpoint* | same stream |
| Heartbeat + integrity | 60s heartbeat event; HMAC-signed batches (the `internal/inbound` webhook shape already verifies standard signatures — one new feed kind); local spool with retry; Ed25519-signed installer and config digest | all stdlib |
| Config | declarative watch list (paths, hashes, rates) fetched from the server, validated into a Go struct, **never executed** (CrowdStrike lesson, §2.2) | — |

Privileges: run as a dedicated user with `CAP_AUDIT_READ` (audit file read) and
`CAP_NET_RAW`; no root needed on modern hosts with `auditd` logging to file;
document the LSM notes (SELinux watch permissions).

### 8.3 Windows and macOS (phase 2)

- **Windows:** `wevtutil qe` XML poll of Security (4688 process, 4624/4648
  logon), PowerShell/Operational (4104), Sysmon channels if present
  (`Microsoft-Windows-Sysmon/Operational` — recommend the free Sysmon install
  in docs); polling file watches for the same watch pack. ETW via
  `syscall.NewLazyDLL("advapi32.dll")` is the later upgrade — possible, tedious,
  optional (§2.3).
- **macOS:** no ESF year one (entitlement regime, §2.3). `log stream
  --style json` with predicates (process exec-ish events, SSH/auth), OpenBSM
  `praudit` subprocess for audit records, polling watches for the watch pack.

### 8.4 eBPF (phase 2-3, optional, honest)

Where auditd cannot go (container-dense hosts, auditd contention), a fixed
two-program set — `sys_enter_execve`, `sys_enter_connect` — loaded via raw
`bpf(2)` through stdlib `syscall`, attached via `perf_event_open` +
`PERF_EVENT_IOC_SET_BPF`, context layout read from the tracepoint `format`
file (stable ABI; no CO-RE needed for tracepoints — §2.3 sources). Ship the
compiled program bytes in the binary. Difficulty: moderate; scope creep risk:
high; kept behind a build tag and a config flag, with per-kernel smoke tests
in CI. It is an optimisation of what auditd already provides — never a
dependency of the MVP.

### 8.5 The agent-telemetry role (why this binary exists at all)

The collector is one of the three agent-evidence channels in the master report
(§4.3 there: sidecar / MCP-proxy / OTel). Concretely it provides:

1. **Out-of-process tool-call receipts** — transcript tails produce receipts
   into the SCITT-shaped, Merkle+Ed25519+ML-DSA+OpenTimestamps-anchored chain
   (all exists) — the record an agent cannot reach to erase.
2. **MCP config rug-pull detection** — `.mcp.json`/settings hash changes after
   approval, new/unsigned MCP servers, matching the master report's detection
   list — *observed from outside the agent process*.
3. **Egress corroboration** — DNS/SNI shows the LLM endpoints actually
   contacted, so a "toxic flow complete" correlation (untrusted read →
   sensitive read → new egress) has network-side evidence, not just
   transcript-side.
4. **Recorder-blind detection** — heartbeat gaps flag "agent machine stopped
   telling the truth" (the arXiv 2609.30266 answer).

No OSS agent (osquery, Velociraptor, Wazuh) ships any of this; that is the
defensible reason the binary exists despite "integrate-first".

### 8.6 Why a separate binary is still "zero dependencies"

The README's claim is about the *platform*; the collector honours it: same
stdlib-only rule, single `cmd/` package, static-linked, no cgo. It is the
second binary the project ships beside `vaigil` (which already runs `logd` as
a separate account) — a pattern the audit architecture already established.

---

## 9. Twelve-month sequence (tied to the master report's releases N/N+1/N+2)

**Month 0–1 (with Release N substrate work).** Stop dropping `audit.KindAI`
(the one-line change); add source mappings: osquery/Fleet JSON, Velociraptor
artifact JSONL, Wazuh `alerts.json`, Sysmon; add AWS/GCP/Azure flow-log
sources; add TIP feeds (ThreatFox, Feodo, URLhaus, OpenSSF) as `internal/feed`
entries with confidence priors; land ITDR pack v1 (consent grants,
standing-privilege, dormant admin) on existing Entra/Okta data. *Everything
this month is mappings and rules — no new binaries.*

**Month 2–4.** `vaigil-collector` MVP on Linux (auditd follow, watch pack,
DNS/SNI, heartbeat, HMAC batches into `internal/inbound`); ~15 collector
detections with fixtures (authorized_keys change, .env read-then-egress,
agent-config change, new MCP server, curl|sh exec, heartbeat gap); STIX 2.1
bundle out; JML closure checks against SCIM + vault + sessions.

**Month 5–8.** Collector on Windows (wevtutil) and macOS (log stream);
transcript tails + receipts into the anchored chain (flagship complete);
agent-identity posture (Entra Agent ID blueprint events, SP hygiene rules);
TAXII 2.1 client; GreyNoise enrichment behind the analyst; eBPF prototype
behind build tag + flag.

**Month 9–12.** Minimal TAXII 2.1 read-server (share-out); JIT-elevation
dual-control actions (Okta/Entra role grant with TTL); vault credential-broker
semantics (short-lived unwrap, audited); the agent/MCP feed published as
signed content (first-mover intel); collector detections into VaigilBench;
README/docs honesty section (§7) and the startup positioning page.

---

## 10. Sources

**Local (repo).** `README.md`; `docs/research/2026-10-24-master-report.md` (§1
speed ceiling, §4.3 agent core, §4.5 scanner, §4.8 content plane, §5 roadmap);
`docs/research/13-startup-and-agent-failures.md` (DBIR/M-Trends SMB figures);
`docs/research/03-integrations.md` (connector/source inventory);
`/home/rashik/vaigil-research/sources/pdf/cs-rca.txt` (CrowdStrike RCA),
`dbir.txt`, `mtrends.txt`; `internal/{feed,indicator,inbound,scim,vault,source,workforce}`
as cited in text.

**Startup reality / installed-vs-used.**
[Techaisle 2025 SMB & Midmarket Security Adoption](https://techaisle.com/security-reports/260-2025-smb-midmarket-security-adoption-trends) ·
[Underdefense: AI SOC for SMBs (Huntress 150K SMBs / 4.5M endpoints)](https://underdefense.com/blog/ai-soc-for-smb) ·
[Help Net Security: 73% of SME pros missed/ignored critical alerts](https://www.helpnetsecurity.com/2024/04/25/73-of-sme-security-pros-missed-or-ignored-critical-alerts) ·
[Field Effect: why EDR is not enough](https://fieldeffect.com/blog/why-edr-solutions-are-not-enough) ·
[SANS 2025 Detection & Response report](https://www.sans.org/research/detection-response-report) ·
[Stamus: 5 trends from the SANS 2025 D&R survey](https://www.stamus-networks.com/blog/2025-sans-detection-response-survey-5-trends-you-cant-ignore) ·
[SANS 2025 D&R survey webcast](https://www.sans.org/webcasts/sans-2025-detection-and-response-survey-webcast-forum) ·
[survey PDF copy (MTTD/MTTR tracking)](https://www.scribd.com/document/994534524/SANS-2025-Detection-Response-Survey-251208) ·
[OPSWAT on EDR overreliance](https://www.opswat.com/resources/reports/sans-detection-response-survey) ·
[Defender for Business](https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-business) ·
[Defender for Business overview (Learn)](https://learn.microsoft.com/en-us/defender-business/mdb-overview) ·
[ciaops: MDB vs MDE](https://blog.ciaops.com/2025/06/05/) ·
[Jeffrey Appel: MDB limits](https://jeffreyappel.nl/microsoft-defender-for-business-how-to-use-it-and-what-are-the-differences) ·
[Huntress: why small businesses need EDR](https://www.huntress.com/small-business-cybersecurity-guide/why-small-businesses-need-edr) ·
[CISA Enhanced Visibility and Hardening guidance](https://www.cisa.gov/resources-tools/resources/enhanced-visibility-and-hardening-guidance-communications-infrastructure) ·
[CISA 2025 Year in Review (500K+ federal EDR endpoints)](https://www.cisa.gov/about/2025YIR)

**EDR building blocks / platform.**
[SANS: osquery+Fleet+Elastic as OSS EDR](https://www.sans.edu/cyber-research/39165) ·
[Fleet: osquery as hunting platform](https://fleetdm.com/securing/osquery-as-a-threat-hunting-platform) ·
[Velociraptor setup 2026](https://tech-insider.org/velociraptor-dfir-setup-2026) ·
[DFRWS: Velociraptor paper](https://dfrws.org/wp-content/uploads/2021/03/DFRWS-EU-2021-Velociraptor-Digging-Deeper.pdf) ·
[Rapid7 XDR + Velociraptor](https://www.rapid7.com/blog/post/2023/09/29/unlock-broader-detections-forensics-with-velociraptor-in-rapid7-xdr) ·
[Packetlabs: open-source EDR roundup](https://www.packetlabs.net/posts/open-source-edr-solutions) ·
[Wazuh release notes (5.0 RC / 4.14 stable)](https://documentation.wazuh.com/current/release-notes/index.html) ·
[Wazuh 5.0 RC1 announcement](https://www.reddit.com/r/Wazuh/comments/1wzzqi1/wazuh_50_release_candidate_1_is_here) ·
[Wazuh osquery docs](https://documentation.wazuh.com/current/user-manual/capabilities/system-inventory/osquery.html) ·
[cilium/ebpf](https://github.com/cilium/ebpf) ·
[A pure Go eBPF library (LPC)](https://lpc.events/event/4/contributions/449/attachments/239/529/A_pure_Go_eBPF_library.pdf) ·
[networkop: eBPF and Go](https://networkop.co.uk/post/2021-03-ebpf-intro) ·
[Tetragon process-lifecycle use case](https://tetragon.io/docs/use-cases/process-lifecycle/privileged-execution) ·
[Falco vs Tetragon (2026)](https://blog.ncse.tw/tetragon-ebpf-runtime-security-container-vps) ·
[HN: eBPF was not designed for security](https://news.ycombinator.com/item?id=37942791) ·
[Apple: Endpoint Security framework](https://developer.apple.com/documentation/endpointsecurity) ·
[Huntress: ES in a macOS world](https://www.huntress.com/blog/endpoint-security-in-a-macos-world) ·
[Elastic: macOS system extensions for threat detection](https://www.elastic.co/blog/mac-system-extensions-for-threat-detection-part-3)

**NDR.**
[ExtraHop: wire vs log data in cloud security](https://www.extrahop.com/blog/wire-data-vs-log-data-cloud-security) ·
[Corelight: network flow monitoring](https://corelight.com/resources/glossary/network-flow-monitoring) ·
[Suricata EVE JSON docs](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html) ·
[Zeek: JSON and TSV logs simultaneously](https://zeek.org/2026/04/how-to-write-zeek-logs-in-json-tsv-simultaneously) ·
[Google SecOps Suricata EVE parser](https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/suricata-eve)

**TIP.**
[MISP vs OpenCTI (Obsidian Corps, 2026)](https://obsidiancorps.com/en/blog/2026/06/misp-vs-opencti) ·
[MISP vs OpenCTI (Decryption Digest)](https://www.decryptiondigest.com/blog/misp-vs-opencti-threat-intelligence-platform) ·
[AWS prescriptive guidance: deploying a TIP](https://docs.aws.amazon.com/prescriptive-guidance/latest/cyber-threat-intelligence-sharing/architecture-threat-intelligence-platform.html) ·
[OpenCTI](https://github.com/opencti-platform/opencti) · [MISP](https://www.misp-project.org) ·
[ThreatFox](https://threatfox.abuse.ch) · [URLhaus](https://urlhaus.abuse.ch) ·
[Spamhaus/abuse.ch real-time feeds](https://docs.spamhaus.com/real-time-feeds/docs/source/50-abuse-ch-real-time-feeds/600-feeds-ach.html) ·
[Cyware: top free feeds 2026](https://www.cyware.com/blog/best-threat-intelligence-feeds) ·
[GreyNoise Community API docs (50 searches/week)](https://docs.greynoise.io/docs/using-the-greynoise-community-api) ·
[OASIS TAXII 2.1 specification](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html) ·
[OASIS reference TAXII server (medallion)](https://github.com/oasis-open/cti-taxii-server) ·
[Sentinel TAXII connector docs](https://learn.microsoft.com/en-us/azure/sentinel/connect-threat-intelligence-taxii)

**Identity / NHI / agents.**
[Microsoft Learn: agent identities in Entra](https://learn.microsoft.com/en-us/entra/agent-id/agent-identities) ·
[Microsoft: what are non-human identities](https://www.microsoft.com/en-us/security/business/security-101/what-are-non-human-identities) ·
[Guardz: anatomy of Entra Agent ID](https://guardz.com/blog/the-anatomy-of-entra-agent-id) ·
[YouAttest: reviewing NHIs and AI agents in Entra](https://youattest.com/insights/how-to-review-non-human-identities-and-ai-agents-in-microsoft-entra-id) ·
[Cayosoft: NHI management](https://www.cayosoft.com/non-human-identity-security-management) ·
[CSA research note: Cisco–Astrix and agent-identity consolidation](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisco-astrix-ai-agent-identity-market-cons) ·
[Astrix (standalone sales ended June 2026)](https://astrix.security) ·
[Menlo Ventures: beyond human identity](https://menlovc.com/perspective/beyond-human-the-next-frontier-of-identity-security) ·
[Valyu: MCP/agent CVE list 2026](https://www.valyu.ai/blogs/mcp-ai-agent-vulnerabilities) ·
[SecValley: MCP server security 2026](https://www.secvalley.com/insights/mcp-server-security) ·
[CRITICALSTART: 8,000+ public MCP servers scanned](https://security.criticalstart.com/rs/586-OQG-630/images/%5BCS-SA-26-0901B%5D%20AI%20As%20a%20Target.pdf) ·
[CSA: MCP security crisis research note](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/05/CSA_research_note_MCP_security_crisis_20260504-csa-styled.pdf) ·
[Adversa: MCP security roundup Sept 2026](https://adversa.ai/blog/top-mcp-security-resources-september-2026) ·
[OECD.AI: malicious MCP supply-chain incident](https://oecd.ai/en/incidents/2026-04-29-8e04) ·
[State of MCP Security 2026](https://cybertizeweb.com/blog/ai/state-of-mcp-security-2026)
