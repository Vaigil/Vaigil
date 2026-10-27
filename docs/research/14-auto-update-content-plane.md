# 14 — The signed auto-updating content plane

Status: design, October 2026. Owner of the decision: Rashik.
Context: [master report §4.8](2026-10-24-master-report.md) (content plane as the
solo-dev unlock), [03-integrations §8](03-integrations.md) (connectors and
mappings are already data — this plane needs no engine change), and the
salvaged [CrowdStrike RCA of July 19
2024](prior-session/sources/pdf/cs-rca.txt) — the canonical failure this
design exists to not repeat. Scheduled, per the roadmap, for Release N+1
(3–6 months) with the marketplace in N+2.

## 0. The problem, in one paragraph

Vaigil is maintained by one person. Today, every new detection, source
mapping, connector manifest, playbook and eval set ships inside a binary
release, which means the product's living part moves at the speed of
compiled software: slow for the owner, and slow for a customer who is
waiting for coverage of an incident that happened last week. Every SIEM
vendor solved this years ago — Splunk's ESCU, Elastic's detection-rules,
Sentinel's Content Hub, Wazuh's ruleset — and every one of them arrived at
the same shape: rules decoupled from engine releases, delivered on their
own cadence. Elastic only finished that decoupling in 2025; Wazuh moved its
ruleset to a separate repository that the manager pulls without a version
upgrade. The content plane is that move for Vaigil, done with the threat
model the incumbents mostly skipped: signed metadata with rollback and
freeze protection (TUF/Uptane), a per-customer empirical gate before
anything goes live, and automatic rollback. The single constraint that
shapes everything below: **it must never cause a CrowdStrike-July-2024**.
That incident was content — data, not code — interpreted by an engine whose
validator disagreed with its runtime. The defense is not "better testing
before release". It is that the customer's own installation is the last
gate, the gate is empirical (replay against the customer's own telemetry),
and the failure mode is a rollback, not an outage.

## 1. What others do, and what it settles for us

| System | Model | What we take | What we refuse |
|---|---|---|---|
| CrowdStrike Falcon, Rapid Response Content | regex content in channel files, interpreted on-sensor by a Content Interpreter; validated by a separate Content Validator; pre-July-2024 no staged rollout | their post-incident mitigations verbatim: staged rings, customer control, validator that checks against what the runtime actually provides | a validator separate from the runtime; interpreting content in anything kernel-adjacent; fleet-wide simultaneous exposure |
| Splunk ES Content Update (ESCU) | pre-packaged detections from Splunk's threat research team, applied as app updates the customer imports | content as a first-class product stream with release notes customers can subscribe to | app-upgrade mechanics (we are one binary) |
| Elastic detection-rules | rules developed/tested/released in the open, shipped as a "Prebuilt Security Detection Rules" package historically pinned to the Kibana stack release, decoupled in 2025 so rule updates no longer wait for stack upgrades | decoupling from day one; open repository with visible QA | package-per-stack-version coupling |
| Microsoft Sentinel Content Hub | solutions and content packs in a hub; updating a solution can overwrite analytics rules the customer had customised | the overwrite problem is a named failure class for us (§3.4: user edits win) | silent overwrite of customer-modified content |
| Wazuh | ruleset/decoders/SCA in a dedicated repository pulled by the manager independently of engine releases, with automatic updates that can be disabled | independent content repo; updates without engine upgrade; an explicit off switch | — |
| SigmaHQ | community rules with an automated QA pipeline (pySigma-based validation, CI checks on every contribution) | CI gates as the community-marketplace baseline (§6) | publishing rules that have never been shown to fire (their own pipeline measures shape, not behaviour; our fixtures do) |
| Nuclei templates | versioned template releases; engine pulls at most once per 24h | templates as data with their own version line | executing templates (Nuclei's templates carry protocols and execution semantics; ours cannot) |
| Trivy DB | vulnerability DB as versioned OCI/GitHub artifacts, updated at scan time, signed; the 2026 CVE-2026-33634 in its update pipeline shows a DB updater is attack surface too | signed DB artifacts; air-gap mirroring | trusting the transport instead of the signature |

Security technology, all implementable with the Go standard library this
repo already builds on:

- **TUF** (The Update Framework): four signed metadata roles — root
  (trust anchor, lists keys and thresholds for the other roles), targets
  (lists target files with hashes and sizes), snapshot (lists version
  numbers of all targets metadata — the mix-and-match defense), timestamp
  (frequently re-signed, short expiry, pins the snapshot hash — the freeze
  defense). Rollback protection is version counters plus client-side
  state: a client refuses metadata older than anything it has seen.
- **Uptane**: TUF's automotive hardening — the observation that the
  interesting attacks on an update stream are rollback, freeze,
  mix-and-match and endless-data, and that a compromised *online* key must
  not be enough to serve arbitrary old content. Its split (offline root +
  online director) maps to our split (offline root key + online release
  key).
- **Sigstore** (keyless signing, Fulcio ephemeral certificates, Rekor
  transparency log): the ideas worth taking are the transparency log and
  inclusion proofs — signing events are witnessed publicly, so a hidden or
  backdated release is detectable. We do not adopt the OIDC/keyless
  machinery (a solo producer with an offline root key has no identity
  problem to solve); we adopt the witnessed-publication property via
  OpenTimestamps, which is already in the repo.
- **in-toto / SLSA**: signed attestations about how an artifact was built.
  Our equivalent is the pack manifest's build record plus the CI gate
  results (§4.1), carried inside the signed metadata rather than beside it.

Post-quantum note: `crypto/mldsa` (FIPS 204) is in the Go standard library
since 1.26; this repo builds on 1.27 and already dual-signs audit heads
with Ed25519 + ML-DSA-65 in `internal/audit/sign.go`. The content plane
reuses exactly that pattern and argument: two algorithms that fail
differently, both required.

## 2. What content is, in Vaigil, today

Verified against the tree, October 2026:

| Content | Where it lives | Data or code | Existing gate |
|---|---|---|---|
| Detection rules | JSON in `internal/detect/pack/` (28 files), installed to `store/detections/` | data: a closed predicate tree over fields `internal/telemetry` publishes (`internal/detect/rule.go`) | `Rule.Validate`: fixtures that must match **and** must not; every field the rule reads must appear in a fixture; predicate depth ≤ 16; RE2 only |
| Correlations | `correlations.yml` in the pack | data (counts across rules) | validated at load |
| Source mappings | Go constructors for 17 built-ins in `internal/source/known.go`, but the struct is JSON and custom mappings install from files | data (dotted paths, required paths, outcome conventions, declared lateness) | `source.Check` against real sample records; install refuses a mapping that maps none of its sample |
| Connector manifests | JSON catalogue (8 connectors) | data (host, auth kind, endpoints, pagination, `reads` allow-list) — the engine (`internal/connector`) is generic | `manifest.Validate`: one HTTPS host, SSRF rules, scope spelling, secret-shaped values refused |
| Actions | `internal/action/catalogue/*.json` — declared requests (fixed method/host/path/constant body) | data; the two-person approval rule is code | catalogue validation at load |
| Playbooks | `internal/incident/playbook.go` + embedded set | data (steps, needs, why, undo) | `Playbook.Validate`; ≤ 60 steps; needs point backwards |
| Automations | `internal/automate` — when/if/then rules over closed event kinds | data; watch/ask/act modes, hourly limits are code | condition validation against closed field lists |
| Indicators | STIX 2.1 bundles / plain lists (`internal/indicator`) | data | schema validation |
| Vuln feeds | KEV/EPSS/OSV via `internal/feed` mirror machinery | data with its own mirror cadence | digest-per-release, staleness-as-finding |
| Eval sets | `internal/analyst/eval.go` cases | data (state + expected verdict; pass^k, hijack measurement) | run against the configured model |
| Prompts / the analyst plan | code (`internal/analyst`) | **code, by policy** — the plan is fixed before untrusted text is read | — |
| Suppressions, ring placements | org-local (`internal/detect/tuning.go`) | **org decisions, not content** — expire in ≤ 90 days, need owner and reason | `Validate` refuses whole-rule/whole-source suppressions and AI-made ones |

The line, restated from 03-integrations §8: **a manifest cannot execute**.
The connector path language has no wildcards or functions; the detection
predicate set is nine operators over strings; a playbook is a checklist
executed by humans. Everything in the left column above ships as data
already. The genuinely-compiled remainder: new auth kinds (SigV4,
signed-JWT), new inbound verification schemes, new pagination kinds, the
rule evaluator itself, and the analyst's plan. Those release as binaries
and the content plane never touches them.

## 3. The pack format

### 3.1 What a pack is

A pack is a directory of content files plus one manifest, published under
a pack id in a channel at a version. It is addressed content: the same
pack id always claims the same namespace of content ids (a rule id, a
mapping issuer, a playbook id), and two installed packs may not claim the
same id — the installer refuses overlaps, because overlapping content is
how a "which copy is real?" question starts.

```
vaigil.detections-2026.11.0/
  manifest.json
  detections/
    okta.api-token-created.json
    entra.difficult-travel.json          (new)
    ...
  correlations/
    cross-platform-password-spray.yml
```

Pack ids: `vaigil.*` is reserved for first-party content (the same
convention as the `vaigil.admin-granted` self-detections). Third parties
use a domain-reversed id (`com.example.phishing`). Day-one first-party
catalogue, split by cadence:

| Pack | Cadence | Carries |
|---|---|---|
| `vaigil.detections` | weekly (Tuesdays) + hotfixes | detection rules, correlations |
| `vaigil.mappings` | as needed | source mappings |
| `vaigil.connectors` | as needed | connector manifests |
| `vaigil.playbooks` | rare | playbooks |
| `vaigil.evals` | rare | analyst eval cases |
| `vaigil.core` | per binary release | the seed set a new store installs (today's embedded starter pack), so a fresh install starts current without a network round-trip |

### 3.2 The manifest

```json
{
  "id": "vaigil.detections",
  "version": "2026.11.0",
  "channel_floor": "stable",
  "about": "Vaigil's maintained detections.",
  "engine": {
    "minimum_binary": "0.9.0",
    "tested_binaries": ["0.9.0", "0.9.3", "0.10.1"],
    "schemas": { "detections": 3, "correlations": 2 }
  },
  "counts": { "detections": 214, "correlations": 9 },
  "changes": [
    { "content": "entra.difficult-travel", "kind": "new",
      "note": "impossible travel across two IdPs; correlation counts platforms" },
    { "content": "okta.signin-through-proxy", "kind": "tuned",
      "note": "requires risk field present; was firing on corporate ZTNA exits" }
  ],
  "built": {
    "at": "2026-11-04T02:11:00Z",
    "by": "ci@vaigil-build",
    "commit": "a1b2c3d",
    "gates": {
      "schema": "pass", "fixtures": "pass", "corpus": "pass",
      "producer_replay": "pass: 14-day estate corpus, 0 regressions"
    }
  },
  "files": {
    "detections/okta.api-token-created.json":
      "sha256-9f2b...",
    "correlations/cross-platform-password-spray.yml":
      "sha256-4c8e..."
  }
}
```

Rules the loader enforces:

- `version` is CalVer (`YYYY.MM.PATCH`) for humans; the signed metadata
  carries its own monotonic integer version (§4) which is the only thing
  rollback protection reasons about.
- `engine.minimum_binary` and `engine.schemas` are the version
  negotiation: a binary older than `minimum_binary`, or one that does not
  know schema major N, refuses the whole pack atomically (§5.4) and says
  so. Unknown JSON fields in pack files are refused everywhere
  (`DisallowUnknownFields`, the strictness the connector catalogue load
  already uses) so "a pack written for a newer schema" fails loudly on an
  older binary instead of loading half-meaningful content.
- `changes` is the release note. It is data for the UI (§5.5) and the
  thing a customer subscribes to — CrowdStrike's post-incident mitigation
  list, verbatim: customer control *plus* content update details via
  release notes.
- `built.gates` is the producer-side in-toto/SLSA-shaped attestation:
  what CI checked, inside the signature. A pack whose gates are missing or
  failed does not pass client-side policy either (§5.3, step 3).

### 3.3 Content types: day one, later, never

**Day one** (all already data in the tree, §2): detections, correlations,
source mappings, connector manifests, playbook definitions, eval sets,
indicator lists (treated as content with declared expiry, not permanent
files).

**Later (N+2+)**: secret-scanning patterns (Release N+ brings
first-party secret scanning; its pattern set is then packable),
SSVC/decision-policy templates (recommendations a human accepts),
SCA policy tweaks, UI strings once there is a translation story (i18n is
pure data but there is no i18n yet; do not build the plane around it).

**Never**:

- **Prompts or any change to the analyst's plan.** The plan is fixed in
  code before untrusted text is read; a prompt pack is a pack that talks
  to the model. Refused outright.
- **Suppressions and ring placements.** Those are this organisation's
  verdicts on content, with owners, reasons and expiry dates. A pack that
  could ship them would be a pack that could switch detection off and
  have the switch expire responsibly-looking. Packs propose nothing here;
  the existing tuning proposals (which compute and never apply) remain the
  only channel.
- **Credential values** — manifests carry credential *names* only; the
  pack validator refuses anything that looks like a pasted token (the
  `looksSecret` check already in the connector engine).
- **Anything executable**: no plugins, no DSL, no expression strings, no
  WASM, no scripts. See §4.7 for why data-only is not a compromise.

### 3.4 Local overrides that survive updates

`detect pack install` today leaves any file already in `detections/`
alone. That behaviour is the seed; the plane formalises it as
**user-wins, recorded, shown**:

- The store keeps the pristine pack under `store/packs/<id>/<version>/`
  and the working copies where the engines already read them
  (`detections/`, `sources/`, `connect/`).
- `store/pack-state.json` records, per file a pack owns, the digest of
  the version it last installed (the baseline).
- On update, per file: if the working copy still matches the baseline
  digest, it is replaced with the new pack version (an unremarkable
  update); if it does not match, a human edited it — the edit wins, the
  file is kept, and a **fork** is recorded: pack id, file, version
  diverged, digest of both.
- The UI lists forks ("3 of your edits were kept; the pack moved on —
  show diff"), every fork and every apply is written to the audit log
  (the pack plane is itself auditable content: a `vaigil.content-updated`
  detection in the starter pack watches it), and `vaigil content forks`
  prints them.
- Nothing is ever merged automatically. A fork is resolved by a person
  choosing "keep mine" or "take the pack's", on the record.

This is the Sentinel Content Hub overwrite problem answered by
construction: an update can never clobber a customer modification, and it
can never silently leave one behind either.

## 4. Signing, verification, and update metadata

### 4.1 Minimal TUF for a single producer

Full TUF supports delegations, multiple repositories and thresholds of
many keys; a solo producer needs the load-bearing parts. The repository
layout a mirror serves:

```
content.vaigil.org/
  1.root.json 2.root.json ...        (every root version, ever — never deleted)
  targets.json                        (one target entry per pack file)
  snapshot.json
  timestamp.json
  packs/vaigil.detections/2026.11.0/...
  journal.tsv                         (transparency, §4.5)
```

Four roles, minimal thresholds, all dual-signed Ed25519 + ML-DSA-65 with
both signatures required (no single-signature accept option exists, for
the reason `internal/audit/sign.go` gives: a verifier that can be told
"one is enough" is a verifier that will be told so under time pressure):

| Role | Key | Expiry | Notes |
|---|---|---|---|
| `root` | offline, dual pair, threshold 1 pair | 12 months | trusts the targets/snapshot/timestamp keys; versioned chain; rotation in §4.3 |
| `targets` | online (release CI), dual pair | 90 days | lists every pack file by path with length and sha256 |
| `snapshot` | online, same release key as targets | 30 days | lists versions of `targets.json` |
| `timestamp` | online, same release key | 14 days | pins `snapshot.json` hash and version |

`snapshot.json` and `timestamp.json` may share the online key: TUF
separates the roles so an at-risk online key cannot freeze or mix
metadata; a single release key here can at worst replay old *consistent*
state, which version counters and expiry catch. The offline root key
never touches the release pipeline.

Metadata is canonical JSON (sorted keys, no insignificant whitespace) so
signatures are over stable bytes. The signing context string is
`vaigil/pack-metadata/v1` — domain-separated from the audit log's context
exactly as `internal/audit/sign.go` separates its own domains, so no
signature made for one purpose can be presented as another.

`timestamp.json`:

```json
{
  "signed": {
    "_type": "vaigil-timestamp-v1",
    "version": 4193,
    "expires": "2026-11-18T00:00:00Z",
    "snapshot": {
      "version": 381,
      "length": 24110,
      "hashes": { "sha256": "b6d1..." }
    }
  },
  "signatures": [{
    "key_id": "a91f...c",
    "alg": ["ed25519", "ml-dsa-65"],
    "ed25519": "base64...",
    "ml_dsa_65": "base64..."
  }]
}
```

`targets.json` entry for one pack file:

```json
"packs/vaigil.detections/2026.11.0/detections/entra.difficult-travel.json": {
  "length": 1834,
  "hashes": { "sha256": "77ac..." },
  "custom": { "pack": "vaigil.detections", "version": "2026.11.0",
              "channel_floor": "stable", "schemas": { "detections": 3 } }
}
```

The `custom` block lets a client refuse a pack by engine/schema version
before downloading it.

### 4.2 Client trust state and the update check

The binary pins the root **public** keys at build time (like a CT log's
pinned root) — the initial `1.root.json` is compiled in, and `vaigil
content keys` prints what is pinned. Client state lives in
`store/content-state.json`: highest root version seen, highest
snapshot/timestamp versions seen, per-pack last-applied version, pins and
holds. The check runs every 6 hours with jitter (and on `vaigil content
check`), pulls `timestamp.json` first, and the chain walk in §5.3
determines everything after that.

Mirrors are interchangeable and untrusted: any HTTPS mirror (or a USB
stick, or an internal file server) may serve the metadata, because trust
is in the signatures, not the transport. `content.mirrors` is a list;
clients try in order. A MITM or hostile mirror can serve stale or
mangled metadata — stale is caught by version counters (rollback) and
expiry (freeze), mangled by signature verification. This is the whole
TUF/Uptane argument and it is why the mirror list needs no special
protection.

### 4.3 Key rotation

Root rotation is a rare, deliberate act (annually, or on suspicion):

1. Generate the new offline dual pair from two 32-byte seeds (seeds, not
   encoded keys — the ML-DSA private key is kilobytes and a seed fits on
   paper; `internal/audit/sign.go` already works this way).
2. Sign `N+1.root.json` with **both** the old pair and the new pair
   (TUF's belt-and-braces: a client that missed the transition verifies
   the new root with the old, a client that already has it verifies it
   with itself).
3. Publish; keep every root version forever, so any client at any point
   in history can walk the chain forward.
4. Old root seeds are destroyed only after every supported binary has had
   a release cycle to see version N+1.

Online (release) key rotation is cheap and should be routine: rotate by
signing a new root that swaps the targets/snapshot/timestamp key, no
ceremony beyond the root signature. A compromised online key is contained
by exactly this: it can sign new releases (bad, and bounded by §5's
gates) but cannot rotate trust, cannot shorten expiries, and cannot
re-sign old metadata to roll clients back — the version counters in
client state, not in anything the mirror serves, are what rollback
protection compares against.

Root key compromise is the disaster case, and the honest answer is
section §7: recovery is a binary release with new pinned roots plus a
loud channel (the web manual, the README banner), because a pinned root
cannot be evicted by the attacker's own metadata. Open problem 3 (§9).

### 4.4 Expiry and freeze — what expiry does and does not do

Expiry protects the update path, never the running system. **Expired
metadata refuses new updates; it never disables installed content.** A
detection engine that switched itself off because a clock said so would
be a self-inflicted CrowdStrike — the content equivalent of bricking the
fleet. Concretely:

- A client whose freshest `timestamp.json` is past expiry stops applying
  updates, and raises a **finding**: "content frozen since 2026-11-04"
  (the `internal/feed` staleness-as-finding precedent: a scanner whose
  database stopped updating looks exactly like one with nothing to
  report, so staleness must be visible, not silent).
- The producer re-signs `timestamp.json` daily even when nothing was
  published — an idle repo otherwise impersonates an attack (freeze) and
  trains customers to ignore expiry.
- Air-gapped installs (§4.6) carry a fresh chain in the bundle; a bundle
  older than the timestamp expiry imports but warns, and the import is
  gated by the same replay pipeline as an online update.

Clock rollback on the client (an attacker rewinds the host clock to make
stale metadata valid again) is bounded by the version counters, which
only move forward in client state; the freeze finding's "since" date is
computed from the metadata, not the host clock, where possible.

### 4.5 Transparency anchoring

Every `timestamp.json` version's digest is appended to `journal.tsv`
(one line: version, digest, time) and the daily digest of that journal is
committed to Bitcoin through the existing OpenTimestamps machinery
(`internal/anchor`, already proven by `vaigil auditlog anchor`). This is
the Rekor property — witnessed, publicly verifiable signing events —
implemented with what the repo has:

- Anyone can detect a **split view**: two valid chains sharing a version
  number with different digests is cryptographic proof of malfeasance,
  checkable offline against the journal and the anchor.
- `vaigil content audit` walks the journal, verifies continuity, and
  checks the OTS proofs (pending vs anchored states, per `internal/anchor`).
- Backdating is not possible past an anchor; hiding a release from the
  journal is detectable by anyone holding the journal.

We do not build a gossip network (CT's hard part); a solo producer
publishing one journal, anchored daily, gets the property that matters:
the producer cannot later deny or reorder what it published, and a
compromised online key cannot serve two different histories to two
customers without leaving proof.

### 4.6 Offline and air-gapped

`vaigil content export --channel stable --packs all --freshness 7d >
bundle.vpb` writes one file: the full metadata chain (root history,
targets, snapshot, a freshly-signed timestamp — signed at export time by
the online key, so the bundle's freeze clock starts at export), all pack
files, and the journal with OTS proofs. `vaigil content import
bundle.vpb` on the air-gapped host verifies the identical chain from the
pinned root down and then runs **the same safety pipeline as an online
update** — schema, fixtures, replay against the local estate, budget. An
air-gapped customer gives up the network, not the gates. Import is
audited, dual-controlled (`internal/dual`), and is itself an action the
starter pack detects.

### 4.7 Why data-only is the whole sandbox answer

The question every content-delivering system eventually faces is "what
happens when content is malicious?" — and the industry answers it with
sandboxes, capability lists, resource caps, interpreter audits. Vaigil's
answer is that the question does not arise: **a pack is inert data**. No
plugin host, no scripting, no eval, no WASM, no expression grammar that
could grow one (the predicate is a closed tree of nine comparison
operators precisely because a string expression needs a parser and a
parser is where evaluation hatches — `internal/detect/rule.go` says this
out loud). The engines that consume packs are the same engines that
consume files a customer typed by hand; there is no second interpreter to
get wrong.

So the worst a *malicious but well-formed* pack can do, even signed, is:
raise wrong findings (bounded by replay + budget + rollback, §5), widen
what a connector reads (bounded by the manifest engine's own validation,
the `reads` allow-list and the install-time diff ack, per 03-integrations
§8.2), or aim an action at a new host (bounded by per-entry admin ack and
the two-person action rule). Every one of those is a decision a person
sees, not a memory-safety event. CrowdStrike's July 2024 was, at bottom,
content steering an interpreter into an out-of-bounds read; there is no
interpreter here to steer, and the consuming process is a memory-safe Go
binary where even a latent engine bug is a recoverable panic in a process
the supervisor restarts, not a kernel bugcheck on 8.5 million machines.

## 5. The safety pipeline

### 5.1 The ordered checklist

Every pack, online or imported, passes these gates **in this order** —
cheap and stateless first, empirical last, and nothing applies until
everything passes. The order is load-bearing: each early gate removes a
class of input the later gates would otherwise have to be trusted with.

1. **Metadata chain**: `timestamp.json` signature (both algorithms) →
   expiry fresh → snapshot hash matches → `snapshot.json` signature →
   version > last seen (rollback refuse) → `targets.json` signature →
   version matches snapshot. Root checked first if its version moved.
   Any failure: stop, keep current content, finding, no partial state.
2. **Bounds** (before parsing any pack body): pack ≤ 64 MiB, ≤ 5,000
   files, file ≤ 2 MiB, path ≤ 128 bytes of `[a-z0-9./_-]`, no symlinked
   or absolute or `..` paths, counts in manifest match reality. This is
   the "content bounds" lesson — refuse the weird before interpreting it.
3. **Manifest and policy**: schema versions known to this binary;
   `engine.minimum_binary` satisfied; channel floor acceptable for the
   customer's channel; `built.gates` present and passing. Refuse, keep
   current, say "needs a newer binary" or "written for a newer schema".
4. **Digests**: every file hash matches `targets.json`. (Transport
   integrity is free here; TLS was never the trust.)
5. **Schema validation**: every file decodes with
   `DisallowUnknownFields` and passes the **same `Validate()` the binary
   runs at load** — rule, correlation, mapping, connector manifest,
   action entry, playbook, eval case. There is deliberately no separate
   "content validator" binary or definition file: CrowdStrike's channel
   291 passed a Content Validator that validated against a Template Type
   Definitions file which disagreed with the compiled sensor. The only
   validator is the shipping engine.
6. **Fixtures**: every rule passes every fixture, must-match and
   must-not-match (already refused otherwise by `internal/detect`); every
   field the rule reads appears in a fixture (already enforced — this is
   the "wildcard in the 21st field" lesson: the fields that matter must
   be exercised, not presumed); mappings additionally pass against the
   stored sample records the customer already keeps; playbooks validate
   structurally.
7. **Producer replay record**: the manifest's `built.gates.producer_replay`
   must show the pack ran clean over the producer's estate corpus.
   (Customers cannot verify this; it is defence-in-depth and the
   release discipline of §5.2.)
8. **Shadow replay** (the customer's own gate, §5.3).
9. **Budget** (§5.4).
10. **Staged apply** (§5.5) — only now does anything change on disk, and
    atomically.

### 5.2 Producer-side discipline (the edge → beta → stable ladder)

The producer cannot see customer data, so its gates are its own corpus
plus time. Channels are cumulative bake periods:

- **edge**: pushed on merge; CI corpus replay must pass.
- **beta**: content that has lived on edge ≥ 7 days with no regression
  in the producer corpus replay.
- **stable**: content that has lived on beta ≥ 21 more days (28 total)
  without a fixture or corpus failure. Hotfix path: a detection for an
  active campaign may go stable in 72 hours with an explicit owner ack
  recorded in `built` — and it still faces every customer-side gate; the
  hotfix buys speed on the ladder, never a skip of §5.3.

This is the Wazuh/Sentinel "content on its own cadence" model with
CrowdStrike's post-incident "additional deployment layers and acceptance
checks" applied to a fleet of one producer.

### 5.3 Shadow replay against the customer's own telemetry

The trial-ring machinery already exists (`internal/detect/tuning.go`:
live/trial/off rings; `internal/detect/replay.go`: corpus replay with
caught/missed/wrong). The pipeline extends it:

- On a candidate pack, run new and changed rules in the **trial ring**
  over the last N days (default 7, `content.replay.days`) of the
  customer's stored telemetry, recording would-have-fired counts per
  rule, per entity, per day — outside the queue, exactly as a trial rule
  behaves today.
- Mappings replay against a sample of stored raw records
  (`source.Check`, already written) — a mapping that misses required
  paths or produces drift on the customer's actual pages is refused.
- Connector manifests are validated and diffed (hosts, `reads`, scopes)
  against the currently-installed version; a change to `reads` or `host`
  surfaces as an explicit ack item, never a silent apply.
- Findings raised in replay are never queued; the output is a report:
  per rule, "would have fired 4 times in 7 days; noisiest entity
  backup-svc".

Replay cost is real (open problem 1, §9) and the default N and sampling
rate are settings; what is not a setting is the gate itself.

### 5.4 The false-positive budget

Measured against the pre-update baseline (what the current content would
have fired over the same window), the pack auto-rolls-back — before
applying, or during staged apply — if any of:

- any single new or changed rule would have fired more than **100 times
  in the window**;
- total would-have-fired exceeds baseline by more than **50%** and more
  than **50 findings**;
- any rule would have fired on more than **25 distinct entities** in the
  window (a rule wrong about a whole class of machine, not one noisy
  service).

Defaults, not constants: `content.budget` tunable per estate, but with
floors (they cannot be raised above 10x by a setting change — a budget
that can be configured into meaninglessness will be, the same reason
`AcceptSingle` in the audit verifier defaults off and stays off). On
breach: the pack is not applied (or the ring is rolled back), a finding
explains which rule and what the numbers were, and the pack id/version is
**held** (§5.6) until a person releases it. A rollback is itself audited
and raises a finding — a content plane that silently rolled back would be
its own silence-failure.

### 5.5 Staged apply and automatic rollback

Apply is: new pack version lands in `store/packs/<id>/<version>/`,
working copies are updated per the fork rules (§3.4) via
`internal/atomicfile` (rename-based, fsynced — the two-process safe
write), the current-version pointer moves last, and the previous 10
versions are retained. New and changed rules **enter the trial ring for
48 hours** (`content.bake`) before automatic promotion to live — every
customer is its own canary ring, which is the honest version of
"1% rollout" for software that runs inside each customer's estate.

Automatic rollback triggers after apply: the FP budget measured on live
traffic over the bake window (same thresholds); a fixture regression
discovered by later telemetry; a parse failure of any pack file at load
(engine falls back to the previous version and raises a finding —
stale-but-working beats new-and-broken, the `internal/feed` argument).
Manual: `vaigil content rollback vaigil.detections` — instant, one
pointer move, audited.

### 5.6 The CrowdStrike lessons, one-to-one

| RCA finding (their words) | Concrete countermeasure here |
|---|---|
| "The number of fields in the IPC Template Type was not validated at sensor compile time" — the definition file and the compiled code disagreed (21 vs 20 inputs) | **No definition file exists to disagree.** The only validator is the shipping binary's own `Validate()`/loader (§5.1 step 5); producer CI lints packs by running the actual release binary, and unknown fields are refused by every decoder |
| "A runtime array bounds check was missing" — content indexed past the input array; out-of-bounds read; kernel bugcheck | **Content cannot index anything.** Predicates name fields from a closed set by string; depth ≤ 16; RE2 regexes (linear time, no backtracking); length caps on values and patterns; the consumer is a memory-safe userspace process, so even an engine bug is a restartable panic, not a fleet-wide crash |
| "Template Type testing should cover a wider variety of matching criteria" — every test used a wildcard in the 21st field, so the failing field was never exercised | **Fixtures must exercise every field the rule reads** — `Rule.Validate` already refuses a rule whose fixture set never emits a field it reads, and requires both a must-match and a must-not-match fixture; the same principle extends to mappings (must map their sample) |
| "The Content Validator contained a logic error" — it validated against what it *expected* (21 inputs), not what the runtime *provided* (20) | **Validation is the runtime, plus empirical replay**: the shadow ring (§5.3) checks content against the customer's real telemetry, which is the test CrowdStrike's synthetic 12 cases and stress instance were standing in for |
| "Template Instances should have staged deployment" — new content went to the whole fleet at once; no rings, no bake, no rollback | **Rings everywhere**: producer ladder (edge/beta/stable with bake), then every customer's trial ring with a 48h bake, FP budget with automatic rollback, and customer control — hold, pin, channel choice, release notes in `manifest.changes` (their sixth mitigation, verbatim: "customer control over the deployment of Rapid Response Content updates... release notes, to which customers can subscribe") |

The meta-lesson under all five: their content was *configuration for an
interpreter*. Ours is data for validators. The class of failure — content
steering an interpreter into undefined behaviour — is removed rather than
mitigated (§4.7).

## 6. Update mechanics

### 6.1 Channels, holds, pins

- `content.channel`: `stable` (default) | `beta` | `edge`. A channel move
  to a faster channel is a normal admin setting; there is **no setting
  that disables signature verification**, on the `AcceptSingle` principle
  — the option would be found and used.
- `content.mode`: `auto` (check, gate, apply) | `hold` (check and
  download, apply nothing — download-only is the air-gap-adjacent
  posture, and the CrowdStrike "customer control" ask implemented
  directly) | `off` (never check; a staleness finding appears after the
  timestamp expiry, because off must be visible, not silent).
- `content.pin.<pack-id>: <version>` — pin a pack at a version; updates
  to that pack are downloaded and reported but not applied until the pin
  is lifted. Used during change freezes and incident windows.
- Every mode change, hold, pin, apply and rollback is written to the
  audit log with who and why.

### 6.2 Cadence

Check every 6h with jitter (thundering-herd avoidance; also the Nuclei
at-most-daily precedent). `vaigil.detections` publishes weekly with a
hotfix path; mappings/connectors as needed; the whole plane is idle-safe
(timestamp re-signed daily regardless, §4.4).

### 6.3 Version negotiation with old binaries

Three independent floors, checked in this order, refuse-atomically:

1. metadata `custom.schemas` — binary must know the schema major of every
   content type in the pack (unknown ⇒ refuse, "written for a newer
   Vaigil");
2. `manifest.engine.minimum_binary` — semver floor;
3. pack-internal references — a rule reading a source the installed
   mappings do not provide fails fixtures at gate 6, not silently at
   runtime.

An old binary never half-applies: the pack is refused whole, current
content keeps running, and the Today screen says "content update
2026.11.0 needs Vaigil 0.10.0 (you run 0.9.3)". Forward compatibility
(binary newer than pack) is normal and expected.

### 6.4 What the customer sees

The Today screen carries a content line ("Content: detections
2026.11.0 · 3 new live, 1 tuned, 2 kept as your edits · mappings
2026.10.0"), an update event becomes an audit record and, the first time
after an apply, a dismissible card: **"Content updated — 3 new detections
live, 2 tuned. 1 rule was held back by the false-positive budget."** A
detail page shows the `changes` list with per-rule diffs (old/new
predicate side by side — reviewable data with a diff is the property that
makes model-authored rules safe, and it makes pack updates legible too).
The console, CLI and MCP views agree, per the repo's three-ways-in rule:
`vaigil content status` and a read-only MCP operation beside them.

### 6.5 Binary self-update: deliberately not now

The content plane never carries binaries. Reasons: (a) package managers
and the container image already do verified binary updates with rollback
habits operators know (`INSTALL`, `deploy/`); (b) self-updating a
long-running single binary inside a customer's estate adds a restart-time
failure mode the content plane was designed to avoid having; (c) the
solo-dev win is content cadence — binaries change monthly at most. If it
is ever added, it rides the same TUF metadata as additional targets with
their own expiry and a staged-restart protocol, and it is a separate
design document. `vaigil version --check` (reports, does not fetch) is
the only binary-update feature proposed here.

## 7. Community marketplace and the AI loop (N+2)

### 7.1 Third-party packs and the trust model

- Authors sign their own packs with their own keys (the same dual-sign
  format; `vaigil content keygen` gives every author the same tooling).
- The `vaigil.*` namespace stays first-party. Third-party ids live under
  `community/` targets, and the **root delegates** the `community/*`
  namespace to a registry key (TUF delegation, one level, no recursion):
  the registry co-signs what it has listed. A listed pack carries two
  independent signatures — author and registry — and the client policy
  for `community/*` requires both. Unlisted (author-only) packs install
  with an explicit trust-on-first-use screen naming the key fingerprint.
- Registry review is the SigmaHQ QA pipeline as a gate, plus the
  behaviours Sigma's pipeline cannot check: fixtures must exist and pass,
  the pack must replay clean over the registry's corpus, and — the
  part no community repository does today — the **customer's own shadow
  replay still applies**. The marketplace changes who writes content; it
  does not change the last gate.
- Revocation: a registry deny-list (signed, in the snapshot), plus
  per-customer `content.deny.<pack-id>`. An author key compromise is
  contained by the registry co-signature; a registry key compromise is
  contained by the root (rotate the delegation); both are bounded again
  by the customer-side budget — a malicious community pack can be loud,
  not destructive.

### 7.2 The AI-drafted detection loop

The precedent is already code: `internal/detect/tuning.go` computes
demote/promote/suppress proposals and never applies them, and
`Placement.Validate` refuses changes whose kind is AI. The loop:

1. A model (or a red-team exercise) proposes a rule as **data with a
   diff** — never more than that, per the package comment in
   `internal/detect`.
2. The proposal must arrive with fixtures the model also produced — and
   the gates do not trust them: fixtures are checked, then the rule is
   replayed over the estate in the trial ring, and the proposal records
   would-have-fired, noise concentration, and Wilson-interval precision
   if any verdicts exist.
3. A human promotes, edits, or rejects, on the record. Nothing is
   auto-deployed — not to live, not to a pack, not to the registry. A
   promoted rule is the customer's; a rule promoted by enough customers
   becomes a candidate for `vaigil.detections` through the ordinary
   contribution path.

This is the "red-team → rule loop" of the roadmap with the same shape as
everything above: the model proposes, the estate adjudicates, a person
decides.

## 8. Threat model

### 8.1 What each attacker can and cannot do

| Attacker | Can | Cannot |
|---|---|---|
| MITM / hostile mirror (no keys) | withhold metadata (freeze — detected at 14d expiry + staleness finding); serve mangled or stale metadata (signature + version counters refuse); serve truncated packs (digests refuse) | install content, roll back content, or hide that updates stopped |
| Thief of the **online release key** | sign *new* metadata and packs (the serious case) — bounded by: schema/fixtures gates refuse malformed content; the customer's replay + FP budget bound the damage of well-formed junk; journal anchoring makes the illegitimate releases publicly provable; root rotation retires the key | re-sign old metadata to roll customers back (client version counters); change trust (root key, offline); serve two histories without proof left in the journal; disable the customer's gates |
| Thief of the **offline root key** | full compromise: sign a new root, then anything | operate quietly — journal anchoring and the pinned-key binary release path (§4.3) evict it, and the customer-side gates still bound what content alone can do; recovery is a binary release + loud channel, honestly the worst case (open problem 3) |
| Malicious pack author (marketplace) | attempt loud content: FP floods (budget rolls back), over-broad rules (fixtures refuse unread fields; replay exposes), connector reads-widening (manifest engine validation + install diff ack) | execute anything (data-only, §4.7); carry credentials (validator refuses); suppress detections (suppressions are not content); touch the analyst plan or prompts (not content) |
| Compromised producer CI | sign garbage as the release key — same bounds as the stolen online key; `built.gates` is signed but self-attested, so this is the case the customer gates exist for | bypass the customer-side pipeline (it runs on the customer's binary, against the customer's data, from source the customer pinned) |
| Rollback attempt (serve version N-1) | nothing — refused by client state version counters | — |
| Freeze attempt (serve nothing / stale timestamp) | delay updates | detect: expiry + staleness finding; installed content keeps running |
| Clock manipulation on the customer host | make expiry checks lenient | defeat version counters (persisted, monotonic); the freeze finding quotes metadata dates, not the host clock, where it can |
| USB/air-gap sneak (tampered bundle) | nothing — the bundle verifies through the same pinned-root chain | bypass replay (import runs the full pipeline) |

### 8.2 Failure modes, ranked

1. **Signed but bad content at fleet scale** — a pack that passes every
   gate and still floods findings (the gates measured the wrong thing).
   Bounded by: trial-ring bake + FP budget + automatic rollback on every
   estate independently. Residual: a 48h window of noise.
2. **Online key compromise** — rogue releases. Bounded by customer gates,
   detected by journal anchoring, healed by root rotation. Residual: the
   attacker's releases were real releases.
3. **Root key compromise** — worst case; recovery needs a binary release
   (§4.3, §9). Bounded by: gates still apply to whatever the attacker
   ships, and data-only bounds what "ships" can mean.
4. **Freeze (producer goes dark)** — detected, visible as a finding,
   non-fatal; content keeps running. The operational risk is customers
   trained to ignore the finding — the `internal/feed` "two different
   silences" argument, inherited.
5. **Rollback/mix-and-match** — refused by construction (counters +
   snapshot + timestamp). Failure here would be a bug in the chain walk,
   which is why that walk is small, ordered (§5.1 step 1), and tested
   against every attack class in this table.
6. **Bad apply mechanics** (half-written files, crashes mid-apply) —
   bounded by atomicfile renames and pointer-last ordering; the previous
   version is always intact.

### 8.3 What the design refuses

Code execution in any form (plugins, DSLs, expression strings, WASM,
scripts). Network calls at content load (packs are read, never run).
Prompts. Suppressions and ring placements as content. Credential values.
Suppressing the safety pipeline by setting (budgets have floors,
verification has no off switch, `off` mode is a visible, finding-raising
posture). And a separate "content validator" artifact that could ever
disagree with the engine — the specific CrowdStrike failure shape.

## 9. Open problems

1. **Shadow replay cost.** Replaying a candidate pack over 7 days of the
   customer's stored events, per pack, per check, is the plane's
   compute-centre. The columnar storage engine is scheduled for N+1 and
   will carry most of it; until then, sampled replay (uniform over
   entities, all events for rules whose sources are rare) with the
   sampling factor recorded in the report. The gate is non-negotiable;
   its precision is the tunable.
2. **Fleet learning without fleet telemetry.** The producer learns a
   stable pack is bad only from customers who tell it, unless customers
   opt in to reporting aggregate rollback/budget events (counts only, no
   content of findings). The beta-ladder plus per-estate gates is the
   design's answer; an opt-in "content health report" (`content.report`)
   is the honest enhancement, and the decision of what it may contain is
   open.
3. **Root key ceremony for one human.** An offline root key, one
   operator, no committee: rotation discipline rests on calendar
   reminders; recovery from compromise rests on shipping a binary. Paper
   seeds in two locations + annual rotation + the pre-staged recovery
   procedure (drafted release notes, pinned-key PR ready) is the current
   answer; it should be pressure-tested before the marketplace opens,
   when third-party money makes the target bigger.

## 10. Go package layout

```
internal/pack/
  pack.go        Pack, Manifest, content-type registry, per-type bounds,
                 counts-vs-reality checks (the §5.1 step 2–3 gates)
  overlay.go     install with fork detection: baselines, user-wins merge,
                 fork records (§3.4)
  store.go       store/packs layout, version retention, current pointer,
                 rollback (atomicfile throughout)
  state.go       client trust state: versions seen, pins, holds, channel
internal/pack/meta/
  roles.go       Root/Targets/Snapshot/Timestamp structs, canonical JSON,
                 delegation records for community/*
  mirror.go      mirror list, fetch order, journal download
internal/pack/sign/
  sign.go        dual Ed25519 + ML-DSA-65 over metadata — the
                 internal/audit/sign.go pattern, context
                 "vaigil/pack-metadata/v1", both signatures required,
                 no single-signature option
  keys.go        seeds, KeyID (over both keys), publication, rotation
                 helpers (root chain N → N+1, belt-and-braces signing)
internal/pack/verify/
  verify.go      the chain walk — exactly §5.1 step 1, ordered, small,
                 tested against every §8.1 attack class
  bundle.go      air-gapped export/import, OTS proof checking,
                 journal continuity audit
internal/pack/replay/
  replay.go      shadow-ring orchestration over stored telemetry,
                 would-have-fired report, baseline comparison (uses
                 internal/detect Replay + rings; mappings via source.Check)
  budget.go      FP budget thresholds, floors, auto-rollback triggers
cmd/vaigil/
  contentcmd.go  content status | check | apply | hold | unhold | pin |
                 rollback | forks | export | import | keys | audit | lint
cmd/vapack/      producer-only tool (not shipped in releases; CI runs it):
                 assemble, lint (runs the release binary's validators),
                 corpus replay, sign metadata, journal append, anchor
```

Wiring notes: `ensureRules` grows into "install `vaigil.core` at the
embedded version, then behave like any pack" so a new store starts
current; settings live in the existing settings store (`content.*`); the
Today-screen card, the audit records, the staleness findings and the
`vaigil.content-updated` self-detection ride the existing UI, audit and
detection machinery. Nothing in `internal/connector`, `internal/detect`,
`internal/source`, `internal/incident` changes except gaining a caller —
that is the point of 03-integrations §8: the plane ships around files
that already exist.

## 11. Sources

- CrowdStrike, *External Technical Root Cause Analysis — Channel File
  291* (Aug 6, 2024) — local salvage
  `/home/rashik/vaigil-research/sources/pdf/cs-rca.txt`; canonical PDF
  https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf;
  announcement
  https://www.crowdstrike.com/en-us/blog/channel-file-291-rca-available
- TUF roles and metadata:
  https://theupdateframework.io/docs/metadata/ ; spec
  https://github.com/theupdateframework/specification/blob/master/tuf-spec.md ;
  client edge-case testing
  https://theupdateframework.github.io/python-tuf/2022/06/15/testing-ngclient.html
- Uptane: standard
  https://uptane.org/docs/1.1.0/standard/uptane-standard ; threat model
  https://uptane.org/learn-more/threat ; escar '16 paper
  https://ssl.engineering.nyu.edu/papers/kuppusamy_escar_16.pdf
- Sigstore: signing overview (Rekor witnessing)
  https://docs.sigstore.dev/cosign/signing/overview ; keyless/Fulcio/Rekor
  https://blog.sigstore.dev/why-you-cant-use-sigstore-without-sigstore-de1ed745f6fc
- in-toto / SLSA: https://slsa.dev/blog/2023/05/in-toto-and-slsa ;
  provenance https://slsa.dev/provenance
- Go `crypto/mldsa` (FIPS 204, Go ≥ 1.26):
  https://pkg.go.dev/crypto/mldsa ; tracker
  https://github.com/golang/go/issues/77626 ; FIPS 204
  https://csrc.nist.gov/pubs/fips/204/final
- Splunk ES Content Update (ESCU):
  https://community.splunk.com/t5/c-oqeym24965/Splunk+ES+Content+Update/pd-p/3449 ;
  release notes
  https://community.splunk.com/t5/Product-News-Announcements/Enterprise-Security-Content-Update-ESCU-New-Releases/ba-p/679519
- Elastic detection-rules: repo
  https://github.com/elastic/detection-rules ; decoupling blog
  https://www.elastic.co/blog/security-prebuilt-rules-editing ;
  version-pinning discussion
  https://discuss.elastic.co/t/prebuilt-security-detection-rules-in-policy-or-just-install-assets/312959
- Microsoft Sentinel Content Hub: docs
  https://learn.microsoft.com/en-us/azure/sentinel/connect-data-sources ;
  issue tracker (customisation-overwrite class)
  https://github.com/Azure/Azure-Sentinel/issues
- Wazuh ruleset: separate-repository history
  https://github.com/wazuh/wazuh-ruleset ; automatic ruleset updates
  https://wazuh.com/blog/keep-your-ruleset-updated-automatically ;
  disabling them https://github.com/wazuh/wazuh/discussions/17456
- SigmaHQ QA pipeline: https://blog.sigmahq.io (Quality Assurance
  Pipeline, Nov 2025); a practitioner's CI stages
  https://andreafortuna.org (validate → translate → test)
- Nuclei templates: versioned releases, ≤24h update check — engine docs
  and setup walkthroughs, e.g.
  https://tech-insider.org/nuclei-vulnerability-scanner-setup-2026
- Trivy DB: docs https://trivy.dev/docs/latest/configuration/db ; repo
  https://github.com/aquasecurity/trivy-db ; update-pipeline CVE-2026-33634
  https://nvd.nist.gov/vuln/detail/CVE-2026-33634
- In-repo prior art: `internal/audit/sign.go` (dual signing, domain
  separation), `internal/detect/{rule,tuning,replay,pack}.go` (fixtures,
  rings, corpus replay, starter pack), `internal/detect/pack/*.json`
  (`vaigil.*` naming), `internal/source/known.go`, `internal/action/catalogue/`,
  `internal/incident/playbook.go`, `internal/feed` (staleness as finding),
  `internal/anchor` (OpenTimestamps), `internal/atomicfile`,
  `cmd/vaigil/detectpack.go` ("left alone" install semantics),
  [03-integrations §8](03-integrations.md).
