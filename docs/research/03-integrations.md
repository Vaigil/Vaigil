# Integrations audit — connectors, sources, credentials, egress, portability, roadmap

Date: 2026-10-25 · Scope: `internal/connector`, `internal/source`, `internal/inbound` + `internal/ssf`, `internal/vault` + `internal/secret`, `internal/fetch` + `internal/egress`, `cmd/vaigil/{connectcmd,collectcmd,inboundserve,exportcmd,vaultcmd,actioncmd,detectpack}.go`, export surface (`internal/{siem,auditstream,sigma,sarif,sca,indicator,vuln}`). All findings cite file:line as of this tree.

---

## 1. Executive summary

Vaigil's integration layer is architecturally unusual and unusually disciplined: **there is no per-tool code**. A connector is a declarative JSON manifest (host, auth kind, endpoints, pagination, field allow-list) executed by one generic engine (`internal/connector`), and a log-source mapping is a declarative JSON document (dotted paths, required paths, outcome convention, declared lateness) applied by one generic mapper (`internal/source`). The security properties that matter are enforced by the engine, not by each integration:

- One HTTPS host per connector, validated against URL/wildcard/userinfo/port/IP-literal/local-name tricks (`internal/connector/manifest.go:576-625`).
- Server-chosen next-page URLs are host-checked and a mismatch ends the run (`internal/connector/run.go:226-235`) — the SSRF-via-pagination class is closed by design.
- Reads are GET-only from a closed set; the one POST in the system is the OAuth token exchange, to a declared host, with no redirect following (`internal/connector/session.go:160-275`, `internal/egress/egress.go:321-328`).
- Every field a connector may keep is declared under `reads`, and the map may not touch anything else — the Drift-style "integration harvested support-case text" failure is structurally excluded (`manifest.go:372-378, 853-887`, `run.go:459-477`).
- Forbidden-field lists refuse passwords, recovery keys, private keys, coordinates, and location history regardless of what the scope allows (`manifest.go:933-949`).
- Scopes/roles must be read-shaped, and for Entra the token's own roles claim is parsed and a token holding undeclared permissions is refused before use (`manifest.go:748-804`, `session.go:285-321`).

Ratings: **7 of 8 connectors are solid and secure** under the manifest engine (Okta, Entra, GitHub, KnowBe4, Endpoint Central, MDM Plus, Vanta); the EVM/Blockscout connector is **partial by admission** — the explorer offers no "since" parameter, so it reads the newest page and can silently miss bursts, which it reports as a gap rather than hiding (`catalogue/evm.json:39`, `cmd/vaigil/collectcmd.go:487-492`).

The main weaknesses found are not in the manifest engine but around it:

1. **Connector dials do not pass the IP blocklist that `internal/fetch` enforces.** `connect run` uses `egress.Client("connector", …)` (`cmd/vaigil/connectcmd.go:382-384`), whose transport enforces the network mode and refuses redirects (`egress.go:298-329`) but installs no `net.Dialer.Control` hook — the metadata/link-local/private-range check lives only in `internal/fetch` (`fetch.go:473-509`). TLS name verification makes actual exploitation hard, but defense-in-depth against a hostile DNS answer is present on one outbound path and absent on the other.
2. **Credential plaintext fallback.** With no keyring enabled, `connect secret` stores values in cleartext in `connect/secrets.json` (`connectcmd.go:306-311`) with only a printed warning. The vault itself (AES-256-GCM envelope, per-object DEK, AAD-bound, rewrap rotation) is good.
3. **Inbound replay defence is in-memory only** (`internal/inbound/inbound.go:230-275`), and the GitHub signature scheme carries no timestamp, so a captured delivery replayed after a restart within the retention window is only defended by luck.
4. **Several built-in source mappings reference array-valued paths the mapping language cannot read** (CrowdStrike `behaviors.*`, Kubernetes `sourceIPs`, `annotations`), which either silently produce empty observables or — for CrowdStrike — would fail its own `Require` list against the real Falcon payload shape. The package's founding failure mode ("mapping keeps working, fields quietly empty") exists in three of its own built-ins.
5. **No-lock-in is half-done**: the audit log exports to OCSF/CEF/JSONL with verifiable chain envelopes and an RFC 9421-signed stream, and VEX decisions export as OpenVEX; but telemetry events, findings, detection rules (no Sigma export), and playbooks (no CACAO) have no export path. A customer can leave with their audit trail and their vulnerability decisions, not with their detections or their event history.

For the owner's vision, the highest-leverage next moves are cheap because of the manifest design: OpenAI/Anthropic audit APIs, Slack audit logs, JumpCloud, Auth0 and Bedrock/Vertex detection content are all data-only (manifest + mapping + rules) or near-data-only. The genuinely new code work is OTLP/OTel-GenAI ingestion, a signed-JWT auth kind (Google), SigV4 (AWS posture APIs), and declared-POST actions (Teams/PagerDuty response).

---

## 2. Connector inventory and per-connector review

### 2.1 The engine every connector runs through

Before the per-connector notes, what is shared — because each connector's security posture is mostly this engine.

| Property | Mechanism | Citation |
|---|---|---|
| TLS | https only, default verification (no `InsecureSkipVerify` anywhere in the tree — grep), hostname from `checkHost` | `manifest.go:576-625` |
| Auth kinds | none / bearer / header / basic / oauth-client / oauth-refresh | `manifest.go:96-116` |
| Read-only enforcement | GET-only pages; scopes must end `:read`/`.read` and contain no write/update/delete/create/admin/manage/upload; MS app roles checked per-action for Read; Entra `.default` tokens inspected, undeclared roles refuse the token | `manifest.go:748-804`, `session.go:285-321` |
| SSRF surface | host = one DNS name (no IP literals, no ports, no wildcards, no local suffixes); endpoints = absolute paths only (no `..`, no `://`); per-record `{key}` must match `^[A-Za-z0-9._:~-]{1,128}$` and is `url.PathEscape`d; next-URL host must equal declared host or the run ends; catalogues fill params only from closed region lists with per-param regexes (tenant GUID / one DNS label / 0x+40hex) | `manifest.go:576-625, 975-992`; `run.go:382, 226-235`; `catalogue.go:59-67, 119-184` |
| Pagination | 4 strategies (cursor, next-url, offset, page) + one-page; cursor loop detection; `more` flag for cursor-on-last-page; `Link` header parsed per RFC 8288 rel=next | `manifest.go:237-294`, `run.go:181-305` |
| Checkpointing | `since` param + `watermark` path (+ `since_as` filter template with checkpoint shape regex; `epoch-ms` layout conversion); watermark advances **only on a complete run**; first incremental read starts one day back | `session.go:364-375`, `run.go:43-49, 159-175`, `collectcmd.go:443-463` |
| Error handling | 401 → one token re-fetch; 429/5xx → Retry-After, then draft RateLimit (`t=`/`reset=`), then vendor headers, then exp backoff with jitter, capped 2m, max 4 attempts; non-2xx → status-only error (bodies never echoed into logs) | `session.go:574-663`, `run.go:323-417` |
| Budgets | tool-level + endpoint-level rate spacing; daily budget persisted across runs in `connect/budget.json`; ceilings 1000 pages / 200k records / 32MiB body / 2m timeout per request | `manifest.go:77-93`, `session.go:105-126`, `connectcmd.go:554-567` |
| Schema fidelity | `UseNumber()` decode so >2^53 device ids survive; absent records-path is an error, not an empty estate; null vs absent distinguished; only declared fields copied out of a response | `session.go:665-683`, `run.go:419-450, 459-477` |
| Credential hygiene | manifests hold credential *names*; `Validate` refuses anything that looks like a pasted token; token responses capped at 64KiB; access-token charset checked before it goes into a header; token endpoint errors echo only the OAuth error code | `manifest.go:425-446`, `session.go:142-151, 325-335` |

One structural caveat that applies to all of them: the fan-out model (`Each`) is one level deep and multiplies requests (Endpoint Central is "three or more requests per computer", `catalogue/endpointcentral.json:30`), bounded only by page/record ceilings and the daily budget — there is no per-run wall-clock budget other than the per-request timeout, so a large estate's nightly `estate sync` is long but bounded.

### 2.2 Per-connector findings

| Connector | Auth | Collection model | Resumable | Fidelity | Rating |
|---|---|---|---|---|---|
| **Okta** | SSWS bearer (API token of a Read-Only Administrator) | 3 regions (`{org}.okta.com` etc.); people + leavers + system log; Link-header next-URL; 100 req/min | Yes — `since` + `published` watermark, ASCENDING | Good (13 system-log fields; geolocation limited to country by policy) | **solid / secure** |
| **Microsoft Entra ID (+Intune)** | OAuth client-credentials, `.default` scope, roles claim enforced | people / devices / signIns; `$select` everywhere; `@odata.nextLink`; 5 req/s | Yes — `$filter=createdDateTime ge {since}` + watermark | Good (sign-in risk level, CA status, failure reason kept) | **solid / secure** |
| **GitHub** | Bearer (fine-grained PAT / classic `read:audit_log`) | org audit log only; Link next-URL; 60 req/min | Yes — `phrase=created:>={since}`, `@timestamp` epoch-ms watermark | Narrow but complete for audit events (9 fields incl. `actor_ip`, `_document_id` dedupe) | **solid / secure** |
| **EVM (Blockscout)** | none (public explorer) | 6 chains; newest ~50 events of one contract; no `since` capability in the API | **No** — newest-page only; gaps reported as `Gap` | Decoded method + up to 3 args; verified-contract caveat noted | **partial / secure** |
| **KnowBe4** | Bearer reporting key | 5 regions; users / enrollments / phishing tests / per-test recipients (180-day window); page-number pagination; 4/s, 50/min, 2000/day | Snapshot (no watermark; dedupe downstream via digest) | Rich (phish-prone %, risk score, per-recipient click timeline; click IP/location/browser deliberately not read) | **solid / secure** (pagination migration risk noted for Nov 2026) |
| **ManageEngine Endpoint Central** | OAuth refresh (Zoho accounts per DC), `Zoho-oauthtoken` | computers + per-computer encryption/posture/software + vulnerabilities (explode); 100/min global, 25/min vulns | Snapshot | Good; BitLocker keys/credentials refused by forbidden lists; `invsw\.software_name` dotted-key escaping exercised | **solid / secure** |
| **ManageEngine MDM Plus** | OAuth refresh, `MDMOnDemand.MDMInventory.READ` | devices + per-device security + apps; 60/min; 2 req/device | Snapshot | Good; >2^53 device ids preserved exactly; locations/firmware passwords never read | **solid / secure** |
| **Vanta** | OAuth client-credentials (JSON body), `vanta-api.all:read` | people / computers / tests / policies; cursor + `hasNextPage`; one live token per app handled by session-scoped token reuse | Snapshot | Good (task/training/policy status per person; per-test outcomes) | **solid / secure** |

Details worth recording per connector:

**Okta** (`internal/connector/catalogue/okta.json`)
- Auth: `{"kind":"bearer","scheme":"SSWS"}` (okta.json:26-29); the credentials note demands a Read-Only Administrator's token because an Okta token can do whatever its maker can (okta.json:20).
- `org` param is one DNS label (`catalogue.go:64`) so `{org}.okta.com` cannot be steered off okta.com; regions closed-list (okta.json:5-15).
- Deprovisioned users need a separate endpoint because the default list omits them (okta.json:34, 70-98) — the leaver-reconciliation case was thought through.
- System log reads `target.0.id` and maps it to `target.id` (okta.json:141) — the numeric-index convention the mapping language supports.
- Lateness/mapping: `internal/source/known.go:135-156` (`okta/system`, 5 min lateness).

**Entra** (`catalogue/entra.json`)
- Token path `/{tenant}/oauth2/v2.0/token` (entra.json:27) with tenant a GUID (catalogue.go:62) — deliberately excludes `organizations`/`common`.
- The `.default` scope is accepted only because roles are verified on the token itself: extra app permissions abort the connector with instructions to remove them (entra.json:32-43, `session.go:285-321`). This is the right answer to Graph's permission model.
- signIns: `$top=500`, `$orderby=createdDateTime asc`, `$filter=createdDateTime ge {since}` via `since_as` (entra.json:126-140) — both filter and orderby on the same field, which is the combination Graph permits.
- Devices endpoint 403 without Intune is tolerated by design (entra.json:43).

**GitHub** (`catalogue/github.json`)
- Single endpoint; `include=all`, `order=asc`, `per_page=100` (github.json:32-36); epoch-ms watermark converted to RFC3339 and sent as `created:>={since}` inside the `phrase` parameter (github.json:43-46, `run.go:159-175`).
- Requires GitHub Enterprise Cloud (audit log API not on other plans) — stated in `about` (github.json:3).
- Fine-grained PAT guidance in credentials (github.json:14).

**EVM / Blockscout** (`catalogue/evm.json`)
- `auth: none`, public data, six public explorers (evm.json:5-24). The honesty in the note is the best part: the API returns the newest 50 events with no since-filter, so a contract emitting more than that between reads is read incompletely, "and the read says so" (evm.json:39).
- The gap is surfaced: a page where every record was new sets `Gap` in collect status (`collectcmd.go:487-492`).
- Mapping `evm/logs` requires `signature` but keeps decoded `event` only when present (verified contracts) — `known.go:492-511`.

**KnowBe4** (`catalogue/knowbe4.json`)
- Daily budget of 2000/day declared and enforced across runs (`knowbe4.json:20`, `connectcmd.go:554-567`) because the budget is shared with the customer's own console reports — unusually thoughtful.
- Page-number pagination retires November 2026; the note documents the exact manifest edit and the `probe` command to discover the new cursor header (knowbe4.json:21). This is the one dated time-bomb in the catalogue.
- Phishing recipients are read per test within 180 days (`each.when/within_days`, knowbe4.json:72) — the fan-out window keeps request counts sane.

**Endpoint Central** (`catalogue/endpointcentral.json`)
- Seven data centres with paired token hosts (endpointcentral.json:6-13) — the region-closure design exists precisely because ManageEngine accounts are DC-pinned.
- `explode` used for per-computer vulnerabilities with `^.resource_id` parent reach (endpointcentral.json:92-105) — the only connector using explode.
- Deprecating `/api/1.4` paths avoided; Accept-versioned media types used where required (endpointcentral.json:36, 78).

**MDM Plus** (`catalogue/mdmplus.json`)
- The documentation's non-resolving `www.mdm.manageengine.com` corrected in the manifest note (mdmplus.json:30) — evidence the hosts were actually exercised.
- Device ids past 2^53 kept exactly by `UseNumber()` (`session.go:665-683`) — a correctness trap the code documents from a real incident shape.

**Vanta** (`catalogue/vanta.json`)
- JSON-body token exchange (`body: "json"`, vanta.json:20); one live token per application is why the session caches its token and re-fetches only once on a 401 (`session.go:26-33, 609-620`).
- Cursor pagination with `more` to avoid the trailing empty request (vanta.json:30); cursor loop detection in the engine (`run.go:196-198`).

### 2.3 Issues found in the connector layer

- **C1 (medium) — connector dials skip the address blocklist.** `client(timeout)` returns `egress.Client("connector", timeout)` (`connectcmd.go:375-384`). `egress.Client`'s transport dials through `egress.Dial` (mode + purpose only, `egress.go:298-329`); the `Control`-hook check against link-local/private/metadata ranges exists only in `internal/fetch`'s dialer (`fetch.go:473-509`). A malicious DNS answer for a declared vendor hostname could connect the socket to `169.254.169.254`; the TLS handshake would then fail cert verification (the name wouldn't match), so this is defense-in-depth, not an exploitable path today. Fix: route connector sessions through `fetch.Speaking("connector", …)` or add the Control hook to `egress.Client`.
- **C2 (low) — `connect probe` is neither authorised nor audited.** Every other credential-touching subcommand resolves a caller and checks `auth.ActGrant` (e.g. `connectcmd.go:341-343, 475-478, 769-771`); `connectProbe` (`connectcmd.go:390-442`) loads secrets and sends an authenticated request with no `authorise` and no audit record. Probe output is field-names only (good, `connectcmd.go:415-441`), but the invocation itself should be an audit event.
- **C3 (low) — token-endpoint exchange not covered by `fetch`'s no-redirect guarantees on all paths.** The session exchanges use the same egress client (no redirects, `egress.go:321-328`), which is correct; noting for the record that this property must survive any future switch of the connector client (see C1) — `fetch.PostForm` also refuses redirects (`fetch.go:598-600`).
- **C4 (info) — no per-credential-use audit granularity.** `connect.run` records host/records/pages/field-names per endpoint (`connectcmd.go:592-601`) — good — but there is no "credential X was used by run Y" linkage; the audit record names the connector, not the credential. Sufficient for review, worth noting for forensics.

---

## 3. Log-source mappings (`internal/source`, `internal/inbound`)

### 3.1 How mappings are declared

A `Source` is a JSON-serialisable struct: issuer/stream, OCSF class + activity (optionally selected by a `From` path + `Activities` map), mandatory `Time` path + explicit `Layout` (RFC3339 variants, `epoch-s`, `epoch-ms`), Actor/Target/Device/Person paths, an `Outcome` path with one of three conventions (Failed list / Succeeded list / presence-is-failure), `Observables` by kind, `Require` and `Keep` lists, and a mandatory `Lateness` capped at one hour (`source.go:59-149`). Validation refuses: non-lowercase issuers (join-breaking), missing layout, both Failed and Succeeded, zero `Require`, a required path nothing reads, lateness 0 or > 1h (`source.go:152-248`).

The Miss/Drift machinery is the package's raison d'être and is real: a record missing a required path yields a `Miss`, never a holey event (`source.go:271-285`); a batch failing >5% on one path is "drifted" with a sentence naming the field (`run.go:72, 96-111`); health across batches distinguishes a bad page from a changed source (`run.go:149-215`); a quiet source is reported as indistinguishable from a dead connector (`run.go:161-169`). `Check` runs a mapping against real sample records without storing events (`run.go:224-237`), and `vaigil source add MAPPING.json --sample RECORDS.json` refuses to install a mapping that maps none of its sample (`collectcmd.go:167-241`). Issuer agreement between mapping and manifest is checked because a mismatch silently breaks every workforce join (`run.go:246-255`).

Custom mappings are **data files** in `sources/`, validated on load, rejected on name collision with built-ins (`collectcmd.go:111-145`).

### 3.2 The 17 built-in mappings and quality

| Source (issuer/stream) | Class | Lateness | Outcome convention | Kept fields | Assessment |
|---|---|---|---|---|---|
| aws/cloudtrail | API activity | 15m | presence of `errorCode` = failure | 7 | OK but thin — no `requestParameters`/`responseElements`, so "which policy was attached" is invisible to detections |
| entra/signin | Authentication | 10m | `status.errorCode == 0` | 9 | good |
| workspace/login | Authentication | 30m | `login_failure` in events.name | 4 | login events only; admin/SAML/token audits absent |
| okta/system | Authentication | 5m | FAILURE/DENY list | 6 | good; `debugContext` (risk reasons) dropped |
| azure/activity | API activity | 20m | Failed/Failure list | 6 | fine |
| gcp/audit | API activity | 10m | status.code presence | 6 | fine |
| duo/auth | Authentication | 5m | success list | 7 | auth log only; admin/telephony logs absent |
| crowdstrike/detections | Detection | 2m | — | 6 | **see finding S1 — array paths likely break against real payloads** |
| jamf/events | Account change | 10m | — | 5 | thin; webhook-shape only |
| github/audit | API activity | 5m | — | 5 | fine |
| kubernetes/audit | API activity | 2m | HTTP 2xx list | 6 | **S1: `sourceIPs` observable dead; `annotations` keep dead** |
| cloudflare/firewall | HTTP activity | 3m | allow/log/skip list | 6 | firewall events only; no Logpush/access logs, no account audit log |
| salesforce/login | Authentication | 15m | Success list | 7 | login history only; no Event Monitoring objects |
| slack/audit | API activity | 10m | — | 3 | thinnest mapping; entity details and session context dropped |
| snowflake/logins | Authentication | 30m | YES list | 6 | logins only; no QUERY_HISTORY |
| auditd/events | Process activity | 1m | success list | 8 | appropriate minimalism for shipper variance |
| evm/logs | API activity | 10m | — | 12 | good |

**S1 (high for fidelity, medium overall) — array-valued paths in built-ins resolve to empty, or fail.** The path language reads arrays only by literal index (`path.go:76-93`). Three mappings reference array fields as if scalar:
- `crowdstrike/detections`: Actor `device.hostname` is fine, but Target `behaviors.filename`, observables `behaviors.sha256`, and Keep `behaviors.tactic/technique/pattern_disposition` (`known.go:296-305`) read nothing when `behaviors` is the array the Falcon detections API returns — and `Require` includes `behaviors.description` (`known.go:301-302`), so **every real Falcon detection would be a Miss** and the source would report 100% drift. Either the intended input is a flattened per-behavior record (undocumented) or this mapping has never run against the real API.
- `kubernetes/audit`: observable `sourceIPs` (`known.go:364-366`) — `sourceIPs` is an array in audit records; `asString` renders arrays as `""` (`path.go:135-141`), so the IP observable is always empty. Same for Keep `annotations` (`known.go:371`) — an object, silently dropped.
- Fix options: a `first:` or `*.field` semantics for single-element intent, or numeric indices in the built-ins, plus a `Validate` rule that a path resolving through an array at install time is explicit.

**S2 (info) — thinnest mappings**: slack/audit (3 kept), jamf (5), cloudflare/firewall (6, no account-audit stream), salesforce (login-only). For a startup-first product the high-value gaps are Slack workspace-admin audit detail and Cloudflare account/zone audit log (the "who changed the WAF" question), both of which are additive `Keep`/`Require` work or a second stream per tool.

### 3.3 Inbound (push) auth robustness

Four schemes on `/feeds/{name}` (`cmd/vaigil/inboundserve.go:532-577`):

| Scheme | Verification | Replay defence | Notes |
|---|---|---|---|
| Okta event hook | static secret in Authorization header, SHA-256 digest stored, constant-time compare (`inbound.go:129-135`) | eventId dedupe, in-memory | challenge echo whitelists charset + escapes (`inbound.go:283-297`); ≤1000 events per delivery (`inbound.go:317`); secret is the whole proof — Okta signs nothing, and the code says so (`inbound.go:8-13`) |
| Standard Webhooks | HMAC-SHA256 over `id.timestamp.body`, `whsec_` base64 key 24–64 bytes, multiple `v1` sigs for rotation (`inbound.go:155-201`) | ±5 min timestamp **and** id dedupe | best of the four |
| GitHub | `X-Hub-Signature-256` HMAC, hex, secret ≥16 bytes (`inbound.go:206-228`) | **id dedupe only** — no timestamp in GitHub's scheme | replay window bounded only by the in-memory cache |
| SSF/CAEP/RISC (RFC 8417/8935) | JWT verified by the OIDC token verifier: alg from agreed list (never from token), `secevent+jwt` typ, exact issuer, audience membership, exactly one event, jti, iat age (default 72h) (`internal/ssf/ssf.go:16-120`) | jti dedupe, in-memory | stream verification challenge + stream-updated handled (`inboundserve.go:698-721`); JWKS fetched under the `signals` purpose |

Per-feed rate limit 3000 deliveries/min, body caps 1 MiB (webhooks) / 64 KiB (SSF), queue 10k, writes to the append-only spool before 2xx semantics (`inboundserve.go:256-262, 506-577`). Refusals are counted on feed status rather than the audit log to prevent an attacker choosing how fast the log grows (`inboundserve.go:480-491`) — a deliberate and correct trade.

**S3 (medium) — replay cache is process-local.** `inbound.Seen` is a bounded in-memory map (`inbound.go:230-275`); a restart within the 24h keep window re-accepts a replayed delivery id, and for the GitHub scheme there is no timestamp check to fall back on. Persisting seen-ids (e.g., into the spool's metadata with the same 24h horizon) closes it.

**S4 (low) — SSF static bearer is optional** (`f.TokenHash != ""` guard, `inboundserve.go:669`): a stream configured without a token hash relies on JWT verification alone, which is actually sound (signature + iss + aud + jti); fine, but worth a doc line so admins don't disable it thinking it's the auth.

---

## 4. Credential storage (`internal/vault`, `internal/secret`, `cmd/vaigil/vaultcmd.go`)

**Sealing.** AES-256-GCM envelope encryption: a fresh random 32-byte DEK per secret, used once (nonce reuse structurally impossible), DEK wrapped by the active KEK, ciphertext + wrapped key stored as readable JSON (`vault.go:86-102, 189-228`). AAD binds each sealed object to its address — `connect/<name>` (`connectcmd.go:293, 266`) — so a swapped file fails to open (`vault.go:194-200`). Version guard refuses unknown formats; wrong-size keys are refused rather than padded (`vault.go:387-402`).

**Master key.** Never on disk beside the data and never in code: `VAIGIL_KEY` (base64), `VAIGIL_KEY_FILE`, or `VAIGIL_KEY_CMD` — the command form is the KMS/HSM/password-manager/Yubikey hook, run through `/bin/sh` (`vaultcmd.go:84-107`). Key material printed exactly once at `vault enable` (`vaultcmd.go:255-284`). No KDF/password-derived keys — an operator must supply 32 random bytes; that refusal to stretch is documented as deliberate.

**Rotation.** `vault rotate` adds a KEK id and retires (not deletes) the old one; `vault rewrap` re-wraps DEKs to the active key without decrypting bodies (`vault.go:144-169, 262-296`; `vaultcmd.go:291+`). Multiple keys can be supplied as `id=base64` pairs mid-rotation (`vaultcmd.go:75-80`).

**Audit of use.** `connect.secret` records the credential name and sealed-ness, never the value (`connectcmd.go:351-356`); `connect.run` records host/pages/records/field-names per endpoint (`connectcmd.go:592-601`); `vault.enable`/`rotate` are audited with KEK id (`vaultcmd.go:264-270`). The `internal/secret` scanner (credential shapes + entropy-confirmed assignments, `secret.go:28-104`) is what masks credentials before model prompts and is reused as a defence in depth by the audit layer's detail-key refusal.

**V1 (medium) — plaintext fallback is the default until `vault enable` runs.** `storeSecret` writes the value into the `plain` map when no keyring exists (`connectcmd.go:306-311`), and `loadSecrets` reads it back happily. The warning exists (`connectcmd.go:361-363`) and `init`/first-run could push harder: consider refusing to store connector credentials at all without a keyring, or sealing with a machine-local key by default and requiring explicit `--insecure-plaintext` to opt out.

**V2 (low) — file permissions are right (0600 secrets, 0700 connect dir, `atomicfile.Write`)** — verified at `connectcmd.go:316, 673-677`; no issue, recorded as a check performed.

---

## 5. HTTP fetch layer and egress control (`internal/fetch`, `internal/egress`)

- **Purposes system**: a closed list of 10 reasons this program opens a connection (model, webhook, anchor, mail, slack, siem, action, connector, signals, sso), each carrying what it is for and what breaks without it (`egress.go:87-164`). A fetch with no purpose is refused outright (`fetch.go:241-243, 521-527`); an unlisted purpose is refused in every mode (`egress.go:248-258`). `Offline` mode refuses every off-host dial with an error naming the feature, and counts refusals per purpose for the auditor report (`egress.go:212-227, 350-395`). A test walks the source to ensure nothing builds a client outside these packages (comment at `egress.go:96-98`).
- **DNS rebinding defence**: the check and the connection are one operation — `net.Dialer.Control` inspects the exact address being dialled, after resolution, before connect (`fetch.go:473-487`); every DNS answer is checked, not the first (`fetch.go:551-559`). This is the correct construction, and redirect connections go through the same dialer.
- **Redirects**: `Get` follows at most 2 hops, each revalidated against the same URL/address rules (`fetch.go:419-429`); every POST-bearing method refuses redirects outright — form posts, JSON posts, signed webhooks, protocol speakers, and `egress.Client` itself, with the rationale that a redirected POST replays the body (and any secret in it) to an unapproved host (`fetch.go:598-600, 674-676, 727-729, 784-786, 836-838`; `egress.go:315-328`; `speaking.go:180-187`).
- **TLS**: https-only, userinfo refused (parser-disagreement rationale, `fetch.go:371-381`), standard chain verification; no insecure-verify flag exists anywhere in the tree.
- **Size/timeout ceilings**: 32 MiB default body, 20s exchange timeout, 10s dial/TLS, 15s response-header (`fetch.go:77-90, 498-503`); protocol speakers' response bodies discarded capped at 64 KiB (`fetch.go:805, 847`).
- **Reach rules for non-public endpoints**: `OnThisNetwork` (loopback+private, never link-local), `Within(declared ranges)` where `Declarable` refuses anything overlapping metadata or wider than one private block (`speaking.go:80-120`, `fetch.go:186-239`) — an MCP server on the org network is declarable, `169.254.0.0/16` never is.

The one gap is C1 above: the connector and action paths use `egress.Client`, which enforces mode+purpose+no-redirects but not the address ranges. Everything user-URL-driven (`fetch.Get` etc.) is fully covered.

---

## 6. No-lock-in scorecard

### What exists today

| Artifact | Export | Verifiability | Citation |
|---|---|---|---|
| Audit log | OCSF / CEF / JSONL, sequence-bounded, pseudonymised by default, `--reveal` audited | chain envelope: anchor-prev, per-event hashes, seq range, pseudonymous flag; exported as a separate file | `internal/siem/siem.go:62-132`, `cmd/vaigil/exportcmd.go:17-96` |
| Audit log (streaming) | `siem.stream.url` push, batches ≤500, at-least-once with receiver-corrected cursor | RFC 9421 HTTP message signature over `@method,@target-uri,content-type,content-digest` (RFC 9530), plus Merkle leaves and Ed25519+ML-DSA-signed tree heads | `internal/auditstream/stream.go:1-60` |
| Vulnerability decisions | OpenVEX document (`@context` v0.2.0) via `vaigil vuln vex` | standard OpenVEX | `internal/vuln/plan.go:304-352` |
| SBOM | CycloneDX/SPDX **import** + OSV matching (pass-through of the BOMs you already have) | — | `internal/sca/bom.go`, `internal/sca/match.go` |
| Code scanning | SARIF **import** → findings | — | `internal/sarif/convert.go` |
| IOCs | STIX 2.1 bundle **import** + plain lists | — | `internal/indicator/read.go:245+` |
| Detection rules | Sigma **import** (with the honest "all imported rules are unproven" report) | — | `internal/sigma/import.go:32-56` |
| Rules/mappings/manifests | Plain JSON files on disk (detections/, sources/, connect/) — trivially copyable | native schema only | `collectcmd.go:106-145`, `detectpack.go` |

### What is missing for "leave with your data and your content"

1. **Telemetry event export.** The event store (spool) has no OCSF export; `siem` exports the *audit log* only. The customer's collected security telemetry cannot leave in a standard shape (or at all, beyond raw store files). This is the single biggest portability gap.
2. **Detection rule export to Sigma.** Import exists; export does not. Rules are JSON in a native schema; a Sigma/YAML writer (the reverse of `sigma/import.go`) would make the ruleset portable to any other SIEM — and forces the discipline of expressing what the native schema can do and Sigma can't.
3. **Findings export (STIX/OCSF).** Findings, cases, and decisions exist only in-store and in the audit log's record of decisions; no findings feed.
4. **Playbook export (CACAO).** No CACAO anywhere in code (grep; only the master report's roadmap names it). Playbooks are Go-side templates today.
5. **Full store export/migration.** No dump/restore command; the append-only spool plus JSON config files is copyable directory-wise, but nothing documents or versions a migration format.

Scorecard: **audit trail A (best-in-class integrity story), vulnerability decisions A−, content (rules/mappings/manifests) B (files, but native schema only), telemetry D, findings/cases D, playbooks D.** Overall: a customer can prove what happened and take their VEX decisions; they cannot take their detections in a standard form or their event history at all.

---

## 7. Prioritised integration roadmap (~15, ranked by value/effort)

Effort in stdlib-only Go: **S** = data-only or near (manifest + mapping + rule files, ≤ a day), **M** = small Go (a package-scale addition), **L** = new engine capability. "Data-only" is load-bearing: the manifest engine makes many of these shippable without touching code.

| # | Integration | What it unlocks | Mechanism | Push/poll | Effort |
|---|---|---|---|---|---|
| 1 | **OTel GenAI / OTLP HTTP-JSON ingestion** | AI-agent telemetry as a first-class source: LLM spans (genai semconv), tool calls, token/cost, latency — the substrate for the whole "SOC for AI agents" story and the master report's Release N | New inbound endpoint parsing OTLP/JSON (`/v1/traces`), a source mapping per signal; no credentials | push | **M** |
| 2 | **OpenAI audit logs API** (organization/audit logs, project API-key usage) | Which agent/service called which model, from where, key rotations — the audit trail of the AI stack | Existing engine: bearer key + offset/cursor pagination — **data-only** manifest + mapping | poll | **S** |
| 3 | **Anthropic Compliance API** (audit log export) | Same for Claude-based agents; the two cover most startup AI usage | Existing engine: OAuth or API key + pagination — **data-only** | poll | **S** |
| 4 | **Bedrock + Vertex detection content** | Model-invocation audit events already land in CloudTrail (`aws/cloudtrail`) and `gcp/audit`; what's missing is *detections* (InvokeModel anomalies, new model IDs, guardrail changes) | Rules only — mappings exist (`known.go:48-76, 238-261`) | already polled | **S** |
| 5 | **Slack audit-log poller** | workspace/admin changes (app installs, token grants, retention changes) — top startup identity-adjacent surface; mapping exists but only via file import today | Existing engine: bearer + cursor — **data-only** | poll | **S** |
| 6 | **GitHub Actions supply-chain events** | workflow runs/jobs, `workflow_run` deployments, artifact/attestation events; pairs with existing GH audit + SARIF/SBOM import | Inbound GitHub webhook scheme already verified (`inbound.go:206-228`); attestations API is a small manifest | push + poll | **S** |
| 7 | **Auth0** | tenant logs (login/manager/failure streams) for startup IdPs beyond Okta; also an SSF transmitter candidate | Existing engine: bearer + cursor — **data-only**; SSF inbound already generic | poll (+push option) | **S–M** |
| 8 | **JumpCloud** | directory + system insights + MDM for the Okta-alternative startup segment | Existing engine: bearer (`x-api-key`) + offset — **data-only** | poll | **S–M** |
| 9 | **PagerDuty (inbound + notify)** | response-side: incident webhooks into findings, and the notify channel for on-call | Inbound needs a third signature scheme (PD HMAC over `timestamp.body`, close to Standard Webhooks — extend `VerifyStandard`); notify is an egress purpose + template | push + poll | **M** |
| 10 | **Google Workspace connector** | the biggest missing identity/endpoint source for startups (Workspace login mapping exists but is file-import only) | **New auth kind**: signed-JWT client assertion (RS256 service account) — not expressible in the manifest engine today | poll | **M** |
| 11 | **Kubernetes audit ingest** | `kubernetes/audit` mapping exists but nothing ships records; needs a documented agent path (audit-sink webhook or file collect) plus secret for the sink | Inbound webhook + mapping (fix S1's array paths first); `collect file` already works | push (or file) | **M** |
| 12 | **Salesforce connector** | the UNC6395 narrative already lives in the code (`known.go:396-401`); login-history mapping exists, the poller doesn't | Existing engine: oauth-refresh is built (`manifest.go:114-116`); refresh token minted in the customer's org | poll | **M** |
| 13 | **MCP-gateway / self-MCP telemetry** | agent-ecosystem coverage: ingest this platform's own MCP server operations (it is already an MCP server) and MCP-gateway audit logs as events; feeds tool-schema-drift and delegation-loop detections | Self-telemetry is **S** (log MCP ops into the spool); gateway traffic standardises on OTel GenAI (#1) | internal + poll | **M** |
| 14 | **AWS Security Hub / Config posture** | cloud posture findings as first-class findings+controls | **New auth kind**: SigV4 request signing — engine work; alternatively start with Config-rule snapshots delivered as files | poll | **M–L** |
| 15 | **Microsoft Teams response actions** | response channel beyond Slack reminders (notify + declared POST) | Extend `internal/action`'s declared-request model (already fixed-method/fixed-host/constant-body, `action/action.go:16-70`); Graph token needs the oauth-client kind + `ApplicationAccessPolicy`-style review | push | **M** |
| 16 | **GCP Security Command Center / Azure posture** | completes cloud posture triad | SCC: bearer + pagination (data-only once #10's signing exists is *not* required — SCC uses OAuth token, so oauth-client works); Azure: Graph-backed | poll | **M** |

Top five by value/effort: **1, 2+3 (one work stream), 5, 6, 4**. Items 10, 14 and the OTLP endpoint are the three pieces of genuine engine work; everything else rides the manifest machinery.

---

## 8. Data vs code: can connectors and mappings ship as signed content packs?

### 8.1 What is data today

| Layer | Data | Code |
|---|---|---|
| Connector | **100%** — 8 JSON manifests embedded as a catalogue (`catalogue.go:30-31`), installed as ordinary files (`connectcmd.go:738-820`); `findConnector` accepts any path (`connectcmd.go:120-123`) | the generic engine (`session.go`, `run.go`, `path.go`, `manifest.go` validation) |
| Source mapping | the 17 built-ins are Go constructors, but the struct is JSON and custom mappings install from files with validation + sample-proof (`collectcmd.go:111-145, 167-241`) | the Miss/Drift machinery, OCSF class semantics |
| Detections | JSON rule files; embedded starter pack installs as files (`detectpack.go:17-90`) | rule evaluation, trial rings, Sigma import |
| Actions | declared requests (fixed method/host/path-with-{target}/constant body) — data-shaped, though currently Go/embed-declared (`action/action.go:52-70`) | the approval two-person rule, egress `action` purpose |
| Inbound feeds | feed configs JSON in `inbound/` | the four verification schemes |

So for connectors and mappings the answer to "can it ship as a signed pack?" is **yes, structurally, today**: a pack is a directory of JSON files, and the loader (`manifests()`, `allSources()`) already reads whatever files are there. The master report's §4.8 content plane (TUF-style signed packs, staged rollout, shadow-ring replay) needs no change to the connector model — only the distribution/signing/rollout machinery around files that already exist.

### 8.2 Why this is safe here, and where the edges are

The security argument for packable connectors is that **a manifest cannot execute**. The path language has no wildcards, filters, functions, arithmetic, or loops (`path.go:10-27`); manifests cannot name a plugin, a script, or a transform; `Validate` refuses anything that could widen reach (hosts, ports, paths, scopes, undeclared reads). A signed pack of manifests is **signed data**, reviewable in minutes — which is exactly the property the package comment stakes out against executable connector definitions (`manifest.go:26-34`: "a manifest that could execute is a supply-chain foothold with a friendly name").

The residual risks a content-pack design must hold at the pack layer, all already mitigated in-engine but worth restating as pack invariants:

1. **A pack that declares a host + credential name could aim exfiltration at an attacker's host** if an admin installs it unreviewed. Invariants that block this: closed region lists for catalogue connectors (a pack manifest is still host-validated, IP/local refused); secrets are referenced by *name*, and a pack cannot carry a credential value (`manifest.go:136-152`; `looksSecret` refuses values); `reads` allow-list bounds what leaves. A pack installer should still diff `reads`/`host` against the currently-installed version and require an explicit ack — the `connect add --replace` warning (`connectcmd.go:773-777`) is the seed of that flow.
2. **Scope creep via roles/scopes fields** is refused by spelling rules (`manifest.go:748-804`) and, for Entra, by on-token verification (`session.go:285-321`). A pack cannot widen this.
3. **Update-without-release for the engine itself is a non-goal**: new auth kinds (SigV4, signed-JWT), new pagination kinds, or new verification schemes are code and must ship as binaries. The clean line to draw publicly: *content packs carry connectors, mappings, rules, feeds, prompts; the engine is the TCB and releases on its own cadence.* That framing is also the honest security story — signed code would be a different and much harder claim than signed data, and the design deliberately never makes it.
4. **Mappings are the same shape of safety** (dotted paths + enums), with one gap: S1 shows the built-ins themselves can be wrong against reality. The pack pipeline's shadow-ring replay (§4.8) is precisely the right gate for mappings: a mapping pack should be replayed against a sample of the customer's own records (`source.Check` already exists, `run.go:224-237`) before promotion — the machinery is already written.

### 8.3 What would need to change

- **Distribution**: signed pack format + key rotation (Ed25519 now, ML-DSA dual-sign per the master report), channels, and the staged-rollout/rollback loop. No engine change.
- **Install UX**: `connect add`/`source add`/`detect pack install` gain a pack source (URL/file) with signature verification and a review diff. The `authorise(ActGrant)` + audit pattern already in those commands extends naturally.
- **Versioning of the data schemas**: `DisallowUnknownFields` on catalogue load (`catalogue.go:82-89`) is the right strictness for packs too — a pack written for a newer schema must fail loudly on an older binary, and the schema needs a version field to say so.
- **KnownBe4 November 2026** (`knowbe4.json:21`) is the live proof this design pays: the pagination migration is a manifest edit, distributable as a pack, with no binary release.

Bottom line: **connectors and mappings are already content**; the content plane's work is signing, channels, and rollout gates, not un-executing the integration layer — because it was never executable.
