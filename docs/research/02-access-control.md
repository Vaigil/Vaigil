# Access control and separation of duties in Vaigil — audit and target architecture

Date: 2026-10-25. Scope: the whole authorization surface as it stands in code — `internal/auth`, `cmd/vaigil` (CLI gates, MCP wiring), `internal/admin` (HTTP routes, sessions, sign-in), `internal/dual`, `internal/audit`/`logd`/`anchor`, the agent-facing MCP path — followed by a NIST/OWASP mapping and a concrete design for AI agents as principals, kept inside the zero-dependency constraint.

---

## 1. Executive summary

Vaigil today has an unusually disciplined human access-control core and almost no agent access-control at all. Those are the two headline facts, and both are deliberate.

**The human core is strong and centralized.** One package (`internal/auth`) holds the entire model: a four-rung role ladder (viewer → analyst → responder → admin), three granttable permissions beside it (approve / tune / assess), resource-scoped bindings with expiry and deny-wins semantics, and two "areas" (`/@security`, `/@log`) that let jobs be scoped without granting the ladder. Every one of the three surfaces — CLI, console, MCP — funnels through the same `Policy.Evaluate` plus `auth.CheckGranted` (credential caps), and each surface has a *structural* fail-closed mechanism rather than a convention: the CLI refuses any command not in `commandNeeds` (enforced by `TestEveryDispatchedCommandDeclaresItsPrivilege`, `cmd/vaigil/privilege_test.go:30`), the MCP server refuses any operation when no `Authorise` hook is wired or an operation declares no role (`internal/mcp/mcp.go:439-448`, `cmd/vaigil/mcp.go:85-107`), and an unreadable policy file makes every authorization decision "no" (`cmd/vaigil/caller.go:186-195`). The comment trail shows each of these was added *after* a real hole was found — the design learned from its own incidents.

**Dual control covers the four take-over moves.** Making somebody an admin, issuing an admin token, weakening a setting, and moving the audit log each require a second administrator (`internal/dual/dual.go:39-49`), with a self-approval refusal (`dual.go:194-195`) and an "only administrator" escape that is itself recorded as approved-alone. Separately, platform acts (suspend an Okta account) require requester ≠ approver (`internal/incident/act.go:127-130`), and automation runs are approved by somebody other than the rule's author (`internal/automate/automate.go:718-724`).

**The audit log is the best-protected object in the system.** Hash chain + Merkle tree + dual Ed25519/ML-DSA-65 signed heads + OpenTimestamps anchoring, plus an optional separate-account writer (`internal/logd`) that computes the chain itself so a compromised Vaigil cannot forge a consistent history. The known weakness is named in the code: in the default single-account deployment the head-signing seeds and the pseudonymisation key sit on the same disk the admin's account owns (`cmd/vaigil/auditsign.go:59-91`, `cmd/vaigil/auditlog.go:143-148`).

**Agents are not principals.** The MCP surface authenticates *whoever holds a local token file* (`cmd/vaigil/caller.go:105-152`), records every agent write as `Kind: ai` under a fixed `mcp-client` principal (`cmd/vaigil/mcpsecurity.go:369-378`), and is capped by two hard backstops: a model cannot record a finding decision (`internal/finding/decision.go:94-99`) and an operation with no role is refused outright. What does not exist: an agent registry, delegation/on-behalf-of chains, per-agent tool allowlists, time/purpose/budget-bound grants, maker-checker between agents, and a global kill switch. The code carries fossils of a planned OAuth agent interface that was never (or not yet) built: `Caller.Remote`'s comment points at `agentinterface.go` which does not exist (`cmd/vaigil/caller.go:54`), `Token.Audience` points at `internal/oauthas` (`internal/auth/auth.go:656`), and four files cite `internal/agent` as if it existed (`internal/finding/decision.go:49`, `internal/finding/finding.go:289`, `internal/telemetry/event.go:215`, `internal/connector/run.go:57`). Meanwhile the full MCP-over-HTTP transport with an `Authenticate` hook, DPoP challenge, and RFC 9728 metadata exists as a library (`internal/mcp/http.go`) but is mounted **nowhere** — `vaigil serve` wires no `/mcp` route; MCP is stdio-only today.

**The strategic risk** for the "SOC platform for AI agents" vision is not that agent controls are missing — it is that they must be added to a codebase whose safety argument currently rests on *"agents can only read and propose."* The moment an agent can act, every property that is today guaranteed by absence (no approve, no tune, no reach) has to be guaranteed by enforcement. The target architecture in §8 is sized for that: agents as a distinct principal type with their own registry, macaroon-style caveat tokens (already sketched in `/home/rashik/vaigil-research/04-ai-layer.md` §6.3), OAuth 2.1 + DPoP + RFC 8693 exchange for delegation, per-agent tool allowlists in the existing `Authorise` hook, maker-checker between model families, and a kill switch built from parts that already exist (token revocation cascade + step-up + SSF consumption).

---

## 2. Role → permission matrix

### 2.1 The ladder and the actions (`internal/auth/auth.go:70-141`, `permission.go:20-45`)

| Action (Go const) | What it means | Minimum role by default | Grantable alone? |
|---|---|---|---|
| `view` (ActView) | read findings, cases, vuln queue, dashboards | viewer | no (implied by all roles) |
| `triage` (ActTriage) | triage findings, open/comment cases, hunt | analyst | no |
| `respond` (ActRespond) | run cases, request platform acts, accept risk | responder | no |
| `grant` (ActGrant) | manage people/roles, connectors, settings, estate | admin | no |
| `manage-tokens` (ActToken) | issue/revoke tokens, vault rewrap | admin | no |
| `approve` (ActApprove) | approve another's platform act or automation run | responder | **yes** (`permission.go:42`) |
| `tune` (ActTune) | change detections, correlations, automation rules | admin (as role); follows engineer job | **yes** (`permission.go:43`) |
| `assess` (ActAssess) | decide vulnerabilities (SSVC, VEX, tags, plans) | admin (as role) | **yes** (`permission.go:44`) |

Evaluation rules (`auth.go:313-417`): (1) unknown action → refuse; (2) explicit **deny wins anywhere it covers**, and denying role R also denies every action needing ≥ R but not below (`auth.go:333-362`); (3) otherwise the effective role is the highest live binding covering the resource; a permission binding satisfies its one action even below the role that would otherwise hold it (`auth.go:364-404`); (4) `/@log` is a *guarded area* — a role on `/` reaches it only at admin rank, so an auditor must be granted on the area itself (`auth.go:199-213`, `387-392`).

### 2.2 The jobs (`auth.go:235-242`)

| Job | Bindings granted | Notes |
|---|---|---|
| `engineer` | `tune` on `/@security` + viewer on `/@security` | tunes detections/automations, reads the queue |
| `vuln-manager` | `assess` on `/@security` + viewer on `/@security` | decides vulnerabilities |
| `auditor` | viewer on `/@security` + viewer on `/@log`, `Ends: true` | time-boxed by construction; the whole store's binding model supports `Expires` (`auth.go:172-182`) |

Jobs are data, not code: "granting one is granting those" and `vaigil auth roles` prints them in full.

### 2.3 The complete matrix (who may do what, today)

| Capability | viewer | analyst | responder | admin | engineer | vuln-manager | auditor |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Read queue/cases/vulns (`view` on /@security) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Read audit log (`/@log`) | – | – | – | ✓ | – | – | ✓ |
| Triage/decide findings (`triage`) | – | ✓ | ✓ | ✓ | – | – | – |
| Own cases, request acts, accept risk (`respond`) | – | – | ✓ | ✓ | – | – | – |
| Approve another's act / automation run (`approve`) | – | – | ✓ | ✓ | – | – | – |
| Tune detections/automations (`tune`) | – | – | – | ✓ | ✓ | – | – |
| Decide vulnerabilities (`assess`) | – | – | – | ✓ | – | ✓ | – |
| Manage people/policy/connectors/settings (`grant`) | – | – | – | ✓ | – | – | – |
| Issue/revoke tokens (`manage-tokens`) | – | – | – | ✓ | – | – | – |

Enforcement of that matrix, per surface:

- **CLI**: one table, `commandNeeds` (`cmd/vaigil/privilege.go:52-319`); every dispatched command must have a row or it is refused (`privilege.go:443-462`), tested at `privilege_test.go:30`. Read-only subcommands step down from privileged parents (e.g. `auditlog show` → view, while `auditlog`/`auditlog anchor` → grant, `privilege.go:62,64,74`). Commands working in an area are checked against the area (`commandAreas`, `privilege.go:550-559`), so a job grant on `/@security` runs `finding`, `vuln`, `detect`, `hunt` etc. and nothing else. Every refusal is audit-logged (`privilege.go:502`).
- **Console (admin HTTP)**: handlers gate via `requireAuth` + `can`/`canAnywhere` (`internal/admin/server.go:502-617`) or the shared `postFrom` POST preamble (`internal/admin/people.go:453-472`), all of which call `Policy.Evaluate` + `auth.CheckGranted`.
- **MCP**: per-operation `Authorise` hook (`cmd/vaigil/mcp.go:85-107`) maps the operation's declared role to an action (`actionForRole`, `mcp.go:154-168`: viewer→view, analyst→triage, responder→respond, admin→grant) and refuses anything undeclared; read handlers re-check in-handler as defence in depth (`mcpsecurity.go:59` etc.).

Centralization verdict: **enforcement is genuinely centralized in `internal/auth`** — all three surfaces call `Evaluate` + `CheckGranted`/`CheckCredential`, and the historically scattered per-surface copies (documented in `caller.go:226-238`, `server.go:506-525`) were collapsed into those shared functions. What remains per-surface is only *which* action a route/command/operation maps to, which is inherent.

---

## 3. Enforcement inventory

### 3.1 Admin HTTP routes (`internal/admin/server.go:918-1023`)

All routes are registered on one mux wrapped by `securityHeaders(signedFlash(sameSiteOnly(limitBody(readOnlyTokens(mux))))` (`server.go:1022`). Inventory by gate class:

| Class | Routes | Gate |
|---|---|---|
| Public by design | `/signin`, `/signin/*`, `/auth/callback`, `/saml/`, `/enrol/`, `/passkeys*` (challenge/register/remove), `/token/exchange`, `/scim/v2/`, `/feeds/`, static (`/style.css`, `/admin.js`, fonts, `/icon.svg`) | own authentication: passkey ceremony (UV required — `passkeyuv_test.go:18,45,105`), OIDC/SAML signed assertions, SCIM provisioning bearer (`internal/scim/handler.go:75-81`), per-feed provenance proofs (`internal/inbound`), RFC 8693 exchange |
| Authenticated person screens | `/today`, `/start*`, `/approvals`, `/find`, `/security/*`, `/findings*`, `/workforce*`, `/people*`, `/sessions/revoke`, `/sso*`, `/provisioning*`, `/settings*`, `/logs`, `/profile*`, `/session/alive`, `/theme`, `/sidebar`, `/nav/order` | `requireAuth` (+ `can`/`postFrom` with the specific action) at every handler head — verified for furniture routes too (`theme.go:75`, `nav.go:305`, `find.go:35`, `scimadmin.go:45`) |
| Sign-in/out | `/signin` POST exchanges pasted token for session cookie via `Tokens.Exchange` (`server.go:1140`); `/signout` **revokes** the session, not just the cookie (`server.go:1275-1302`) | throttled both paths (`server.go:1080-1105`, `1340-1399`; regression tests `credentials_test.go:30,128`) |

Middleware guarantees worth naming: read-only tokens refused on every non-GET before any handler logic (`server.go:885-914`); `sameSiteOnly` accepts the SAML ACS as the one cross-site POST (`server.go:806-867`); `MaxRequestBody` 2 MiB (`server.go:793`); CSP with no default origins and nonce-only script (`server.go:725-789`).

`requireAuth` itself implements the session policy stack (`server.go:1340-1444`): per-source throttle checked before credential lookup; token store re-read from disk so CLI revocations take effect without restart (`server.go:245-257`, `Reload` doc at `server.go:229-237`); idle clock; session-moved binding check; **a bearer token at AAL1 is refused at the console entirely** ("the console is for people signed in with two factors", `server.go:1414-1419`); organisation-wide SSO-only enforcement on every request (`server.go:1423-1433`); and a step-up session is redirected to `/signin/verify` before anything else (`server.go:1435-1442`).

**Sessions and TTLs.** `session.max` defaults 8h (`internal/config/settings.go:128`), `session.idle` defaults 1h (`settings.go:140`, clamped 5min–1h at `settings.go:383`); grant-capable principals idle out at 15 minutes via `PrivilegedIdle` (`auth.go:791`, `internal/admin/settings.go:290-298`); idle is *use*-based (key/click/scroll reported by the page, `internal/admin/idle.go:14-27, 110-119`) and idle expiry revokes the session token (`idle.go:78-92`). Exchanged sessions cap at `MaxSessionTTL` 12h (`auth.go:785`) and never outlive their parent (`auth.go:1083-1090`); revocation cascades to children (`auth.go:1387-1414`); ended sessions leave a 16-hex fingerprint so a stale script is told "ended" not "guessed" (`auth.go:846-860, 1354-1362`).

**MFA posture.** Two factors on every person-request, not just sign-in: `authenticate` marks any AAL<2 session step-up when MFA is enforced (`server.go:482-493`); a passkey with user verification is AAL2 alone (`auth.go:716-723`); SSO counts as AAL2 **only when the provider says so** — `amr` containing `mfa` (RFC 8176) or an `acr` the operator named, with a fresh enough `auth_time` (`internal/admin/oidcauth.go:113-141`) — otherwise `sso-1fa` and step-up. Admin passkeys without UV are refused outright (`passkeyuv_test.go:18,45`). The "SSO counts as two factors only when provider says so" logic is exactly right and tested.

**Lockout and enrolment.** Smart lockout locks *places*, not people (`internal/lockout/lockout.go:4-11`, escalating `LockFor<<strikes` at `lockout.go:179-183`), complementing the per-source throttle. Enrolment links are one-time, hashed at rest, expiring, replaced-per-person (`internal/enrol/enrol.go:34,43,86-90,187`), with a single uniform "does not work" error to avoid an enumeration oracle.

**DPoP / token exchange.** Full RFC 9449 check suite (typ, asymmetric alg, htm/htu/iat/ath/jti, replay window) at `internal/dpop/dpop.go:110+`; key-bound tokens are refused as bearer everywhere except `/mcp`, `/v1`, `/a2a` (`ErrKeyBound`, `auth.go:1176-1179` — note those surfaces are the unwired ones), and `/token/exchange` implements RFC 8693 with narrowing-only exchange and DPoP proof binding (`internal/admin/tokenexchange.go:85-196`; `actor_token` explicitly refused at :119-121, so on-behalf-of exchange does not exist yet).

### 3.2 CLI commands

Covered by the table + test described in §2.3. Special cases audited: `init` (creates the store — no policy exists yet), `logd` (derives authority from socket peer uid, not a store token), `auth recover` (break-glass that verifies no usable admin token exists and cannot require what it exists to restore, `privilege.go:310-312`), `token keygen`/`proof` (never open the store), and the one-shot bootstrap that allows the *first* token issue to an already-bound principal while the token store is empty (`bootstrapIssue`, `privilege.go:511-541`) — a chicken-and-egg escape that closes itself the moment any token exists.

### 3.3 MCP operations

Eight operations behind four tools (`vaigil_find`, `vaigil_read`, `vaigil_write`, `vaigil_check`):

| Operation | Role | Area | Writes | Gate |
|---|---|---|---|---|
| `find` | viewer | `/` | no | `mcp.go:113` |
| `list_findings` | viewer | /@security | no | `mcpsecurity.go:45,59` |
| `detection_stats` | viewer | /@security | no | `mcpsecurity.go:96,107` |
| `incident_status` | viewer | /@security | no | `mcpsecurity.go:134,146` |
| `vuln_plan` | viewer | /@security | no | `mcpsecurity.go:227,239` |
| `read_finding` | viewer | /@security | no | `mcpsecurity.go:264,273` |
| `propose_finding_decision` | analyst | /@security | **yes** | `mcpsecurity.go:314,329` + `auditReady` |
| `estate_summary` | admin | /@security | no | `mcpestate.go:27,38` |

Structural guarantees: a read tool cannot reach a write operation and vice versa (`internal/mcp/mcp.go:428-437`); nil `Authorise` hook = everything refused (`mcp.go:439-448`, test `internal/mcp/authorise_test.go:22`); operations with no declared role refused (`cmd/vaigil/mcp.go:87-93`); agent *writes* additionally require the audit log to be provably writable first (`auditReady`, `cmd/vaigil/mcp.go:97-102` → `cmd/vaigil/auditlog.go:242-269`) — AU-5 applied to agents, while human actions proceed with a loud warning (`auditlog.go:186-201`). Refusals carry JSON-RPC code `-32001` with `retryable: false` so an agent does not grind on a decision (`mcp.go:93-100, 456-466`).

### 3.4 Gaps found

1. **The MCP HTTP transport is dead code.** `internal/mcp/http.go` (Endpoint with `Authenticate`/`Build`/`Called` hooks, modern 2026-07-28 stateless revision, header/body mismatch checks, batch refusal, DPoP challenge, RFC 9728 `resource_metadata` in 401s) is referenced by nothing; `serve` mounts no `/mcp`. For the agentic vision this is the single most consequential gap: remote agents cannot reach Vaigil at all today except by holding a local token file and speaking stdio.
2. **Dead OAuth/agent references** (`caller.go:54` → `agentinterface.go`; `auth.go:656` → `internal/oauthas`; four `internal/agent` citations; `Token.Audience`/`Client`/`Grant` fields at `auth.go:655-663` and `IssueForGrant`/`RevokeGrant` at `auth.go:1260-1310` are an OAuth authorization-server half-built and unwired). The data model is ahead of the surface. Risk: someone wires it up quickly later without the gates the comments assume.
3. **Console handler gating is convention + review, not structure.** Unlike the CLI (table + test) and MCP (nil-hook-refuses), a new admin handler that forgets `requireAuth` would be open; the route-walking tests that exist check headers/cache (`headers_test.go:19`) and navigation (`reachable_test.go:30`), not "every non-public route 401s anonymously". A one-line test over the route list would close this.
4. **`ErrKeyBound`'s message names `/mcp`, `/v1`, `/a2a`** (`auth.go:1176-1179`) — surfaces that do not exist yet. Harmless today (the only DPoP-accepting surface is `/token/exchange`), but it documents an intended perimeter that has not been built.
5. **Token principal-kind is a name heuristic.** `resolveCaller` labels a token human if its name is `cli` or contains `@` (`caller.go:141-147`) — the code itself calls it "a weak heuristic". Agent identity bolted onto token *names* is the wrong axis; §8 replaces it with a principal type.
6. **Session-move binding is advisory-through-rules**: a session issued to "Chrome on Windows|GB" seen elsewhere triggers rule-driven step-up (`server.go:1406-1410`), which is the right shape, but the binding string is recorded at issue and never re-verified cryptographically (no token binding/DPoP on the cookie path).

No ungated admin route, CLI command, or MCP operation was found in this audit beyond the items above; items 1–4 are missing/latent surfaces rather than open doors.

---

## 4. Dual control / separation of duties

### 4.1 What is dual-gated (two administrators)

`internal/dual` (`dual.go:39-49`): **Grant** (any binding that makes somebody admin, `Privileged` at `dual.go:76-83`), **Token** (issuing an *admin-role* token — proposed at `cmd/vaigil/auth.go:713-720`, redeemed only by the requester within 24h via `pending redeem` → `tokenIssueAs`, `dualcmd.go:177-196`, `dual.go:235-253`), **Setting** (any value weaker than default, `dual.go:88-95`; proposed from `configcmd.go:266-268` and the reset-to-default path `configcmd.go:309-311`), **AuditLog** (moving the log directory, `cmd/vaigil/auditlog.go:88-108`). Requests wait 7 days (`dual.go:100`).

Semantics: proposer cannot approve their own request unless they are the only administrator (`dual.go:194-195`), and the alone case is recorded as `alone: true` in the audit chain (`dualcmd.go:37-44`, `admin/dual.go:58-61`). The console decides requests at `/people/pending` with the same store and the same self-approval refusal (`admin/dual.go:136-176`); both apply paths converge on the same `applyDual`.

### 4.2 What is two-person in other shapes

- **Platform acts** (suspend an Okta account): requester ≠ approver, always, "the commander included" (`internal/incident/act.go:114-135`, refusal at :127-130); approval is of the exact call shown (`Says`), recorded approved-before-sent, unknown-outcome-on-crash, reversible-by-anyone-with-reason.
- **Automation runs**: `automate.Decide` refuses the rule's author as approver ("wrote %s, so its runs are approved by somebody else", `automate.go:718-724`); rules that act on *access* are admin-of-whole-site to write or approve (`Action.Access`, `automate.go:218-221`, `Rule.Access` :361-371); runs are rate-limited (`PerHour`, default 20, `automate.go:197`).
- **Findings**: `finding.Decision.Validate` is the backstop that makes a person (or at least a non-AI principal) structurally necessary for every closing verdict (`decision.go:80-131`).

### 4.3 Bypass analysis

- **Direct file access:** `policy.json`, `tokens.json` and `dual.json` live in the store (`dualcmd.go:22-24`), writable by the account running Vaigil. Anyone with that filesystem access — including a lone admin — can append an admin binding to `policy.json` directly, bypassing dual control entirely and leaving **no audit entry**. The program's own stance (privilege.go:31-36) is that the audit log's separate writer is what makes this detectable, and that is coherent: the bypass is *visible* as a policy state that disagrees with the log, and `vaigil auditlog verify` plus an anchored head makes the gap provable. But it must be said plainly: dual control here is a product-level control, not an OS-level one; only the log enjoys OS-level separation, and only in the `logd` deployment.
- **CLI vs console:** both go through the same `dual.Store` file, so there is no cross-surface bypass (the console cannot approve what the CLI proposed *as the proposer*, because `Decide` checks names, not surfaces).
- **Alone-admin escape:** one-admin stores auto-approve (`dual.go:168-172`), recorded as such. This is a deliberate availability trade, correctly audited, and `lastAdminIn` refuses removing the last admin binding (`people.go:483-493`).
- **Token redegradation:** an approved-then-redeemed admin token is issued with the *original* args; the requester cannot widen them through redemption (`tokenIssueAs(root, ch.Args, true)` replays the recorded command).

Residual SoD note: **no dual control exists on the *agent* side at all** — nothing stops one agent's proposal being "checked" by the same model behind it, because there is only one agent principal shape (`mcp-client`) and no notion of distinct agent identities. §8.6 addresses this.

---

## 5. AI agents as principals: today vs the vision

### 5.1 What exists today

| Concern | Today | Where |
|---|---|---|
| Agent authentication | A local Vaigil token (`~/.vaigil/token`, `--token`, `VAIGIL_TOKEN` — in that order of deliberateness, `caller.go:75-98`); token file preferred over env *because agents read env* (`caller.go:69-74`) | `cmd/vaigil/caller.go:105-152` |
| Agent authorization | The token's principal + role evaluated per operation through the same `authorise` path as humans; role declared per operation, nil-hook and no-role refusals | `cmd/vaigil/mcp.go:85-107` |
| Actor kind in audit | `audit.KindAI` (`internal/audit/audit.go:83-85`); `Record.Model` carries the model name; `Caller.Model` exists for it | `audit.go:152-153`, `caller.go:66` |
| Attribution | Every MCP write records `Principal: "mcp-client", Kind: ai, Model: "mcp-client", Verified: false` with `on_behalf_of: caller.Name` in detail | `mcpsecurity.go:369-378` |
| The model-is-not-a-principal rule | `Decision.Validate` refuses `Kind == ai` outright; proposals live under a *different audit action* (`proposal.finding`) that `FromAudit` structurally cannot read as a verdict | `decision.go:94-99`, `:309-347` |
| Injection containment for agents | Evidence fenced and labelled untrusted (`<<<untrusted log text…>>>`, `mcpsecurity.go:41,386-395`); estate exposed only in aggregate, never by name (`mcpestate.go:16-24`) |
| Audit-first for agent acts | `auditReady` gate before any agent write | `mcp.go:97-102` |

### 5.2 What the vision needs that does not exist

1. **Agent registry.** No first-class agent identity: no enrolment, no owner, no per-agent credential, no inventory to review or kill. "Which agents hold what today" is unanswerable.
2. **Delegation / on-behalf-of.** `actor_token` is refused in token exchange (`tokenexchange.go:119-121`); `on_behalf_of` is a detail string, not a chain. No RFC 8693 impersonation semantics, no `act` claims.
3. **Per-tool scopes.** An agent's reach is the *operation's* role, not the *agent's* allowlist; a viewer token granted to an agent lets that agent run every viewer operation. There is no "this agent may list findings but never read evidence".
4. **Time/purpose/budget bounds.** Tokens expire (`ExpiresAt`), bindings expire (`auth.go:172`), but there is no purpose statement, no call-count budget, no spend budget, no deadline carried by a credential. `Scope` today is a single boolean (`ReadOnly`, `scope.go:15-23`).
5. **Maker-checker between agents.** Impossible: there is one agent label. The prior-session design already specifies it (independence by model family), and the human side has the pattern to copy (`dual`, `automate.Decide`).
6. **Kill switch.** Nearest primitives: token `Revoke` cascade (`auth.go:1387-1414`), `RequireStepUpFor(principal, …)` (`auth.go:1434-1447`), automation rules that step sessions up on signals. No global "all agents stop now", no CAEP *transmit* (SSF machinery is receiver-only: `internal/ssf/ssf.go:57-60` consumes `session-revoked`; nothing emits it).
7. **The transport.** No HTTP MCP, no OAuth 2.1 AS, no RFC 9728 discovery — all sketched, none wired (§3.4 gaps 1–2). Prior-session doc §6.3–6.13 contains the macaroon capability token, taint-typed tool layer, autonomy levels L0–L4, budgets-as-caveats and the agent step ledger, none of which has a package (`internal/agent` is referenced but absent).

The safety invariant that must survive all of this is already stated in the research and in code: **closing-direction actions stay human(-principal)**; escalation-direction, reversible actions are where agent autonomy pays. The `never` row of the autonomy table (04-ai-layer.md §6.9) matches exactly the backstops that exist (`Decision.Validate`, `Placement`/`Suppression` validates, `automate.Decide`).

---

## 6. Audit-log protection assessment

**Structure.** Append-only JSONL; each event carries `seq`, `prev` (hash of predecessor) and `hash` (SHA-256 of content) (`internal/audit/audit.go:119-170`); records validated on construction (action/when/where/source/outcome/identity mandatory — AU-3 mapped field-by-field at `audit.go:7-17`); `Detail` keys carrying token/secret/password/key/body/content refuse the **whole record** (`audit.go:465`); principals pseudonymised with HMAC-SHA256 under an out-of-log key (`audit.go:38-51, 387-428`). A Merkle tree over the log yields signed tree heads (`internal/audit/merkle.go:51-56,129-137`) with inclusion and consistency proofs (`merkle.go:147,205`). Heads are signed **twice** — Ed25519 and ML-DSA-65 — with domain separation (`vaigil/audit-head/v1`, `sign.go:68`), deterministic ML-DSA so a head has one canonical signature form (`sign.go:279-296`), and verification requiring both unless a FIPS build knowingly accepts one (`sign.go:305-352`). The head digest is committed to Bitcoin via OpenTimestamps (`cmd/vaigil/auditanchor.go:17-19`, `internal/anchor`), and the log can be streamed to another SIEM as OCSF with RFC 9421-signed batches carrying the signed head (README:139-150).

**Key custody.** Signing seeds: `auditdir/head.key`, 0600, auto-created on first use, 64 bytes (two 32-byte seeds — "small enough to write down", `cmd/vaigil/auditsign.go:36-41,59-91`); public half republished as `head.pub.json` (0644) on every load so it cannot drift (`auditsign.go:104-113`). Pseudonymisation key: `audit.key` beside the log, 0640 in separated deployments (`cmd/vaigil/auditlog.go:143-163`). Connector secrets: envelope-encrypted in `internal/vault` with externally-sourced KEKs. Nothing is in a hardware keystore by default — the code says so itself.

**Can an admin rewrite history?**

- *Single-account default:* yes, materially. The admin's account owns the log, `head.key` and `audit.key`. A rewrite requires truncating and re-signing, which succeeds locally — the defenses that catch it are the ones outside the machine: an anchored OTS proof of an old head, a published `head.pub.json`/head copy held elsewhere, or the streamed SIEM copy. The threat model is honest about this (`logd.go:19-23`: "It does not stop root… published tree head is the layer above").
- *Separated `logd` deployment:* the writer runs as another account; Vaigil can only submit records over a 0660 socket and **cannot supply seq/prev/hash** — the writer computes the chain, so a compromised Vaigil can add records but cannot make the log misstate its own past (`logd.go:24-42,73-98`). `CheckOwnership` verifies the separation is actually in force rather than configured (`logd.go:280-292`). Moving the log directory is itself dual-gated. Residual: the signing seeds and pseudonymisation key move with the audit dir, so the *writer* account can forge heads — key separation between "writes records" and "signs heads" is not modelled; anchoring remains the outer bound.
- *AU-5 behavior split:* human actions proceed when the log cannot take a record (stderr warning, `record`, `auditlog.go:186-201`); **agent actions are refused outright** (`auditReady`, `auditlog.go:242-269`, invoked from the MCP write gate). That asymmetry is exactly the NIST reading and is the right default for agents.

**Trust model summary:** integrity within the machine = chain + (optionally) OS separation; authenticity of heads = dual signatures + published keys; global verifiability = OTS anchoring + optional external stream. The weakest link, named in code, is the local key file in the default deployment; the strongest property is that *everything an agent does* is gated on the log being writable and is recorded as `Kind: ai`.

---

## 7. NIST SP 800-53r5 and OWASP Agentic Top 10 mapping

### 7.1 NIST

| Control | Status | Evidence |
|---|---|---|
| **AC-2** account management (create/change/remove; expiry; reviews) | **Largely satisfied** | Bindings with `Expires` (`auth.go:172-182`); auditor job `Ends: true`; SCIM provisioning (`internal/scim`); access-review campaigns (`access` CLI, `privilege.go:158-163`); token `Stale` sweep (`auth.go:1464`); last-admin protection (`people.go:483`). Gap: no scheduled *review* of agent accounts (none exist). |
| **AC-2(3)** disable expired/inactive accounts | **Satisfied for grants; partial for sessions** | Binding expiry enforced at evaluation (`auth.go:180,377`); token expiry + revocation cascade; idle sign-out revokes. |
| **AC-2(5)** inactivity logout | **Satisfied** | `session.idle` 1h default, 15min privileged, use-based, revoking (`idle.go:37-92`, `settings.go:290`). |
| **AC-3** enforced access control on every operation | **Satisfied on existing surfaces** | §3 inventory; three fail-closed structures. Gap: latent (unmounted HTTP MCP; convention-based admin handler gating). |
| **AC-5** separation of duties | **Satisfied for the take-over set; dual-gated; bypassable only with store file access** | §4. Gap: none between agents. |
| **AC-6** least privilege | **Strong** | Ladder + no custom roles by design (`auth.go:23-26`); job bindings minimal by construction; token scoping (role cap, resource cap, read-only) enforced via `CheckGranted` on all surfaces; permissions granttable singly. Gap: no per-tool scoping for agents. |
| **IA-2** identification & authentication (organizational users) | **Satisfied; MFA-forward** | Passkeys with required UV; SSO AAL2 only on provider proof (`oidcauth.go:113-141`); AAL1 refused at console (`server.go:1414`); break-glass authenticated by *absence of any usable admin token*. |
| **IA-4** identifier management | **Satisfied** | Random 256-bit tokens, hashed storage, constant-time compare (`auth.go:824,1340-1376`); pseudonymised principals in audit. |
| **IA-5** authenticator management | **Mostly satisfied** | No default accounts/passwords; token TTL ceilings (`token.ttl.max` check at `auth.go:694-703`); DPoP binding; revocation cascade; enrolment links one-time. Gap: no in-product rotation reminder for head.key/audit.key beyond `vault rewrap` for connector secrets. |
| **IA-9** services (non-organizational users; *the agent clause*) | **Absent → target** | No service/agent principal registration, no per-agent auth, no cross-organizational trust. The federated token path (`IssueFederated`, 1h max, key-bound) is the seed. |
| **AU-9** protection of audit information | **Satisfied with named residual** | §6: chain, Merkle, dual signatures incl. post-quantum, OTS, optional separate writer; AU-9(5) dual authorization to move the log. Residual: local key files in default deployment. |
| **AU-10** non-repudiation | **Strong** | `Verified` flag separating proved from asserted identity (`audit.go:134-146`); pseudonyms reversible only with the key; per-record principal/kind; signed heads; proposals never masquerade as decisions (`decision.go:309-315`). |
| *(AU-5, noted)* audit failure handling | **Satisfied, asymmetric by design** | Humans: alert-and-continue; agents: refuse-when-unrecordable (`auditlog.go:186-269`). |

### 7.2 OWASP Agentic Security Top 10 (ASI01–ASI10)

| ASI | Threat | Status in Vaigil |
|---|---|---|
| ASI01 credential enumeration/authority confusion | **Partial.** Opaque tokens, constant-time compares, no enumeration oracle (`signInReasons` closed list, `server.go:1220`), audience and DPoP binding fields exist — but audience is only enforced at `/token/exchange`, and tokens are one-factor for programs by design and stated. Agent delegation would multiply issuers; the `mcp.go:39-51` comment already names the RFC 8707 seam. |
| ASI02 excessive agency / overprivileged agents | **Currently minimal by absence** (read + propose only; `never`-list enforced by backstops). Becomes the central risk when L2–L4 autonomy lands → caveat tokens + allowlists (§8). |
| ASI03 prompt injection | **Strong for the read path** — fixed analyst plan, fenced untrusted text, counts/words separation, echo/ablation checks specified in research §6.10; MCP evidence fencing is code (`mcpsecurity.go:41,301-308`). |
| ASI04 tool misuse / dangerous actions | **Strong**: acts need two humans; automation runs need a non-author approver; access-affecting automations admin-gated; agent tool surface is 8 read/propose ops. Per-agent allowlists absent. |
| ASI05 cascading hallucinations / agent-to-agent trust | **Absent** (no agent-to-agent channels). Target: maker-checker across model families + ledger. |
| ASI06 memory/context poisoning | **Partial** — no persistent agent memory exists; privacy guard masks secrets/PII before prompts (`internal/secret`, `internal/model/guard`); context minimised by design (4 tools, on-demand descriptions). |
| ASI07 insecure output handling | **Strong on the decision path** — closed-set verdict words, confidence threshold below which nothing is shown; agent-written content marked AI; no agent output reaches a control flow unchecked. |
| ASI08 human agency/accountability erosion | **Designed against explicitly** — rubber-stamp detection (`review.RubberStamped`), adoption-time canary in research §6.8, decisions always human-recorded. |
| ASI09 unsandboxed tool/credential scope | **Partial** — connector credentials in vault, SSRF-hardened fetcher, egress control; but agent credentials are not scoped per tool (§5.2 item 3). |
| ASI10 supply-chain/model provenance | **Strong on binary** (0 deps, `go.mod` asserted by test); model provenance partially (audit `Model` field, ledger fields specified in research §6.12; shadow-ring promotion pattern exists for detections and is specified for models). |

---

## 8. Target authorization architecture for agents

Design constraints: zero third-party dependencies (stdlib only — `crypto/ed25519`, `crypto/mldsa`, `crypto/hmac`, `crypto/rand` suffice for everything below); reuse the existing `auth` policy as the single source of truth; keep every existing backstop (`Decision.Validate`, `automate.Decide`, `dual`) untouched and *behind* the new layers.

### 8.1 Agent principals in the policy (IA-9)

Add a principal *type*, not a parallel model. Today `Binding.Principal` is a bare string; introduce a reserved syntax `agent:<name>` handled by the same `Policy`:

- `internal/auth`: `type PrincipalKind` (human/service/agent) parsed from the binding string. Agents **cannot hold `admin`**: `Grant` refuses `Role == RoleAdmin` when the principal is an agent, and refuses granting `manage-tokens` — an agent can never mint credentials. Agents may hold viewer/analyst/responder rungs and the `approve`/`tune`/`assess` permissions exactly like a person, which immediately makes the existing ladder, expiry, deny, areas, jobs, `auth explain` and the access-review machinery work for agents for free.
- New `internal/agentreg` package: the registry file `agents.json` in the store — per agent: id, owner (a human principal, who receives the alerts), model family, tool allowlist, max autonomy level, budget defaults, status (`active`/`suspended`/`revoked`), created/expires, and the hash of its credential. Registration is `ActGrant`; **suspending/revoking is `ActRespond`** so a responder under pressure can kill an agent without being an admin. The registry is the AC-2 review object: `vaigil auth agents` lists what exists, what it may do, and when it ends.

### 8.2 Delegation: OAuth 2.1 + DPoP + RFC 8693 (on-behalf-of chains)

The half-built pieces line up exactly: `Token.Audience/Client/Grant` (`auth.go:655-663`), `IssueForGrant`/`RevokeGrant` (`auth.go:1260-1310`), the DPoP stack (`internal/dpop`), the exchange endpoint (`admin/tokenexchange.go`), and the unwired `mcp.Endpoint` hooks. Wire them:

1. Mount `/mcp` in `serve` using `internal/mcp/http.go`; serve RFC 9728 protected-resource metadata at `/.well-known/oauth-protected-resource` naming the AS; add a minimal stdlib OAuth 2.1 **AS** (authorization-code + PKCE; client = registered agent; no client secrets — DPoP key thumbprint as the client authentication, reusing `BindKey`). Consent is recorded as a grant with scope = a *named tool bundle*, resource = `/mcp`, expiry ≤ 12h.
2. Extend `/token/exchange` to accept `actor_token` (today refused at `tokenexchange.go:119-121`) for the agent case: subject_token = the *user's* session or token, actor_token = the agent's token, issued token carries `Parent` = both, principal = `agent:<name>`, and the audit record and every `Authorise` decision see the chain. Add `Token.Actor string` to `auth` — with the invariant, enforced in `Exchange`, that the delegated token's role never exceeds either parent (intersection, not min — intersection of scopes). Chains cap at depth 2 (person → agent; no agent→agent re-exchange) in v1, which keeps `Revoke`'s cascade walk bounded (it already walks one level; extend to the grant, as `RevokeGrant` shows the pattern).
3. `on_behalf_of` in audit detail becomes a real chain: extend `audit.Record` with `Actor []string` (rendered `person via agent-x`) — `Kind` stays `ai` for the terminal actor, `Model` carries the family, and `finding.Proposal.For` reads the human end of the chain.

### 8.3 Per-agent tool allowlists in the Authorise hook

The MCP gate already receives the whole `Operation` before anything runs — the allowlist is one more conjunct:

- `Operation` gains `Tool string` (canonical tool id, e.g. `findings.read`, `findings.propose`). `agentreg` stores `Allow []string` plus `Deny []string` (deny wins, mirroring the policy's rule). The hook in `cmd/vaigil/mcp.go` becomes: unknown tool id → refuse (fail-closed, same as no-role); role check (existing); registry check (agent active, tool allowed, autonomy level sufficient for `Writes`); caveat-token check (§8.4).
- Allowlists are enforced **only** in the hook and the handlers, never in the client, and `mcp --list` prints an agent's *effective* tool set so the registry and reality can be diffed — the same "readable in full" doctrine as `vaigil auth roles`.

### 8.4 Time/purpose/budget-bound grants: macaroon caveat tokens

Adopt research §6.3 essentially as written, as `internal/agent/capability`:

```go
type Caveat struct{ Key, Op, Value string } // "tool" ∈ allowlist, "finding" = id,
                                           // "exp" < t, "calls" ≤ n, "tokens" ≤ b, "level" ≤ L3, "purpose" = hash
type Token struct {
    RunID   string
    Agent   string        // agent:<name>
    OnBehalf string       // human principal (chain root)
    Caveats []Caveat
    MAC     [32]byte      // HMAC-SHA256(k_run, len-prefixed chain of caveats)
}
func (t Token) Attenuate(c ...Caveat) Token   // append + re-MAC; never widens
func (v Verifier) Check(t Token, call ToolCall) error
```

- The run key `k_run` is minted per run by the interpreter from `crypto/rand` and held only in that process; every caveat narrows (append-only, HMAC-chained — stdlib `crypto/hmac`, no dependencies). `purpose` is the hash of the operator-approved purpose statement, so a token used outside its stated purpose fails loudly. Budgets (`calls`, `tokens`, `exp`, plus a wall-clock deadline) are caveats per §6.11 — enforced at the interpreter, *and* surfaced to the ledger so budget exhaustion is visible in the audit chain.
- Interop note: these are *internal* capability tokens beneath the OAuth access token (which stays the network credential); the access token's OAuth scope names the tool bundle, the macaroon narrows per run. `Scope` in `internal/auth` gains `Tools []string` alongside `ReadOnly`, still only-narrowing via the existing `Narrow` discipline (`scope.go:42`).

### 8.5 Kill switch (local + CAEP transmit)

- **Local, authoritative:** `agentreg` status `revoked` is checked in the `Authorise` hook (before caveats), so revocation is effective on the next request with no token round-trips. `vaigil agent revoke <name>` (ActRespond) revokes the registry entry *and* cascades `TokenStore.RevokeGrant`/`Revoke` for its credential and `RequireStepUpFor` for any human sessions it touched — all existing primitives.
- **Global shape:** a `KillAll` bit in the registry (admin, dual-gated — it is an availability attack surface of its own) refusing every agent operation and every token-exchange with an agent subject.
- **CAEP transmit:** `internal/ssf` is receiver-only today. Add the transmitter half (it is a small, symmetric addition: sign SETs with the existing Ed25519 head key under an `ssf/v1` context via `SignStatement`, which already exists for non-head statements — `sign.go:387-430`), and emit `session-revoked`/`credential-change` about *agent* subjects to any configured receiver, so neighbouring platforms learn the kill at once. Publishing the receiver side's stream config rides the existing feeds/SSF wiring patterns.

### 8.6 Maker-checker between agents

Reuse `internal/dual` with agent principals, plus an independence rule that is the analogue of author-cannot-approve:

- An agent's proposal at autonomy ≥ L2 requires a *different* agent (or a human) to check before it becomes a case note/action request; the checker must be from a **different model family** than the proposer (the registry stores family; the check is `proposer.Family != checker.Family`), and never the same owner+family pair (one person running two copies of one model is not dual control).
- Escalation-only asymmetry from §6.9 stays: agents may propose *escalation-direction* and reversible containment; every closing direction, every tune of what counts as wrong, and every approval of an *access-affecting* action remains human (the existing backstops already enforce the important ones — keep them as the last line behind the new gates).
- The `dual.Store` gets `AgentAlone` semantics for single-agent deployments: an agent's own request cannot be approved by the same agent even when it is the only one, exactly the refusal shape `automate.Decide:718-724` already has.

### 8.7 Phased plan

| Phase | Deliverable | Size/risk |
|---|---|---|
| **0. Hygiene (now)** | Delete or fix dead references (`agentinterface.go`, `internal/oauthas`, `internal/agent`); add the anonymous-401 route-walking test for admin; wire `ErrKeyBound`'s message to reality. | Trivial; removes latent-surface confusion. |
| **1. Agent principals (registry + policy)** | `agent:<name>` principal kind; admin/manage-tokens refusal for agents; `internal/agentreg` with owner/family/allowlist/status; `vaigil agent` commands; access-review integration. No new transport — works over stdio immediately. | Small; pure `internal/auth` + one new package. |
| **2. Mount the MCP HTTP endpoint** | `/mcp` via `internal/mcp/http.go`; RFC 9728 metadata; bearer + DPoP acceptance using existing `AuthenticateProved`; per-operation gates unchanged. | Small; the transport is already written and tested. |
| **3. Delegation** | OAuth 2.1 AS (code+PKCE, DPoP client auth), consent grants with tool-bundle scopes; `actor_token` exchange with intersection semantics; `Actor` chains in audit; chain-capped revocation. | Medium; the sensitive phase — needs the §8.2 invariants tested like `Exchange`'s are. |
| **4. Caveat tokens + budgets** | `internal/agent/capability` (HMAC macaroons); `Scope.Tools`; budget/deadline/purpose caveats; ledger records per §6.12 (`agent.step` entries, `Kind: ai`, no model prose). | Medium; isolated behind the Authorise hook. |
| **5. Maker-checker + kill switch + CAEP transmit** | Family-independence rule in `dual`/proposals; `agent revoke` + KillAll (dual-gated) + cascade; SSF transmitter for agent subjects. | Medium; composes existing primitives. |
| **6. Autonomy levels L2–L4** | Only after 1–5: the research §6.2 interpreter (playbook DAGs, taint, verifier, conformal gates) driving `automate.Propose` and reversible containment, with the closing direction permanently human. | Large; gated on the eval harness of §6.8. |

Each phase leaves the system in a state where the previous guarantees still hold — the property that makes the current architecture trustworthy is that every layer fails closed; the extension must inherit that, and every new gate added above (registry check, caveat check, family check) follows the existing rule: *absent means refused.*

---

## Appendix: file index

- Roles/bindings/policy/tokens: `/home/rashik/vaigil/internal/auth/auth.go`, `permission.go`, `scope.go`
- CLI gates: `/home/rashik/vaigil/cmd/vaigil/privilege.go`, `caller.go` (+ `privilege_test.go`)
- Admin routes/sessions/MFA: `/home/rashik/vaigil/internal/admin/server.go`, `idle.go`, `settings.go`, `people.go`, `oidcauth.go`, `tokenexchange.go`, `passkeys.go`
- MCP: `/home/rashik/vaigil/internal/mcp/mcp.go`, `http.go` (+ `cmd/vaigil/mcp.go`, `mcpsecurity.go`, `mcpestate.go`)
- Dual control: `/home/rashik/vaigil/internal/dual/dual.go` (+ `cmd/vaigil/dualcmd.go`, `internal/admin/dual.go`, `internal/incident/act.go`, `internal/automate/automate.go`)
- Audit protection: `/home/rashik/vaigil/internal/audit/{audit,merkle,sign}.go`, `/home/rashik/vaigil/internal/logd/logd.go`, `/home/rashik/vaigil/internal/anchor/anchor.go`, `/home/rashik/vaigil/cmd/vaigil/{auditlog,auditsign,auditanchor}.go`
- Agent vision prior art: `/home/rashik/vaigil//home/rashik/vaigil-research/04-ai-layer.md` §6.1–6.13
