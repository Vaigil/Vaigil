# 13 — Startup failure modes and AI-agent failure modes: a detection-content backlog

October 2026. This is the backlog for the detection pack: two catalogues of failure
and attack modes, each entry shaped so it can become a rule file in
`internal/detect/pack/` or a document in its `correlations.yml`, with the
fixture, the technique IDs and the response already decided. The goal is that
the platform ships content that matters on day one — the patterns that actually
breach startups and the agent failures nobody else detects — instead of generic
enterprise rules.

Sources for the threat picture: the local 2026 DBIR and M-Trends 2026 extracts
(`/home/rashik/vaigil-research/sources/pdf/`), the prior market research
(`/home/rashik/vaigil-research/06-market.md`), and the incident write-ups cited
per entry.

## How to read an entry

Each entry carries seven things:

1. **Name + one line** — written the way the pack's titles are written: a
   plain sentence a founder can read.
2. **Evidence** — the incident or statistic that says this happens.
3. **Telemetry** — the source and the fields, using the normalised event
   model's names (`source`, `message`, `raw.*`, `actor`, `disposition`,
   observables). Where the field does not exist yet, it is marked **new**.
4. **Logic** — which of the three mechanisms: a single rule (a predicate
   tree), a correlation (one of the four Sigma v2 types with window and
   condition), or a baseline (rarity against an entity's own history; the
   `internal/baseline` model reports the denominator and stays quiet below
   30 observations). Correlations count *rules*, not raw events, so every
   correlation names quiet base rules that exist only to feed it.
5. **Technique IDs** — ATT&CK, ATLAS, OWASP ASI / LLM Top 10.
6. **FP rate + fixture** — expected false positives, and the must-match /
   must-not-match fixtures in the pack's style.
7. **Response** — watch / ask / act, with the concrete action.

Framework ID notes. MITRE ATLAS: `AML.T0051` is LLM Prompt Injection (with
direct/indirect sub-techniques), `AML.T0010` ML Supply Chain Compromise,
`AML.T0024` Exfiltration via ML Inference API, and `AML.T0083` (Credentials
from AI Agent Configuration Files) per ATLAS case study AML.CS0045
([atlas.mitre.org](https://atlas.mitre.org),
[CS0045 write-up](https://www.startupdefense.io/mitre-atlas-case-studies/aml-cs0045-data-exfiltration-via-an-mcp-server-used-by-cursor)).
OWASP Top 10 for Agentic Applications 2026 (ASI): ASI01 Goal Hijack, ASI02
Tool Misuse & Exploitation, ASI03 Identity & Privilege Abuse, ASI04 Agentic
Supply Chain, ASI05 Unexpected Code Execution, ASI06 Memory & Context
Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures,
ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents
([Akto summary](https://www.akto.io/blog/owasp-top-10-agentic-applications),
[Zenity white paper](https://zenity.io/resources/white-papers/owasp-top-10-for-agentic-app-security)).

## Priority tiers

- **Tier 1 — ship first.** Deterministic, near-zero FP: the event itself is
  the finding (a control disabled, a forbidden action allowed, a documented
  bad thing). Every one must have fixtures before it lands.
- **Tier 2 — statistical.** Baselines and counting correlations; each needs a
  denominator and a tuning period. Ship second, per-tenant, with the
  baseline's "not yet" verdict respected.
- **Tier 3 — content-signature.** Matches against a feed (OSV, a
  malicious-skill list, domain-age) rather than behaviour. These are the
  auto-updating rules; they inherit their FP rate from the feed.

Entries note where they **share a correlation pattern** with another entry;
those are listed at the end of each catalogue.

---

# Catalogue A — Startup failure modes (40)

Why these forty: DBIR 2026 says small and medium businesses are breached by
System Intrusion, Basic Web Application Attacks and Social Engineering — 100%
of the SMB sample — all external, all financially motivated, with initial
access split exploitation 26% / credential abuse 13% / phishing 9% and
third-party involvement in 55% (local `dbir.txt`, SMB section). M-Trends 2026
adds: exploits 32% (top vector six years running), voice phishing up to 11%
and now the number-two vector, OAuth tokens and session cookies harvested
because they outlive logout, third-party SaaS integration tokens as the new
perimeter, hand-off from initial-access brokers to a second group in a median
22 seconds, and backups/identity/virtualisation deliberately destroyed
(local `mtrends.txt`). A startup with three security staff does not need
coverage; it needs the fifteen things that actually happen.

## A1. An MFA push was denied repeatedly and then one was allowed
1. **One line:** a person pushed "no" to several second-factor prompts and
   then said "yes" — fatigue or mistake, and the sign-in then succeeded.
2. **Evidence:** MFA-fatigue/push-bombing is the Uber-2022 pattern and is
   ATT&CK's textbook case for T1621; M-Trends 2026's voice-phicing surge is
   the interactive cousin, often ending in exactly this approval.
3. **Telemetry:** `duo/auth` — `raw.result` (`failure`/`success`),
   `raw.factor` (`push`), `actor.value` (user key).
4. **Logic:** quiet base rule `duo.push-denied` (all: message equals reason,
   raw.factor equals push, disposition equals failed), then a
   **temporal_ordered** correlation `corr.mfa-fatigue`: rules
   [duo.push-denied, duo.push-allowed], group-by `actor.value`, timespan
   30m. Ordered matters: deny-then-allow, not the reverse.
5. **Techniques:** T1621 (MFA Request Generation).
6. **FP:** low — a user fumbling their phone produces 2–3 denials, so the
   base rule alone stays quiet and only the ordered pair fires on ≥4 denials
   first (add `event_count ≥ 4` on the base rule in a 30m window if needed).
   Fixtures: "five push denials then a success for one user" (match);
   "one denial then success" (no match); "denials only" (no match).
7. **Response:** act — step-up: revoke the Duo session and force
   re-authentication; ask the user out-of-band.

## A2. A sign-in succeeded from a country that person has never signed in from
1. **One line:** first-time geography for a known identity.
2. **Evidence:** the AiTM kits (Evilginx-class) replay stolen session cookies
   through attacker infrastructure, and UNC5537's Snowflake access came from
   unfamiliar VPN egress (see A4); geography novelty is the common tell.
   M-Trends: session cookies harvested precisely because they outlive logout.
3. **Telemetry:** `okta/system`, `entra/signin`, `workspace/login`,
   `salesforce/login`, `snowflake/logins` — `raw.person` / `userPrincipalName`
   plus the country field each keeps (`client.geographicalContext.country`,
   `location.countryOrRegion`, `CountryIso`).
4. **Logic:** **baseline** — first-observation rarity per (person, country)
   against ≥30 prior sign-ins; the existing `okta.signin-through-proxy` rule
   covers the anonymising-proxy half deterministically.
5. **Techniques:** T1078 (Valid Accounts), T1557 (Adversary-in-the-Middle).
6. **FP:** medium-low — holidays and VPNs; the reported denominator ("0 of
   412 prior sign-ins") is what makes it triageable. Fixture: fixture runs on
   the baseline's own test harness; must-not-match is a repeat country.
7. **Response:** ask — notify the person; act (step-up) if the same person
   also matches A3.

## A3. One person's session appeared from two far-apart addresses within minutes
1. **One line:** token/cookie replay — the same account signing in
   successfully from two IPs no human could travel between.
2. **Evidence:** CircleCI 2023 — malware stole a post-2FA session cookie and
   impersonated the engineer
   ([incident report](https://circleci.com/blog/jan-4-2023-incident-report));
   Okta's own breach ran on .har files full of session cookies stolen from
   its support system ([Okta root-cause
   analysis](https://sec.okta.com/articles/2023/11/unauthorized-access-oktas-support-case-management-system-root-cause),
   [BeyondTrust's detection](https://www.beyondtrust.com/blog/entry/okta-support-unit-breach)).
3. **Telemetry:** `okta/system` user.session.start with `ip` observables;
   `entra/signin` with `ipAddress`; base rule `okta.signin-succeeded`
   (quiet) over successful session starts.
4. **Logic:** **value_count** correlation `corr.session-two-places`: rules
   [okta.signin-succeeded, entra.signin-succeeded], group-by `raw.person`,
   field `ip`, timespan 30m, condition gte 2. (Distance itself is not
   computable in the engine; two distinct addresses in half an hour is the
   honest proxy, and Cloudflare/geo enrichment can refine later.)
5. **Techniques:** T1550.001 (Application Access Token), T1528.
6. **FP:** low-medium (mobile carrier IP churn); severity high because both
   events must be *successes*. Fixtures: "two success IPs for one person in
   10m" (match); "a success and a failure" (no match); "two persons one IP"
   (no match — group-by is the person).
7. **Response:** act — kill sessions for that person, revoke refresh tokens,
   reset factor.

## A4. A Snowflake login used a password with no second factor
1. **One line:** the exact login shape UNC5537 used — single-factor on a
   warehouse that holds copies of everything.
2. **Evidence:** Mandiant: 165+ Snowflake customer tenants entered with
   infostealer-harvested credentials; every victim lacked MFA, several were
   stale trial tenants
   ([Google Cloud blog](https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion)).
3. **Telemetry:** `snowflake/logins` — `raw.FIRST_AUTHENTICATION_FACTOR`
   equals `PASSWORD`, `raw.SECOND_AUTHENTICATION_FACTOR` absent or `NONE`,
   disposition allowed.
4. **Logic:** single **rule** `snowflake.password-only-login`: all:
   message equals LOGIN, disposition equals allowed,
   raw.FIRST_AUTHENTICATION_FACTOR equals PASSWORD, any: raw.SECOND_AUTHENTICATION_FACTOR
   exists=false … expressed as a Not{Match exists} on the second-factor field.
5. **Techniques:** T1078.004 (Cloud Accounts), T1110 (Brute Force) family —
   really "stolen valid credential".
6. **FP:** near zero — legitimate integrations that use key-pair or OAuth
   don't say PASSWORD; the only benign case is a deliberately password-only
   service account, which belongs in the tenant's allowlist. Fixtures: "a
   password-only success" (match); "password + TOTP" (no match); "a failed
   password-only attempt" (no match — disposition).
7. **Response:** act — kill the Snowflake session, rotate the user, raise to
   critical if A5 fires for the same user.

## A5. A Snowflake or Salesforce integration account signed in from a new network
1. **One line:** a machine identity suddenly working from somewhere new.
2. **Evidence:** UNC6395 (Aug 2025): OAuth tokens stolen from one Salesforce
   integration vendor were replayed across 700+ orgs — the tell was in this
   login log (noted in `internal/source/known.go`); UNC5537's VPN/residential
   egress.
3. **Telemetry:** `snowflake/logins` (`USER_NAME` + `CLIENT_IP`),
   `salesforce/login` (`UserId` + `Application` + `SourceIp`).
4. **Logic:** **baseline** — first-observation rarity per (integration
   account, ASN or /24) against ≥30 priors. Peer comparison across the same
   *application* (per `target.value`) once several orgs run vaigil — not
   before.
5. **Techniques:** T1078.004, T1528.
6. **FP:** low — integration accounts are the most stable identities a
   startup has. Fixture: new /24 for SERVICE_ACCT with 200 priors (match);
   the usual collector IP (no match).
7. **Response:** act — revoke the integration's token/session; watch if the
   destination is a known corporate egress.

## A6. A second factor was reset and then the account signed in from a new country
1. **One line:** the helpdesk-vishing kill chain, compressed.
2. **Evidence:** M-Trends 2026 — vishing of IT helpdesks to reset MFA is a
   top-2 vector class; Uber-2022 and the 2023 MGM chain both ran through it.
   The pack already has `okta.mfa-reset`.
3. **Telemetry:** `okta/system` (reset event + session start with country),
   base rule `okta.signin-succeeded`.
4. **Logic:** **temporal_ordered** `corr.reset-then-strange-login`: rules
   [okta.mfa-reset, okta.signin-succeeded], group-by `raw.person`, timespan
   24h (the cap — a longer chain is a search, not a detection, and the
   correlate package enforces exactly that).
5. **Techniques:** T1621/T1656 (Impersonation), T1078.
6. **FP:** very low — resets are rare and legitimate resets are followed by
   the same old geography. Fixtures: "reset then new-country sign-in" (match);
   "reset then usual office" (no match); "new-country sign-in a week before
   the reset" (no match — ordered).
7. **Response:** act — kill session, revert the factor, contact the person
   through a channel the caller cannot hear.

## A7. An OAuth application was consented to by a user, not an admin
1. **One line:** illicit consent grant — a user handed a third-party app a
   standing token.
2. **Evidence:** M-Trends 2026 recommends locking down end-user consent
   precisely because token-grabbing apps are the persistence of choice;
   Microsoft's 2024 breach began with an OAuth app created from a test tenant
   ([SC Media](https://www.scworld.com/news/microsoft-fell-victim-to-oauth-attack-it-issued-warning-about)).
3. **Telemetry:** Entra audit log (`azure/activity` stream or the Entra
   audit connector) — message equals `Consent to application`,
   `raw.properties` carrying the scopes; also `okta/system`
   `user.grant.oauth.token` / `grant_type` events.
4. **Logic:** single **rule** `entra.oauth-consent-granted` (severity 3) plus
   a **temporal** correlation with `entra.legacy-protocol-signin`-style
   follow-on read rules if scopes include `mail.read`/`Files.Read.All`
   (scope text is a Contains on the raw payload).
5. **Techniques:** T1098.001 (Additional Cloud Credentials).
6. **FP:** medium alone (people connect tools); near zero when the scope
   list contains mailbox or files read. Fixtures: "user consent to app with
   mail.read" (match); "admin-consented enterprise app" (no match);
   "user consent to a vetted app" (no match, allowlist).
7. **Response:** ask — surface to the admin with a one-click revoke; act
   (revoke grant) on matching scopes.

## A8. A federation or token-signing configuration changed on the identity provider
1. **One line:** the 2024 Microsoft lesson — once an attacker can mint
   tokens, no password matters.
2. **Evidence:** Midnight Blizzard pivoted from a password-sprayed legacy
   *test tenant* into a production tenant through a privileged OAuth app and
   forged tokens for executive mail
   ([Microsoft statement](https://www.reddit.com/r/cybersecurity/comments/19aw15a/microsoft_actions_following_attack_by_nation),
   [pivot analysis](https://x.com/cnotin/status/1751028257405665773)).
3. **Telemetry:** `entra/signin`'s sibling audit stream — `Add domain`,
   `Update domain federation settings`, `Add service principal credentials`,
   `Set federation settings`; Okta `system.oauth.application.policy`... in
   okta terms: `raw.eventType` in org.* policy/authenticator updates.
4. **Logic:** single **rule** `entra.federation-changed` over the audit
   stream, message equals any of the four operations. Deterministic.
5. **Techniques:** T1649 (Steal or Forge Authentication Certificates),
   T1098, T1556 (Modify Authentication Process).
6. **FP:** near zero — these operations are change-controlled at any sane
   startup; a match outside a change window is the finding. Fixtures: "federation
   settings updated" (match); "domain verified" (no match); "read of
   federation config" (no match).
7. **Response:** act — break-glass posture: page, review, revert.

## A9. A Conditional Access or sign-on policy was weakened
1. **One line:** the control that would have caught everything else, switched
   off. The pack has `okta.policy-weakened`; Entra needs its twin.
2. **Evidence:** DBIR: only 23% of third-party cloud MFA exposures get fully
   remediated — policies drift off and stay off (local `dbir.txt`).
3. **Telemetry:** Entra audit — `Update Conditional Access policy` where the
   diff removes `requireMfa`/adds an exclusion; predicate on the operation
   plus raw diff Contains "disable".
4. **Logic:** single **rule** `entra.ca-policy-weakened`.
5. **Techniques:** T1562 (Impair Defenses), T1556.
6. **FP:** low — matches when the payload says disabled/removed, not on
   every policy edit. Fixtures: "policy deleted" (match); "policy report-only
   toggled on" (match, severity 3); "new policy created" (no match).
7. **Response:** ask — to the identity owner with the diff attached.

## A10. An IAM user was created and given an access key within minutes
1. **One line:** the classic cloud persistence hand-off — credentials
   manufactured, not stolen.
2. **Evidence:** M-Trends' 22-second hand-off between access brokers and a
   second cluster is the same shape at machine speed: create → use
   immediately (local `mtrends.txt`).
3. **Telemetry:** `aws/cloudtrail` — base rules `aws.iam-user-created`
   (CreateUser) and `aws.access-key-created` (CreateAccessKey), both quiet.
4. **Logic:** **temporal** `corr.iam-user-then-key`: rules
   [aws.iam-user-created, aws.access-key-created], group-by `actor.value`,
   timespan 15m. Shares the pattern with A11.
5. **Techniques:** T1136.003 (Cloud Account), T1098 (Account Manipulation).
6. **FP:** low — IaC pipelines do this constantly, so exclude actors whose
   user-agent is terraform/cloudformation via a Not on the `user_agent`
   observable. Fixtures: "CreateUser then CreateAccessKey for one actor 3m
   apart" (match); "CreateAccessKey alone" (no match); the terraform case
   (no match, and a fixture that must stay green).
7. **Response:** ask — with the actor's last-30-day history attached.

## A11. A cloud access key was used from a network it has never been used from
1. **One line:** the Snowflake pattern, CloudTrail edition — long-lived key,
   new geography.
2. **Evidence:** UNC5537 infostealer→replay chain applies to AWS keys
   identically; M-Trends on harvesting long-lived tokens.
3. **Telemetry:** `aws/cloudtrail` — `ip` observable + `userIdentity.arn`;
   first-use events (`eventName` in GetAccessKeyLastUsed family) are the
   cheapest signal.
4. **Logic:** **baseline** per (arn, ASN or country). Then a **temporal**
   correlation with A10's rules for the create-then-use-from-elsewhere
   chain, 24h.
5. **Techniques:** T1078.004, T1528.
6. **FP:** low for humans' keys, medium for CI keys (runner regions move);
   report the denominator and let the tenant tune. Fixture: new country for
   a deploy key with 90 priors (match); the usual region (no match).
7. **Response:** act — disable the key (that's why short-lived is the
   recommendation, but detect the long-lived world as it is).

## A12. The organisation's S3 public-access block was lowered
1. **One line:** the moment a bucket becomes the internet's bucket.
2. **Evidence:** public storage remains the signature "Miscellaneous Error"
   breach in DBIR's SMB slice (local `dbir.txt`).
3. **Telemetry:** `aws/cloudtrail` — message equals
   `PutAccountPublicAccessBlock` with the raw flags, or `PutBucketPolicy`.
4. **Logic:** single **rule** `aws.public-access-lowered` (Equals on the two
   messages; a Contains on raw for `"PublicAccessBlockConfiguration":
   "False"` where the connector keeps the request body). Note the pack's
   `Keep` list for CloudTrail does not carry the request body today — the
   connector must add it or the rule stays operation-only.
5. **Techniques:** T1562 (Impair Defenses); the read side is T1530.
6. **FP:** near zero — nobody lowers this accidentally and legitimately
   outside a one-off data-publish change. Fixtures: "account block set to
   false" (match); "bucket policy tightened" (no match); "block enabled"
   (no match).
7. **Response:** act — auto-revert via SOAR is defensible here; at minimum
   page.

## A13. Objects were read from a bucket in bulk by one identity
1. **One line:** the exfiltration half of the public-bucket or stolen-key
   story.
2. **Evidence:** UNC5537's data theft was bulk SELECTs; ransomware
   pre-encryption collection is bulk GETs (M-Trends recovery-denial section).
3. **Telemetry:** `aws/cloudtrail` — base rule `aws.s3-get` over GetObject
   successes (quiet, generate=false).
4. **Logic:** **event_count** `corr.s3-bulk-read`: rule [aws.s3-get],
   group-by `actor.value`, timespan 15m, condition gte 500 (tune per
   tenant). Shares the burst pattern with A22/A35.
5. **Techniques:** T1530 (Data from Cloud Storage), T1567.002.
6. **FP:** medium un-tuned (backup jobs) — exclude the backup role's arn in
   the base rule; the correlation only alerts on the count. Fixtures run on
   the correlation harness: 600 GETs by one arn in 10m (match); 600 across
   twenty arns (no match); 200 by one (no match).
7. **Response:** act — revoke the session/keys, quarantine the arn.

## A14. A Kubernetes request succeeded as system:anonymous
1. **One line:** an exposed API server or dashboard being used.
2. **Evidence:** exposed K8s dashboards/APIs remain a default-credential and
   exploitation staple in DBIR's Basic Web Application Attacks pattern.
3. **Telemetry:** `kubernetes/audit` — `actor.value` equals
   `system:anonymous`, disposition allowed (responseStatus 2xx).
4. **Logic:** single **rule** `k8s.anonymous-succeeded`, severity 4; and
   treat any *write* verb as 5.
5. **Techniques:** T1190 (Exploit Public-Facing Application), T1078.001
   (Default Accounts).
6. **FP:** near zero — anonymous success is a misconfiguration being used,
   full stop. Fixtures: "anonymous create pod, 201" (match); "anonymous list,
   403" (no match); "authenticated user create" (no match).
7. **Response:** act — network-block the source, rotate any exposed
   dashboard credentials.

## A15. A pod exec succeeded in production
1. **One line:** hands-on-keyboard inside the cluster, or a developer doing
   it by hand — either way it deserves eyes.
2. **Evidence:** M-Trends: interactive takeover after hand-off is the
   22-second problem; exec into pods is its cloud-native shape.
3. **Telemetry:** `kubernetes/audit` — verb create on `pods/exec`,
   `raw.objectRef.namespace`.
4. **Logic:** single **rule** `k8s.pod-exec` (severity 3) plus **baseline**
   rarity per `actor.value` so the one SRE who legitimately debugs weekly
   goes quiet after 30 observations.
5. **Techniques:** T1059.004 (Unix Shell) via exec.
6. **FP:** low after baseline; high for the first two weeks of a
   break-glass-free shop. Fixtures: "exec by a human account" (match);
   "exec by the CI service account" (no match, allowlist); "get pods"
   (no match).
7. **Response:** watch, escalate to ask if the actor also matches A14 or an
   unusual-namespace baseline.

## A16. Secrets were read from a cluster in bulk
1. **One line:** credential shopping inside Kubernetes.
2. **Evidence:** ransomware operators' recon-then-destroy of identity and
   backup material (M-Trends) starts with exactly this read pattern.
3. **Telemetry:** `kubernetes/audit` — verb get/list on resource `secret`.
4. **Logic:** base rule `k8s.secret-read` (quiet), then **value_count**
   `corr.k8s-secret-sweep`: field `raw.objectRef.name`, group-by
   `actor.value`, timespan 10m, gte 20. Shares the burst pattern.
5. **Techniques:** T1552.001 (Credentials In Files), T1213.
6. **FP:** low-medium (operators/GitOps read all secrets on sync) — exclude
   the sync service accounts in the base rule. Fixtures: "25 distinct
   secrets by one account in 5m" (match); "same secret 25 times" (no match
   — value_count counts distinct); "the GitOps controller" (no match).
7. **Response:** act — revoke the account's tokens; rotate cluster secrets.

## A17. An organisation app or OAuth app was installed on GitHub
1. **One line:** the standing token nobody rotates.
2. **Evidence:** tj-actions showed that one compromised integration's token
   is every customer's incident ([Wiz
   analysis](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066));
   CircleCI is the CI-shaped version.
3. **Telemetry:** `github/audit` — action in
   `org_integration_installation`, `integration_installation`,
   `org_oauth_app_access_granted`.
4. **Logic:** single **rule** `github.app-installed`, severity 3.
5. **Techniques:** T1098.001, T1199 (Trusted Relationship).
6. **FP:** low-medium (developers install tools); the rule exists to build
   the inventory that A18's baseline needs. Fixtures: "new OAuth app granted
   org access" (match); "app removed" (no match); "app's repo access
   updated" (no match).
7. **Response:** watch — feed the inventory; ask if the app is not in the
   tenant's approved list.

## A18. A GitHub actor's token was used from a new network
1. **One line:** the audit log's `actor_ip` says the session moved.
2. **Evidence:** tj-actions' victims leaked tokens in logs; Shai-Hulud's
   whole propagation loop is *stolen npm session tokens used from the
   attacker's host* ([CISA
   alert](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem),
   [Snyk on the May 2026 TanStack
   wave](https://snyk.io/blog/tanstack-npm-packages-compromised)).
3. **Telemetry:** `github/audit` — `ip` observable per actor.
4. **Logic:** **baseline** per (actor, ASN). Then **temporal** correlation:
   A17 (app installed) → A18 (new-network use) within 24h = likely
   attacker-installed app.
5. **Techniques:** T1528 (Steal Application Access Token).
6. **FP:** low — developers travel, but the ASN denominator absorbs it.
   Fixture: new ASN for `dana-gh` with 60 priors (match); home ASN (no
   match).
7. **Response:** act — revoke the PAT/OAuth grant via SOAR.

## A19. Push protection was bypassed on a repository
1. **One line:** somebody pushed past the secret-scanning guardrail — the
   guardrail said so.
2. **Evidence:** keys-in-repos are the starter of CircleCI/Shai-Hulud-class
   chains; the pack already fires when scanning is *disabled*
   (`github.secret-scanning-disabled`); the bypass is the per-push twin.
3. **Telemetry:** `github/audit` — action equals
   `secret_scanning_push_protection_bypassed`.
4. **Logic:** single **rule** `github.push-bypassed`.
5. **Techniques:** T1552.001, T1562.
6. **FP:** low — legitimate bypasses are rare and should carry a ticket
   number. Fixtures: "bypass recorded" (match); "alert resolved as used in
   tests" (no match); "scanning disabled" (no match — different rule).
7. **Response:** act — rotate the named secret; ask if the alert names a
   test fixture pattern.

## A20. A self-hosted GitHub runner was registered
1. **One line:** a machine with your org's secrets joined the fleet.
2. **Evidence:** the runner is where tj-actions' payload ran; self-hosted
   runners on public repos are a standing GitHub advisory.
3. **Telemetry:** `github/audit` — action in
   `self_hosted_runner_group_runner_registered`,
   `repository_self_hosted_runner_updated`.
4. **Logic:** single **rule** `github.runner-registered`, severity 4 when
   the repo is public (raw visibility field if the connector keeps it).
5. **Techniques:** T1195.002 (Compromise Software Supply Chain).
6. **FP:** near zero — registration is a deliberate act. Fixtures:
   "runner registered to private repo" (match, sev 3); "public repo" (match,
   sev 5); "runner removed" (no match).
7. **Response:** act — quarantine the runner group, ask on intent.

## A21. A repository's visibility was changed to public
1. **One line:** the accidental (or hostile) publication of the whole
   company.
2. **Evidence:** DBIR misconfiguration breaches; every startup's near-miss.
3. **Telemetry:** `github/audit` — action `repo.archived`... precisely:
   `repository_visibility_change` / `repo.change_visibility` (name per
   GitHub's audit schema).
4. **Logic:** single **rule** `github.repo-made-public` on
   private→public direction only.
5. **Techniques:** T1562, T1530 (once public, it's data from a repo).
6. **FP:** near zero for private→public; public→private must not match.
   Fixtures: "private to public" (match); "public to private" (no match);
   "repo transferred within org" (no match).
7. **Response:** act — revert visibility and rotate any repo-scoped secrets.

## A22. One identity downloaded from a SaaS data store in bulk
1. **One line:** the leaver or the compromised account, measured in rows.
2. **Evidence:** DBIR privilege-misuse and insider patterns; the Snowflake
   breaches were bulk exports.
3. **Telemetry:** **gap** — vaigil connects Snowflake *logins* and
   Salesforce *logins*, not query/history logs. This entry is the reason to
   add `snowflake/history` (QUERY_HISTORY) and `salesforce/eventmonitor`
   sources; the detection is written for them.
4. **Logic:** **event_count** over a quiet `snowflake.rows-read`-style base
   rule (connector aggregates rows scanned per query into `raw.rows`), or a
   single rule with an `Above` on `raw.rows`. Shares the burst pattern with
   A13/A16.
5. **Techniques:** T1213 (Data from Information Repositories), T1537.
6. **FP:** low once BI-tool service accounts are in the base rule's
   allowlist. Fixture: 2M rows by a human account (match); the weekly
   Looker extract (no match).
7. **Response:** act — kill the session, snapshot the audit trail first.

## A23. An admin reset another person's credentials outside their own timezone hours
1. **One line:** the helpdesk-vishing primitive, caught at the reset.
2. **Evidence:** M-Trends: unauthorised MFA-reset requests via voice are a
   named training target now; `okta.mfa-reset` exists but does not ask
   *who reset whom, when*.
3. **Telemetry:** `okta/system` — reset events where actor ≠ target, plus
   each side's country fields.
4. **Logic:** the predicate tree cannot compare two fields to each other, so
   the connector exposes the fact: base **rule** `okta.admin-reset` (quiet,
   severity 2) matches the admin-initiated reset action names, and the
   correlation A6 supplies the consequence. The honest form is the chain,
   not a standalone rule.
5. **Techniques:** T1656 (Impersonation), T1078.
6. **FP:** medium alone (helpdesks do this all day) — that is why it only
   matters inside A6.
7. **Response:** ask — verify with the *target* person out-of-band.

## A24. A dormant account signed in
1. **One line:** nobody had used this account for 90 days; today somebody
   did.
2. **Evidence:** Microsoft's test tenant was exactly a dormant, no-MFA
   foothold; Snowflake trial tenants the same.
3. **Telemetry:** all auth sources; the baseline package's absence framing.
4. **Logic:** **baseline** in the "silence then activity" form — needs the
   Falling side of the engine (the correlate package already warns about
   `lte` semantics for exactly this); per-person event_count of sign-ins
   `lte 1` over 90d followed by a success inside 24h. Implemented as a
   temporal correlation over a quiet `*.dormant-signin` rule the store
   emits from its own history.
5. **Techniques:** T1078, T1078.001.
6. **FP:** low — returning from leave is the benign case; the 90d threshold
   absorbs it. Fixture: success after 120 idle days (match); weekly user
   (no match).
7. **Response:** act — disable pending verification.

## A25. A sign-in succeeded over a legacy protocol (reference)
`entra.legacy-protocol-signin` and `aws.root-account-used` already exist and
are exactly right; listed so the coverage map counts them. Techniques:
T1550/T1078. Response: act.

## A26. CloudTrail was tampered with (reference)
`aws.trail-tampered` exists. M-Trends adds the sibling that does not exist
yet: **a log stream that stops sending** — "configure repositories to alert
on unexpected log termination" (local `mtrends.txt`). That is a platform
heartbeat (`internal/logd`/spool), not a rule, but the backlog item is: a
**falling event_count** per source (`source` group-by, `lte 0` over 2× the
source's declared lateness) labelled "log went quiet", with the same
severity as tampering. Techniques: T1562.008.

## A27. An endpoint's audit daemon was stopped or its logs cleared
1. **One line:** Linux-side anti-forensics.
2. **Evidence:** M-Trends anti-forensics section — clearing system logs
   makes scope unknowable (local `mtrends.txt`).
3. **Telemetry:** `auditd/events` — process events with exe in
   (systemctl/auditctl/service) and raw.comm contains audit; plus file
   events on /var/log/audit.
4. **Logic:** two single **rules**: `auditd.auditd-stopped` and
   `auditd.log-file-deleted` (exe in rm/shred, file observable suffix
   `/var/log/audit/audit.log`); command-history deletion
   (`rm .bash_history`) is the third.
5. **Techniques:** T1070.002 (Clear Linux System Logs), T1070.003 (Clear
   Command History), T1070.004.
6. **FP:** near zero for the audit.log path; medium for .bash_history (some
   dotfile managers) — keep that one severity 3. Fixtures: "rm
   /var/log/audit/audit.log" (match); "logrotate move" (no match —
   suffix/comm distinct); "journalctl --vacuum" (match, sev 4).
7. **Response:** act — isolate the host (CrowdStrike/Jamf action) — this is
   the M-Trends "destroy the evidence" move.

## A28. A CI secret appeared in a public workflow log
1. **One line:** the tj-actions payload's exact behaviour, seen from the
   runner side.
2. **Evidence:** CVE-2025-30066 dumped `/proc/self/environ` into public
   Actions logs across ~23k repos ([Wiz](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066),
   [CISA](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction)).
3. **Telemetry:** **gap** — GitHub's audit log does not carry workflow-run
   output; a `github/workflow` source (workflow job events) plus runner-side
   file/egress telemetry (auditd or the runner's egress) is needed. On the
   runner, the payload was a base64 `cat /proc/self/environ`.
4. **Logic:** auditd **rule**: execve with argument containing
   `/proc/self/environ` from a runner host (Arguments aren't in the Keep
   list — connector addition), severity 5.
5. **Techniques:** T1552.001, T1567 (exfil into public log).
6. **FP:** near zero off-runner; the rule is scoped to hosts tagged as
   runners.
7. **Response:** act — kill the job, rotate all org secrets exposed to that
   workflow.

## A29. A workflow file was changed to run on pull_request_target
1. **One line:** the file that gives forks your secrets.
2. **Evidence:** the persistent pattern behind Actions compromises,
   including tj-style tag rewriting ([StepSecurity detection
   notes](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised)).
3. **Telemetry:** **gap** — needs the `github/workflow` source (workflow
   file pushes are in the audit log as `repo.push` but without content).
4. **Logic:** **rule** on push events whose diff (connector-supplied
   `raw.diff_contains`) contains `pull_request_target` — content-signature
   tier once the source exists.
5. **Techniques:** T1195.002.
6. **FP:** low — legitimate uses exist and get an allowlist.
7. **Response:** ask — to the repo owner with the diff.

## A30. An Actions runner pulled a package version published minutes earlier by a new maintainer
1. **One line:** the Shai-Hulud propagation shape, seen at install time.
2. **Evidence:** the worm authenticates as compromised maintainers and
   publishes new versions that installs pull immediately; the May 2026
   TanStack wave hit 84 artifacts across 42 packages
   ([Snyk](https://snyk.io/blog/tanstack-npm-packages-compromised),
   [CISA Sep 2025](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem),
   [Datadog on Shai-Hulud 2.0](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm)).
3. **Telemetry:** **new** source `registry/npm` (registry webhooks: package
   publish, maintainer change) + runner-side install logs (auditd execve of
   npm/pnpm or a `github/workflow` step).
4. **Logic:** **temporal** `corr.fresh-package-used`: rules
   [npm.package-published (quiet), npm.package-installed (quiet)], group-by
   the package name, timespan 1h, condition — published < 60m before
   install. Then **Tier 3**: package@version on the known-bad feed.
5. **Techniques:** T1195.001 (Software Dependencies).
6. **FP:** low-medium — fast-follow publishes are real; the maintainer-age
   field (new maintainer) sharpens it.
7. **Response:** act — quarantine the runner cache; ask on the repo owner.

## A31. A dependency was installed that did not exist last week (slopsquatting)
1. **One line:** the hallucinated-name attack — an agent or dev installs a
   package whose only history is being freshly registered under an
   AI-suggested name.
2. **Evidence:** 21.7% of packages suggested by open-weight models don't
   exist ([arXiv 2406.10279](https://arxiv.org/html/2406.10279v3));
   Lanyado's `huggingface-cli` experiment drew 30k downloads; CSA research
   note Apr 2026 ([CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-slopsquatting-ai-supply-chain-20260419-csa)).
3. **Telemetry:** the `registry/npm`/`registry/pypi` webhook source from
   A30 (registration age), plus the agent/CI install event.
4. **Logic:** **rule** with `Above`/`Below` on `raw.age_days` Below 7 AND
   install disposition allowed. Content-signature + age heuristic.
5. **Techniques:** T1195.001; ATLAS AML.T0010.
6. **FP:** medium — every genuinely new library looks like this; only alert
   on installs *not* present in the lockfile diff the dev intended.
7. **Response:** ask — revert the lockfile change; act if the same session
   matches B-series egress.

## A32. An OAuth grant or token outlived its owner
1. **One line:** the tokens of someone who left last month still work.
2. **Evidence:** M-Trends: tokens remain valid post-logout and become the
   ignored perimeter; leaver hygiene is the classic insider gap.
3. **Telemetry:** auth sources + the estate's workforce list
   (`internal/workforce`); GitHub app installations.
4. **Logic:** **temporal** correlation is the wrong tool past 24h — this is
   a scheduled *posture* report: active tokens whose `raw.person` left the
   workforce directory. Tier 2, computed nightly, not a stream rule.
5. **Techniques:** T1078.004, T1098.001.
6. **FP:** low (contractor renewals) — the report carries the owner.
7. **Response:** act — revoke; this one should be automatic.

## A33. A third-party integration's tokens changed behaviour
1. **One line:** UNC6395 — the vendor you trusted, from someone else's
   chair.
2. **Evidence:** stolen Salesforce integration OAuth tokens used across
   700+ orgs, Aug 2025 (documented in `internal/source/known.go`; M-Trends'
   "integrations are the new perimeter").
3. **Telemetry:** `salesforce/login` Application field; `snowflake/logins`
   REPORTED_CLIENT_TYPE.
4. **Logic:** **baseline** per (application, country/ASN) — A5 generalised;
   plus a **value_count** on distinct target applications per token subject
   where the platform exposes it.
5. **Techniques:** T1199 (Trusted Relationship), T1528.
6. **FP:** low.
7. **Response:** act — revoke the grant; notify the vendor.

## A34. An edge rule was disabled on Cloudflare
1. **One line:** the WAF rule that faced the internet, turned off before an
   exploit.
2. **Evidence:** DBIR: exploitation is now the #1 initial-access vector
   (31%) — removing the edge control is the enabling step (local
   `dbir.txt`).
3. **Telemetry:** **new** stream `cloudflare/audit` (zone/ruleset audit
   events — the connector today ships only `firewall`).
4. **Logic:** single **rule** `cloudflare.rule-deleted` on ruleset delete /
   firewall rule disable actions.
5. **Techniques:** T1562.
6. **FP:** near zero.
7. **Response:** act — re-enable via API is safe enough to automate.

## A35. One address sprayed many accounts at one SaaS
1. **One line:** password spray, already modelled — `corr.password-spray`
   in `correlations.yml` covers okta/entra/workspace; extend it.
2. **Evidence:** password spray is how the Microsoft test tenant fell.
3. **Logic:** extend the existing **value_count** correlation with
   `salesforce/login`, `snowflake/logins`, `duo/auth` failure rules and
   `slack/audit` — one pattern, five more sources. Shares the burst pattern.
4. **Techniques:** T1110.003.
5. **FP:** low (NAT'd offices) — the gte 10 threshold plus distinct-person
   count handles it.
6. **Response:** act — block at the edge; step-up the tenant.

## A36. Backup or snapshot deletion in the cloud
1. **One line:** M-Trends' recovery-denial move as a cloud API call.
2. **Evidence:** attackers "systematically delete backup objects from cloud
   storage" (local `mtrends.txt`).
3. **Telemetry:** `aws/cloudtrail` — DeleteSnapshot, DeleteBackupSelection,
   DeleteRecoveryPoint, continuous_backup Delete.
4. **Logic:** single **rule** `aws.backup-deleted` over those event names,
   severity 5.
5. **Techniques:** T1490 (Inhibit System Recovery), T1485.
6. **FP:** near zero — retention jobs are the exception and get an allowlist
   on the backup role's arn. Fixtures: "DeleteRecoveryPoint by a human
   role" (match); "by the lifecycle role" (no match).
7. **Response:** act — freeze the account's delete permissions; page. This
   is minutes-before-ransomware.

## A37. An encryption key or vault was destroyed
1. **One line:** the destroy-the-recovery variant for KMS.
2. **Evidence:** same M-Trends section — denying recovery as the pressure
   tactic.
3. **Telemetry:** `aws/cloudtrail` ScheduleKeyDeletion, `azure/activity`
   vault delete, plus `evm/*` ownership transfers are the on-chain sibling
   the pack already covers.
4. **Logic:** single **rule** `aws.key-deletion-scheduled`.
5. **Techniques:** T1486/T1490.
6. **FP:** near zero (the 30-day KMS window is the response window).
7. **Response:** act — cancel the deletion immediately.

## A38. Files were staged to a file-sharing or webhook destination
1. **One line:** exfiltration over a legitimate service.
2. **Evidence:** T1567.004 is now a named malicious-package exfil channel
   ([Checkmarx "Webhook Party"](https://checkmarx.com/blog/webhook-party-malicious-packages-caught-exfiltrating-data-via-legit-webhook-services)).
3. **Telemetry:** **gap** — needs a DNS/egress source; Cloudflare's
   firewall stream only reports what it *blocked*.
4. **Logic:** once an `egress/dns` or L7 egress source exists: **value_count**
   of distinct external destinations per person with bytes `Above` a
   tenant-tuned threshold — Tier 2. The deterministic Tier-1 piece that
   works *today*: Cloudflare **rule** on `action equals block` where
   `raw.ruleId` is the DLP/webhook rule and `clientCountry` differs from
   the actor's usual — weak; honest answer: blocked-only telemetry bounds
   this.
5. **Techniques:** T1567.004, T1567.002.
6. **FP:** medium — marketing uploads to Drive all day.
7. **Response:** ask — with the volume and destination history.

## A39. Shadow AI: corporate data submitted to an unapproved model service
1. **One line:** the DBIR's fastest-growing insider action, on our own
   telemetry.
2. **Evidence:** Shadow AI is the #3 non-malicious insider DLP action;
   source code is the #1 submitted data type; 67% of users reach AI services
   from non-corporate accounts (local `dbir.txt`).
3. **Telemetry:** the same future egress source as A38 (DNS/SNI to model
   APIs), or the agent proxy of Catalogue B for the sanctioned half.
4. **Logic:** **baseline** — first-observation per (person, destination
   domain not in the approved AI list); the approved-list comparison is a
   rule-level Not{equals on the allowlist} which the engine supports.
5. **Techniques:** T1567; OWASP LLM03 supply-chain adjacency.
6. **FP:** medium — this is policy, and the list is the tenant's.
7. **Response:** watch (report) — this is a posture metric more than an
   alert.

## A40. The browser session of an engineer was harvested (composite)
1. **One line:** infostealer on a laptop is the upstream cause of A3/A4/A11
   — detect the endpoint half.
2. **Evidence:** UNC5537 (infostealer origins), CircleCI (session cookie
   theft), QUIETVAULT (stealers now check for AI CLI tools and their config
   files — local `mtrends.txt`).
3. **Telemetry:** `crowdstrike/detections` (a detection source — treat its
   verdicts as findings, severity carried through) plus `jamf/events`.
4. **Logic:** not a new rule — a **correlation** pattern: any
   crowdstrike detection classified credential-access (raw.behaviors.tactic
   Contains `Credential Access`) followed within 24h by A4/A11/A2 for any
   identity that used that device. **temporal_ordered**, group-by the
   device.
5. **Techniques:** T1555 (Credentials from Password Stores), T1539 (Steal
   Web Session Cookie).
6. **FP:** low — the endpoint already said malware; the chain only ranks
   the blast radius.
7. **Response:** act — this chain is the auto-rotate trigger.

---

# Catalogue B — AI-agent failure and attack modes (30)

This is the differentiator: the SOC platform *for* agents. None of these are
detectable with the current 18 sources; all of them become detectable with
one addition plus the model that is already built.

## The telemetry prerequisite

Two new sources, both outside the agent's trust boundary (the arXiv
2609.30266 result — 5 of 6 major harnesses delete their own traces when
asked — says in-process logs are not evidence; local `06-market.md` §5.1):

- **`mcp/proxy`** — tool calls observed at an MCP gateway/forward proxy
  (agentgateway, mcphub, or vaigil's own sidecar). Class 6003 (API
  activity), activity 1. Fields: `actor.value` = agent id (issuer
  `mcp`), `raw.session_id`, `raw.tool_name`, `raw.server_name`,
  `raw.tool_args_hash` (sha256 of normalised args — never the args
  themselves; args are attacker-influenced and the event model already
  treats `message` as hostile), `raw.effect` (verb the connector
  classified: `read.untrusted`, `read.sensitive`, `write`, `execute`,
  `egress`, `schema.change`), `raw.sensitivity` (data-class label of what
  was touched: `public`, `internal`, `secret`), `raw.tokens_in`/`tokens_out`,
  `raw.model`, `raw.verified` (schema hash matches the pinned AI-BOM
  entry), observables: `domain`/`url` for egress destinations, `ip`.
- **`agent/registry`** — lifecycle events for agents, MCP servers and
  skills: installed, updated, enabled, heartbeat. Class 3001 (account
  change) or 6003. Fields: `raw.component` (`agent`/`mcp`/`skill`/`model`),
  `raw.name`, `raw.version`, `raw.sha256`, `raw.source_registry`,
  `raw.declared` (present in the AI-BOM manifest or not).

The OTel GenAI semantic conventions (`gen_ai.*`, `mcp.method.name`,
`mcp.session.id`) already define the wire shape
([semconv status](https://john-hodge.com/blog/opentelemetry-genai-semantic-conventions/));
a collector emits both sources from one span stream. Per the market research,
OCSF has no agent class and Sigma has no GenAI logsource — proposing both
upstream is part of this backlog, not a prerequisite for it.

## B1. A pinned MCP tool's schema changed underneath the pin
1. **One line:** the rug pull, seen at the gateway — same version, new
   instructions to the model.
2. **Evidence:** postmark-mcp shipped 15 benign versions, then v1.0.16 BCC'd
   every email to the attacker — the first in-the-wild malicious MCP server
   ([Snyk](https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails),
   [The Register](https://www.theregister.com/2025/09/29/postmark_mcp_server_code_hijacked/));
   tool descriptions enter context as trusted instructions (Invariant tool
   poisoning, local `06-market.md` §4.3).
3. **Telemetry:** `agent/registry` update events + `mcp/proxy` tool-list
   responses — `raw.sha256` of the tool schema/description against the
   AI-BOM pin; the connector emits `raw.verified=false`.
4. **Logic:** single **rule** `mcp.tool-schema-drift`: all: source equals
   agent/registry, raw.component equals mcp, raw.verified equals false.
   Deterministic — the hash comparison happens in the connector, the rule
   just refuses to be quiet about it.
5. **Techniques:** ATT&CK T1195.002; ATLAS AML.T0010; OWASP ASI04, LLM03.
6. **FP:** near zero — a pinned server's schema hash changing *is* the
   finding; unpinned servers are excluded by requiring the pin to exist
   (raw.declared true). Fixtures: "pinned tool, hash differs" (match);
   "unpinned tool updated" (no match — different rule, posture); "hash
   matches pin" (no match).
7. **Response:** act — quarantine the tool at the gateway (pin the previous
   schema), notify the owner; this is the exact SOAR action the market
   research flags as unserved.

## B2. An agent sent data to a destination it has never sent to, right after reading untrusted content
1. **One line:** the lethal trifecta completed — untrusted read → sensitive
   read → egress, in one session.
2. **Evidence:** the GitHub MCP exploit leaked private repos through a
   public issue
   ([Willison](https://feeds.simonwillison.net/2025/May/26/github-mcp-exploited));
   the Supabase MCP leak was the same shape with root on the database
   ([Pomerium, "When AI Has Root"](https://www.pomerium.com/blog/when-ai-has-root-lessons-from-the-supabase-mcp-data-leak));
   Invariant's toxic-flow formalisation (local `06-market.md`).
3. **Telemetry:** `mcp/proxy` — three quiet base rules:
   `agent.untrusted-read` (raw.effect equals read.untrusted — web fetch,
   issue read, email read), `agent.sensitive-read` (raw.effect equals
   read.sensitive OR raw.sensitivity in [internal, secret]),
   `agent.egress-call` (raw.effect equals egress).
4. **Logic:** **temporal_ordered** `corr.lethal-trifecta`: rules
   [agent.untrusted-read, agent.sensitive-read, agent.egress-call],
   group-by `raw.session_id`, timespan 1h. Ordered: the untrusted read must
   precede the sensitive read, which must precede egress — that ordering is
   what separates a hijack from a search.
5. **Techniques:** ATLAS AML.T0051.001 (indirect prompt injection),
   ATT&CK T1567; OWASP ASI01/ASI02, LLM01/LLM06.
6. **FP:** the reason this is tier-1 despite being a correlation: agents
   that legitimately do all three (research assistants) are labelled at
   onboarding and the *session* pattern — the same session, ordered — is
   rare even for them. Fixtures: "fetch issue → read private repo → POST to
   webhook, one session" (match); "read private repo then fetch issue, no
   egress" (no match — no sink); "fetch → sensitive read with no egress"
   (no match); egress first (no match — ordered).
7. **Response:** act — kill the session at the gateway, quarantine the
   egress tool; watch if the destination is on the approved list.

## B3. An agent performed a destructive operation on a production resource
1. **One line:** drop-table / delete-repo / mass-delete, executed with
   agent-held privileges.
2. **Evidence:** Replit's agent deleted a production database during a code
   freeze ([Fortune](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure),
   [AIID 1152](https://incidentdatabase.ai/cite/1152)); Amazon Q's
   full-auto mode was led by a prompt injection in a GitHub issue to try
   mass deletion ([ReversingLabs](https://www.reversinglabs.com/blog/aws-amazonq-ai-incident),
   [Adversa](https://adversa.ai/blog/amazon-ai-coding-assistant-q-incident-lessons-learned)).
3. **Telemetry:** `mcp/proxy` — the connector classifies the operation into
   `raw.effect` (execute/write verbs on schemas/files); target resource in
   observables; `raw.environment` (prod/staging) where the gateway knows.
4. **Logic:** single **rule** `agent.destructive-effect`: all: raw.effect
   equals one of [schema.drop, file.mass-delete, repo.purge],
   disposition equals allowed. Optionally And raw.environment equals
   production for severity 5.
5. **Techniques:** ATT&CK T1485 (Data Destruction), T1490; OWASP ASI02,
   ASI08 (cascading), LLM06 (Excessive Agency).
6. **FP:** near zero — the connector's verb classification is conservative
   and these effects have no benign mapping; a migration tool doing drops
   is allowlisted by tool name. Fixtures: "DROP TABLE by db tool" (match);
   "EXPLAIN TABLE" (no match); "drop on staging" (match, sev 4);
   "migration tool, allowlisted" (no match).
7. **Response:** act — kill session, revoke the agent's DB credential;
   this is the case for the two-person rule the research recommends.

## B4. An agent fetched a cloud metadata or internal admin endpoint
1. **One line:** the SSRF-shaped tool call — the agent reading the
   instance's own credentials.
2. **Evidence:** the confused-deputy/credential-harvesting step of every
   injection-to-theft chain; ATLAS case study AML.CS0045 is exactly this
   via an MCP server used by Cursor
   ([write-up](https://www.startupdefense.io/mitre-atlas-case-studies/aml-cs0045-data-exfiltration-via-an-mcp-server-used-by-cursor)).
3. **Telemetry:** `mcp/proxy` — url/ip observables on fetch/http tools.
4. **Logic:** single **rule** `agent.ssrf-metadata`: match on `ip` Inside
   169.254.0.0/16 (the engine's `Inside` operator exists for exactly this)
   or url Contains `169.254.169.254`, plus a second for
   `metadata.google.internal` / `*.amazonaws.com` admin paths. Blocking is
   the gateway's job; the rule catches what was allowed.
5. **Techniques:** ATT&CK T1552.005 (Cloud Instance Metadata API);
   ATLAS AML.T0083; OWASP ASI02.
6. **FP:** near zero — no legitimate agent tool talks to link-local
   metadata. Fixtures: "fetch to 169.254.169.254" (match); "fetch to
   api.stripe.com" (no match); "blocked attempt" (match, disposition
   detected, sev 3).
7. **Response:** act — kill session; rotate the instance role if allowed.

## B5. An agent's session credentials were presented from a second address
1. **One line:** session hijack — one session id, two sources.
2. **Evidence:** agents hold long-lived OAuth/session tokens (M-Trends'
   harvested-token pattern applied to non-human identities).
3. **Telemetry:** `mcp/proxy` — `raw.session_id` + ip observable per call.
4. **Logic:** quiet base rule `agent.call` then **value_count**
   `corr.agent-session-two-sources`: field `ip`, group-by `raw.session_id`,
   timespan 30m, gte 2. Shares the A3 pattern exactly.
5. **Techniques:** T1550.001; OWASP ASI03.
6. **FP:** low — NAT/VPN switches produce adjacent ASNs; severity from the
   ASN distance the enricher carries.
7. **Response:** act — kill the session at the gateway (the response the
   agent itself cannot delete).

## B6. A tool returned content carrying injection markers, and the session then called an egress tool
1. **One line:** telemetry for prompt injection, as a *sequence*, not a
   block.
2. **Evidence:** regex-on-text detection tops out at 1–5% recall (local
   `06-market.md`, ATR finding) — which is why the marker alone is sev 2
   and the *consequence* is the detection.
3. **Telemetry:** `mcp/proxy` — the gateway scans tool outputs for the
   standard marker set (ignore previous instructions, tool/system-prompt
   disclosure asks, base64 blobs, hidden-unicode instructions) and emits
   `raw.injection_markers` with disposition `detected`.
4. **Logic:** quiet rule `agent.injection-marker` (disposition equals
   detected) then **temporal_ordered** `corr.marker-then-egress`: rules
   [agent.injection-marker, agent.egress-call], group-by `raw.session_id`,
   timespan 10m. The marker without the consequence stays a watch metric.
5. **Techniques:** AML.T0051.001; LLM01/LLM05; ASI01.
6. **FP:** low as a pair — markers alone fire on documentation quoting
   attacks (that's the point of not alerting on them alone). Fixtures:
   "marker then POST" (match); "marker then another read" (no match);
   "egress with no prior marker" (no match).
7. **Response:** act — kill session; feed the marker text to the analyst,
   never back to a model (the event model already treats `message` as
   hostile — B6's marker payload lives under the same rule).

## B7. An agent's recorder went quiet while the agent kept working
1. **One line:** the arXiv finding as a detection — the agent's own trace
   stopped, the independent one didn't.
2. **Evidence:** 5 of 6 harnesses (Claude Code, Codex, Antigravity, Open
   Code, Grok Build) delete their traces on request without tripping
   guardrails; the fix is interception the agent cannot control
   ([arXiv 2609.30266](https://arxiv.org/abs/2609.30266); local
   `06-market.md`).
3. **Telemetry:** `agent/registry` heartbeat per agent id (the sidecar's
   liveness), `mcp/proxy` continuing to see calls from the same
   `raw.agent_id`.
4. **Logic:** **falling event_count** `corr.recorder-blind`: rule
   [agent.heartbeat], group-by `actor.value`, timespan 15m, condition lte 0
   — with the correlate package's own warning honoured: the group set is
   bounded by agents that *have* heartbeated before (the Falling()
   semantics note in `internal/correlate`). The proxy-saw-calls half is a
   temporal companion: heartbeat-gap while `agent.call` count for the same
   id is above zero.
5. **Techniques:** ATT&CK T1070.004 (Indicator Removal: File Deletion) —
   applied to agent traces; OWASP ASI10 (Rogue Agents: concealment).
6. **FP:** near zero — a sidecar restart under 15m is absorbed; the
   *combination* (blind recorder, live agent) has no benign mapping.
7. **Response:** act — kill the session; the tamper-evident audit chain
   already holds what the agent tried to erase.

## B8. A skill or model was loaded whose hash is not in the manifest
1. **One line:** ClawHavoc and nullifAI at load time.
2. **Evidence:** ClawHavoc poisoned 341+ (later counted 1,184+) skills on
   ClawHub with Atomic Stealer, alongside OpenClaw gateway RCE exploited
   in the wild ([Antiy](https://www.antiy.net/p/clawhavoc-analysis-of-large-scale-poisoning-campaign-targeting-the-openclaw-skill-market-for-ai-agents/));
   nullifAI models bypassed HF's picklescan with crafted Pickle files
   ([ReversingLabs](https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face),
   [Wiz](https://threats.wiz.io/all-incidents/malicious-ai-models-bypass-picklescan-detection)).
3. **Telemetry:** `agent/registry` — `raw.component` in [skill, model],
   `raw.sha256`, `raw.declared`.
4. **Logic:** two rules. `agent.undeclared-skill-loaded` (raw.declared
   equals false — deterministic, the manifest is the tenant's own) and
   Tier-3 `agent.skill-hash-on-feed` against the malicious-skill feed the
   vuln pipeline already models (SBOM→OSV extended to AI-BOM; local
   `06-market.md` §5.6).
5. **Techniques:** T1195.001; AML.T0010; ASI04, LLM03.
6. **FP:** near zero for the undeclared rule (it *is* the inventory
   check); the feed rule inherits the feed's FP rate.
7. **Response:** act — block the hash at the gateway; quarantine the agent
   that loaded it (Atomic Stealer means assume endpoint compromise).

## B9. A model file was deserialised without being scanned
1. **One line:** the nullifAI primitive — a Pickle loaded that the scanner
   never saw.
2. **Evidence:** nullifAI (above); JFrog's silent-backdoor HF models
   ([JFrog](https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor)).
3. **Telemetry:** `agent/registry` or `mcp/proxy` model-load events —
   `raw.format` equals pickle/safetensors, `raw.scanned` true/false,
   `raw.model_registry`.
4. **Logic:** single **rule** `agent.unscanned-model-load`: all:
   raw.format equals pickle, raw.scanned equals false. Plus
   `agent.model-off-registry`: raw.model_registry Not equals the
   allowlisted registries.
5. **Techniques:** T1195.001, T1203 (exploit on deserialisation);
   AML.T0010; ASI04/ASI05.
6. **FP:** near zero — the field is the scanner's own verdict.
7. **Response:** act — kill the loading process's session; snapshot the
   model file for the feed.

## B10. A new MCP server appeared in a developer's client config
1. **One line:** shadow MCP — the undeclared server in `.mcp.json`,
    `~/.claude.json`, or a CLI agent config.
2. **Evidence:** shadow-agent/shadow-MCP discovery is graded
   "contested-but-thin in OSS" in the market research (§5.7); endpoint MCP
   configs are where postmark-mcp-class servers actually get added.
3. **Telemetry:** `auditd/events` file watches on the config paths
   (connector key), or the vaigil collector reading configs on a schedule;
   `agent/registry` first-seen.
4. **Logic:** single **rule** `auditd.mcp-config-written`: file observable
   suffix in [.mcp.json, .claude.json, .cursor/mcp.json, .codex/config.toml]
   — severity 3; combined with `agent/registry` **baseline** first-seen per
   (host, server_name) for the alert-worthy form.
5. **Techniques:** T1098 (standing credentials added), T1195.002; ASI04.
6. **FP:** medium as a bare write rule (developers edit configs) — the
   registry first-seen form is the one that alerts.
7. **Response:** ask — with the diff; act if the server is off-registry.

## B11. A SessionStart hook or rules file was modified in a developer's repo
1. **One line:** the config-poisoning primitive — `CLAUDE.md`,
   `.cursorrules`, `settings.json` hooks.
2. **Evidence:** Pillar's "Rules File Backdoor" in Copilot/Cursor
   ([Pillar Security](https://pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents));
   Lasso's hidden backdoor in Claude Code
   ([Lasso](https://lasso.security/blog/the-hidden-backdoor-in-claude-coding-assistant));
   Mitiga's poisoned coding test exfiltrated cloud credentials in under two
   minutes via malicious CLAUDE.md instructions
   ([Mitiga](https://mitiga.io/blog/poisoned-coding-test-ai-agent-attack)).
3. **Telemetry:** `github/audit` pushes (file-level: needs the
   connector to keep the changed-path list — currently not kept; connector
   addition) and `auditd/events` writes to those filenames.
4. **Logic:** single **rule** `agent.rules-file-changed` over the paths,
   severity 3 — the deterministic ship-first half. The dangerous form is a
   **temporal** correlation: rules-file change → `agent.egress-call` by
   that repo's coding agent within 24h (Mitiga's chain; same pattern as
   B6).
5. **Techniques:** AML.T0051.001; ASI06 (Memory & Context Poisoning);
   ATT&CK T1176 (Browser/IDE extension adjacency) is honest enough here as
   T1195.002.
6. **FP:** medium alone (every repo edit), near-zero in the correlated
   form.
7. **Response:** ask; act on the correlated form.

## B12. An agent tool read a credential source
1. **One line:** `.env`, keychain, kubeconfig, or the AI CLI's own config —
   read by a tool, labelled by the connector.
2. **Evidence:** QUIETVAULT executes predefined prompts against AI CLI
   tools to find config files (local `mtrends.txt`); AML.T0083
   (Credentials from AI Agent Configuration Files).
3. **Telemetry:** `mcp/proxy` — `raw.sensitivity` equals secret,
   `raw.effect` equals read.sensitive, with the path class in
   `raw.resource_class` (env-file, keychain, token-file).
4. **Logic:** single **rule** `agent.read-secret-source`, severity 4 —
   deterministic because the label is policy, not inference. Alone it is
   the prerequisite leg of B2/B6 chains.
5. **Techniques:** T1552.001; AML.T0083; ASI02/ASI03.
6. **FP:** near zero — the label is assigned at onboarding; the only
   benign case is a secret-manager tool, allowlisted by name.
7. **Response:** act if followed by egress (B2's correlation covers it);
   otherwise ask.

## B13. One agent called the same tool with the same arguments in a loop
1. **One line:** the runaway loop — identical hash, no progress, burning
   money.
2. **Evidence:** unbounded-consumption and runaway agency are the two
   failure modes founders report anecdotally and OWASP codifies (LLM10).
3. **Telemetry:** `mcp/proxy` — `raw.tool_args_hash`, `raw.session_id`,
   `raw.tokens_out`.
4. **Logic:** quiet base rule `agent.tool-call`, then **event_count**
   `corr.agent-loop`: group-by [raw.session_id, raw.tool_name,
   raw.tool_args_hash] (multi-field group-by is supported), timespan 10m,
   gte 20. Shares the burst pattern with A13/A16/A22.
5. **Techniques:** OWASP LLM10 (Unbounded Consumption); ASI08.
6. **FP:** low — legitimate retries are single digits; pagination calls
   differ in args hash.
7. **Response:** act — throttle at the gateway; zero the session's token
   budget; ask the owner.

## B14. A session's token spend exceeded every prior session of that agent
1. **One line:** the cost bomb, measured against the agent's own history.
2. **Evidence:** LLM10; the same runaway as B13 measured in tokens.
3. **Telemetry:** `mcp/proxy` — `raw.tokens_in`/`tokens_out` per call,
   summed per session (connector aggregate `raw.session_tokens`).
4. **Logic:** single **rule** with `Above` on `raw.session_tokens`
   (tenant-tuned constant) plus **baseline** rarity of session totals per
   agent id for the adaptive form.
5. **Techniques:** LLM10; ASI08.
6. **FP:** low — thresholds from the agent's own distribution, reported
   with the denominator.
7. **Response:** act — budget cap enforcement at the gateway.

## B15. An agent used a tool it has never used before
1. **One line:** first-use-of-tool — the cheapest agent UEBA that still
   means something.
2. **Evidence:** the market research grades agent behaviour baselining as
   contested-only-by-Exabeam (§5.5); the baseline package's
   rarity-with-denominator is exactly the honest small-population form.
3. **Telemetry:** `mcp/proxy` — `actor.value` (agent id),
   `raw.tool_name`.
4. **Logic:** **baseline** — first observation of (agent, tool) against
   ≥30 prior calls; reported with "0 of 30" so the analyst sees the
   confidence. The declared-purpose manifest makes it sharper: a tool
   *outside the manifest* is a rule, not a baseline (see B16).
5. **Techniques:** ASI02/ASI03 (privilege abuse).
6. **FP:** low — new tools are rare after onboarding and the denominator
   says so.
7. **Response:** watch; ask when the tool is also egress-capable.

## B16. An agent reached for a tool outside its declared purpose
1. **One line:** the manifest says research-only; the session called the
   deploy tool.
2. **Evidence:** drift-from-declared-purpose scoring is the open white
   space in the market research (§5.5).
3. **Telemetry:** `agent/registry` manifest (declared tool list) +
   `mcp/proxy` calls.
4. **Logic:** the connector marks calls with `raw.in_manifest=false`;
   single **rule** `agent.out-of-manifest-tool`. Deterministic given the
   manifest — tier 1 once tenants write manifests.
5. **Techniques:** ASI02/ASI03; LLM06.
6. **FP:** near zero — it is a policy check; unmanifested agents are
   excluded (and counted in a posture metric).
7. **Response:** ask — kill session for write/execute effects (B3's verb
   set), watch for reads.

## B17. An agent ran outside its working hours
1. **One line:** cron'd agent at 3am is normal; interactive assistant at
   3am is not.
2. **Evidence:** out-of-hours activity is the classic compromise tell,
   transplanted to agents; nothing published — this is original vaigil
   content, and it only works because agents have declared schedules.
3. **Telemetry:** `mcp/proxy` — `raw.local_hour` (connector-computed),
   agent id; the declared schedule in `agent/registry`.
4. **Logic:** single **rule** `agent.off-hours-call`: raw.in_schedule
   equals false, disposition allowed. (Hour arithmetic stays in the
   connector; the predicate stays a comparison, as the engine requires.)
5. **Techniques:** T1078-adjacent (anomalous timing); ASI03.
6. **FP:** low — the schedule is the agent owner's own declaration;
   deployments without schedules are excluded.
7. **Response:** ask; correlate with B2 for act.

## B18. An A2A delegation crossed a tenant boundary
1. **One line:** our agent took a task from an agent outside the org.
2. **Evidence:** A2A card signing is optional and cards are spoofable
   ("Agent Card Poisoning", local `06-market.md` §4.4; [Keysight
   blog](https://keysight.com/blogs/en/tech/nwvs/2026/03/12/agent-card-poisoning)).
3. **Telemetry:** **new** `a2a/protocol` source (or `mcp/proxy` with
   `raw.peer_tenant`).
4. **Logic:** single **rule** `agent.cross-tenant-delegation`:
   raw.peer_tenant Not equals own-tenant list. The unsigned-card half is
   posture, not detection.
5. **Techniques:** ASI07 (Insecure Inter-Agent Communication), ASI03.
6. **FP:** near zero if tenants are labelled; impossible without labels
   (see gaps).
7. **Response:** act — cut the delegation at the gateway.

## B19. A delegation chain grew too deep or looped
1. **One line:** agent A → B → C → … past any sane review depth, or back to
   A.
2. **Evidence:** A2A has no built-in injection defense and no loop
   protection; cascading failures are ASI08's whole entry.
3. **Telemetry:** `a2a/protocol` or `mcp/proxy` — `raw.delegated_to`,
   `raw.chain_depth` (connector-computed).
4. **Logic:** single **rule** with `Above` on `raw.chain_depth` (gte 5
   tenant-tuned); the *cycle* form is a **value_count** on distinct
   delegated_to per session against the session's own agent set — honest
   form: the connector computes `raw.chain_cycle=true` and the rule matches
   it.
5. **Techniques:** ASI07/ASI08.
6. **FP:** low — deep fan-out is real but declared; the rule asks for
   review, doesn't block.
7. **Response:** ask — surface the chain; act on cycles (infinite-loop
   spend).

## B20. An MCP server component matched a known CVE
1. **One line:** the installed mcp-remote/Inspector/Filesystem server is a
   vulnerable version.
2. **Evidence:** CVE-2025-6514 (mcp-remote OS command injection, 9.6,
   ~437k downloads), CVE-2025-49596 (Inspector unauth RCE),
   CVE-2025-53109/53110 (Filesystem path escape) — 50+ tracked MCP CVEs by
   Apr 2026 ([OSV entry](https://osv.dev/vulnerability/CVE-2025-6514),
   [pipelab tracker](https://pipelab.org/learn/mcp-vulnerabilities/),
   local `06-market.md` §4.3).
3. **Telemetry:** `agent/registry` versions + the existing SBOM→OSV
   pipeline.
4. **Logic:** **Tier 3 content rule** — version range match, expressed as
   `raw.version Below <fixed>` per CVE, with SSVC-style runtime grounding
   ("tool reachable from an agent with egress" upgrades severity).
5. **Techniques:** T1195.002; ASI04/ASI05.
6. **FP:** the feed's rate — near zero for the KEV-grade entries.
7. **Response:** act for RCE-class on reachable servers; ask otherwise.

## B21. An agent's tool call targeted a file path outside its workspace
1. **One line:** path escape — `../../etc/passwd`, `~/.ssh`, `/var/log`.
2. **Evidence:** CVE-2025-53109/53110 filesystem-server path escapes; the
   general class in the MCP CVE corpus.
3. **Telemetry:** `mcp/proxy` — `raw.path_class` (connector-classified:
   in-workspace, home, system, ssh-keys, agent-config).
4. **Logic:** single **rule** `agent.path-escape`: raw.path_class Not
   equals in-workspace (Not over a Match on equals, as the tree supports).
5. **Techniques:** T1083/T1552.001; ASI02/ASI05.
6. **FP:** low — the classifier allowlists the tool's declared roots.
7. **Response:** act for ssh-keys/agent-config classes; ask otherwise.

## B22. An agent's egress volume was many multiples of its own history
1. **One line:** the data-egress anomaly, per agent, with the denominator.
2. **Evidence:** exfiltration is the payoff of every B2/B6 chain;
   anomaly-with-denominator is what makes it triageable for a 3-person
   team.
3. **Telemetry:** `mcp/proxy` — bytes/tokens per egress call, summed per
   session (`raw.session_bytes`).
4. **Logic:** **baseline** rarity of session egress totals per agent id;
   the same mechanism as B14 on the bytes axis.
5. **Techniques:** T1567; LLM05 (Improper Output Handling).
6. **FP:** low after 30 sessions; honest "not yet" before that.
7. **Response:** act above a hard tenant cap; ask for the statistical
   form.

## B23. An agent presented an identity that was itself attacker-influenced
1. **One line:** the confused deputy — the agent acted on behalf of
   someone the attacker put in front of it.
2. **Evidence:** the MCP spec's own security-best-practices section names
   it: proxies must obtain per-client consent *before* the third-party OAuth
   flow, and token passthrough is forbidden
   ([MCP spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices)).
3. **Telemetry:** `mcp/proxy` — `raw.on_behalf_of` (the end-user identity
   the delegation cites) + the consent event; new connector field.
4. **Logic:** **temporal** `corr.deputy-no-consent`: rules
   [agent.oauth-consent-requested (quiet), agent.call-on-behalf (quiet)],
   group-by `raw.on_behalf_of`, timespan 24h — a call citing an identity
   with no matching consent event inside the window. Absence detection:
   bounded exactly the way `internal/correlate`'s Falling() note requires.
5. **Techniques:** ASI03; the MCP-spec confused-deputy class.
6. **FP:** low — consent caching is timestamped by the gateway.
7. **Response:** act — refuse the token exchange; kill the session.

## B24. Two agents edited the same resource from opposite instructions
1. **One line:** the multi-agent integrity break — write-write conflict
   between agents of different owners.
2. **Evidence:** ASI08 cascading failures; incident reports of agent
   armies undoing each other's work (anecdotal but the topology makes it
   inevitable).
3. **Telemetry:** `mcp/proxy` — write effects with `raw.resource_id`,
   `actor.value`.
4. **Logic:** **value_count** `corr.opposing-writers`: field
   `actor.value`, group-by `raw.resource_id`, timespan 30m, gte 2 —
   distinct agents writing one resource.
5. **Techniques:** ASI08.
6. **FP:** medium (legitimate pipelines) — restrict the base rule to
   `raw.environment equals production`.
7. **Response:** watch — this is a reliability signal worth having, not a
   page.

## B25. An agent installed a global-scope tool or skill
1. **One line:** the escalation primitive — the agent editing the very
   config that defines its powers.
2. **Evidence:** ClawHavoc's delivery path is skill installation; the
   Amazon Q chain ended in attempts to rewrite the environment it ran in.
3. **Telemetry:** `agent/registry` — `raw.scope` equals global for
   install/enable events; `raw.installed_by` equals agent (not human).
4. **Logic:** single **rule** `agent.self-extended`: raw.installed_by
   equals agent AND raw.scope equals global.
5. **Techniques:** T1098; ASI02/ASI04.
6. **FP:** near zero — agents should never self-install at global scope;
   the flag is the platform's own enforcement record.
7. **Response:** act — revert the install, quarantine the agent.

## B26. A coding agent's repository run coincided with a credential leak upstream
1. **One line:** the cross-source join that no single vendor sees —
   agent/CI activity correlated with the A-catalogue's identity signals.
2. **Evidence:** Mitiga's two-minute credential exfil; the GitHub-MCP
   private-repo leak.
3. **Telemetry:** `mcp/proxy` + `aws/cloudtrail`/`github/audit`.
4. **Logic:** **temporal** `corr.agent-then-cloud-anomaly`: rules
   [agent.sensitive-read (from B12), aws.key-new-network (A11's base)],
   group-by the workforce person tied to the agent, timespan 24h.
5. **Techniques:** T1528 + AML.T0083.
6. **FP:** low — both legs are already individually meaningful.
7. **Response:** act — rotate.

## B27. A model responded with the session's own instructions or keys in clear
1. **One line:** system-prompt/key leakage in output — the exfil that
   needs no tool.
2. **Evidence:** LLM02/LLM07 (sensitive disclosure / system prompt
   leakage); postmark's BCC is the tool-mediated sibling.
3. **Telemetry:** `mcp/proxy` — output scan verdict `raw.leak_class` in
   [system_prompt, api_key, token] with disposition detected.
4. **Logic:** single **rule** `agent.output-leak`, severity 4.
5. **Techniques:** LLM02/LLM07; AML.T0024 (exfil via inference).
6. **FP:** low — the scan is for high-entropy/format-matched secrets, not
   prose.
7. **Response:** act — kill session, rotate the named credential.

## B28. An agent's declared task text diverged from its observed behaviour class
1. **One line:** goal-hijack detection without reading the prompt — the
   manifest says "summarise support tickets", the session called deploy
   tools.
2. **Evidence:** ASI01 Goal Hijack; the market research's purpose-drift
   scoring (§5.5).
3. **Telemetry:** `agent/registry` manifest purpose label +
   `mcp/proxy` effect mix per session.
4. **Logic:** **baseline** over the session effect-vector per agent id
   (read/write/execute/egress proportions); divergence is reported as a
   count comparison ("3 egress calls against 0 in 41 prior sessions"), not
   a score.
5. **Techniques:** ASI01/ASI06.
6. **FP:** medium — this is the most statistical entry; it ships last and
   only with the denominator shown.
7. **Response:** ask.

## B29. An agent was created with no owner registered
1. **One line:** the rogue agent — somebody stood up an agent identity and
   nobody is accountable.
2. **Evidence:** ASI10 Rogue Agents; shadow-agent white space (§5.7).
3. **Telemetry:** `agent/registry` create events — `raw.owner` absent.
4. **Logic:** single **rule** `agent.unowned-agent-created`: raw.owner
   exists equals false. Simple, deterministic, and the inventory backbone
   for B15/B16.
5. **Techniques:** ASI03/ASI10.
6. **FP:** near zero.
7. **Response:** act — disable at the gateway until an owner claims it.

## B30. An agent acted during a declared change freeze
1. **One line:** the Replit lesson, verbatim — the freeze is in the
   calendar, the agent did not check.
2. **Evidence:** Replit's agent destroyed a production database during a
   production freeze ([Fortune](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure)).
3. **Telemetry:** `mcp/proxy` write/execute effects with
   `raw.change_freeze` (connector reads the freeze calendar),
   `raw.environment` equals production.
4. **Logic:** single **rule** `agent.write-during-freeze`.
5. **Techniques:** LLM06; ASI02/ASI08.
6. **FP:** near zero — the freeze is declared by the same people who own
   the agent.
7. **Response:** act — revert capability plus kill session; this is the
   two-person-rule case.

---

# Shared correlation patterns

One engine pattern serves many entries; implement once, instantiate per
entry:

- **Ordered consequence chain (temporal_ordered, group-by session or
  person):** A1 (deny→allow), A6 (reset→strange login), B2 (trifecta),
  B6 (marker→egress), B11 (rules-file→egress), B26 (sensitive read→cloud
  anomaly). The pattern is "a quiet precursor made meaningful by its
  ordered consequence" — every one of them is near-zero FP *because* of the
  ordering, not despite it.
- **Two-places-at-once (value_count on ip per identity/session):** A3 and
  B5 — humans and agents, same rule shape.
- **Burst (event_count per identity/session with a tuned threshold):** A13,
  A16, A22, A35, B13 — always grouped, never estate-wide, exactly as the
  correlate package's own warnings require.
- **Create-then-use (temporal, group-by actor):** A10/A11, A30, B23's
  consent shape — the hand-off pattern, 15 minutes to 24 hours.
- **First-time-X (baseline rarity with denominator):** A2, A5, A11, A18,
  A24, A33, A39, B15, B22, B28 — one mechanism, ten entries; the manifest
  and inventory make the agent versions *sharper* than the human ones.
- **Quiet-then-loud (falling counts / absence):** A26 (log went quiet), A24
  (dormant account), B7 (recorder blind), B23 (no consent) — all need the
  bounded-group discipline the correlate package already warns about.

# The five hardest gaps

Detections above that vaigil cannot ship today, and why:

1. **Tool-argument content.** The model stores `raw.tool_args_hash`, not
   args — correctly, since args are attacker-controlled text. Everything
   that must *read* the action (B3's SQL verbs, postmark's BCC domain, the
   tj-actions `/proc/self/environ` read) therefore depends on the MCP
   proxy/connector classifying args into `raw.effect`,
   `raw.path_class`, `raw.resource_class` before hashing. Without a
   gateway in the path, B1–B4 and B12 are undetectable, full stop.
2. **Egress and DNS telemetry.** Cloudflare's connected stream is
   firewall-*blocked* traffic only. A38 (webhook/file-share exfil), A39
   (shadow AI), B2/B6/B22 (egress legs) need an SNI/DNS or L7 egress feed —
   a new source, not a new rule.
3. **SaaS data-plane logs.** Snowflake and Salesforce connectors carry
   *logins*; A22 (bulk row reads) needs QUERY_HISTORY / event-monitoring
   streams — the difference between knowing somebody got in and knowing
   what left.
4. **GitHub workflow telemetry.** The audit log has no workflow triggers,
   job output, or changed-path detail: A28 (secrets in logs), A29
   (pull_request_target) and B11's repo half need a `github/workflow`
   source with per-job and per-path records.
5. **Consent and tenant labelling.** B23 (confused deputy) and B18
   (cross-tenant A2A) require `raw.on_behalf_of` consent records and
   tenant labels on every agent — metadata the platform must *create*
   (onboarding manifests, `agent/registry`), because no vendor log
   carries it. This is the one gap that is a product feature, not a
   connector.

# What ships first (the fifteen)

A4, A12, A14, A19, A20, A21, A27, A36, A37 (deterministic single rules);
A1, A6, A10 (ordered correlations over quiet bases); B1, B3, B4 (agent
deterministic); B2 (the trifecta — the differentiator, ship it even though
it is a correlation, because the ordering is what buys the precision).
Everything statistical waits for a denominator; everything
content-signature inherits its FP rate from the feed and updates itself —
which is the promise the platform makes.
