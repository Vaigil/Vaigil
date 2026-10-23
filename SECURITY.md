# Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting:
**[Report a vulnerability](../../security/advisories/new)**

That channel is private between you and the maintainers until an advisory is
published. It needs no email address from either side, which is deliberate: a
disclosure process should not depend on anybody publishing a personal address.
Today there is one maintainer, Rashik Adhikari ([@rsh1k](https://github.com/rsh1k)),
who receives every report.

If private reporting is unavailable to you for any reason, open a public issue
containing only the words "security contact requested" and nothing else, and a
maintainer will open a private advisory to continue in.

## What to expect

| | |
|---|---|
| First response | within 5 days |
| Assessment and severity | within 14 days |
| Fix for a confirmed high or critical issue | within 30 days, or a written explanation of why longer |
| Credit | in the advisory, under whatever name you choose, including none |

There is no bounty. This project has no money. What it can offer is that your
report is taken seriously, fixed properly rather than patched around, and
credited.

## What counts

Vaigil makes specific structural claims, and a demonstration that any of them
is false is a vulnerability even without a working exploit:

- **Authorisation is enforced at the action, not the screen.** Any request
  that performs an action the caller's role, job or permission does not
  allow, through the console, the command line or the agent interface — and
  any state of the store in which the checks stop happening at all. A
  damaged policy file must refuse, not permit.
- **A credential is capped by what it carries.** Any way a token acts beyond
  its role, the area it was issued for, or its read-only limit, or a session
  outlives the limits it was issued under.
- **Two factors for everybody.** Any way a person reaches the console on one
  factor once two are required, or single sign-on counts as two factors when
  the provider did not say it used two.
- **Nobody acts alone where two are required.** Any way an act on another
  platform is approved by whoever asked for it; a run an automation held is
  approved by whoever wrote the rule; or somebody is made an administrator,
  an administrator's token is issued, a setting is weakened or the audit log
  is moved on one administrator's word while another exists.
- **Failures lock out places, not people.** Any way failed sign-ins from
  somewhere else lock a person out of the places they sign in from.
- **The audit log is append-only and verifiable.** Any way to alter, drop or
  add a record and still have `vaigil auditlog verify` pass, a signed tree
  head verify over a log it does not cover, or a streamed batch be accepted
  by a receiver that checks it with a record changed or missing.
- **An agent reads and proposes, and does nothing else.** Any way an agent
  connected over MCP records a decision, approves an act, changes who may do
  what, or reaches another platform.
- **What an agent reads cannot instruct it.** Any way text in an event, a
  finding or a log reaches the analyst model as anything but fenced data, or
  the analyst records a decision rather than a proposal.
- **Personal data stays out of prompts.** Any way a value the privacy guard
  masks reaches a model that may not receive it.
- **A credential sealed is a credential kept.** Any way a connector's
  credential or a feed's secret is stored in the clear once a keyring exists,
  or read with a key other than the one it was sealed under.
- **A connector reaches only what it declares.** Any request a connector or a
  feed makes to a host its manifest does not name, or to this machine's
  private network when it was not allowed to.

## What does not count

- Findings against a deployment that has the console on a public interface
  without TLS in front of it. `vaigil serve` listens on loopback by default.
- Missing hardening headers on a response that carries no content.
- Denial of service by sending very large or very many requests.
- Automated scanner output with no demonstrated impact.
- Anything requiring an already-compromised host or an already-valid
  administrator credential.

## Supported versions

No release is published yet. Report against `main`, where fixes land.

## Our own claims, tested

The properties above are asserted by the test suite rather than argued for,
and a report is most useful when it makes one of those tests fail:

- `internal/auth` — roles, jobs, permissions, scopes and sessions
- `internal/admin/roles_test.go`, `internal/admin/jobs_test.go` — every role and job reaches its own work and no more
- `cmd/vaigil/privilege_test.go`, `cmd/vaigil/coverage_test.go` — every command declares what it needs, and has a screen and an MCP operation or a written reason
- `internal/admin/mfa_test.go`, `internal/admin/stepup_test.go`, `internal/admin/sessions_test.go` — two factors, step-up and session limits
- `internal/lockout` — smart lockout
- `internal/dual`, `internal/incident`, `internal/automate` — second people
- `internal/audit`, `internal/translog`, `internal/auditstream` — the chain, the tree, signed heads and the stream
- `internal/pii`, `internal/model` — the privacy guard in front of a model
- `internal/fetch`, `internal/egress`, `internal/connector` — what may be reached
