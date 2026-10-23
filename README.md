# Vaigil

**Security operations for the systems your organisation runs.** Vaigil
collects what happens on the platforms you use, decides what is wrong, and
keeps a record nobody can quietly change of what was done about it.

<p>
  <a href="https://github.com/quilzo/vaigil/actions/workflows/ci.yml"><img src="https://github.com/quilzo/vaigil/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-Apache--2.0-blue" alt="licence: Apache-2.0"></a>
  <a href="go.mod"><img src="https://img.shields.io/badge/dependencies-0-brightgreen" alt="dependencies: 0"></a>
</p>

[Quickstart](#quickstart) · [What it does](#what-it-does) · [Roles](#roles) ·
[Three ways in](#three-ways-in) · [Its own record](#its-own-record) ·
[Install](#install) · [Manual](https://quilzo.github.io/vaigil.github.io/)

One static binary. Go, standard library only, no third-party dependencies;
the few third-party assets it carries (a typeface, icons, public data sets)
are credited in [NOTICE](NOTICE).

## Quickstart

```bash
git clone https://github.com/quilzo/vaigil && cd vaigil
go build -o vaigil ./cmd/vaigil      # Go 1.27 or later, nothing to fetch

./vaigil init --admin you@example.com   # a store, and the link that adds your passkey
./vaigil serve                          # the console, on http://localhost:8080
```

Open the link `init` printed, add a passkey, and you are signed in. There is
no default password and no default account: nobody is an administrator until
you say so, and everybody signs in with two factors.

The first screen is **Today**: what is waiting for you to decide, then what is
wrong in the parts of the estate you work in. **Get started** walks the four
things that make it useful, reading the store rather than telling a story:
bring events in, decide what counts as wrong, know the estate, and decide who
else may do what.

## What it does

| | |
|---|---|
| **Collect** | Connectors that read other tools with stored credentials, scheduled collection, files, and feeds that other systems push to: an identity provider's security events (SSF, CAEP) and signed webhooks. Every event is mapped to one shape and kept, append-only, before anything reads it. |
| **Detect** | Rules over the events, written here or imported as Sigma, each with fixtures that must match and must not. A new rule runs in a trial ring that records what it would raise until its record earns it the queue. Correlations across rules and platforms, suppressions that end, and indicators of compromise. |
| **Decide** | One queue of findings, ranked by risk, with every decision kept and replayable. An AI analyst writes suggestions a person agrees with or not; it has no way to record a decision itself. |
| **Respond** | Cases with the clocks the law sets (GDPR, NIS2, DORA and others), playbooks, and acts on other platforms — suspend an account, end its sessions — asked for by one person and approved by another. Automations that watch, ask, or act, within limits. Breach notices to the people affected. |
| **Exposure** | Vulnerabilities of the estate decided with SSVC and published as VEX, dependency and code-scanning results, workforce and device risk from the company's own tools, reminders to the people who have something to do, vendor risk, and access reviews closed by the next import. |

## Roles

A security team separates watching, deciding, acting and administering, and
so does Vaigil. Each role includes the ones before it:

| Role | May |
|---|---|
| `viewer` | read findings, cases, the vulnerability queue and the dashboards |
| `analyst` | triage findings, open and note on cases, hunt through events |
| `responder` | run cases, ask for an act on another platform, approve somebody else's act, accept a risk |
| `admin` | manage people, connectors and their credentials, and settings |

Beside the ladder are jobs, for different kinds of work rather than more of
it: an `engineer` tunes detections and automation rules, a `vuln-manager`
decides vulnerabilities, and an `auditor` reads the queue and the audit log
for a set time, after which the grant ends by itself. Each job is a set of
bindings anybody can read in full (`vaigil auth roles`).

What stops one person acting alone is not a setting:

- Everybody signs in with a passkey, or with a password and a second factor
  through single sign-on that says it used one.
- Failed sign-ins lock out the places they come from, not the person.
- An act on another platform is approved by somebody other than whoever asked.
- Whoever wrote an automation rule does not approve the runs it holds.
- Making somebody an administrator, an administrator's token, a weaker
  setting and moving the audit log each take a second administrator.
- Sessions end after an hour unused, fifteen minutes for administrators.

## Three ways in

Everything is reachable from the console, from the command line
(`vaigil help`), and from the agent interface over MCP (`vaigil mcp --list`).
A test fails when a command has no screen and no written reason, or no MCP
operation and no written reason.

The agent interface reads and proposes. It lists findings, cases,
detections, vulnerabilities and the estate, and it may propose a decision on
a finding for a person to agree with. It cannot change who may do what,
approve an act or reach another platform: an agent reading events is
reading text an attacker chose.

## Its own record

Every change is written to an append-only audit log: a hash chain, a Merkle
tree over it, tree heads signed with Ed25519 and ML-DSA, and the head
committed to Bitcoin through OpenTimestamps (`vaigil auditlog anchor`). The
log writer can run as its own account (`vaigil logd`), so the console cannot
rewrite what it recorded.

The log goes to a SIEM as it is written (`siem.stream.url`): batches of OCSF,
each following the last, carrying a signed tree head and an HTTP message
signature, so the receiver can prove nothing was dropped or changed.

## Install

From source, as above, or with `make install`. A container image builds from
the [Dockerfile](Dockerfile): the binary alone on
`gcr.io/distroless/static-debian12:nonroot`, with no shell.

```bash
docker build -t vaigil .
docker run --rm -v vaigil:/srv vaigil --root /srv/store init --admin you@example.com
docker run -p 8080:8080 -v vaigil:/srv vaigil
```

Behind a reverse proxy, set `admin.behind_tls_proxy` and `admin.base_url`;
[deploy/](deploy/) has a systemd unit and a Caddy configuration.

## Licence

Apache-2.0. Copyright 2026 Rashik Adhikari. See [LICENSE](LICENSE) and
[NOTICE](NOTICE). Security reports: [SECURITY.md](SECURITY.md).
