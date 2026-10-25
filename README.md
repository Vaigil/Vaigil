# Vaigil

**Open-source AI security operations: SIEM, SOAR and vulnerability management
in one self-hosted binary.** Vaigil collects what happens on the platforms your
organisation runs, detects what is wrong, lets an AI analyst take the first
pass without letting it decide anything, and keeps a tamper-evident record of
every action a person took about it.

<p>
  <a href="https://github.com/Vaigil/Vaigil/actions/workflows/ci.yml"><img src="https://github.com/Vaigil/Vaigil/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-Apache--2.0-blue" alt="licence: Apache-2.0"></a>
  <a href="go.mod"><img src="https://img.shields.io/badge/dependencies-0-brightgreen" alt="dependencies: 0"></a>
  <a href="https://vaigil.github.io/"><img src="https://img.shields.io/badge/manual-vaigil.github.io-informational" alt="manual"></a>
</p>

[Quickstart](#quickstart) · [What it does](#what-it-does) ·
[AI that cannot be talked into anything](#ai-that-cannot-be-talked-into-anything) ·
[Integrations](#integrations) · [Roles](#roles) · [Three ways in](#three-ways-in) ·
[Its own record](#its-own-record) · [Install](#install) ·
[Manual](https://vaigil.github.io/)

One static binary written in Go, using the standard library only, with no
third-party dependencies. The few third-party assets it carries (a typeface,
icons, public data sets) are credited in [NOTICE](NOTICE).

## Quickstart

```bash
git clone https://github.com/Vaigil/Vaigil vaigil && cd vaigil
go build -o vaigil ./cmd/vaigil      # Go 1.27 or later, nothing to fetch

./vaigil init --admin you@example.com   # a store, and the link that adds your passkey
./vaigil serve                          # the console, on http://localhost:8080
```

Open the link `init` printed and add a passkey, and you are signed in. There
is no default password and no default account. Nobody is an administrator
until you say so, and everybody signs in with two factors.

The first screen is **Today**: what is waiting for you to decide, then what is
wrong in the parts of the estate you work in. **Get started** walks the four
things that make it useful: bring events in, decide what counts as wrong, know
the estate, and decide who else may do what.

## What it does

| | |
|---|---|
| **Collect** | Connectors that read other tools with stored credentials, scheduled collection, log files, and feeds other systems push to: an identity provider's security events (SSF, CAEP, RISC), Okta event hooks, signed webhooks, and Quilzo's audit log, checked record by record against its signed chain. Every event is mapped to one shape and kept, append-only, before anything reads it. |
| **Detect** | Detection rules written here or imported as Sigma, each with fixtures that must match and must not, and MITRE ATT&CK technique IDs. A new rule runs in a trial ring that records what it would raise until its record earns it the queue. Correlations across rules and platforms, suppressions that end, and indicators of compromise imported from STIX 2.1 bundles or plain lists. |
| **Triage** | One queue of findings, ranked by risk, with every decision kept and replayable. An AI analyst writes the first pass as a suggestion that a person agrees with or not; it has no way to record a decision itself. |
| **Respond** | Cases and incidents with the notification clocks each law starts (GDPR, NIS2, DORA, SEC, CIRCIA, HIPAA), playbooks for account compromise, phishing, malware, lost devices and exposed data, and actions on other platforms (suspend an Okta account, end its sessions) asked for by one person and approved by another. Automations that watch, ask, or act, within limits. |
| **Exposure** | Vulnerabilities of the estate ranked with CISA KEV and EPSS, decided with SSVC and published as OpenVEX; dependency scanning from CycloneDX and SPDX SBOMs against OSV; code-scanning results from SARIF; workforce and device risk from the company's own tools; vendor risk; reminders to people who have something to do; and access reviews closed by the next import. |

## AI that cannot be talked into anything

A security tool that puts a language model in front of log data hands the
model text written by attackers. Vaigil is built so that the worst an AI can
do is be wrong in a suggestion:

- **The AI analyst's plan is fixed in code before anything untrusted is
  read.** Nothing a log line says can add a step.
- **Counts and quoted text are kept apart.** The model is given numbers and
  closed words the program worked out, and, separately and marked as such,
  the text somebody else wrote.
- **The output is one word from a closed set, with a confidence.** Below the
  threshold it is not even shown. The reason a person reads is assembled from
  the counts, never from what the model wrote, so a prompt injection in a log
  cannot reach the screen of whoever decides.
- **A privacy guard sits in front of every model call.** Personal data and
  credentials are masked before the prompt leaves and restored in the answer,
  and invisible characters are removed first.
- **It works with any OpenAI-compatible endpoint**, hosted or local
  (`VAIGIL_MODEL_URL`, `VAIGIL_MODEL_KEY`, `VAIGIL_MODEL`), and with none: the
  model is an aid, never a dependency.

AI agents reach Vaigil through its **MCP server**: eight operations behind four
tools, which an agent loads only as it searches for them. They list and read
findings, cases, detection statistics, the vulnerability plan and the estate in
numbers, and propose a decision on a finding for a person to make. They cannot
change who may do what, approve an action, or reach another platform.

## Integrations

**Connectors** (read through each tool's API, credentials kept in Vaigil's
vault): Okta, Microsoft Entra ID, GitHub, EVM smart contracts through a
Blockscout explorer, KnowBe4, ManageEngine Endpoint Central, ManageEngine MDM
Plus and Vanta.

**Log sources** mapped to one event shape: AWS CloudTrail, Microsoft Entra ID,
Microsoft Azure, Google Workspace, Google Cloud, Okta, Duo, CrowdStrike Falcon,
Jamf Pro, GitHub, Kubernetes, Cloudflare, Salesforce, Slack, Snowflake, Linux
auditd and EVM chains.

**Standards**: OCSF, Sigma, MITRE ATT&CK, STIX 2.1, SSF/CAEP/RISC, CycloneDX,
SPDX, OSV, OpenVEX, SSVC, CISA KEV, EPSS, SARIF, MCP, OpenID Connect, SAML 2.0,
SCIM 2.0 and WebAuthn passkeys.

## Roles

A security team separates watching, deciding, acting and administering, and
so does Vaigil. Each role includes the ones before it:

| Role | May |
|---|---|
| `viewer` | read findings, cases, the vulnerability queue and the dashboards |
| `analyst` | triage findings, open cases and add notes to them, hunt through events |
| `responder` | run cases, ask for an action on another platform, approve somebody else's action, accept a risk |
| `admin` | manage people, connectors and their credentials, and settings |

Beside the ladder are jobs, for different kinds of work rather than more of
it: an `engineer` tunes detections and automation rules, a `vuln-manager`
decides vulnerabilities, and an `auditor` reads the queue and the audit log
for a set time, after which the grant ends by itself. Each job is a set of
bindings anybody can read in full (`vaigil auth roles`).

What stops one person acting alone is not a setting:

- Everybody signs in with a passkey that checks it is them (user
  verification), or through single sign-on that says it used two factors
  (NIST SP 800-63B-4).
- Failed sign-ins lock out the places they come from, not the person.
- An action on another platform is approved by somebody other than whoever
  asked.
- Whoever wrote an automation rule does not approve the runs it holds.
- Making somebody an administrator, issuing an administrator's token,
  weakening a setting and moving the audit log each take a second
  administrator.
- Sessions end after an hour unused, and after fifteen minutes for
  administrators.

## Three ways in

Everything is reachable from the console, from the command line
(`vaigil help`), and from AI agents over MCP (`vaigil mcp --list`). A test
fails when a command has no screen and no written reason, or no MCP operation
and no written reason.

## Its own record

Every change is written to an append-only audit log: a hash chain, a Merkle
tree over it, tree heads signed with Ed25519 and ML-DSA (post-quantum), and the
head committed to Bitcoin through OpenTimestamps (`vaigil auditlog anchor`).
The log writer can run as its own account (`vaigil logd`), so the console
cannot rewrite what it recorded.

The log can also be sent to another SIEM as it is written (`siem.stream.url`):
batches of OCSF, each following the last, carrying a signed tree head and an
HTTP message signature (RFC 9421), so the receiver can prove nothing was
dropped or changed.

## Install

From source, as above, or with `make install`. Each release publishes static
binaries for Linux, macOS and Windows with build provenance, and a container
image, `ghcr.io/vaigil/vaigil`: the binary alone on
`gcr.io/distroless/static-debian12:nonroot`, with no shell. See
[INSTALL](INSTALL).

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
