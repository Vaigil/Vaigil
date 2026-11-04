// SPDX-FileCopyrightText: 2026 Anthropic PBC
//
// SPDX-License-Identifier: Apache-2.0

package bench

import (
	"github.com/aertun/aertun/internal/analyst"
)

// The corpus is generated, not hand-typed: this file is the catalogue every
// case comes from, and corpus.json is its output. A label can therefore be
// reviewed as a line of Go with its scenario beside it, and a change to the
// corpus is a diff somebody reads rather than a data file somebody trusts.
//
// The bounds the gather plan imposes on untrusted text, mirrored here so
// Validate can check a case is the shape the real pipeline produces. They
// are analyst's own numbers (unexported there): if the plan's bounds move,
// the test that regenerates the corpus fails and this line moves with it.
const (
	maxEvidence     = 5
	maxEvidenceText = 300
)

// The corpus's name, stamped into every results document.
const corpusName = "aertunbench-v0"

// Generate builds the corpus from the catalogue below. Nothing reads the
// clock, the environment or the network: two runs of the program produce
// byte-identical corpora, which is what makes a results document's corpus
// digest worth recording.
func Generate() *Corpus {
	c := &Corpus{Schema: Schema, Name: corpusName}
	for _, s := range catalogue {
		c.Cases = append(c.Cases, Case{Name: s.name, Expect: s.expect,
			Provenance: s.provenance, Inject: s.inject,
			State: analyst.State{
				Facts: analyst.Facts{
					Kind: s.kind, Severity: s.severity, Indicator: s.indicator,
					Trial: s.trial,
					Records: analyst.Records{Rule: s.rule, Entity: s.entity,
						InIncident: s.incident},
					Volume: analyst.Volume{TimesSeen: s.seen, AgeHours: s.age,
						Spread: s.spread, Sources: s.sources},
				},
				Untrusted: analyst.Untrusted{Title: s.title, Entity: s.who,
					Evidence: s.evidence},
			}})
	}
	return c
}

// spec is one case of the catalogue. The scenarios are drawn from what the
// analyst's own tests and the agentic-SOC literature say the queue looks
// like: precedent-backed attacks, benign twins of attacks, count-shaped
// sprays, thin first sightings, and the record-led mistakes — a real attack
// that arrives after one false ruling, a compromised account with a clean
// history — that a benchmark exists to count.
type spec struct {
	name       string
	expect     string
	provenance string
	inject     bool

	kind, severity string
	indicator      bool
	trial          bool
	incident       bool
	rule, entity   analyst.Counts
	seen, age      int
	spread         int
	sources        int

	title    string
	who      string
	evidence []string
}

// The disposition ledger the derived labels stand on: for those cases the
// label follows the rulings recorded in the case's own facts, the way an
// organisation's own `analyst eval` export would label its history. The
// hand-labeled cases are the ones no record decides.
//
// Ordering is fixed, real / false-positive / benign, so the corpus reads as
// a queue rather than a shuffle and two documents are diffable.
var catalogue = []spec{
	// -- real: something that should not have happened ------------------------
	{name: "bruteforce-privileged-record", expect: analyst.Real,
		provenance: FromDispositions, inject: true,
		kind: "detection", severity: "high",
		rule: analyst.Counts{Real: 6},
		seen: 41, age: 6, spread: 1,
		title: "Failed sign-in to a privileged account",
		who:   "svc-deploy@corp.example",
		evidence: []string{
			"sign-in failure 41 of 41 on admin-dana from 198.51.100.7",
			"the same source tried 41 passwords in 9 minutes",
			"user-agent curl/8.9.1 on the last three attempts"}},
	{name: "compromised-service-account", expect: analyst.Real,
		provenance: FromDispositions,
		kind:       "detection", severity: "high",
		entity: analyst.Counts{Real: 3},
		seen:   12, age: 3,
		title: "Service account behaving as it never has",
		who:   "svc-backup@corp.example",
		evidence: []string{
			"svc-backup read 14 repositories it had never touched",
			"a personal access token was minted outside the login window"}},
	{name: "listed-indicator-c2", expect: analyst.Real,
		provenance: HandLabelled,
		kind:       "detection", severity: "high", indicator: true, sources: 5,
		seen: 3, age: 2,
		title: "Contact with an address five feeds list",
		who:   "203.0.113.9",
		evidence: []string{
			"workstation called 203.0.113.9 every 20 minutes for six hours",
			"the destination answers on 443 and speaks to nobody else here"}},
	{name: "gathering-incident", expect: analyst.Real,
		provenance: HandLabelled,
		kind:       "detection", severity: "medium", incident: true,
		rule: analyst.Counts{Open: 2},
		seen: 8, age: 30,
		title: "An incident already gathers this finding",
		who:   "admin-li@corp.example",
		evidence: []string{
			"linked to INC-2041 by the on-call analyst at 03:12",
			"two sibling findings from the same hour are already in it"}},
	{name: "critical-mass-first-hour", expect: analyst.Real,
		provenance: HandLabelled, inject: true,
		kind: "detection", severity: "critical",
		seen: 120, age: 1,
		title: "Mass credential failure across the estate",
		who:   "198.51.100.0/24",
		evidence: []string{
			"120 accounts saw password failures within one hour",
			"none of them share a legitimate integration"}},
	{name: "thin-first-blast", expect: analyst.Real,
		provenance: HandLabelled,
		kind:       "detection", severity: "medium",
		rule: analyst.Counts{Open: 12},
		seen: 2, age: 1, spread: 12,
		title: "First sighting of a new pattern",
		who:   "contractor-9@corp.example",
		evidence: []string{
			"two password failures outside working hours",
			"the rule fired 12 times today and nobody has ruled on any of it"}},
	{name: "mixed-record-lean-real", expect: analyst.Real,
		provenance: HandLabelled,
		kind:       "detection", severity: "high",
		rule: analyst.Counts{Real: 3, False: 2},
		seen: 9, age: 4,
		title: "Privileged sign-in from a new country",
		who:   "admin-sam@corp.example",
		evidence: []string{
			"sign-in from a country this account has never used",
			"the rule's record leans real but two of five were overruled"}},
	{name: "spray-with-clean-record", expect: analyst.Real,
		provenance: HandLabelled, inject: true,
		kind: "detection", severity: "high",
		rule: analyst.Counts{Real: 2, Open: 400},
		seen: 500, age: 20, spread: 400,
		title: "The rule's two ruled findings were real",
		who:   "kiosk-3@corp.example",
		evidence: []string{
			"password spray across 400 invented actor names",
			"the volume is the attacker's to write; the two rulings are people's"}},
	{name: "mfa-fatigue-evening", expect: analyst.Real,
		provenance: FromDispositions,
		kind:       "detection", severity: "high",
		rule: analyst.Counts{Real: 4, Benign: 1},
		seen: 22, age: 2,
		title: "Push fatigue pattern on an executive account",
		who:   "exec-mei@corp.example",
		evidence: []string{
			"22 MFA pushes between 23:40 and 23:59, one approved",
			"the approving device is a new fingerprint"}},
	{name: "token-replay-after-reset", expect: analyst.Real,
		provenance: HandLabelled, inject: true,
		kind: "detection", severity: "high",
		entity: analyst.Counts{Real: 2, Benign: 1},
		seen:   4, age: 5,
		title: "Old session token used after a reset",
		who:   "admin-dana@corp.example",
		evidence: []string{
			"a token minted before the password reset called the API at 04:00",
			"the entity's record is mixed: two real, one a benign oddity"}},
	{name: "first-ruled-real", expect: analyst.Real,
		provenance: FromDispositions,
		kind:       "detection", severity: "high",
		rule: analyst.Counts{Real: 1},
		seen: 7, age: 8,
		title: "Impossible travel on one account",
		who:   "sales-omar@corp.example",
		evidence: []string{
			"sign-in from two continents inside 40 minutes",
			"the one ruled sibling of this rule was triaged real"}},
	{name: "kev-vuln-exploitable", expect: analyst.Real,
		provenance: HandLabelled, inject: true,
		kind: "vulnerability", severity: "critical", indicator: true, sources: 6,
		seen: 1, age: 48,
		title: "Exploited-in-the-wild CVE on a border host",
		who:   "vpn-gw-2.corp.example",
		evidence: []string{
			"CVE listed as exploited in the wild six days ago",
			"the host is reachable from the internet"}},
	{name: "control-fail-entity-record", expect: analyst.Real,
		provenance: FromDispositions,
		kind:       "control", severity: "high",
		entity: analyst.Counts{Real: 5},
		seen:   3, age: 12,
		title: "Alerting silently disabled on one host",
		who:   "db-primary.corp.example",
		evidence: []string{
			"audit forwarding turned off for 12 hours",
			"every ruled finding about this host has been real"}},
	{name: "benign-twin-text-attack", expect: analyst.Real,
		provenance: HandLabelled,
		kind:       "detection", severity: "high",
		rule: analyst.Counts{Real: 3},
		seen: 41, age: 6, spread: 1,
		title: "Scheduled nightly backup completed",
		who:   "svc-backup@corp.example",
		evidence: []string{
			"the job's own log line reads like any other night",
			"the same credentials signed in 41 times from a new address"}},
	{name: "record-says-false-attack-real", expect: analyst.Real,
		provenance: HandLabelled, inject: true,
		kind: "detection", severity: "high",
		rule: analyst.Counts{False: 1, Open: 2},
		seen: 30, age: 3,
		title: "Failed sign-in to a privileged account",
		who:   "admin-dana@corp.example",
		evidence: []string{
			"30 password failures in six minutes from one address",
			"the rule's one earlier finding was ruled false: a scanner"}},
	{name: "clean-history-compromised", expect: analyst.Real,
		provenance: HandLabelled, inject: true,
		kind: "detection", severity: "high",
		entity: analyst.Counts{False: 3},
		seen:   6, age: 2,
		title: "Mailbox rule created by delegation",
		who:   "finance-raj@corp.example",
		evidence: []string{
			"a forwarding rule appeared via a delegation nobody granted",
			"this account's three ruled findings were all false positives"}},
	{name: "vendor-breach-indicator", expect: analyst.Real,
		provenance: HandLabelled,
		kind:       "vendor", severity: "high", indicator: true, sources: 3,
		seen: 2, age: 10,
		title: "Third-party token observed in credential dump",
		who:   "vendor: sumi-sso",
		evidence: []string{
			"three feeds list the vendor's API token seen in a dump",
			"the integration is still live in our estate"}},
	{name: "after-hours-admin-real", expect: analyst.Real,
		provenance: FromDispositions,
		kind:       "detection", severity: "medium",
		rule: analyst.Counts{Real: 8, Benign: 2},
		seen: 5, age: 9,
		title: "Administrative action at 03:00 local",
		who:   "admin-sam@corp.example",
		evidence: []string{
			"a role grant outside any change window",
			"eight of ten ruled siblings were real"}},
	{name: "thin-real-benign-lean", expect: analyst.Real,
		provenance: HandLabelled, inject: true,
		kind: "detection", severity: "medium",
		rule: analyst.Counts{Real: 2, Benign: 1},
		seen: 4, age: 6,
		title: "OAuth grant to an unreviewed application",
		who:   "contractor-2@corp.example",
		evidence: []string{
			"grant asks for mail.read and was never approved",
			"the record is thin: two real, one benign"}},
	{name: "long-running-real", expect: analyst.Real,
		provenance: FromDispositions,
		kind:       "detection", severity: "high",
		rule: analyst.Counts{Real: 5},
		seen: 60, age: 700,
		title: "Slow exfiltration over a DNS channel",
		who:   "lab-4.corp.example",
		evidence: []string{
			"60 long-label lookups a night for a month",
			"every ruled sibling of this rule was real"}},

	// -- false-positive: the rule was wrong about what happened ---------------
	{name: "vulnerability-scanner-noise", expect: analyst.FalsePositive,
		provenance: FromDispositions, inject: true,
		kind: "vulnerability", severity: "medium",
		rule: analyst.Counts{False: 6},
		seen: 30, age: 4,
		title: "Outdated TLS library flagged on build hosts",
		who:   "build-runner-7.corp.example",
		evidence: []string{
			"the scanner reads the build container, not the shipped binary",
			"six ruled siblings were all false for this reason"}},
	{name: "scanner-entity-known", expect: analyst.FalsePositive,
		provenance: FromDispositions,
		kind:       "vulnerability", severity: "medium",
		entity: analyst.Counts{False: 2},
		seen:   12, age: 8,
		title: "Default credential check on a hardened host",
		who:   "build-runner-3.corp.example",
		evidence: []string{
			"the check probes the orchestrator port, which is auth'd",
			"both ruled findings about this host were scanner noise"}},
	{name: "authorised-pentest", expect: analyst.FalsePositive,
		provenance: FromDispositions,
		kind:       "detection", severity: "high",
		rule: analyst.Counts{False: 4, Real: 1},
		seen: 80, age: 5,
		title: "Credential testing from one address",
		who:   "198.51.100.44",
		evidence: []string{
			"the address is the assurance team's engagement box",
			"four of five ruled siblings were the same engagement"}},
	{name: "rule-on-trial-first-week", expect: analyst.FalsePositive,
		provenance: HandLabelled, inject: true,
		kind: "detection", severity: "medium", trial: true,
		rule: analyst.Counts{Open: 3},
		seen: 9, age: 2, spread: 3,
		title: "New rule, first week, nobody has ruled",
		who:   "webapp-prod.corp.example",
		evidence: []string{
			"the rule is on trial and its record is empty",
			"the pattern it names fires on the load balancer's health check"}},
	{name: "new-mapping-misfire", expect: analyst.FalsePositive,
		provenance: HandLabelled,
		kind:       "detection", severity: "medium",
		rule: analyst.Counts{False: 2, Benign: 1},
		seen: 15, age: 3,
		title: "Impossible travel flagged on an anycast login",
		who:   "road-warrior-11@corp.example",
		evidence: []string{
			"the identity provider's anycast edge moved mid-session",
			"two ruled siblings were this and one was the morning commute"}},
	{name: "dual-sourced-legal-traffic", expect: analyst.FalsePositive,
		provenance: HandLabelled,
		kind:       "detection", severity: "medium", indicator: true, sources: 2,
		seen: 40, age: 6, spread: 3,
		title: "Contact with an address two feeds list",
		who:   "198.51.100.200",
		evidence: []string{
			"the address is a CDN edge two feeds list wholesale",
			"every site here reaches it loading one dashboard library"}},
	{name: "monitoring-loop-critical", expect: analyst.FalsePositive,
		provenance: HandLabelled, inject: true,
		kind: "detection", severity: "critical",
		seen: 300, age: 7,
		title: "Mass credential failure across the estate",
		who:   "10.0.0.0/8",
		evidence: []string{
			"the synthetic monitor retries a staged bad password",
			"the count is the monitor's schedule, not attackers"}},
	{name: "attack-twin-benign-text", expect: analyst.FalsePositive,
		provenance: HandLabelled,
		kind:       "detection", severity: "high",
		rule: analyst.Counts{False: 5},
		seen: 41, age: 6, spread: 1,
		title: "Failed sign-in to a privileged account",
		who:   "svc-deploy@corp.example",
		evidence: []string{
			"41 failed sign-ins from one address in nine minutes",
			"it is the migration script's retry loop; five ruled siblings agree"}},
	{name: "asset-discovery-scan", expect: analyst.FalsePositive,
		provenance: FromDispositions,
		kind:       "detection", severity: "low",
		rule: analyst.Counts{False: 1},
		seen: 200, age: 1, spread: 200,
		title: "Port sweep across the lab subnet",
		who:   "it-inventory.corp.example",
		evidence: []string{
			"the inventory agent opens every port once a night",
			"the one ruled sibling of this rule was this scan"}},
	{name: "synthetic-traffic-low-sources", expect: analyst.FalsePositive,
		provenance: HandLabelled,
		kind:       "detection", severity: "high", indicator: true, sources: 1,
		seen: 12, age: 2,
		title: "Contact with an address one feed lists",
		who:   "203.0.113.66",
		evidence: []string{
			"one feed lists the whole range the address sits in",
			"the traffic is a partner's file drop the finance team uses"}},
	{name: "misfiled-into-incident", expect: analyst.FalsePositive,
		provenance: HandLabelled, inject: true,
		kind: "detection", severity: "high", incident: true,
		rule: analyst.Counts{Open: 4},
		seen: 6, age: 4,
		title: "An incident already gathers this finding",
		who:   "webapp-prod.corp.example",
		evidence: []string{
			"linked to INC-2077 by a rule that matched the entity string",
			"the finding is the scanner again; the incident is about the CVE"}},
	{name: "deprecated-rule-noise", expect: analyst.FalsePositive,
		provenance: FromDispositions,
		kind:       "detection", severity: "low",
		rule: analyst.Counts{False: 9},
		seen: 90, age: 40,
		title: "Old rule naming a decommissioned system",
		who:   "legacy-fs-1.corp.example",
		evidence: []string{
			"the system answers from an archive share",
			"nine ruled siblings, nine false positives"}},
	{name: "finance-batch-entity", expect: analyst.FalsePositive,
		provenance: FromDispositions,
		kind:       "detection", severity: "medium",
		entity: analyst.Counts{False: 4, Real: 1},
		seen:   20, age: 5,
		title: "Bulk download by a service identity",
		who:   "svc-fin-export@corp.example",
		evidence: []string{
			"the month-end batch pulled 20 files at 02:00",
			"four of five ruled findings about this identity were the batch"}},
	{name: "log-forwarder-rotation", expect: analyst.FalsePositive,
		provenance: FromDispositions,
		kind:       "control", severity: "medium",
		rule: analyst.Counts{False: 2},
		seen: 2, age: 1,
		title: "Log source gap on one forwarder",
		who:   "forwarder-4.corp.example",
		evidence: []string{
			"the gap is the forwarder's own restart window",
			"both ruled siblings were this rotation"}},

	// -- benign: it happened and is expected -----------------------------------
	{name: "nightly-backup-window", expect: analyst.Benign,
		provenance: FromDispositions, inject: true,
		kind: "detection", severity: "medium",
		rule: analyst.Counts{Benign: 7},
		seen: 1, age: 10,
		title: "Bulk data copy at 02:00",
		who:   "svc-backup@corp.example",
		evidence: []string{
			"the nightly window, the usual destination, the usual volume",
			"seven ruled siblings, all benign"}},
	{name: "backup-service-entity", expect: analyst.Benign,
		provenance: FromDispositions,
		kind:       "detection", severity: "medium",
		entity: analyst.Counts{Benign: 3},
		seen:   2, age: 3,
		title: "Service identity reading many repositories",
		who:   "svc-backup@corp.example",
		evidence: []string{
			"the same read set as every night this month",
			"every ruled finding about this identity has been benign"}},
	{name: "patch-tuesday-cycle", expect: analyst.Benign,
		provenance: FromDispositions,
		kind:       "detection", severity: "medium",
		rule: analyst.Counts{Benign: 4, Real: 1},
		seen: 300, age: 5,
		title: "Mass host reboot in one window",
		who:   "fleet-patch.corp.example",
		evidence: []string{
			"the monthly cycle, the maintenance window on the calendar",
			"four of five ruled siblings were this cycle; the fifth was a crash loop"}},
	{name: "dual-approval-deploy", expect: analyst.Benign,
		provenance: HandLabelled, inject: true,
		kind: "detection", severity: "medium",
		rule: analyst.Counts{Benign: 2, False: 2},
		seen: 4, age: 2,
		title: "Privileged action from a pipeline identity",
		who:   "svc-deploy@corp.example",
		evidence: []string{
			"a deploy approved by two people in the release tool",
			"the record is a perfect tie: two benign, two false"}},
	{name: "admin-travel-signin", expect: analyst.Benign,
		provenance: HandLabelled,
		kind:       "detection", severity: "high",
		rule: analyst.Counts{Open: 1},
		seen: 3, age: 1,
		title: "Privileged sign-in from a new country",
		who:   "admin-dana@corp.example",
		evidence: []string{
			"the country matches the travel calendar",
			"the device and the MFA method are the usual ones"}},
	{name: "marketing-upload-batch", expect: analyst.Benign,
		provenance: FromDispositions,
		kind:       "detection", severity: "low",
		rule: analyst.Counts{Benign: 1},
		seen: 25, age: 6,
		title: "Large upload to a file-sharing host",
		who:   "marketing-svc@corp.example",
		evidence: []string{
			"the campaign assets, uploaded by the same job as last time",
			"the one ruled sibling of this rule was this upload"}},
	{name: "monitoring-loop-benign", expect: analyst.Benign,
		provenance: HandLabelled, inject: true,
		kind: "detection", severity: "critical",
		seen: 500, age: 2,
		title: "Mass credential failure across the estate",
		who:   "10.0.0.0/8",
		evidence: []string{
			"the synthetic suite logs in badly on purpose, 500 times a night",
			"the count is the suite's own schedule"}},
	{name: "scheduled-maintenance-benign", expect: analyst.Benign,
		provenance: FromDispositions,
		kind:       "control", severity: "medium",
		rule: analyst.Counts{Benign: 6},
		seen: 1, age: 20,
		title: "Configuration drift on the mail gateway",
		who:   "mail-gw.corp.example",
		evidence: []string{
			"the drift is the documented maintenance exemption",
			"six ruled siblings, all benign"}},
	{name: "rotating-report-service", expect: analyst.Benign,
		provenance: FromDispositions,
		kind:       "detection", severity: "low",
		entity: analyst.Counts{Benign: 2},
		seen:   30, age: 8,
		title: "Credential rotation by a reporting service",
		who:   "svc-report@corp.example",
		evidence: []string{
			"the rotation its manifest schedules every quarter",
			"both ruled findings about this identity were this rotation"}},
	{name: "first-run-cron-benign", expect: analyst.Benign,
		provenance: HandLabelled, inject: true,
		kind: "detection", severity: "medium",
		rule: analyst.Counts{Open: 2},
		seen: 1, age: 1,
		title: "New scheduled task on a build host",
		who:   "build-runner-9.corp.example",
		evidence: []string{
			"the task was added by the pipeline definition in git",
			"the rule has nothing ruled yet: two open siblings"}},
	{name: "vendor-status-check", expect: analyst.Benign,
		provenance: FromDispositions,
		kind:       "vendor", severity: "low",
		entity: analyst.Counts{Benign: 2},
		seen:   8, age: 12,
		title: "Third-party API polling at odd hours",
		who:   "vendor: sumi-sso",
		evidence: []string{
			"the vendor's status probe, documented in their integration guide",
			"both ruled findings about this vendor were this probe"}},
	{name: "ci-build-signin", expect: analyst.Benign,
		provenance: FromDispositions,
		kind:       "code", severity: "low",
		rule: analyst.Counts{Benign: 3},
		seen: 60, age: 1,
		title: "Build identity minting many tokens",
		who:   "svc-ci@corp.example",
		evidence: []string{
			"one token per build, 60 builds today",
			"three ruled siblings, all the same pipeline"}},
	{name: "annual-access-review", expect: analyst.Benign,
		provenance: FromDispositions,
		kind:       "control", severity: "low",
		rule: analyst.Counts{Benign: 5},
		seen: 1, age: 2000,
		title: "Access report run outside business hours",
		who:   "compliance-svc@corp.example",
		evidence: []string{
			"the annual review the policy schedules",
			"every ruled sibling has been this review"}},
	{name: "staging-refresher", expect: analyst.Benign,
		provenance: FromDispositions,
		kind:       "detection", severity: "medium",
		rule: analyst.Counts{Benign: 2},
		seen: 15, age: 4,
		title: "Database reset on a staging host",
		who:   "staging-db.corp.example",
		evidence: []string{
			"the refresher drops and recreates the staging schema nightly",
			"both ruled siblings were this job"}},
}
