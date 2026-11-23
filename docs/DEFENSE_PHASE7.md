# Phase 7 — Autonomous Defensive Investigation (PR #7)

Phase 7 adds **autonomous, durable, evidence-only** investigations on top
of Phase 6 case-scoped threat correlation. It introduces a fixed,
deterministic investigator with bounded database reads, independent
review lenses, explicit uncertainty, immutable provenance and human
verdicts. It is **not an LLM agent** and does not perform live response
actions. This conservative first increment is intentionally inspectable
and testable before permitting any model-assisted investigation.

## Behavior

When an authenticated operator opens a case, ARTEX queues a local investigation
**in the same PostgreSQL transaction as case creation and initial correlation**.
A background worker starts automatically in `ARTEX_MODE=defense`, collects
existing Phase 6 evidence, and runs these independent review lenses:

1. **Alert signal/context:** source alert is unverified, regardless of
   vendor severity.
2. **Corroboration:** count distinct, bounded, same-source correlated events;
   do not treat same-sensor repetition as independent confirmation.
3. **Asset context:** list the number of inventory IDs already attached to
   the alert; no vulnerability, reachability or OT-safety claim.
4. **ATT&CK hypothesis:** suggest human review only when an existing Phase 6
   technique mapping has a supporting event. Cap automated confidence.
5. **Coverage gaps / counterhypotheses:** flag a single-observation case,
   missing inventory links and lack of independent sensor confirmation.
   Encourage investigating benign administration, authorized testing,
   spoofed sensors and missing context.

All findings contain an existing case-linked `defense_events.id`,
a category, bounded explanation and confidence **at most 55/100**.
Scores are review heuristics, not probabilities of maliciousness.
This is no automatic threat-actor attribution, offensive capability,
auto-triage disposition, or emergency response authorization.

### Automated intake

An authenticated operator can separately enable **high/critical auto case
intake** from the investigation panel; it is **OFF by default**.
When enabled, one new recent high/critical alert is admitted per
2-second polling tick, with at most 30 automated case intakes per
rolling hour across concurrent ARTEX processes. The worker creates a
case, Phase 6 correlation snapshot, and investigation queue entry in
one transaction with an operator-visible case audit. The case remains
`open`; no network, firewall, EDR or identity action occurs.

Pausing stops new work at the next tick; it does not abort a currently
committing transaction. Individual queued/running investigations can
be cancelled. All controls have recorded operator rationales, and
the database survives application restarts. A case may be investigated
again manually, but never has more than one active queued/running
investigation.

### Reliability / resource bounds

- Poll every 2 seconds while defense mode is running.
- At most **two** jobs per tick *per process*, one SQL analysis transaction
  at a time. A 16-second tick deadline and 30-second database lease prevent
  stale work. Jobs are acquired atomically with `FOR UPDATE SKIP LOCKED`.
- Up to **three** attempts per job. Expired leases may be retried after an
  application crash; exhausted leases become terminal failures.
- Source data is constrained by Phase 6 correlation to at most 50 observed
  events per case. Technique hints are capped at 20; report views return
  at most 20 runs and 120 findings.
- Findings and audit entries are append-only and are committed atomically
  with each completed investigation. A cancelled/superseded job cannot
  finish twice or create duplicate findings.
- Run summaries and errors are static/generic. Raw logs, credentials,
  passwords, arbitrary scripts, LLM prompts and off-platform artifacts
  are never exported from this worker.

## Human-in-the-loop

Each finding starts unreviewed. An authenticated analyst can record exactly
one of `supported`, `refuted`, or `needs_more_evidence` with a 12–1200-byte
rationale. The verdict is immutable, with its own evidence record and
audit entry. **Supported** means supported for *investigative follow-up*,
not confirmed maliciousness or approval to act. No verdict changes
case status or response permissions, and emergency containment remains
controlled solely by its existing independent safeguards.

The user interface is inside the static-export-compatible Phase 6 page:
`/function/defense/intelligence?case=<id>`.
The case graph and timeline link investigation runs, findings, backing
sensor event IDs, append-only reviews and audit activity.

## Migration

Additive migration `db/migrations/0018_defense_autonomous_investigation.sql`
creates:

| Table | Purpose |
| --- | --- |
| `defense_investigation_control` | Persistent operator switch for auto-intake and pause |
| `defense_investigation_control_audit` | Immutable operator configuration history |
| `defense_investigation_runs` | Durable case jobs, lease, attempt and bounded status |
| `defense_investigation_findings` | Immutable case/run/event-backed investigator suggestions |
| `defense_investigation_reviews` | Immutable one-verdict-per-finding human decisions |
| `defense_investigation_audit` | Immutable queue, start, complete, failure, cancellation and review trail |

Composite foreign keys prevent linking evidence from a different case.
The schema installs database triggers that reject ordinary mutation to
findings, reviews, and audit history. Database owners/superusers can
override these controls; this is **not cryptographically immutable**.

Previous migrations 0001–0017 remain untouched.

## Authenticated REST API

All routes below require existing ARTEX JWT/cookie protections and
`ARTEX_MODE=defense`. Mutations are protected by existing same-origin
cookie rules. Unknown JSON fields and oversize mutation bodies are
rejected by the existing Phase 3 workflow decoder.

| Method | Endpoint | Function |
| --- | --- | --- |
| GET | `/api/defense/investigations/control` | Read auto-intake/pause, queued/running/finished counts |
| POST | `/api/defense/investigations/control` | Update `auto_intake` and/or `paused`, with required reason |
| POST | `/api/defense/cases/{id}/investigations` | Queue an active-case rerun |
| GET | `/api/defense/cases/{id}/investigations` | Read bounded jobs, findings and reviewer verdicts |
| POST | `/api/defense/investigations/{id}/cancel` | Cancel a queued/running job with reason |
| POST | `/api/defense/investigations/findings/{id}/review` | Record one immutable finding verdict |
| GET | `/api/defense/cases/{id}/graph` | Phase 6 graph extended with investigation and evidence links |
| GET | `/api/defense/cases/{id}/timeline` | Phase 6 timeline extended with investigation records |

Enable automatic intake (only if your SOC explicitly authorizes it):

```json
{"auto_intake":true,"reason":"Our on-call SOC team approves read-only high severity case intake"}
```

Pause work:

```json
{"paused":true,"reason":"Investigations paused while verifying ingestion and source integrity"}
```

Review a reported finding:

```json
{"verdict":"needs_more_evidence","reason":"One sensor observation is insufficient to confirm this hypothesis"}
```

No API supports arbitrary target names, custom SQL, shell commands, HTTP
requests, agent tool arguments, firewall rules or endpoint isolation.

## Security caveats / limitations

- This implementation uses an **autonomous deterministic worker**, **not**
  generative AI or machine-learning inference. It intentionally cannot
  browse, query external threat intel feeds or inspect hosts. Any future
  optional LLM would require prompt-injection isolation, strict source
  redaction, evidence-only outputs, budget caps and additional approval.
- Phase 6 source authentication currently inherits console JWT; do not
  interpret source-attested IPs or an untrusted sensor as verified attacker
  infrastructure.
- Case intake may be noisy, despite the high/critical threshold and quota.
  Auto-intake is opt-in and can be disabled or paused immediately.
- The current worker does not start containment, perform host-side collection,
  modify the Phase 3 response approval state, or self-approve findings.
- Production log retention, per-operator identities, independent sensor
  attestation and site-specific OT safety checks remain future work.
- The system can store sensitive hostnames/signature strings received from
  telemetry. Restrict database/console access and establish a retention policy.

## Validation and rollout

```bash
go test ./defense
go test ./server -run 'Test(AnalyzeInvestigation|DefensiveInvestigator|InvestigationHuman|InvestigationQueue)'
go test ./db -run 'TestOpenMigratesFreshDatabase'
go build ./...
cd web && npm ci && npx tsc --noEmit && npm run build:static
```

The dedicated PR #7 CI workflow uses PostgreSQL 16 to verify new schema
constraints, evidence-only job processing, case-unique queue admission,
append-only reviewer verdicts and regression tests. Confirm the *full*
ARTEX CI before merging and validate on a staging sensor using synthetic
alerts. Test process restarts, worker leases and human pause/cancel behavior.

Keep PR #7 as draft until all gates pass. Do not merge automatically.
