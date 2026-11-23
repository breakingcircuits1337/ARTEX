# PR #13 — Production Observability & Operational Readiness

ARTEX-DEFENSE PR #13 adds read-only, admin-authenticated operational status,
Prometheus text-format metrics, process-local ingestion counters and an
operator-facing health panel. It makes no new automatic response decisions,
does not enable active scanning and does not claim a production safety or
performance certification. **It is a visibility milestone, not an HA or SLO
guarantee.**

## API contract and authentication

| Endpoint | Method | Access | Contract |
| --- | --- | --- | --- |
| `/api/health` | GET | Anonymous (minimal) | **Liveness only:** `{"ok":true}`; authentication provides additional build info. Do not use to assess database readiness. |
| `/api/ready` | GET | Anonymous (minimal) | Existing cached PostgreSQL ping; HTTP 200/503. Intended for *internal* liveness/readiness probes. |
| `/api/defense/soc/health` | GET | Admin JWT | Existing source-activity and event-clock freshness; no sensor attestation. |
| **`/api/defense/operations/health`** | GET | Admin JWT, defense mode | Bounded database snapshot, process-local counters, warnings and interpretation. |
| **`/api/defense/operations/metrics`** | GET | Admin JWT, defense mode | Prometheus 0.0.4 text; deliberately fixed metric names, no user-generated labels. |

New routes are **NOT** added to the anonymous auth-exemption list.
A collector credential works only on its existing one-purpose ingest endpoint.
Anonymous or expired-admin access to the operations API is rejected. Defense
mode is required; in pentest mode these endpoints return 404. They cannot
read the secret credential hash, arbitrary logs or source event data.
**Do not configure Prometheus with bearer tokens in URL/query strings.**
Use a protected service credentials file, short-lived JWT refresh process
or internal bearer-header proxy where appropriate. Never allow third parties
to scrape the metrics endpoint. HTTPS, proxy access controls, server-side
authentication, and a private monitoring network are still required.

### Example scrape (from your private, approved monitoring host)

```bash
curl -fsS -H "Authorization: Bearer ${ARTEX_ADMIN_JWT}" \
  https://private-soc.example/api/defense/operations/metrics
```

For Prometheus static scrape configurations, the metrics path is
`/api/defense/operations/metrics`, the scraping interval should be
**at least 30 seconds**, and the target must be reachable only from the
authorized monitoring environment. Prefer a managed bearer token file
with strict permissions and rotation; don't put credentials in committed YAML.
The same application-admin token has broader powers than a scrape-only
credential, so full production-grade least-privilege metrics authentication
is **future work**. Use a tightly restricted internal collector/proxy
rather than broadly distributing an admin JWT.

## Signals and interpretation

`operations.status` is one of:

- `ready`: required SQL snapshot queries succeeded, at least one enrolled
  active collector exists, and no configured operational warning threshold
  (failed emergency/failed investigation/backlog >=100) was triggered.
  **Does NOT prove collectors are online or security controls are effective.**
- `attention`: known failures within the last hour or >=100 queued
  evidence-only investigations. Investigate the ledger. No automatic
  containment is invoked or suppressed by this label.
- `unknown`: database queries worked but there are no active enrolled
  collectors. An empty SOC can be intentional; this is not an outage verdict.
- HTTP **503**: a database dependency or snapshot query failed. No cached
  healthy state is returned after the short error-cache period; the
  dashboard clears its prior good state on request failures.

Warnings include `collectors_require_company_binding`,
`collector_has_no_telemetry`, `collector_no_recent_telemetry`,
`collector_sample_incomplete`, `emergency_action_failed`,
`investigation_failed`, `investigation_backlog`, and
`no_enrolled_active_collectors`. They are **review cues**, not verified
attacks, incident escalation or authority to automate firewall actions.

### Sensor freshness sample

The backend inspects **at most 201 active collectors**, ordered by ID,
using the index on collector ID and most recent ingested event per collector.
The API reports up to 200 sampled collectors. If more than 200 are present,
`collector_sample_truncated=true` and the sampled never-seen and
silent-15-minute counts become **-1 (unknown)** rather than false totals.
An event-free collector may be disabled, newly enrolled, misconfigured or
simply idle; silence alone does **not prove sensor downtime**. This does not
perform live probes, heartbeat attestations or synthetic packet injection.

### Process counters and metrics

`artex_defense_ingest_handler_*_total` counters and a fixed-bucket
`artex_defense_ingest_handler_duration_seconds` histogram count POST
requests that actually reach the Go **ingestion handler**. Auth failures
denied before the handler are not counted. Counters are **per process**
and reset on restart; add a `job`/`instance` identity in your own
Prometheus target configuration if running multiple app instances.

Operational metrics are mostly PostgreSQL **gauges** and can reflect
concurrent transactions and changing clocks; they are not a single
transactionally consistent global point-in-time state. Read-side caches
combine requests within five seconds to prevent expensive repeated SQL
work; on failure, cache only for one second so recovery is visible.
Samples are evaluated with a five-second overall timeout.
The `process_goroutines` gauge is informational, not evidence of leaks.

**Metric privacy:** No username, IP address, file path, event ID, source
signature, company ID, collector ID, case ID, hostname or source-provided
string becomes a metric label or value. The fixed `le` bucket labels in
histogram output are the only labels in PR #13 metrics. Prometheus endpoint
calls themselves are not included in the ingestion counters.

## Deployment / rollback / incident handling

1. Back up PostgreSQL. Apply normal application migration 0023,
   which only adds three **read-side indexes**. It does not add triggers,
   event writes, policy changes or external network connectivity.
2. Deploy server and static UI together. Keep the previously configured
   JWT/collector authentication and defense-mode restrictions.
3. Set up HTTPS reverse proxy and private, credentialed scraping; do not
   expose `/api/defense/operations/metrics` anonymously or to the public.
4. Smoke-check `GET /api/ready`, then authenticated operations `health`
   and `metrics`. Verify a deliberately invalid token returns **401**,
   a collector credential returns **401**, and pentest mode returns **404**.
5. Confirm that the SOC dashboard clears the old snapshot when the
   health API fails, rather than displaying stale green status.
6. Simulate one synthetic collector event in an isolated staging company.
   Verify a single ingestion handler increment and no active response.
7. Validate the existing case, collector, emergency, Sigma and investigation
   CI suites, a full database backup/restore rehearsal, PostgreSQL pool
   tuning, metrics access logging and disk retention outside PR #13.
8. On rollback, revert app/API/UI deployment together. The three indexes
   are additive, remain harmless and can be removed separately during
   a controlled maintenance change if needed.

### Example monitoring review thresholds

These are **starting points for human review**, not hard SLOs:
- Snapshot endpoint HTTP 503 for >2 consecutive scrapes: check PostgreSQL.
- `emergency_failed_last_hour > 0`: review emergency audit and revert logs.
- `investigations_failed_last_hour > 0`: review worker logs and case context.
- `investigations_queued >= 100`: inspect slow/backlogged worker.
- `collectors_unassigned > 0`: finish PR #11 verified company binding.
- `collectors_silent_15m > 0`: compare source activity with scheduled
  sensor behavior. Do not infer an outage without direct independent health
  checks. If sample truncated, use fleet inventory tooling instead.

### Tests and limitations

```bash
go test -count=1 ./server -run 'TestOps'
go test -count=1 ./db -run 'TestOpenMigratesFreshDatabase'
go build ./...
go vet ./...
cd web && npm ci && npx tsc --noEmit && npm run build:static
```

Dedicated CI uses PostgreSQL 16 for end-to-end validation. Tests assert
JWT and mode gates, collector credential rejection, synthetic event
instrumentation, Prometheus metric cardinality/privacy, read-only
behavior, cache coalescing and database-missing HTTP 503.
**No full SIEM observability, network tracing, OTel distributed traces,
independent sensor heartbeat, tenant-user RBAC, production SLA,
automatic remediation or threat confirmation is implemented here.**
