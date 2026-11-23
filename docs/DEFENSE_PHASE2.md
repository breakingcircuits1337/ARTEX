# ARTEX Defense — Phase 2 telemetry MVP

Phase 2 builds on Phase 1's `ARTEX_MODE=defense` guard. It adds a **passive,
authenticated telemetry-ingestion API**, a normalized PostgreSQL event ledger,
two deterministic alert indicators, exact-match asset correlation, and a
read-only SOC view. No autonomous response, remote probes, or AI-driven
detector execution is introduced.

This is an **MVP for a trusted operator's lab / controlled network**; it is
not a certified OCSF integration, full Sigma rule interpreter, SIEM, EDR,
production-grade high-volume collector, or OT enforcement layer.

## Start

On the Phase 2 branch, set `ARTEX_MODE=defense`, configure a PostgreSQL
password, then `docker compose up -d --build`. The server automatically
applies additive migration `0014_defense_telemetry.sql`, preserving prior
ARTEX assets, findings, and investigations.

Open **Functions → Defense SOC** (`/function/defense`). The page polls
`/api/defense/summary`, `/api/defense/events` and
`/api/defense/alerts` every 15 seconds while the tab is visible.

## API and authentication (Phase 2 legacy and PR #10)

The original Phase 2 `POST /api/defense/events` uses an administrator
session JWT and remains for compatibility. **Do not give it to an unattended
collector.** PR #10 provides a separate least-privileged sensor credential
for `POST /api/defense/collector/events`, bound to a single sensor type.
Administrator-only collector creation, rotation and revocation endpoints return
a random secret only once. See [PR #10 guide](DEFENSE_PHASE10.md).

The original read-only endpoints continue to require a console session.
Sensor posts remain capped at 50 events and 1 MiB per batch, with per-collector
600-events/minute admission. A rejected/over-quota batch does not commit.
Malformed records fail before database writes. Within a collector, replayed
events with identical external IDs deduplicate; overlapping IDs from
different collectors remain separate evidence.

### Continuous log forwarding

Use `scripts/defense_forwarder.py` **with a dedicated sensor credential**,
not `ARTEX_DEFENSE_JWT`. The Python standard-library collector now persists
an SQLite queue, source offset and device/inode in atomic transactions, retries
network failures with backoff, and handles rename/create log rotation.
The queue holds raw sensor JSON and requires restrictive local permissions.

```bash
export ARTEX_COLLECTOR_TOKEN='<securely issued dc1 collector token>'
python3 scripts/defense_forwarder.py --source suricata \
  --file /var/log/suricata/eve.json --follow \
  --url https://your-private-soc.example \
  --state /var/lib/artex-defense/sensor-01.sqlite3
```

For collector provisioning, endpoint contracts, reliability guarantees and
known limitations, read [Secure Collector & Durable Telemetry](DEFENSE_PHASE10.md).

## Detectors — deterministic version 1

1. `vendor_alert_v1`: emits a signal when an incoming Suricata event has
   `event_type=alert` and a signature, or a Wazuh event has
   `rule.level>=10` and a description. Severity derives from the source.
2. `password_spray_v1`: emits a medium-severity **possible** spray signal
   after at least five **distinct account names** have recorded failed
   authentication events from one source IP within the preceding ten minutes.
   The alert is deduplicated by source IP and ten-minute time bucket.

These rules are explicit Go logic; **Sigma parsing and programmable rules are
not yet implemented**. An alert never means successful compromise by itself.
Rule outputs reference the initiating event ID, and matched inventory asset IDs,
if any.

## Correlation and evidence boundaries

Exact matches are made against existing ARTEX assets by `src_ip`, `dst_ip`,
or hostname (case-insensitive domain). Matches are capped to 32 asset IDs per
event. The correlation never performs DNS resolution, active scanning or
Internet lookups. Missing inventory means an event remains **unlinked**, not
that the host is benign.

Only normalized, bounded fields are stored: source, external identifier,
timestamp, class, action, outcome, source/destination IP, hostname, username,
signature, severity, upstream alert flag and asset IDs. Raw JSON is **not**
persisted. Treat identity fields and signatures as sensitive security
metadata. Access should remain administrator-only; establish retention and
redaction policies before real-world deployment.

## Validation / known limitations

```bash
go test ./defense ./server
go test -p 1 ./...
cd web && npx tsc --noEmit && cd ..
```

The GitHub CI pipeline also runs gofmt, Go build/vet/tests, PostgreSQL migration
and web checks. A green CI run and isolated deployment smoke test are required
before merging.

Operational limitations: no dedicated collector identity, rate limiter, queue,
dead-letter transport, bulk retention, rule tuning/UI, incident status workflow,
or autonomous containment. The SOC page is read-only. Phase 2 is deliberately
passive and inherits Phase 1's documented non-agent API/runtime limitations.

AGPL-3.0 and upstream attribution remain intact.
