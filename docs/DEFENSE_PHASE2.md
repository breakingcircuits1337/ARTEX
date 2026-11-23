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

## API and authentication

All endpoints go through ARTEX's existing session JWT verification and
same-origin cookie protections. **No anonymous ingest route exists**.
For this prototype, use a bearer token obtained from your own ARTEX login
session over a trusted/private network. The existing JWT expires after seven
days; rotate/re-authenticate collectors before expiry. A dedicated
restricted-scope collector token with rotation and IP/rate restrictions is
future work; **never expose an admin JWT in a public-facing collector**.

| Method | Route | Operation |
| --- | --- | --- |
| POST | `/api/defense/events` | Insert 1–50 security events (max 1 MiB request, 128 KiB/event) |
| GET | `/api/defense/events?limit=50` | Latest normalized events (max 100) |
| GET | `/api/defense/alerts?limit=50` | Latest detection signals with linked evidence IDs (max 100) |
| GET | `/api/defense/summary` | Event, alert and asset-link counts |

Ingestion envelope: `{"source":"suricata|wazuh|generic|ocsf","events":[{...}]}`.
Malformed event data fails the batch before any database writes; database
insertion and detection are transactional. Replayed events with an identical
`source` and `external_id` are deduplicated. Without a vendor ID, the
normalized JSON content is hashed as the stable event ID.

**Generic example** (replace JWT with a valid ARTEX session bearer):

```bash
curl -fsS http://127.0.0.1:8787/api/defense/events \
  -H "Authorization: Bearer $ARTEX_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"source":"generic","events":[{"event_id":"demo-1","kind":"authentication","outcome":"failure","src_ip":"192.0.2.10","username":"alice","timestamp":"2026-11-23T12:00:00Z"}]}'
```

**Suricata EVE**: send a JSON event object inside `events`, including
`event_type="alert"`, `src_ip`, `dest_ip`,
`alert.signature`, and `alert.severity`. Severity 1 becomes high; other
levels are mapped conservatively. **Wazuh**: send the alert JSON with `id`,
`rule.level`, `rule.description`, `rule.groups`, `agent.name`,
`data.srcip`, `data.srcuser`. A Wazuh level of 10 or greater qualifies as
a vendor signal. `ocsf` accepts a **limited field projection only** and
is not full OCSF validation or fidelity.

Forwarders should batch fewer than 50 records and send them using TLS or a
private tunnel. Do not automatically forward complete raw logs, credentials,
request/response bodies, or tokens.

### Continuous log forwarding (included)

A Python standard-library forwarder now reads Suricata EVE or Wazuh
newline-delimited JSON and pushes batches to the authenticated API:

```bash
# Authenticated ARTEX session bearer from your own login, never hard-code in a script.
export ARTEX_DEFENSE_JWT='<your-authenticated-session-token>'
python3 scripts/defense_forwarder.py --source suricata --file /var/log/suricata/eve.json --follow --url https://your-private-soc.example
# Wazuh on a separately authorized collector:
python3 scripts/defense_forwarder.py --source wazuh --file /var/ossec/logs/alerts/alerts.json --follow --url https://your-private-soc.example
```

Remote HTTP destinations are rejected; local loopback HTTP is allowed.
Redirects are disabled so authorization headers are not sent to a new origin.
Partial batches flush after roughly five seconds when following a quiet file.
The forwarder does not implement durable cursor checkpoints, log rotation
reopening, queueing, backpressure or retry scheduling; a failed send causes
a visible failure and needs operator supervision. Replaying the file on restart
is safe with ingestion deduplication, but can be costly for large logs.
Run `python3 -m unittest scripts/test_defense_forwarder.py` for offline checks.


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
