# PR #10 — Secure Sensor Identity & Durable Telemetry Collection

This change introduces a separate, least-privileged **collector authentication**
scheme and a crash-recoverable Python collector spool. It is intended for
authorized, controlled network deployment; it is not an OT certification.

## Security contract

- `POST /api/defense/collector/events` accepts **only**
  `Authorization: Collector dc1.<id>.<secret>` issued by the administrator.
  No session JWT, cookie, query token, or other API path accepts this credential.
- Every collector is restricted to exactly one `suricata`, `wazuh`,
  `generic`, or `ocsf` source label, verified before any insert.
- Each credential has 256 random bits. The database stores only the SHA-256
  digest of the *complete* token; the secret is returned only on creation or
  rotation. All successful and failed token attempts avoid token logging.
- Admin `GET/POST /api/defense/collectors`,
  `POST /api/defense/collectors/{id}/rotate` and
  `POST /api/defense/collectors/{id}/revoke` use existing admin JWT session
  and same-origin protections. List returns **no token hashes**.
- Rotation immediately invalidates the previous token and preserves the
  collector's ID, source, and evidence provenance.
- A per-collector PostgreSQL minute bucket admits **up to 600 events/minute**
  across all server instances. Over-quota batches return HTTP 429 and
  `Retry-After`; they create no events and are safely retried.
- `defense_events.collector_id` records immutable collector provenance. The
  event dedupe index keys on `source + collector_id + external_id`. Legacy
  operator-inserted rows have a NULL collector ID and remain independent.
- **Collector credentials cannot trigger the emergency containment fast path**.
  Defense mode and collector authentication do not arm the firewall.
  The preexisting admin-only ingestion API remains available for compatibility
  but is **not for unattended remote sensors**; avoid using admin JWTs on
  collectors. A future migration should retire that legacy path.
- A compromised collector can still forge events *under its own credential*:
  this provides credential provenance, not cryptographic sensor attestation.
  A collector token must never be treated as proof that the source event is true.
- This phase does not yet implement multi-tenant isolation, mTLS, RBAC,
  per-collector IP ACLs, or SIEM-scale queuing.

## Provision a collector

Start ARTEX with `ARTEX_MODE=defense`, log in as the administrator, and send
the following to the **private console endpoint**:

```bash
curl -fsS https://your-private-soc.example/api/defense/collectors \
  -H "Authorization: Bearer $ARTEX_ADMIN_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"name":"sensor-dmz-01","source":"suricata"}'
```

The `token` appears **once** in the response. Store it in a restricted secret
manager; never commit it, log it, or put it on a command line. Do not use an
administrator JWT in the log forwarder.

```bash
# Supply the token from a restricted secret store, not a shared shell history.
export ARTEX_COLLECTOR_TOKEN='<issued dc1 token>'
python3 scripts/defense_forwarder.py \
  --source suricata --file /var/log/suricata/eve.json \
  --url https://your-private-soc.example --follow \
  --state /var/lib/artex-defense/sensor-dmz-01.sqlite3
```

Use a private `0700` state directory on encrypted or otherwise protected
storage, and protect the environment of the collector process. The collector
queue contains **raw incoming JSONL records** and can include sensitive
security metadata. Restrict host access and define retention and privacy rules.

Revoke a device using
`POST /api/defense/collectors/{id}/revoke`, or rotate without altering
its identity using `POST /api/defense/collectors/{id}/rotate` with
your administrator JWT. Update the collector secret securely after rotation.

## Delivery and durability

The forwarder uses a local SQLite write-ahead-log database with synchronous
FULL commits, a single-process lock, and an owner-private queue. The source
device/inode/offset and pending records commit **in the same transaction**.
Records are removed only after the server confirms that every submitted event
was ingested or already existed. Process crashes after server commit and before
local acknowledgment are safe: retries are deduplicated per collector.

- Retries use capped exponential backoff; a 429 is retryable.
- Malformed JSONL records, invalid credentials, and invalid source scopes stop
  safely without silently advancing the source cursor.
- An incomplete log line is held until it receives a newline; oversize lines
  fail without losing the checkpoint.
- When a log file is renamed during rotation, the spool drains the old inode
  when the rotated file remains in the same directory, then follows the new
  inode. If the prior inode vanishes, ingestion stops for manual recovery
  rather than silently skipping unread events.
- `copytruncate` is **not lossless**; the forwarder emits a warning when
  truncation is detected, but bytes written during copy/truncation can still
  be lost. Prefer rename/create rotation and keep rotated logs available.
- Queue backpressure stops further reads at `--max-queued` (default 10000),
  preserving the cursor. **Retain source logs during prolonged outages**;
  queues cannot protect data deleted before it was spooled.
- It is at-least-once delivery, **not** end-to-end exactly-once processing.
  Collector identity, local spool state, and the PostgreSQL database must
  survive their respective restarts.

## Verification

```bash
python3 scripts/test_defense_forwarder.py
go test -count=1 ./server -run 'TestCollector'
go test -count=1 ./db -run TestOpenMigratesFreshDatabase
go test -p 1 ./...
```

Test token rotation/revocation, source mismatches, duplicate vendor IDs across
collectors, a lost connection mid-batch, renaming a live log, PostgreSQL
unavailability, quota rejection and credential theft in an isolated staging
installation before connecting real sensors.
