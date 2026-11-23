# Phase 8 — Real-Time SOC Improvements

PR #8 adds a near-real-time, authenticated SOC monitoring layer to the
existing ARTEX Defense ingestion, alert, case, investigation and emergency
response pipelines. It does **not** change emergency enforcement eligibility,
move containment into the SOC dashboard, or automatically mark an alert
as a confirmed intrusion.

## What changed

### 1. Live, authenticated change feed

`GET /api/defense/live` is a Server-Sent Events (SSE) connection.
Its only data event is a JSON watermark:

```text
event: revision
data: {"events":123,"alerts":31,"case_updated_micros":1795411020000000}

```

These numbers are **database revision hints**, not confidence, telemetry
payloads or sequence-replay guarantees. A reconnect immediately sends a full
current watermark; the browser refetches existing JWT-protected SOC APIs.

- **Authentication:** inherits the existing ARTEX JWT and cookie-CSRF
  middleware. The browser opens the stream with an Authorization bearer
  header using `fetch` (EventSource alone cannot set custom headers).
  **No JWT is put in a URL or query string.**
- **Data minimization:** never streams usernames, event IDs, IP addresses,
  endpoint labels, file paths, signatures, free text or raw sensor logs.
- **Isolation:** enabled only in `ARTEX_MODE=defense`, never in pentest mode.
- **Scalability guardrails:** one bounded read-only watermark query every
  ~2 seconds per active stream, up to 16 concurrent streams per process,
  a short 2-minute connection lifetime, a 15-second heartbeat, 3-second
  stream write deadline, and a 3-second Retry-After if at capacity.
- **Multi-process correctness:** watermarks are read from shared PostgreSQL
  tables. A change ingested by another ARTEX server is eventually seen by
  every connected dashboard; no in-memory-only publish channel is required.
- **Performance isolation:** no new per-event trigger, `pg_notify`,
  global row lock, hot revision counter or database write has been added
  to the high-speed ingestion or emergency-enforcement path.
- **Proxy behavior:** `Cache-Control: no-store, no-transform`,
  `Content-Type: text/event-stream`, and `X-Accel-Buffering: no`
  discourage buffering. Operators must still configure their reverse proxy
  to support SSE flushes and a persistent connection.
- **Fallback:** the browser switches to ~8-second polling if the stream
  cannot open or stalls behind a proxy. It reconnects with capped
  exponential backoff and does a refresh when the tab becomes visible.

**Latency limitation:** an update is signaled *approximately within 2
seconds after its SQL commit* under healthy, unbuffered networking.
It is **not guaranteed 2-second end-to-end detection/response**, is
not a delivery/latency SLA, and does not change when the emergency
containment fast path runs. Database load, reverse proxies and tab
suspension affect actual update delay.

### 2. Priority review queue

`GET /api/defense/soc/queue` returns at most 50 open/unassigned
human-review alerts in descending detector severity order (critical,
high, medium, low). Unassigned alerts of equal severity appear before
already-open cases; newer alerts break ties.

The operator-facing score is deliberately simple: critical=90,
high=65, medium=40 and low=15, plus 10 for an unassigned alert.
This score is a **queue sort hint**, not a probability of exploitation,
incident confidence, asset criticality, or authority to contain.

The panel can filter by severity and whether a case has been opened.
**Open review case** requires a human click and confirmation. It uses
the original authenticated Phase 3 `POST /api/defense/cases` endpoint,
which queues Phase 7's evidence-only investigation. Cases and
approvals remain under human review.

### 3. Ingestion/source health

`GET /api/defense/soc/health` supplies a server timestamp,
recent ingested events and alerts (5m and 1h), each sensor source's
1h volume and last ingestion time, plus the last reported sensor
observation time.

`ingest_state` has three states:

- `receiving`: most recent ingestion was within 5 minutes;
- `no_recent_ingest`: previously received data, but nothing in 5 minutes;
- `unknown`: no stored ingestion record.

A period without new events does **not** establish a sensor outage
or the absence of threats. The sensor-clock delta is
`ingested_at - observed_at` for the **same latest-ingested event**,
not a tested network transmission latency. It can be negative when
sensor clocks are ahead.

The endpoint **does not** attempt live sensor connectivity probes,
new network connections, privileged status actions, outside intel
queries or host process execution. Real sensor heartbeat attestations
and synthetic end-to-end probe checks are future work.

### Schema

Migration `0019_defense_soc_monitoring.sql` adds two read-side indexes
for recent ingestion and case update monitoring. All prior migrations
0001–0018 stay unchanged. The emergency action and ingestion tables
receive **no new write-time triggers**.

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/defense/live` | Authenticated SSE watermarks |
| GET | `/api/defense/soc/queue` | Bounded severity-ranked review queue |
| GET | `/api/defense/soc/health` | Source freshness and event/alert counts |

All inherit the same existing ARTEX session middleware and defense-mode
gate; none changes application state.

## Dashboard

Go to **Functions → Defense SOC**.

The new **Real-time SOC operations** panel displays LIVE / CONNECTING /
POLLING mode, recent flow rates, last-ingest freshness, source volumes
and potential sensor clock skew. The **Priority review queue** allows
operator-reviewed case creation and navigation into the Phase 6/7
case intelligence/timeline panel. Existing detection pack, normalized
event table, case/approval queue and emergency reversal dashboard are
preserved.

## Verification

```bash
go test ./server -run 'TestSOC'
go test ./db -run 'TestOpenMigratesFreshDatabase'
go build ./...
go vet ./...
cd web && npm ci && npx tsc --noEmit && npm run build:static
```

The dedicated GitHub Actions workflow runs the Go/database suite against
PostgreSQL 16, compiles the backend and builds the static Next.js UI.
The test coverage includes authentication, defense-mode isolation,
the initial revision resynchronization frame, explicit field-leak
checks, queue ordering, ingest freshness and monitoring read-only behavior.

### Pre-merge operator verification

1. Simulate passive Suricata/Wazuh events and check the dashboard
   increments after an actual commit.
2. Restart the Go backend, disconnect/reconnect the network and hide /
   show the browser tab; ensure the UI self-recovers.
3. Confirm that a buffering reverse proxy causes fallback to polling
   rather than showing a misleading LIVE state.
4. Verify read-only API use cannot produce an emergency action,
   case-status change or investigation verdict.
5. Under heavy ingestion and several SOC viewers, monitor PostgreSQL
   index use, stream limits and response time; the 2-second refresh
   cadence is a tuning target, not a guaranteed SLA.
6. Complete the general ARTEX CI and staging regression suite.

**Security boundary:** operator actions continue through the original
reviewed APIs. This PR does not change containment thresholds, allowlists,
ARM/PAUSE/REVERT safety controls, worker permissions or the rules for
automatic emergency response.
