# Phase 6 — Threat Correlation Graph and Incident Timelines

ARTEX Phase 6 adapts the source archive's `threat_actors`, `threat_edges`,
`kill_chain_nodes` and `kill_chain_edges` concepts to the existing ARTEX
Phase 2/3 evidence and case model. The source is
`artex-defender-github-ready.zip`:
`artex-defender/db/schema.sql`, `store/store.go`, and
`docs/ARCHITECTURE.md`. It is **not** a wholesale database or response-engine
import. The source includes confidence scores and MITRE tactic/technique
fields, but neither confidence nor edges themselves prove attribution or
the attacker kill chain. No threat actor names are inferred in this PR.

## Scope and what is deliberately not changed

- **Case-local indicator and graph records:** source/destination IP, reported
  host and rule signature extracted from already-authorized, normalized
  `defense_events`. No reverse DNS, web lookups, new remote scans, shell
  commands or log scraping.
- **Bounded cross-event correlation:** one existing alert event plus up to 49
  nearby events from the *same telemetry source* within ±15 minutes. Peers
  must match **source IP AND destination IP** or **source IP AND reported
  host**. One shared IP/ASN/port, a sensor signature alone, or two assets in
  an inventory are not sufficient to link incidents.
- **Evidence provenance:** every observation refers to an existing event ID,
  sensor source, external event ID, observation timestamp and link reason.
  Every observed indicator has its own event/role links. Graph relations have
  a source event backing them and are limited to **co-observed IP pairs**.
- **Confidence semantics:** 95/100 for the case's own anchor event, 55 for
  same-source/source+destination peers, and 50 for same-source/source+host
  peers. These are engineering estimates of **linkage**, not probabilities
  of attack, compromise or maliciousness. No automatic escalation relies on
  the numbers. An indicator deduplicated across linked events retains the
  highest linkage score, NOT a stronger threat verdict.
- **MITRE ATT&CK hypotheses:** the built-in `password_spray_v1` rule
  may produce a low-confidence suggestion of `T1110.003` (Password Spraying)
  under tactic `TA0006` (Credential Access). A human may add other
  technique/tactic IDs only with an existing case observation, a 12–1200-byte
  rationale and a confidence between 1 and 90. Syntax is validated, but this
  PR does **not** ship or fetch the full ATT&CK catalog; an arbitrary
  well-formed code is not guaranteed to correspond to a published technique.
- **Audited case updates:** opening a case creates a bounded correlation
  snapshot in the same transaction as the case/audit creation. Existing cases
  can be refreshed explicitly by an authenticated operator.
  Refresh is idempotent for observed evidence/edges, and the refresh
  action itself leaves an append-only audit record.
- **Incident timeline:** chronologically displays the latest 250 relevant
  stored sensor observations, analyst decisions, evidence refreshes and
  technique hypotheses. The sensor observation time and audit creation time
  use different clocks and are **not evidence of causation**.

Phase 6 does not modify the original asset/exploration graph or existing
offensive behavior in `ARTEX_MODE=pentest`. The SOC features are enabled only
in `ARTEX_MODE=defense`. It does not modify or consult the emergency
auto-containment source rule allowlist; no graph evidence or confidence number
can arm, dispatch or execute a firewall, EDR or identity change.

## Data model

Migration: `db/migrations/0017_defense_threat_correlation.sql`.

| Table | Purpose |
| --- | --- |
| `defense_case_observations` | Case/event link and bounded matching reason |
| `defense_case_indicators` | Case-scoped normalized observed IP/host/signature, first/last timestamps |
| `defense_indicator_evidence` | Every indicator ↔ source event and specific evidence role |
| `defense_case_relations` | Event-backed IP pair co-observation (NOT causation) |
| `defense_case_techniques` | Human/low-confidence-rule ATT&CK hypotheses with supporting event |
| `defense_case_intel_audit` | Append-only correlator/console change history |

All graph links are enforced through case-scoped composite foreign keys.
No arbitrary value can link an indicator from another case. Evidence, links,
techniques and audit updates occur transactionally; repeated refreshes
cannot create duplicate observed graph entities. Previous migrations remain
unchanged and the existing migration SHA-256 checking is preserved.
The append-only trigger prevents ordinary UPDATE and DELETE; privileged
database owners can still override it. This is **not cryptographically WORM**.

### Confidence vs. threat attribution

This is a **threat investigation graph**, not an automated threat-actor
attribution engine. A relationship such as `co_observed` means that two IP
values were present in one observed event; it does **not** mean that one IP
controls the other, that either host is compromised, or that traffic was
necessarily malicious. Imported historical IOC labels or scanner outputs
are not privileged compared with normalized evidence. Do not feed this
graph directly to the containment rule engine.

### Data minimization

Indicator extraction is limited to bounded IP literals, host labels and
upstream sensor signatures already in the existing event record. Arbitrary
metadata, raw logs, credentials, passwords, full event bodies and user/account
names are **not** materialized as indicators. Hostnames and signatures can
still carry sensitive information from source logs, so secure the existing
ARTEX database and dashboard; apply an appropriate retention policy before
operating on real production logs. This PR does not implement automatic data
purging or external STIX/TAXII feeds.

## APIs (authenticated, defense-mode-only)

| Method | Route | Function |
| --- | --- | --- |
| `POST` | `/api/defense/cases/{id}/intelligence/refresh` | Recompute a bounded case snapshot from *existing* events |
| `GET` | `/api/defense/cases/{id}/intelligence` | Read indicator inventory, provenance, co-observation edges, hypotheses |
| `POST` | `/api/defense/cases/{id}/intelligence/techniques` | Add an audited analyst ATT&CK hypothesis |
| `GET` | `/api/defense/cases/{id}/timeline` | Read chronological incident record with source timestamps |
| `GET` | `/api/defense/cases/{id}/graph` | Existing evidence graph, extended with indicator and ATT&CK nodes |

Example analyst mapping payload (requires an active case and previously linked
event ID):

```json
{
  "technique_id": "T1110.003",
  "tactic_id": "TA0006",
  "event_id": 42,
  "confidence": 45,
  "reason": "Repeated account failures were recorded; confirm against authoritative identity provider logs."
}
```

The response reports `verified_compromise: false` and `execution: false`;
mapping is not an approval for a firewall or credential change. All incoming
JSON uses the existing 4 KiB bounded decoder with unknown fields rejected.

## Dashboard

From **Functions → Defense → Cases & Approvals**, choose any case and
**Threat intelligence & timeline**. The detail page is the static-export
compatible route `/function/defense/intelligence?case=<id>` and shows:

1. Event-linked indicators with per-event provenance and first/last seen.
2. Co-observation relationships with exact backing event IDs.
3. Suggested/analyst ATT&CK mappings labeled as hypotheses.
4. Read-only chronological incident timeline with observed and audit times.
5. A case-evidence graph inspector retaining the original case, alert,
   asset, response and audit nodes alongside the new indicator/technique nodes.

**Refresh evidence correlation** explicitly collects only rows already
present in ARTEX's database. It does not start a sensor, widen scope,
trigger an agent or change emergency containment rules.

## Tests and safe rollout

```bash
go test ./defense
go test ./server -run 'TestThreatCorrelation|TestIndicatorCrossCase|TestCorrelationRead|TestIntelligenceEndpoints'
go build ./...
cd web && npm ci && npx tsc --noEmit
```

The dedicated PR workflow uses PostgreSQL for migration, idempotence,
cross-case FK rejection, append-only audit and source/endpoint matching
tests. Verify general ARTEX CI separately. Use synthetic test events,
check chronology with out-of-order sensor timestamps, and confirm
`ARTEX_MODE=pentest` returns 404 for all new routes.

**Operational limitations:** 50-event refresh cap and 250-item read limits,
case-scoped rather than global attribution, no automatic backfill of older
cases except explicit refresh, no external ATT&CK taxonomy verification,
no independent sensor attestation, no full visual graph layout engine, and
no measured production data-retention or query-load budget. Incident
analysts must still validate hypotheses and infrastructure ownership
before taking any external action.

Upstream/source attribution and ARTEX AGPL-3.0 remain preserved.
