# PR #11 — Cross-Sensor Correlation and Company-Scoped Evidence

## Security boundary

**ARTEX-DEFENSE is still a single-administrator platform.** Company-scoped
evidence **does not provide tenant-user RBAC, PostgreSQL row-level security,
multi-tenant hosting, or independent customer access**. An authenticated
administrator can inspect every company's events. These changes prevent
the *correlation engine* from linking events and inventory across company
assignments. Do not market this phase as a multi-tenant SaaS isolation layer.

In the existing asset inventory, a single `assets.ip` value is globally unique.
That database model does **not** support separate copies of identical private
IP addresses in two company inventories; isolating overlapping RFC1918
networks will require a separate future asset-schema change.

## Company enrollment

1. Create or select the appropriate company in the existing inventory.
   Record its numeric `companies.id` using your authorized administrator
   session (do not guess a name-to-ID mapping).
2. When provisioning a **new** collector, include `company_id`:

```bash
curl -fsS https://private-soc.example/api/defense/collectors \
  -H "Authorization: Bearer $ARTEX_ADMIN_JWT" \
  -H 'Content-Type: application/json' \
  --data '{"name":"dmz-suricata-01","source":"suricata","company_id":42}'
```

3. PR #10 collectors already enrolled before this migration are **unassigned**.
   Their credential remains valid but ingestion now returns **409** until an
   admin binds them to an existing company. Bind once:

```bash
curl -fsS https://private-soc.example/api/defense/collectors/123/scope \
  -H "Authorization: Bearer $ARTEX_ADMIN_JWT" \
  -H 'Content-Type: application/json' --data '{"company_id":42}'
```

The binding is **permanent**: to change a collector's company, revoke its
credential and create a new collector identity. New tokens cannot select or
override a company by HTTP payload or query string. The company assignment
is read from PostgreSQL after credential validation, and is rechecked under
the ingestion transaction lock so concurrent scope changes cannot race a
queued batch. One-way binds are recorded in `defense_collector_audit`.

## Evidence collection and asset linkage

- `defense_events.company_id` is assigned from the enrolled collector; the
  request body **cannot** override it. The database trigger independently
  rejects a collector/company mismatch, including direct SQL imports.
- IP/hostname-to-asset linking always includes
  `assets.company_id = defense_events.company_id`. It never matches globally.
- Event IDs remain deduplicated per collector, as introduced in PR #10.
- Existing events and alerts are **not retroactively attributed** using IP
  addresses, existing JSON links, or current collector bindings. An unknown
  company remains `NULL`.
- Legacy operator-only `POST /api/defense/events` can optionally include
  `"company_id":42` in its JSON envelope, but requires an **admin JWT**.
  If no company is supplied, it remains unscoped, has no new asset links,
  and is not eligible for automatic containment.
- Event/alert list APIs accept optional `?company_id=42` **for admin filtering**.
  Responses include `company_id` and `collector_id` provenance. Historical
  unscoped events' legacy `asset_ids` are omitted from the API output as
  unverified, and case graph rendering omits such asset links.
- Legacy **already-stored** case observations are retained for audit, but
  observation/indicator/timeline read paths filter evidence by the anchor
  alert's company scope to avoid displaying mismatched old links.

## Bounded independent-sensor correlation

The deterministic case correlator examines the alert anchor and at most 49
matching nearby events in the **±15-minute** event-time window. A peer is
eligible only when:

- It has the **same explicit company ID** as the anchor, and
- Both **source IP and destination IP**, or both **source IP and reported host**
  match (a shared IP or signature alone is insufficient), and
- It comes from the same collector/vendor as before, **or**, for genuine
  independent-source review, from a **different enrolled collector ID** with
  both collectors assigned to that same company.

The new `independent_collector_endpoints` and
`independent_collector_host_ip` reasons use conservative linkage confidence
values of 60 and 55. Those values describe a *heuristic evidence link*, **not
the probability of compromise**. Multiple sensors can still share an upstream
feed or common misconfiguration: distinct credentials do not guarantee
independent physical observations. Legacy events with unknown company remain anchor-only when refreshing a
case: matching IP addresses cannot establish ownership, even within one vendor.

Nothing in this path performs network lookups, executes tools, changes firewall
policy, upgrades incident severity, or grants autonomous response permissions.
**Collector-origin events remain ineligible for auto-containment** (PR #10).

## Database protections and upgrade sequence

The additive checksum-protected migration
`db/migrations/0021_defense_tenant_correlation.sql` adds:

- Company assignments for collectors and immutable event provenance;
- Company/time and IP/hostname indexes for bounded investigation;
- New case observation link reasons;
- Insert-time SQL guards against cross-company event/collector mislabeling
  and cross-company case observations;
- Audited one-way binding of existing unassigned collectors.

Apply migrations at server startup, stop old collectors during rollout,
bind each verified existing collector to the correct company, and restart its
forwarder. Take an encrypted backup before upgrading. A mistake in company
enrollment must be fixed with a new collector identity, not by rewriting
historical event ownership. The migration does not repair old incorrect links.

## Validation

```bash
go test -count=1 ./server -run 'Test(DefenseTenant|DefenseCrossSensor|Collector|ThreatCorrelation|DecodeDefenseCompany)'
go test -p 1 ./...
```

Run staging fixtures covering two companies with overlapping indicators,
collector revocation, cross-company SQL insertion, missing company scope,
cross-vendor two-field matching, duplicate retries and ambiguous private IP
ownership before allowing any production sensor traffic.
