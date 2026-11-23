# ARTEX Defense — Phase 3: case triage, approval and audit

Phase 3 extends the merged Phase 1/2 defensive preview into an operator-owned
incident investigation and **manual-only response review workflow**.

**This phase DOES NOT execute containment**. An approval authorizes a human
review plan within ARTEX, **not** an endpoint isolation, firewall rule, account
disablement, network block, shell command or third-party API request.
`simulate` produces the recorded plan description and always reports
`executed: false`. External change control, asset ownership, rollback and
independent safety signoff are mandatory before any real infrastructure change.

## Enable and access

Use the Phase 3 branch in a controlled environment with `ARTEX_MODE=defense`.
The existing ARTEX JWT and same-origin cookie CSRF checks protect the new API.
Only an authenticated ARTEX console operator can create, approve, reject,
simulate or close cases. The current ARTEX auth model has **one admin role**,
so this is not two-person approval; do not claim separation of duties.

The additive migration `db/migrations/0015_defense_response_workflows.sql`
is applied after Phase 2 migration 0014 and adds:

- `defense_cases`: one durable incident case per source alert.
- `defense_response_requests`: four hard-coded, nonexecutable playbooks,
  approval status, supporting rationale, decision and simulation timestamps.
- `defense_case_audit`: append-only timestamped console-admin decision records.
  Each case/response mutation writes its audit record in the same transaction.
  A database trigger rejects UPDATE and DELETE, but database administrators
  can override the trigger; this is **not cryptographic WORM storage**.

Open **Functions → Response Review** or visit
`/function/defense/cases`. The SOC page links to the same interface.

## Workflow

1. Ingest alerts using Phase 2 Suricata/Wazuh/generic collectors.
2. **Open case** from a known alert. Opening is idempotent by alert ID, and
   retains the alert's original event and recorded asset IDs.
3. **Triage** from `open` → `investigating` (or `dismissed`), then from
   `investigating` → `resolved` or `dismissed`. Each decision requires a
   12–1200 byte operator justification. Terminal states cannot be reopened.
4. **Propose** one of the reviewed manual response playbooks on an active case.
   The plan is `pending` until a human explicitly approves or rejects it.
5. **Approve/reject** with recorded rationale. Approval never calls any
   external API and never automatically advances to simulated.
6. **Simulate** a previously approved plan using a separate explicit action.
   Simulation logs the operation as `simulated`, returns the safe plan and
   `executed: false`; no live intervention occurs.
7. Review **Audit trail** and **Evidence graph**. The graph links a case to its
   source alert/event, existing inventory IDs, response proposals and audit
   entries. This is **evidence lineage**, not a proven causal intrusion graph.
8. Close the case once no requests remain `pending` or `approved`. The
   case closes as `resolved` or `dismissed`, subject to the state machine.

### Available fixed playbooks

| ID | Impact caution | Scope |
| --- | --- | --- |
| `collect_additional_evidence` | Low | Request authorized existing logs, verify source event and hypotheses |
| `review_network_block` | High | Assess potential firewall change, dependencies, rollback and approval |
| `review_identity_controls` | High | Assess account actions and impact to legitimate users/services |
| `review_endpoint_isolation` | Critical | Require asset/safety-owner signoff, especially for OT endpoints |

Each playbook contains static, reviewable human instructions. User-supplied
commands, target URLs, executable scripts, API adapters, remote actions,
automated blocking and arbitrary tool names are **not** accepted.

## API

All endpoints require ARTEX authentication and `ARTEX_MODE=defense`.
Authenticated operators may use bearer tokens or same-origin cookie sessions.
The `POST` endpoints enforce JSON bodies <=4 KiB and reject unknown fields.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/defense/playbooks` | Enumerate reviewed manual plans |
| GET | `/api/defense/cases?limit=50` | Review incidents and source alert/event IDs |
| POST | `/api/defense/cases` | `{"alert_id":123}`, idempotent |
| POST | `/api/defense/cases/{id}/triage` | `{"status":"investigating","reason":"…"}` |
| GET | `/api/defense/cases/{id}/audit` | Read append-only audit trail |
| GET | `/api/defense/cases/{id}/graph` | Read case/alert/event/asset/approval edges |
| GET | `/api/defense/responses?limit=50` | Review operator proposal queue |
| POST | `/api/defense/cases/{id}/responses` | `{"playbook":"collect_additional_evidence","justification":"…"}` |
| POST | `/api/defense/responses/{id}/decision` | `{"decision":"approve","reason":"…"}` or reject |
| POST | `/api/defense/responses/{id}/simulate` | Approved plan → recorded preview only |

State changes on missing objects return 404, invalid transitions 409,
invalid input 400, and database failures 503. These endpoints are not
accessible in `ARTEX_MODE=pentest`.

### Example with a console session token

```bash
# Never expose session JWT to untrusted forwarders, shells or public hosts.
curl -fsS http://127.0.0.1:8787/api/defense/playbooks \
  -H "Authorization: Bearer $ARTEX_JWT"

curl -fsS http://127.0.0.1:8787/api/defense/cases \
  -H "Authorization: Bearer $ARTEX_JWT" \
  -H "Content-Type: application/json" \
  --data '{"alert_id":123}'
```

The web UI includes reason fields and explicit confirmation for each
human decision. The case/response database is persistent across restarts.

## Safety, limitations and next stage

- No live response adapter exists: **approved** means reviewed, never executed.
- Every change requires an authenticated operator and is linked to a case.
- The audit actor is `console-admin` because ARTEX currently has one
  administrator, not per-user identities. Stronger role separation, scoped
  collector credentials and two-person approval remain future work.
- Phase 3 inherits Phase 1's documented limitations on non-agent administrative
  API paths, traffic capture and host-wide network egress enforcement.
- Case graph asset links reflect stored ingestion-time matches; they may be
  incomplete/stale and do not prove reachability or compromise.
- Action plans are **not safe to execute merely because they were approved in
  ARTEX**. In safety-critical/OT environments, require independent site safety
  authorization, impact review and tested restoration procedures.

## Validation and merge gate

```bash
go test ./defense ./server
go test -p 1 ./...
./scripts/verify.sh
```

Review the additive migration on a disposable PostgreSQL database, the
JWT/CSRF gate, concurrent approval behavior and audit immutability.
Ensure `main` continues to operate in `pentest` mode unchanged.
CI and a controlled deployment smoke test are required before merging.

AGPL-3.0 and upstream attribution remain intact.
