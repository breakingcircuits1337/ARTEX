# PR #14 — AI-Assisted Defensive Investigation (Human-Governed)

**Status:** Optional, **disabled by default**. Read-only to all enforcement,
case adjudication, account systems, network devices and detection policies.

PR #14 adds a separate *operator-requested* AI advisory panel alongside the
existing deterministic Phase 7 investigator. It does **not** modify the
deterministic investigation worker, auto-intake, case status, ATT&CK mapping
logic, emergency response eligibility, auto-containment, firewall
configuration, arbitrary agent tools or collector scope.

## Enablement and data egress

An operator must intentionally set `ARTEX_MODE=defense` and
`ARTEX_DEFENSE_AI_ASSIST_ENABLED=1` in the backend environment, configure
an existing ARTEX LLM provider, and explicitly consent **for each call**.
There is no background AI worker, silent retry, scheduler or automated LLM
call on page load. The UI consent checkbox always resets after each request.
The backend independently rejects requests missing
`{"consent_to_model":true}`.

**Important privacy limitation:** The provider can be external. The approved
metadata packet (below) leaves the server via the existing configured
model provider, which may retain inputs/outputs under its own terms.
ARTEX's existing LLM recording hooks may also retain model transactions.
Use a private/local model (e.g. operator-managed Ollama) or disable the
feature for environments in which **even categorical operational metadata
must not leave the trust boundary**. The operator must independently
evaluate data residency, logging, retention, regulated environments,
incident evidence handling and any model-provider agreement.

### Data sent to the model

Only a versioned, size-limited JSON object with:

- `schema: "artex-redacted-evidence-v1"`
- `alert_severity` from the database's fixed severity enum
- Up to 12 case-scoped evidence records with ephemeral sequential
  `ref: ev1` etc, normalized `source` and `kind` enums, reviewed
  `relation` link kind, and a numeric **linkage confidence**
- A fixed uncertainty notice: linkage confidence is **not** compromise
  probability.

**Never supplied**: raw logs/payloads, IP addresses, hostnames,
usernames, signatures, sensor-free-text messages, tokens, API keys,
case identifiers, event IDs, company/collector IDs, file contents,
ATT&CK user-authored rationale or process command lines.

These categorical facts **can still be sensitive**, e.g. they reveal
that a classified sensor event exists. Treat the model call as an
explicit data egress and apply organizational policy before enabling.

### LLM execution

The server uses the existing configured shared LLM provider and
`agentcore.Run` with `MaxTurns=1`, `MaxTokens=2048`, and an **explicit
empty tool list**. This is critical: in the underlying SDK, `nil` tools
may enable default shell/file capabilities. This call cannot use
the scanner, shell, browser, agent tool bus, emergency action adapters
or application database writes. A configured model connection is
the only intended external operation.

Each call has a 35-second deadline; two minutes after a crashed call,
the next manual request can reclaim the expired reservation with
an append-only failure audit. No automatic retry or model fallback
that replays telemetry was added in this PR; however, if an existing
configured provider uses provider-level failover, your organization's
selected providers and logging arrangements must be reviewed.

## Advisory validation

The model must return one JSON object with:

```json
{
  "summary": "Unverified incident evidence requires independent confirmation.",
  "findings": [
    {
      "evidence_ref": "ev1",
      "category": "verification_gap",
      "explanation": "Check whether the sensor observation was authorized maintenance."
    }
  ]
}
```

Only 1–3 findings are accepted, each limited to 18–400 characters.
Categories: `verification_gap`, `corroboration`,
`alternative_explanation`. Summary: 18–500 characters.

Parser behavior is **fail-closed**: rejects non-JSON, extraneous or
duplicated JSON keys, extra output objects, unsupported attributes,
unknown evidence refs, invalid categories, unsupported markup, control
characters, URLs, repeated ref/category pairs and oversized output.
Each accepted `evN` reference maps **only** to an event already
linked to that case and company. For legacy unscoped cases, only
the alert-anchor event can be cited. PostgreSQL checks the
case-evidence foreign key and rejects cross-company evidence
**even on direct SQL insert**. Cited events and AI interpretations
are still **unverified**.

A hash of the exact versioned redacted packet, the model request time,
completion status and fixed audit event codes are stored, not raw
provider errors or original model output. The accepted summary and
individual findings are stored for review. Findings cannot be
edited/deleted (append-only trigger), and AI suggestions are **not**
written into the deterministic investigator's findings table.

### Human verdict

An administrator can record one immutable verdict per AI finding:

- `supported` — a reviewer considers it worth further investigation;
- `refuted` — reviewer disagrees with it;
- `needs_more_evidence` — evidence is insufficient.

A 12+ character reason is required. A supported verdict **never**
confirms maliciousness, modifies an incident's verified status,
maps ATT&CK techniques or authorizes a response. The audit contains
a fixed `human_verdict` code. Every analyst must consult the original
case evidence in the SOC before making a decision.

## APIs

| Method | Route | Behavior |
| --- | --- | --- |
| GET | `/api/defense/cases/{id}/ai-reviews` | Read-only case-specific review status and cited findings |
| POST | `/api/defense/cases/{id}/ai-reviews` | Create ONE consented model request; provider egress |
| POST | `/api/defense/ai-reviews/{id}/decision` | Immutable human verdict and audit |

All require a valid ARTEX admin JWT, cookie-origin CSRF enforcement
for writes, and `ARTEX_MODE=defense`. Collector credentials are
limited to ingestion and **cannot** use these routes.
No anonymous model access. The POST is disabled unless the operator
has enabled the environment flag. Read-only access to historical
advice remains available if the feature is subsequently disabled.

A process-wide serial reservation checks a **global 12-request/hour
budget** and a **3-request/case/hour** budget, preventing concurrent
per-case LLM calls across server instances sharing PostgreSQL.
Provider errors and ungrounded output are marked failed and visible
to the operator, without storing raw model/provider error strings.
These are abuse/cost guardrails, not guaranteed global token limits.

## Operations, verification and rollback

1. Apply additive migration `0024_defense_ai_advisory.sql`; back up the
   DB before production rollout. Existing migration checksums unchanged.
2. Leave `ARTEX_DEFENSE_AI_ASSIST_ENABLED` **unset** until policy
   and evidence-egress review are complete.
3. In staging, configure an operator-owned local model first. Confirm
   GET works without any model request and POST is rejected with
   **403** while the feature flag is disabled.
4. Enable the feature, open an *active* case with refreshed correlation,
   check the consent box, and confirm a human model request.
5. Verify the returned advice has citations that resolve to events
   in the case; inspect original evidence separately.
6. Enter a human rationale and choose a verdict. Reattempting the
   same verdict or deleting the original should be refused.
7. Review `defense_ai_review_runs`, `defense_ai_review_audit` and
   `defense_ai_review_decisions` for completed/failed/reviewed records.
8. Verify **zero changes** to `defense_emergency_actions`,
   `defense_case_techniques`, case status and deterministic findings.
9. For emergency disable, unset the environment flag and restart
   the backend. Pending model requests on the old process should
   be drained via normal process shutdown. The schema is additive;
   do not delete the audit or original human verdicts on rollback.

```bash
go test -count=1 ./defense -run TestAI
go test -count=1 ./server -run TestAI
go test -count=1 ./db -run TestOpenMigratesFreshDatabase
go build ./...
go vet ./...
cd web && npm ci && npx tsc --noEmit && npm run build:static
```

The GitHub Actions fixture uses a **fake model callback** and
synthetic PostgreSQL evidence; it never contacts a paid AI provider.
Only real deployments configured by an operator can trigger egress.

## Non-goals and remaining risks

This is *not* autonomous response, incident attribution, verified
compromise detection, model correctness certification, safety-rated
OT automation, multi-tenant user RBAC, encrypted evidence vault,
complete prompt-injection defense, provider attestation, model-specific
data residency enforcement, or separate low-privilege inference service.
No model can prove its own hallucinations impossible; the validation
layer checks structural linkage and human workflows, not the truth of
the generated explanation. Protect admin tokens, evaluate privacy,
operate on a private network and require independent analyst review.
