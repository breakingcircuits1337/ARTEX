# Phase 15 — AI Egress Preview, Evidence Integrity & Safety Evaluation

PR #15 builds on merged PR #14. It strengthens the **operator-consented,
read-only AI advisory** workflow without granting the model any additional
capability. The deterministic Phase 7 investigator and emergency response
engine remain independent and unchanged.

## Operator-visible evidence egress preview

The case investigation page now requires these steps before each AI call:

1. Click **Preview exact redacted evidence**. This is an authenticated
   read-only GET. It does **not** call the configured AI provider or write a
   reservation/audit record.
2. Inspect the full `artex-redacted-evidence-v1` JSON packet displayed in
   the page: sensor source/observation category/linkage type, severity,
   numeric linkage confidence, fixed uncertainty text, and sequential
   `evN` references. The server excludes company and collector IDs,
   event/case IDs, IPs, usernames, hostnames, signatures, raw logs and
   analyst free-text from the model packet.
3. Consent to transmitting **that packet** to the configured provider,
   which may be remote and subject to the provider's retention policy.
4. Confirm the per-call review, including the packet digest displayed in
   the UI. The server independently rebuilds the packet before any model
   call. A mismatch returns HTTP 409, with **no provider request**.

### Exact API contract

| Method | Route | Behavior |
| --- | --- | --- |
| `GET` | `/api/defense/cases/{id}/ai-reviews/preview` | Returns `packet`, `packet_sha256`, `no_model_call: true`, `requires_fresh_consent: true`, and model-configuration status |
| `POST` | `/api/defense/cases/{id}/ai-reviews` | Requires `consent_to_model: true` AND `reviewed_packet_sha256` matching the current versioned packet |
| `GET` | `/api/defense/cases/{id}/ai-reviews` | Existing historical advisory list, unchanged |
| `POST` | `/api/defense/ai-reviews/{id}/decision` | Existing append-only human verdict, unchanged |

All endpoints use the existing admin JWT and defense-only route gate.
The new preview also requires `ARTEX_DEFENSE_AI_ASSIST_ENABLED=1`.
Collector credentials and anonymous callers are rejected. Cookies retain
the existing CSRF/origin controls for the model POST. Output is
`Cache-Control: no-store`.

**This POST schema intentionally supersedes Phase 14:** old clients sending
only `consent_to_model: true` receive HTTP 400 and make no model request.
The response on success includes the verified `packet_sha256`, which
already has a matching digest in the Phase 14 run record. No new migration
or data-retention table is required.

Example authorized request shape (use a digest actually received from
the GET preview; the value here is deliberately invalid):

```json
{
  "consent_to_model": true,
  "reviewed_packet_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

### Integrity boundary and limitations

The SHA-256 digest binds the authorization to the **exact categorical
JSON bytes the AI will see**, using the same server marshal path for GET
and POST. The server compares digests before reserving a run, and then
saves the same digest in the existing append-only review record.

The digest is **not a signature, secret or proof of operator identity**;
an authorized API client can automate fetching a preview and POSTing
its digest. There is no one-time nonce or expiration time. The browser
clears its checkbox/preview after each attempt, but server-side
rate limits remain the actual enforcement on repeated requests.

**Very important:** raw source event fields are *intentionally excluded*
from the privacy-preserving packet. Changes to excluded raw fields do
not change the digest. Only changes to the redacted, projected
categorical facts or ordering produce a new digest. Case status is
checked separately before provider egress and during persistence.

There is no claim of independent sensor integrity, full audit
attestation, model/provider identity proof, perfect prompt-injection
resistance, or cryptographic evidence provenance.

## Deterministic output quality evaluation

After the existing strict JSON decoder and evidence-citation validation,
a second fail-closed gate rejects some common unsafe LLM output forms:

- Summaries missing the explicit word `unverified`.
- IPv4-literal addresses and email-like identifiers hallucinated into
  summary or explanation text. The input packet contains neither.
- Several direct operational-command or enforcement terms such as
  block, isolate, delete, execute, sudo, nftables, and patterns
  indicating requests to run commands.
- Unsupported certainty phrases such as confirmed breach, confirmed
  compromise or known attacker.
- `corroboration` findings that cite only the alert anchor or have
  no additional case-linked observation. A second event is a minimal
  structural requirement, **not independent confirmation**.

Rejected model output gets the existing `invalid_output` failure code
and cannot be stored as approved advice. It is **not** forwarded to a
firewall or response adapter. The model remains no-tool, one-turn,
timeout-limited and subject to the Phase 14 per-case/global budgets.

This is deliberately a **limited lexical and structural safety gate**.
Models can evade these patterns through euphemisms, spelling changes,
different languages or misleading yet valid statements. Some benign
quotations/negations can be rejected (false positives). Such requests
fail closed and can be retried only with a fresh preview and consent;
there is no automatic retry or removal of human review.

### Offline evaluation set

`defense/ai_safety_test.go` runs seeded benign vs. malicious
model-response variants, including command suggestions, invented
addresses, impersonated attribution, unsupported verdicts and
anchor-only corroboration. It also includes an in-process fuzz entry
point. These tests use fixed synthetic strings; **they never
contact an LLM or execute commands**.

`server/defense_ai_advisory_test.go` tests the actual PostgreSQL
boundary: no preflight writes, no provider call for missing/forged
digests, rejection after severity changes, valid fresh request with
matching persisted digest, and 401/403/404 gates. The old consent,
provider failure, quota, immutability and company-scope tests also
run under the revised POST contract.

## Operator rollout and rollback

1. Deploy server and static UI **together**, because the POST
   schema has changed. No migration is needed.
2. Keep `ARTEX_DEFENSE_AI_ASSIST_ENABLED` **disabled by default**.
   Enable only after evaluating the configured provider's handling
   of redacted operational data and any LLM request recording.
3. In a staging case, preview then inspect the exact payload;
   verify that no AI request or new run is written from the GET.
4. In the same case, send an incorrect digest and verify 409 and no
   model request. Change projected severity/linkage and verify the
   previous digest becomes stale.
5. Send a fresh digest and explicitly approve a model call.
   Review the stored digest and cited original case evidence.
6. Try a model fixture containing a fabricated IP, a command
   instruction or confirmed-attribution claim. Verify 502,
   `invalid_output` and no findings/containment action.
7. Verify existing no-tool model behavior and immutable human
   verdicts in a private staging environment.
8. To halt further model egress, unset the feature flag and
   restart the server. The preview and POST both return 403.
   Existing advisory records remain viewable.

```bash
go test -count=1 ./defense ./server -run 'TestAI'
go test -count=1 ./db -run 'TestOpenMigratesFreshDatabase'
go build ./...
go vet ./...
cd web && npm ci && npx tsc --noEmit && npm run build:static
```

A dedicated PR #15 GitHub Actions workflow runs these checks against
PostgreSQL 16 plus the frontend build. The broad repository CI covers
other collectors, SOC, Sigma, emergency and deterministic investigation
regression suites.

**Safety boundary:** Output validation improves *quality control*, not
truthfulness or incident attribution; even passing outputs remain
unverified, subject to source-evidence review, and never authorize
response, scanning, shell execution or OT intervention.
