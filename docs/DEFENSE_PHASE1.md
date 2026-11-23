# ARTEX Defense — Phase 1 (opt-in preview)

Phase 1 adds **passive, evidence-first exposure triage** while preserving the
original penetration-testing behavior when the raw binary is run with
`ARTEX_MODE` unset, or when an operator explicitly opts into `pentest`.
The fork's packaged installers and Compose examples now default to `defense`.
This is an experimental analyst workflow, **not** a SIEM, firewall, EDR, or
production-ready containment engine.

## Enable

1. Clone this fork and copy `.env.example` to `.env`. Verify
   `ARTEX_MODE=defense` and `ARTEX_AUTO_CONTAIN_MODE=off`.
2. Set a strong `POSTGRES_PASSWORD`; configure an LLM in the UI or by env.
3. Run `docker compose up -d --build`, then open the local web UI. Use the
   one-time setup token shown in `docker compose logs artex`.
4. Authenticate and inspect `GET /api/health`: it includes `mode: defense`
   for an authenticated caller. Unauthenticated health remains minimal.

## What Phase 1 does

- Enforces a **fail-closed allowlist** in the agent `PreToolUse` guard,
  including the planner and main-agent target-only guard. The check precedes
  the optional/user-configured interception rules.
- Denies Bash, interactive shell, network fetch/search, arbitrary code,
  custom/MCP tools, credential reads, scope widening, and unknown tool names.
  Unrecognized `ARTEX_MODE` fails startup validation and tool policy.
- Appends defensive operating instructions to the rendered agent prompts after
  database prompt overrides. Prompts are **guidance only**; the Go guard is
  the operative policy.
- Disables automatic asset enrichment that would initiate DNS/HTTP lookups.
- Adds `assess_exposure(ids=[...])` to analyst toolsets. First retrieve existing
  assets via `list_assets`, then request an assessment of 1–50 specific IDs.
  Results flag administrative/database ports and recorded plain-HTTP URLs as
  **review candidates**. They neither measure Internet reachability nor
  establish vulnerability or compromise. The tool uses scope-filtered database
  reads; it never initiates a network request.

## Recommended workflow

1. Import or review an **authorized** asset inventory using existing admin UI
   or APIs. Agent-driven scope expansion and active enrichment are disabled.
2. Start a task describing an exposure-review goal and explicit existing assets.
3. Ask the analyst to use `list_assets` to identify recorded assets and
   `assess_exposure` for metadata-only prioritization.
4. Correlate review candidates with existing evidence-backed findings.
5. Produce a remediation report identifying observations, unverified hypotheses,
   missing evidence, owners, priority, and operator validation steps.

The graph, task engine, stored findings, evidence and UI remain intact.

## Important limitations and threat model

This Phase 1 guard applies to **agent tool execution**. It is not a global
outbound firewall or a replacement for authentication, data access policies,
container isolation, or network segmentation. Operator/admin APIs and other
non-agent runtime paths may still perform their existing operations; do not
expose this preview to untrusted operators or treat it as an OT-safe enforcement
system. The standalone traffic proxy and administrative features are not
comprehensively disabled in this phase. Existing archived evidence may contain
sensitive data; follow least-privilege and retention procedures.

Keep the service bound to localhost or a controlled reverse proxy. Run in an
isolated environment without unrestricted egress when evaluating sensitive
systems. No automatic network blocking, remediation, or incident response has
been implemented. Human-approved response and telemetry ingestion are later
phases.

## Validation

```bash
go test ./defense ./guard
go test ./agent ./server
./scripts/verify.sh --go-only
```

Suggested integration checks:
- Run the raw Go binary with no `ARTEX_MODE`: legacy penetration-testing mode remains available;
  packaged Compose/installer defaults are intentionally different.
- Run with `ARTEX_MODE=defense`: Bash, WebFetch, shell, MCP and unknown tool
  calls fail in both worker and planner/main-agent paths.
- Confirm `assess_exposure` returns metadata-only assessments for existing
  scoped assets and no confirmed vulnerability claims.
- Confirm passive mode does not schedule DNS/HTTP asset-enrichment probes.
- Try invalid `ARTEX_MODE`: startup must fail before the HTTP server starts.

This branch preserves third-party AGPL-3.0 licensing and upstream attribution.
