# PR #12 — Expanded Detection Coverage, ATT&CK Review and Sigma-Compatible Rules

**Scope:** deterministic, auditable, alert-only telemetry detection. No active
scanning, external network calls, automatic rule deployment, LLM rule
evaluation, shell commands, firewall changes or automatic containment.

## What is (and is not) Sigma-compatible

The repository includes a **fixed, code-reviewed YAML artifact**:
`detectionpack/sigma/artex-normalized.yml`. The format follows the Sigma
rule structure (`title`, `id`, `description`, `logsource`,
`detection.selection`, `detection.condition`, `falsepositives`,
`level` and `tags`). ARTEX implements a **restricted execution subset**:

- Only `logsource.category: artex_normalized` and
  `product: artex-defense`; the engine matches ARTEX's bounded normalized
  fields **after** Suricata/Wazuh/OCSF/generic input normalization.
- `detection.condition: selection` only. All selection map fields are AND,
  list values for one field are OR. Supported modifiers:
  unmodified equality, `|contains`, `|startswith`, `|endswith`.
- Supported normalized fields: `source`, `kind`, `outcome`, `action`,
  `signature`, `host`, `username`, `src_ip`, `dst_ip`.
- Case-insensitive string comparisons. The engine **rejects** wildcards,
  regexes, unknown fields and modifiers, aliases, duplicates, unsafe
  severities, unsupported conditions, extra documents and unknown keys.
  It is *not* a general Sigma engine, a SigmaHQ-compatible backend, full
  schema compliance or a universal conversion pipeline.
- Four static rules with UUIDs; no external rule loading, hot reload or
  user-upload API. Rule validation is fail-closed and executed before
  serving the detection-pack catalog and before committing ingestion.
- `x_artex` metadata records the local false-positive review, alert-only
  disposition and non-enforcement policy. Do not mistake it for upstream
  Sigma syntax that every Sigma parser implements.

## Reviewed rule inventory

| Event action / predicate | ATT&CK Enterprise technique | Tactic | Severity |
| --- | --- | --- | --- |
| Endpoint reports `security_agent_disabled` or `edr_service_stopped` | [T1685: Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/) | [TA0112: Defense Impairment](https://attack.mitre.org/tactics/TA0112/) | Medium |
| Endpoint reports `powershell_encoded_command` | [T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001/) | [TA0002: Execution](https://attack.mitre.org/tactics/TA0002/) | Medium |
| Network event reports `dns_tunnel_suspected` | [T1071.004: DNS](https://attack.mitre.org/techniques/T1071/004/) | [TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011/) | Medium |
| Endpoint reports `credential_dump_reported` | [T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003/) | [TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006/) | Medium |
| Eight authentication failures for one account/source IP within ten minutes | [T1110.001: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) | TA0006 | Medium |
| Existing five-account failures from one source IP within ten minutes | [T1110.003: Password Spraying](https://attack.mitre.org/techniques/T1110/003/) | TA0006 | Medium |

**ATT&CK verification:** This curated allowlist was reviewed against MITRE
ATT&CK Enterprise on **2026-11-23**. The 2026 ATT&CK taxonomy names
`T1685 / TA0112` for tool tampering; do not silently substitute the
older `T1562.001` mapping. The pack rejects tags outside the reviewed
technique/tactic pairs. Technique identifiers can evolve—re-review at each
version update. All built-in mappings become **low-confidence rule hints
(35)** for an existing, evidence-backed case, *never confirmation that an
ATT&CK behavior occurred*. A user-authored hypothesis has separate validation
and review requirements.

## Password guessing versus password spraying

The previously shipped `password_spray_v1` checks failures for five distinct
account names from one source IP within ten minutes. The new
`auth_guess_burst_v1` instead requires **eight distinct persisted failure
events for the same case-insensitive account and source IP** in the preceding
ten minutes. It does not merge evidence from other sensors or companies.
It requires explicitly assigned `company_id`; legacy unscoped events do not
count. Alert deduplication uses a ten-minute event-time bucket and an
account-derived digest (not the raw account name) in the correlation key.
It is deliberately heuristic and may report mistyped passwords, scheduled
services, misconfigured authentication and approved security exercises.
Events must be deduplicated before counting. The PostgreSQL migration
`0022_defense_auth_guess_burst.sql` adds an indexed review window.

## Operator workflow

Authenticated administrator APIs:

```text
GET /api/defense/detection-pack
GET /api/defense/detection-pack/sigma
```

The first returns a read-only `sigma_catalog`, explicit compatibility
limitations and the fixed download path. The second returns the vetted YAML.
**No endpoint installs, activates or modifies rules on sensors.**

For illustration, an *authorized administrator* with an existing verified
company 42 can post a normalized generic batch to the legacy admin path:

```json
{
  "source": "generic",
  "company_id": 42,
  "events": [
    {
      "event_id": "example-123",
      "kind": "endpoint",
      "action": "security_agent_disabled",
      "timestamp": "2026-11-23T12:00:00Z"
    }
  ]
}
```

A remotely enrolled collector must instead use its **PR #10 per-device
credential**, be bound to the correct **PR #11 company**, and **must not**
include `company_id` in the posted envelope. ARTEX derives that scope
from the authenticated database identity. This feature does not add tenant
user RBAC, sensor attestation, full Sigma compliance, automatic mapping
for arbitrary rules, or high-volume stream processing.

## Defense-in-depth and tests

- `EvaluateEventWithSigma` runs against already bounded `SecurityEvent`.
  If pack validation fails, ingestion rolls back with 503; no partially
  persisted new detections or badges.
- Imported rule matches never set `VendorAlert`, change event severity
  or authorize automatic containment. The admin-only emergency fast path is
  also skipped when an event matched one of these Sigma heuristics.
- Positive and negative fixtures test every reviewed rule and reject unknown
  YAML keys, invalid conditions, regex, wildcards, unreviewed ATT&CK IDs,
  over-size YAML and flags requesting auto containment.
- PostgreSQL integration tests verify a Sigma alert creates only a
  35-confidence case hint and that guessing thresholds/replay do not mix
  company scopes.

```bash
go test -count=1 ./detectionpack ./defense
go test -count=1 ./server -run 'TestPR12'
go test -p 1 ./...
```

All tests use synthetic events. The pack does not connect to sensors,
launch network scans, execute files or apply firewall changes.
