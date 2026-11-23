# ARTEX Defense — PR #5 Detection Pack (alert-only)

This pack integrates a **curated subset** of detection signatures from the two
user-supplied archives, primarily `artex-defender-github-ready.zip`. Its
`detection/rules/artex.rules` and `detection/yara/artex.yar` were reviewed
alongside the earlier `ARTEXDEFENDER.zip`.

The uploaded package ships under **MIT** with
Copyright (c) 2026 Breaking Circuits. The original notice is retained at
`detectionpack/LICENSE-MIT`. ARTEX's repository-wide AGPL-3.0 obligations
remain unchanged.

**Important:** The pack is **NOT automatically loaded**, is not an intrusion
prevention system, never executes YARA against local files by itself, and
contains no active response logic. Every Suricata directive is `alert`.
Its manifest marks **all** rules `auto_containment_eligible: false`.
A match is only an investigative signal; it is not proof of compromise,
malware, attacker identity, or successful exploitation.

## Contents and review status

The source ZIP contains 18 Suricata signatures and seven YARA rule names.
We selected **7 Suricata** and **3 YARA** rules after narrowing some
conditions and revising their classifications. The other **15** remain
quarantined **outside deployable rule files**.

### Included Suricata SIDs

| SID | Description | Primary limitation |
| --- | --- | --- |
| `9900001` | `artex-enrich/1.0` user-agent | Legitimate ARTEX/research deployments match |
| `9900006` | Connections to local console port 8787 | Port reuse and permitted administration |
| `9900011` | Repeated `.env` URI requests | Narrowed from upstream broad path enumeration; legitimate testing |
| `9900012` | `artex-probe` URI marker | Easily spoofed and used in authorized testing |
| `9900020` | `CyberStrikeAI` user-agent | Client-supplied string is not attribution |
| `9900021` | `PentAGI` user-agent | Client-supplied string is not attribution |
| `9900030` | Connections to proxy port 8788 | Port reuse and permitted administration |

All retain the original SIDs; revised conditions use `rev:2`.
Set `HOME_NET` and `EXTERNAL_NET` for your own network, and make sure
the sensor actually sees the relevant flow. No signature matches encrypted
HTTP payloads unless your monitoring architecture legitimately observes
decrypted traffic.

### Included YARA rules

| Rule name | Description | Limitation |
| --- | --- | --- |
| `ARTEX_Binary_Strings` | ELF with ARTEX-related embedded strings | Finds legitimate ARTEX applications too |
| `ARTEX_JSP_Webshell_Numbered` | Suspicious command-executing JSP content | Generic content heuristic; inspect original file and context |
| `ARTEX_Probe_File` | Small file containing a probe marker | Benign files and test artifacts can match |

YARA has no filename-matching primitive; the JSP name is inherited from
the source archive, but **file naming is NOT enforced by the YARA rule**.
Selectively scope scans to authorized artifacts or paths, exclude the rule
pack and your own test fixtures, and keep scan output as evidence rather
than proof of compromise.

### Quarantined, not shipped as deployable signatures

Suricata SIDs `9900002` (generic SDK user-agent), `9900003-4`
(historical IP attribution), `9900005` (generic port),
`9900007-8` (legitimate webhook callback service),
`9900009` (reseller domain), `9900010` (ordinary rapid HTTP traffic),
`9900013` (duplicative probe marker), and `9900040-41`
(normal commercial LLM API usage).

YARA rules `ARTEX_Config_File`, `ARTEX_EVE_Log_Artifact`,
`ARTEX_Go_Module_Cache`, and `ARTEX_Docker_Compose` were quarantined
because normal development or authorization evidence can trigger them.

The exact excluded items and reason strings are retained in
`detectionpack/manifest.json`; neither the backend catalog nor a dashboard
download exposes any file containing their original matching expressions.

## Validate before using

**CI rule checks** run a real Suricata parser and YARA compiler on the
artifact files. They do not start a sensor or activate any firewall rule.

```bash
sudo apt-get install -y suricata yara
bash scripts/validate-detection-pack.sh
go test ./detectionpack ./defense ./server
```

`detectionpack.Validate()` independently checks the embedded catalog,
SID uniqueness, exact names, zero unreviewed rules, and alert-only Suricata
actions; the native binaries additionally catch parser errors. Test the
rules with representative **benign** traffic and recordings from your
environment. Do not deploy these signatures with IPS `drop` semantics.

## ARTEX interface and installation

In `ARTEX_MODE=defense`, an authenticated operator can browse the catalog
in **Functions → Defense SOC** and download both rule files. No changes to
current agent permissions or firewall privileges are needed.

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/api/defense/detection-pack` | Catalog, false-positive limits, exclusions and installation status |
| GET | `/api/defense/detection-pack/suricata` | Download curated Suricata `alert` rules |
| GET | `/api/defense/detection-pack/yara` | Download curated YARA signatures |

These endpoints inherit ARTEX's existing JWT session auth and cookie CSRF
protection. All are read-only and disabled outside defense mode.

An administrator can place the reviewed Suricata file on an **external
sensor** using that sensor's ordinary rule configuration/reload procedures.
The existing Phase 2 authenticated forwarder can then stream Suricata EVE
alerts into `POST /api/defense/events`, where ARTEX already stores them in
the normalized evidence/alert ledger. The detection pack **does not**
reload Suricata or run sensors inside the main ARTEX container.

**Example Suricata EVE alert** to ingest (for operator lab use only):

```json
{
  "source": "suricata",
  "events": [{
    "event_id": "sample-9900001",
    "timestamp": "2026-11-23T12:00:00Z",
    "event_type": "alert",
    "src_ip": "192.0.2.10",
    "dest_ip": "198.51.100.8",
    "alert": {
      "signature_id": 9900001,
      "signature": "ARTEX-DEFENDER ARTEX Enrich User-Agent Detected",
      "severity": 3
    }
  }]
}
```

Curated SID `9900001` produces a `curated_suricata_9900001` **alert-only**
SOC finding, with `vendor_alert=false` regardless of incoming sensor
severity. It is not a confirmed intrusion and is ineligible for emergency
auto-containment. The original source event remains linked as evidence.

### Authorized YARA scan reports

ARTEX does **not** launch YARA scans. An authorized external scanner can
submit an observation using the existing Phase 2 generic event contract:

```json
{
  "source": "generic",
  "events": [{
    "event_id": "your-scanner-job-123:artifact-456",
    "kind": "endpoint",
    "host": "lab-host",
    "signature": "ARTEX_JSP_Webshell_Numbered",
    "severity": 6
  }]
}
```

A report matching **one of the three curated YARA names** produces a
`curated_yara_*` SOC alert labeled **unverified** and references the
original submitted event. Other generic events remain unaffected.
The report cannot request a local YARA execution, remote file read,
endpoint isolation, or automatic firewall intervention.

**Operator caution:** ARTEX Phase 2 collector authentication currently
uses the main session JWT. This is a prototype integration, not a
sensor-specific authenticity or nonrepudiation system. Protect JWTs, use
authenticated transport, and independently verify original sensor files
before acting on a submitted scan result.

## Relationship with Emergency Auto-Containment PR #4

PR #5 targets **main** independently of still-draft PR #4. It does not
modify `ARTEX_AUTO_CONTAIN_SURICATA_SIGNATURES`, the runtime allowlist,
or any enforcement adapter.

PR #4 requires **independent operator configuration and arming** before
temporary containment. PR #5 also enforces a separate hard gate: when a
Suricata alert contains one of the curated SIDs, the normalizer sets
`vendor_alert=false` and issues an alert-only finding. The PR #4 emergency
fast path requires `vendor_alert=true`, so **these curated detections cannot
activate automatic containment even if their signature string is added to an
emergency allowlist**. Do not alter this guard without a new safety review.
Unverified YARA reports use `generic` source and are also ineligible under
PR #4's vendor-specific deterministic containment conditions.

## Validation gates before merging

- [ ] Native Suricata `-T` and YARA syntax checks pass in CI
- [ ] Embedded manifest and SID/YARA uniqueness tests pass
- [ ] Go package tests and existing server tests pass
- [ ] Web typechecking and build pass
- [ ] Authorized EVE and YARA sample events appear only as alerts
- [ ] No emergency containment privileges, firewall changes or sensor
      reloads are triggered by downloading or inspecting the pack
- [ ] Real-world false-positive baselines established before deployment

This package is a small, operator-reviewed *starting point*, not a complete
intrusion detection rule corpus or validated attribution dataset.
