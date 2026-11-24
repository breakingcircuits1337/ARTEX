# PR #22 — ARTEX signature import and archive comparison

This review compares the user-supplied **`aipt_artex.yar`** and two
**ARTEX-DEFENDER** ZIP archives against the existing ARTEX-DEFENSE
detection pack. All uploaded material was inspected as **untrusted data**:
archive members, rule text and the separate prototype's code were not
executed. The original ARTEX-DEFENSE Go SOC, auth, independent human
review and deterministic emergency guards are preserved.

## Input inventory

| Input | What was inspected | Decision |
| --- | --- | --- |
| `aipt_artex.yar` (10 rules) | ARTEX file/binary, embedded console, prompt, tool schema, transcript, API-recon skill, supervisor, Norma SDK, go-mitmproxy executable and CA certificate signatures | **All 10 retained verbatim** as a separately identifiable, DRL-licensed YARA source. Included in the authenticated, **operator-only** downloadable YARA bundle. |
| `artex-defender-github-ready(1).zip` (51 entries) | 18 Suricata signatures, seven YARA rules, a standalone defender's planner/worker, incident DB, analyst auth, response executor, Docker configuration, and tests | The **previous PR #5 catalog already imported the reviewed 7 Suricata and 3 YARA signatures**. Do not duplicate these. Assess architecture separately. |
| `ARTEXDEFENDER(1).zip` (10 entries) | Alternate version of 18 Suricata and seven YARA rules, plus prototype Go planner/worker/response/server and deployment files | Earlier prototype overlaps the ready ZIP. Do not reintroduce outdated rule conditions or a second server and response engine. |

The input ZIP rules are not all deployment-worthy. The existing pack
**continues to quarantine 11 broad/duplicate Suricata signatures** and
**four broad YARA signatures**. In particular, a
`webhook.site` callback, commercial OpenAI/Anthropic API connection,
a common port, a generic SDK, or a historical infrastructure IP
address is **not reliable evidence of compromise**. Source SIDs in the
original archive do not independently establish legitimacy or current
IOC attribution. Review the latest primary-source advisories before
using any infrastructure IOC.

## Added AIPT YARA signatures

| Rule | What a match suggests | Risk / interpretation |
| --- | --- | --- |
| `AIPT_ARTEX_Go_Binary` | ARTEX-specific strings in a binary | Legitimate upstream/fork ARTEX installations can match. |
| `AIPT_ARTEX_Embedded_WebUI` | Historical ARTEX web-console strings | Backups, bundles and documentation may match. |
| `AIPT_ARTEX_LLM_Prompt_Markers` | ARTEX-shaped prompt or transcript content | Investigative clue, **not** proof the model executed a tool. |
| `AIPT_ARTEX_LLM_Tool_Schema` | Tool/function schema markers | Many names are generic; require independent corroboration. |
| `AIPT_ARTEX_Transcript_File` | ARTEX session ID pattern with a tool name | Legitimate logs and authorized testing can match. |
| `AIPT_ARTEX_ApiRecon_Skill_Scripts` | Distinctive API-recon skill constants | Installed or copied scripts are not inherently malicious. |
| `AIPT_ARTEX_Supervisor_Script` | Older ARTEX supervisor markers | May fail to identify current versions. |
| `AIPT_Norma_SDK_Go_Binary` | Norma SDK Go binary | **Not ARTEX-specific**; high false-positive risk. |
| `AIPT_GoMitmproxy_Embedded_Recorder` | go-mitmproxy recorder strings | **Not ARTEX-specific**; high false-positive risk. |
| `AIPT_GoMitmproxy_CA_Certificate_PEM` | go-mitmproxy CA certificate | Legitimate proxy CA; high false-positive risk. |

These are **file-scope YARA 4.x rules**, not live-process memory rules.
Some use `filesize`, binary-format checks and relatively costly
regular expressions; large files (up to the supplied 500 MB upper
bound) should be scanned only in a resource-bounded, authorized,
operator-controlled environment. Exclude this repository, rule
sources, and known test fixtures from scan roots to reduce self-matches.
No source rule is claimed to be a validated malware signature.

The authored source explicitly provides **`author = "Xint"`** and
**DRL-1.1** attribution per rule. We preserve all original meta fields,
license links, rule names, expressions, original comments and dates.
`manifest.json` also lists author/license, and a submitted matched
rule will display author/license in the SOC finding summary. DRL-1.1
requires attribution in shared rules **and in messages based on matches**:
<https://github.com/SigmaHQ/Detection-Rule-License>.

## Security boundaries retained

- The two YARA sources are embedded and concatenated into the **same**
  fixed `GET /api/defense/detection-pack/yara` download. No request
  specifies a filesystem path; all signatures are validated against an
  exact catalog name.
- `default_deployed=false`, `execution_enabled=false`, and
  `autonomous_containment_enabled=false`; **all** catalog entries have
  `operator_install_required=true` and
  `auto_containment_eligible=false`.
- ARTEX never launches YARA or Suricata, reads an endpoint file using a
  matching rule, or deploys these rules to a sensor. Existing
  sensor/forwarder authentication is still required to submit evidence.
- Imported YARA matches are **unverified generic endpoint observations**,
  not authenticated source attestations and not authorizations to arm
  firewall actions or isolation.
- The original Suricata alert-only pack and its quarantined list are
  unchanged. Nothing here upgrades generic YARA results into
  `vendor_alert=true` evidence for the independent emergency engine.

## Further improvements worth a dedicated review (not merged here)

1. **Zeek log support:** The prototype has a Zeek TSV DNS counter, but its
   log-path safety policy uses canonicalize-then-open checks that can race
   symlink substitution. Implement any ingestion as bounded, authenticated,
   confined, passive parsing, independent of an LLM's generated commands.
2. **Detection coverage evaluations:** Use synthetic authorized ARTEX
   traces and known-benign datasets to measure false-positive rates,
   recall, sequence timing and signature drift per version; write the
   metrics to a reproducible CI artifact, not an accuracy claim.
3. **AI hypothesis suggestions:** The ZIP proposes an LLM planner and
   sensor workers. The existing AI advisory lane is **zero-tool and
   human-consented**. Do not replace this with unbounded LLM-directed
   file reads, network tests, or firewall commands. Any future proposed
   rule requires an independent human review and deterministic validator.
4. **Proposed response actions:** The standalone archive includes
   `block_ip`, `null_route`, `rate_limit`, `watchlist`,
   `isolate_host`, and capture actions. Copying them into the
   running server would violate the existing narrowly scoped,
   independently armed emergency-containment model. Perform a separate
   threat model, rollback/scope/authorization review before extending it.
5. **Security boundaries:** The archive's relative path helpers and
   general-purpose command execution should not replace ARTEX-DEFENSE's
   `os.Root` confinement, per-collector credentials, deterministic
   triage and audited case review.

## Verify

```sh
go test ./detectionpack ./defense
bash scripts/validate-detection-pack.sh
# Native rule compilation and Go full matrix are enforced by CI.
```

`scripts/validate-detection-pack.sh` uses Suricata `-T` and real YARA
compilation against an empty file. It compiles **each source plus the
combined download**; it never runs live scanning or activates an IDS.
A passing syntax check is not a false-positive benchmark, provenance
attestation, or production validation.
