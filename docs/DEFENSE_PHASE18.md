# PR #18 — Production Security Gates & Release Qualification

This phase adds enforceable software-delivery checks to ARTEX-DEFENSE. A passed
workflow **does not mean** the platform, host, container, or industrial network
has been independently certified secure.

## Automated gates

| Gate | PR/main | Tag release | What it establishes |
| --- | --- | --- | --- |
| Core CI (Go build/vet/test/race, frontend, Python, shell) | `ci.yml` | Same exact tagged commit via reusable CI | Tests and compilation passed on the tested environment |
| Go vulnerability advisories | Reachable-source `govulncheck` | Same exact tagged commit | No vulnerabilities reported for reachable Go code during that scan |
| Node production dependency advisories | `npm audit --omit=dev --audit-level=high` | Same exact tagged commit | No high/critical production npm advisories reported during that scan |
| CodeQL | Go, JS/TS and Python on PR/main; scheduled | Review the alert state on main | Static-analysis results are uploaded; not proof that all alerts are closed |
| Tag provenance | n/a | Tag-only preflight | Annotated SemVer tag targets a commit reachable from `main` |
| Release ZIP qualification | n/a | Before publication | Five expected ZIPs, binaries, launchers, config, README and skills; no traversal, links or bad CRC |
| Checksums and SBOM | n/a | Before signing/publishing | Exactly five correct SHA256SUMS digests and CycloneDX Go+Node inventory |
| Build provenance | n/a | GitHub attestation | An attested ZIP artifact build |

**Scanners are blocking.** A newly disclosed vulnerability can make the check
fail even without code changes. Fix and retest the affected dependency; do not
silence a failure with `|| true`, `continue-on-error`, or blanket exclusions.

## Release behavior

- `.github/workflows/release.yml` invokes both `ci.yml` and
  `security-gates.yml` at the tagged commit. Building for publication only
  begins when these and the release preflight all succeed.
- Tags must be `vMAJOR.MINOR.PATCH` with an optional prerelease suffix
  (for example `v1.2.3-rc.1`), must be annotated, and must point to an
  ancestor of `main`. GitHub tag rulesets to restrict who can create or
  update tags **must also be configured outside this repository**.
- Manual `workflow_dispatch` uses a fixed `v0.0.0-ci` build version.
  It can produce CI artifacts but cannot publish GitHub Releases or registry
  images. Only stable tags advance the floating `latest` image alias.
- The release job validates every ZIP before computing digests and checks
  the digest set and CycloneDX inventory before attestation and publication.
- Registry and GitHub Release publication are separate external transactions:
  a failed job can leave a partially published version. Operators must not
  declare a release qualified until both publication jobs pass, and should
  document how to withdraw an incomplete release.

## Maintainer production signoff (manual)

Repository owners should enable `main` branch rulesets with required
`ci`, `security-gates`, and `codeql` status checks, disallow bypasses,
restrict `v*` tag creation and mutation, enable private vulnerability
reporting, and verify permissions for release environments. Merely adding
a workflow does not set required-check policies.

Before a production release, complete and retain an approval record covering:

1. Review CodeQL findings, vulnerability and secret alerts, and scan the final
   container OS/Python runtime, base layers and pinned third-party binaries
   for high/critical vulnerabilities. This last scan is **not yet automated**.
2. Validate data encryption, key custody, root privilege and file-system
   trust boundaries, proxy/TLS exposure, privileged containment helper scope,
   restricted network egress, logging and database access.
3. Exercise clean install, backup, restore, database migration rollback,
   collector re-enrollment/recovery, crash restart and telemetry continuity.
4. Smoke-test defense-mode startup, default-disabled containment and AI
   advisory, human review, short TTL, budgets, protected destination ranges,
   and simulated emergency rollback in an isolated lab.
5. Check detection false positives, event integrity and replay resistance
   under representative workloads; verify latency, CPU/RAM and retention.
6. Reconcile the GitHub Release ZIP checksums, provenance and SBOM against
   the exact commit SHA and deployment image digest.

**Known limitations:** the main application still has root privileges and
other documented filesystem races; third-party tools/Python/container base
image need complete image scanning; CodeQL uploads do not automatically fail
a build merely because an alert exists; no production HA, OT readiness,
safety certification or regulatory compliance is implied.

## Local verifier checks

```bash
python3 -m unittest discover -s scripts -p 'test_release_qualification.py' -v
python3 scripts/release_qualification.py tag --tag v1.2.3
bash scripts/test-defense-defaults.sh
```

The CI release workflow invokes the `artifacts` and `metadata` stages
after cross-platform packaging and after SBOM generation, respectively.
