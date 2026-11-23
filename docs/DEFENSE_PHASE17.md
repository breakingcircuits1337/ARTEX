# PR #17 — Security Hardening & Isolation

## Scope and non-goals
This PR changes the implicit runtime mode to `defense` everywhere, reinforces two documented privileged file-read/write boundaries, and adds focused regression tests. It does **not** make the whole Go server non-root, provide a full sandbox, guarantee complete symlink-race elimination, or enable automated containment.

## Changes
- Unset `ARTEX_MODE` resolves to `defense` in the core policy (including directly invoked binaries); active `pentest` mode requires an explicit value. Invalid values continue to fail validation; unknown modes stay restricted.
- Cold task archive **source reads** use `os.OpenRoot(payloadDir)` and `Root.Lstat/Open`, and compare opened inodes against preflight metadata before reading. A symlink inserted between metadata lookup and actual open cannot redirect source reads outside the payload. Symlinks are still omitted from archives.
- `ask_operator` image source opens are anchored in the agent's run directory; staged output files open via a separate `os.Root` rooted at the task directory. A symlink replacement to outside either directory is refused. Existing image type/size and collision rules remain.
- Chat attachment file creation is now `os.Root`-confined to the application data directory, with exclusive creation rather than any truncating write. This closes external-path redirection from substituted uploads directories, while leaving other workspace upload paths for follow-on review.
- Race-detector CI expands to cover `defense` and `containment`.
- Regression tests cover the archive symlink substitution boundary, package symlink omission, and image source confinement.

## Deployment migration
Unattended direct-binary deployments that formerly relied on implicit active-testing mode now start in `defense`. Operators who are authorized to conduct penetration tests must set `ARTEX_MODE=pentest` explicitly. Docker Compose and installers already defaulted to defense, and auto-containment stays off.

## Verification
```bash
go test -count=1 ./defense ./containment ./server
go test -p 1 ./...
go test -race -p 1 ./defense ./containment ./server
bash scripts/test-defense-defaults.sh
```
The normal CI matrix additionally tests the frontend, Python forwarder, and shell scripts. Run these on a disposable PostgreSQL-backed CI installation. No live firewall or external testing target is required.

## Remaining limitations / next work
- The main server still runs as root and should eventually drop privileges. The agent UID drop and file-rooting controls are layers, not a host-wide sandbox.
- Workspace upload paths, archive move/restore/recovery operations, and third-party background output paths need their own descriptor-relative audits. This PR does not claim to close them.
- Confined file opens do not solve hard-link source provenance or modified file contents after an already opened handle; additional policy and storage ownership controls are recommended.
- Containment remains disabled by default and has not been certified for production or industrial environments.

## Legacy test fixtures and the default-mode migration

The pre-PR17 `agent`, `guard`, and `server` integration suites assume active-testing tools are available. Their package-level `TestMain` now opts into `pentest` **only in test processes when ARTEX_MODE is unset**. This does not alter the production binary, embedded application behavior, or end-user defaults. Tests that explicitly set `ARTEX_MODE=defense` continue to exercise the restricted policy.

The `defense` package's `TestModeValidation` explicitly checks that an empty mode resolves to `defense` with restrictions enabled. To confirm both modes locally:
```bash
env -u ARTEX_MODE go test -count=1 ./defense
env -u ARTEX_MODE go test -count=1 ./agent ./guard ./server
```
The latter runs the legacy test fixture baseline; the Go package's `TestMain` sets `pentest` solely for its own test binary.
