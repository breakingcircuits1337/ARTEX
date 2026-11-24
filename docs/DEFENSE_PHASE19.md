# PR #19 — Runtime Isolation & Container Security

PR #19 hardens privileged workspace file operations and narrows the
container's privileges. This is a **defense-in-depth change**, not a claim
that ARTEX's root daemon or executor is fully sandboxed or safe for critical
infrastructure. ARTEX continues to default to `ARTEX_MODE=defense`, and
automatic containment remains disabled unless explicitly armed.

## Workspace filesystem boundaries

Previously the authenticated workspace file manager checked path confinement,
then performed path-based privileged operations. A less-privileged executor
could rename a directory after the check, redirecting a later read, write,
upload, download or recursive deletion outside the workspace.

The following endpoints now use `os.Root` directory handles anchored under
the data directory, rather than relying on canonicalized paths alone:

| Endpoint | Behavior |
| --- | --- |
| `/api/workspace/list` | Directory descriptor `ReadDir`; listing stays in the opened directory. |
| `/api/workspace/read` | Bounded reads from an opened, regular file; avoids a second path open. |
| `/api/workspace/download` | `http.ServeContent` on the opened descriptor, retaining range requests. |
| `/api/workspace/write` | Rooted parent, exclusive temp-file creation, atomic rename to replace; refuses non-regular destination. |
| `/api/workspace/upload` | One pinned upload directory for the multipart request, atomic replacements; refuses existing symlink/fifo/directory destinations. |
| `/api/workspace/mkdir` | Rooted `MkdirAll`; cannot traverse an external symlink. |
| `/api/workspace/delete` | Rooted parent and leaf-only `RemoveAll`; deleting a final symlink unlinks it, not its target. |

Atomic replacements preserve the existing permission bits and, when running
as root on Unix, UID/GID of regular destination files; this avoids making
a private executor-owned file unexpectedly unreadable by the executor.
Failed writes clean up their temporary entries.

Regression tests cover a parent renamed and replaced by a symlink *after*
its directory handle has been acquired, an out-of-root symlink at open,
final-component symlinks, regular-file mode preservation, and basic
workspace read/write/list/upload/download/delete request behavior.

### Remaining filesystem limitations

- Root confinement prevents escapes **outside** the data root, but internal
  symlinks to other in-root subtrees can still race authorization checks for
  platform-denied prefixes (`traffic/_ca`, `_index`, `_blobs`).
  This PR does **not** eliminate every internal-subtree authorization race.
- `os.Root` is not a mount namespace, and bind mounts, hard links to already
  permitted files, FUSE, network filesystems, and nonregular-file races
  require separate threat-model review. Directory permission/ACL policy
  remains essential.
- Task-archive staging, journaling and restore paths, other server-owned
  output directories and legacy ingestion files are not all converted here.
- The main Go server still runs as root by design because it provisions
  executor-owned run directories and isolates keys. Process-level privilege
  minimization and independent credential/network isolation remain work.
- Files replaced by an atomic rename receive a new inode; software holding an
  old descriptor may continue reading the previous inode. This is safer for
  integrity than truncation, but can affect filesystem watchers.

## Docker runtime hardening

Both `docker-compose.yml` and `docker-compose.ghcr.yml` now:

- Retain `no-new-privileges`; keep daemon capabilities required for the
  intentional `setuid`/`setgid` executor isolation and owner management.
- Drop `NET_RAW`, `MKNOD`, `SYS_CHROOT`, `SETPCAP`, `SETFCAP`, and
  `NET_BIND_SERVICE`. No net-admin, privileged mode or host network is added.
- Enable a bounded 1024-process limit, an init reaper, and a 1 GiB
  `/tmp` tmpfs with `nosuid,nodev`. The tmpfs is `exec`-capable because
  existing browser/recon tools may require executable scratch space.
- Keep data and key mounts persistent. The local source-build Compose file
  mounts host-provided `skills/` **read-only**; update skills on the host,
  not from inside the runtime container.

### Compatibility / opt-in active testing

Removing `NET_RAW` may disable tools that need raw ICMP/packet sockets in
explicitly authorized `ARTEX_MODE=pentest` deployments. If required,
configure a **reviewed deployment-specific Compose override** after
documenting scope, operator approvals, egress allowlists and the host
impact. Do not weaken the default defense deployment for active scans.
Some workloads may legitimately need a higher `pids_limit` or `/tmp`
budget; benchmark in isolation before adjusting them.

The application remains root in the container; a `read_only` root
filesystem is not yet enabled because third-party software currently writes
to runtime caches outside `/app/data`. Moving those caches and dropping
the main server's privileges is follow-on work.

## Release-blocking runtime image vulnerability assessment

`.github/workflows/container-security.yml` validates the **effective**
Compose configuration on pull requests and main. Its reusable
`scan_image=true` mode builds the complete Linux/amd64 runtime image
without publishing it, downloads **Trivy v0.76.2** with an independently
recorded release SHA-256, and fails if it finds **fixable HIGH or CRITICAL**
vulnerabilities across detected OS and application packages.

The image-audit job is required by `.github/workflows/release.yml`
*before* either GitHub Release or registry publication. It runs after the
existing release preflight, full tests and dependency advisory gates, without
registry credentials. A failed scan blocks publication; the table report is
retained as a workflow artifact for investigation.

Current scope: Linux/amd64 release image only. The arm64 image, externally
downloaded database definitions, unsigned nonpackage executables, runtime
configurations and vulnerabilities without available fixes need separate
assessment. `--ignore-unfixed` filters unfixed advisories from the **gate**
but does not make them safe: operators must review their impact.

No production image build or full CVE report is asserted until the
`runtime-image-audit` job actually completes in GitHub Actions.

## Validate

```bash
go test ./server -run 'TestWorkspace' -count=1
go test -race ./server -run 'TestWorkspace' -count=1
python3 scripts/test_container_hardening.py
# With Docker Compose installed; does not create containers or start postgres.
```

Security gate: `container-security / compose-isolation`. For a full
nonpublishing container scan, manually dispatch `container-security.yml`.
Production releases invoke it automatically. Check the report and
follow [Phase 18 qualification](DEFENSE_PHASE18.md) before any tag.
